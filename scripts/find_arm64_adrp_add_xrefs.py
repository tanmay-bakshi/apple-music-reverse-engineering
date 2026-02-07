#!/usr/bin/env python3
"""
Find arm64e `adrp`+`add` references ("xrefs") to a target VM address in a Mach-O.

This is a lightweight static-analysis helper. The Music.app binary is heavily
stripped, but it still contains many interesting C strings (bag keys, os_log
format strings, operation names like "StoreGetLyrics", etc.). Code references to
those strings usually materialize their addresses via an `adrp` (page) followed
by an `add` (page offset). Scanning for those instruction pairs gives us
candidate code locations to disassemble in LLDB.
"""

import argparse
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path


DEFAULT_MUSIC_BINARY: str = "/System/Applications/Music.app/Contents/MacOS/Music"

FAT_MAGIC: int = 0xCAFEBABE
FAT_MAGIC_64: int = 0xCAFEBABF
MH_MAGIC_64: int = 0xFEEDFACF

CPU_TYPE_ARM64: int = 0x0100000C

LC_SEGMENT_64: int = 0x19


@dataclass(frozen=True)
class MachOSlice:
    """A single-architecture Mach-O slice within a file.

    :ivar arch: Human label ("arm64e" best-effort, otherwise "arm64"/"unknown").
    :ivar file_offset: File offset where the Mach-O slice begins.
    :ivar file_size: Size in bytes of the slice.
    """

    arch: str
    file_offset: int
    file_size: int


@dataclass(frozen=True)
class MachOSection:
    """A Mach-O section.

    :ivar segname: Segment name (e.g. "__TEXT").
    :ivar sectname: Section name (e.g. "__text").
    :ivar vmaddr: VM address where the section is mapped.
    :ivar size: Size in bytes.
    :ivar file_offset: File offset (absolute, including universal header offset).
    """

    segname: str
    sectname: str
    vmaddr: int
    size: int
    file_offset: int


@dataclass(frozen=True)
class AdrpAddXref:
    """An `adrp`+`add` pair that materializes a target address.

    :ivar adrp_addr: Address of the `adrp` instruction.
    :ivar add_addr: Address of the `add` instruction.
    :ivar adrp_rd: Destination register number used by `adrp` (0-31).
    :ivar add_rd: Destination register number used by `add` (0-31).
    :ivar add_rn: Source register number used by `add` (0-31).
    :ivar add_imm: Immediate value added (after shift).
    """

    adrp_addr: int
    add_addr: int
    adrp_rd: int
    add_rd: int
    add_rn: int
    add_imm: int


def _decode_fixed_cstring(raw: bytes) -> str:
    """Decode a fixed-width C string field from a Mach-O structure.

    :param raw: Fixed-width byte field, null-terminated or padded.
    :returns: Decoded ASCII-ish string.
    """

    nul_index: int = raw.find(b"\x00")
    if nul_index >= 0:
        raw = raw[0:nul_index]
    return raw.decode("utf-8", errors="replace")


def _sign_extend(value: int, bit_width: int) -> int:
    """Sign-extend an integer.

    :param value: Unsigned integer value.
    :param bit_width: Bit width of the input value.
    :returns: Signed integer.
    """

    sign_bit: int = 1 << (bit_width - 1)
    mask: int = (1 << bit_width) - 1
    value_masked: int = value & mask
    if (value_masked & sign_bit) != 0:
        return value_masked - (1 << bit_width)
    return value_masked


def _reg_name(reg: int) -> str:
    """Render an AArch64 register number.

    :param reg: Register number (0-31).
    :returns: Name like "x0" or "sp" (for 31).
    """

    if reg == 31:
        return "sp"
    return f"x{reg}"


def _is_adrp(instr: int) -> bool:
    """Return True if an instruction word is `adrp`.

    :param instr: 32-bit instruction word.
    :returns: True if ADRP.
    """

    return (instr & 0x9F000000) == 0x90000000


def _decode_adrp(instr: int, pc: int) -> tuple[int, int]:
    """Decode an ADRP instruction.

    :param instr: 32-bit instruction word.
    :param pc: Address of the instruction.
    :returns: `(rd, page_addr)` where `page_addr` is the computed page base.
    """

    immlo: int = (instr >> 29) & 0x3
    immhi: int = (instr >> 5) & 0x7FFFF
    imm21: int = (immhi << 2) | immlo
    imm21_signed: int = _sign_extend(imm21, 21)
    page_delta: int = imm21_signed << 12
    pc_page: int = pc & ~0xFFF
    rd: int = instr & 0x1F
    return rd, pc_page + page_delta


def _is_add_imm64(instr: int) -> bool:
    """Return True if an instruction word is `add xD, xN, #imm`.

    :param instr: 32-bit instruction word.
    :returns: True if it's 64-bit ADD (immediate), no flags.
    """

    return (instr & 0xFF000000) == 0x91000000


def _decode_add_imm64(instr: int) -> tuple[int, int, int, int]:
    """Decode 64-bit `add` (immediate).

    :param instr: 32-bit instruction word.
    :returns: `(rd, rn, imm, shift)` where `imm` is the 12-bit immediate and
      `shift` is 0 or 12 (effective shift amount).
    """

    shift_bit: int = (instr >> 22) & 0x1
    imm12: int = (instr >> 10) & 0xFFF
    rn: int = (instr >> 5) & 0x1F
    rd: int = instr & 0x1F
    shift: int = 12 if shift_bit == 1 else 0
    return rd, rn, imm12, shift


def find_adrp_add_xrefs(
    text: MachOSection,
    text_bytes: bytes,
    target_addr: int,
    window_instructions: int,
) -> list[AdrpAddXref]:
    """Scan a `__text` section for `adrp`+`add` xrefs to a target address.

    :param text: Text section metadata.
    :param text_bytes: Raw bytes of the text section.
    :param target_addr: Target VM address to find references to.
    :param window_instructions: Max distance (in instructions) to look ahead for
      the matching `add`.
    :returns: A list of xrefs.
    """

    if window_instructions <= 0:
        raise ValueError("window_instructions must be > 0")

    target_page: int = target_addr & ~0xFFF
    target_off: int = target_addr & 0xFFF

    size: int = len(text_bytes)
    if (size % 4) != 0:
        # Keep scanning anyway; just ignore the tail.
        size = size - (size % 4)

    results: list[AdrpAddXref] = []
    insn_count: int = size // 4

    i: int = 0
    while i < insn_count:
        pc: int = text.vmaddr + (i * 4)
        instr: int = struct.unpack_from("<I", text_bytes, i * 4)[0]

        if _is_adrp(instr) is False:
            i += 1
            continue

        adrp_rd: int
        adrp_page: int
        adrp_rd, adrp_page = _decode_adrp(instr, pc=pc)
        if adrp_page != target_page:
            i += 1
            continue

        # Look ahead for `add` using the adrp destination as its base.
        j: int = 1
        while j <= window_instructions and (i + j) < insn_count:
            pc2: int = text.vmaddr + ((i + j) * 4)
            instr2: int = struct.unpack_from("<I", text_bytes, (i + j) * 4)[0]
            if _is_add_imm64(instr2) is False:
                j += 1
                continue

            add_rd: int
            add_rn: int
            imm12: int
            shift: int
            add_rd, add_rn, imm12, shift = _decode_add_imm64(instr2)
            if add_rn != adrp_rd:
                j += 1
                continue

            add_imm: int = imm12 << shift
            if add_imm != target_off:
                j += 1
                continue

            # adrp_page already matches the target page, and add_imm matches the
            # page offset, so this pair materializes the target address.
            results.append(
                AdrpAddXref(
                    adrp_addr=pc,
                    add_addr=pc2,
                    adrp_rd=adrp_rd,
                    add_rd=add_rd,
                    add_rn=add_rn,
                    add_imm=add_imm,
                )
            )
            break

        i += 1

    return results


def _select_arm64_slice(universal_bytes: bytes) -> MachOSlice | None:
    """Select the arm64/arm64e slice from a universal Mach-O.

    :param universal_bytes: Full file bytes.
    :returns: Slice info, or None if not universal or not found.
    """

    if len(universal_bytes) < 8:
        return None

    magic_be: int = struct.unpack_from(">I", universal_bytes, 0)[0]
    if magic_be != FAT_MAGIC and magic_be != FAT_MAGIC_64:
        return None

    nfat_arch: int = struct.unpack_from(">I", universal_bytes, 4)[0]
    if nfat_arch <= 0:
        raise ValueError("invalid fat header: nfat_arch <= 0")

    best: MachOSlice | None = None

    # FAT32: entries start at 8, size 20 each.
    # FAT64: entries start at 8, size 32 each.
    arch_size: int = 20 if magic_be == FAT_MAGIC else 32
    arch_base: int = 8

    for idx in range(nfat_arch):
        off: int = arch_base + (idx * arch_size)
        if (off + arch_size) > len(universal_bytes):
            raise ValueError("invalid fat header: arch table truncated")

        cputype: int = struct.unpack_from(">I", universal_bytes, off + 0)[0]
        cpusubtype: int = struct.unpack_from(">I", universal_bytes, off + 4)[0]

        if cputype != CPU_TYPE_ARM64:
            continue

        if magic_be == FAT_MAGIC:
            slice_off: int = struct.unpack_from(">I", universal_bytes, off + 8)[0]
            slice_size: int = struct.unpack_from(">I", universal_bytes, off + 12)[0]
        else:
            slice_off = struct.unpack_from(">Q", universal_bytes, off + 8)[0]
            slice_size = struct.unpack_from(">Q", universal_bytes, off + 16)[0]

        # Best-effort label: low 8 bits are usually the subtype value.
        subtype_low: int = cpusubtype & 0xFF
        arch_label: str = "arm64e" if subtype_low == 2 else "arm64"

        candidate: MachOSlice = MachOSlice(
            arch=arch_label,
            file_offset=int(slice_off),
            file_size=int(slice_size),
        )

        if best is None:
            best = candidate
            continue

        # Prefer arm64e if available.
        if best.arch != "arm64e" and candidate.arch == "arm64e":
            best = candidate

    return best


def _find_text_section(macho_bytes: bytes, slice_file_offset: int) -> MachOSection:
    """Locate the main text section for a Mach-O slice.

    :param macho_bytes: Slice bytes (starting at 0 for the slice).
    :param slice_file_offset: Absolute file offset of the slice start.
    :returns: Text section metadata.
    :raises ValueError: If the slice does not look like Mach-O or no text section.
    """

    if len(macho_bytes) < 32:
        raise ValueError("Mach-O slice too small")

    magic_le: int = struct.unpack_from("<I", macho_bytes, 0)[0]
    if magic_le != MH_MAGIC_64:
        raise ValueError(f"unexpected Mach-O magic: 0x{magic_le:08X}")

    ncmds: int = struct.unpack_from("<I", macho_bytes, 16)[0]
    sizeofcmds: int = struct.unpack_from("<I", macho_bytes, 20)[0]
    if ncmds <= 0:
        raise ValueError("invalid Mach-O header: ncmds <= 0")
    if sizeofcmds <= 0:
        raise ValueError("invalid Mach-O header: sizeofcmds <= 0")

    cmd_off: int = 32
    cmd_end: int = cmd_off + sizeofcmds
    if cmd_end > len(macho_bytes):
        raise ValueError("Mach-O load commands truncated")

    best: MachOSection | None = None

    i: int = 0
    while i < ncmds:
        if (cmd_off + 8) > cmd_end:
            raise ValueError("Mach-O load command truncated")

        cmd: int = struct.unpack_from("<I", macho_bytes, cmd_off + 0)[0]
        cmdsize: int = struct.unpack_from("<I", macho_bytes, cmd_off + 4)[0]
        if cmdsize < 8:
            raise ValueError("Mach-O load command has invalid cmdsize")
        next_off: int = cmd_off + cmdsize
        if next_off > cmd_end:
            raise ValueError("Mach-O load command overruns table")

        if cmd == LC_SEGMENT_64:
            if cmdsize < 72:
                raise ValueError("LC_SEGMENT_64 too small")

            segname_raw: bytes = struct.unpack_from("<16s", macho_bytes, cmd_off + 8)[0]
            segname: str = _decode_fixed_cstring(segname_raw)
            nsects: int = struct.unpack_from("<I", macho_bytes, cmd_off + 64)[0]

            sect_off: int = cmd_off + 72
            for _ in range(nsects):
                if (sect_off + 80) > next_off:
                    raise ValueError("section_64 table truncated")

                sectname_raw: bytes = struct.unpack_from("<16s", macho_bytes, sect_off + 0)[0]
                segname2_raw: bytes = struct.unpack_from("<16s", macho_bytes, sect_off + 16)[0]
                sectname: str = _decode_fixed_cstring(sectname_raw)
                segname2: str = _decode_fixed_cstring(segname2_raw)

                addr: int = struct.unpack_from("<Q", macho_bytes, sect_off + 32)[0]
                size: int = struct.unpack_from("<Q", macho_bytes, sect_off + 40)[0]
                offset: int = struct.unpack_from("<I", macho_bytes, sect_off + 48)[0]

                if sectname == "__text":
                    candidate: MachOSection = MachOSection(
                        segname=segname2 if len(segname2) > 0 else segname,
                        sectname=sectname,
                        vmaddr=int(addr),
                        size=int(size),
                        file_offset=int(slice_file_offset + offset),
                    )

                    # Prefer __TEXT/__text over other segments if present.
                    if best is None:
                        best = candidate
                    elif best.segname != "__TEXT" and candidate.segname == "__TEXT":
                        best = candidate

                sect_off += 80

        cmd_off = next_off
        i += 1

    if best is None:
        raise ValueError("no __text section found")

    return best


def _read_file_range(path: Path, offset: int, size: int) -> bytes:
    """Read a contiguous range from a file.

    :param path: File path.
    :param offset: Start offset.
    :param size: Number of bytes.
    :returns: Bytes read.
    """

    if offset < 0:
        raise ValueError("offset must be >= 0")
    if size < 0:
        raise ValueError("size must be >= 0")

    with path.open("rb") as f:
        f.seek(offset)
        data: bytes = f.read(size)
        if len(data) != size:
            raise ValueError("file range read was short")
        return data


def _render_text(target_addr: int, xrefs: list[AdrpAddXref]) -> str:
    """Render xrefs as plain text.

    :param target_addr: Target address.
    :param xrefs: Xref list.
    :returns: Text.
    """

    lines: list[str] = []
    lines.append(f"target=0x{target_addr:016X} xrefs={len(xrefs)}")
    for x in xrefs:
        lines.append(
            "0x{adrp:016X}: adrp {base}, <page>; 0x{add:016X}: add {dst}, {src}, #0x{imm:X}".format(
                adrp=x.adrp_addr,
                add=x.add_addr,
                base=_reg_name(x.adrp_rd),
                dst=_reg_name(x.add_rd),
                src=_reg_name(x.add_rn),
                imm=x.add_imm,
            )
        )
    return "\n".join(lines) + "\n"


def _render_json(target_addr: int, xrefs: list[AdrpAddXref]) -> str:
    """Render xrefs as JSON.

    :param target_addr: Target address.
    :param xrefs: Xref list.
    :returns: JSON string.
    """

    payload: dict[str, object] = {
        "target": f"0x{target_addr:016X}",
        "xrefs": [
            {
                "adrp_addr": f"0x{x.adrp_addr:016X}",
                "add_addr": f"0x{x.add_addr:016X}",
                "adrp_rd": x.adrp_rd,
                "add_rd": x.add_rd,
                "add_rn": x.add_rn,
                "add_imm": x.add_imm,
            }
            for x in xrefs
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def main(argv: list[str]) -> int:
    """CLI entrypoint.

    :param argv: Raw argv (excluding program name).
    :returns: Exit code.
    """

    parser = argparse.ArgumentParser(
        description="Find arm64e ADRP+ADD xrefs to a VM address in a Mach-O"
    )
    parser.add_argument(
        "--binary",
        type=Path,
        default=Path(DEFAULT_MUSIC_BINARY),
        help=f"Binary path (default: {DEFAULT_MUSIC_BINARY})",
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target VM address (hex), e.g. 0x101A3353E",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=8,
        help="How many instructions after ADRP to search for the matching ADD (default: 8)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    args = parser.parse_args(argv)

    binary_path: Path = args.binary
    if binary_path.exists() is False:
        sys.stderr.write(f"error: binary not found: {binary_path}\n")
        return 2

    target_str: str = args.target
    try:
        target_addr: int = int(target_str, 16)
    except ValueError:
        sys.stderr.write(f"error: invalid --target hex value: {target_str}\n")
        return 2

    # Read enough of the file to detect universal header and parse arch table.
    file_size: int = binary_path.stat().st_size
    if file_size <= 0:
        sys.stderr.write("error: empty file\n")
        return 2

    header_read: int = 256 * 1024
    if file_size < header_read:
        header_read = file_size

    with binary_path.open("rb") as f:
        header_bytes: bytes = f.read(header_read)

    slice_info: MachOSlice | None = _select_arm64_slice(header_bytes)
    if slice_info is None:
        # Not universal (or universal detection failed). Assume the file itself is a Mach-O.
        slice_info = MachOSlice(arch="unknown", file_offset=0, file_size=file_size)

    slice_bytes: bytes = _read_file_range(
        binary_path, offset=slice_info.file_offset, size=slice_info.file_size
    )

    try:
        text: MachOSection = _find_text_section(
            macho_bytes=slice_bytes, slice_file_offset=slice_info.file_offset
        )
    except ValueError as e:
        sys.stderr.write(f"error: {e}\n")
        return 2

    # Convert absolute file offset back into slice-relative offset for the slice buffer.
    text_off_in_slice: int = text.file_offset - slice_info.file_offset
    if text_off_in_slice < 0:
        sys.stderr.write("error: internal offset calculation failure\n")
        return 2

    end_off: int = text_off_in_slice + text.size
    if end_off > len(slice_bytes):
        sys.stderr.write("error: __text section overruns slice bytes\n")
        return 2

    text_bytes: bytes = slice_bytes[text_off_in_slice:end_off]

    xrefs: list[AdrpAddXref] = find_adrp_add_xrefs(
        text=text,
        text_bytes=text_bytes,
        target_addr=target_addr,
        window_instructions=args.window,
    )

    if args.format == "json":
        sys.stdout.write(_render_json(target_addr=target_addr, xrefs=xrefs))
        return 0

    sys.stdout.write(_render_text(target_addr=target_addr, xrefs=xrefs))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
