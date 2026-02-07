#!/usr/bin/env python3
"""
Find arm64e `bl` callsite references ("xrefs") to a target VM address in a Mach-O.

This complements the existing ADRP+ADD xref scanner. Direct (non-virtual) calls
to internal functions in Music.app frequently use `bl` with a PC-relative
immediate. By scanning for `bl` instructions that resolve to a given target
address, we can quickly locate callsites for constructors, response parsers,
and other key helpers.
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
class BlXref:
    """A `bl` instruction that targets a given address.

    :ivar call_addr: VM address of the `bl` instruction.
    :ivar target_addr: VM address of the resolved branch target.
    :ivar imm26: Raw 26-bit immediate encoded in the instruction.
    """

    call_addr: int
    target_addr: int
    imm26: int


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


def _is_bl(instr: int) -> bool:
    """Return True if a 32-bit instruction word is `bl` (immediate).

    :param instr: 32-bit instruction word.
    :returns: True if BL.
    """

    return (instr & 0xFC000000) == 0x94000000


def _decode_bl_target(instr: int, pc: int) -> tuple[int, int]:
    """Decode a `bl` (immediate) instruction.

    :param instr: 32-bit instruction word.
    :param pc: VM address of the `bl` instruction.
    :returns: `(imm26, target_addr)`.
    """

    imm26: int = instr & 0x03FFFFFF
    imm26_signed: int = _sign_extend(imm26, 26)
    offset: int = imm26_signed << 2
    return imm26, pc + offset


def find_bl_xrefs(text: MachOSection, text_bytes: bytes, target_addr: int) -> list[BlXref]:
    """Scan a `__text` section for `bl` callsites to a target address.

    :param text: Text section metadata.
    :param text_bytes: Raw bytes of the text section.
    :param target_addr: Target VM address to find callsites for.
    :returns: List of callsites.
    """

    size: int = len(text_bytes)
    if (size % 4) != 0:
        size = size - (size % 4)

    results: list[BlXref] = []
    insn_count: int = size // 4

    i: int = 0
    while i < insn_count:
        pc: int = text.vmaddr + (i * 4)
        instr: int = struct.unpack_from("<I", text_bytes, i * 4)[0]

        if _is_bl(instr) is False:
            i += 1
            continue

        imm26: int
        resolved: int
        imm26, resolved = _decode_bl_target(instr=instr, pc=pc)
        if resolved == target_addr:
            results.append(BlXref(call_addr=pc, target_addr=resolved, imm26=imm26))

        i += 1

    return results


def _render_text(target_addr: int, xrefs: list[BlXref]) -> str:
    """Render xrefs as plain text.

    :param target_addr: Target address.
    :param xrefs: Xref list.
    :returns: Text.
    """

    lines: list[str] = []
    lines.append(f"target=0x{target_addr:016X} xrefs={len(xrefs)}")
    for x in xrefs:
        lines.append(
            f"0x{x.call_addr:016X}: bl 0x{x.target_addr:016X} (imm26=0x{x.imm26:X})"
        )
    return "\n".join(lines) + "\n"


def _render_json(target_addr: int, xrefs: list[BlXref]) -> str:
    """Render xrefs as JSON.

    :param target_addr: Target address.
    :param xrefs: Xref list.
    :returns: JSON string.
    """

    payload: dict[str, object] = {
        "target": f"0x{target_addr:016X}",
        "xrefs": [
            {
                "call_addr": f"0x{x.call_addr:016X}",
                "target_addr": f"0x{x.target_addr:016X}",
                "imm26": x.imm26,
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
        description="Find arm64e BL callsite xrefs to a VM address in a Mach-O"
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
        help="Target VM address (hex), e.g. 0x100809000",
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

    text_off_in_slice: int = text.file_offset - slice_info.file_offset
    if text_off_in_slice < 0:
        sys.stderr.write("error: internal offset calculation failure\n")
        return 2

    end_off: int = text_off_in_slice + text.size
    if end_off > len(slice_bytes):
        sys.stderr.write("error: __text section overruns slice bytes\n")
        return 2

    text_bytes: bytes = slice_bytes[text_off_in_slice:end_off]
    xrefs: list[BlXref] = find_bl_xrefs(
        text=text,
        text_bytes=text_bytes,
        target_addr=target_addr,
    )

    if args.format == "json":
        sys.stdout.write(_render_json(target_addr=target_addr, xrefs=xrefs))
        return 0

    sys.stdout.write(_render_text(target_addr=target_addr, xrefs=xrefs))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

