#!/usr/bin/env python3
"""
Find arm64e `movk` instruction references ("xrefs") to a target immediate.

This is useful when analyzing pointer-authenticated virtual dispatch patterns.
In Music.app, vtable dispatch sequences frequently include an instruction like:

    movk x17, #0x75AF, lsl #48

where the imm16 value (0x75AF above) matches the "diversity" shown in
`dyld_info -fixup_chain_details` for an authenticated pointer (e.g. a vtable
slot). By scanning `__TEXT,__text` for `movk` with a given imm16 + shift, we can
quickly locate candidate virtual callsites to disassemble.
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
class MovkXref:
    """A `movk` instruction matching a filter.

    :ivar addr: VM address of the `movk` instruction.
    :ivar rd: Destination register number (0-31).
    :ivar imm16: 16-bit immediate value.
    :ivar shift: Shift amount in bits (0/16/32/48).
    :ivar instr: Raw 32-bit instruction word.
    """

    addr: int
    rd: int
    imm16: int
    shift: int
    instr: int


def _decode_fixed_cstring(raw: bytes) -> str:
    """Decode a fixed-width C string field from a Mach-O structure.

    :param raw: Fixed-width byte field, null-terminated or padded.
    :returns: Decoded string.
    """

    nul_index: int = raw.find(b"\x00")
    if nul_index >= 0:
        raw = raw[0:nul_index]
    return raw.decode("utf-8", errors="replace")


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

                if segname2 == "__TEXT" and sectname == "__text":
                    candidate: MachOSection = MachOSection(
                        segname=segname,
                        sectname=sectname,
                        vmaddr=int(addr),
                        size=int(size),
                        file_offset=slice_file_offset + int(offset),
                    )
                    best = candidate

                sect_off += 80

        cmd_off = next_off
        i += 1

    if best is None:
        raise ValueError("no __TEXT,__text section found")

    return best


def _read_file_range(path: Path, offset: int, size: int) -> bytes:
    """Read a file slice.

    :param path: File path.
    :param offset: Offset in bytes.
    :param size: Size to read in bytes.
    :returns: Bytes.
    """

    if offset < 0:
        raise ValueError("offset must be >= 0")
    if size < 0:
        raise ValueError("size must be >= 0")

    with path.open("rb") as f:
        f.seek(offset)
        data: bytes = f.read(size)
    if len(data) != size:
        raise ValueError("short read")
    return data


def _is_movk64(instr: int) -> bool:
    """Return True if an instruction is 64-bit MOVK (move wide with keep).

    :param instr: 32-bit instruction word.
    :returns: True if MOVK Xd, #imm, LSL #shift.
    """

    return (instr & 0xFF800000) == 0xF2800000


def _decode_movk64(instr: int) -> tuple[int, int, int]:
    """Decode a 64-bit MOVK instruction.

    :param instr: 32-bit instruction word.
    :returns: (rd, imm16, shift).
    """

    rd: int = instr & 0x1F
    imm16: int = (instr >> 5) & 0xFFFF
    hw: int = (instr >> 21) & 0x3
    shift: int = hw * 16
    return rd, imm16, shift


def find_movk_xrefs(
    text: MachOSection,
    text_bytes: bytes,
    imm16: int,
    shift: int,
    rd: int | None,
) -> list[MovkXref]:
    """Scan `__text` for MOVK xrefs matching a filter.

    :param text: Text section metadata.
    :param text_bytes: Raw bytes of the text section.
    :param imm16: Immediate value to match (0..65535).
    :param shift: Shift amount to match (0/16/32/48).
    :param rd: Optional destination register filter (0..31).
    :returns: Matching MOVK instruction locations.
    """

    if imm16 < 0 or imm16 > 0xFFFF:
        raise ValueError("imm16 must be in range 0..0xFFFF")
    if shift not in (0, 16, 32, 48):
        raise ValueError("shift must be one of 0,16,32,48")
    if rd is not None and (rd < 0 or rd > 31):
        raise ValueError("rd must be in range 0..31")

    if (len(text_bytes) % 4) != 0:
        raise ValueError("__text length is not instruction-aligned (not multiple of 4)")

    results: list[MovkXref] = []
    count: int = len(text_bytes) // 4

    i: int = 0
    while i < count:
        pc: int = text.vmaddr + (i * 4)
        instr: int = struct.unpack_from("<I", text_bytes, i * 4)[0]

        if _is_movk64(instr) is False:
            i += 1
            continue

        rd_i: int
        imm16_i: int
        shift_i: int
        rd_i, imm16_i, shift_i = _decode_movk64(instr=instr)

        if imm16_i != imm16:
            i += 1
            continue
        if shift_i != shift:
            i += 1
            continue
        if rd is not None and rd_i != rd:
            i += 1
            continue

        results.append(
            MovkXref(addr=pc, rd=rd_i, imm16=imm16_i, shift=shift_i, instr=instr)
        )
        i += 1

    return results


def _render_text(imm16: int, shift: int, rd: int | None, xrefs: list[MovkXref]) -> str:
    """Render xrefs as plain text.

    :param imm16: Immediate filter.
    :param shift: Shift filter.
    :param rd: Optional rd filter.
    :param xrefs: Xref list.
    :returns: Text.
    """

    rd_str: str = "any" if rd is None else str(rd)
    lines: list[str] = []
    lines.append(f"imm16=0x{imm16:04X} shift={shift} rd={rd_str} xrefs={len(xrefs)}")
    for x in xrefs:
        lines.append(
            f"0x{x.addr:016X}: movk x{x.rd}, #0x{x.imm16:04X}, lsl #{x.shift} (instr=0x{x.instr:08X})"
        )
    return "\n".join(lines) + "\n"


def _render_json(imm16: int, shift: int, rd: int | None, xrefs: list[MovkXref]) -> str:
    """Render xrefs as JSON.

    :param imm16: Immediate filter.
    :param shift: Shift filter.
    :param rd: Optional rd filter.
    :param xrefs: Xref list.
    :returns: JSON string.
    """

    payload: dict[str, object] = {
        "imm16": imm16,
        "shift": shift,
        "rd": rd,
        "xrefs": [
            {
                "addr": f"0x{x.addr:016X}",
                "rd": x.rd,
                "imm16": x.imm16,
                "shift": x.shift,
                "instr": f"0x{x.instr:08X}",
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
        description="Find arm64e MOVK instruction xrefs to an imm16 (optionally filtered by shift/rd)"
    )
    parser.add_argument(
        "--binary",
        type=Path,
        default=Path(DEFAULT_MUSIC_BINARY),
        help=f"Binary path (default: {DEFAULT_MUSIC_BINARY})",
    )
    parser.add_argument(
        "--imm16",
        required=True,
        help="Immediate value (hex), e.g. 0x75AF",
    )
    parser.add_argument(
        "--shift",
        type=int,
        default=48,
        choices=[0, 16, 32, 48],
        help="Shift to match (default: 48)",
    )
    parser.add_argument(
        "--rd",
        type=int,
        default=None,
        help="Optional destination register filter (0-31). Example: 17 for x17.",
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

    imm_str: str = args.imm16
    try:
        imm16: int = int(imm_str, 16)
    except ValueError:
        sys.stderr.write(f"error: invalid --imm16 hex value: {imm_str}\n")
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
    try:
        xrefs: list[MovkXref] = find_movk_xrefs(
            text=text,
            text_bytes=text_bytes,
            imm16=imm16,
            shift=int(args.shift),
            rd=args.rd,
        )
    except ValueError as e:
        sys.stderr.write(f"error: {e}\n")
        return 2

    if args.format == "json":
        sys.stdout.write(_render_json(imm16=imm16, shift=int(args.shift), rd=args.rd, xrefs=xrefs))
        return 0

    sys.stdout.write(_render_text(imm16=imm16, shift=int(args.shift), rd=args.rd, xrefs=xrefs))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

