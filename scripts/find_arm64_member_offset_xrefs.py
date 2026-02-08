#!/usr/bin/env python3
"""
Find arm64e code locations that reference specific byte offsets from a base register.

This is a static-analysis helper for reverse engineering struct/class layouts in the
macOS Music.app binary. Once we know (or suspect) that a member lives at some offset
within an object (e.g. `songInfo + 0x90`), we can scan the `__TEXT,__text` section
for instructions that use that offset (usually via `add/sub (immediate)` or
`ldr/str (unsigned immediate)`), group hits by function start, and then disassemble
those candidate functions in LLDB for deeper inspection.
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
LC_FUNCTION_STARTS: int = 0x26


@dataclass(frozen=True)
class MachOSlice:
    """A single-architecture Mach-O slice within a file.

    :ivar arch: Human label ("arm64e" best-effort, otherwise "arm64"/"thin").
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
    :ivar file_offset: Absolute file offset (including universal header offset).
    """

    segname: str
    sectname: str
    vmaddr: int
    size: int
    file_offset: int


@dataclass(frozen=True)
class LinkeditBlob:
    """A linkedit data blob (e.g. LC_FUNCTION_STARTS).

    :ivar file_offset: Absolute file offset.
    :ivar size: Size in bytes.
    """

    file_offset: int
    size: int


@dataclass(frozen=True)
class OffsetHit:
    """A single instruction hit referencing one of the target offsets.

    :ivar addr: Instruction VM address.
    :ivar kind: One of "add_imm", "sub_imm", "ldr_imm", "str_imm".
    :ivar offset: Byte offset used by the instruction.
    :ivar rn: Base register number (0-31).
    :ivar rd: Destination/source register number (0-31).
    """

    addr: int
    kind: str
    offset: int
    rn: int
    rd: int


def _decode_fixed_cstring(raw: bytes) -> str:
    """Decode a fixed-width C string field from a Mach-O structure.

    :param raw: Fixed-width byte field, null-terminated or padded.
    :returns: Decoded UTF-8-ish string.
    """

    nul_index: int = raw.find(b"\x00")
    if nul_index >= 0:
        raw = raw[0:nul_index]
    return raw.decode("utf-8", errors="replace")


def _read_file_range(path: Path, offset: int, size: int) -> bytes:
    """Read a contiguous range from a file.

    :param path: File path.
    :param offset: Byte offset.
    :param size: Byte size.
    :returns: Bytes read (may be shorter only if the file is truncated).
    """

    with path.open("rb") as f:
        f.seek(offset)
        data: bytes = f.read(size)
    return data


def _select_arm64_slice(path: Path) -> MachOSlice:
    """Select the arm64/arm64e slice from a universal Mach-O (or return thin slice).

    :param path: Binary path.
    :returns: Slice metadata.
    :raises ValueError: If the file is too small or the universal header is invalid.
    """

    head: bytes = _read_file_range(path, 0, 4096)
    if len(head) < 8:
        raise ValueError("file too small to contain a Mach-O header")

    magic_be: int = struct.unpack_from(">I", head, 0)[0]
    if magic_be != FAT_MAGIC and magic_be != FAT_MAGIC_64:
        file_size: int = path.stat().st_size
        return MachOSlice(arch="thin", file_offset=0, file_size=file_size)

    nfat_arch: int = struct.unpack_from(">I", head, 4)[0]
    if nfat_arch <= 0:
        raise ValueError("invalid fat header: nfat_arch <= 0")

    arch_size: int = 20 if magic_be == FAT_MAGIC else 32
    arch_table_size: int = 8 + (nfat_arch * arch_size)
    if len(head) < arch_table_size:
        head = _read_file_range(path, 0, arch_table_size)
        if len(head) < arch_table_size:
            raise ValueError("invalid fat header: arch table truncated")

    best: MachOSlice | None = None

    for idx in range(nfat_arch):
        off: int = 8 + (idx * arch_size)
        cputype: int = struct.unpack_from(">I", head, off + 0)[0]
        cpusubtype: int = struct.unpack_from(">I", head, off + 4)[0]
        if cputype != CPU_TYPE_ARM64:
            continue

        if magic_be == FAT_MAGIC:
            slice_off: int = struct.unpack_from(">I", head, off + 8)[0]
            slice_size: int = struct.unpack_from(">I", head, off + 12)[0]
        else:
            slice_off = int(struct.unpack_from(">Q", head, off + 8)[0])
            slice_size = int(struct.unpack_from(">Q", head, off + 16)[0])

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

    if best is None:
        raise ValueError("no arm64 slice found in universal binary")
    return best


def _parse_text_section_and_text_vmaddr(
    path: Path, slice_info: MachOSlice
) -> tuple[MachOSection, int, LinkeditBlob | None]:
    """Locate the `__TEXT,__text` section, the `__TEXT` segment vmaddr, and function-starts blob.

    :param path: Binary path.
    :param slice_info: Slice metadata.
    :returns: (text_section, text_segment_vmaddr, function_starts_blob_or_none)
    :raises ValueError: If parsing fails or the slice is not Mach-O 64-bit.
    """

    hdr: bytes = _read_file_range(path, slice_info.file_offset, 32)
    if len(hdr) < 32:
        raise ValueError("Mach-O slice too small")

    magic_le: int = struct.unpack_from("<I", hdr, 0)[0]
    if magic_le != MH_MAGIC_64:
        raise ValueError(f"unexpected Mach-O magic: 0x{magic_le:08X}")

    ncmds: int = struct.unpack_from("<I", hdr, 16)[0]
    sizeofcmds: int = struct.unpack_from("<I", hdr, 20)[0]
    if ncmds <= 0:
        raise ValueError("invalid Mach-O header: ncmds <= 0")
    if sizeofcmds <= 0:
        raise ValueError("invalid Mach-O header: sizeofcmds <= 0")

    cmds: bytes = _read_file_range(path, slice_info.file_offset + 32, sizeofcmds)
    if len(cmds) < sizeofcmds:
        raise ValueError("Mach-O load commands truncated")

    text_section: MachOSection | None = None
    text_segment_vmaddr: int | None = None
    function_starts: LinkeditBlob | None = None

    cmd_off: int = 0
    cmd_index: int = 0
    while cmd_off < sizeofcmds and cmd_index < ncmds:
        if (cmd_off + 8) > sizeofcmds:
            raise ValueError("Mach-O load command truncated (header)")

        cmd: int = struct.unpack_from("<I", cmds, cmd_off + 0)[0]
        cmdsize: int = struct.unpack_from("<I", cmds, cmd_off + 4)[0]
        if cmdsize < 8:
            raise ValueError("Mach-O load command has invalid cmdsize < 8")
        if (cmd_off + cmdsize) > sizeofcmds:
            raise ValueError("Mach-O load command truncated (cmdsize)")

        if cmd == LC_SEGMENT_64:
            if cmdsize < 72:
                raise ValueError("LC_SEGMENT_64 cmdsize too small")

            segname: str = _decode_fixed_cstring(cmds[cmd_off + 8 : cmd_off + 24])
            vmaddr: int = int(struct.unpack_from("<Q", cmds, cmd_off + 24)[0])
            nsects: int = struct.unpack_from("<I", cmds, cmd_off + 64)[0]

            if segname == "__TEXT":
                text_segment_vmaddr = vmaddr

            sect_off: int = cmd_off + 72
            for _ in range(nsects):
                if (sect_off + 80) > (cmd_off + cmdsize):
                    raise ValueError("LC_SEGMENT_64 sections truncated")

                sectname: str = _decode_fixed_cstring(cmds[sect_off + 0 : sect_off + 16])
                sect_segname: str = _decode_fixed_cstring(cmds[sect_off + 16 : sect_off + 32])
                addr: int = int(struct.unpack_from("<Q", cmds, sect_off + 32)[0])
                size: int = int(struct.unpack_from("<Q", cmds, sect_off + 40)[0])
                offset: int = struct.unpack_from("<I", cmds, sect_off + 48)[0]

                if (
                    text_section is None
                    and sect_segname == "__TEXT"
                    and sectname == "__text"
                    and size > 0
                ):
                    text_section = MachOSection(
                        segname=sect_segname,
                        sectname=sectname,
                        vmaddr=addr,
                        size=size,
                        file_offset=slice_info.file_offset + int(offset),
                    )

                sect_off += 80

        if cmd == LC_FUNCTION_STARTS:
            if cmdsize < 16:
                raise ValueError("LC_FUNCTION_STARTS cmdsize too small")

            dataoff: int = struct.unpack_from("<I", cmds, cmd_off + 8)[0]
            datasize: int = struct.unpack_from("<I", cmds, cmd_off + 12)[0]
            if datasize > 0:
                function_starts = LinkeditBlob(
                    file_offset=slice_info.file_offset + int(dataoff),
                    size=int(datasize),
                )

        cmd_off += cmdsize
        cmd_index += 1

    if text_section is None:
        raise ValueError("failed to locate __TEXT,__text section")
    if text_segment_vmaddr is None:
        raise ValueError("failed to locate __TEXT segment vmaddr")

    return text_section, int(text_segment_vmaddr), function_starts


def _decode_uleb128_stream(data: bytes) -> list[int]:
    """Decode a ULEB128 stream into a list of integers.

    :param data: Encoded bytes.
    :returns: Decoded integers.
    :raises ValueError: If the stream ends mid-integer.
    """

    results: list[int] = []
    i: int = 0
    while i < len(data):
        value: int = 0
        shift: int = 0
        while True:
            if i >= len(data):
                raise ValueError("ULEB128 stream truncated")
            byte: int = data[i]
            i += 1
            value |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                break
            shift += 7
            if shift > 63:
                raise ValueError("ULEB128 value too large")

        results.append(value)
        if value == 0:
            break
    return results


def _read_function_starts(
    path: Path,
    text_segment_vmaddr: int,
    function_starts_blob: LinkeditBlob | None,
    text_section: MachOSection,
) -> list[int]:
    """Load and decode function start addresses within the text section.

    :param path: Binary path.
    :param text_segment_vmaddr: VM address of the start of the __TEXT segment.
    :param function_starts_blob: Linkedit blob (LC_FUNCTION_STARTS), if present.
    :param text_section: __TEXT,__text section descriptor.
    :returns: Sorted function start addresses within [text_section.vmaddr, end).
    """

    if function_starts_blob is None:
        return []

    blob: bytes = _read_file_range(path, function_starts_blob.file_offset, function_starts_blob.size)
    if len(blob) < function_starts_blob.size:
        raise ValueError("LC_FUNCTION_STARTS blob truncated")

    deltas: list[int] = _decode_uleb128_stream(blob)

    starts: list[int] = []
    offset: int = 0
    for delta in deltas:
        if delta == 0:
            break
        offset += delta
        addr: int = text_segment_vmaddr + offset
        if addr < text_section.vmaddr:
            continue
        if addr >= (text_section.vmaddr + text_section.size):
            continue
        starts.append(addr)

    starts.sort()
    return starts


def _is_add_sub_imm(instr: int) -> bool:
    """Check if an instruction is an ADD/SUB (immediate)."""

    return (instr & 0x1F000000) == 0x11000000


def _decode_add_sub_imm(instr: int) -> tuple[str, int, int, int] | None:
    """Decode an ADD/SUB (immediate).

    :param instr: 32-bit instruction.
    :returns: (kind, offset_bytes, rn, rd) or None if shift encoding unsupported.
    """

    op: int = (instr >> 30) & 0x1
    shift: int = (instr >> 22) & 0x3
    if shift != 0 and shift != 1:
        return None
    imm12: int = (instr >> 10) & 0xFFF
    imm: int = imm12 << (12 * shift)
    rn: int = (instr >> 5) & 0x1F
    rd: int = instr & 0x1F
    kind: str = "sub_imm" if op == 1 else "add_imm"
    return kind, imm, rn, rd


def _is_ldr_str_uimm64(instr: int) -> bool:
    """Check if an instruction is LDR/STR (unsigned immediate) for 64-bit regs."""

    top: int = instr & 0xFFC00000
    return top == 0xF9400000 or top == 0xF9000000


def _is_ldr_str_uimm32(instr: int) -> bool:
    """Check if an instruction is LDR/STR (unsigned immediate) for 32-bit regs."""

    top: int = instr & 0xFFC00000
    return top == 0xB9400000 or top == 0xB9000000


def _decode_ldr_str_uimm(instr: int, scale: int) -> tuple[str, int, int, int]:
    """Decode an LDR/STR (unsigned immediate).

    :param instr: 32-bit instruction.
    :param scale: Byte scale (8 for X regs, 4 for W regs).
    :returns: (kind, offset_bytes, rn, rt)
    """

    is_load: bool = (instr & 0x00400000) != 0
    imm12: int = (instr >> 10) & 0xFFF
    offset: int = imm12 * scale
    rn: int = (instr >> 5) & 0x1F
    rt: int = instr & 0x1F
    kind: str = "ldr_imm" if is_load else "str_imm"
    return kind, offset, rn, rt


def _scan_for_offsets(
    text: MachOSection,
    text_bytes: bytes,
    function_starts: list[int],
    offsets: list[int],
    include_add_sub: bool,
    include_ldr_str: bool,
    include_fp: bool,
) -> dict[int, list[OffsetHit]]:
    """Scan `__text` for references to specified offsets, grouped by function start.

    :param text: Text section descriptor.
    :param text_bytes: Raw bytes for the text section.
    :param function_starts: Sorted function start addresses within this section.
    :param offsets: Offsets to match (byte offsets).
    :param include_add_sub: Include add/sub immediate matches.
    :param include_ldr_str: Include ldr/str unsigned-immediate matches.
    :param include_fp: Include matches whose base register is x29 (frame pointer).
    :returns: Mapping {function_start_addr: [hits]}.
    """

    offsets_set: set[int] = set(offsets)
    hits_by_func: dict[int, list[OffsetHit]] = {}

    fn_index: int = 0
    current_fn: int | None = None
    next_fn: int | None = None
    if len(function_starts) > 0:
        current_fn = function_starts[0]
        if len(function_starts) > 1:
            next_fn = function_starts[1]

    for insn_index, (instr,) in enumerate(struct.iter_unpack("<I", text_bytes)):
        addr: int = text.vmaddr + (insn_index * 4)

        while next_fn is not None and addr >= next_fn:
            fn_index += 1
            current_fn = next_fn
            if (fn_index + 1) < len(function_starts):
                next_fn = function_starts[fn_index + 1]
            else:
                next_fn = None

        if current_fn is None:
            continue
        if addr < current_fn:
            continue

        if include_add_sub and _is_add_sub_imm(instr):
            decoded: tuple[str, int, int, int] | None = _decode_add_sub_imm(instr)
            if decoded is not None:
                kind, off_bytes, rn, rd = decoded
                rn_is_stack: bool = rn == 31 or (include_fp is False and rn == 29)
                rd_is_stack: bool = rd == 31
                if (rn_is_stack is False) and (rd_is_stack is False) and off_bytes in offsets_set:
                    hit: OffsetHit = OffsetHit(
                        addr=addr,
                        kind=kind,
                        offset=off_bytes,
                        rn=rn,
                        rd=rd,
                    )
                    hits_by_func.setdefault(current_fn, []).append(hit)

        if include_ldr_str and _is_ldr_str_uimm64(instr):
            kind, off_bytes, rn, rt = _decode_ldr_str_uimm(instr, scale=8)
            rn_is_stack = rn == 31 or (include_fp is False and rn == 29)
            if (rn_is_stack is False) and off_bytes in offsets_set:
                hit = OffsetHit(
                    addr=addr,
                    kind=kind,
                    offset=off_bytes,
                    rn=rn,
                    rd=rt,
                )
                hits_by_func.setdefault(current_fn, []).append(hit)

        if include_ldr_str and _is_ldr_str_uimm32(instr):
            kind, off_bytes, rn, rt = _decode_ldr_str_uimm(instr, scale=4)
            rn_is_stack = rn == 31 or (include_fp is False and rn == 29)
            if (rn_is_stack is False) and off_bytes in offsets_set:
                hit = OffsetHit(
                    addr=addr,
                    kind=kind,
                    offset=off_bytes,
                    rn=rn,
                    rd=rt,
                )
                hits_by_func.setdefault(current_fn, []).append(hit)

    return hits_by_func


def _render_text(
    offsets: list[int],
    hits_by_func: dict[int, list[OffsetHit]],
    require_all: bool,
    limit: int | None,
) -> str:
    """Render results as text.

    :param offsets: Target offsets.
    :param hits_by_func: Mapping of function start -> hits.
    :param require_all: Whether to only include functions that hit all offsets.
    :param limit: Optional max number of functions to output.
    :returns: Human-readable output.
    """

    want: set[int] = set(offsets)

    def passes(hits: list[OffsetHit]) -> bool:
        seen: set[int] = {h.offset for h in hits}
        if require_all:
            return want.issubset(seen)
        return len(seen.intersection(want)) > 0

    candidates: list[tuple[int, list[OffsetHit]]] = []
    for fn, hits in hits_by_func.items():
        if passes(hits):
            candidates.append((fn, hits))

    candidates.sort(key=lambda t: t[0])

    if limit is not None and limit > 0 and len(candidates) > limit:
        candidates = candidates[0:limit]

    lines: list[str] = []
    lines.append("Targets: " + ", ".join([f"0x{o:x}" for o in offsets]))
    lines.append(f"Functions matched: {len(candidates)}")
    lines.append("")

    for fn, hits in candidates:
        by_off: dict[int, int] = {}
        for h in hits:
            by_off[h.offset] = by_off.get(h.offset, 0) + 1

        lines.append(f"0x{fn:016x}: hits=" + ", ".join([f"0x{k:x}:{v}" for k, v in sorted(by_off.items())]))
        for h in hits[0:20]:
            lines.append(
                f"  0x{h.addr:016x}  {h.kind:7s}  off=0x{h.offset:x}  rn={h.rn:2d} rd={h.rd:2d}"
            )
        if len(hits) > 20:
            lines.append(f"  ... ({len(hits) - 20} more hits)")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _render_json(
    offsets: list[int],
    hits_by_func: dict[int, list[OffsetHit]],
    require_all: bool,
    limit: int | None,
) -> str:
    """Render results as JSON.

    :param offsets: Target offsets.
    :param hits_by_func: Mapping of function start -> hits.
    :param require_all: Whether to only include functions that hit all offsets.
    :param limit: Optional max number of functions to output.
    :returns: JSON string.
    """

    want: set[int] = set(offsets)

    def passes(hits: list[OffsetHit]) -> bool:
        seen: set[int] = {h.offset for h in hits}
        if require_all:
            return want.issubset(seen)
        return len(seen.intersection(want)) > 0

    funcs: list[dict[str, object]] = []
    for fn, hits in hits_by_func.items():
        if passes(hits):
            funcs.append(
                {
                    "function_start": fn,
                    "hits": [
                        {
                            "addr": h.addr,
                            "kind": h.kind,
                            "offset": h.offset,
                            "rn": h.rn,
                            "rd": h.rd,
                        }
                        for h in hits
                    ],
                }
            )

    funcs.sort(key=lambda d: int(d["function_start"]))

    if limit is not None and limit > 0 and len(funcs) > limit:
        funcs = funcs[0:limit]

    payload: dict[str, object] = {
        "offsets": offsets,
        "require_all": require_all,
        "functions": funcs,
    }
    return json.dumps(payload, indent=2, sort_keys=False) + "\n"


def main(argv: list[str]) -> int:
    """CLI entrypoint.

    :param argv: Argv list (excluding program name).
    :returns: Exit code.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default=DEFAULT_MUSIC_BINARY, help="Path to Mach-O binary")
    parser.add_argument(
        "--offset",
        action="append",
        required=True,
        help="Byte offset to match (hex like 0x90 or decimal like 144). Repeatable.",
    )
    parser.add_argument("--require-all", action="store_true", help="Only include functions that hit all offsets")
    parser.add_argument("--no-add-sub", action="store_true", help="Do not scan ADD/SUB (immediate)")
    parser.add_argument("--ldr-str", action="store_true", help="Also scan LDR/STR (unsigned immediate)")
    parser.add_argument(
        "--include-fp",
        action="store_true",
        help="Include hits that use x29 as the base register (frame-pointer locals)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format",
    )
    parser.add_argument("--limit", type=int, default=0, help="Max number of functions to output (0 = unlimited)")
    args = parser.parse_args(argv)

    offsets: list[int] = []
    for raw in args.offset:
        value: int
        if raw.lower().startswith("0x"):
            value = int(raw, 16)
        else:
            value = int(raw, 10)
        if value < 0:
            raise ValueError("--offset must be >= 0")
        offsets.append(value)

    binary_path: Path = Path(args.binary)
    slice_info: MachOSlice = _select_arm64_slice(binary_path)
    text_section, text_vmaddr, function_starts_blob = _parse_text_section_and_text_vmaddr(
        binary_path, slice_info
    )
    function_starts: list[int] = _read_function_starts(
        binary_path, text_vmaddr, function_starts_blob, text_section
    )

    if len(function_starts) == 0:
        raise ValueError("no function starts decoded (unexpected); cannot group hits")

    text_bytes: bytes = _read_file_range(binary_path, text_section.file_offset, text_section.size)
    if len(text_bytes) < text_section.size:
        raise ValueError("__text section bytes truncated")

    include_add_sub: bool = args.no_add_sub is False
    include_ldr_str: bool = args.ldr_str is True
    include_fp: bool = args.include_fp is True

    hits_by_func: dict[int, list[OffsetHit]] = _scan_for_offsets(
        text=text_section,
        text_bytes=text_bytes,
        function_starts=function_starts,
        offsets=offsets,
        include_add_sub=include_add_sub,
        include_ldr_str=include_ldr_str,
        include_fp=include_fp,
    )

    limit: int | None = None
    if args.limit > 0:
        limit = args.limit

    if args.format == "json":
        sys.stdout.write(_render_json(offsets, hits_by_func, args.require_all, limit))
    else:
        sys.stdout.write(_render_text(offsets, hits_by_func, args.require_all, limit))

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
