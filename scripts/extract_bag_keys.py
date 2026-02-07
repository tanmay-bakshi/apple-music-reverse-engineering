#!/usr/bin/env python3
"""
Extract `bag://...` keys from a binary via `/usr/bin/strings`.

This repository uses bag keys as a primary static-analysis clue for where Apple
Music (and related StoreServices code) discovers endpoint URLs and feature flags.
"""

import argparse
import json
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path


DEFAULT_MUSIC_BINARY: str = "/System/Applications/Music.app/Contents/MacOS/Music"
STRINGS_BIN: str = "/usr/bin/strings"


@dataclass(frozen=True)
class BagKeyReport:
    """A report of discovered bag keys.

    :ivar keys: Sorted unique bag keys.
    :ivar grouped: Map of group name to sorted unique bag keys.
    """

    keys: list[str]
    grouped: dict[str, list[str]]


def _iter_strings(binary_path: Path, min_length: int) -> Iterator[str]:
    """Yield `strings(1)` output lines for a binary.

    :param binary_path: File path to scan.
    :param min_length: Minimum string length, passed to `strings -n`.
    :yields: Lines of text from `strings`.
    :raises RuntimeError: If `strings` fails.
    """

    cmd: list[str] = [STRINGS_BIN, "-a", "-n", str(min_length), str(binary_path)]
    proc: subprocess.Popen[str] = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.stdout is None:
        raise RuntimeError("strings stdout pipe was not created")
    if proc.stderr is None:
        raise RuntimeError("strings stderr pipe was not created")

    for line in proc.stdout:
        yield line.rstrip("\n")

    stderr: str = proc.stderr.read()
    rc: int = proc.wait()
    if rc != 0:
        raise RuntimeError(f"strings failed (exit={rc}): {stderr.strip()}")


def _extract_bag_urls(line: str) -> list[str]:
    """Extract `bag://...` URLs from a line.

    :param line: A single line of text (typically a `strings` output line).
    :returns: A list of extracted `bag://...` substrings.
    """

    results: list[str] = []
    search_from: int = 0
    while True:
        start: int = line.find("bag://", search_from)
        if start < 0:
            break

        end: int = start
        while end < len(line) and line[end].isspace() is False:
            end += 1

        results.append(line[start:end])
        search_from = end

    return results


def _group_key(key: str) -> str:
    """Return a stable grouping label for a bag key.

    :param key: A `bag://...` key.
    :returns: Group label (first path component, or "<empty>").
    """

    prefix: str = "bag://"
    if key.startswith(prefix) is False:
        return "<non-bag>"

    remainder: str = key[len(prefix) :]
    if len(remainder) == 0:
        return "<empty>"

    slash_index: int = remainder.find("/")
    if slash_index < 0:
        return remainder

    if slash_index == 0:
        return "<empty>"

    return remainder[0:slash_index]


def build_report(binary_path: Path, min_length: int) -> BagKeyReport:
    """Build a report for a given binary.

    :param binary_path: File path to scan.
    :param min_length: Minimum string length for `strings -n`.
    :returns: A report with unique keys and groups.
    """

    unique: set[str] = set()
    grouped: dict[str, set[str]] = {}

    for line in _iter_strings(binary_path=binary_path, min_length=min_length):
        bag_urls: list[str] = _extract_bag_urls(line)
        if len(bag_urls) == 0:
            continue

        for url in bag_urls:
            unique.add(url)
            group: str = _group_key(url)
            if group not in grouped:
                grouped[group] = set()
            grouped[group].add(url)

    keys: list[str] = sorted(unique)
    grouped_out: dict[str, list[str]] = {}
    for group_name in sorted(grouped.keys()):
        grouped_out[group_name] = sorted(grouped[group_name])

    return BagKeyReport(keys=keys, grouped=grouped_out)


def _render_text(report: BagKeyReport) -> str:
    """Render report as plain text.

    :param report: Bag key report.
    :returns: Rendered text.
    """

    return "\n".join(report.keys) + "\n"


def _render_json(report: BagKeyReport) -> str:
    """Render report as JSON.

    :param report: Bag key report.
    :returns: Rendered JSON.
    """

    payload: dict[str, object] = {"keys": report.keys, "grouped": report.grouped}
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _render_md(report: BagKeyReport) -> str:
    """Render report as Markdown.

    :param report: Bag key report.
    :returns: Rendered markdown.
    """

    lines: list[str] = []
    lines.append(f"# Bag Keys ({len(report.keys)})")
    lines.append("")

    for group_name, keys in report.grouped.items():
        lines.append(f"## {group_name} ({len(keys)})")
        lines.append("")
        for key in keys:
            lines.append(f"- `{key}`")
        lines.append("")

    return "\n".join(lines)


def main(argv: list[str]) -> int:
    """CLI entrypoint.

    :param argv: Raw argv (excluding program name).
    :returns: Process exit code.
    """

    parser = argparse.ArgumentParser(description="Extract bag:// keys from a binary")
    parser.add_argument(
        "--binary",
        type=Path,
        default=Path(DEFAULT_MUSIC_BINARY),
        help=f"Binary path (default: {DEFAULT_MUSIC_BINARY})",
    )
    parser.add_argument(
        "--min-length",
        type=int,
        default=4,
        help="Minimum string length passed to strings -n (default: 4)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "md"],
        default="text",
        help="Output format (default: text)",
    )
    args = parser.parse_args(argv)

    binary_path: Path = args.binary
    if binary_path.exists() is False:
        sys.stderr.write(f"error: binary not found: {binary_path}\n")
        return 2

    report: BagKeyReport = build_report(binary_path=binary_path, min_length=args.min_length)

    if args.format == "json":
        sys.stdout.write(_render_json(report))
        return 0
    if args.format == "md":
        sys.stdout.write(_render_md(report))
        return 0

    sys.stdout.write(_render_text(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
