#!/usr/bin/env python3
"""Refuse new source monoliths and growth of the legacy recompiler file."""

from __future__ import annotations

import sys
from pathlib import Path


SOURCE_ROOTS = (
    "XenonAnalyse",
    "XenonRecomp",
    "XenonRecompTests",
    "XenonTests",
    "XenonUtils",
    "XexInspect",
    "XexInspectTests",
    "tools",
)
SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".h", ".hpp", ".py"}
DEFAULT_LIMIT = 1200
LEGACY_LIMITS = {"XenonRecomp/recompiler.cpp": 2728}


def violations(entries: dict[str, int]) -> list[str]:
    failures = []
    for path, count in sorted(entries.items()):
        limit = LEGACY_LIMITS.get(path, DEFAULT_LIMIT)
        if count > limit:
            failures.append(f"{path}: {count} lines exceeds {limit}")
        elif path in LEGACY_LIMITS and count < limit:
            failures.append(
                f"{path}: reduced to {count} lines; ratchet its legacy limit below {limit}"
            )
    return failures


def source_counts(root: Path) -> dict[str, int]:
    counts = {}
    for source_root in SOURCE_ROOTS:
        for path in (root / source_root).rglob("*"):
            if path.is_file() and path.suffix in SOURCE_SUFFIXES:
                relative = path.relative_to(root).as_posix()
                counts[relative] = len(path.read_bytes().splitlines())
    return counts


def selftest() -> int:
    assert not violations({"XenonUtils/small.cpp": 1200,
                           "XenonRecomp/recompiler.cpp": 2728})
    assert "exceeds" in violations({"XenonUtils/new.cpp": 1201})[0]
    assert "exceeds" in violations({"XenonRecomp/recompiler.cpp": 2729})[0]
    assert "ratchet" in violations({"XenonRecomp/recompiler.cpp": 2727})[0]
    print("source-structure selftest passed: new, growth, and ratchet controls exercised")
    return 0


def main(argv: list[str]) -> int:
    if argv[1:] == ["--selftest"]:
        return selftest()
    if len(argv) != 1:
        print(f"usage: {argv[0]} [--selftest]", file=sys.stderr)
        return 2

    root = Path(__file__).resolve().parents[1]
    failures = violations(source_counts(root))
    if failures:
        for failure in failures:
            print(f"REFUSING: {failure}", file=sys.stderr)
        return 1
    print("source-structure gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
