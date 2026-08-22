#!/usr/bin/env python3
"""Non-mutating Clang format and tidy gate for the maintained recompiler seam."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path


FORMATTED = (
    "XenonRecomp/function_binding.cpp",
    "XenonRecomp/function_binding.h",
    "XenonRecompTests/binding_emission_test.cpp",
    "XenonRecompTests/binding_link_fixture.h",
    "XenonRecompTests/binding_link_generated.cpp",
    "XenonRecompTests/binding_link_override.cpp",
)

TIDY_UNITS = (
    "XenonRecomp/function_binding.cpp",
    "XenonRecompTests/binding_emission_test.cpp",
    "XenonRecompTests/binding_link_generated.cpp",
    "XenonRecompTests/binding_link_override.cpp",
)

RECOMPILER_RANGES = ((1, 5), (2696, 2697), (2762, 2762), (2972, 2979))


def require_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise RuntimeError(f"{name} is not installed")
    return path


def compile_database_sources(database: Path) -> set[Path]:
    if not database.is_file():
        raise RuntimeError(f"{database} is missing")
    try:
        entries = json.loads(database.read_text(encoding="utf-8"))
        sources = set()
        for entry in entries:
            source = Path(entry["file"])
            if not source.is_absolute():
                source = Path(entry["directory"]) / source
            sources.add(source.resolve())
        return sources
    except (OSError, KeyError, TypeError, ValueError) as error:
        raise RuntimeError(f"{database} is invalid: {error}") from error


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} BUILD_DIR", file=sys.stderr)
        return 2

    root = Path(__file__).resolve().parents[1]
    build = Path(argv[1]).resolve()
    try:
        clang_format = require_tool("clang-format")
        clang_tidy = require_tool("clang-tidy")
        clang_cxx = require_tool("clang++")
        sources = compile_database_sources(build / "compile_commands.json")
    except RuntimeError as error:
        print(f"REFUSING: {error}", file=sys.stderr)
        return 1

    required_units = (*TIDY_UNITS, "XenonRecomp/recompiler.cpp")
    missing = [unit for unit in required_units if (root / unit).resolve() not in sources]
    if missing:
        print("REFUSING: compile database omits " + ", ".join(missing), file=sys.stderr)
        return 1

    subprocess.run(
        [clang_format, "--dry-run", "--Werror", *FORMATTED], cwd=root, check=True
    )
    recomp_format = [clang_format, "--dry-run", "--Werror"]
    recomp_format.extend(
        f"-lines={first}:{last}" for first, last in RECOMPILER_RANGES
    )
    recomp_format.append("XenonRecomp/recompiler.cpp")
    subprocess.run(recomp_format, cwd=root, check=True)
    resource_dir = subprocess.run(
        [clang_cxx, "-print-resource-dir"], check=True, capture_output=True, text=True
    ).stdout.strip()
    subprocess.run(
        [
            clang_tidy,
            "-p",
            str(build),
            f"--extra-arg=-resource-dir={resource_dir}",
            "--quiet",
            *TIDY_UNITS,
        ],
        cwd=root,
        check=True,
    )
    line_filter = json.dumps(
        [{"name": "XenonRecomp/recompiler.cpp", "lines": RECOMPILER_RANGES}],
        separators=(",", ":"),
    )
    subprocess.run(
        [
            clang_tidy,
            "-p",
            str(build),
            "XenonRecomp/recompiler.cpp",
            f"-line-filter={line_filter}",
            f"--extra-arg=-resource-dir={resource_dir}",
            "--quiet",
        ],
        cwd=root,
        check=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
