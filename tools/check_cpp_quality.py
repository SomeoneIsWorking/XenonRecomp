#!/usr/bin/env python3
"""Non-mutating Clang format and tidy gate for the maintained recompiler seam."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path


FORMATTED = (
    "XenonAnalyse/function.cpp",
    "XenonAnalyse/function.h",
    "XenonRecomp/data_range.cpp",
    "XenonRecomp/data_range.h",
    "XenonRecomp/function_binding.cpp",
    "XenonRecomp/function_binding.h",
    "XenonRecomp/function_scan.cpp",
    "XenonRecomp/function_scan.h",
    "XenonRecomp/main.cpp",
    "XenonRecomp/recompiler.h",
    "XenonRecomp/recompiler_config.h",
    "XenonRecomp/switch_extent.cpp",
    "XenonRecompTests/binding_emission_test.cpp",
    "XenonRecompTests/binding_link_fixture.h",
    "XenonRecompTests/binding_link_generated.cpp",
    "XenonRecompTests/binding_link_override.cpp",
    "XenonRecompTests/data_range_test.cpp",
    "XenonRecompTests/disassembler_state_test.cpp",
    "XenonRecompTests/function_scan_test.cpp",
    "XenonRecompTests/instruction_emission_test.cpp",
    "XenonUtils/disasm.cpp",
    "XenonUtils/disasm.h",
    "XenonUtils/image.cpp",
    "XenonUtils/image.h",
    "XenonUtils/xex.cpp",
    "XenonUtils/xex.h",
    "XexInspect/inspect.cpp",
    "XexInspect/inspect.h",
    "XexInspect/main.cpp",
    "XexInspect/pattern_scan.cpp",
    "XexInspect/pattern_scan.h",
    "XexInspect/sha256.cpp",
    "XexInspect/sha256.h",
    "XexInspectTests/inspect_tests.cpp",
)

TIDY_UNITS = (
    "XenonRecomp/data_range.cpp",
    "XenonRecomp/function_binding.cpp",
    "XenonRecomp/function_scan.cpp",
    "XenonRecomp/main.cpp",
    "XenonRecomp/switch_extent.cpp",
    "XenonRecompTests/binding_emission_test.cpp",
    "XenonRecompTests/binding_link_generated.cpp",
    "XenonRecompTests/binding_link_override.cpp",
    "XenonRecompTests/data_range_test.cpp",
    "XenonRecompTests/disassembler_state_test.cpp",
    "XenonRecompTests/function_scan_test.cpp",
    "XenonRecompTests/instruction_emission_test.cpp",
    "XenonUtils/disasm.cpp",
    "XenonUtils/image.cpp",
    "XenonUtils/xex.cpp",
    "XexInspect/inspect.cpp",
    "XexInspect/main.cpp",
    "XexInspect/pattern_scan.cpp",
    "XexInspect/sha256.cpp",
    "XexInspectTests/inspect_tests.cpp",
)

RANGED_SOURCES = {
    "XenonRecomp/recompiler.cpp": (
        (1, 7),
        (199, 272),
        (753, 768),
        (1171, 1177),
    ),
    "XenonRecomp/recompiler_config.cpp": ((72, 97),),
}


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

    required_units = (*TIDY_UNITS, *RANGED_SOURCES)
    missing = [unit for unit in required_units if (root / unit).resolve() not in sources]
    if missing:
        print("REFUSING: compile database omits " + ", ".join(missing), file=sys.stderr)
        return 1

    subprocess.run(
        [clang_format, "--dry-run", "--Werror", *FORMATTED], cwd=root, check=True
    )
    for source, ranges in RANGED_SOURCES.items():
        command = [clang_format, "--dry-run", "--Werror"]
        command.extend(f"-lines={first}:{last}" for first, last in ranges)
        command.append(source)
        subprocess.run(command, cwd=root, check=True)
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
        [{"name": source, "lines": ranges} for source, ranges in RANGED_SOURCES.items()],
        separators=(",", ":"),
    )
    subprocess.run(
        [
            clang_tidy,
            "-p",
            str(build),
            *RANGED_SOURCES,
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
