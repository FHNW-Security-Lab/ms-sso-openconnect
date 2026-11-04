#!/usr/bin/env python3
"""Print the highest macOS deployment target of a staged package's binaries."""

import re
import subprocess
import sys
from pathlib import Path


def minimum_version(root: Path) -> str:
    # Mach-O and universal binary magic values, in either byte order.
    magic_values = {
        b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
    }
    minimum = (11, 0, 0)
    found = False
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        with path.open("rb") as handle:
            if handle.read(4) not in magic_values:
                continue
        # vtool treats parentheses in Chromium helper filenames literally;
        # otool interprets them as archive member syntax.
        output = subprocess.check_output(["xcrun", "vtool", "-show-build", str(path)], text=True)
        command = None
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("cmd LC_"):
                command = line.split()[1]
            key = "minos" if command == "LC_BUILD_VERSION" else "version"
            if command not in {"LC_BUILD_VERSION", "LC_VERSION_MIN_MACOSX"}:
                continue
            match = re.fullmatch(rf"{key}\s+(\d+(?:\.\d+){{1,2}})", line)
            if match:
                parts = tuple(int(value) for value in match.group(1).split("."))
                minimum = max(minimum, parts + (0,) * (3 - len(parts)))
                found = True
                command = None
    if not found:
        raise RuntimeError("No macOS deployment targets found in the staged package")
    return ".".join(map(str, minimum if minimum[2] else minimum[:2]))


if __name__ == "__main__":
    print(minimum_version(Path(sys.argv[1])))
