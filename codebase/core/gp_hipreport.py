#!/usr/bin/env python3
"""GlobalProtect HIP wrapper with configurable Linux OS reporting."""

from __future__ import annotations

import html
import os
import platform
import re
import shutil
import subprocess
import sys


def _detected_os_version() -> str:
    """Keep HIP reporting useful when privilege escalation filters environment."""
    try:
        return platform.freedesktop_os_release().get("PRETTY_NAME") or platform.platform()
    except OSError:
        return platform.platform()


def _find_base_hipreport() -> str | None:
    configured = (os.environ.get("MS_SSO_GP_HIP_REPORT_BASE") or "").strip()
    if configured:
        return configured

    candidates = [
        "/usr/lib/openconnect/hipreport.sh",
        "/usr/libexec/openconnect/hipreport.sh",
        "/usr/local/lib/openconnect/hipreport.sh",
        "/usr/local/libexec/openconnect/hipreport.sh",
    ]
    for candidate in candidates:
        if os.path.exists(candidate) and os.access(candidate, os.X_OK):
            return candidate

    return shutil.which("hipreport.sh")


def main() -> int:
    base = _find_base_hipreport()
    if not base:
        print("Could not find OpenConnect hipreport.sh", file=sys.stderr)
        return 127

    proc = subprocess.run(
        [base, *sys.argv[1:]],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        return proc.returncode

    os_version = (
        os.environ.get("MS_SSO_GP_OS_VERSION")
        or os.environ.get("MS_SSO_GP_HIP_OS")
        or ""
    ).strip()
    if not os_version or os_version.lower() == "auto":
        os_version = _detected_os_version()
    os_vendor = (os.environ.get("MS_SSO_GP_OS_VENDOR") or "Linux").strip()

    output = proc.stdout
    if os_version:
        output = re.sub(
            r"<os>.*?</os>",
            lambda _: f"<os>{html.escape(os_version)}</os>",
            output,
            count=1,
            flags=re.DOTALL,
        )
    if os_vendor:
        output = re.sub(
            r"<os-vendor>.*?</os-vendor>",
            lambda _: f"<os-vendor>{html.escape(os_vendor)}</os-vendor>",
            output,
            count=1,
            flags=re.DOTALL,
        )

    sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
