"""Platform and binary selection helpers."""

from __future__ import annotations

import os
import platform
import subprocess
from typing import Optional


DEFAULT_GP_OS_VERSION = "Ubuntu 26.04 LTS"


def _read_os_release_pretty_name() -> Optional[str]:
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as f:
            for line in f:
                if not line.startswith("PRETTY_NAME="):
                    continue
                value = line.split("=", 1)[1].strip()
                if len(value) >= 2 and value[0] == value[-1] == '"':
                    value = value[1:-1]
                return value or None
    except Exception:
        return None
    return None


def _run_first_success(commands: list[list[str]]) -> Optional[str]:
    for cmd in commands:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
        except Exception:
            continue
        if result.returncode != 0:
            continue
        value = (result.stdout or "").strip()
        if not value:
            continue
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        return value
    return None


def get_gp_client_os() -> str:
    """Return the GlobalProtect client OS string."""
    configured = (os.environ.get("MS_SSO_GP_CLIENT_OS") or "").strip()
    if configured in {"Linux", "Windows", "Mac"}:
        return configured
    return {"Darwin": "Mac", "Windows": "Windows"}.get(platform.system(), "Linux")


def get_gp_os_version() -> str:
    """Return the OS version string reported to GlobalProtect."""
    configured = (os.environ.get("MS_SSO_GP_OS_VERSION") or "").strip()
    if configured and configured.lower() != "auto":
        return configured

    detected = _detect_os_version()
    if detected:
        return detected

    return DEFAULT_GP_OS_VERSION


def _detect_os_version() -> Optional[str]:
    if platform.system() == "Darwin":
        version = platform.mac_ver()[0]
        return f"macOS {version}" if version else platform.platform()
    if platform.system() == "Windows":
        return platform.platform()
    detected = _run_first_success(
        [
            ["lsb_release", "-ds"],
        ]
    )
    if detected:
        return detected

    os_release = _read_os_release_pretty_name()
    if os_release:
        return os_release

    detected = _run_first_success(
        [
            ["/run/current-system/sw/bin/nixos-version"],
        ]
    )
    if detected:
        return detected

    return platform.platform()


def get_gp_hip_report_wrapper() -> Optional[str]:
    """Return the HIP report wrapper path for GlobalProtect, when available."""
    configured = (os.environ.get("MS_SSO_GP_HIP_REPORT_WRAPPER") or "").strip()
    if configured:
        return configured

    candidates = [
        "/usr/libexec/ms-sso-openconnect-gp-hipreport",
        "/usr/local/libexec/ms-sso-openconnect-gp-hipreport",
        os.path.join(os.path.dirname(__file__), "gp_hipreport.py"),
    ]
    for candidate in candidates:
        if os.path.exists(candidate) and os.access(candidate, os.X_OK):
            return candidate

    return None


def get_openconnect_binary(protocol: str) -> str:
    """Return the configured OpenConnect-compatible binary for a protocol."""
    if protocol == "gp":
        gp_binary = (os.environ.get("MS_SSO_GP_OPENCONNECT_BIN") or "").strip()
        if gp_binary:
            return gp_binary

    configured = (os.environ.get("MS_SSO_OPENCONNECT_BIN") or "").strip()
    if configured:
        return configured

    return "openconnect"
