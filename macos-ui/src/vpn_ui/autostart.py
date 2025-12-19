"""Autostart management for the VPN UI application on macOS."""

import os
import plistlib
import sys
from pathlib import Path
from typing import Optional

from vpn_ui.constants import APP_ID, APP_NAME

# LaunchAgents directory
LAUNCH_AGENTS_DIR = Path.home() / "Library" / "LaunchAgents"
LAUNCH_AGENT_FILE = LAUNCH_AGENTS_DIR / f"{APP_ID}.plist"


def _find_executable() -> str:
    """Find the executable path for the application.

    Returns:
        Path to the executable
    """
    # Check if running from .app bundle
    app_bundle_paths = [
        Path("/Applications/MS SSO OpenConnect.app/Contents/MacOS/ms-sso-openconnect-ui"),
        Path.home() / "Applications/MS SSO OpenConnect.app/Contents/MacOS/ms-sso-openconnect-ui",
    ]

    for path in app_bundle_paths:
        if path.exists():
            return str(path)

    # Check standard install paths
    installed_paths = [
        "/usr/local/bin/ms-sso-openconnect-ui",
        str(Path.home() / ".local/bin/ms-sso-openconnect-ui"),
    ]

    for path in installed_paths:
        if Path(path).exists():
            return path

    # Fallback to the command name (should be in PATH)
    return "ms-sso-openconnect-ui"


def _create_launch_agent_plist() -> dict:
    """Create the LaunchAgent plist dictionary.

    Returns:
        Dictionary suitable for plistlib
    """
    exec_path = _find_executable()

    return {
        "Label": APP_ID,
        "ProgramArguments": [exec_path],
        "RunAtLoad": True,
        "KeepAlive": False,
        "ProcessType": "Interactive",
        "LSUIElement": True,
        "StandardOutPath": str(Path.home() / "Library/Logs" / f"{APP_ID}.log"),
        "StandardErrorPath": str(Path.home() / "Library/Logs" / f"{APP_ID}.error.log"),
    }


def is_autostart_enabled() -> bool:
    """Check if autostart is currently enabled.

    Returns:
        True if LaunchAgent plist exists
    """
    return LAUNCH_AGENT_FILE.exists()


def enable_autostart() -> bool:
    """Enable autostart for the application.

    Returns:
        True if successfully enabled
    """
    try:
        # Create LaunchAgents directory if it doesn't exist
        LAUNCH_AGENTS_DIR.mkdir(parents=True, exist_ok=True)

        # Create logs directory
        logs_dir = Path.home() / "Library/Logs"
        logs_dir.mkdir(parents=True, exist_ok=True)

        # Generate and write plist
        plist_data = _create_launch_agent_plist()
        with open(LAUNCH_AGENT_FILE, "wb") as f:
            plistlib.dump(plist_data, f)

        # Load the LaunchAgent
        os.system(f'launchctl load "{LAUNCH_AGENT_FILE}"')

        return True
    except Exception as e:
        print(f"Failed to enable autostart: {e}", file=sys.stderr)
        return False


def disable_autostart() -> bool:
    """Disable autostart for the application.

    Returns:
        True if successfully disabled
    """
    try:
        # Unload the LaunchAgent first
        if LAUNCH_AGENT_FILE.exists():
            os.system(f'launchctl unload "{LAUNCH_AGENT_FILE}"')
            LAUNCH_AGENT_FILE.unlink()
        return True
    except Exception as e:
        print(f"Failed to disable autostart: {e}", file=sys.stderr)
        return False


def set_autostart(enabled: bool) -> bool:
    """Set autostart state.

    Args:
        enabled: True to enable, False to disable

    Returns:
        True if operation succeeded
    """
    if enabled:
        return enable_autostart()
    else:
        return disable_autostart()


def get_autostart_file_path() -> Path:
    """Get the path to the autostart plist file.

    Returns:
        Path to the LaunchAgent plist
    """
    return LAUNCH_AGENT_FILE
