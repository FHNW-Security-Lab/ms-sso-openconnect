"""Autostart management for the VPN UI application."""

import os
import sys
from pathlib import Path
from typing import Optional

from vpn_ui.constants import APP_ID, APP_NAME

# XDG autostart directory
AUTOSTART_DIR = Path.home() / ".config" / "autostart"
AUTOSTART_FILE = AUTOSTART_DIR / f"{APP_ID}.desktop"

# Desktop file content template
DESKTOP_TEMPLATE = """[Desktop Entry]
Name={name}
GenericName=VPN Client
Comment=Connect to VPN with Microsoft SSO authentication
Exec={exec_path}
Icon={app_id}
Terminal=false
Type=Application
Categories=Network;Security;
X-GNOME-Autostart-enabled=true
X-GNOME-Autostart-Delay=5
StartupNotify=false
NoDisplay=false
"""


def _find_executable() -> str:
    """Find the executable path for the application.

    Returns:
        Path to the executable
    """
    # Check if running from installed location
    installed_paths = [
        "/usr/bin/ms-sso-openconnect-ui",
        "/usr/local/bin/ms-sso-openconnect-ui",
        str(Path.home() / ".local/bin/ms-sso-openconnect-ui"),
    ]

    for path in installed_paths:
        if Path(path).exists():
            return path

    # Check if running as AppImage
    appimage_path = os.environ.get("APPIMAGE")
    if appimage_path and Path(appimage_path).exists():
        return appimage_path

    # Fallback to the command name (should be in PATH)
    return "ms-sso-openconnect-ui"


def is_autostart_enabled() -> bool:
    """Check if autostart is currently enabled.

    Returns:
        True if autostart desktop file exists and is enabled
    """
    if not AUTOSTART_FILE.exists():
        return False

    try:
        content = AUTOSTART_FILE.read_text()
        # Check for X-GNOME-Autostart-enabled=false or Hidden=true
        for line in content.splitlines():
            line = line.strip().lower()
            if line == "x-gnome-autostart-enabled=false":
                return False
            if line == "hidden=true":
                return False
        return True
    except Exception:
        return False


def enable_autostart() -> bool:
    """Enable autostart for the application.

    Returns:
        True if successfully enabled
    """
    try:
        # Create autostart directory if it doesn't exist
        AUTOSTART_DIR.mkdir(parents=True, exist_ok=True)

        # Find the executable
        exec_path = _find_executable()

        # Generate desktop file content
        content = DESKTOP_TEMPLATE.format(
            name=APP_NAME,
            exec_path=exec_path,
            app_id=APP_ID,
        )

        # Write the desktop file
        AUTOSTART_FILE.write_text(content)

        # Make it executable (not strictly required but good practice)
        AUTOSTART_FILE.chmod(0o755)

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
        if AUTOSTART_FILE.exists():
            AUTOSTART_FILE.unlink()
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
    """Get the path to the autostart desktop file.

    Returns:
        Path to the autostart file
    """
    return AUTOSTART_FILE
