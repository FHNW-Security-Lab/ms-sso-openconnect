"""Autostart management for the VPN UI application."""

import os
import sys
import plistlib
from pathlib import Path
from typing import Optional

from vpn_ui.constants import APP_ID, APP_NAME

# Platform-specific paths
if sys.platform == "darwin":
    AUTOSTART_DIR = Path.home() / "Library/LaunchAgents"
    AUTOSTART_FILE = AUTOSTART_DIR / f"{APP_ID}.plist"
else:
    AUTOSTART_DIR = Path.home() / ".config" / "autostart"
    AUTOSTART_FILE = AUTOSTART_DIR / f"{APP_ID}.desktop"


def _find_executable() -> str:
    """Find the executable path for the application."""
    if sys.platform == "darwin":
        app_paths = [
            "/Applications/MS SSO OpenConnect.app/Contents/MacOS/ms-sso-openconnect-ui",
            str(Path.home() / "Applications/MS SSO OpenConnect.app/Contents/MacOS/ms-sso-openconnect-ui"),
        ]
    else:
        app_paths = [
            "/usr/bin/ms-sso-openconnect-ui",
            "/usr/local/bin/ms-sso-openconnect-ui",
            str(Path.home() / ".local/bin/ms-sso-openconnect-ui"),
        ]

    for path in app_paths:
        if Path(path).exists():
            return path

    appimage = os.environ.get("APPIMAGE")
    if appimage and Path(appimage).exists():
        return appimage

    return "ms-sso-openconnect-ui"


def is_autostart_enabled() -> bool:
    """Check if autostart is currently enabled."""
    if not AUTOSTART_FILE.exists():
        return False

    try:
        if sys.platform == "darwin":
            with open(AUTOSTART_FILE, "rb") as f:
                plist = plistlib.load(f)
            return not plist.get("Disabled", False)
        else:
            content = AUTOSTART_FILE.read_text()
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
    """Enable autostart for the application."""
    try:
        AUTOSTART_DIR.mkdir(parents=True, exist_ok=True)
        exec_path = _find_executable()

        if sys.platform == "darwin":
            plist = {
                "Label": APP_ID,
                "ProgramArguments": [exec_path],
                "RunAtLoad": True,
                "Disabled": False,
            }
            with open(AUTOSTART_FILE, "wb") as f:
                plistlib.dump(plist, f)
        else:
            content = f"""[Desktop Entry]
Name={APP_NAME}
GenericName=VPN Client
Comment=Connect to VPN with Microsoft SSO authentication
Exec={exec_path}
Icon={APP_ID}
Terminal=false
Type=Application
Categories=Network;Security;
X-GNOME-Autostart-enabled=true
X-GNOME-Autostart-Delay=5
StartupNotify=false
NoDisplay=false
"""
            AUTOSTART_FILE.write_text(content)
            AUTOSTART_FILE.chmod(0o755)

        return True
    except Exception as e:
        print(f"Failed to enable autostart: {e}", file=sys.stderr)
        return False


def disable_autostart() -> bool:
    """Disable autostart for the application."""
    try:
        if AUTOSTART_FILE.exists():
            AUTOSTART_FILE.unlink()
        return True
    except Exception as e:
        print(f"Failed to disable autostart: {e}", file=sys.stderr)
        return False


def set_autostart(enabled: bool) -> bool:
    """Set autostart state."""
    return enable_autostart() if enabled else disable_autostart()


def get_autostart_file_path() -> Path:
    """Get the path to the autostart file."""
    return AUTOSTART_FILE
