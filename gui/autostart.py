"""Autostart management."""

import os
import sys
from pathlib import Path

from .constants import APP_ID, APP_NAME

# Platform-specific paths
if sys.platform == "darwin":
    AUTOSTART_DIR = Path.home() / "Library/LaunchAgents"
    AUTOSTART_FILE = AUTOSTART_DIR / f"{APP_ID}.plist"
else:
    AUTOSTART_DIR = Path.home() / ".config/autostart"
    AUTOSTART_FILE = AUTOSTART_DIR / f"{APP_ID}.desktop"


def _find_executable() -> str:
    """Find the GUI executable path."""
    # Check common locations
    if sys.platform == "darwin":
        paths = [
            "/Applications/MS SSO OpenConnect.app/Contents/MacOS/ms-sso-openconnect-ui",
            Path.home() / "Applications/MS SSO OpenConnect.app/Contents/MacOS/ms-sso-openconnect-ui",
        ]
    else:
        paths = [
            Path("/usr/bin/ms-sso-openconnect-ui"),
            Path("/usr/local/bin/ms-sso-openconnect-ui"),
            Path.home() / ".local/bin/ms-sso-openconnect-ui",
        ]

    for p in paths:
        if Path(p).exists():
            return str(p)

    # Check AppImage
    appimage = os.environ.get("APPIMAGE")
    if appimage and Path(appimage).exists():
        return appimage

    return "ms-sso-openconnect-ui"


def is_autostart_enabled() -> bool:
    """Check if autostart is enabled."""
    if not AUTOSTART_FILE.exists():
        return False

    try:
        if sys.platform == "darwin":
            import plistlib
            with open(AUTOSTART_FILE, "rb") as f:
                plist = plistlib.load(f)
            return not plist.get("Disabled", False)
        else:
            content = AUTOSTART_FILE.read_text()
            for line in content.lower().splitlines():
                if "x-gnome-autostart-enabled=false" in line:
                    return False
                if "hidden=true" in line:
                    return False
            return True
    except Exception:
        return False


def enable_autostart() -> bool:
    """Enable autostart."""
    try:
        AUTOSTART_DIR.mkdir(parents=True, exist_ok=True)
        exe = _find_executable()

        if sys.platform == "darwin":
            import plistlib
            plist = {
                "Label": APP_ID,
                "ProgramArguments": [exe],
                "RunAtLoad": True,
                "Disabled": False,
            }
            with open(AUTOSTART_FILE, "wb") as f:
                plistlib.dump(plist, f)
        else:
            content = f"""[Desktop Entry]
Name={APP_NAME}
Comment=VPN client with Microsoft SSO
Exec={exe}
Icon={APP_ID}
Terminal=false
Type=Application
Categories=Network;Security;
X-GNOME-Autostart-enabled=true
X-GNOME-Autostart-Delay=5
StartupNotify=false
"""
            AUTOSTART_FILE.write_text(content)
            AUTOSTART_FILE.chmod(0o755)

        return True
    except Exception:
        return False


def disable_autostart() -> bool:
    """Disable autostart."""
    try:
        if AUTOSTART_FILE.exists():
            AUTOSTART_FILE.unlink()
        return True
    except Exception:
        return False


def set_autostart(enabled: bool) -> bool:
    """Set autostart state."""
    return enable_autostart() if enabled else disable_autostart()