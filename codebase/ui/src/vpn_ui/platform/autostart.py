"""Platform-specific autostart management.

- Linux: Uses XDG Desktop Entry files in ~/.config/autostart/
- macOS: Uses LaunchAgent plist files in ~/Library/LaunchAgents/
"""

import subprocess
import sys
from pathlib import Path

from vpn_ui.constants import APP_ID, APP_NAME


if sys.platform == "darwin":
    # ==========================================================================
    # macOS Implementation - LaunchAgent
    # ==========================================================================
    import plistlib

    LAUNCH_AGENTS_DIR = Path.home() / "Library" / "LaunchAgents"
    AUTOSTART_FILE = LAUNCH_AGENTS_DIR / f"{APP_ID}.plist"

    def _find_executable() -> str:
        """Find the executable path for the application."""
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

        return "ms-sso-openconnect-ui"

    def _create_launch_agent_plist() -> dict:
        """Create the LaunchAgent plist dictionary."""
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
        """Check if autostart is currently enabled."""
        return AUTOSTART_FILE.exists()

    def enable_autostart() -> bool:
        """Enable autostart for the application."""
        try:
            LAUNCH_AGENTS_DIR.mkdir(parents=True, exist_ok=True)
            logs_dir = Path.home() / "Library/Logs"
            logs_dir.mkdir(parents=True, exist_ok=True)

            plist_data = _create_launch_agent_plist()
            with open(AUTOSTART_FILE, "wb") as f:
                plistlib.dump(plist_data, f)

            subprocess.run(["launchctl", "load", str(AUTOSTART_FILE)], capture_output=True)
            return True
        except Exception as e:
            print(f"Failed to enable autostart: {e}", file=sys.stderr)
            return False

    def disable_autostart() -> bool:
        """Disable autostart for the application."""
        try:
            if AUTOSTART_FILE.exists():
                subprocess.run(["launchctl", "unload", str(AUTOSTART_FILE)], capture_output=True)
                AUTOSTART_FILE.unlink()
            return True
        except Exception as e:
            print(f"Failed to disable autostart: {e}", file=sys.stderr)
            return False

else:
    # ==========================================================================
    # Linux Implementation - XDG Desktop Entry
    # ==========================================================================
    import os

    AUTOSTART_DIR = Path.home() / ".config" / "autostart"
    AUTOSTART_FILE = AUTOSTART_DIR / f"{APP_ID}.desktop"

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
        """Find the executable path for the application."""
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

        return "ms-sso-openconnect-ui"

    def is_autostart_enabled() -> bool:
        """Check if autostart is currently enabled."""
        if not AUTOSTART_FILE.exists():
            return False

        try:
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

            content = DESKTOP_TEMPLATE.format(
                name=APP_NAME,
                exec_path=exec_path,
                app_id=APP_ID,
            )

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


# Common interface
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
    """Get the path to the autostart file.

    Returns:
        Path to the autostart file
    """
    return AUTOSTART_FILE
