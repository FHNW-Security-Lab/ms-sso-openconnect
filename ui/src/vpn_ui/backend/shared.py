"""Shared backend functionality for all platforms.

This module contains the core module setup and methods that are
identical across Linux and macOS.
"""

import json
import os
import sys
from pathlib import Path
from typing import Optional

from vpn_ui.constants import STATE_DIR, STATE_FILE

# System-installed paths (vary by platform)
if sys.platform == "darwin":
    # macOS: app bundle paths
    SYSTEM_VENV = Path("/Applications/MS SSO OpenConnect.app/Contents/Resources/venv")
    SYSTEM_BROWSERS = Path("/Applications/MS SSO OpenConnect.app/Contents/Resources/browsers")
    USER_APP_BUNDLE = Path.home() / "Applications/MS SSO OpenConnect.app/Contents/Resources"
else:
    # Linux: Debian package paths
    SYSTEM_VENV = Path("/opt/ms-sso-openconnect-ui/venv")
    SYSTEM_BROWSERS = Path("/opt/ms-sso-openconnect-ui/browsers")
    USER_APP_BUNDLE = None


def _setup_system_venv():
    """Add system venv to path if it exists."""
    venv_paths = [SYSTEM_VENV]
    if USER_APP_BUNDLE:
        venv_paths.insert(0, USER_APP_BUNDLE / "venv")

    for venv in venv_paths:
        if venv and venv.exists():
            # Find site-packages directory
            for python_ver in venv.glob("lib/python*/site-packages"):
                if python_ver.exists() and str(python_ver) not in sys.path:
                    sys.path.insert(0, str(python_ver))
                    break

            # Set playwright browsers path
            browsers = venv.parent / "browsers" if "venv" in str(venv) else SYSTEM_BROWSERS
            if browsers.exists():
                os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(browsers))
            break


def _setup_core_module():
    """Add core module to path if not already importable."""
    # Try to import core module
    try:
        import core
        return
    except ImportError:
        pass

    # Paths to search for core module
    search_paths = []

    # Development: ui/src/vpn_ui/backend/shared.py -> ../../../../core
    project_root = Path(__file__).parent.parent.parent.parent.parent
    if (project_root / "core").exists():
        search_paths.append(project_root)

    # macOS app bundle
    if sys.platform == "darwin":
        search_paths.extend([
            Path("/Applications/MS SSO OpenConnect.app/Contents/Resources"),
            Path.home() / "Applications/MS SSO OpenConnect.app/Contents/Resources",
        ])

    # Linux system paths
    search_paths.extend([
        Path("/usr/share/ms-sso-openconnect"),
        Path("/usr/lib/ms-sso-openconnect"),
        Path.home() / ".local/share/ms-sso-openconnect",
    ])

    for path in search_paths:
        if path.exists() and (path / "core").exists():
            if str(path) not in sys.path:
                sys.path.insert(0, str(path))
            return

    raise ImportError(
        "Cannot find core module. "
        f"Searched: {', '.join(str(p) for p in search_paths)}"
    )


# Setup on module load
_setup_system_venv()
_setup_core_module()

# Now import from core module
from core import (
    # Config
    get_all_connections,
    get_connection,
    save_connection,
    delete_connection,
    get_config,
    PROTOCOLS,
    # Cookies
    store_cookies,
    get_stored_cookies,
    clear_stored_cookies,
    # Auth
    do_saml_auth,
    # Connect
    connect_vpn as _connect_vpn,
    # TOTP
    generate_totp,
)


class SharedBackendMixin:
    """Mixin class providing shared backend functionality.

    This mixin provides all the platform-independent methods.
    Platform-specific backends should inherit from this and implement
    the platform-specific methods (connect_vpn, disconnect, is_connected).
    """

    # Connection Management

    def get_connections(self) -> dict:
        """Get all saved VPN connections."""
        return get_all_connections()

    def get_connection(self, name: str) -> Optional[dict]:
        """Get a specific connection by name."""
        return get_connection(name)

    def save_connection(
        self,
        name: str,
        address: str,
        protocol: str,
        username: str,
        password: str,
        totp_secret: str
    ) -> bool:
        """Save a VPN connection."""
        try:
            save_connection(
                name, address, protocol, username, password, totp_secret
            )
            return True
        except Exception:
            return False

    def delete_connection(self, name: str) -> bool:
        """Delete a VPN connection."""
        try:
            delete_connection(name)
            return True
        except Exception:
            return False

    # Cookie/Session Management

    def get_stored_cookies(self, name: str, max_age_hours: int = 12) -> Optional[tuple]:
        """Get cached session cookies for a connection."""
        return get_stored_cookies(name, max_age_hours)

    def store_cookies(
        self,
        name: str,
        cookies: dict,
        usergroup: Optional[str] = None
    ) -> bool:
        """Store session cookies for a connection."""
        try:
            store_cookies(name, cookies, usergroup)
            return True
        except Exception:
            return False

    def clear_stored_cookies(self, name: Optional[str] = None) -> bool:
        """Clear cached cookies."""
        try:
            clear_stored_cookies(name)
            return True
        except Exception:
            return False

    # Authentication

    def do_saml_auth(
        self,
        vpn_server: str,
        username: str,
        password: str,
        totp_secret: str,
        protocol: str = "anyconnect",
        headless: bool = True,
        debug: bool = False
    ) -> Optional[dict]:
        """Perform SAML authentication via browser automation."""
        return do_saml_auth(
            vpn_server,
            username,
            password,
            totp_secret,
            protocol=protocol,
            auto_totp=True,
            headless=headless,
            debug=debug,
        )

    # State Management

    def save_active_connection(self, name: str) -> None:
        """Save the active connection name to state file."""
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        state = {"active_connection": name}
        STATE_FILE.write_text(json.dumps(state))

    def get_active_connection(self) -> Optional[str]:
        """Get the active connection name from state file."""
        if not STATE_FILE.exists():
            return None
        try:
            state = json.loads(STATE_FILE.read_text())
            return state.get("active_connection")
        except Exception:
            return None

    def clear_active_connection(self) -> None:
        """Clear the active connection state."""
        if STATE_FILE.exists():
            STATE_FILE.unlink()

    # Utilities

    def generate_totp(self, secret: str) -> str:
        """Generate a TOTP code from a secret."""
        return generate_totp(secret)

    def get_config(self, name: str) -> Optional[tuple]:
        """Get full configuration for a connection."""
        return get_config(name)

    def infer_connection_name(self) -> Optional[str]:
        """Try to infer connection name from running openconnect process."""
        import subprocess

        if not self.is_connected():
            return None

        try:
            # Get the openconnect process command line
            result = subprocess.run(
                ["pgrep", "-a", "openconnect"],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                return None

            cmd_line = result.stdout.strip()

            # Extract server address from command line
            parts = cmd_line.split()
            if len(parts) < 2:
                return None

            server_address = None
            for i, part in enumerate(parts):
                if part.startswith("--server="):
                    server_address = part.split("=", 1)[1]
                    break
                # Check if it looks like a hostname
                if not part.startswith("-") and "." in part and part != "openconnect":
                    server_address = part

            if not server_address:
                return None

            # Match against saved connections
            connections = self.get_connections()
            for name, details in connections.items():
                conn_address = details.get("address", "")
                if conn_address and (
                    conn_address == server_address or
                    conn_address in server_address or
                    server_address in conn_address
                ):
                    return name

        except Exception:
            pass

        return None


# Re-export core module's connect function for platform backends
core_connect_vpn = _connect_vpn
