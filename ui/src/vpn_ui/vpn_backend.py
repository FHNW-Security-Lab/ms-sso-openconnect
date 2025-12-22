"""Backend interface to ms-sso-openconnect core module.

This module provides a clean interface for the GUI to use the unified core library.
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

IS_MAC = sys.platform == "darwin"

# State file for tracking active connection
if IS_MAC:
    STATE_FILE = (
        Path.home()
        / "Library"
        / "Application Support"
        / "ms-sso-openconnect"
        / "state.json"
    )
    APP_BUNDLE_RESOURCES = Path("/Applications/MS SSO OpenConnect.app/Contents/Resources")
    USER_APP_BUNDLE_RESOURCES = (
        Path.home() / "Applications/MS SSO OpenConnect.app/Contents/Resources"
    )
else:
    STATE_FILE = Path.home() / ".cache" / "ms-sso-openconnect-ui" / "state.json"
    # System-installed venv paths (from Debian package postinst)
    SYSTEM_VENV = Path("/opt/ms-sso-openconnect-ui/venv")
    SYSTEM_BROWSERS = Path("/opt/ms-sso-openconnect-ui/browsers")


def _setup_system_venv() -> None:
    """Add system venv to path if it exists (Debian package installation)."""
    if IS_MAC:
        return

    if SYSTEM_VENV.exists():
        # Find site-packages directory
        for python_ver in SYSTEM_VENV.glob("lib/python*/site-packages"):
            if python_ver.exists() and str(python_ver) not in sys.path:
                sys.path.insert(0, str(python_ver))
                break

        # Set playwright browsers path
        if SYSTEM_BROWSERS.exists():
            os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(SYSTEM_BROWSERS))


def _setup_core_module() -> None:
    """Add core module to path if not already importable."""
    # Try to import core module
    try:
        import core
        return
    except ImportError:
        pass

    if IS_MAC:
        bundle_paths = [
            APP_BUNDLE_RESOURCES,
            USER_APP_BUNDLE_RESOURCES,
        ]
        for bundle in bundle_paths:
            if (bundle / "core").exists():
                if str(bundle) not in sys.path:
                    sys.path.insert(0, str(bundle))
                return

    # Add project root to path
    # ui/src/vpn_ui/vpn_backend.py -> ../../.. -> project root
    project_root = Path(__file__).parent.parent.parent.parent
    if project_root.exists() and (project_root / "core").exists():
        if str(project_root) not in sys.path:
            sys.path.insert(0, str(project_root))
        return

    # Try system installation paths
    if IS_MAC:
        system_paths = [
            Path("/usr/local/share/ms-sso-openconnect"),
            Path("/opt/homebrew/share/ms-sso-openconnect"),
            Path.home() / ".local/share/ms-sso-openconnect",
        ]
    else:
        system_paths = [
            Path("/usr/share/ms-sso-openconnect"),
            Path("/usr/lib/ms-sso-openconnect"),
            Path.home() / ".local/share/ms-sso-openconnect",
        ]

    for path in system_paths:
        if (path / "core").exists():
            if str(path) not in sys.path:
                sys.path.insert(0, str(path))
            return

    raise ImportError(
        "Cannot find core module. "
        f"Searched: {project_root}, {', '.join(str(p) for p in system_paths)}"
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
    disconnect as _disconnect,
    # TOTP
    generate_totp,
)


class VPNBackend:
    """Wrapper class for ms-sso-openconnect core functionality."""

    def __init__(self):
        """Initialize the backend."""
        pass  # No dynamic loading needed anymore

    # Connection Management

    def get_connections(self) -> dict:
        """Get all saved VPN connections.

        Returns:
            Dictionary of connection name -> connection details
        """
        return get_all_connections()

    def get_connection(self, name: str) -> Optional[dict]:
        """Get a specific connection by name.

        Args:
            name: Connection name

        Returns:
            Connection details dict or None if not found
        """
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
        """Save a VPN connection.

        Args:
            name: Connection identifier
            address: VPN server address
            protocol: Protocol type ('anyconnect' or 'gp')
            username: Login username/email
            password: Login password
            totp_secret: TOTP secret for 2FA

        Returns:
            True if saved successfully
        """
        try:
            save_connection(
                name, address, protocol, username, password, totp_secret
            )
            return True
        except Exception:
            return False

    def delete_connection(self, name: str) -> bool:
        """Delete a VPN connection.

        Args:
            name: Connection name to delete

        Returns:
            True if deleted successfully
        """
        try:
            delete_connection(name)
            return True
        except Exception:
            return False

    # Cookie/Session Management

    def get_stored_cookies(self, name: str, max_age_hours: int = 12) -> Optional[tuple]:
        """Get cached session cookies for a connection.

        Args:
            name: Connection name
            max_age_hours: Maximum age of cached cookies

        Returns:
            Tuple of (cookies_dict, usergroup) or None if not cached/expired
        """
        return get_stored_cookies(name, max_age_hours)

    def store_cookies(
        self,
        name: str,
        cookies: dict,
        usergroup: Optional[str] = None
    ) -> bool:
        """Store session cookies for a connection.

        Args:
            name: Connection name
            cookies: Cookies dictionary
            usergroup: Optional usergroup for reconnection

        Returns:
            True if stored successfully
        """
        try:
            store_cookies(name, cookies, usergroup)
            return True
        except Exception:
            return False

    def clear_stored_cookies(self, name: Optional[str] = None) -> bool:
        """Clear cached cookies.

        Args:
            name: Connection name (None to clear all)

        Returns:
            True if cleared successfully
        """
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
        """Perform SAML authentication via browser automation.

        Args:
            vpn_server: VPN server address
            username: Login username
            password: Login password
            totp_secret: TOTP secret for 2FA (will auto-generate codes)
            protocol: VPN protocol ('anyconnect' or 'gp')
            headless: Run browser in headless mode
            debug: Enable debug output

        Returns:
            Dictionary with cookies/tokens or None on failure
        """
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

    # VPN Connection

    def connect_vpn(
        self,
        address: str,
        protocol: str,
        cookies: dict,
        no_dtls: bool = False,
        username: Optional[str] = None,
        allow_fallback: bool = False,
        connection_name: Optional[str] = None,
        cached_usergroup: Optional[str] = None,
        use_pkexec: bool = True
    ) -> bool:
        """Connect to VPN using openconnect.

        Args:
            address: VPN server address
            protocol: VPN protocol
            cookies: Authentication cookies
            no_dtls: Disable DTLS (TCP only)
            username: Username for connection
            allow_fallback: Allow fallback on failure
            connection_name: Connection name for cookie caching
            cached_usergroup: Usergroup from cached cookies
            use_pkexec: Use pkexec instead of sudo (for GUI without terminal)

        Returns:
            True if connection successful (note: may not return if using execvp)
        """
        if IS_MAC:
            return self._connect_vpn_macos(
                address=address,
                protocol=protocol,
                cookies=cookies,
                no_dtls=no_dtls,
                username=username,
                connection_name=connection_name,
                cached_usergroup=cached_usergroup,
            )

        return _connect_vpn(
            address, protocol, cookies, no_dtls, username,
            allow_fallback, connection_name, cached_usergroup, use_pkexec
        )

    def _connect_vpn_macos(
        self,
        address: str,
        protocol: str,
        cookies: dict,
        no_dtls: bool,
        username: Optional[str],
        connection_name: Optional[str],
        cached_usergroup: Optional[str],
    ) -> bool:
        from vpn_ui.macos_launchd import request_connect, request_status

        response = request_connect(
            address=address,
            protocol=protocol,
            cookies=cookies,
            no_dtls=no_dtls,
            username=username,
            cached_usergroup=cached_usergroup,
            connection_name=connection_name,
        )

        if not response.get("ok"):
            raise RuntimeError(response.get("error", "Failed to connect"))

        portal_cookie = response.get("portal_cookie")
        portal_usergroup = response.get("portal_usergroup")
        if not portal_cookie and protocol == "gp":
            try:
                status = request_status()
                portal_cookie = status.get("portal_cookie")
                portal_usergroup = status.get("portal_usergroup")
            except Exception:
                pass

        if portal_cookie and connection_name:
            self.store_cookies(
                connection_name,
                {"portal-userauthcookie": portal_cookie},
                usergroup=portal_usergroup,
            )

        return True

    def disconnect(self, force: bool = False) -> bool:
        """Disconnect from VPN.

        Args:
            force: If True, send SIGTERM (terminate session).
                   If False, send SIGKILL (keep session alive).

        Returns:
            True if disconnect signal sent
        """
        if IS_MAC:
            from vpn_ui.macos_launchd import request_disconnect

            response = request_disconnect(force=force)
            if response.get("ok"):
                if force:
                    self.clear_stored_cookies()
                return True
            return False

        try:
            # Use pkexec for GUI (polkit) instead of sudo which needs a terminal
            # IMPORTANT: Use -x for exact process name match, NOT -f which matches paths
            # -f would kill our app too since it runs from a path containing "openconnect"
            signal_flag = "-TERM" if force else "-KILL"
            result = subprocess.run(
                ["pkexec", "pkill", signal_flag, "-x", "openconnect"],
                capture_output=True
            )
            if result.returncode == 0:
                if force:
                    self.clear_stored_cookies()
                return True
            # Try with sudo as fallback (might work if running from terminal)
            result = subprocess.run(
                ["sudo", "-n", "pkill", signal_flag, "-x", "openconnect"],
                capture_output=True
            )
            return result.returncode == 0
        except Exception:
            return False

    # State Management

    def save_active_connection(self, name: str) -> None:
        """Save the active connection name to state file.

        Args:
            name: Connection name
        """
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        state = {"active_connection": name}
        STATE_FILE.write_text(json.dumps(state))

    def get_active_connection(self) -> Optional[str]:
        """Get the active connection name from state file.

        Returns:
            Connection name or None if not connected via UI
        """
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
        """Generate a TOTP code from a secret.

        Args:
            secret: Base32-encoded TOTP secret

        Returns:
            Current TOTP code

        Raises:
            ValueError: If secret is invalid
        """
        return generate_totp(secret)

    def is_connected(self) -> bool:
        """Check if VPN is currently connected.

        Returns:
            True if openconnect process is running
        """
        try:
            # Use pgrep -x to match exact process name
            result = subprocess.run(
                ["pgrep", "-x", "openconnect"],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return False

    def get_connection_info(self) -> Optional[dict]:
        """Get information about current VPN connection.

        Returns:
            Dictionary with connection info or None if not connected
        """
        if not self.is_connected():
            return None

        try:
            if IS_MAC:
                result = subprocess.run(
                    ["pgrep", "-l", "openconnect"],
                    capture_output=True,
                    text=True
                )
            else:
                result = subprocess.run(
                    ["pgrep", "-a", "-f", "openconnect"],
                    capture_output=True,
                    text=True
                )

            if result.returncode == 0:
                cmd_line = result.stdout.strip()
                return {"process": cmd_line, "connected": True}
        except Exception:
            pass

        return {"connected": True}

    def infer_connection_name(self) -> Optional[str]:
        """Try to infer connection name from running openconnect process.

        This is useful when the app starts and finds openconnect already
        running (e.g., connected via CLI or app restart).

        Returns:
            Connection name if it can be inferred, None otherwise
        """
        if not self.is_connected():
            return None

        try:
            if IS_MAC:
                # On macOS, use ps to get the full command line
                result = subprocess.run(
                    ["ps", "-x", "-o", "args="],
                    capture_output=True,
                    text=True
                )
                if result.returncode != 0:
                    return None

                # Find openconnect line
                for line in result.stdout.splitlines():
                    if "openconnect" in line and "grep" not in line:
                        parts = line.split()
                        server_address = None

                        for part in parts:
                            if part.startswith("--server="):
                                server_address = part.split("=", 1)[1]
                                break
                            if not part.startswith("-") and "." in part and part != "openconnect":
                                server_address = part

                        if server_address:
                            connections = self.get_connections()
                            for name, details in connections.items():
                                conn_address = details.get("address", "")
                                if conn_address and (
                                    conn_address == server_address or
                                    conn_address in server_address or
                                    server_address in conn_address
                                ):
                                    return name

                return None

            # Linux/default behavior
            result = subprocess.run(
                ["pgrep", "-a", "openconnect"],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                return None

            cmd_line = result.stdout.strip()

            # Extract server address from command line
            # openconnect typically has the server as an argument
            # Format: "PID openconnect [options] server"
            parts = cmd_line.split()
            if len(parts) < 2:
                return None

            # The server is usually the last argument or after --server=
            server_address = None
            for part in parts:
                if part.startswith("--server="):
                    server_address = part.split("=", 1)[1]
                    break
                # Check if it looks like a hostname (not an option)
                if not part.startswith("-") and "." in part and part != "openconnect":
                    # Skip the PID (first element) and command name
                    server_address = part

            if not server_address:
                return None

            # Match against saved connections
            connections = self.get_connections()
            for name, details in connections.items():
                conn_address = details.get("address", "")
                # Match by server address (could be exact or partial match)
                if conn_address and (
                    conn_address == server_address or
                    conn_address in server_address or
                    server_address in conn_address
                ):
                    return name

        except Exception:
            pass

        return None

    def get_config(self, name: str) -> Optional[tuple]:
        """Get full configuration for a connection.

        Args:
            name: Connection name

        Returns:
            Tuple of (name, address, protocol, username, password, totp_secret)
            or None if not found
        """
        return get_config(name)


# Singleton instance
_backend_instance: Optional[VPNBackend] = None


def get_backend() -> VPNBackend:
    """Get the singleton VPN backend instance.

    Returns:
        VPNBackend instance
    """
    global _backend_instance
    if _backend_instance is None:
        _backend_instance = VPNBackend()
    return _backend_instance
