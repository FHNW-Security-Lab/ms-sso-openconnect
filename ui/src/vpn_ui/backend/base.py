"""Base backend protocol definition."""

from typing import Optional, Protocol, runtime_checkable


@runtime_checkable
class VPNBackendProtocol(Protocol):
    """Protocol defining the VPN backend interface.

    All platform-specific backends must implement this interface.
    """

    # Connection Management (uses core module)

    def get_connections(self) -> dict:
        """Get all saved VPN connections.

        Returns:
            Dictionary of connection name -> connection details
        """
        ...

    def get_connection(self, name: str) -> Optional[dict]:
        """Get a specific connection by name.

        Args:
            name: Connection name

        Returns:
            Connection details dict or None if not found
        """
        ...

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
        ...

    def delete_connection(self, name: str) -> bool:
        """Delete a VPN connection.

        Args:
            name: Connection name to delete

        Returns:
            True if deleted successfully
        """
        ...

    # Cookie/Session Management

    def get_stored_cookies(self, name: str, max_age_hours: int = 12) -> Optional[tuple]:
        """Get cached session cookies for a connection.

        Args:
            name: Connection name
            max_age_hours: Maximum age of cached cookies

        Returns:
            Tuple of (cookies_dict, usergroup) or None if not cached/expired
        """
        ...

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
        ...

    def clear_stored_cookies(self, name: Optional[str] = None) -> bool:
        """Clear cached cookies.

        Args:
            name: Connection name (None to clear all)

        Returns:
            True if cleared successfully
        """
        ...

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
            totp_secret: TOTP secret for 2FA
            protocol: VPN protocol
            headless: Run browser in headless mode
            debug: Enable debug output

        Returns:
            Dictionary with cookies/tokens or None on failure
        """
        ...

    # VPN Connection (PLATFORM-SPECIFIC)

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

        Returns:
            True if connection successful
        """
        ...

    def disconnect(self, force: bool = False) -> bool:
        """Disconnect from VPN.

        Args:
            force: If True, terminate session. Behavior varies by platform:
                   - Linux: SIGTERM (terminate) vs SIGKILL (keep session)
                   - macOS: Always SIGTERM for graceful shutdown

        Returns:
            True if disconnect signal sent
        """
        ...

    def is_connected(self) -> bool:
        """Check if VPN is currently connected.

        Returns:
            True if openconnect process is running
        """
        ...

    # State Management

    def save_active_connection(self, name: str) -> None:
        """Save the active connection name to state file.

        Args:
            name: Connection name
        """
        ...

    def get_active_connection(self) -> Optional[str]:
        """Get the active connection name from state file.

        Returns:
            Connection name or None if not connected via UI
        """
        ...

    def clear_active_connection(self) -> None:
        """Clear the active connection state."""
        ...

    # Utilities

    def generate_totp(self, secret: str) -> str:
        """Generate a TOTP code from a secret.

        Args:
            secret: Base32-encoded TOTP secret

        Returns:
            Current TOTP code
        """
        ...

    def get_config(self, name: str) -> Optional[tuple]:
        """Get full configuration for a connection.

        Args:
            name: Connection name

        Returns:
            Tuple of (name, address, protocol, username, password, totp_secret)
            or None if not found
        """
        ...

    def infer_connection_name(self) -> Optional[str]:
        """Try to infer connection name from running openconnect process.

        Returns:
            Connection name if it can be inferred, None otherwise
        """
        ...
