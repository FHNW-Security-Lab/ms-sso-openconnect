"""Connection configuration management via system keyring."""

import json
from typing import Optional

import keyring

KEYRING_SERVICE = "ms-sso-openconnect"
CONNECTIONS_KEY = "connections"

PROTOCOLS = {
    "anyconnect": {"name": "Cisco AnyConnect", "flag": "anyconnect"},
    "gp": {"name": "GlobalProtect", "flag": "gp"},
}


def get_connections() -> dict:
    """Get all saved VPN connections.

    Returns:
        Dict of connection_name -> connection_details
    """
    try:
        data = keyring.get_password(KEYRING_SERVICE, CONNECTIONS_KEY)
        if data:
            return json.loads(data)
    except Exception:
        pass
    return {}


# Alias for backwards compatibility with Linux UI
get_all_connections = get_connections


def _save_connections(connections: dict) -> bool:
    """Save all connections to keyring."""
    try:
        keyring.set_password(KEYRING_SERVICE, CONNECTIONS_KEY, json.dumps(connections))
        return True
    except Exception:
        return False


def get_connection(name: str) -> Optional[dict]:
    """Get a specific connection by name.

    Args:
        name: Connection name

    Returns:
        Connection details dict or None
    """
    return get_connections().get(name)


def save_connection(
        name: str,
        address: str,
        protocol: str,
        username: str,
        password: str,
        totp_secret: str,
        **options,
) -> bool:
    """Save a VPN connection.

    Args:
        name: Connection identifier
        address: VPN server address
        protocol: 'anyconnect' or 'gp'
        username: Login email
        password: Login password
        totp_secret: Base32 TOTP secret

    Returns:
        True if saved successfully
    """
    connections = get_connections()
    old = connections.get(name, {})
    updated = dict(old)
    updated.update({
        "address": address,
        "protocol": protocol,
        "username": username,
        "password": password,
        "totp_secret": totp_secret,
    })
    allowed = {"mfa_preference", "gp_auth_interface", "gp_os_version", "auto_reconnect"}
    if set(options) - allowed:
        raise ValueError("Unknown connection option")
    updated.update(options)
    if updated.get("mfa_preference", "auto") not in {"auto", "push", "totp"}:
        raise ValueError("Invalid MFA preference")
    if updated.get("gp_auth_interface", "portal") not in {"portal", "gateway"}:
        raise ValueError("Invalid GlobalProtect authentication interface")
    if not isinstance(updated.get("auto_reconnect", True), bool):
        raise ValueError("Automatic reconnect must be a boolean")
    connections[name] = updated
    if not _save_connections(connections):
        return False
    # An edited profile must not reuse a cookie issued to a different account,
    # gateway, authentication method, or password.
    if old and any(old.get(key) != updated.get(key) for key in updated if key != "auto_reconnect"):
        from .cookies import clear_cookies
        clear_cookies(name)
    return True


def delete_connection(name: str) -> bool:
    """Delete a connection.

    Args:
        name: Connection name

    Returns:
        True if deleted
    """
    connections = get_connections()
    if name in connections:
        del connections[name]
        if not _save_connections(connections):
            return False
        # Also clear cookies
        from .cookies import clear_cookies
        clear_cookies(name)
        return True
    return False


def get_config(name: str) -> Optional[tuple]:
    """Get full config tuple for a connection.

    Args:
        name: Connection name

    Returns:
        (name, address, protocol, username, password, totp_secret) or None
    """
    conn = get_connection(name)
    if conn:
        return (
            name,
            conn.get("address"),
            conn.get("protocol", "anyconnect"),
            conn.get("username"),
            conn.get("password"),
            conn.get("totp_secret"),
        )
    return None


def delete_all() -> bool:
    """Delete all connections and cookies."""
    try:
        keyring.delete_password(KEYRING_SERVICE, CONNECTIONS_KEY)
        from .cookies import clear_cookies
        clear_cookies()
        return True
    except Exception:
        return False
