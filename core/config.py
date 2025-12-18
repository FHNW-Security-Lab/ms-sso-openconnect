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
    connections[name] = {
        "address": address,
        "protocol": protocol,
        "username": username,
        "password": password,
        "totp_secret": totp_secret,
    }
    return _save_connections(connections)


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
        _save_connections(connections)
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