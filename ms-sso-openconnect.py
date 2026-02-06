#!/usr/bin/env python3
"""
MS SSO OpenConnect - CLI Tool

Connects to VPNs using Microsoft SSO via a headless browser,
supporting both Cisco AnyConnect and GlobalProtect protocols.

This is a thin CLI wrapper around the core module.

Usage:
    ./ms-sso-openconnect --setup            (add/edit VPN connection)
    ./ms-sso-openconnect                    (connect to default/only connection)
    ./ms-sso-openconnect <name>             (connect by connection name)
    ./ms-sso-openconnect --list             (list saved connections)
    ./ms-sso-openconnect --no-cache         (force re-authentication)
    ./ms-sso-openconnect --visible          (show browser for debugging)
    ./ms-sso-openconnect -d                 (disconnect, keep session alive)
    ./ms-sso-openconnect --force-disconnect (disconnect and terminate session)
"""

import argparse
import getpass
import sys
from pathlib import Path

# Add codebase directory to path for development
project_root = Path(__file__).parent
codebase_root = project_root / "codebase"
if (codebase_root / "core").exists():
    sys.path.insert(0, str(codebase_root))

# Import from core module
from core import (
    # Config
    get_connections,
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
    connect_vpn,
    disconnect,
)

# Terminal colors
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BOLD = "\033[1m"
NC = "\033[0m"


def print_header():
    """Print application header."""
    print(f"{GREEN}========================================{NC}")
    print(f"{GREEN}    MS SSO OpenConnect - VPN Client{NC}")
    print(f"{GREEN}========================================{NC}")
    print()


def list_connections_cmd():
    """List all saved VPN connections."""
    connections = get_connections()
    if not connections:
        print(f"{YELLOW}No saved connections.{NC}")
        print(f"Use --setup to add a connection.")
        return

    print(f"{GREEN}Saved VPN connections:{NC}\n")
    for name, details in connections.items():
        protocol_name = PROTOCOLS.get(details.get("protocol", ""), {}).get("name", "Unknown")
        print(f"  {BOLD}{name}{NC}")
        print(f"    Server: {details.get('address', 'N/A')}")
        print(f"    Protocol: {protocol_name}")
        print(f"    Username: {details.get('username', 'N/A')}")
        print()


def setup_config_cmd(edit_name=None):
    """Interactive setup for VPN connection."""
    connections = get_connections()

    # Determine if editing existing or creating new
    if edit_name and edit_name in connections:
        print(f"{GREEN}Editing connection: {edit_name}{NC}\n")
        existing = connections[edit_name]
        name = edit_name
    else:
        existing = {}
        if edit_name:
            name = edit_name
            print(f"{GREEN}Creating new connection: {name}{NC}\n")
        else:
            name = input(f"Connection name [{existing.get('name', 'work')}]: ").strip()
            if not name:
                name = existing.get('name', 'work')

    # Get connection details
    default_addr = existing.get('address', '')
    address = input(f"VPN server address [{default_addr}]: ").strip()
    if not address:
        address = default_addr
    if not address:
        print(f"{RED}Server address is required.{NC}")
        return

    # Protocol selection
    print(f"\nAvailable protocols:")
    for key, val in PROTOCOLS.items():
        marker = "*" if key == existing.get('protocol', 'anyconnect') else " "
        print(f"  {marker} {key}: {val['name']}")

    default_proto = existing.get('protocol', 'anyconnect')
    protocol = input(f"Protocol [{default_proto}]: ").strip().lower()
    if not protocol:
        protocol = default_proto
    if protocol not in PROTOCOLS:
        print(f"{RED}Invalid protocol. Using 'anyconnect'.{NC}")
        protocol = 'anyconnect'

    # Credentials
    default_user = existing.get('username', '')
    username = input(f"Username/email [{default_user}]: ").strip()
    if not username:
        username = default_user
    if not username:
        print(f"{RED}Username is required.{NC}")
        return

    # Password (hidden input)
    if existing.get('password'):
        password = getpass.getpass(f"Password [keep existing]: ")
        if not password:
            password = existing['password']
    else:
        password = getpass.getpass("Password: ")
    if not password:
        print(f"{RED}Password is required.{NC}")
        return

    # TOTP secret
    default_totp = existing.get('totp_secret', '')
    if default_totp:
        totp_secret = input(f"TOTP secret (base32) [keep existing]: ").strip()
        if not totp_secret:
            totp_secret = default_totp
    else:
        totp_secret = input("TOTP secret (base32): ").strip()

    # Save
    if save_connection(name, address, protocol, username, password, totp_secret):
        print(f"\n{GREEN}Connection '{name}' saved successfully.{NC}")
    else:
        print(f"\n{RED}Failed to save connection.{NC}")


def delete_config_cmd(name=None):
    """Delete a VPN connection."""
    connections = get_connections()

    if not connections:
        print(f"{YELLOW}No connections to delete.{NC}")
        return

    if not name:
        print(f"Available connections: {', '.join(connections.keys())}")
        name = input("Connection to delete: ").strip()

    if name not in connections:
        print(f"{RED}Connection '{name}' not found.{NC}")
        return

    confirm = input(f"Delete '{name}'? [y/N]: ").strip().lower()
    if confirm == 'y':
        delete_connection(name)
        print(f"{GREEN}Connection '{name}' deleted.{NC}")
    else:
        print("Cancelled.")


def select_connection_cmd():
    """Interactive connection selection."""
    connections = get_connections()

    if not connections:
        print(f"{RED}No saved connections. Use --setup to add one.{NC}")
        sys.exit(1)

    if len(connections) == 1:
        return list(connections.keys())[0]

    print(f"Available connections:")
    names = list(connections.keys())
    for i, name in enumerate(names, 1):
        print(f"  {i}. {name}")

    while True:
        choice = input(f"Select connection [1-{len(names)}]: ").strip()
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(names):
                return names[idx]
        except ValueError:
            if choice in names:
                return choice
        print(f"{RED}Invalid selection.{NC}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="OpenConnect VPN with Microsoft SSO authentication (AnyConnect & GlobalProtect)"
    )
    parser.add_argument("name", nargs="?", help="Connection name to connect to")
    parser.add_argument("--visible", action="store_true", help="Show browser window for debugging")
    parser.add_argument("--debug", action="store_true", help="Enable debug output and screenshots")
    parser.add_argument("--disconnect", "-d", action="store_true", help="Disconnect (keep session alive)")
    parser.add_argument("--force-disconnect", action="store_true", help="Disconnect and terminate session")
    parser.add_argument("--setup", "-s", action="store_true", help="Add/edit VPN connection")
    parser.add_argument("--list", "-l", action="store_true", help="List saved connections")
    parser.add_argument("--delete", action="store_true", help="Delete connection from keyring")
    parser.add_argument("--no-cache", action="store_true", help="Force re-authentication")
    parser.add_argument("--no-dtls", action="store_true", help="Disable DTLS (use TCP only)")

    args = parser.parse_args()

    print_header()

    # Handle disconnect commands
    if args.disconnect:
        disconnect(force=False)
        return

    if args.force_disconnect:
        disconnect(force=True)
        return

    # Handle management commands
    if args.list:
        list_connections_cmd()
        return

    if args.setup:
        setup_config_cmd(edit_name=args.name)
        return

    if args.delete:
        delete_config_cmd(name=args.name)
        return

    # Connect flow
    # Determine which connection to use
    if args.name:
        conn_name = args.name
    else:
        conn_name = select_connection_cmd()

    config = get_config(conn_name)
    if not config:
        print(f"{RED}Connection '{conn_name}' not found. Use --setup to configure.{NC}")
        sys.exit(1)

    conn_name, address, protocol, username, password, totp_secret = config

    if not all([conn_name, address, protocol, username, password, totp_secret]):
        print(f"{RED}Connection incomplete. Use --setup to configure.{NC}")
        sys.exit(1)

    print(f"{GREEN}Connection: {conn_name}{NC}")
    print(f"{GREEN}VPN Server: {address}{NC}")
    print(f"{GREEN}Protocol: {PROTOCOLS.get(protocol, {}).get('name', protocol)}{NC}")
    print(f"{GREEN}Username: {username}{NC}")
    print(f"{GREEN}TOTP code will be generated automatically.{NC}\n")

    # Check for cached cookies
    cached_cookies = None
    cached_usergroup = None
    if not args.no_cache and protocol != 'gp':
        # Skip cache for GlobalProtect (short TTL)
        cached_result = get_stored_cookies(conn_name)
        if cached_result:
            cached_cookies, cached_usergroup = cached_result
            print(f"{GREEN}Found cached session cookie.{NC}")
            if cached_usergroup:
                print(f"  Cached usergroup: {cached_usergroup}")

    # Try cached cookies first
    if cached_cookies:
        print(f"{CYAN}Trying cached session cookie...{NC}")
        success = connect_vpn(
            address, protocol, cached_cookies.copy(),
            no_dtls=args.no_dtls,
            username=username,
            allow_fallback=True,
            connection_name=conn_name,
            cached_usergroup=cached_usergroup
        )
        if success:
            return
        else:
            print(f"{YELLOW}Cached cookie expired or invalid. Re-authenticating...{NC}\n")
            clear_stored_cookies(conn_name)

    # Authenticate via browser
    cookies = do_saml_auth(
        address, username, password, totp_secret,
        auto_totp=True,
        headless=not args.visible,
        debug=args.debug,
        protocol=protocol
    )

    if cookies:
        # Store cookies (skip for GlobalProtect due to short TTL)
        if protocol != 'gp':
            store_cookies(conn_name, cookies, usergroup='portal:prelogin-cookie')
        connect_vpn(
            address, protocol, cookies,
            no_dtls=args.no_dtls,
            username=username,
            connection_name=conn_name
        )
    else:
        print(f"\n{RED}Authentication failed.{NC}")
        print(f"Try with --visible to see the browser window.")
        sys.exit(1)


if __name__ == "__main__":
    main()
