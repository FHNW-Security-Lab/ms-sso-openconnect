"""Input validation for daemon commands."""

import re
from typing import Tuple, Optional

# Valid commands
VALID_COMMANDS = {'connect', 'disconnect', 'status', 'output'}

# Valid protocols
VALID_PROTOCOLS = {'anyconnect', 'gp'}

# Regex patterns
# Server: hostname or IP - alphanumeric, dots, hyphens (e.g., vpn.company.com, vpn-01.corp.net)
RE_SERVER = re.compile(r'^[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9]$')

# Username: email or simple username - alphanumeric, @, dot, underscore, hyphen (e.g., user@company.com, john_doe)
RE_USERNAME = re.compile(r'^[a-zA-Z0-9@._-]+$')

# Usergroup: openconnect usergroup - alphanumeric, colon, underscore, hyphen (e.g., portal:prelogin-cookie)
RE_USERGROUP = re.compile(r'^[a-zA-Z0-9:_-]+$')

# Cookie: per RFC 6265 - any chars except semicolon, comma, whitespace (HTTP header delimiters)
RE_COOKIE = re.compile(r'^[^\x00-\x1f]+$')

# Length limits
MAX_SERVER_LEN = 253      # DNS hostname max
MAX_USERNAME_LEN = 254    # Email max
MAX_USERGROUP_LEN = 128
MAX_COOKIE_LEN = 65536


def validate_request(request: dict) -> Tuple[bool, Optional[str]]:
    """Validate an incoming request.

    Returns:
        (True, None) if valid, (False, error_message) if invalid
    """
    if not isinstance(request, dict):
        return False, "Request must be a JSON object"

    command = request.get("command")
    if not command or command not in VALID_COMMANDS:
        return False, f"Invalid command: {command}"

    if command == "connect":
        # Server (required)
        server = request.get("server")
        if not server:
            return False, "Missing 'server' parameter"
        if len(server) > MAX_SERVER_LEN or not RE_SERVER.match(server):
            return False, "Invalid server format"

        # Protocol
        protocol = request.get("protocol", "anyconnect")
        if protocol not in VALID_PROTOCOLS:
            return False, "Invalid protocol"

        # Cookie (required)
        cookie = request.get("cookie")
        if not cookie:
            return False, "Missing 'cookie' parameter"
        if len(cookie) > MAX_COOKIE_LEN or not RE_COOKIE.match(cookie):
            # Cookie (required)
            cookie = request.get("cookie")
            if not cookie:
                return False, "Missing 'cookie' parameter"
            print(f"[DEBUG] Cookie length: {len(cookie)}")
            print(f"[DEBUG] Cookie first 100 chars: {repr(cookie[:100])}")
            print(f"[DEBUG] Cookie matches regex: {bool(RE_COOKIE.match(cookie))}")
            if len(cookie) > MAX_COOKIE_LEN or not RE_COOKIE.match(cookie):
                # Find the offending character
                for i, c in enumerate(cookie):
                    if c in ' \t\n\r;,':
                        print(f"[DEBUG] Bad char at pos {i}: {repr(c)}")
                        break
                return False, "Invalid cookie format"
            return False, "Invalid cookie format"

        # Username (optional)
        username = request.get("username")
        if username:
            if len(username) > MAX_USERNAME_LEN or not RE_USERNAME.match(username):
                return False, "Invalid username format"

        # Usergroup (optional)
        usergroup = request.get("usergroup")
        if usergroup:
            if len(usergroup) > MAX_USERGROUP_LEN or not RE_USERGROUP.match(usergroup):
                return False, "Invalid usergroup format"

    return True, None