"""macOS launchd client for privileged openconnect operations."""

import getpass
import json
import os
import socket
from typing import Optional

SOCKET_PATH = "/var/run/ms-sso-openconnect-ui.sock"


def _recv_line(sock: socket.socket) -> str:
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if b"\n" in chunk:
            break
    return data.decode("utf-8").strip()


def _send_request(payload: dict, timeout: float) -> dict:
    if not os.path.exists(SOCKET_PATH):
        raise RuntimeError(
            "Launchd helper is not available. Install the macOS pkg to enable "
            "privileged connections."
        )

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect(SOCKET_PATH)
        except OSError as exc:
            raise RuntimeError(
                "Unable to connect to launchd helper. Make sure the helper is loaded."
            ) from exc

        message = json.dumps(payload).encode("utf-8") + b"\n"
        sock.sendall(message)

        response = _recv_line(sock)
        if not response:
            raise RuntimeError("No response from launchd helper.")

        try:
            return json.loads(response)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Invalid response from launchd helper.") from exc


def _client_info() -> dict:
    return {
        "user": getpass.getuser(),
        "uid": os.getuid(),
    }


def request_connect(
    address: str,
    protocol: str,
    cookies: dict,
    no_dtls: bool,
    username: Optional[str],
    cached_usergroup: Optional[str],
    connection_name: Optional[str],
) -> dict:
    payload = {
        "action": "connect",
        "address": address,
        "protocol": protocol,
        "cookies": cookies,
        "no_dtls": no_dtls,
        "username": username,
        "cached_usergroup": cached_usergroup,
        "connection_name": connection_name,
    }
    payload.update(_client_info())
    return _send_request(payload, timeout=20.0)


def request_disconnect(force: bool) -> dict:
    payload = {
        "action": "disconnect",
        "force": force,
    }
    payload.update(_client_info())
    return _send_request(payload, timeout=10.0)


def request_status() -> dict:
    payload = {
        "action": "status",
    }
    payload.update(_client_info())
    return _send_request(payload, timeout=5.0)
