"""Platform-specific VPN backends.

macOS uses the helper installed by the package for every privileged operation.
Linux uses pkexec and graceful signals for the owned tunnel.
"""

import json
import re
import socket
import sys
import time
from typing import Callable, Optional

from vpn_ui.backend.base import VPNConnectionError
from vpn_ui.backend.shared import SharedBackendMixin, core_connect_vpn


DAEMON_SOCKET = "/var/run/ms-sso-openconnect/daemon.sock"
MAX_DAEMON_MESSAGE = 1024 * 1024
HELPER_UNAVAILABLE_MESSAGE = (
    "The macOS VPN helper is unavailable. Install or reinstall the macOS package, "
    "then try again. Administrator approval is only required during installation."
)
CONNECTION_ERRORS = {
    "helper_stopping": "VPN helper is stopping",
    "already_connected": "A VPN connection is already active",
    "openconnect_missing": "OpenConnect is not installed in a standard location",
    "hip_support_missing": "OpenConnect HIP report support is unavailable; reinstall OpenConnect",
    "openconnect_exit": "OpenConnect exited before the VPN tunnel was ready",
    "openconnect_start_failed": "OpenConnect could not be started",
    "openconnect_timeout": "VPN tunnel did not become ready in time",
    "connection_cancelled": "Connection cancelled",
    "disconnect_in_progress": "VPN is still disconnecting; try again shortly",
}


def _connection_error(result: dict) -> VPNConnectionError:
    """Use known diagnostics rather than reflecting possible credentials in output."""
    code = result.get("error_code")
    if not isinstance(code, str) or code not in CONNECTION_ERRORS:
        return VPNConnectionError(
            "The VPN helper could not establish the connection. Check the connection settings "
            "and try again.", error_code="connection_failed",
        )
    message = CONNECTION_ERRORS[code]
    exit_status = result.get("exit_status")
    if code == "openconnect_exit" and type(exit_status) is int:
        message += f" (exit status {exit_status})"
    retryable = (result.get("retryable") is True and code in {
        "openconnect_exit", "openconnect_timeout", "disconnect_in_progress",
    })
    return VPNConnectionError(message, retryable=retryable, error_code=code)


class MacOSHelperUnavailable(RuntimeError):
    """The installed privileged helper could not complete an IPC request."""


class VPNBackend(SharedBackendMixin):
    """Shared account handling with platform-specific VPN operations."""

    if sys.platform == "darwin":
        def _daemon_request(self, method: str, params: Optional[dict] = None) -> dict:
            """Exchange one bounded, newline-delimited JSON-RPC message."""
            request = {"jsonrpc": "2.0", "method": method, "params": params or {}, "id": 1}
            try:
                payload = json.dumps(request).encode() + b"\n"
                if len(payload) > MAX_DAEMON_MESSAGE:
                    raise ValueError("Helper request exceeds the message size limit")
                timeout = 60 if method == "connect" else 20 if method == "disconnect" else 5
                deadline = time.monotonic() + timeout
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    sock.connect(DAEMON_SOCKET)
                    sock.settimeout(max(0.001, deadline - time.monotonic()))
                    sock.sendall(payload)
                    response = bytearray()
                    while b"\n" not in response:
                        if len(response) >= MAX_DAEMON_MESSAGE:
                            raise ValueError("Helper response exceeds the message size limit")
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise TimeoutError("Timed out waiting for the VPN helper")
                        sock.settimeout(remaining)
                        chunk = sock.recv(min(65536, MAX_DAEMON_MESSAGE - len(response)))
                        if not chunk:
                            raise ValueError("VPN helper closed an incomplete response")
                        response.extend(chunk)
                result = json.loads(response.split(b"\n", 1)[0])
                if (not isinstance(result, dict) or result.get("jsonrpc") != "2.0"
                        or result.get("id") != request["id"]):
                    raise ValueError("Invalid VPN helper response")
                return result
            except (OSError, ValueError, TypeError) as exc:
                raise MacOSHelperUnavailable(HELPER_UNAVAILABLE_MESSAGE) from exc

        def _daemon_result(self, method: str, params: Optional[dict] = None) -> dict:
            response = self._daemon_request(method, params)
            result = response.get("result") if isinstance(response, dict) else None
            error = response.get("error") if isinstance(response, dict) else None
            if isinstance(error, dict) and error.get("code") == -32602:
                raise VPNConnectionError(
                    "The macOS VPN helper rejected the connection settings. "
                    "Check the server address, protocol and authentication settings.",
                    error_code="invalid_params",
                )
            if (not isinstance(response, dict) or "error" in response
                    or not isinstance(result, dict) or "error" in result):
                raise MacOSHelperUnavailable(HELPER_UNAVAILABLE_MESSAGE)
            return result

        def ensure_helper_available(self) -> None:
            """Fail before sign-in if the installed helper is unavailable."""
            result = self._daemon_result("ping")
            if result.get("pong") is not True:
                raise MacOSHelperUnavailable(HELPER_UNAVAILABLE_MESSAGE)
            version = re.fullmatch(
                r"(\d+)\.(\d+)\.(\d+)(?:[-+][\w.-]+)?", str(result.get("version", "")),
            )
            if version is None or tuple(map(int, version.groups())) < (1, 1, 0):
                raise MacOSHelperUnavailable(
                    "The installed macOS VPN helper needs an update. Install the latest macOS "
                    "package, then try again. Administrator approval is only required during installation."
                )

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
            gp_auth_interface: str = "portal",
            gp_os_version: Optional[str] = None,
            cancel_callback: Optional[Callable[[], bool]] = None,
        ) -> bool:
            """Connect through the installed helper without requesting admin access."""
            cancelled = cancel_callback or (lambda: False)
            if cancelled():
                raise _connection_error({"error_code": "connection_cancelled"})
            self.ensure_helper_available()
            if cancelled():
                raise _connection_error({"error_code": "connection_cancelled"})
            result = self._daemon_result("connect", {
                "address": address,
                "protocol": protocol,
                "cookies": cookies,
                "no_dtls": no_dtls,
                "username": username,
                "connection_name": connection_name,
                "cached_usergroup": cached_usergroup,
                "gp_auth_interface": gp_auth_interface,
                "gp_os_version": gp_os_version,
            })
            if not isinstance(result.get("success"), bool):
                raise MacOSHelperUnavailable(HELPER_UNAVAILABLE_MESSAGE)
            if not result["success"]:
                raise _connection_error(result)
            if cancelled():
                # Disconnect may have arrived before this request reached the
                # helper. Clean up only after it accepted our connection; a
                # rejected request must never disconnect another session.
                self.disconnect()
                raise _connection_error({"error_code": "connection_cancelled"})
            return result["success"]

        def disconnect(self, force: bool = False) -> bool:
            """Ask the helper to gracefully stop only its own VPN process."""
            result = self._daemon_result("disconnect", {"force": force})
            if not isinstance(result.get("success"), bool):
                raise MacOSHelperUnavailable(HELPER_UNAVAILABLE_MESSAGE)
            if not result["success"]:
                raise _connection_error(result)
            if result["success"] and force:
                self.clear_stored_cookies()
            return result["success"]

        def is_connected(self, require_helper: bool = False) -> bool:
            """Poll quietly for the tray, or fail an active session on helper loss."""
            try:
                result = self._daemon_result("status")
                if not isinstance(result.get("connected"), bool):
                    raise MacOSHelperUnavailable(HELPER_UNAVAILABLE_MESSAGE)
                return result["connected"]
            except (MacOSHelperUnavailable, VPNConnectionError):
                if require_helper:
                    raise
                return False

    else:
        def connect_vpn(
            self, address: str, protocol: str, cookies: dict, no_dtls: bool = False,
            username: Optional[str] = None, allow_fallback: bool = False,
            connection_name: Optional[str] = None, cached_usergroup: Optional[str] = None,
            **options,
        ) -> bool:
            return core_connect_vpn(
                address, protocol, cookies, no_dtls, username,
                allow_fallback, connection_name, cached_usergroup,
                use_pkexec=True, **options,
            )

        def disconnect(self, force: bool = False) -> bool:
            from core.connect import disconnect
            return disconnect(force=force, use_pkexec=True)

        def is_connected(self) -> bool:
            from core.connect import is_connected
            return is_connected()
