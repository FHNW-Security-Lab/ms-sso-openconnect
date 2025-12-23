"""Platform-specific VPN backend implementations.

This module provides the VPNBackend class with platform-specific
implementations for connecting, disconnecting, and checking VPN status.

- Linux: Uses pkexec for privilege escalation, SIGKILL for disconnect
- macOS: Uses daemon IPC for privilege escalation, SIGTERM for graceful disconnect
"""

import subprocess
import sys
from typing import Optional

from vpn_ui.backend.shared import SharedBackendMixin, core_connect_vpn


if sys.platform == "darwin":
    # macOS-specific imports and constants
    DAEMON_SOCKET = "/var/run/ms-sso-openconnect/daemon.sock"


class VPNBackend(SharedBackendMixin):
    """Platform-specific VPN backend.

    Inherits shared functionality from SharedBackendMixin and provides
    platform-specific implementations for:
    - connect_vpn
    - disconnect
    - is_connected
    """

    def __init__(self):
        """Initialize the backend."""
        pass

    if sys.platform == "darwin":
        # =====================================================================
        # macOS Implementation - Uses daemon IPC
        # =====================================================================

        def _daemon_request(self, method: str, params: dict = None) -> dict:
            """Send a request to the VPN daemon.

            Args:
                method: RPC method name
                params: Optional parameters

            Returns:
                Response dict with 'result' or 'error'
            """
            import json
            import socket

            request = {
                "jsonrpc": "2.0",
                "method": method,
                "params": params or {},
                "id": 1
            }

            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(30)
                sock.connect(DAEMON_SOCKET)
                sock.sendall(json.dumps(request).encode() + b"\n")
                response = sock.recv(65536)
                sock.close()
                return json.loads(response.decode())
            except FileNotFoundError:
                return {"error": {"code": -1, "message": "Daemon not running"}}
            except Exception as e:
                return {"error": {"code": -1, "message": str(e)}}

        def _is_daemon_available(self) -> bool:
            """Check if the daemon is running and responsive."""
            try:
                result = self._daemon_request("ping")
                return "result" in result and result["result"].get("pong")
            except Exception:
                return False

        def _find_openconnect(self) -> Optional[str]:
            """Find openconnect binary path."""
            import os
            for path in ["/opt/homebrew/bin/openconnect", "/usr/local/bin/openconnect", "/usr/bin/openconnect"]:
                if os.path.exists(path):
                    return path
            return None

        def _connect_with_osascript(
            self,
            address: str,
            protocol: str,
            cookies: dict,
            no_dtls: bool = False,
            username: Optional[str] = None,
        ) -> bool:
            """Connect to VPN using osascript for admin privileges (macOS fallback).

            This is used when the daemon is not available.
            """
            import shlex

            openconnect_bin = self._find_openconnect()
            if not openconnect_bin:
                print("[Error] openconnect not found")
                return False

            # Build command
            cmd_parts = [openconnect_bin, "--verbose", f"--protocol={protocol}"]

            if no_dtls:
                cmd_parts.append("--no-dtls")

            if username:
                cmd_parts.extend(["--user", username])

            # Handle cookies based on protocol
            cookie_value = None
            gp_cookie_type = None

            if protocol == "gp":
                # GlobalProtect - add GP-specific options
                cmd_parts.extend(["--os=linux-64", "--useragent=PAN GlobalProtect"])

                # Determine cookie and usergroup type
                if "prelogin-cookie" in cookies:
                    cookie_value = cookies["prelogin-cookie"]
                    gp_cookie_type = "portal:prelogin-cookie"
                elif "portal-userauthcookie" in cookies:
                    cookie_value = cookies["portal-userauthcookie"]
                    gp_cookie_type = "portal:portal-userauthcookie"

                if gp_cookie_type:
                    cmd_parts.append(f"--usergroup={gp_cookie_type}")
            else:
                # AnyConnect/other
                cookie_value = cookies.get("webvpn") or cookies.get("session_token")
                if not cookie_value:
                    # Try to combine all cookies
                    cookie_value = "; ".join([f"{k}={v}" for k, v in cookies.items()])

            cmd_parts.append(address)

            # Build shell command with cookie on stdin
            if cookie_value:
                # GlobalProtect uses --passwd-on-stdin, AnyConnect uses --cookie-on-stdin
                stdin_flag = "--passwd-on-stdin" if protocol == "gp" else "--cookie-on-stdin"
                cmd_parts.append(stdin_flag)
                # Escape the command parts for shell
                cmd_str = " ".join(shlex.quote(p) for p in cmd_parts)
                # Create script that pipes cookie to openconnect
                shell_cmd = f"echo {shlex.quote(cookie_value)} | {cmd_str}"
            else:
                cmd_str = " ".join(shlex.quote(p) for p in cmd_parts)
                shell_cmd = cmd_str

            # Escape for AppleScript (backslash-escape quotes and backslashes)
            shell_cmd_escaped = shell_cmd.replace("\\", "\\\\").replace('"', '\\"')

            # Wrap in osascript for admin privileges
            script = f'do shell script "{shell_cmd_escaped}" with administrator privileges'

            try:
                print(f"[Fallback] Connecting via osascript...")
                print(f"[Fallback] Command: {cmd_str}")
                result = subprocess.Popen(
                    ["osascript", "-e", script],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )
                # Don't wait - openconnect runs in foreground
                # Give it a moment to start
                import time
                time.sleep(3)

                # Check if it's running
                if self.is_connected():
                    return True

                # Check if osascript is still running (user might be entering password)
                if result.poll() is None:
                    # Wait a bit more for password dialog
                    time.sleep(5)
                    if self.is_connected():
                        return True

                output = result.stdout.read().decode()[:500] if result.stdout else ""
                print(f"[Fallback] Failed: {output}")
                return False
            except Exception as e:
                print(f"[Fallback] Error: {e}")
                return False

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
            """Connect to VPN via daemon IPC (macOS).

            The daemon runs as root and manages openconnect, eliminating
            the need for per-connection sudo prompts.
            """
            if self._is_daemon_available():
                # Use daemon for connection
                result = self._daemon_request("connect", {
                    "address": address,
                    "protocol": protocol,
                    "cookies": cookies,
                    "no_dtls": no_dtls,
                    "username": username,
                    "connection_name": connection_name,
                    "cached_usergroup": cached_usergroup,
                })
                if "result" in result:
                    return result["result"].get("success", False)
                # Daemon returned error, fall back to direct connection
                print(f"[Daemon error] {result.get('error', {}).get('message', 'Unknown')}")

            # Fallback: direct connection with osascript for admin privileges
            return self._connect_with_osascript(
                address, protocol, cookies, no_dtls, username
            )

        def disconnect(self, force: bool = False) -> bool:
            """Disconnect from VPN via daemon IPC (macOS).

            Always uses SIGTERM for graceful shutdown to restore network.
            This prevents DNS lockout issues on macOS.

            Args:
                force: If True, also terminates the session. On macOS, the
                       signal is always SIGTERM (graceful) regardless.
            """
            if self._is_daemon_available():
                result = self._daemon_request("disconnect", {"force": force})
                if "result" in result:
                    success = result["result"].get("success", False)
                    if success and force:
                        self.clear_stored_cookies()
                    return success

            # Fallback: use osascript for admin privileges
            # IMPORTANT: Always use SIGTERM on macOS for graceful shutdown
            try:
                script = 'do shell script "pkill -TERM -x openconnect" with administrator privileges'
                result = subprocess.run(
                    ["osascript", "-e", script],
                    capture_output=True,
                    timeout=60
                )
                if result.returncode == 0:
                    if force:
                        self.clear_stored_cookies()
                    return True

                # Try killall as alternative
                script = 'do shell script "killall -TERM openconnect" with administrator privileges'
                result = subprocess.run(
                    ["osascript", "-e", script],
                    capture_output=True,
                    timeout=60
                )
                return result.returncode == 0
            except Exception:
                return False

        def is_connected(self) -> bool:
            """Check if VPN is connected (macOS)."""
            if self._is_daemon_available():
                result = self._daemon_request("status")
                if "result" in result:
                    return result["result"].get("connected", False)

            # Fallback: check process directly
            try:
                result = subprocess.run(
                    ["pgrep", "-x", "openconnect"],
                    capture_output=True,
                    text=True
                )
                return result.returncode == 0
            except Exception:
                return False

    else:
        # =====================================================================
        # Linux Implementation - Uses pkexec
        # =====================================================================

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
            """Connect to VPN using pkexec (Linux).

            Uses pkexec (PolicyKit) for privilege escalation which shows
            a graphical password prompt.
            """
            return core_connect_vpn(
                address, protocol, cookies, no_dtls, username,
                allow_fallback, connection_name, cached_usergroup,
                use_pkexec=True  # Use pkexec for GUI (no terminal needed)
            )

        def disconnect(self, force: bool = False) -> bool:
            """Disconnect from VPN using pkexec (Linux).

            Args:
                force: If True, send SIGTERM (terminate session).
                       If False, send SIGKILL (keep session alive for reconnect).
            """
            try:
                # IMPORTANT: Use -x for exact process name match
                # -f would match paths containing "openconnect" and kill the UI
                signal_flag = "-TERM" if force else "-KILL"
                result = subprocess.run(
                    ["pkexec", "pkill", signal_flag, "-x", "openconnect"],
                    capture_output=True
                )
                if result.returncode == 0:
                    if force:
                        self.clear_stored_cookies()
                    return True

                # Fallback: try sudo (might work if running from terminal)
                result = subprocess.run(
                    ["sudo", "-n", "pkill", signal_flag, "-x", "openconnect"],
                    capture_output=True
                )
                return result.returncode == 0
            except Exception:
                return False

        def is_connected(self) -> bool:
            """Check if VPN is connected (Linux)."""
            try:
                # Use pgrep -x for exact process name match
                result = subprocess.run(
                    ["pgrep", "-x", "openconnect"],
                    capture_output=True,
                    text=True
                )
                return result.returncode == 0
            except Exception:
                return False
