#!/usr/bin/env python3
"""VPN Daemon - runs as root via LaunchDaemon.

This daemon manages openconnect connections on macOS. It:
- Listens on a Unix socket for commands from the UI
- Starts openconnect with the provided credentials
- Gracefully stops openconnect with SIGTERM (restores network)
- Reports connection status

The daemon runs as root, so individual VPN connections don't require
sudo prompts - only the initial pkg installation requires admin.

Usage (development):
    sudo python3 vpn_daemon.py
"""

import asyncio
import json
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import Optional

# Constants (defined here to allow standalone execution)
DAEMON_VERSION = "1.0.0"
SOCKET_PATH = "/var/run/ms-sso-openconnect/daemon.sock"
PID_FILE = "/var/run/ms-sso-openconnect/daemon.pid"

# Search paths for openconnect binary
OPENCONNECT_PATHS = [
    "/opt/homebrew/bin/openconnect",
    "/usr/local/bin/openconnect",
    "/usr/bin/openconnect",
]


def find_openconnect() -> Optional[str]:
    """Find the openconnect binary."""
    for path in OPENCONNECT_PATHS:
        if os.path.exists(path):
            return path
    return None


# Try to import from protocol module, but make it optional for standalone use
try:
    from ui.macos.daemon.protocol import Request, Response, ErrorCode, Method
    USE_PROTOCOL_MODULE = True
except ImportError:
    USE_PROTOCOL_MODULE = False


class VPNDaemon:
    """VPN daemon that manages openconnect connections."""

    def __init__(self):
        self._openconnect_proc: Optional[subprocess.Popen] = None
        self._current_connection: Optional[str] = None
        self._server: Optional[asyncio.Server] = None
        self._running = True

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle a client connection."""
        try:
            data = await asyncio.wait_for(reader.readline(), timeout=30)
            if not data:
                return

            request_str = data.decode().strip()
            try:
                request = json.loads(request_str)
            except json.JSONDecodeError:
                response = {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": 0}
                writer.write(json.dumps(response).encode() + b"\n")
                await writer.drain()
                return

            method = request.get("method", "")
            params = request.get("params", {})
            req_id = request.get("id", 0)

            # Dispatch to handler
            result = await self._dispatch(method, params)
            response = {"jsonrpc": "2.0", "result": result, "id": req_id}
            writer.write(json.dumps(response).encode() + b"\n")
            await writer.drain()

        except asyncio.TimeoutError:
            pass
        except Exception as e:
            print(f"[Daemon] Error handling client: {e}", file=sys.stderr)
        finally:
            writer.close()
            await writer.wait_closed()

    async def _dispatch(self, method: str, params: dict) -> dict:
        """Dispatch a request to the appropriate handler."""
        handlers = {
            "ping": self._handle_ping,
            "connect": self._handle_connect,
            "disconnect": self._handle_disconnect,
            "status": self._handle_status,
        }

        handler = handlers.get(method)
        if not handler:
            return {"error": f"Unknown method: {method}"}

        try:
            return await handler(params)
        except Exception as e:
            return {"error": str(e)}

    async def _handle_ping(self, params: dict) -> dict:
        """Handle ping request."""
        return {"pong": True, "version": DAEMON_VERSION}

    async def _handle_connect(self, params: dict) -> dict:
        """Handle connect request."""
        # Check if already connected
        if self._openconnect_proc and self._openconnect_proc.poll() is None:
            return {"success": False, "message": "Already connected"}

        # Build openconnect command
        address = params.get("address")
        protocol = params.get("protocol", "anyconnect")
        cookies = params.get("cookies", {})
        no_dtls = params.get("no_dtls", False)
        username = params.get("username")
        cached_usergroup = params.get("cached_usergroup")

        if not address:
            return {"success": False, "message": "Address is required"}

        # Find openconnect binary
        openconnect_bin = find_openconnect()
        if not openconnect_bin:
            return {"success": False, "message": "openconnect not found in standard paths"}

        cmd = [openconnect_bin]

        # Add protocol
        if protocol == "gp":
            cmd.extend(["--protocol=gp"])
        else:
            cmd.extend(["--protocol=anyconnect"])

        # Add username if provided
        if username:
            cmd.extend(["--user", username])

        # Add no-dtls if requested
        if no_dtls:
            cmd.append("--no-dtls")

        # Note: --dpd is not supported in all openconnect versions

        # Handle cookies based on protocol
        cookie_value = None
        if protocol == "gp":
            # GlobalProtect uses different cookie handling
            if "portal-userauthcookie" in cookies:
                cookie_value = cookies["portal-userauthcookie"]
                cmd.extend(["--usergroup", "portal:portal-userauthcookie"])
            elif "portal_userauthcookie" in cookies:
                cookie_value = cookies["portal_userauthcookie"]
                cmd.extend(["--usergroup", "portal:portal-userauthcookie"])
            elif "prelogin-cookie" in cookies:
                cmd.extend(["--usergroup", f"portal:{cached_usergroup or 'prelogin-cookie'}"])
                cookie_value = cookies["prelogin-cookie"]
        else:
            # AnyConnect - check various cookie names
            # webvpn is the standard AnyConnect cookie
            # SVPNCOOKIE is used by some servers
            for key in ["webvpn", "SVPNCOOKIE", "session_token"]:
                if key in cookies:
                    cookie_value = cookies[key]
                    print(f"[Daemon] Using cookie key: {key}", file=sys.stderr)
                    break

            # If no specific cookie found, try combining all cookies
            if not cookie_value and cookies:
                cookie_value = "; ".join([f"{k}={v}" for k, v in cookies.items()])
                print(f"[Daemon] Using combined cookies", file=sys.stderr)

        # Add server address
        cmd.append(address)

        # Start openconnect
        try:
            # Log the command for debugging
            print(f"[Daemon] Running: {' '.join(cmd)}", file=sys.stderr)
            print(f"[Daemon] Cookies received: {list(cookies.keys())}", file=sys.stderr)
            print(f"[Daemon] Cookie available: {bool(cookie_value)}", file=sys.stderr)
            if cookie_value:
                print(f"[Daemon] Cookie length: {len(cookie_value)}", file=sys.stderr)
                print(f"[Daemon] Cookie preview: {cookie_value[:50]}...", file=sys.stderr)

            if cookie_value and protocol != "gp":
                # AnyConnect: pass cookie via stdin
                full_cmd = cmd + ["--cookie-on-stdin"]
                print(f"[Daemon] Full command: {' '.join(full_cmd)}", file=sys.stderr)
                self._openconnect_proc = subprocess.Popen(
                    full_cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )
                self._openconnect_proc.stdin.write((cookie_value + "\n").encode())
                self._openconnect_proc.stdin.close()
            elif cookie_value and protocol == "gp":
                # GlobalProtect: pass cookie via stdin with --passwd-on-stdin
                full_cmd = cmd + ["--passwd-on-stdin"]
                print(f"[Daemon] Full command (GP): {' '.join(full_cmd)}", file=sys.stderr)
                self._openconnect_proc = subprocess.Popen(
                    full_cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )
                self._openconnect_proc.stdin.write((cookie_value + "\n").encode())
                self._openconnect_proc.stdin.close()
            else:
                self._openconnect_proc = subprocess.Popen(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )

            # Wait briefly to check for immediate failure
            await asyncio.sleep(2)

            if self._openconnect_proc.poll() is not None:
                # Process exited immediately - read output for error
                output = self._openconnect_proc.stdout.read().decode()
                print(f"[Daemon] openconnect output: {output}", file=sys.stderr)
                return {"success": False, "message": f"Connection failed: {output[:500]}"}

            self._current_connection = params.get("connection_name", address)
            return {"success": True, "message": "Connected"}

        except Exception as e:
            return {"success": False, "message": str(e)}

    async def _handle_disconnect(self, params: dict) -> dict:
        """Handle disconnect request.

        IMPORTANT: Always uses SIGTERM for graceful shutdown.
        This allows openconnect to restore DNS and network settings,
        preventing the "network lockout" issue on macOS.
        """
        if not self._openconnect_proc:
            return {"success": False, "message": "Not connected"}

        if self._openconnect_proc.poll() is not None:
            # Already exited
            self._openconnect_proc = None
            self._current_connection = None
            return {"success": True, "message": "Already disconnected"}

        try:
            # ALWAYS use SIGTERM for graceful shutdown on macOS
            # This allows openconnect to clean up network settings
            self._openconnect_proc.send_signal(signal.SIGTERM)

            # Wait for graceful shutdown (up to 10 seconds)
            try:
                self._openconnect_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                # Force kill if it doesn't respond
                print("[Daemon] Graceful shutdown timed out, force killing", file=sys.stderr)
                self._openconnect_proc.kill()
                self._openconnect_proc.wait()

            self._openconnect_proc = None
            self._current_connection = None
            return {"success": True, "message": "Disconnected"}

        except Exception as e:
            return {"success": False, "message": str(e)}

    async def _handle_status(self, params: dict) -> dict:
        """Handle status request."""
        if self._openconnect_proc and self._openconnect_proc.poll() is None:
            return {
                "connected": True,
                "connection_name": self._current_connection,
                "pid": self._openconnect_proc.pid
            }
        return {"connected": False, "connection_name": None, "pid": None}

    def _signal_handler(self, signum, frame):
        """Handle termination signals."""
        print(f"[Daemon] Received signal {signum}, shutting down...", file=sys.stderr)
        self._running = False

        # Gracefully disconnect if connected
        if self._openconnect_proc and self._openconnect_proc.poll() is None:
            print("[Daemon] Disconnecting VPN...", file=sys.stderr)
            self._openconnect_proc.send_signal(signal.SIGTERM)
            try:
                self._openconnect_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._openconnect_proc.kill()

    async def run(self):
        """Run the daemon."""
        # Setup signal handlers
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        # Create socket directory
        socket_dir = Path(SOCKET_PATH).parent
        socket_dir.mkdir(parents=True, exist_ok=True)

        # Remove stale socket
        socket_path = Path(SOCKET_PATH)
        if socket_path.exists():
            socket_path.unlink()

        # Write PID file
        Path(PID_FILE).write_text(str(os.getpid()))

        # Start server
        self._server = await asyncio.start_unix_server(
            self.handle_client,
            path=SOCKET_PATH
        )

        # Set socket permissions (allow all users to connect)
        os.chmod(SOCKET_PATH, 0o666)

        openconnect_bin = find_openconnect()
        print(f"[Daemon] VPN daemon v{DAEMON_VERSION} started")
        print(f"[Daemon] Listening on {SOCKET_PATH}")
        print(f"[Daemon] openconnect binary: {openconnect_bin or 'NOT FOUND'}")

        try:
            while self._running:
                await asyncio.sleep(1)

                # Check if openconnect died unexpectedly
                if self._openconnect_proc and self._openconnect_proc.poll() is not None:
                    exit_code = self._openconnect_proc.returncode
                    output = ""
                    try:
                        output = self._openconnect_proc.stdout.read().decode()[:1000]
                    except:
                        pass
                    print(f"[Daemon] openconnect process exited with code {exit_code}", file=sys.stderr)
                    if output:
                        print(f"[Daemon] Output: {output}", file=sys.stderr)
                    self._openconnect_proc = None
                    self._current_connection = None
        finally:
            self._server.close()
            await self._server.wait_closed()

            # Cleanup
            if socket_path.exists():
                socket_path.unlink()
            pid_path = Path(PID_FILE)
            if pid_path.exists():
                pid_path.unlink()

            print("[Daemon] Shutdown complete")


def main():
    """Main entry point."""
    # Check if running as root
    if os.geteuid() != 0:
        print("Error: This daemon must run as root", file=sys.stderr)
        sys.exit(1)

    daemon = VPNDaemon()
    asyncio.run(daemon.run())


if __name__ == "__main__":
    main()
