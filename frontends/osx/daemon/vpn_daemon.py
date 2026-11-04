#!/usr/bin/env python3
"""Installed macOS VPN helper; only installation needs administrator approval.

The helper uses a bounded local JSON-RPC connection and only manages the
OpenConnect process it started. It has no dependency on the UI's Python modules.
"""

import argparse
import asyncio
import html
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

DAEMON_VERSION = "1.1.0"
SOCKET_PATH = "/var/run/ms-sso-openconnect/daemon.sock"
PID_FILE = "/var/run/ms-sso-openconnect/daemon.pid"
MAX_MESSAGE_BYTES = 1024 * 1024
CONNECT_TIMEOUT = 45
HIP_WRAPPER_PATH = "/Library/PrivilegedHelperTools/ms-sso-openconnect/ms-sso-hip-report"
OPENCONNECT_PATHS = [
    "/opt/homebrew/bin/openconnect",
    "/usr/local/bin/openconnect",
    "/usr/bin/openconnect",
]


def find_openconnect() -> Optional[str]:
    for path in OPENCONNECT_PATHS:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def find_base_hipreport():
    for path in ("/opt/homebrew/opt/openconnect/libexec/openconnect/hipreport.sh",
                 "/usr/local/opt/openconnect/libexec/openconnect/hipreport.sh",
                 "/usr/local/libexec/openconnect/hipreport.sh",
                 "/usr/local/lib/openconnect/hipreport.sh"):
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def run_hip_report(arguments):
    """Adapt OpenConnect's native Mac HIP report to the selected OS version."""
    base = find_base_hipreport()
    if not base:
        print("OpenConnect HIP report support is unavailable", file=sys.stderr)
        return 127
    try:
        result = subprocess.run([base, *arguments], capture_output=True, text=True,
                                check=False, timeout=30)
    except (OSError, subprocess.SubprocessError):
        print("OpenConnect HIP report generation failed", file=sys.stderr)
        return 1
    if result.returncode:
        print("OpenConnect HIP report generation failed", file=sys.stderr)
        return result.returncode
    output = result.stdout
    version = (os.environ.get("MS_SSO_GP_OS_VERSION") or "").strip()
    if version and version.lower() != "auto":
        output = re.sub(r"<os>.*?</os>", lambda _: f"<os>{html.escape(version)}</os>",
                        output, count=1, flags=re.DOTALL)
    output = re.sub(r"<os-vendor>.*?</os-vendor>", "<os-vendor>Apple</os-vendor>",
                    output, count=1, flags=re.DOTALL)
    sys.stdout.write(output)
    return 0


class RPCError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _text(value, label, optional=False):
    if optional and value is None:
        return
    if not isinstance(value, str) or any(c in value for c in "\r\n\0"):
        raise RPCError(-32602, f"Invalid {label}")


def _validate_connect(params):
    allowed = {"address", "protocol", "cookies", "no_dtls", "username",
               "connection_name", "cached_usergroup", "gp_auth_interface", "gp_os_version"}
    if set(params) - allowed:
        raise RPCError(-32602, "Unsupported connection option")
    address = params.get("address")
    _text(address, "VPN address")
    try:
        parsed = urlsplit(address if "://" in address else "https://" + address)
        port = parsed.port
        if (not address or any(c.isspace() for c in address) or address.startswith("-")
                or parsed.scheme != "https" or not parsed.hostname
                or parsed.hostname.startswith("-") or parsed.username is not None
                or parsed.password is not None or parsed.fragment
                or (port is not None and port == 0)):
            raise ValueError
    except ValueError:
        raise RPCError(-32602, "Invalid VPN address") from None
    protocol = params.get("protocol", "anyconnect")
    if not isinstance(protocol, str) or protocol not in {"anyconnect", "gp"}:
        raise RPCError(-32602, "Unsupported VPN protocol")
    if not isinstance(params.get("no_dtls", False), bool):
        raise RPCError(-32602, "Invalid no_dtls option")
    for key in ("username", "connection_name", "cached_usergroup", "gp_os_version"):
        _text(params.get(key), key, optional=True)
    if params.get("gp_auth_interface", "portal") not in ("portal", "gateway"):
        raise RPCError(-32602, "Invalid GlobalProtect authentication interface")
    group = params.get("cached_usergroup")
    if group not in {None, "", "prelogin-cookie", "portal-userauthcookie",
                     "portal:prelogin-cookie", "portal:portal-userauthcookie",
                     "gateway:prelogin-cookie"}:
        raise RPCError(-32602, "Invalid GlobalProtect cookie group")
    cookies = params.get("cookies")
    if not isinstance(cookies, dict) or not cookies:
        raise RPCError(-32602, "VPN authentication returned no cookies")
    for key, value in cookies.items():
        _text(key, "cookie name")
        _text(value, "cookie value")
        if not key or any(c in key for c in "=;\t "):
            raise RPCError(-32602, "Invalid cookie name")


def _cookie_input(params):
    """Use the same full AnyConnect header as the shared core, privately on stdin."""
    cookies = params["cookies"]
    if params.get("protocol", "anyconnect") == "gp":
        interface = params.get("gp_auth_interface", "portal")
        names = (("prelogin-cookie",) if interface == "gateway" else
                 ("portal-userauthcookie", "portal_userauthcookie", "prelogin-cookie"))
        for name in names:
            if cookies.get(name):
                group_name = "portal-userauthcookie" if name == "portal_userauthcookie" else name
                group = interface + ":" + group_name
                value = cookies[name]
                return ["--passwd-on-stdin", "--usergroup=" + group], (value + "\n").encode()
        raise RPCError(-32602, "GlobalProtect authentication returned no usable cookie")
    parts = [f"{key.strip()}={value}" for key, value in cookies.items()
             if not key.startswith("_") and key.casefold() not in {"samlresponse", "saml-username"}]
    if not parts:
        raise RPCError(-32602, "AnyConnect authentication returned no usable cookies")
    # cookie-on-stdin has a small line limit. A private config input also handles
    # large modern SSO cookies without exposing them in the process arguments.
    return ["--config=/dev/stdin"], ("cookie=" + "; ".join(parts) + "\n").encode()


class VPNDaemon:
    def __init__(self):
        self._openconnect_proc: Optional[subprocess.Popen] = None
        self._current_connection: Optional[str] = None
        self._server: Optional[asyncio.Server] = None
        self._running = True
        self._lifecycle_lock = asyncio.Lock()
        self._stopping = asyncio.Event()
        self._connect_cancel = None
        self._connecting = False

    async def handle_client(self, reader, writer):
        req_id = None
        try:
            try:
                data = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=30)
            except (asyncio.LimitOverrunError, asyncio.IncompleteReadError):
                raise RPCError(-32600, "Request is incomplete or exceeds the size limit") from None
            if len(data) > MAX_MESSAGE_BYTES:
                raise RPCError(-32600, "Request exceeds the size limit")
            try:
                request = json.loads(data)
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise RPCError(-32700, "Parse error") from None
            if not isinstance(request, dict):
                raise RPCError(-32600, "Invalid request")
            req_id = request.get("id")
            if not (req_id is None or isinstance(req_id, (str, int))):
                req_id = None
                raise RPCError(-32600, "Invalid request id")
            if request.get("jsonrpc") != "2.0" or not isinstance(request.get("method"), str):
                raise RPCError(-32600, "Invalid request")
            params = request.get("params", {})
            if not isinstance(params, dict):
                raise RPCError(-32602, "Invalid request parameters")
            result = await self._dispatch(request["method"], params)
            response = {"jsonrpc": "2.0", "result": result, "id": req_id}
        except RPCError as exc:
            response = {"jsonrpc": "2.0", "error": {"code": exc.code, "message": str(exc)}, "id": req_id}
        except asyncio.TimeoutError:
            response = {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Request timed out"}, "id": req_id}
        except Exception:
            # Exceptions and process output may contain authentication material.
            response = {"jsonrpc": "2.0", "error": {"code": -32603, "message": "VPN helper operation failed"}, "id": req_id}
        try:
            writer.write(json.dumps(response).encode() + b"\n")
            await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    async def _dispatch(self, method, params):
        handlers = {"ping": self._handle_ping, "connect": self._handle_connect,
                    "disconnect": self._handle_disconnect, "status": self._handle_status}
        if method not in handlers:
            raise RPCError(-32601, "Unknown method")
        if method == "connect" and not self._running:
            return {"success": False, "message": "VPN helper is stopping",
                    "retryable": False, "error_code": "helper_stopping"}
        return await handlers[method](params)

    async def _handle_ping(self, params):
        return {"pong": True, "version": DAEMON_VERSION}

    async def _handle_connect(self, params):
        _validate_connect(params)
        flags, payload = _cookie_input(params)
        openconnect_bin = find_openconnect()
        if not openconnect_bin:
            return {"success": False, "message": "OpenConnect is not installed in a standard location",
                    "retryable": False, "error_code": "openconnect_missing"}
        protocol = params.get("protocol", "anyconnect")
        cmd = [openconnect_bin, "--protocol=" + protocol, "--non-inter",
               "--reconnect-timeout=300", "--force-dpd=" + ("10" if protocol == "gp" else "30")]
        username = params.get("username")
        env = os.environ.copy()
        if protocol == "gp":
            username = params["cookies"].get("saml-username") or username
            cmd.extend(["--useragent=PAN GlobalProtect", "--os=mac-intel"])
            if not find_base_hipreport() or not os.access(HIP_WRAPPER_PATH, os.X_OK):
                return {"success": False, "retryable": False, "error_code": "hip_support_missing",
                        "message": "OpenConnect HIP report support is unavailable; reinstall OpenConnect"}
            cmd.append("--csd-wrapper=" + HIP_WRAPPER_PATH)
            env["MS_SSO_GP_OS_VERSION"] = params.get("gp_os_version") or "auto"
        if username:
            cmd.append("--user=" + username)
        if params.get("no_dtls"):
            cmd.append("--no-dtls")
        cmd.extend(flags)
        cmd.extend(["--", params["address"]])
        async with self._lifecycle_lock:
            if self._openconnect_proc and self._openconnect_proc.poll() is None:
                return {"success": False, "message": "A VPN connection is already active",
                        "retryable": False, "error_code": "already_connected"}
            try:
                # The unlinked file has owner-only permissions and no pipe
                # capacity limit. The child inherits only the open descriptor.
                with tempfile.TemporaryFile() as secret:
                    secret.write(payload)
                    secret.seek(0)
                    process = subprocess.Popen(cmd, stdin=secret, stdout=subprocess.PIPE,
                                               stderr=subprocess.STDOUT, env=env)
            except (OSError, subprocess.SubprocessError):
                return {"success": False, "retryable": False, "error_code": "openconnect_start_failed",
                        "message": "OpenConnect could not be started"}
            self._openconnect_proc = process
            self._connect_cancel = cancelled = threading.Event()
            self._connecting = True
            self._current_connection = None
            ready = threading.Event()
            threading.Thread(target=self._consume_output, args=(process.stdout, ready),
                             daemon=True, name="openconnect-output").start()

        # Do not hold the lifecycle lock while waiting: Disconnect must be able
        # to cancel a slow portal/gateway negotiation without another prompt.
        loop = asyncio.get_running_loop()
        deadline = loop.time() + CONNECT_TIMEOUT
        while loop.time() < deadline:
            if cancelled.is_set():
                return {"success": False, "retryable": False, "error_code": "connection_cancelled",
                        "message": "Connection cancelled"}
            code = process.poll()
            if code is not None:
                async with self._lifecycle_lock:
                    if self._openconnect_proc is process:
                        self._openconnect_proc = None
                        self._connecting = False
                return {"success": False, "retryable": True, "error_code": "openconnect_exit",
                        "message": "OpenConnect exited before the VPN tunnel was ready", "exit_status": code}
            if ready.is_set():
                async with self._lifecycle_lock:
                    if self._openconnect_proc is process and not cancelled.is_set():
                        self._connecting = False
                        self._current_connection = params.get("connection_name") or params["address"]
                        return {"success": True, "message": "Connected"}
            await asyncio.sleep(0.1)
        async with self._lifecycle_lock:
            if self._openconnect_proc is process:
                await self._stop_owned_process()
        return {"success": False, "retryable": True, "error_code": "openconnect_timeout",
                "message": "VPN tunnel did not become ready in time"}

    @staticmethod
    def _consume_output(stream, ready):
        """Drain bounded output chunks without retaining or logging secrets."""
        try:
            while raw := stream.readline(4096):
                if re.match(rb"^(?:Connected|Configured) as [0-9a-fA-F:.]+", raw):
                    ready.set()
        except (OSError, ValueError):
            pass
        finally:
            stream.close()

    async def _handle_disconnect(self, params):
        if set(params) - {"force"} or not isinstance(params.get("force", False), bool):
            raise RPCError(-32602, "Invalid disconnect options")
        async with self._lifecycle_lock:
            return await self._stop_owned_process()

    async def _stop_owned_process(self):
        """Called with the lifecycle lock held; never signals unrelated VPNs."""
        if self._connect_cancel:
            self._connect_cancel.set()
        process = self._openconnect_proc
        if process and process.poll() is None:
            try:
                process.send_signal(signal.SIGTERM)
                await asyncio.to_thread(process.wait, timeout=10)
            except subprocess.TimeoutExpired:
                # Keep ownership; killing would bypass route/DNS cleanup.
                return {"success": False, "retryable": True, "error_code": "disconnect_in_progress",
                        "message": "VPN is still disconnecting; try again shortly"}
            except ProcessLookupError:
                pass
        self._openconnect_proc = None
        self._current_connection = None
        self._connecting = False
        return {"success": True, "message": "Disconnected"}

    async def _handle_status(self, params):
        if self._openconnect_proc and self._openconnect_proc.poll() is None:
            return {"connected": not self._connecting, "connecting": self._connecting,
                    "connection_name": self._current_connection,
                    "pid": self._openconnect_proc.pid}
        return {"connected": False, "connection_name": None, "pid": None}

    def _signal_handler(self, signum, frame):
        self._running = False
        self._stopping.set()

    async def _start_server(self, path):
        self._server = await asyncio.start_unix_server(
            self.handle_client, path=str(path), limit=MAX_MESSAGE_BYTES,
        )
        os.chmod(path, 0o666)

    async def run(self):
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        socket_path, pid_path = Path(SOCKET_PATH), Path(PID_FILE)
        socket_path.parent.mkdir(parents=True, exist_ok=True)
        socket_path.unlink(missing_ok=True)
        pid_path.write_text(str(os.getpid()))
        try:
            await self._start_server(socket_path)
            print(f"[Daemon] Started v{DAEMON_VERSION}", flush=True)
            await self._stopping.wait()
        finally:
            if self._server:
                self._server.close()
                await self._server.wait_closed()
            await self._handle_disconnect({})
            socket_path.unlink(missing_ok=True)
            pid_path.unlink(missing_ok=True)
            print("[Daemon] Shutdown complete", flush=True)


def check_helper(path=SOCKET_PATH):
    """Nonprivileged installer/startup health check; never starts a server."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(3)
            client.connect(path)
            client.sendall(b'{"jsonrpc":"2.0","method":"ping","params":{},"id":1}\n')
            data = bytearray()
            while b"\n" not in data:
                chunk = client.recv(min(65536, MAX_MESSAGE_BYTES + 1 - len(data)))
                if not chunk:
                    return False
                data.extend(chunk)
                if len(data) > MAX_MESSAGE_BYTES:
                    return False
            response = json.loads(bytes(data).split(b"\n", 1)[0])
            result = response.get("result", {})
            return (response.get("jsonrpc") == "2.0" and response.get("id") == 1
                    and isinstance(result, dict) and result.get("pong") is True
                    and result.get("version") == DAEMON_VERSION)
    except (OSError, ValueError, AttributeError):
        return False


def main():
    if sys.argv[1:2] == ["--hip-report"]:
        return run_hip_report(sys.argv[2:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Check the installed helper without elevation")
    parser.add_argument("--version", action="version", version=DAEMON_VERSION)
    args = parser.parse_args()
    if args.check:
        return 0 if check_helper() else 1
    if os.geteuid() != 0:
        print("Error: Install the macOS package to start the VPN helper", file=sys.stderr)
        return 1
    asyncio.run(VPNDaemon().run())
    return 0


if __name__ == "__main__":
    sys.exit(main())
