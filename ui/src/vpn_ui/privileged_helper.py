"""Privileged launchd helper for macOS openconnect operations."""

import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from shutil import which

SOCKET_PATH = "/var/run/ms-sso-openconnect-ui.sock"
PKILL_PATH = "/usr/bin/pkill"
PGREP_PATH = "/usr/bin/pgrep"

OPENCONNECT_CANDIDATES = [
    "/usr/local/bin/openconnect",
    "/opt/homebrew/bin/openconnect",
    "/usr/bin/openconnect",
    "/usr/sbin/openconnect",
]


def _find_openconnect() -> str | None:
    for path in OPENCONNECT_CANDIDATES:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return path
    return which("openconnect")


def _build_openconnect_command(
    openconnect_path: str,
    address: str,
    protocol: str,
    cookies: dict,
    no_dtls: bool,
    username: str | None,
    cached_usergroup: str | None,
) -> tuple[list[str], str | None]:
    cookie_data = dict(cookies or {})
    cookie_data.pop("_gateway_ip", None)
    proto_flag = "gp" if protocol == "gp" else "anyconnect"

    gp_cookie_type = None
    if protocol == "gp":
        if cached_usergroup:
            gp_cookie_type = cached_usergroup
            if "portal-userauthcookie" in cookie_data:
                cookie_str = cookie_data["portal-userauthcookie"]
            elif "prelogin-cookie" in cookie_data:
                cookie_str = cookie_data["prelogin-cookie"]
            else:
                cookie_str = "; ".join([f"{k}={v}" for k, v in cookie_data.items()])
        elif "prelogin-cookie" in cookie_data:
            cookie_str = cookie_data["prelogin-cookie"]
            gp_cookie_type = "portal:prelogin-cookie"
        elif "portal-userauthcookie" in cookie_data:
            cookie_str = cookie_data["portal-userauthcookie"]
            gp_cookie_type = "portal:portal-userauthcookie"
        elif "SAMLResponse" in cookie_data:
            cookie_str = cookie_data["SAMLResponse"]
            gp_cookie_type = "prelogin-cookie"
        elif "SESSID" in cookie_data:
            cookie_str = cookie_data["SESSID"]
            gp_cookie_type = "portal-userauthcookie"
        else:
            cookie_str = "; ".join([f"{k}={v}" for k, v in cookie_data.items()])
            gp_cookie_type = "portal-userauthcookie"
    else:
        cookie_str = "; ".join([f"{k}={v}" for k, v in cookie_data.items()])

    use_stdin_cookie = protocol == "gp" and "prelogin-cookie" in cookie_data

    if use_stdin_cookie:
        cmd = [
            openconnect_path,
            "--verbose",
            f"--protocol={proto_flag}",
            "--passwd-on-stdin",
            address,
        ]
    else:
        cmd = [
            openconnect_path,
            "--verbose",
            f"--protocol={proto_flag}",
            f"--cookie={cookie_str}",
            address,
        ]

    if protocol == "gp":
        cmd.insert(2, "--os=linux-64")
        cmd.insert(2, "--useragent=PAN GlobalProtect")
        if username:
            cmd.insert(2, f"--user={username}")
        if gp_cookie_type:
            cmd.insert(2, f"--usergroup={gp_cookie_type}")

    if no_dtls:
        cmd.insert(2, "--no-dtls")

    return cmd, (cookie_str if use_stdin_cookie else None)


class OpenConnectHelper:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._process: subprocess.Popen | None = None
        self._portal_cookie: str | None = None
        self._portal_usergroup: str | None = None
        self._portal_event = threading.Event()

    def _is_connected(self) -> bool:
        if self._process and self._process.poll() is None:
            return True
        result = subprocess.run([PGREP_PATH, "-x", "openconnect"], capture_output=True)
        return result.returncode == 0

    def _read_output(self, process: subprocess.Popen) -> None:
        if process.stdout is None:
            return

        for line in process.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()

            if "portal-userauthcookie=" in line:
                match = re.search(r"portal-userauthcookie=(\S+)", line)
                if match:
                    cookie = match.group(1)
                    if cookie.lower() != "empty":
                        self._portal_cookie = cookie
                        self._portal_usergroup = "portal:portal-userauthcookie"
                        self._portal_event.set()

        process.wait()
        with self._lock:
            if self._process is process:
                self._process = None

    def handle_connect(self, payload: dict) -> dict:
        address = payload.get("address")
        protocol = payload.get("protocol", "anyconnect")
        cookies = payload.get("cookies", {})
        no_dtls = bool(payload.get("no_dtls", False))
        username = payload.get("username")
        cached_usergroup = payload.get("cached_usergroup")

        if not address:
            return {"ok": False, "error": "Missing VPN server address."}

        with self._lock:
            if self._is_connected():
                return {"ok": False, "error": "openconnect is already running."}

            openconnect_path = _find_openconnect()
            if not openconnect_path:
                return {"ok": False, "error": "openconnect was not found on this system."}

            cmd, stdin_cookie = _build_openconnect_command(
                openconnect_path,
                address,
                protocol,
                cookies,
                no_dtls,
                username,
                cached_usergroup,
            )

            self._portal_cookie = None
            self._portal_usergroup = None
            self._portal_event.clear()

            try:
                if stdin_cookie is not None:
                    process = subprocess.Popen(
                        cmd,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        bufsize=1,
                    )
                    assert process.stdin is not None
                    process.stdin.write(stdin_cookie + "\n")
                    process.stdin.flush()
                    process.stdin.close()
                else:
                    process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        bufsize=1,
                    )
            except Exception as exc:
                return {"ok": False, "error": f"Failed to start openconnect: {exc}"}

            self._process = process
            thread = threading.Thread(target=self._read_output, args=(process,), daemon=True)
            thread.start()

        time.sleep(0.5)
        if process.poll() is not None:
            return {
                "ok": False,
                "error": f"openconnect exited with code {process.returncode}",
            }

        if protocol == "gp":
            self._portal_event.wait(timeout=3.0)

        return {
            "ok": True,
            "pid": process.pid,
            "portal_cookie": self._portal_cookie,
            "portal_usergroup": self._portal_usergroup,
        }

    def handle_disconnect(self, payload: dict) -> dict:
        force = bool(payload.get("force", False))
        # On macOS, use SIGTERM for graceful cleanup to restore networking.
        signal_flag = "-TERM"

        result = subprocess.run(
            [PKILL_PATH, signal_flag, "-x", "openconnect"], capture_output=True
        )
        if result.returncode != 0:
            return {"ok": False, "error": "No openconnect process found."}

        with self._lock:
            self._process = None
            self._portal_cookie = None
            self._portal_usergroup = None
            self._portal_event.clear()

        return {"ok": True}

    def handle_status(self) -> dict:
        return {
            "ok": True,
            "running": self._is_connected(),
            "portal_cookie": self._portal_cookie,
            "portal_usergroup": self._portal_usergroup,
        }


def _set_socket_permissions(path: str) -> None:
    try:
        import grp

        admin_gid = grp.getgrnam("admin").gr_gid
        os.chown(path, 0, admin_gid)
        os.chmod(path, 0o660)
    except Exception:
        os.chmod(path, 0o666)


def _handle_client(helper: OpenConnectHelper, conn: socket.socket) -> None:
    with conn:
        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\n" in chunk:
                break

        if not data:
            return

        try:
            payload = json.loads(data.decode("utf-8").strip())
        except json.JSONDecodeError:
            conn.sendall(b"{\"ok\": false, \"error\": \"Invalid request\"}\n")
            return

        action = payload.get("action")
        if action == "connect":
            response = helper.handle_connect(payload)
        elif action == "disconnect":
            response = helper.handle_disconnect(payload)
        elif action == "status":
            response = helper.handle_status()
        else:
            response = {"ok": False, "error": "Unknown action"}

        conn.sendall(json.dumps(response).encode("utf-8") + b"\n")


def main() -> int:
    helper = OpenConnectHelper()

    if os.path.exists(SOCKET_PATH):
        try:
            os.unlink(SOCKET_PATH)
        except OSError:
            pass

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)
    _set_socket_permissions(SOCKET_PATH)
    server.listen(5)

    def _shutdown(_signum: int, _frame) -> None:
        try:
            server.close()
        finally:
            if os.path.exists(SOCKET_PATH):
                try:
                    os.unlink(SOCKET_PATH)
                except OSError:
                    pass
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    while True:
        try:
            conn, _ = server.accept()
        except OSError:
            continue
        thread = threading.Thread(target=_handle_client, args=(helper, conn), daemon=True)
        thread.start()


if __name__ == "__main__":
    sys.exit(main())
