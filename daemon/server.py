#!/usr/bin/env python3
"""Privileged daemon for ms-sso-openconnect.

Runs as root/admin, listens on Unix socket for commands from GUI/CLI.
Only handles privileged operations: starting and stopping openconnect.
"""

import json
import logging
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from typing import Optional

from daemon.validator import validate_request
from .platform import (
    get_socket_path,
    get_pid_file,
    get_log_file,
    is_root,
    find_openconnect,
    kill_process,
    is_process_running,
    get_process_info,
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(get_log_file()),
    ],
)
log = logging.getLogger(__name__)


class VPNDaemon:
    """Daemon that manages openconnect process."""

    def __init__(self):
        self._vpn_process: Optional[subprocess.Popen] = None
        self._output_thread: Optional[threading.Thread] = None
        self._output_lines: list[str] = []
        self._running = True
        self._lock = threading.Lock()
        self._socket_path = get_socket_path()
        self._pid_file = get_pid_file()
        self._socket: Optional[socket.socket] = None

    def start(self):
        """Start daemon, listen for commands."""
        if not is_root():
            log.error("Daemon must run as root/admin")
            sys.exit(1)

        # Handle signals for clean shutdown
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        # Cleanup old socket
        if os.path.exists(self._socket_path):
            os.remove(self._socket_path)

        # Create Unix socket
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(self._socket_path)
        os.chmod(self._socket_path, 0o666)  # Allow non-root clients
        self._socket.listen(5)
        self._socket.settimeout(1.0)  # Allow periodic check of _running

        log.info(f"Daemon listening on {self._socket_path}")

        # Check for orphaned openconnect process
        self._recover_orphaned_process()

        while self._running:
            try:
                conn, _ = self._socket.accept()
                threading.Thread(
                    target=self._handle_connection,
                    args=(conn,),
                    daemon=True,
                ).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    log.error(f"Accept error: {e}")

        self._cleanup()

    def _handle_signal(self, signum, frame):
        """Handle shutdown signals."""
        log.info(f"Received signal {signum}, shutting down...")
        self._running = False

    def _cleanup(self):
        """Cleanup on shutdown."""
        if self._socket:
            self._socket.close()
        if os.path.exists(self._socket_path):
            os.remove(self._socket_path)
        log.info("Daemon stopped")

    def _recover_orphaned_process(self):
        """Check if openconnect is already running (e.g., after daemon restart)."""
        proc = find_openconnect()
        if proc:
            log.info(f"Found existing openconnect process (PID {proc.pid})")
            self._pid_file.write_text(str(proc.pid))

    def _handle_connection(self, conn: socket.socket):
        """Handle a client connection."""
        try:
            conn.settimeout(30.0)
            data = conn.recv(65536).decode("utf-8")
            if not data:
                return

            try:
                request = json.loads(data)
            except json.JSONDecodeError as e:
                log.error(f"Invalid JSON: {e}")
                conn.send(json.dumps({"success": False, "error": "Invalid JSON"}).encode())
                return

            #################################
            # INPUT VALIDATION / SANITIZING #
            #################################
            valid, error = validate_request(request)
            if not valid:
                log.warning(f"Invalid request: {error}")
                conn.send(json.dumps({"success": False, "error": error}).encode())
                return

            command = request.get("command")
            log.info(f"Received command: {command}")

            with self._lock:
                if command == "connect":
                    response = self._cmd_connect(request)
                elif command == "disconnect":
                    response = self._cmd_disconnect(request)
                elif command == "status":
                    response = self._cmd_status()
                elif command == "output":
                    response = self._cmd_output()

            conn.send(json.dumps(response).encode("utf-8"))

        except Exception as e:
            log.error(f"Connection handler error: {e}")
            try:
                conn.send(json.dumps({"success": False, "error": str(e)}).encode())
            except Exception:
                pass
        finally:
            conn.close()

    def _cmd_connect(self, request: dict) -> dict:
        """Handle connect command."""
        # Check if already connected
        if self._vpn_process and self._vpn_process.poll() is None:
            return {"success": False, "error": "Already connected"}

        existing = find_openconnect()
        if existing:
            return {"success": False, "error": f"OpenConnect already running (PID {existing.pid})"}

        server = request.get("server")
        protocol = request.get("protocol", "anyconnect")
        cookie = request.get("cookie", "")

        if not server:
            return {"success": False, "error": "Missing 'server' parameter"}
        if not cookie:
            return {"success": False, "error": "Missing 'cookie' parameter"}

        cmd = ["openconnect", "--verbose", f"--protocol={protocol}"]

        if request.get("no_dtls"):
            cmd.append("--no-dtls")

        # Protocol-specific handling
        if protocol == "gp":
            # GlobalProtect: stdin cookie, usergroup, os, useragent
            cmd.extend(["--os=linux-64", "--useragent=PAN GlobalProtect"])
            if request.get("username"):
                cmd.append(f"--user={request['username']}")
            if request.get("usergroup"):
                cmd.append(f"--usergroup={request['usergroup']}")
            cmd.extend(["--passwd-on-stdin", server])
            self._use_stdin = True
        else:
            # AnyConnect: cookie via --cookie flag
            if request.get("username"):
                cmd.append(f"--user={request['username']}")
            cmd.append(f"--cookie={cookie}")
            cmd.append(server)
            self._use_stdin = False

        log.info(f"Starting: {' '.join(cmd[:6])}... {server}")

        try:
            self._output_lines = []
            self._vpn_process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            # Send cookie via stdin for GlobalProtect only
            if self._use_stdin:
                self._vpn_process.stdin.write(cookie + "\n")
            self._vpn_process.stdin.close()

            # Save PID
            self._pid_file.parent.mkdir(parents=True, exist_ok=True)
            self._pid_file.write_text(str(self._vpn_process.pid))

            # Start output reader thread
            self._output_thread = threading.Thread(
                target=self._read_output,
                daemon=True,
            )
            self._output_thread.start()
            time.sleep(2)
            print(f"[DEBUG] First output lines: {self._output_lines[:5]}")

            log.info(f"OpenConnect started (PID {self._vpn_process.pid})")

            log.info(f"OpenConnect started (PID {self._vpn_process.pid})")

            # Wait for connection to establish or fail
            for i in range(15):  # Wait up to 15 seconds
                time.sleep(1)

                # Check if process died
                if self._vpn_process.poll() is not None:
                    error_output = "\n".join(self._output_lines[-10:])
                    log.error(f"OpenConnect exited: {error_output}")
                    self._vpn_process = None
                    if self._pid_file.exists():
                        self._pid_file.unlink()
                    return {"success": False, "error": f"OpenConnect failed: {error_output}"}

                # Check for success indicators in output
                output = "\n".join(self._output_lines)
                if "Connected as" in output or "ESP session established" in output or "DTLS connected" in output:
                    log.info("VPN connection established")
                    return {"success": True, "pid": self._vpn_process.pid}

                # Check for auth failure
                if "authentication failed" in output.lower() or "cookie rejected" in output.lower():
                    log.error(f"Auth failed: {output}")
                    return {"success": False, "error": "Authentication failed"}

            # Timeout but process still running - might be okay
            return {"success": True, "pid": self._vpn_process.pid}

        except FileNotFoundError:
            return {"success": False, "error": "openconnect not found in PATH"}
        except Exception as e:
            log.error(f"Failed to start openconnect: {e}")
            return {"success": False, "error": str(e)}

    def _read_output(self):
        """Read openconnect stdout in background thread."""
        if not self._vpn_process or not self._vpn_process.stdout:
            return

        try:
            for line in self._vpn_process.stdout:
                line = line.rstrip("\n")
                self._output_lines.append(line)
                # Keep last 100 lines
                if len(self._output_lines) > 100:
                    self._output_lines.pop(0)
                log.debug(f"[openconnect] {line}")
        except Exception:
            pass

    def _cmd_disconnect(self, request: dict) -> dict:
        """Handle disconnect command."""
        pid = None

        # Find PID from our process, PID file, or by searching
        if self._vpn_process and self._vpn_process.poll() is None:
            pid = self._vpn_process.pid
        elif self._pid_file.exists():
            try:
                pid = int(self._pid_file.read_text().strip())
                if not is_process_running(pid):
                    pid = None
            except (ValueError, OSError):
                pid = None

        if not pid:
            proc = find_openconnect()
            if proc:
                pid = proc.pid

        if not pid:
            return {"success": False, "error": "Not connected"}

        log.info(f"Stopping openconnect (PID {pid})")

        success = kill_process(pid)

        # Cleanup
        self._vpn_process = None
        if self._pid_file.exists():
            self._pid_file.unlink()

        if success:
            log.info("OpenConnect stopped")
            return {"success": True}
        else:
            return {"success": False, "error": "Failed to stop process"}

    def _cmd_status(self) -> dict:
        """Handle status command."""
        connected = False
        pid = None
        info = None

        # Check our managed process
        if self._vpn_process and self._vpn_process.poll() is None:
            connected = True
            pid = self._vpn_process.pid
        else:
            # Check PID file
            if self._pid_file.exists():
                try:
                    pid = int(self._pid_file.read_text().strip())
                    if is_process_running(pid):
                        connected = True
                    else:
                        self._pid_file.unlink()
                        pid = None
                except (ValueError, OSError):
                    pass

            # Check by process name
            if not connected:
                proc = find_openconnect()
                if proc:
                    connected = True
                    pid = proc.pid

        if pid:
            info = get_process_info(pid)

        return {
            "success": True,
            "connected": connected,
            "pid": pid,
            "info": info,
        }

    def _cmd_output(self) -> dict:
        """Return recent openconnect output."""
        return {
            "success": True,
            "lines": self._output_lines[-50:],  # Last 50 lines
        }


def main():
    """Daemon entry point."""
    daemon = VPNDaemon()
    daemon.start()


if __name__ == "__main__":
    main()