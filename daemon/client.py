"""Client to communicate with VPN daemon."""

import json
import socket
from typing import Optional

from .platform import get_socket_path


class DaemonError(Exception):
    """Error communicating with daemon."""
    pass


class DaemonNotRunning(DaemonError):
    """Daemon is not running."""
    pass


class DaemonClient:
    """Client for sending commands to the VPN daemon."""

    def __init__(self, timeout: float = 30.0):
        """Initialize client.

        Args:
            timeout: Socket timeout in seconds
        """
        self._socket_path = get_socket_path()
        self._timeout = timeout

    def _send(self, command: dict) -> dict:
        """Send command to daemon and return response.

        Args:
            command: Command dictionary

        Returns:
            Response dictionary

        Raises:
            DaemonNotRunning: If daemon is not running
            DaemonError: If communication fails
        """
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self._timeout)

        try:
            sock.connect(self._socket_path)
        except FileNotFoundError:
            raise DaemonNotRunning(
                "Daemon not running. Start with: sudo ms-sso-openconnect-daemon"
            )
        except ConnectionRefusedError:
            raise DaemonNotRunning(
                "Daemon not responding. Restart with: sudo ms-sso-openconnect-daemon"
            )
        except Exception as e:
            raise DaemonError(f"Cannot connect to daemon: {e}")

        try:
            # Send command
            sock.send(json.dumps(command).encode("utf-8"))

            # Receive response
            chunks = []
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                # Try to parse - if valid JSON, we're done
                try:
                    data = b"".join(chunks).decode("utf-8")
                    return json.loads(data)
                except json.JSONDecodeError:
                    continue

            # Final attempt to parse
            data = b"".join(chunks).decode("utf-8")
            if not data:
                raise DaemonError("Empty response from daemon")
            return json.loads(data)

        except socket.timeout:
            raise DaemonError("Timeout waiting for daemon response")
        except json.JSONDecodeError as e:
            raise DaemonError(f"Invalid response from daemon: {e}")
        except Exception as e:
            raise DaemonError(f"Communication error: {e}")
        finally:
            sock.close()

    def connect(
            self,
            server: str,
            protocol: str,
            cookie: str,
            username: Optional[str] = None,
            usergroup: Optional[str] = None,
            no_dtls: bool = False,
    ) -> dict:
        """Connect to VPN.

        Args:
            server: VPN server address
            protocol: 'anyconnect' or 'gp'
            cookie: Authentication cookie
            username: Optional username
            usergroup: Optional usergroup (for GlobalProtect)
            no_dtls: Disable DTLS (TCP only)

        Returns:
            Response dict with 'success', 'pid' or 'error'
        """
        cmd = {
            "command": "connect",
            "server": server,
            "protocol": protocol,
            "cookie": cookie,
            "no_dtls": no_dtls,
        }
        if username:
            cmd["username"] = username
        if usergroup:
            cmd["usergroup"] = usergroup

        return self._send(cmd)

    def disconnect(self) -> dict:
        """Disconnect VPN.

        Returns:
            Response dict with 'success' or 'error'
        """
        return self._send({"command": "disconnect"})

    def status(self) -> dict:
        """Get VPN status.

        Returns:
            Response dict with 'success', 'connected', 'pid', 'info'
        """
        return self._send({"command": "status"})

    def output(self) -> dict:
        """Get recent openconnect output.

        Returns:
            Response dict with 'success', 'lines'
        """
        return self._send({"command": "output"})

    def is_connected(self) -> bool:
        """Check if VPN is connected.

        Returns:
            True if connected
        """
        try:
            resp = self.status()
            return resp.get("connected", False)
        except DaemonError:
            return False

    def is_daemon_running(self) -> bool:
        """Check if daemon is running.

        Returns:
            True if daemon is responding
        """
        try:
            self.status()
            return True
        except DaemonNotRunning:
            return False
        except DaemonError:
            return False


# Convenience functions

def connect(server: str, protocol: str, cookie: str, **kwargs) -> dict:
    """Connect to VPN (convenience function)."""
    return DaemonClient().connect(server, protocol, cookie, **kwargs)


def disconnect() -> dict:
    """Disconnect VPN (convenience function)."""
    return DaemonClient().disconnect()


def status() -> dict:
    """Get status (convenience function)."""
    return DaemonClient().status()


def is_connected() -> bool:
    """Check if connected (convenience function)."""
    return DaemonClient().is_connected()