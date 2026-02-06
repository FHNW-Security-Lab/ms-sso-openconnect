"""macOS VPN daemon package.

This daemon runs as root via LaunchDaemon and manages openconnect connections.
The UI communicates with it via Unix socket IPC.
"""

DAEMON_VERSION = "1.0.0"
SOCKET_PATH = "/var/run/ms-sso-openconnect/daemon.sock"
PID_FILE = "/var/run/ms-sso-openconnect/daemon.pid"
