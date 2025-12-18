"""Background workers for async VPN operations."""

from typing import Optional

from PyQt6.QtCore import QObject, QThread, pyqtSignal

from core import do_saml_auth, get_config, get_cached_cookies, store_cookies, clear_cookies
from daemon import DaemonClient
from daemon.client import DaemonError, DaemonNotRunning


class ConnectWorker(QObject):
    """Worker for VPN connection."""

    started = pyqtSignal()
    progress = pyqtSignal(str)
    finished = pyqtSignal(bool, str)  # success, message
    error = pyqtSignal(str)

    def __init__(
            self,
            connection_name: str,
            no_cache: bool = False,
            visible: bool = False,
            debug: bool = False,
            no_dtls: bool = False,
    ):
        super().__init__()
        self.connection_name = connection_name
        self.no_cache = no_cache
        self.visible = visible
        self.debug = debug
        self.no_dtls = no_dtls
        self._cancelled = False

    def run(self):
        self.started.emit()

        try:
            # Get connection config
            config = get_config(self.connection_name)
            if not config:
                self.error.emit(f"Connection '{self.connection_name}' not found")
                self.finished.emit(False, "Connection not found")
                return

            name, address, protocol, username, password, totp_secret = config

            # Check for cached cookies
            cached_cookies = None
            cached_usergroup = None

            if not self.no_cache:
                cached = get_cached_cookies(name)
                if cached:
                    cached_cookies, cached_usergroup = cached
                    self.progress.emit("Found cached session...")

            if self._cancelled:
                self.finished.emit(False, "Cancelled")
                return

            # Try cached cookies first
            if cached_cookies:
                self.progress.emit("Trying cached session...")

                success = self._try_connect(
                    address, protocol, cached_cookies,
                    username, cached_usergroup,
                )

                if success:
                    self.finished.emit(True, f"Connected to {name}")
                    return

                # Cache failed, clear and re-auth
                self.progress.emit("Session expired, re-authenticating...")
                clear_cookies(name)

            if self._cancelled:
                self.finished.emit(False, "Cancelled")
                return

            # Authenticate via browser
            self.progress.emit(f"Authenticating to {name}...")

            cookies = do_saml_auth(
                vpn_server=address,
                username=username,
                password=password,
                totp_secret=totp_secret,
                protocol=protocol,
                headless=not self.visible,
                debug=self.debug,
            )

            if not cookies:
                self.error.emit("Authentication failed")
                self.finished.emit(False, "Authentication failed")
                return

            if self._cancelled:
                self.finished.emit(False, "Cancelled")
                return

            # Store cookies
            store_cookies(name, cookies, usergroup="portal:prelogin-cookie")

            # Connect
            self.progress.emit(f"Connecting to {address}...")

            success = self._try_connect(
                address, protocol, cookies, username, "portal:prelogin-cookie"
            )

            if success:
                self.finished.emit(True, f"Connected to {name}")
            else:
                self.finished.emit(False, f"Failed to connect to {name}")

        except DaemonNotRunning as e:
            self.error.emit(str(e))
            self.finished.emit(False, "Daemon not running")
        except Exception as e:
            self.error.emit(str(e))
            self.finished.emit(False, str(e))

    def _try_connect(self, address, protocol, cookies, username, usergroup):
        # Build cookie string based on protocol
        if protocol == "gp":
            if "prelogin-cookie" in cookies:
                cookie_str = cookies["prelogin-cookie"]
            elif "portal-userauthcookie" in cookies:
                cookie_str = cookies["portal-userauthcookie"]
                usergroup = "portal:portal-userauthcookie"
            else:
                cookie_str = list(cookies.values())[0] if cookies else ""
        else:
            # AnyConnect: name=value; name=value format
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
            usergroup = None  # AnyConnect doesn't use usergroup

        client = DaemonClient()
        resp = client.connect(
            server=address,
            protocol=protocol,
            cookie=cookie_str,
            username=username,
            usergroup=usergroup if protocol == "gp" else None,
            no_dtls=self.no_dtls,
        )

        if not resp.get("success"):
            error = resp.get("error", "Unknown error")
            self.error.emit(error)
            return False

        return True

    def cancel(self):
        self._cancelled = True


class DisconnectWorker(QObject):
    """Worker for VPN disconnection."""

    started = pyqtSignal()
    progress = pyqtSignal(str)
    finished = pyqtSignal(bool, str)
    error = pyqtSignal(str)

    def __init__(self, force: bool = False):
        super().__init__()
        self.force = force

    def run(self):
        self.started.emit()
        self.progress.emit("Disconnecting...")

        try:
            client = DaemonClient()
            resp = client.disconnect()

            if resp.get("success"):
                if self.force:
                    clear_cookies()
                self.finished.emit(True, "Disconnected")
            else:
                error = resp.get("error", "Failed to disconnect")
                self.error.emit(error)
                self.finished.emit(False, error)

        except DaemonNotRunning as e:
            self.error.emit(str(e))
            self.finished.emit(False, "Daemon not running")
        except Exception as e:
            self.error.emit(str(e))
            self.finished.emit(False, str(e))


class WorkerThread(QThread):
    """Thread wrapper for workers."""

    started = pyqtSignal()
    progress = pyqtSignal(str)
    finished = pyqtSignal(bool, str)
    error = pyqtSignal(str)

    def __init__(self, worker: QObject):
        super().__init__()
        self.worker = worker

        # Forward signals
        self.worker.started.connect(self.started.emit)
        self.worker.progress.connect(self.progress.emit)
        self.worker.finished.connect(self._on_finished)
        self.worker.error.connect(self.error.emit)

        self.worker.moveToThread(self)

    def _on_finished(self, success: bool, message: str):
        self.finished.emit(success, message)

    def run(self):
        self.worker.run()

    def cancel(self):
        if hasattr(self.worker, "cancel"):
            self.worker.cancel()


def create_connect_thread(connection_name: str, **kwargs) -> WorkerThread:
    """Create a connection worker thread."""
    worker = ConnectWorker(connection_name, **kwargs)
    return WorkerThread(worker)


def create_disconnect_thread(force: bool = False) -> WorkerThread:
    """Create a disconnect worker thread."""
    worker = DisconnectWorker(force)
    return WorkerThread(worker)