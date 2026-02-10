"""QThread workers for async VPN operations."""

import os
import time
from typing import Optional, TYPE_CHECKING

from PyQt6.QtCore import QObject, QThread, pyqtSignal

if TYPE_CHECKING:
    from vpn_ui.backend.base import VPNBackendProtocol


class VPNConnectWorker(QObject):
    """Worker for VPN connection operations."""

    # Signals
    started = pyqtSignal()
    progress = pyqtSignal(str)  # Status message
    finished = pyqtSignal(bool, str)  # success, message
    error = pyqtSignal(str)  # error message

    def __init__(
        self,
        backend: "VPNBackendProtocol",
        connection_name: str,
        visible: bool = False,
        debug: bool = False,
        no_cache: bool = False,
        no_dtls: bool = False
    ):
        """Initialize the connect worker.

        Args:
            backend: VPN backend instance
            connection_name: Name of the connection to use
            visible: Show browser window during auth
            debug: Enable debug mode
            no_cache: Skip cached cookies
            no_dtls: Disable DTLS (TCP only)
        """
        super().__init__()
        self.backend = backend
        self.connection_name = connection_name
        self.visible = visible
        self.debug = debug
        self.no_cache = no_cache
        self.no_dtls = no_dtls
        self._is_cancelled = False

    def run(self) -> None:
        """Execute the connection operation."""
        self.started.emit()

        try:
            # Get connection configuration
            config = self.backend.get_config(self.connection_name)
            if not config:
                self.error.emit(f"Connection '{self.connection_name}' not found")
                self.finished.emit(False, f"Connection '{self.connection_name}' not found")
                return

            name, address, protocol, username, password, totp_secret = config

            # Watchdog retries for both AnyConnect and GlobalProtect.
            try:
                max_connect_attempts = max(
                    1,
                    int(os.environ.get("MS_SSO_RECONNECT_MAX_ATTEMPTS", "3").strip() or "3"),
                )
            except Exception:
                max_connect_attempts = 3
            try:
                reconnect_delay_seconds = max(
                    0,
                    int(os.environ.get("MS_SSO_RECONNECT_DELAY_SECONDS", "5").strip() or "5"),
                )
            except Exception:
                reconnect_delay_seconds = 5

            # Fresh auth retries: AnyConnect sometimes needs one extra first-pass auth.
            fresh_auth_attempts = 1
            anyconnect_retry_delay_seconds = 2
            if protocol == "anyconnect":
                try:
                    fresh_auth_attempts = max(
                        1,
                        int(os.environ.get("MS_SSO_ANYCONNECT_FRESH_AUTH_ATTEMPTS", "2").strip() or "2"),
                    )
                except Exception:
                    fresh_auth_attempts = 2
                try:
                    anyconnect_retry_delay_seconds = max(
                        0,
                        int(os.environ.get("MS_SSO_ANYCONNECT_RETRY_DELAY_SECONDS", "2").strip() or "2"),
                    )
                except Exception:
                    anyconnect_retry_delay_seconds = 2

            cached_checked = self.no_cache
            auth_ok = False

            for connect_attempt in range(max_connect_attempts):
                if self._is_cancelled:
                    self.finished.emit(False, "Cancelled")
                    return

                if connect_attempt > 0:
                    self.progress.emit(
                        f"Connection lost/failed. Watchdog retry {connect_attempt + 1}/{max_connect_attempts}..."
                    )
                    if reconnect_delay_seconds > 0:
                        for _ in range(reconnect_delay_seconds * 2):
                            if self._is_cancelled:
                                self.finished.emit(False, "Cancelled")
                                return
                            time.sleep(0.5)

                # Try cached cookies once on first attempt.
                if not cached_checked:
                    cached_checked = True
                    cached = self.backend.get_stored_cookies(name)
                    if cached:
                        cached_cookies, cached_usergroup = cached
                        self.progress.emit("Using cached session...")
                        self.progress.emit(f"Reconnecting to {name} with cached credentials...")
                        success = self._try_connect(
                            address, protocol, cached_cookies, username,
                            cached_usergroup, allow_fallback=True
                        )
                        if success:
                            self.finished.emit(True, f"Connected to {name}")
                            return
                        self.backend.clear_stored_cookies(name)

                # Fresh auth + connect cycle.
                for auth_attempt in range(fresh_auth_attempts):
                    if self._is_cancelled:
                        self.finished.emit(False, "Cancelled")
                        return

                    if auth_attempt == 0:
                        self.progress.emit(f"Authenticating to {name}...")
                    else:
                        self.progress.emit(
                            f"Retrying authentication ({auth_attempt + 1}/{fresh_auth_attempts})..."
                        )
                        if anyconnect_retry_delay_seconds > 0:
                            for _ in range(anyconnect_retry_delay_seconds * 2):
                                if self._is_cancelled:
                                    self.finished.emit(False, "Cancelled")
                                    return
                                time.sleep(0.5)

                    cookies = self.backend.do_saml_auth(
                        vpn_server=address,
                        username=username,
                        password=password,
                        totp_secret=totp_secret,
                        protocol=protocol,
                        headless=not self.visible,
                        debug=self.debug
                    )

                    if not cookies:
                        continue
                    auth_ok = True

                    if self._is_cancelled:
                        self.finished.emit(False, "Cancelled")
                        return

                    # Store the cookies with initial usergroup for prelogin-cookie
                    self.backend.store_cookies(name, cookies, usergroup='portal:prelogin-cookie')

                    # Connect
                    self.progress.emit(f"Connecting to {address}...")
                    success = self._try_connect(
                        address, protocol, cookies, username,
                        connection_name=name, allow_fallback=False
                    )
                    if success:
                        self.finished.emit(True, f"Connected to {name}")
                        return

                    # Don't keep a fresh cookie cache when the immediate connect fails.
                    self.backend.clear_stored_cookies(name)

            if auth_ok:
                self.finished.emit(False, f"Failed to connect to {name} after {max_connect_attempts} attempts")
            else:
                self.error.emit("Authentication failed")
                self.finished.emit(False, "Authentication failed after retries")

        except Exception as e:
            self.error.emit(str(e))
            self.finished.emit(False, str(e))

    def _try_connect(
        self,
        address: str,
        protocol: str,
        cookies: dict,
        username: str,
        cached_usergroup: Optional[str] = None,
        allow_fallback: bool = False,
        connection_name: Optional[str] = None
    ) -> bool:
        """Try to establish VPN connection.

        Args:
            address: VPN server address
            protocol: VPN protocol
            cookies: Authentication cookies
            username: Username
            cached_usergroup: Usergroup from cache
            allow_fallback: Allow fallback on failure
            connection_name: Connection name for caching

        Returns:
            True if connection successful
        """
        conn_name = connection_name or self.connection_name

        # Note: connect_vpn may not return if it uses execvp
        # For GUI, we always want allow_fallback=True to stay in control
        return self.backend.connect_vpn(
            address=address,
            protocol=protocol,
            cookies=cookies,
            no_dtls=self.no_dtls,
            username=username,
            allow_fallback=True,  # Always use fallback mode for GUI
            connection_name=conn_name,
            cached_usergroup=cached_usergroup,
        )

    def cancel(self) -> None:
        """Cancel the operation."""
        self._is_cancelled = True


class VPNDisconnectWorker(QObject):
    """Worker for VPN disconnection."""

    # Signals
    started = pyqtSignal()
    progress = pyqtSignal(str)
    finished = pyqtSignal(bool, str)
    error = pyqtSignal(str)

    def __init__(self, backend: "VPNBackendProtocol", force: bool = False):
        """Initialize disconnect worker.

        Args:
            backend: VPN backend instance
            force: If True, terminate session (SIGTERM).
                   If False, keep session alive (SIGKILL on Linux, SIGTERM on macOS).
        """
        super().__init__()
        self.backend = backend
        self.force = force

    def run(self) -> None:
        """Execute the disconnect operation."""
        self.started.emit()
        self.progress.emit("Disconnecting...")

        try:
            success = self.backend.disconnect(self.force)
            if success:
                msg = "Disconnected (session terminated)" if self.force else "Disconnected"
                self.finished.emit(True, msg)
            else:
                self.finished.emit(False, "Failed to disconnect")
        except Exception as e:
            self.error.emit(str(e))
            self.finished.emit(False, str(e))


class VPNWorkerThread(QThread):
    """Thread wrapper for VPN workers."""

    # Forward signals from worker
    started = pyqtSignal()
    progress = pyqtSignal(str)
    finished = pyqtSignal(bool, str)
    error = pyqtSignal(str)

    def __init__(self, worker: QObject):
        """Initialize the worker thread.

        Args:
            worker: Worker object (VPNConnectWorker or VPNDisconnectWorker)
        """
        super().__init__()
        self.worker = worker

        # Connect worker signals to thread signals
        self.worker.started.connect(self.started.emit)
        self.worker.progress.connect(self.progress.emit)
        self.worker.finished.connect(self._on_finished)
        self.worker.error.connect(self.error.emit)

        # Move worker to this thread
        self.worker.moveToThread(self)

    def _on_finished(self, success: bool, message: str) -> None:
        """Handle worker finished signal."""
        self.finished.emit(success, message)

    def run(self) -> None:
        """Run the worker."""
        self.worker.run()

    def cancel(self) -> None:
        """Cancel the worker if possible."""
        if hasattr(self.worker, 'cancel'):
            self.worker.cancel()


def create_connect_thread(
    backend: "VPNBackendProtocol",
    connection_name: str,
    **kwargs
) -> VPNWorkerThread:
    """Create a connection worker thread.

    Args:
        backend: VPN backend instance
        connection_name: Name of the connection
        **kwargs: Additional arguments for VPNConnectWorker

    Returns:
        Configured VPNWorkerThread
    """
    worker = VPNConnectWorker(backend, connection_name, **kwargs)
    return VPNWorkerThread(worker)


def create_disconnect_thread(
    backend: "VPNBackendProtocol",
    force: bool = False
) -> VPNWorkerThread:
    """Create a disconnect worker thread.

    Args:
        backend: VPN backend instance
        force: If True, terminate the session

    Returns:
        Configured VPNWorkerThread
    """
    worker = VPNDisconnectWorker(backend, force)
    return VPNWorkerThread(worker)
