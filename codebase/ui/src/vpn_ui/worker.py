"""Cancellable workers with session-local, bounded reconnect intent."""

import os
import sys
import threading
import time
from typing import Optional, TYPE_CHECKING

from PyQt6.QtCore import QObject, QThread, pyqtSignal
from vpn_ui.backend.base import VPNConnectionError

if TYPE_CHECKING:
    from vpn_ui.backend.base import VPNBackendProtocol


def _bounded_env(name, default, lower, upper):
    try:
        return max(lower, min(upper, int(os.environ.get(name, str(default)))))
    except ValueError:
        return default


class VPNConnectWorker(QObject):
    started = pyqtSignal()
    connected = pyqtSignal(str)
    number_match = pyqtSignal(str)
    progress = pyqtSignal(str)
    finished = pyqtSignal(bool, str)
    error = pyqtSignal(str)

    def __init__(self, backend, connection_name, visible=False, debug=False,
                 no_cache=False, no_dtls=False):
        super().__init__()
        self.backend = backend
        self.connection_name = connection_name
        self.visible = visible
        self.debug = debug
        self.no_cache = no_cache
        self.no_dtls = no_dtls
        self._cancelled = threading.Event()
        self._cancel_force = False

    def cancel(self, force=False):
        self._cancel_force = force
        self._cancelled.set()

    def _show_number(self, number):
        if self._cancelled.is_set():
            return False
        self.number_match.emit(number)
        return True

    def _connected(self, name):
        self._connected_at = time.monotonic()
        self.connected.emit(name)

    def _auth_progress(self, event):
        text = event.lower()
        if "clean" in text or "recovery" in text:
            message = "Recovering sign-in with a clean browser session..."
        elif "totp" in text or "otp" in text:
            message = "Completing verification-code authentication..."
        elif "password" in text or "credential" in text:
            message = "Completing Microsoft sign-in..."
        elif "push" in text or "number" in text:
            message = "Waiting for Microsoft Authenticator approval..."
        else:
            message = "Waiting for VPN sign-in to complete..."
        self.progress.emit(message)

    def run(self):
        self.started.emit()
        try:
            self._run_session()
        except Exception as exc:
            if self._cancelled.is_set():
                self.finished.emit(False, "Cancelled")
            else:
                self.error.emit(str(exc))
                self.finished.emit(False, str(exc))

    def _run_session(self):
        from core import SamlSensitiveActionError
        config = self.backend.get_config(self.connection_name)
        if not config:
            self.finished.emit(False, f"Connection '{self.connection_name}' not found")
            return
        name, address, protocol, username, password, totp_secret = config
        options = self.backend.get_connection(name) or {}
        gp_interface = options.get("gp_auth_interface", "portal")
        attempts = _bounded_env("MS_SSO_RECONNECT_MAX_ATTEMPTS", 0, 0, 1000)
        delay = _bounded_env("MS_SSO_RECONNECT_DELAY_SECONDS", 5, 0, 300)
        if not options.get("auto_reconnect", True):
            attempts = 1
        cached = None if self.no_cache else self.backend.get_stored_cookies(name)
        # A direct gateway prelogin cookie is a single-use artifact.
        if protocol == "gp" and (gp_interface == "gateway" or not cached
                                 or not cached[0].get("portal-userauthcookie")):
            cached = None
        attempt = 0
        last_connection_error = None
        self._connected_at = None
        while not attempts or attempt < attempts:
            if self._cancelled.is_set():
                break
            if attempt:
                wait = min(300, delay * (2 ** min(attempt - 1, 10)))
                budget = f"/{attempts}" if attempts else ""
                message = f"Connection lost or expired. Reconnecting ({attempt + 1}{budget}) in {wait}s..."
                if last_connection_error:
                    message += f" {last_connection_error}"
                self.progress.emit(message)
                if self._cancelled.wait(wait):
                    break
            candidates = [cached, None] if cached else [None]
            cached = None
            for candidate in candidates:
                if self._cancelled.is_set():
                    break
                if sys.platform == "darwin":
                    # Installation authorizes the helper once. Never start sign-in or
                    # replay authentication when that helper needs attention.
                    self.backend.ensure_helper_available()
                    if self._cancelled.is_set():
                        break
                if candidate:
                    cookies, group = candidate
                    self.progress.emit("Trying saved session...")
                else:
                    self.progress.emit(f"Authenticating to {name}...")
                    try:
                        cookies = self.backend.do_saml_auth(
                            vpn_server=address, username=username, password=password,
                            totp_secret=totp_secret, protocol=protocol, headless=not self.visible,
                            debug=self.debug, gp_auth_interface=gp_interface,
                            gp_os_version=options.get("gp_os_version") or None,
                            mfa_preference=options.get("mfa_preference", "auto"),
                            cancel_callback=self._cancelled.is_set,
                            progress_callback=self._auth_progress,
                            number_match_callback=self._show_number,
                        )
                    except SamlSensitiveActionError:
                        # A credential may already have been dispatched.
                        raise
                    except Exception as exc:
                        self.progress.emit(f"Sign-in unavailable: {exc}")
                        break
                    group = None
                    if self._cancelled.is_set():
                        break
                    if not cookies:
                        raise RuntimeError("Authentication did not complete. Reconnect to try again.")
                    if protocol != "gp":
                        self.backend.store_cookies(name, cookies)
                self.progress.emit(f"Establishing VPN tunnel to {name}...")
                kwargs = dict(address=address, protocol=protocol, cookies=cookies,
                              no_dtls=self.no_dtls, username=username, allow_fallback=True,
                              connection_name=name, cached_usergroup=group,
                              gp_auth_interface=gp_interface,
                              gp_os_version=options.get("gp_os_version") or None,
                              cancel_callback=self._cancelled.is_set)
                if sys.platform != "darwin":
                    kwargs.update(disconnect_force_callback=lambda: self._cancel_force,
                                  connected_callback=lambda: self._connected(name),
                                  progress_callback=self.progress.emit)
                try:
                    stopped = self.backend.connect_vpn(**kwargs)
                except VPNConnectionError as exc:
                    if not exc.retryable:
                        raise
                    last_connection_error = str(exc)
                    self.progress.emit(last_connection_error)
                    stopped = False
                if sys.platform == "darwin" and stopped:
                    last_connection_error = None
                    self._connected(name)
                    while (self.backend.is_connected(require_helper=True)
                           and not self._cancelled.wait(1)):
                        pass
                    stopped = self._cancelled.is_set()
                if stopped or self._cancelled.is_set():
                    self.finished.emit(False, "Disconnected")
                    return
                self.backend.clear_stored_cookies(name)
            # A stable established session starts a new bounded recovery budget.
            if (options.get("auto_reconnect", True) and self._connected_at is not None
                    and time.monotonic() - self._connected_at >= 60):
                attempt = 0
                self._connected_at = None
                if self._cancelled.wait(delay):
                    break
            else:
                attempt += 1
        message = f"VPN connection failed after {attempts} attempts"
        if last_connection_error:
            message += f": {last_connection_error}"
        self.finished.emit(False, "Cancelled" if self._cancelled.is_set() else message)


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
                   If False, keep session alive with graceful SIGINT on Linux.
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
    connected = pyqtSignal(str)
    number_match = pyqtSignal(str)
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
        if hasattr(self.worker, "connected"):
            self.worker.connected.connect(self.connected.emit)
            self.worker.number_match.connect(self.number_match.emit)
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

    def cancel(self, force: bool = False) -> None:
        """Cancel the worker if possible."""
        if hasattr(self.worker, 'cancel'):
            self.worker.cancel(force=force)


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
