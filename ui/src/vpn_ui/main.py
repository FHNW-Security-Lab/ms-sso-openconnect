"""Main application controller for VPN UI."""

import sys
from typing import Optional

from PyQt6.QtCore import QCoreApplication
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QApplication, QMessageBox

from vpn_ui.constants import (
    APP_ID,
    APP_NAME,
    STATUS_CONNECTED,
    STATUS_CONNECTING,
    STATUS_DISCONNECTED,
    get_icon,
)
from vpn_ui.backend import get_backend
from vpn_ui.platform.notifications import NotificationManager
from vpn_ui.settings_dialog import SettingsDialog
from vpn_ui.tray import VPNTrayIcon
from vpn_ui.worker import (
    VPNWorkerThread,
    create_connect_thread,
    create_disconnect_thread,
)


class VPNApplication:
    """Main VPN application controller."""

    def __init__(self):
        """Initialize the application."""
        self.app = QApplication(sys.argv)

        # Set application metadata
        self.app.setApplicationName(APP_NAME)
        self.app.setApplicationDisplayName(APP_NAME)
        self.app.setDesktopFileName(APP_ID)
        self.app.setQuitOnLastWindowClosed(False)  # Keep running in tray

        # Set application icon
        app_icon = get_icon("app-icon")
        if not app_icon.isNull():
            self.app.setWindowIcon(app_icon)

        # Initialize backend
        try:
            self.backend = get_backend()
        except FileNotFoundError as e:
            QMessageBox.critical(
                None,
                "Error",
                f"Cannot find VPN backend:\n\n{e}\n\n"
                "Please ensure the core module is installed."
            )
            sys.exit(1)

        # Initialize components
        self._worker_thread: Optional[VPNWorkerThread] = None
        self._current_connection: Optional[str] = None
        self._settings_dialog: Optional[SettingsDialog] = None
        self._disconnecting: bool = False  # Flag to suppress errors during disconnect

        # Check system tray availability
        if not VPNTrayIcon.is_system_tray_available():
            if sys.platform != "darwin":
                # Only show warning on non-macOS (macOS always has menu bar)
                QMessageBox.warning(
                    None,
                    "System Tray Not Available",
                    "System tray is not available on your system.\n\n"
                    "On GNOME, you may need to install the "
                    "'gnome-shell-extension-appindicator' extension.\n\n"
                    "The application will still work but won't show a tray icon."
                )

        # Create tray icon
        self.tray = VPNTrayIcon()

        # Create notification manager
        self.notifications = NotificationManager(self.tray.tray)

        # Connect signals
        self.tray.connect_requested.connect(self._on_connect_requested)
        self.tray.disconnect_requested.connect(self._on_disconnect_requested)
        self.tray.settings_requested.connect(self._show_settings)
        self.tray.quit_requested.connect(self._quit)

        # Load connections into tray menu
        self._update_connections_menu()

        # Check current connection status
        if self.backend.is_connected():
            # Try to get the connection name from state file
            active_conn = self.backend.get_active_connection()
            if active_conn:
                self._current_connection = active_conn
                self.tray.set_status(STATUS_CONNECTED, active_conn)
            else:
                # Try to infer from openconnect process arguments
                inferred = self.backend.infer_connection_name()
                if inferred:
                    self._current_connection = inferred
                    self.backend.save_active_connection(inferred)
                    self.tray.set_status(STATUS_CONNECTED, inferred)
                else:
                    # Connected externally (via CLI), can't determine the name
                    self.tray.set_status(STATUS_CONNECTED, "Unknown")
        else:
            # Not connected - clear any stale state
            self.backend.clear_active_connection()

    def run(self) -> int:
        """Run the application.

        Returns:
            Exit code
        """
        # Show tray icon
        self.tray.show()

        # Start status polling
        self.tray.start_status_polling()

        # If no connections exist, show settings dialog
        connections = self.backend.get_connections()
        if not connections:
            self._show_settings()

        # Run event loop
        return self.app.exec()

    def _update_connections_menu(self) -> None:
        """Update the connections menu in the tray."""
        connections = self.backend.get_connections()
        self.tray.update_connections(connections)

    def _show_settings(self) -> None:
        """Show the settings dialog."""
        if self._settings_dialog is None:
            self._settings_dialog = SettingsDialog(self.backend)
            self._settings_dialog.connections_changed.connect(
                self._update_connections_menu
            )

        self._settings_dialog.show()
        self._settings_dialog.raise_()
        self._settings_dialog.activateWindow()

    def _on_connect_requested(self, connection_name: str) -> None:
        """Handle connect request from tray menu.

        Args:
            connection_name: Name of the connection to use
        """
        # Check if already connecting/connected
        if self._worker_thread and self._worker_thread.isRunning():
            QMessageBox.warning(
                None,
                "Already Connecting",
                "A connection is already in progress.\n"
                "Please wait or disconnect first."
            )
            return

        if self.tray.get_status() == STATUS_CONNECTED:
            reply = QMessageBox.question(
                None,
                "Already Connected",
                f"You are already connected to '{self.tray.get_current_connection()}'.\n\n"
                f"Do you want to disconnect and connect to '{connection_name}'?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
            # Disconnect first
            self._disconnect_sync()

        self._current_connection = connection_name
        self.tray.set_status(STATUS_CONNECTING, connection_name)
        self.notifications.connecting(connection_name)

        # Create and start worker thread
        self._worker_thread = create_connect_thread(
            self.backend,
            connection_name,
            visible=False,  # Could be made configurable
            debug=False,
            no_cache=False,
            no_dtls=False
        )

        self._worker_thread.progress.connect(self._on_progress)
        self._worker_thread.finished.connect(self._on_connect_finished)
        self._worker_thread.error.connect(self._on_error)
        self._worker_thread.start()

    def _on_disconnect_requested(self, force: bool) -> None:
        """Handle disconnect request from tray menu.

        Args:
            force: If True, terminate the session
        """
        # Prevent double disconnect
        if self._disconnecting:
            return

        # Set flag to suppress errors during disconnect
        self._disconnecting = True

        # Immediately disable disconnect actions to prevent double-click
        self.tray.set_disconnect_enabled(False)

        # Clean up any existing worker thread
        if self._worker_thread:
            if self._worker_thread.isRunning():
                self._worker_thread.cancel()
            self._cleanup_worker_thread()

        # Create and start disconnect worker
        self._worker_thread = create_disconnect_thread(self.backend, force)
        self._worker_thread.progress.connect(self._on_progress)
        self._worker_thread.finished.connect(self._on_disconnect_finished)
        self._worker_thread.error.connect(self._on_error)
        self._worker_thread.start()

    def _disconnect_sync(self) -> None:
        """Disconnect synchronously (for reconnection flow)."""
        self.backend.disconnect(force=False)

    def _on_progress(self, message: str) -> None:
        """Handle progress updates from worker.

        Args:
            message: Progress message
        """
        # Could show in a status bar or tooltip
        print(f"[Progress] {message}")

    def _cleanup_worker_thread(self) -> None:
        """Clean up the worker thread after it finishes."""
        if self._worker_thread is None:
            return

        # Disconnect signals to prevent any further callbacks
        try:
            self._worker_thread.progress.disconnect()
            self._worker_thread.finished.disconnect()
            self._worker_thread.error.disconnect()
        except (TypeError, RuntimeError):
            pass  # Signals might already be disconnected

        # Wait for thread to fully finish if still running
        if self._worker_thread.isRunning():
            self._worker_thread.wait(1000)

        # Schedule for deletion and clear reference
        self._worker_thread.deleteLater()
        self._worker_thread = None

    def _on_connect_finished(self, success: bool, message: str) -> None:
        """Handle connection finished signal.

        Args:
            success: Whether connection succeeded
            message: Status message
        """
        # Clean up worker thread properly
        self._cleanup_worker_thread()

        if success:
            self.tray.set_status(STATUS_CONNECTED, self._current_connection)
            self.notifications.connected(self._current_connection)
            # Save active connection to state file
            self.backend.save_active_connection(self._current_connection)
        else:
            self.tray.set_status(STATUS_DISCONNECTED)
            # Only show error if not intentionally disconnecting
            if not self._disconnecting:
                self.notifications.error(message)
            self._current_connection = None
            self.backend.clear_active_connection()

    def _on_disconnect_finished(self, success: bool, message: str) -> None:
        """Handle disconnect finished signal.

        Args:
            success: Whether disconnect succeeded
            message: Status message
        """
        # Clean up worker thread properly
        self._cleanup_worker_thread()

        self._disconnecting = False  # Clear flag
        self.tray.set_status(STATUS_DISCONNECTED)
        if success:
            self.notifications.disconnected()
        # Don't show error on disconnect - it's intentional
        self._current_connection = None
        # Clear active connection state
        self.backend.clear_active_connection()

    def _on_error(self, error: str) -> None:
        """Handle error from worker.

        Args:
            error: Error message
        """
        # Suppress errors during intentional disconnect
        if self._disconnecting:
            print(f"[Suppressed during disconnect] {error}")
            return
        self.notifications.error(error)
        print(f"[Error] {error}")

    def _quit(self) -> None:
        """Quit the application."""
        # Ask about disconnecting if connected
        if self.backend.is_connected():
            reply = QMessageBox.question(
                None,
                "Quit",
                "VPN is currently connected.\n\n"
                "Do you want to disconnect before quitting?",
                QMessageBox.StandardButton.Yes |
                QMessageBox.StandardButton.No |
                QMessageBox.StandardButton.Cancel
            )

            if reply == QMessageBox.StandardButton.Cancel:
                return
            elif reply == QMessageBox.StandardButton.Yes:
                self.backend.disconnect(force=False)

        # Stop status polling
        self.tray.stop_status_polling()

        # Hide tray
        self.tray.hide()

        # Quit application
        self.app.quit()


def main() -> int:
    """Main entry point.

    Returns:
        Exit code
    """
    app = VPNApplication()
    return app.run()


if __name__ == "__main__":
    sys.exit(main())
