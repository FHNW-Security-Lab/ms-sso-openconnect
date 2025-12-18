"""Main GUI application."""

import sys
from typing import Optional

from PyQt6.QtWidgets import QApplication, QMessageBox

from core import get_connections, clear_cookies
from daemon import DaemonClient
from daemon.client import DaemonNotRunning

from .constants import APP_NAME, APP_ID, STATUS_CONNECTED, STATUS_CONNECTING, STATUS_DISCONNECTED, get_icon
from .notifications import NotificationManager
from .settings import SettingsDialog
from .tray import VPNTrayIcon
from .worker import WorkerThread, create_connect_thread, create_disconnect_thread


class VPNApplication:
    """Main VPN application controller."""

    def __init__(self):
        self.app = QApplication(sys.argv)

        # Application metadata
        self.app.setApplicationName(APP_NAME)
        self.app.setApplicationDisplayName(APP_NAME)
        self.app.setDesktopFileName(APP_ID)
        self.app.setQuitOnLastWindowClosed(False)

        # Icon
        app_icon = get_icon("app-icon")
        if not app_icon.isNull():
            self.app.setWindowIcon(app_icon)

        # State
        self._worker: Optional[WorkerThread] = None
        self._current_connection: Optional[str] = None
        self._settings_dialog: Optional[SettingsDialog] = None
        self._disconnecting = False

        # Check system tray
        if not VPNTrayIcon.is_system_tray_available():
            QMessageBox.warning(
                None, "System Tray",
                "System tray not available.\n\n"
                "On GNOME, install 'gnome-shell-extension-appindicator'."
            )

        # Create tray
        self.tray = VPNTrayIcon()

        # Notifications
        self.notifications = NotificationManager(self.tray.tray)

        # Connect signals
        self.tray.connect_requested.connect(self._on_connect)
        self.tray.disconnect_requested.connect(self._on_disconnect)
        self.tray.settings_requested.connect(self._show_settings)
        self.tray.quit_requested.connect(self._quit)

        # Load connections
        self._update_connections_menu()

        # Check current status
        self._check_initial_status()

    def run(self) -> int:
        """Run the application."""
        self.tray.show()
        self.tray.start_status_polling()

        # Show settings if no connections
        if not get_connections():
            self._show_settings()

        return self.app.exec()

    def _update_connections_menu(self):
        connections = get_connections()
        self.tray.update_connections(connections)

    def _check_initial_status(self):
        """Check if already connected (e.g., via CLI)."""
        try:
            client = DaemonClient(timeout=2.0)
            resp = client.status()
            if resp.get("connected"):
                self.tray.set_status(STATUS_CONNECTED, "External")
        except Exception:
            pass

    def _show_settings(self):
        if self._settings_dialog is None:
            self._settings_dialog = SettingsDialog()
            self._settings_dialog.connections_changed.connect(self._update_connections_menu)

        self._settings_dialog.show()
        self._settings_dialog.raise_()
        self._settings_dialog.activateWindow()

    def _on_connect(self, connection_name: str):
        # Check if worker is busy
        if self._worker and self._worker.isRunning():
            QMessageBox.warning(
                None, "Busy",
                "A connection is already in progress."
            )
            return

        # Check if already connected
        if self.tray.get_status() == STATUS_CONNECTED:
            current = self.tray.get_current_connection()
            reply = QMessageBox.question(
                None, "Already Connected",
                f"Already connected to '{current}'.\n\n"
                f"Disconnect and connect to '{connection_name}'?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
            self._disconnect_sync()

        # Check daemon
        try:
            client = DaemonClient(timeout=2.0)
            client.status()
        except DaemonNotRunning:
            self.notifications.daemon_not_running()
            QMessageBox.critical(
                None, "Daemon Not Running",
                "The VPN daemon is not running.\n\n"
                "Start it with:\n"
                "  sudo ms-sso-openconnect-daemon"
            )
            return

        self._current_connection = connection_name
        self.tray.set_status(STATUS_CONNECTING, connection_name)
        self.notifications.connecting(connection_name)

        # Start worker
        self._worker = create_connect_thread(connection_name)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_connect_finished)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def _on_disconnect(self, force: bool):
        self._disconnecting = True

        if self._worker and self._worker.isRunning():
            self._worker.cancel()
            self._worker.wait(5000)

        self._worker = create_disconnect_thread(force)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_disconnect_finished)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def _disconnect_sync(self):
        """Synchronous disconnect for reconnection flow."""
        try:
            client = DaemonClient()
            client.disconnect()
        except Exception:
            pass

    def _on_progress(self, message: str):
        print(f"[Progress] {message}")

    def _on_connect_finished(self, success: bool, message: str):
        if success:
            self.tray.set_status(STATUS_CONNECTED, self._current_connection)
            self.notifications.connected(self._current_connection)
        else:
            self.tray.set_status(STATUS_DISCONNECTED)
            if not self._disconnecting:
                self.notifications.error(message)
            self._current_connection = None

    def _on_disconnect_finished(self, success: bool, message: str):
        self._disconnecting = False
        self.tray.set_status(STATUS_DISCONNECTED)
        if success:
            self.notifications.disconnected()
        self._current_connection = None

    def _on_error(self, error: str):
        if self._disconnecting:
            print(f"[Suppressed] {error}")
            return
        self.notifications.error(error)
        print(f"[Error] {error}")

    def _quit(self):
        # Ask about disconnect
        try:
            client = DaemonClient(timeout=2.0)
            if client.is_connected():
                reply = QMessageBox.question(
                    None, "Quit",
                    "VPN is connected. Disconnect before quitting?",
                    QMessageBox.StandardButton.Yes |
                    QMessageBox.StandardButton.No |
                    QMessageBox.StandardButton.Cancel,
                )
                if reply == QMessageBox.StandardButton.Cancel:
                    return
                if reply == QMessageBox.StandardButton.Yes:
                    client.disconnect()
        except Exception:
            pass

        self.tray.stop_status_polling()
        self.tray.hide()
        self.app.quit()


def main() -> int:
    """Entry point."""
    app = VPNApplication()
    return app.run()


if __name__ == "__main__":
    sys.exit(main())