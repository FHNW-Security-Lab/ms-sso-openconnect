"""System tray icon and menu."""

from typing import Optional

from PyQt6.QtCore import QObject, QTimer, pyqtSignal
from PyQt6.QtGui import QAction, QIcon
from PyQt6.QtWidgets import QMenu, QSystemTrayIcon

from daemon import DaemonClient
from daemon.client import DaemonError

from .constants import (
    APP_NAME,
    PROTOCOLS,
    STATUS_CONNECTED,
    STATUS_CONNECTING,
    STATUS_DISCONNECTED,
    get_icon,
)


class VPNTrayIcon(QObject):
    """System tray icon with VPN status and menu."""

    connect_requested = pyqtSignal(str)  # connection name
    disconnect_requested = pyqtSignal(bool)  # force
    settings_requested = pyqtSignal()
    quit_requested = pyqtSignal()

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)

        self.tray = QSystemTrayIcon(parent)
        self.tray.setToolTip(APP_NAME)

        self._status = STATUS_DISCONNECTED
        self._current_connection: Optional[str] = None
        self._connections: dict = {}

        # Load icons
        self._icons = {
            STATUS_DISCONNECTED: get_icon("vpn-disconnected"),
            STATUS_CONNECTING: get_icon("vpn-connecting"),
            STATUS_CONNECTED: get_icon("vpn-connected"),
        }

        # Fallback to app icon
        app_icon = get_icon("app-icon")
        if not app_icon.isNull():
            for status in self._icons:
                if self._icons[status].isNull():
                    self._icons[status] = app_icon

        self._setup_menu()
        self._update_icon()

        # Status polling
        self._poll_timer = QTimer()
        self._poll_timer.timeout.connect(self._poll_status)

        # Double-click to settings
        self.tray.activated.connect(self._on_activated)

    def _setup_menu(self):
        self.menu = QMenu()

        # Status (disabled, informational)
        self._status_action = self.menu.addAction("Status: Disconnected")
        self._status_action.setEnabled(False)

        self.menu.addSeparator()

        # Connections submenu
        self._connect_menu = self.menu.addMenu("Connect")
        self._connect_menu.setEnabled(False)

        # Disconnect actions
        self._disconnect_action = self.menu.addAction("Disconnect")
        self._disconnect_action.triggered.connect(lambda: self.disconnect_requested.emit(False))
        self._disconnect_action.setEnabled(False)

        self._force_disconnect_action = self.menu.addAction("Force Disconnect")
        self._force_disconnect_action.triggered.connect(lambda: self.disconnect_requested.emit(True))
        self._force_disconnect_action.setEnabled(False)

        self.menu.addSeparator()

        # Settings
        settings_action = self.menu.addAction("Settings...")
        settings_action.triggered.connect(self.settings_requested.emit)

        self.menu.addSeparator()

        # Quit
        quit_action = self.menu.addAction("Quit")
        quit_action.triggered.connect(self.quit_requested.emit)

        self.tray.setContextMenu(self.menu)

    def _on_activated(self, reason: QSystemTrayIcon.ActivationReason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.settings_requested.emit()

    def update_connections(self, connections: dict):
        """Update connections menu."""
        self._connections = connections
        self._connect_menu.clear()

        if not connections:
            self._connect_menu.setEnabled(False)
            return

        self._connect_menu.setEnabled(True)

        for name, details in connections.items():
            protocol = details.get("protocol", "anyconnect")
            proto_name = "GP" if protocol == "gp" else "AC"
            action = self._connect_menu.addAction(f"{name} ({proto_name})")
            action.triggered.connect(lambda checked, n=name: self.connect_requested.emit(n))

    def set_status(self, status: str, connection_name: Optional[str] = None):
        """Update status and UI."""
        self._status = status
        self._current_connection = connection_name
        self._update_icon()

        if status == STATUS_CONNECTED:
            self._status_action.setText(f"Connected: {connection_name}")
            self._disconnect_action.setEnabled(True)
            self._force_disconnect_action.setEnabled(True)
            self._connect_menu.setEnabled(False)
            self.tray.setToolTip(f"{APP_NAME} - Connected to {connection_name}")
        elif status == STATUS_CONNECTING:
            self._status_action.setText(f"Connecting: {connection_name}...")
            self._disconnect_action.setEnabled(True)
            self._force_disconnect_action.setEnabled(True)
            self._connect_menu.setEnabled(False)
            self.tray.setToolTip(f"{APP_NAME} - Connecting...")
        else:
            self._status_action.setText("Status: Disconnected")
            self._disconnect_action.setEnabled(False)
            self._force_disconnect_action.setEnabled(False)
            self._connect_menu.setEnabled(bool(self._connections))
            self.tray.setToolTip(f"{APP_NAME} - Disconnected")

    def get_status(self) -> str:
        return self._status

    def get_current_connection(self) -> Optional[str]:
        return self._current_connection

    def _update_icon(self):
        icon = self._icons.get(self._status, self._icons[STATUS_DISCONNECTED])
        self.tray.setIcon(icon)

    def start_status_polling(self, interval_ms: int = 5000):
        self._poll_timer.start(interval_ms)

    def stop_status_polling(self):
        self._poll_timer.stop()

    def _poll_status(self):
        """Poll daemon for connection status."""
        try:
            client = DaemonClient(timeout=2.0)
            resp = client.status()
            connected = resp.get("connected", False)
        except DaemonError:
            connected = False

        if connected and self._status != STATUS_CONNECTED:
            # External connection detected
            self.set_status(STATUS_CONNECTED, "External")
        elif not connected and self._status == STATUS_CONNECTED:
            # Disconnected externally
            self.set_status(STATUS_DISCONNECTED)

    def show(self):
        self.tray.show()

    def hide(self):
        self.tray.hide()

    @staticmethod
    def is_system_tray_available() -> bool:
        return QSystemTrayIcon.isSystemTrayAvailable()