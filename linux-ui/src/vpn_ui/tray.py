"""System tray icon and menu for VPN UI."""

from typing import Optional

from PyQt6.QtCore import QObject, QTimer, pyqtSignal
from PyQt6.QtGui import QAction, QIcon
from PyQt6.QtWidgets import QMenu, QSystemTrayIcon

from vpn_ui.constants import (
    APP_NAME,
    STATUS_CONNECTED,
    STATUS_CONNECTING,
    STATUS_DISCONNECTED,
    get_icon,
)


class VPNTrayIcon(QObject):
    """System tray icon with VPN status and menu."""

    # Signals
    connect_requested = pyqtSignal(str)  # connection name
    disconnect_requested = pyqtSignal(bool)  # force
    settings_requested = pyqtSignal()
    quit_requested = pyqtSignal()

    def __init__(self, parent: Optional[QObject] = None):
        """Initialize the tray icon.

        Args:
            parent: Parent QObject
        """
        super().__init__(parent)

        self.tray = QSystemTrayIcon(parent)
        self.tray.setToolTip(APP_NAME)

        self._current_status = STATUS_DISCONNECTED
        self._current_connection: Optional[str] = None
        self._connections: dict = {}

        # Load icons
        self._icons = {
            STATUS_DISCONNECTED: get_icon("vpn-disconnected"),
            STATUS_CONNECTING: get_icon("vpn-connecting"),
            STATUS_CONNECTED: get_icon("vpn-connected"),
        }

        # Set app icon as fallback if no icons available
        app_icon = get_icon("app-icon")
        if not app_icon.isNull():
            for status in [STATUS_DISCONNECTED, STATUS_CONNECTING, STATUS_CONNECTED]:
                if self._icons[status].isNull():
                    self._icons[status] = app_icon

        self._setup_menu()
        self._update_icon()

        # Status polling timer
        self._status_timer = QTimer()
        self._status_timer.timeout.connect(self._poll_status)

        # Double-click to open settings
        self.tray.activated.connect(self._on_activated)

    def _setup_menu(self) -> None:
        """Set up the tray context menu."""
        self.menu = QMenu()

        # Status header (non-clickable)
        self._status_action = self.menu.addAction("Status: Disconnected")
        self._status_action.setEnabled(False)

        self.menu.addSeparator()

        # Connections submenu (populated dynamically)
        self._connections_menu = self.menu.addMenu("Connect")
        self._connections_menu.setEnabled(False)

        # Disconnect action
        self._disconnect_action = self.menu.addAction("Disconnect")
        self._disconnect_action.triggered.connect(
            lambda: self.disconnect_requested.emit(False)
        )
        self._disconnect_action.setEnabled(False)

        # Force disconnect action
        self._force_disconnect_action = self.menu.addAction("Force Disconnect")
        self._force_disconnect_action.triggered.connect(
            lambda: self.disconnect_requested.emit(True)
        )
        self._force_disconnect_action.setEnabled(False)
        self._force_disconnect_action.setToolTip("Terminates the VPN session completely")

        self.menu.addSeparator()

        # Settings
        settings_action = self.menu.addAction("Settings...")
        settings_action.triggered.connect(self.settings_requested.emit)

        self.menu.addSeparator()

        # Quit
        quit_action = self.menu.addAction("Quit")
        quit_action.triggered.connect(self.quit_requested.emit)

        self.tray.setContextMenu(self.menu)

    def _on_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        """Handle tray icon activation (clicks).

        Args:
            reason: The type of activation
        """
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.settings_requested.emit()

    def update_connections(self, connections: dict) -> None:
        """Update the connections submenu.

        Args:
            connections: Dictionary of connection name -> details
        """
        self._connections = connections
        self._connections_menu.clear()

        if not connections:
            self._connections_menu.setEnabled(False)
            return

        self._connections_menu.setEnabled(True)

        for name, details in connections.items():
            protocol = details.get("protocol", "anyconnect")
            protocol_name = "GP" if protocol == "gp" else "AC"
            action = self._connections_menu.addAction(f"{name} ({protocol_name})")
            # Use default argument to capture name correctly in lambda
            action.triggered.connect(
                lambda checked, n=name: self.connect_requested.emit(n)
            )

    def set_status(
        self,
        status: str,
        connection_name: Optional[str] = None
    ) -> None:
        """Update tray status and icon.

        Args:
            status: One of STATUS_CONNECTED, STATUS_CONNECTING, STATUS_DISCONNECTED
            connection_name: Name of the current/connecting connection
        """
        self._current_status = status
        self._current_connection = connection_name
        self._update_icon()

        if status == STATUS_CONNECTED:
            self._status_action.setText(f"Connected: {connection_name}")
            self._disconnect_action.setEnabled(True)
            self._force_disconnect_action.setEnabled(True)
            self._connections_menu.setEnabled(False)
            self.tray.setToolTip(f"{APP_NAME} - Connected to {connection_name}")
        elif status == STATUS_CONNECTING:
            self._status_action.setText(f"Connecting: {connection_name}...")
            self._disconnect_action.setEnabled(True)
            self._force_disconnect_action.setEnabled(True)
            self._connections_menu.setEnabled(False)
            self.tray.setToolTip(f"{APP_NAME} - Connecting to {connection_name}...")
        else:
            self._status_action.setText("Status: Disconnected")
            self._disconnect_action.setEnabled(False)
            self._force_disconnect_action.setEnabled(False)
            self._connections_menu.setEnabled(bool(self._connections))
            self.tray.setToolTip(f"{APP_NAME} - Disconnected")

    def get_status(self) -> str:
        """Get current status.

        Returns:
            Current status string
        """
        return self._current_status

    def get_current_connection(self) -> Optional[str]:
        """Get current connection name.

        Returns:
            Connection name or None
        """
        return self._current_connection

    def _update_icon(self) -> None:
        """Update the tray icon based on current status."""
        icon = self._icons.get(self._current_status, self._icons[STATUS_DISCONNECTED])
        self.tray.setIcon(icon)

    def start_status_polling(self, interval_ms: int = 5000) -> None:
        """Start polling for VPN connection status.

        Args:
            interval_ms: Polling interval in milliseconds
        """
        self._status_timer.start(interval_ms)

    def stop_status_polling(self) -> None:
        """Stop status polling."""
        self._status_timer.stop()

    def _poll_status(self) -> None:
        """Poll VPN connection status.

        This is called by the timer to check if openconnect is running.
        """
        # Import here to avoid circular imports
        import subprocess
        from vpn_ui.vpn_backend import get_backend

        try:
            # Use pgrep -x to match exact process name, not paths containing "openconnect"
            result = subprocess.run(
                ["pgrep", "-x", "openconnect"],
                capture_output=True,
                text=True
            )
            is_connected = result.returncode == 0
        except Exception:
            is_connected = False

        # Update status based on poll result
        if is_connected:
            if self._current_status != STATUS_CONNECTED:
                # VPN connected - try to get connection name from state
                try:
                    backend = get_backend()
                    active_conn = backend.get_active_connection()
                    conn_name = active_conn if active_conn else "Unknown"
                except Exception:
                    conn_name = "Unknown"
                self.set_status(STATUS_CONNECTED, conn_name)
        else:
            if self._current_status != STATUS_DISCONNECTED:
                # VPN disconnected externally - clear state
                try:
                    backend = get_backend()
                    backend.clear_active_connection()
                except Exception:
                    pass
                self.set_status(STATUS_DISCONNECTED)

    def show(self) -> None:
        """Show the tray icon."""
        self.tray.show()

    def hide(self) -> None:
        """Hide the tray icon."""
        self.tray.hide()

    def is_visible(self) -> bool:
        """Check if tray icon is visible.

        Returns:
            True if visible
        """
        return self.tray.isVisible()

    @staticmethod
    def is_system_tray_available() -> bool:
        """Check if system tray is available.

        Returns:
            True if system tray is available
        """
        return QSystemTrayIcon.isSystemTrayAvailable()
