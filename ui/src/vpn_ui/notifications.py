"""Desktop notification handler for VPN UI."""

import subprocess
import sys

from PyQt6.QtWidgets import QSystemTrayIcon

IS_MAC = sys.platform == "darwin"


class NotificationManager:
    """Manages desktop notifications via system tray or native macOS notifications."""

    def __init__(self, tray_icon: QSystemTrayIcon):
        """Initialize the notification manager.

        Args:
            tray_icon: System tray icon to use for notifications
        """
        self.tray = tray_icon
        self._notifications_enabled = True
        self._use_native = IS_MAC

    def set_enabled(self, enabled: bool) -> None:
        """Enable or disable notifications.

        Args:
            enabled: Whether to show notifications
        """
        self._notifications_enabled = enabled

    def _show_native(self, title: str, message: str, sound: bool = True) -> bool:
        """Show a native macOS notification using osascript.

        Args:
            title: Notification title
            message: Notification message
            sound: Whether to play a sound

        Returns:
            True if successful
        """
        try:
            sound_cmd = 'sound name "default"' if sound else ""
            script = f'display notification "{message}" with title "{title}" {sound_cmd}'
            subprocess.run(
                ["osascript", "-e", script],
                capture_output=True,
                timeout=5
            )
            return True
        except Exception:
            return False

    def show(
        self,
        title: str,
        message: str,
        critical: bool = False,
        duration_ms: int = 5000
    ) -> None:
        """Show a desktop notification.

        Args:
            title: Notification title
            message: Notification message
            critical: If True, show as critical/error notification
            duration_ms: How long to show the notification (milliseconds)
        """
        if not self._notifications_enabled:
            return

        if self._use_native:
            if self._show_native(title, message, sound=critical):
                return

        icon = (
            QSystemTrayIcon.MessageIcon.Critical if critical
            else QSystemTrayIcon.MessageIcon.Information
        )

        self.tray.showMessage(title, message, icon, duration_ms)

    def connected(self, connection_name: str) -> None:
        """Show notification for successful VPN connection.

        Args:
            connection_name: Name of the connection
        """
        self.show(
            "VPN Connected",
            f"Successfully connected to {connection_name}"
        )

    def disconnected(self) -> None:
        """Show notification for VPN disconnection."""
        self.show("VPN Disconnected", "VPN connection closed")

    def connecting(self, connection_name: str) -> None:
        """Show notification when starting connection.

        Args:
            connection_name: Name of the connection
        """
        self.show(
            "Connecting...",
            f"Connecting to {connection_name}",
            duration_ms=3000
        )

    def auth_required(self, connection_name: str) -> None:
        """Show notification when browser auth is needed.

        Args:
            connection_name: Name of the connection
        """
        self.show(
            "Authentication Required",
            f"Please wait while authenticating to {connection_name}...",
            duration_ms=10000
        )

    def error(self, message: str, title: str = "VPN Error") -> None:
        """Show error notification.

        Args:
            message: Error message
            title: Error title
        """
        self.show(title, message, critical=True, duration_ms=8000)

    def cached_session(self, connection_name: str) -> None:
        """Show notification when using cached session.

        Args:
            connection_name: Name of the connection
        """
        self.show(
            "Using Cached Session",
            f"Reconnecting to {connection_name} with cached credentials",
            duration_ms=3000
        )
