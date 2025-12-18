"""Desktop notifications via system tray."""

from PyQt6.QtWidgets import QSystemTrayIcon


class NotificationManager:
    """Manages desktop notifications."""

    def __init__(self, tray_icon: QSystemTrayIcon):
        self.tray = tray_icon
        self._enabled = True

    def set_enabled(self, enabled: bool):
        self._enabled = enabled

    def show(
            self,
            title: str,
            message: str,
            critical: bool = False,
            duration_ms: int = 5000,
    ):
        """Show a notification."""
        if not self._enabled:
            return

        icon = (
            QSystemTrayIcon.MessageIcon.Critical if critical
            else QSystemTrayIcon.MessageIcon.Information
        )
        self.tray.showMessage(title, message, icon, duration_ms)

    def connected(self, name: str):
        self.show("VPN Connected", f"Connected to {name}")

    def disconnected(self):
        self.show("VPN Disconnected", "VPN connection closed")

    def connecting(self, name: str):
        self.show("Connecting...", f"Connecting to {name}", duration_ms=3000)

    def error(self, message: str, title: str = "VPN Error"):
        self.show(title, message, critical=True, duration_ms=8000)

    def daemon_not_running(self):
        self.show(
            "Daemon Not Running",
            "Start daemon with: sudo ms-sso-openconnect-daemon",
            critical=True,
            duration_ms=10000,
        )