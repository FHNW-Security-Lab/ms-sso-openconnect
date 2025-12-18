"""Constants and configuration for GUI."""

from pathlib import Path

from PyQt6.QtGui import QIcon

# Application info
APP_NAME = "MS SSO OpenConnect"
APP_ID = "com.github.ms-sso-openconnect"
VERSION = "2.0.0"

# Paths
RESOURCES_DIR = Path(__file__).parent / "resources"
ICONS_DIR = RESOURCES_DIR / "icons"

# Status constants
STATUS_DISCONNECTED = "disconnected"
STATUS_CONNECTING = "connecting"
STATUS_CONNECTED = "connected"

# Re-export protocols from core
from core import PROTOCOLS


def get_icon(name: str) -> QIcon:
    """Get an icon from bundled resources or system theme.

    Args:
        name: Icon name (without extension)

    Returns:
        QIcon instance
    """
    # Try bundled resource
    for ext in (".svg", ".png"):
        path = ICONS_DIR / f"{name}{ext}"
        if path.exists():
            return QIcon(str(path))

    # Try system theme
    icon = QIcon.fromTheme(name)
    if not icon.isNull():
        return icon

    # Fallback mappings
    fallbacks = {
        "vpn-connected": "network-vpn-symbolic",
        "vpn-disconnected": "network-vpn-disconnected-symbolic",
        "vpn-connecting": "network-vpn-acquiring-symbolic",
        "app-icon": "network-vpn",
    }

    if name in fallbacks:
        icon = QIcon.fromTheme(fallbacks[name])
        if not icon.isNull():
            return icon

    return QIcon()