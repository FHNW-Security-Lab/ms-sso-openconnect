"""Constants and configuration for VPN UI."""

from pathlib import Path
from PyQt6.QtGui import QIcon

# Application info
APP_NAME = "MS SSO OpenConnect"
APP_ID = "com.github.ms-sso-openconnect-ui"
VERSION = "1.0.1"

# Paths
RESOURCES_DIR = Path(__file__).parent / "resources"
ICONS_DIR = RESOURCES_DIR / "icons"

# Status constants
STATUS_DISCONNECTED = "disconnected"
STATUS_CONNECTING = "connecting"
STATUS_CONNECTED = "connected"

# Protocol mapping
PROTOCOLS = {
    "anyconnect": {"name": "Cisco AnyConnect", "flag": "anyconnect"},
    "gp": {"name": "GlobalProtect", "flag": "gp"},
}


def get_icon(name: str) -> QIcon:
    """Get an icon, trying bundled resources first, then system icons.

    Args:
        name: Icon name (without extension)

    Returns:
        QIcon instance
    """
    # Try bundled resource
    for ext in [".svg", ".png"]:
        resource_path = ICONS_DIR / f"{name}{ext}"
        if resource_path.exists():
            return QIcon(str(resource_path))

    # Try system theme icon
    icon = QIcon.fromTheme(name)
    if not icon.isNull():
        return icon

    # Fallback mappings to system icons
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

    # Last resort: return empty icon
    return QIcon()
