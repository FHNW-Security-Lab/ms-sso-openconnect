"""Backend module - provides platform-specific VPN backend implementations."""

import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .base import VPNBackendProtocol

# Singleton instance
_backend_instance = None


def get_backend() -> "VPNBackendProtocol":
    """Get the platform-appropriate backend singleton.

    Returns:
        VPNBackend instance for the current platform
    """
    global _backend_instance
    if _backend_instance is None:
        if sys.platform == "darwin":
            from vpn_ui.platform.backend import VPNBackend
        else:
            from vpn_ui.platform.backend import VPNBackend
        _backend_instance = VPNBackend()
    return _backend_instance
