"""MS SSO OpenConnect - Privileged daemon."""

from .client import DaemonClient
from .platform import is_root, get_socket_path

__all__ = ["DaemonClient", "is_root", "get_socket_path"]