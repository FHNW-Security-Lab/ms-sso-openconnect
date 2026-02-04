"""MS SSO OpenConnect - Core library.

Unified core module for all platforms (Linux, macOS).
"""

from .auth import do_saml_auth, _get_gp_prelogin
from .config import (
    get_connections,
    get_all_connections,  # Alias for backwards compatibility
    get_connection,
    save_connection,
    delete_connection,
    get_config,
    delete_all,
    PROTOCOLS,
)
from .cookies import (
    # User-level storage (for GUI apps)
    store_cookies,
    get_cached_cookies,
    get_stored_cookies,  # Alias for backwards compatibility
    clear_cookies,
    clear_stored_cookies,  # Alias for backwards compatibility
    # NetworkManager-level storage (for NM plugin)
    store_nm_cookies,
    get_nm_stored_cookies,
    clear_nm_cookies,
)
from .connect import (
    connect_vpn,
    disconnect,
)
from .totp import generate_totp, validate_secret

__all__ = [
    # Auth
    "do_saml_auth",
    "_get_gp_prelogin",
    # Config
    "get_connections",
    "get_all_connections",
    "get_connection",
    "save_connection",
    "delete_connection",
    "get_config",
    "delete_all",
    "PROTOCOLS",
    # Cookies (user-level)
    "store_cookies",
    "get_cached_cookies",
    "get_stored_cookies",
    "clear_cookies",
    "clear_stored_cookies",
    # Cookies (NM-level)
    "store_nm_cookies",
    "get_nm_stored_cookies",
    "clear_nm_cookies",
    # Connect
    "connect_vpn",
    "disconnect",
    # TOTP
    "generate_totp",
    "validate_secret",
]
