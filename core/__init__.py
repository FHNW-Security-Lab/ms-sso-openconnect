"""MS SSO OpenConnect - Core library."""

from .auth import do_saml_auth, _get_gp_prelogin
from .config import (
    get_connections,
    get_connection,
    save_connection,
    delete_connection,
    get_config,
    PROTOCOLS,
)
from .cookies import (
    store_cookies,
    get_cached_cookies,
    clear_cookies,
)
from .totp import generate_totp

__all__ = [
    "do_saml_auth",
    "get_connections",
    "get_connection",
    "save_connection",
    "delete_connection",
    "get_config",
    "PROTOCOLS",
    "store_cookies",
    "get_cached_cookies",
    "clear_cookies",
    "generate_totp",
]