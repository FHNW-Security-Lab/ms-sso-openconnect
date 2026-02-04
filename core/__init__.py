"""Core library for MS SSO VPN authentication."""

from .auth import do_saml_auth
from .totp import generate_totp

__all__ = ["do_saml_auth", "generate_totp"]
