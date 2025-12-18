"""TOTP code generation."""

import pyotp


def generate_totp(secret: str) -> str:
    """Generate current TOTP code from secret.

    Args:
        secret: Base32-encoded TOTP secret

    Returns:
        6-digit TOTP code

    Raises:
        ValueError: If secret is invalid
    """
    secret = secret.strip().replace(" ", "").upper()
    totp = pyotp.TOTP(secret)
    return totp.now()


def validate_secret(secret: str) -> bool:
    """Check if TOTP secret is valid.

    Args:
        secret: Base32-encoded TOTP secret

    Returns:
        True if valid
    """
    try:
        generate_totp(secret)
        return True
    except Exception:
        return False