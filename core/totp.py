"""TOTP helpers."""

import base64
import hashlib
import hmac
import struct
import time


def generate_totp(secret: str, digits: int = 6, period: int = 30) -> str:
    """Generate a TOTP code for a base32 secret."""
    if not secret:
        return ""
    key = base64.b32decode(secret.strip().replace(" ", "").upper())
    counter = int(time.time() // period)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    code = code_int % (10 ** digits)
    return str(code).zfill(digits)


def validate_secret(secret: str) -> bool:
    """Check if a TOTP secret is valid base32."""
    try:
        generate_totp(secret)
        return True
    except Exception:
        return False
