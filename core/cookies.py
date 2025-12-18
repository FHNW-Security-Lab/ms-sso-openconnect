"""Session cookie caching."""

import json
import os
import time
from pathlib import Path
from typing import Optional

from platformdirs import user_cache_dir

APP_NAME = "ms-sso-openconnect"


def _get_cache_dir() -> Path:
    """Get cache directory, respecting sudo user."""
    # If running via sudo, use real user's cache
    real_user = os.environ.get("SUDO_USER")
    if real_user and os.geteuid() == 0:
        import pwd
        try:
            home = pwd.getpwnam(real_user).pw_dir
            cache_dir = Path(home) / ".cache" / APP_NAME
        except KeyError:
            cache_dir = Path(user_cache_dir(APP_NAME))
    else:
        cache_dir = Path(user_cache_dir(APP_NAME))

    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def _get_cookie_file(name: str) -> Path:
    """Get path to cookie file for a connection."""
    safe_name = name.replace("/", "_").replace(":", "_").replace(" ", "_")
    return _get_cache_dir() / f"session_{safe_name}.json"


def store_cookies(
        name: str,
        cookies: dict,
        usergroup: Optional[str] = None,
) -> bool:
    """Store session cookies.

    Args:
        name: Connection name
        cookies: Cookie dictionary
        usergroup: Optional usergroup (e.g., 'portal:prelogin-cookie')

    Returns:
        True if stored successfully
    """
    try:
        cookie_file = _get_cookie_file(name)
        data = {
            "cookies": cookies,
            "timestamp": int(time.time()),
        }
        if usergroup:
            data["usergroup"] = usergroup

        cookie_file.write_text(json.dumps(data))
        cookie_file.chmod(0o600)

        # Chown to real user if running as root via sudo
        real_user = os.environ.get("SUDO_USER")
        if real_user and os.geteuid() == 0:
            import pwd
            try:
                pw = pwd.getpwnam(real_user)
                os.chown(cookie_file, pw.pw_uid, pw.pw_gid)
            except (KeyError, OSError):
                pass

        return True
    except Exception:
        return False


def get_cached_cookies(
        name: str,
        max_age_hours: int = 12,
) -> Optional[tuple[dict, Optional[str]]]:
    """Get cached session cookies.

    Args:
        name: Connection name
        max_age_hours: Maximum age before expiry

    Returns:
        (cookies_dict, usergroup) or None if not cached/expired
    """
    try:
        cookie_file = _get_cookie_file(name)
        if not cookie_file.exists():
            return None

        data = json.loads(cookie_file.read_text())

        age = int(time.time()) - data.get("timestamp", 0)
        if age > max_age_hours * 3600:
            clear_cookies(name)
            return None

        return (data.get("cookies"), data.get("usergroup"))
    except Exception:
        return None


def clear_cookies(name: Optional[str] = None) -> bool:
    """Clear cached cookies.

    Args:
        name: Connection name, or None to clear all

    Returns:
        True if cleared
    """
    try:
        if name:
            cookie_file = _get_cookie_file(name)
            if cookie_file.exists():
                cookie_file.unlink()
        else:
            cache_dir = _get_cache_dir()
            for f in cache_dir.glob("session_*.json"):
                f.unlink()
        return True
    except Exception:
        return False