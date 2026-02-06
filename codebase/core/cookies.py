"""Session cookie caching.

Provides two storage backends:
- User cache (via platformdirs): For GUI apps running as user
- System cache (/var/cache): For NetworkManager plugin running as root
"""

import json
import os
import time
from pathlib import Path
from typing import Optional, Tuple

APP_NAME = "ms-sso-openconnect"


# =============================================================================
# User-level cookie storage (for GUI apps)
# =============================================================================

def _get_user_cache_dir() -> Path:
    """Get user cache directory, respecting sudo user."""
    from platformdirs import user_cache_dir

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
    """Get path to cookie file for a connection (user storage)."""
    safe_name = name.replace("/", "_").replace(":", "_").replace(" ", "_")
    return _get_user_cache_dir() / f"session_{safe_name}.json"


def store_cookies(
        name: str,
        cookies: dict,
        usergroup: Optional[str] = None,
) -> bool:
    """Store session cookies (user-level storage).

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
) -> Optional[Tuple[dict, Optional[str]]]:
    """Get cached session cookies (user-level storage).

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


# Alias for backwards compatibility
get_stored_cookies = get_cached_cookies


def clear_cookies(name: Optional[str] = None) -> bool:
    """Clear cached cookies (user-level storage).

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
            cache_dir = _get_user_cache_dir()
            for f in cache_dir.glob("session_*.json"):
                f.unlink()
        return True
    except Exception:
        return False


# Alias for backwards compatibility
clear_stored_cookies = clear_cookies


# =============================================================================
# NetworkManager-level cookie storage (for NM plugin running as root)
# =============================================================================

def _get_nm_cache_dir() -> str:
    """Get NM cache directory (system-level)."""
    cache_dir = f"/var/cache/{APP_NAME}"
    try:
        os.makedirs(cache_dir, mode=0o755, exist_ok=True)
    except PermissionError:
        # Fall back to /tmp if /var/cache is not writable
        cache_dir = f"/tmp/{APP_NAME}-cache"
        os.makedirs(cache_dir, mode=0o755, exist_ok=True)
    return cache_dir


def _get_nm_cookie_file(connection_name: str) -> str:
    """Get path to cookie cache file for NM connection."""
    cache_dir = _get_nm_cache_dir()
    safe_name = connection_name.replace("/", "_").replace(":", "_").replace(" ", "_")
    return os.path.join(cache_dir, f"session_{safe_name}.json")


def store_nm_cookies(
        connection_name: str,
        cookies: dict,
        usergroup: Optional[str] = None,
) -> bool:
    """Store session cookies (NetworkManager version).

    Args:
        connection_name: NM connection name
        cookies: Cookie dictionary
        usergroup: Optional usergroup

    Returns:
        True if stored successfully
    """
    try:
        if not cookies:
            return False

        cookie_file = _get_nm_cookie_file(connection_name)
        data = {
            "cookies": cookies,
            "timestamp": int(time.time())
        }
        if usergroup:
            data["usergroup"] = usergroup

        with open(cookie_file, 'w') as f:
            json.dump(data, f)
        os.chmod(cookie_file, 0o600)
        return True
    except Exception:
        return False


def get_nm_stored_cookies(
        connection_name: str,
        max_age_hours: int = 12,
) -> Optional[Tuple[dict, Optional[str]]]:
    """Retrieve cached session cookies (NetworkManager version).

    Args:
        connection_name: NM connection name
        max_age_hours: Maximum age before expiry

    Returns:
        (cookies_dict, usergroup) or None if not cached/expired
    """
    try:
        cookie_file = _get_nm_cookie_file(connection_name)
        if not os.path.exists(cookie_file):
            return None

        with open(cookie_file, 'r') as f:
            data = json.load(f)

        age_seconds = int(time.time()) - data.get("timestamp", 0)
        if age_seconds > max_age_hours * 3600:
            clear_nm_cookies(connection_name)
            return None

        cookies = data.get("cookies")
        if not cookies:
            return None

        usergroup = data.get("usergroup")
        return (cookies, usergroup)
    except Exception:
        return None


def clear_nm_cookies(connection_name: str) -> bool:
    """Clear cached cookies (NetworkManager version).

    Args:
        connection_name: NM connection name

    Returns:
        True if cleared
    """
    try:
        cookie_file = _get_nm_cookie_file(connection_name)
        if os.path.exists(cookie_file):
            os.remove(cookie_file)
        return True
    except Exception:
        return False
