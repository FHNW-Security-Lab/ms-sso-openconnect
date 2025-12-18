"""Cross-platform abstractions for daemon."""

import os
import sys
from pathlib import Path
from typing import Optional

import psutil

APP_NAME = "ms-sso-openconnect"


# === Paths ===

def get_socket_path() -> str:
    """Get IPC socket/pipe path."""
    if sys.platform == "win32":
        return r"\\.\pipe\ms-sso-openconnect"
    elif sys.platform == "darwin":
        return "/var/run/ms-sso-openconnect.sock"
    else:
        # Linux: try /run first, fall back to /var/run
        if os.path.isdir("/run"):
            return "/run/ms-sso-openconnect.sock"
        return "/var/run/ms-sso-openconnect.sock"


def get_pid_file() -> Path:
    """Get PID file path for openconnect process."""
    if sys.platform == "win32":
        base = Path(os.environ.get("PROGRAMDATA", "C:/ProgramData"))
    elif sys.platform == "darwin":
        base = Path("/var/run")
    else:
        base = Path("/run") if os.path.isdir("/run") else Path("/var/run")

    return base / f"{APP_NAME}-vpn.pid"


def get_log_file() -> Path:
    """Get daemon log file path."""
    if sys.platform == "win32":
        base = Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / APP_NAME
        base.mkdir(parents=True, exist_ok=True)
        return base / "daemon.log"
    else:
        return Path(f"/var/log/{APP_NAME}-daemon.log")


# === Privileges ===

def is_root() -> bool:
    """Check if running with admin/root privileges."""
    if sys.platform == "win32":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return os.geteuid() == 0


# === Process Management ===

def find_process_by_name(name: str) -> Optional[psutil.Process]:
    """Find a running process by exact name.

    Args:
        name: Process name (e.g., 'openconnect')

    Returns:
        Process object or None
    """
    for proc in psutil.process_iter(["name", "pid"]):
        try:
            if proc.info["name"] == name:
                return proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None


def find_openconnect() -> Optional[psutil.Process]:
    """Find running openconnect process."""
    return find_process_by_name("openconnect")


def kill_process(pid: int, timeout: float = 10.0) -> bool:
    """Kill a process gracefully, then forcefully.

    Uses SIGTERM first, waits for exit, then SIGKILL if needed.
    On Windows, uses TerminateProcess.

    Args:
        pid: Process ID
        timeout: Seconds to wait before force kill

    Returns:
        True if process is dead
    """
    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return True  # Already dead

    try:
        # kill() to avoid sending a "goodbye" to the vpn server to keep session cookie alive
        # however, this breaks macOS networking so we use terminate() instead... cookie will be invalid.
        #proc.kill()  # SIGKILL on Unix
        proc.terminate()
        proc.wait(timeout=timeout)
        return True
    except psutil.TimeoutExpired:
        return False
    except psutil.NoSuchProcess:
        return True
    except Exception:
        return False


def send_signal(pid: int, sig: int) -> bool:
    """Send a signal to a process.

    Args:
        pid: Process ID
        sig: Signal number (e.g., signal.SIGINT)

    Returns:
        True if signal sent successfully
    """
    try:
        proc = psutil.Process(pid)
        proc.send_signal(sig)
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
        return False


def is_process_running(pid: int) -> bool:
    """Check if a process is running.

    Args:
        pid: Process ID

    Returns:
        True if running
    """
    try:
        proc = psutil.Process(pid)
        return proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return False


def get_process_info(pid: int) -> Optional[dict]:
    """Get info about a process.

    Args:
        pid: Process ID

    Returns:
        Dict with name, cmdline, status, or None
    """
    try:
        proc = psutil.Process(pid)
        return {
            "pid": pid,
            "name": proc.name(),
            "cmdline": proc.cmdline(),
            "status": proc.status(),
            "create_time": proc.create_time(),
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None