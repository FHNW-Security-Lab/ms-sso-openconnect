"""Owned OpenConnect lifecycle shared by CLI and desktop frontends.

The process stays attached so failures can be retried. A per-user lease prevents
concurrent attempts; only the interface/process recorded in that lease is touched.
"""

from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import re
import signal
import sys
import subprocess
import tempfile
import threading
import time
import uuid
from typing import Callable, Optional

from .cookies import clear_cookies, store_cookies
from .platform_info import get_gp_hip_report_wrapper, get_gp_os_version, get_openconnect_binary


def _state_dir() -> Path:
    base = Path(os.environ.get("XDG_RUNTIME_DIR", tempfile.gettempdir()))
    path = base / f"ms-sso-openconnect-{os.getuid()}"
    path.mkdir(mode=0o700, exist_ok=True)
    if path.is_symlink() or path.stat().st_uid != os.getuid():
        raise RuntimeError("Unsafe VPN runtime directory")
    path.chmod(0o700)
    return path


def _read_state() -> dict:
    try:
        state = json.loads((_state_dir() / "session.json").read_text())
        return state if isinstance(state, dict) else {}
    except (OSError, ValueError):
        return {}


def _owned_pids(state: dict) -> list[int]:
    """Match the exact generated interface, never every OpenConnect process."""
    interface = state.get("interface", "")
    binary = state.get("binary", "")
    if not re.fullmatch(r"msso[0-9a-f]{10}", interface) or not binary:
        return []
    matches = []
    for entry in Path("/proc").glob("[0-9]*"):
        try:
            args = (entry / "cmdline").read_bytes().split(b"\0")
            if not args:
                continue
            executable = os.fsdecode(args[0])
            if (os.path.basename(executable) == os.path.basename(binary)
                    and f"--interface={interface}".encode() in args):
                matches.append(int(entry.name))
        except (OSError, ValueError):
            continue
    return matches


def _tunnel_ready(interface: str) -> bool:
    try:
        result = subprocess.run(["ip", "-j", "addr", "show", "dev", interface],
                                capture_output=True, text=True, timeout=3)
        links = json.loads(result.stdout or "[]")
        return result.returncode == 0 and any(
            addr.get("scope") == "global" and addr.get("local")
            for link in links for addr in link.get("addr_info", [])
        )
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return False


def is_connected() -> bool:
    state = _read_state()
    return bool(state and _owned_pids(state) and _tunnel_ready(state["interface"]))


def active_connection_name() -> Optional[str]:
    return _read_state().get("connection_name") if is_connected() else None


def _signal_owned(state: dict, signum: int, use_pkexec: bool) -> bool:
    pids = _owned_pids(state)
    for pid in pids:
        # Recheck immediately before signalling in case teardown raced us.
        if pid not in _owned_pids(state):
            continue
        try:
            os.kill(pid, signum)
        except PermissionError:
            command = ["/usr/bin/kill", f"-{signum}", str(pid)]
            prefix = ["pkexec"] if use_pkexec else ["sudo"]
            try:
                result = subprocess.run(prefix + command, capture_output=True, timeout=60)
            except (OSError, subprocess.TimeoutExpired):
                return False
            if result.returncode:
                return False
        except ProcessLookupError:
            pass
    return True


def disconnect(force: bool = False, use_pkexec: bool = False, *, _mark_intent: bool = True) -> bool:
    """Stop our own tunnel gracefully, allowing vpnc-script to restore networking."""
    if sys.platform == "darwin":
        from ._connect_macos import disconnect as mac_disconnect
        return mac_disconnect(force)
    state = _read_state()
    if not state:
        if force:
            clear_cookies()
        return True
    if _mark_intent:
        (_state_dir() / "stop").write_text(state.get("interface", ""))
    if not _signal_owned(state, signal.SIGTERM if force else signal.SIGINT, use_pkexec):
        return False
    deadline = time.monotonic() + 15
    while _owned_pids(state) and time.monotonic() < deadline:
        time.sleep(0.1)
    # Do not SIGKILL: that skips OpenConnect's route/DNS teardown script.
    stopped = not _owned_pids(state)
    if stopped and force:
        clear_cookies()
    return stopped


def select_gp_cookie(cookies: dict, auth_interface: str = "portal") -> tuple[str, str]:
    if auth_interface == "gateway":
        if cookies.get("prelogin-cookie"):
            return str(cookies["prelogin-cookie"]), "gateway:prelogin-cookie"
        raise ValueError("GlobalProtect gateway authentication returned no prelogin cookie")
    for key in ("portal-userauthcookie", "prelogin-cookie"):
        if cookies.get(key):
            return str(cookies[key]), f"portal:{key}"
    raise ValueError("GlobalProtect authentication returned no usable cookie")


def build_anyconnect_cookie_header(cookies: dict) -> str:
    parts = []
    for raw_name, raw_value in cookies.items():
        name, value = str(raw_name).strip(), str(raw_value)
        if (not name or name.startswith("_") or name.casefold() in {"samlresponse", "saml-username"}
                or any(c in name or c in value for c in "\r\n")):
            continue
        parts.append(f"{name}={value}")
    if not parts:
        raise ValueError("AnyConnect authentication returned no usable cookies")
    return "; ".join(parts)


def _private_input(payload: bytes):
    """Seekable stdin survives sudo/pkexec fd closing and has no pipe size limit.

    AnyConnect reads this as a config, avoiding cookie-on-stdin's line limit.
    The temporary file is unlinked immediately and never named in argv.
    """
    stream = (os.fdopen(os.memfd_create("ms-sso-cookie", os.MFD_CLOEXEC), "w+b")
              if hasattr(os, "memfd_create") else tempfile.TemporaryFile())
    stream.write(payload)
    stream.seek(0)
    return stream


def _redact_output(line: str) -> str:
    return re.sub(r"(?i)((?:set-cookie|cookie|portal-userauthcookie|prelogin-cookie|webvpn)[=:]\s*)[^\n]*",
                  r"\1<redacted>", line)


def connect_vpn(
    vpn_server: str, protocol: str, cookies: dict, no_dtls: bool = False,
    username: Optional[str] = None, allow_fallback: bool = False,
    connection_name: Optional[str] = None, cached_usergroup: Optional[str] = None,
    use_pkexec: bool = False, cancel_callback: Optional[Callable[[], bool]] = None,
    connected_callback: Optional[Callable[[], None]] = None,
    progress_callback: Optional[Callable[[str], None]] = None,
    gp_auth_interface: str = "portal", gp_os_version: Optional[str] = None,
    disconnect_force_callback: Optional[Callable[[], bool]] = None,
) -> bool:
    """Run an owned tunnel until it stops; True means intentional disconnection.

    ``connected_callback`` fires once the assigned interface has a global address.
    False means failed/expired session (including exit 0), so callers can reconnect.
    """
    if sys.platform == "darwin":
        from ._connect_macos import connect_vpn as mac_connect
        return mac_connect(vpn_server, protocol, cookies.copy(), no_dtls, username,
                           allow_fallback, connection_name, cached_usergroup, use_pkexec)
    if protocol not in {"anyconnect", "gp"}:
        raise ValueError(f"Unsupported VPN protocol: {protocol}")
    if cancel_callback and cancel_callback():
        return True
    directory = _state_dir()
    with (directory / "lock").open("a") as lease:
        try:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Another VPN connection attempt is active")
        old = _read_state()
        if old and _owned_pids(old):
            raise RuntimeError("An owned VPN tunnel is already active; disconnect it first")
        (directory / "stop").unlink(missing_ok=True)
        interface = "msso" + uuid.uuid4().hex[:10]
        binary = get_openconnect_binary(protocol)
        cmd = [binary, "--verbose", f"--protocol={protocol}", f"--interface={interface}",
               "--non-inter", "--reconnect-timeout=300", f"--force-dpd={10 if protocol == 'gp' else 30}"]
        if no_dtls:
            cmd.append("--no-dtls")
        env = os.environ.copy()
        if protocol == "gp":
            # Only the validated auth-interface chooses portal vs gateway mode.
            cookie, group = select_gp_cookie(cookies, gp_auth_interface)
            if any(c in cookie for c in "\r\n"):
                raise ValueError("GlobalProtect cookie contains a line break")
            payload = (cookie + "\n").encode()
            cmd.extend(["--passwd-on-stdin", "--useragent=PAN GlobalProtect", "--os=linux-64",
                        f"--usergroup={group}"])
            gp_username = cookies.get("saml-username") or username
            if gp_username:
                cmd.append(f"--user={gp_username}")
            hip_wrapper = get_gp_hip_report_wrapper()
            if hip_wrapper:
                cmd.append(f"--csd-wrapper={hip_wrapper}")
            env["MS_SSO_GP_OS_VERSION"] = (gp_os_version if gp_os_version and gp_os_version.lower() != "auto"
                                            else get_gp_os_version())
        else:
            payload = ("cookie=" + build_anyconnect_cookie_header(cookies) + "\n").encode()
            cmd.append("--config=/dev/stdin")
        cmd.append(vpn_server)
        state = {"interface": interface, "binary": binary, "connection_name": connection_name}
        (directory / "session.json").write_text(json.dumps(state))
        process = None
        intentional = False
        try:
            if os.geteuid() != 0:
                if not use_pkexec:
                    subprocess.run(["sudo", "-v"], check=True)
                if protocol == "gp":
                    # Elevation filters environment; forward only this explicit
                    # non-secret HIP identity as an argv element, without a shell.
                    cmd = ["/usr/bin/env", "MS_SSO_GP_OS_VERSION=" + env["MS_SSO_GP_OS_VERSION"], *cmd]
                cmd.insert(0, "pkexec" if use_pkexec else "sudo")
            with _private_input(payload) as stdin:
                process = subprocess.Popen(cmd, stdin=stdin, stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT, env=env)
            # A dedicated reader preserves split lines and does not block cancellation
            # or readiness when OpenConnect emits no console output.
            def read_output():
                try:
                    for raw in iter(process.stdout.readline, b""):
                        line = raw.decode(errors="replace")
                        print(_redact_output(line), end="", flush=True)
                        if protocol == "gp" and gp_auth_interface == "portal" and connection_name:
                            match = re.search(r"portal-userauthcookie=(\S+)", line)
                            if match and match[1].lower() != "empty":
                                store_cookies(connection_name, {"portal-userauthcookie": match[1],
                                                               "saml-username": gp_username or ""},
                                              usergroup="portal:portal-userauthcookie")
                except (OSError, ValueError):
                    pass
            reader = threading.Thread(target=read_output, daemon=True)
            reader.start()
            try:
                timeout = max(15, min(600, int(os.environ.get("MS_SSO_TUNNEL_TIMEOUT", "180"))))
            except ValueError:
                timeout = 180
            deadline = time.monotonic() + timeout
            ready = False
            while process.poll() is None:
                stop_requested = (directory / "stop").exists()
                if stop_requested or (cancel_callback and cancel_callback()):
                    intentional = True
                    force = bool(disconnect_force_callback and disconnect_force_callback())
                    disconnect(force=force, use_pkexec=use_pkexec)
                    # A pending privilege prompt is still owned by our user.
                    if process.poll() is None and not _owned_pids(state):
                        try:
                            process.terminate()
                        except (PermissionError, ProcessLookupError):
                            pass
                    break
                if not ready and _tunnel_ready(interface):
                    ready = True
                    if progress_callback:
                        progress_callback("VPN tunnel established")
                    if connected_callback:
                        connected_callback()
                if not ready and time.monotonic() >= deadline:
                    if progress_callback:
                        progress_callback("VPN tunnel setup timed out")
                    disconnect(use_pkexec=use_pkexec, _mark_intent=False)
                    if process.poll() is None and not _owned_pids(state):
                        try:
                            process.terminate()
                        except (PermissionError, ProcessLookupError):
                            pass
                    break
                time.sleep(0.2)
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                raise RuntimeError("VPN process did not stop; refusing an overlapping reconnect")
            reader.join(timeout=2)
            # External --disconnect can race process exit; honor its recorded intent.
            intentional = intentional or (directory / "stop").exists()
            return intentional
        except KeyboardInterrupt:
            disconnect(use_pkexec=use_pkexec)
            return True
        finally:
            # An exception must not abandon an owned tunnel and start another one.
            if process is not None and process.poll() is None:
                _signal_owned(state, signal.SIGINT, use_pkexec)
            if not _owned_pids(state):
                (directory / "session.json").unlink(missing_ok=True)
                (directory / "stop").unlink(missing_ok=True)
