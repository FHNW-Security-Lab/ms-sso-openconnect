"""VPN connection management via openconnect."""

import os
import re
import shlex
import subprocess
from typing import Optional

from .cookies import store_cookies, clear_cookies
from .config import PROTOCOLS

# Terminal colors
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BOLD = "\033[1m"
NC = "\033[0m"


def _cleanup_dns_best_effort(use_pkexec: bool = False) -> None:
    """Best-effort DNS cleanup for tun interfaces after failure/disconnect."""
    tun_devs = set()
    try:
        links = subprocess.run(
            ["ip", "-o", "link", "show"],
            capture_output=True,
            text=True,
            check=False,
        )
        for line in links.stdout.splitlines():
            if ":" not in line:
                continue
            parts = line.split(":", 2)
            if len(parts) < 2:
                continue
            dev = parts[1].strip()
            if dev.startswith("tun"):
                tun_devs.add(dev)
    except Exception:
        pass

    if not tun_devs:
        tun_devs.add("tun0")

    def _run_cleanup_cmd(cmd: list[str]) -> None:
        candidates = [cmd]
        if use_pkexec:
            candidates.append(["pkexec"] + cmd)
        else:
            candidates.append(["sudo", "-n"] + cmd)

        for full_cmd in candidates:
            try:
                subprocess.run(full_cmd, capture_output=True, text=True, check=False, timeout=5)
            except Exception:
                continue

    for dev in sorted(tun_devs):
        _run_cleanup_cmd(["resolvectl", "revert", dev])
        _run_cleanup_cmd(["resolvconf", "-d", dev])


def connect_vpn(
    vpn_server: str,
    protocol: str,
    cookies: dict,
    no_dtls: bool = False,
    username: Optional[str] = None,
    allow_fallback: bool = False,
    connection_name: Optional[str] = None,
    cached_usergroup: Optional[str] = None,
    use_pkexec: bool = False,
) -> bool:
    """Connect to VPN using openconnect with the obtained cookie.

    Args:
        vpn_server: VPN server hostname
        protocol: Protocol ('anyconnect' or 'gp')
        cookies: Cookie dictionary from SAML auth
        no_dtls: Disable DTLS
        username: Username for GlobalProtect
        allow_fallback: Use subprocess so we can return on failure
        connection_name: Connection name for updating cookie cache
        cached_usergroup: Cached usergroup from previous connection
        use_pkexec: Use pkexec instead of sudo (for GUI without terminal)

    Returns:
        True if connection succeeded, False otherwise
    """
    print(f"\n{GREEN}Connecting to VPN...{NC}\n")

    proto_flag = PROTOCOLS.get(protocol, {}).get("flag", "anyconnect")

    # Track which cookie type we're using for --usergroup
    gp_cookie_type = None

    # Check if we have a gateway IP (GlobalProtect)
    gateway_target = cookies.pop('_gateway_ip', None) if protocol == "gp" else None

    if protocol == "gp":
        # GlobalProtect with SAML: prelogin-cookie from SAML response
        if cached_usergroup:
            print(f"  Using cached usergroup: {cached_usergroup}")
            gp_cookie_type = cached_usergroup
            if 'portal-userauthcookie' in cookies:
                cookie_str = cookies['portal-userauthcookie']
                print(f"  Using portal-userauthcookie (long-lived)")
            elif 'prelogin-cookie' in cookies:
                cookie_str = cookies['prelogin-cookie']
                print(f"  Using prelogin-cookie")
            else:
                cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
                print(f"  Using combined cookies")
        elif 'prelogin-cookie' in cookies:
            cookie_str = cookies['prelogin-cookie']
            gp_cookie_type = 'portal:prelogin-cookie'
            print(f"  Using prelogin-cookie (portal mode)")
        elif 'portal-userauthcookie' in cookies:
            cookie_str = cookies['portal-userauthcookie']
            gp_cookie_type = 'portal:portal-userauthcookie'
            print(f"  Using portal-userauthcookie (portal mode)")
        elif 'SAMLResponse' in cookies:
            cookie_str = cookies['SAMLResponse']
            gp_cookie_type = 'prelogin-cookie'
            print(f"  Using SAMLResponse ({len(cookie_str)} chars) - may not work")
        elif 'SESSID' in cookies:
            cookie_str = cookies['SESSID']
            gp_cookie_type = 'portal-userauthcookie'
            print(f"  Using SESSID - may not work for GP SAML")
        else:
            cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
            gp_cookie_type = 'portal-userauthcookie'
            print(f"  Using combined cookies")
    else:
        # AnyConnect uses name=value format
        cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])

    connect_target = vpn_server

    # For GP with SAML, use --passwd-on-stdin (like gp-saml-gui)
    use_stdin_cookie = protocol == "gp" and 'prelogin-cookie' in cookies

    if use_stdin_cookie:
        cmd = [
            "openconnect",
            "--verbose",
            f"--protocol={proto_flag}",
            "--passwd-on-stdin",
            connect_target,
        ]
    else:
        cmd = [
            "openconnect",
            "--verbose",
            f"--protocol={proto_flag}",
            f"--cookie={cookie_str}",
            connect_target,
        ]

    # Add options for GlobalProtect
    if protocol == "gp":
        cmd.insert(2, "--os=linux-64")
        cmd.insert(2, "--useragent=PAN GlobalProtect")
        if username:
            cmd.insert(2, f"--user={username}")
        if gp_cookie_type:
            cmd.insert(2, f"--usergroup={gp_cookie_type}")

    if no_dtls:
        cmd.insert(2, "--no-dtls")

    # Display command (for user visibility)
    display_cmd = f"openconnect --verbose --protocol={proto_flag}"
    if no_dtls:
        display_cmd += " --no-dtls"
    if protocol == "gp":
        display_cmd += " --useragent='PAN GlobalProtect' --os=linux-64"
        if gp_cookie_type:
            display_cmd += f" --usergroup={gp_cookie_type}"
        if username:
            display_cmd += f" --user={username}"
    if use_stdin_cookie:
        display_cmd += f" --passwd-on-stdin {connect_target}"
        print(f"  Running: echo '<cookie>' | {display_cmd}")
    else:
        display_cmd += f" --cookie=<session> {connect_target}"
        print(f"  Running: {display_cmd}")
    print()

    if use_stdin_cookie:
        # Determine privilege escalation command
        if use_pkexec:
            priv_cmd = ["pkexec"] + cmd
        else:
            # Cache sudo credentials before redirecting stdin
            subprocess.run(["sudo", "-v"], check=True)
            priv_cmd = ["sudo"] + cmd

        # Create pipe for stdin
        read_fd, write_fd = os.pipe()
        cookie_bytes = (cookie_str + '\n').encode()
        os.write(write_fd, cookie_bytes)
        os.close(write_fd)

        # Run openconnect with stdin from pipe
        process = subprocess.Popen(
            priv_cmd,
            stdin=read_fd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        os.close(read_fd)

        # Read stdout and look for portal-userauthcookie
        portal_cookie = None
        try:
            for line in process.stdout:
                print(line, end='')

                if 'portal-userauthcookie=' in line and protocol == "gp":
                    match = re.search(r'portal-userauthcookie=(\S+)', line)
                    if match:
                        portal_cookie = match.group(1)
                        if portal_cookie.lower() != 'empty':
                            print(f"\n    [DEBUG] Captured portal-userauthcookie")
        except KeyboardInterrupt:
            process.terminate()

        returncode = process.wait()

        # Update cache with long-lived cookie
        if portal_cookie and connection_name and portal_cookie.lower() != 'empty':
            print(f"\n{GREEN}Updating cache with long-lived portal-userauthcookie...{NC}")
            new_cookies = {'portal-userauthcookie': portal_cookie}
            store_cookies(connection_name, new_cookies, usergroup='portal:portal-userauthcookie')
    else:
        # Use sudo/pkexec for openconnect
        if use_pkexec:
            priv_cmd = ["pkexec"] + cmd
        else:
            priv_cmd = ["sudo"] + cmd
        process = subprocess.Popen(priv_cmd)
        returncode = process.wait()

    if returncode != 0:
        _cleanup_dns_best_effort(use_pkexec=use_pkexec)
        print(f"\n{YELLOW}Connection failed (exit code {returncode}).{NC}")
        return False
    return True


def disconnect(force: bool = False) -> bool:
    """Kill any running openconnect process.

    Args:
        force: If True, also clear session cookies

    Returns:
        True if process was killed
    """
    signal_flag = "-TERM" if force else "-KILL"
    result = subprocess.run(
        ["sudo", "pkill", signal_flag, "-f", "openconnect"],
        capture_output=True
    )
    if result.returncode == 0:
        _cleanup_dns_best_effort(use_pkexec=False)
        if force:
            clear_cookies()
            print(f"{GREEN}VPN disconnected and session terminated.{NC}")
        else:
            print(f"{GREEN}VPN disconnected (session kept alive for reconnect).{NC}")
        return True
    else:
        _cleanup_dns_best_effort(use_pkexec=False)
        print(f"{YELLOW}No active VPN connection found.{NC}")
        return False
