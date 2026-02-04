#!/usr/bin/env python3
"""
NetworkManager VPN Plugin Service for MS SSO OpenConnect

This service implements the org.freedesktop.NetworkManager.VPN.Plugin
D-Bus interface to handle VPN connections via NetworkManager.

It uses the unified core module for:
- SAML authentication via headless browser
- OpenConnect VPN connection
- Keyring credential storage
- TOTP generation
"""

import json
import os
import sys
import signal
import subprocess
import threading
import time
import logging
import socket
from pathlib import Path

# Set up logging - use syslog for reliability
log = logging.getLogger('nm-ms-sso')
log.setLevel(logging.DEBUG)

# Use syslog handler (most reliable for system services)
try:
    from logging.handlers import SysLogHandler
    syslog_handler = SysLogHandler(address='/dev/log')
    syslog_handler.setLevel(logging.DEBUG)
    syslog_handler.setFormatter(logging.Formatter('nm-ms-sso: %(message)s'))
    log.addHandler(syslog_handler)
except Exception:
    pass

# Also log to stderr (journalctl captures this from systemd services)
stderr_handler = logging.StreamHandler(sys.stderr)
stderr_handler.setLevel(logging.DEBUG)
stderr_handler.setFormatter(logging.Formatter('[nm-ms-sso] %(message)s'))
log.addHandler(stderr_handler)

# Try to also log to a file
try:
    file_handler = logging.FileHandler('/tmp/nm-ms-sso.log')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
    log.addHandler(file_handler)
except Exception:
    pass

import gi
gi.require_version('NM', '1.0')
from gi.repository import GLib, NM

import dbus
import dbus.service
import dbus.mainloop.glib


def _setup_core_module():
    """Add core module to path if not already importable."""
    try:
        import core
        return
    except ImportError:
        pass

    # Development: nm-plugin/src/nm-ms-sso-service.py -> ../../ -> project root
    project_root = Path(__file__).parent.parent.parent
    if project_root.exists() and (project_root / "core").exists():
        if str(project_root) not in sys.path:
            sys.path.insert(0, str(project_root))
        return

    # System installation paths
    system_paths = [
        Path("/usr/share/ms-sso-openconnect"),
        Path("/usr/lib/ms-sso-openconnect"),
        Path("/opt/ms-sso-openconnect"),
    ]
    for path in system_paths:
        if (path / "core").exists():
            if str(path) not in sys.path:
                sys.path.insert(0, str(path))
            return

    raise ImportError(
        "Cannot find core module. "
        f"Searched: {project_root}, {', '.join(str(p) for p in system_paths)}"
    )


# Setup core module on import
_setup_core_module()

# Import from core module
from core import (
    do_saml_auth,
    PROTOCOLS,
)
from core.cookies import (
    store_nm_cookies,
    get_nm_stored_cookies,
    clear_nm_cookies,
)


# NetworkManager VPN Plugin D-Bus interface
NM_VPN_DBUS_PLUGIN_PATH = "/org/freedesktop/NetworkManager/VPN/Plugin"
NM_VPN_DBUS_PLUGIN_INTERFACE = "org.freedesktop.NetworkManager.VPN.Plugin"
NM_DBUS_SERVICE = "org.freedesktop.NetworkManager.ms-sso"

# VPN Plugin states (from NM headers)
NM_VPN_SERVICE_STATE_UNKNOWN = 0
NM_VPN_SERVICE_STATE_INIT = 1
NM_VPN_SERVICE_STATE_SHUTDOWN = 2
NM_VPN_SERVICE_STATE_STARTING = 3
NM_VPN_SERVICE_STATE_STARTED = 4
NM_VPN_SERVICE_STATE_STOPPING = 5
NM_VPN_SERVICE_STATE_STOPPED = 6

# Failure reasons
NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED = 0
NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED = 1
NM_VPN_PLUGIN_FAILURE_BAD_IP_CONFIG = 2


class VPNPluginService(dbus.service.Object):
    """NetworkManager VPN Plugin D-Bus Service."""

    def __init__(self, bus):
        self.bus = bus
        self.state = NM_VPN_SERVICE_STATE_INIT
        self.vpn_process = None
        self.connection_thread = None
        self.mainloop = None
        self.inactivity_timeout = None
        # Store connection info for config emission
        self.current_gateway = None
        self.current_tun_device = None
        self.current_protocol = None
        # Cancel flag (e.g. NM timeout/user disconnect) so we don't continue
        # long-running auth and connect behind NetworkManager's back.
        self.cancel_requested = False

        # Register on D-Bus
        bus_name = dbus.service.BusName(NM_DBUS_SERVICE, bus=bus)
        dbus.service.Object.__init__(self, bus_name, NM_VPN_DBUS_PLUGIN_PATH)

        log.info("Core module loaded successfully")

        # Set initial state
        self._set_state(NM_VPN_SERVICE_STATE_INIT)

        # Start inactivity timeout (quit after 2 minutes of inactivity)
        self._reset_inactivity_timeout()

    def _reset_inactivity_timeout(self):
        """Reset the inactivity timeout."""
        if self.inactivity_timeout is not None:
            # Check if source still exists before removing to avoid GLib warning
            source = GLib.main_context_default().find_source_by_id(self.inactivity_timeout)
            if source is not None:
                GLib.source_remove(self.inactivity_timeout)
            self.inactivity_timeout = None
        self.inactivity_timeout = GLib.timeout_add_seconds(120, self._on_inactivity_timeout)

    def _on_inactivity_timeout(self):
        """Called when the service has been inactive for too long."""
        # Mark timeout as fired so we don't try to remove it later
        self.inactivity_timeout = None
        if self.state in (NM_VPN_SERVICE_STATE_INIT, NM_VPN_SERVICE_STATE_STOPPED):
            log.info("Inactivity timeout, shutting down")
            self._shutdown()
        return False

    def _shutdown(self):
        """Shutdown the service."""
        self._set_state(NM_VPN_SERVICE_STATE_SHUTDOWN)
        if self.mainloop:
            self.mainloop.quit()

    def _set_state(self, state):
        """Set and emit the VPN service state."""
        if self.state != state:
            self.state = state
            self.StateChanged(state)

    def _get_connection_secrets(self, settings):
        """Extract secrets from connection settings."""
        secrets = {}

        # Debug: print full settings structure
        log.info(f"Full settings keys: {list(settings.keys())}")

        # Get VPN settings
        vpn_settings = settings.get('vpn', {})
        vpn_data = vpn_settings.get('data', {})
        vpn_secrets = vpn_settings.get('secrets', {})

        log.info(f"VPN settings keys: {list(vpn_settings.keys())}")
        log.info(f"VPN data: {vpn_data}")
        log.info(f"VPN secrets keys: {list(vpn_secrets.keys())}")

        # Extract data fields
        secrets['gateway'] = vpn_data.get('gateway', '')
        secrets['protocol'] = vpn_data.get('protocol', 'anyconnect')
        secrets['username'] = vpn_data.get('username', '')

        # Extract secrets
        secrets['password'] = vpn_secrets.get('password', '')
        secrets['totp_secret'] = vpn_secrets.get('totp-secret', '')

        # If secrets not provided, try to get from keyring using libsecret
        # Use UUID (stable identifier) not connection name
        if not secrets['password'] or not secrets['totp_secret']:
            log.info(f"Secrets not in connection, trying keyring...")
            conn_uuid = settings.get('connection', {}).get('uuid', '')
            log.info(f"Connection UUID for keyring: {conn_uuid}")
            if conn_uuid:
                try:
                    # Use GObject introspection for libsecret (same schema as C editor)
                    gi.require_version('Secret', '1')
                    from gi.repository import Secret

                    schema = Secret.Schema.new(
                        "org.freedesktop.NetworkManager.ms-sso",
                        Secret.SchemaFlags.DONT_MATCH_NAME,
                        {
                            "connection-id": Secret.SchemaAttributeType.STRING,
                            "secret-type": Secret.SchemaAttributeType.STRING,
                        }
                    )

                    if not secrets['password']:
                        pw = Secret.password_lookup_sync(
                            schema, {"connection-id": conn_uuid, "secret-type": "password"}, None
                        )
                        if pw:
                            secrets['password'] = pw
                            log.info(f"Found password in keyring")
                        else:
                            log.info(f"Password not found in keyring")

                    if not secrets['totp_secret']:
                        totp = Secret.password_lookup_sync(
                            schema, {"connection-id": conn_uuid, "secret-type": "totp-secret"}, None
                        )
                        if totp:
                            secrets['totp_secret'] = totp
                            log.info(f"Found TOTP secret in keyring")
                        else:
                            log.info(f"TOTP secret not found in keyring")

                except Exception as ke:
                    log.info(f"Keyring error: {ke}")
                    import traceback
                    traceback.print_exc()

        return secrets

    def _connect_thread(self, settings):
        """Worker thread for VPN connection."""
        try:
            self._reset_inactivity_timeout()
            self.cancel_requested = False

            # Extract connection parameters
            secrets = self._get_connection_secrets(settings)
            gateway = secrets['gateway']
            protocol = secrets['protocol']
            username = secrets['username']
            password = secrets['password']
            totp_secret = secrets['totp_secret']

            if not gateway:
                raise Exception("No gateway specified")

            if not username:
                raise Exception("No username specified")

            log.info(f"Connecting to {gateway} via {protocol}")
            log.info(f"Username: {username}")
            log.debug(f"Password: {'(set)' if password else '(not set)'}")
            log.debug(f"TOTP: {'(set)' if totp_secret else '(not set)'}")

            # Store gateway for config emission
            self.current_gateway = gateway
            self.current_protocol = protocol

            # IMPORTANT: Resolve gateway IP NOW, before VPN connects
            # After VPN connects, DNS switches to VPN DNS servers which can't resolve external hostnames
            self.current_gateway_ip = None
            gateway_lookup = gateway
            try:
                from urllib.parse import urlparse
                parsed = urlparse(gateway if "://" in gateway else f"//{gateway}")
                if parsed.hostname:
                    gateway_lookup = parsed.hostname
            except Exception:
                gateway_lookup = gateway
            try:
                self.current_gateway_ip = socket.gethostbyname(gateway_lookup)
                log.info(f"Pre-resolved gateway {gateway_lookup} -> {self.current_gateway_ip}")
            except Exception as e:
                log.warning(f"Failed to pre-resolve gateway {gateway_lookup}: {e}")
                # If gateway is already an IP address, use it
                if gateway and gateway[0].isdigit():
                    self.current_gateway_ip = gateway
                    log.info(f"Gateway appears to be an IP address: {gateway}")

            # Emit an initial Config early so NetworkManager doesn't time out while
            # long-running SAML authentication is in progress (notably for GlobalProtect).
            GLib.idle_add(self._emit_initial_config)
            # NetworkManager expects the plugin to reach STARTED in a timely manner or it
            # may cancel the connection (observed ~60s). GlobalProtect SAML/MFA flows can
            # easily exceed that. By default we keep STARTING so the UI shows "Connecting"
            # until the tunnel is actually up. Set MS_SSO_NM_GP_EARLY_STARTED=1 to
            # preserve the legacy behavior (optimistically marking STARTED during auth).
            if protocol == 'gp':
                if os.environ.get("MS_SSO_NM_GP_EARLY_STARTED", "").lower() in {"1", "true", "yes"}:
                    GLib.idle_add(self._emit_started_for_auth)

            # Connection name for cookie cache
            connection_name = f"nm-{gateway}"
            log.debug(f"Cookie cache connection name: {connection_name}")

            # Try connection with retry on cookie rejection
            max_attempts = 2
            for attempt in range(max_attempts):
                log.info(f"Connection attempt {attempt + 1}/{max_attempts}")
                if self.cancel_requested:
                    log.info("Connect cancelled before authentication; aborting")
                    return

                # Try cached cookies first (only on first attempt, not for GlobalProtect)
                # GlobalProtect prelogin-cookie has very short TTL, so always re-auth
                cookies = None
                used_cache = False

                if attempt == 0 and protocol == 'gp':
                    log.info("GlobalProtect: skipping cookie cache (short TTL)")
                elif attempt == 0:
                    log.debug("Checking for cached cookies...")
                    cached = get_nm_stored_cookies(connection_name, max_age_hours=12)
                    if cached:
                        # cached is tuple (cookies_dict, usergroup)
                        cookies, usergroup = cached
                        used_cache = True
                        log.info(f"Using cached cookies (keys: {list(cookies.keys()) if cookies else 'none'})")
                        # Debug: write cached cookies to file for comparison
                        try:
                            with open('/tmp/nm-vpn-cached-cookies.json', 'w') as f:
                                json.dump({"source": "cache", "cookies": cookies, "usergroup": usergroup}, f, indent=2)
                            log.debug(f"Cached cookies written to /tmp/nm-vpn-cached-cookies.json")
                        except Exception as e:
                            log.debug(f"Could not write cached cookies debug file: {e}")
                    else:
                        log.info("No valid cached cookies found")

                # If no cached cookies or this is a retry, authenticate
                if not cookies:
                    log.info("Performing SAML authentication...")
                    self.auth_in_progress = True
                    self.saml_start_time = time.monotonic()

                    # Keep NetworkManager from timing out while SAML is in progress by
                    # periodically emitting an initial Config. (GP MFA can take >60s.)
                    stop_keepalive = threading.Event()

                    def _saml_keepalive():
                        while not stop_keepalive.wait(15):
                            if self.cancel_requested:
                                return
                            GLib.idle_add(self._emit_initial_config)
                            # Keep NetworkManager from thinking the connection stalled.
                            if protocol == 'gp' and os.environ.get("MS_SSO_NM_GP_EARLY_STARTED", "").lower() in {"1", "true", "yes"}:
                                GLib.idle_add(self._emit_started_keepalive)
                            else:
                                GLib.idle_add(self._emit_starting_keepalive)

                    keepalive_thread = threading.Thread(target=_saml_keepalive, daemon=True)
                    keepalive_thread.start()

                    # Ensure playwright can find the browser
                    # Check multiple possible locations
                    import glob
                    browser_paths = [
                        "/root/.cache/ms-playwright",
                        "/var/cache/ms-playwright",
                    ]
                    # Expand user home directories
                    home_paths = glob.glob("/home/*/.cache/ms-playwright")
                    browser_paths.extend(home_paths)

                    # Try to find existing playwright installation
                    playwright_path_found = False
                    for p in browser_paths:
                        if not os.path.isdir(p):
                            continue
                        # Check for chromium directory (e.g., chromium-1234)
                        chromium_dirs = glob.glob(os.path.join(p, "chromium*"))
                        if chromium_dirs:
                            os.environ['PLAYWRIGHT_BROWSERS_PATH'] = p
                            log.info(f"Using playwright browsers from: {p}")
                            playwright_path_found = True
                            break

                    if not playwright_path_found:
                        log.warning(f"No playwright browser found in any of: {browser_paths}")

                    try:
                        cookies = do_saml_auth(
                            vpn_server=gateway,
                            vpn_server_ip=self.current_gateway_ip,
                            username=username,
                            password=password,
                            totp_secret=totp_secret,
                            auto_totp=True,
                            headless=True,
                            debug=True,  # Enable debug to see screenshots
                            protocol=protocol  # Pass protocol for correct SAML URL
                        )
                        log.info(f"SAML auth returned cookies: {list(cookies.keys()) if cookies else 'none'}")
                        # Debug: write fresh cookies to file for comparison
                        try:
                            with open('/tmp/nm-vpn-fresh-cookies.json', 'w') as f:
                                json.dump({"source": "fresh_saml", "cookies": cookies}, f, indent=2)
                            log.debug(f"Fresh cookies written to /tmp/nm-vpn-fresh-cookies.json")
                        except Exception as e:
                            log.debug(f"Could not write fresh cookies debug file: {e}")
                    except Exception as auth_err:
                        log.error(f"SAML auth error: {auth_err}")
                        import traceback
                        traceback.print_exc()
                        raise Exception(f"SAML authentication error: {auth_err}")
                    finally:
                        self.auth_in_progress = False
                        self.saml_start_time = None
                        stop_keepalive.set()

                    if not cookies:
                        raise Exception("SAML authentication returned no cookies")

                    if self.cancel_requested:
                        log.info("Connect cancelled during authentication; aborting")
                        return

                    # Store fresh cookies using NM-specific storage (skip GlobalProtect - short TTL)
                    if protocol != 'gp':
                        store_nm_cookies(connection_name, cookies, usergroup='portal:prelogin-cookie')

                # Try to connect with these cookies
                if self.cancel_requested:
                    log.info("Connect cancelled before starting OpenConnect; aborting")
                    return
                success, error_msg = self._attempt_vpn_connection(gateway, protocol, cookies, username)

                if success:
                    log.info("VPN connection successful")
                    break  # Connection successful
                elif used_cache and attempt < max_attempts - 1:
                    # Cookie was rejected, clear cache and retry with fresh auth
                    log.warning("Cookie rejected, clearing cache and re-authenticating...")
                    clear_nm_cookies(connection_name)
                    continue
                else:
                    raise Exception(error_msg or "VPN connection failed")

        except Exception as e:
            error_msg = str(e)
            log.error(f"Connection error: {error_msg}")
            import traceback
            traceback.print_exc()
            GLib.idle_add(lambda msg=error_msg: self._emit_failure(msg))

    def _attempt_vpn_connection(self, gateway, protocol, cookies, username=None):
        """Attempt to establish VPN connection with given cookies.

        Returns:
            Tuple of (success: bool, error_message: str or None)
        """
        try:
            # Log cookie info for debugging
            log.debug(f"Cookie keys: {list(cookies.keys())}")

            # Connect to VPN
            # We use subprocess so we can monitor and return control
            proto_flag = PROTOCOLS.get(protocol, {}).get('flag', 'anyconnect')

            if protocol == 'gp' and 'prelogin-cookie' in cookies:
                cookie_str = cookies.get('prelogin-cookie', '')
                log.debug(f"Using GlobalProtect prelogin-cookie (len={len(cookie_str)})")
                cmd = [
                    "openconnect",
                    "--verbose",
                    f"--protocol={proto_flag}",
                    "--passwd-on-stdin",
                    "--useragent=PAN GlobalProtect",
                    "--usergroup=portal:prelogin-cookie",
                    "--os=linux-64",
                    gateway,
                ]
                # Add username if available (required for GlobalProtect)
                if username:
                    cmd.insert(5, f"--user={username}")
                self.vpn_process = subprocess.Popen(
                    cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT
                )
                self.vpn_process.stdin.write(f"{cookie_str}\n".encode())
                self.vpn_process.stdin.flush()
            else:
                cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
                log.debug(f"Using AnyConnect cookie (len={len(cookie_str)})")
                # Log first/last parts of cookie for debugging (without revealing sensitive parts)
                if len(cookie_str) > 40:
                    log.debug(f"Cookie preview: {cookie_str[:20]}...{cookie_str[-20:]}")
                cmd = [
                    "openconnect",
                    "--verbose",
                    f"--protocol={proto_flag}",
                    f"--cookie={cookie_str}",
                    gateway,
                ]
                log.debug(f"OpenConnect command: {' '.join(cmd[:4])} [cookie] {gateway}")
                # Also log the full command to a debug file for comparison
                try:
                    with open('/tmp/nm-vpn-debug-cmd.txt', 'w') as f:
                        f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write(f"Command: {cmd}\n")
                        f.write(f"Cookie string length: {len(cookie_str)}\n")
                        f.write(f"Cookie keys: {list(cookies.keys())}\n")
                        f.write(f"Cookie string: {cookie_str}\n")  # Full cookie for debugging
                        f.write(f"\nManual test command:\n")
                        f.write(f"sudo openconnect --verbose --protocol={proto_flag} --cookie='{cookie_str}' {gateway}\n")
                except:
                    pass
                self.vpn_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT
                )

            log.info(f"OpenConnect started (PID {self.vpn_process.pid})")

            # Initialize DNS server list
            self.vpn_dns_servers = []
            self.vpn_domains = []

            # Monitor for interface up and parse output for DNS
            # Wait for tun interface to come up
            timeout = 30
            start_time = time.time()
            connected = False
            output_buffer = ""

            # Set stdout to non-blocking so we can read while checking interface
            import fcntl
            import os as os_module
            fd = self.vpn_process.stdout.fileno()
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os_module.O_NONBLOCK)

            while time.time() - start_time < timeout:
                if self.vpn_process.poll() is not None:
                    # Process exited - read remaining output
                    try:
                        remaining = self.vpn_process.stdout.read()
                        if remaining:
                            output_buffer += remaining.decode('utf-8', errors='replace')
                    except:
                        pass
                    exit_code = self.vpn_process.returncode
                    log.error(f"OpenConnect exited prematurely with code {exit_code}")
                    log.error(f"OpenConnect output:\n{output_buffer}")
                    raise Exception(f"OpenConnect exited (code {exit_code}): {output_buffer[-500:]}")

                # Try to read any available output (non-blocking)
                try:
                    chunk = self.vpn_process.stdout.read(4096)
                    if chunk:
                        text = chunk.decode('utf-8', errors='replace')
                        output_buffer += text
                        # Parse for DNS servers (OpenConnect outputs: "Received DNS server X.X.X.X")
                        for line in text.split('\n'):
                            if 'DNS' in line.upper():
                                log.info(f"OpenConnect DNS info: {line.strip()}")
                                # Try to extract IP from various formats
                                import re
                                ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
                                for ip in ips:
                                    if ip not in self.vpn_dns_servers:
                                        self.vpn_dns_servers.append(ip)
                                        log.info(f"Captured VPN DNS: {ip}")
                            # Also capture search domains
                            if 'domain' in line.lower() or 'search' in line.lower():
                                log.info(f"OpenConnect domain info: {line.strip()}")
                except (BlockingIOError, IOError):
                    pass  # No data available yet

                # Check for tun interface
                result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
                if 'tun' in result.stdout:
                    # Find the tun device name
                    for line in result.stdout.split('\n'):
                        if 'tun' in line and ':' in line:
                            # Extract device name (format: "X: tunY: <FLAGS>...")
                            parts = line.split(':')
                            if len(parts) >= 2:
                                self.current_tun_device = parts[1].strip()
                                log.info(f"Found tun device: {self.current_tun_device}")
                                break
                    connected = True
                    break

                time.sleep(0.5)

            if not connected:
                # Check if it's a cookie rejection
                if 'cookie' in output_buffer.lower() and ('reject' in output_buffer.lower() or 'invalid' in output_buffer.lower() or 'fail' in output_buffer.lower()):
                    return (False, "Cookie rejected by server")
                return (False, "VPN connection timeout")

            # Give vpnc-script a moment to configure DNS
            time.sleep(1)

            log.info(f"VPN DNS servers captured: {self.vpn_dns_servers}")

            # Emit full IP config now that interface is up
            GLib.idle_add(self._emit_connected)

            # Wait for process to exit
            self.vpn_process.wait()

            # Connection ended
            GLib.idle_add(self._emit_disconnected)

            return (True, None)

        except Exception as e:
            error_msg = str(e)
            log.info(f"Attempt error: {error_msg}")
            # Check if it's a cookie rejection error
            if 'cookie' in error_msg.lower() and ('reject' in error_msg.lower() or 'invalid' in error_msg.lower()):
                return (False, "Cookie rejected by server")
            return (False, error_msg)

    def _emit_initial_config(self):
        """Emit initial Config signal before interface is created (called from main thread).

        Note: We DON'T include tundev here because NetworkManager will try to look it up
        immediately and fail if it doesn't exist yet.
        """
        import struct

        try:
            if self.current_protocol == 'gp':
                allow_early = os.environ.get("MS_SSO_NM_GP_EARLY_CONFIG", "").lower() in {"1", "true", "yes"}
                if not allow_early:
                    delay_env = os.environ.get("MS_SSO_NM_GP_CONFIG_DELAY", "").strip()
                    try:
                        delay_seconds = int(delay_env) if delay_env else 45
                    except Exception:
                        delay_seconds = 45
                    if getattr(self, "auth_in_progress", False) and getattr(self, "saml_start_time", None):
                        elapsed = time.monotonic() - self.saml_start_time
                        if elapsed < delay_seconds:
                            log.info(
                                "Skipping initial Config for GP to keep UI in connecting state "
                                f"(elapsed {elapsed:.0f}s < {delay_seconds}s)"
                            )
                            return False

            gateway = self.current_gateway or ''

            log.info(f"Emitting initial config (no tundev), gateway {gateway}")

            # Use pre-resolved gateway IP (resolved before VPN connected, when external DNS was available)
            gateway_ip = getattr(self, 'current_gateway_ip', None)
            if gateway_ip:
                log.info(f"Using pre-resolved gateway IP: {gateway_ip}")
            else:
                log.warning(f"No pre-resolved gateway IP available, gateway uint will be 0")

            # Convert gateway IP to uint32 (network byte order)
            gateway_uint = 0
            if gateway_ip:
                try:
                    gw_parts = [int(x) for x in gateway_ip.split('.')]
                    if len(gw_parts) == 4:
                        gateway_uint = struct.unpack('!I', bytes(gw_parts))[0]
                        log.info(f"Gateway uint32: {gateway_uint} (0x{gateway_uint:08x})")
                except Exception as e:
                    log.info(f"Warning: Could not convert gateway IP '{gateway_ip}': {e}")

            # Emit Config signal WITHOUT tundev - just gateway info
            # tundev will be set in the full Config after interface is up
            # During GlobalProtect SAML auth, avoid telling NM we already have IPv4
            # config; otherwise it may time out waiting for Ip4Config.
            has_ip4 = self.current_protocol != 'gp'
            config = dbus.Dictionary({
                'gateway': dbus.UInt32(gateway_uint),
                'has-ip4': dbus.Boolean(has_ip4),
                'has-ip6': dbus.Boolean(False),
            }, signature='sv')
            self.Config(config)
            log.info(f"Emitted initial Config signal (gateway only)")

        except Exception as e:
            log.info(f"Error emitting initial config: {e}")
            import traceback
            traceback.print_exc()

        return False

    def _emit_starting_keepalive(self):
        """Emit a keepalive STARTING state to reduce NM connect timeouts."""
        try:
            # Intentionally emit even if our internal state didn't change.
            self.StateChanged(NM_VPN_SERVICE_STATE_STARTING)
        except Exception:
            pass
        return False

    def _emit_started_for_auth(self):
        """Enter STARTED while authentication is still in progress.

        NetworkManager may cancel VPN connections that stay in STARTING too long.
        This is common for GlobalProtect SAML flows with MFA. We later emit the
        full Config/Ip4Config once the tunnel device exists.
        """
        try:
            self._set_state(NM_VPN_SERVICE_STATE_STARTED)
        except Exception:
            pass
        return False

    def _emit_started_keepalive(self):
        """Emit a keepalive STARTED state."""
        try:
            # Intentionally emit even if our internal state didn't change.
            self.StateChanged(NM_VPN_SERVICE_STATE_STARTED)
        except Exception:
            pass
        return False

    def _emit_connected(self):
        """Emit IP config after interface is up (called from main thread)."""
        import struct

        try:
            # Get IP configuration from tun device
            tun_dev = self.current_tun_device or 'tun0'
            gateway = self.current_gateway or ''

            log.info(f"Emitting config for {tun_dev}, gateway {gateway}")

            # Get IP address from interface
            result = subprocess.run(['ip', '-4', 'addr', 'show', tun_dev], capture_output=True, text=True)
            ip_addr = None
            prefix = 32
            for line in result.stdout.split('\n'):
                if 'inet ' in line:
                    # Format: "inet 10.x.x.x/24 ..."
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        addr_prefix = parts[1]
                        if '/' in addr_prefix:
                            ip_addr, prefix_str = addr_prefix.split('/')
                            prefix = int(prefix_str)
                        else:
                            ip_addr = addr_prefix
                        break

            log.info(f"Detected IP: {ip_addr}/{prefix}")

            # Use pre-resolved gateway IP (resolved before VPN connected, when external DNS was available)
            gateway_ip = getattr(self, 'current_gateway_ip', None)
            if gateway_ip:
                log.info(f"Using pre-resolved gateway IP: {gateway_ip}")
            else:
                log.warning(f"No pre-resolved gateway IP available, gateway uint will be 0")

            # Convert gateway IP to uint32 (network byte order)
            gateway_uint = 0
            if gateway_ip:
                try:
                    gw_parts = [int(x) for x in gateway_ip.split('.')]
                    if len(gw_parts) == 4:
                        gateway_uint = struct.unpack('!I', bytes(gw_parts))[0]
                        log.info(f"Gateway uint32: {gateway_uint} (0x{gateway_uint:08x})")
                except Exception as e:
                    log.info(f"Warning: Could not convert gateway IP '{gateway_ip}': {e}")

            if gateway_uint == 0:
                log.info(f"ERROR: Gateway is 0, NetworkManager will reject this!")

            # Emit Config signal with tunnel device info
            # gateway must be uint32 (network byte order)
            config = dbus.Dictionary({
                'tundev': dbus.String(tun_dev),
                'gateway': dbus.UInt32(gateway_uint),
                'has-ip4': dbus.Boolean(True),
                'has-ip6': dbus.Boolean(False),
            }, signature='sv')
            self.Config(config)
            log.info(f"Emitted Config signal")

            # Emit Ip4Config signal with proper format
            # NetworkManager expects 'addresses' as array of arrays: [[addr, prefix, gateway], ...]
            if ip_addr:
                # Convert IP to uint32 (network byte order)
                ip_parts = [int(x) for x in ip_addr.split('.')]
                ip_uint = struct.unpack('!I', bytes(ip_parts))[0]

                # Get DNS servers - try multiple methods
                dns_servers = []

                # Method 1: Try resolvectl for systemd-resolved systems
                try:
                    result = subprocess.run(
                        ['resolvectl', 'dns', tun_dev],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        # Parse output like "Link 123 (tun0): 10.0.0.1 10.0.0.2"
                        for line in result.stdout.split('\n'):
                            if tun_dev in line:
                                parts = line.split(':')
                                if len(parts) >= 2:
                                    dns_part = parts[1].strip()
                                    for ns in dns_part.split():
                                        try:
                                            ns_parts = [int(x) for x in ns.split('.')]
                                            if len(ns_parts) == 4:
                                                # Convert IP to uint32 in host byte order (little-endian on x86)
                                                # IP a.b.c.d becomes: a + b*256 + c*65536 + d*16777216
                                                ns_uint = ns_parts[0] | (ns_parts[1] << 8) | (ns_parts[2] << 16) | (ns_parts[3] << 24)
                                                dns_servers.append(dbus.UInt32(ns_uint))
                                                log.info(f"Found DNS from resolvectl: {ns} -> {ns_uint}")
                                        except:
                                            pass
                except Exception as e:
                    log.info(f"resolvectl failed: {e}")

                # Method 2: If no DNS yet, check stored DNS from OpenConnect output
                if not dns_servers and hasattr(self, 'vpn_dns_servers') and self.vpn_dns_servers:
                    for ns in self.vpn_dns_servers:
                        try:
                            ns_parts = [int(x) for x in ns.split('.')]
                            if len(ns_parts) == 4:
                                # Convert IP to uint32 in host byte order (little-endian on x86)
                                ns_uint = ns_parts[0] | (ns_parts[1] << 8) | (ns_parts[2] << 16) | (ns_parts[3] << 24)
                                dns_servers.append(dbus.UInt32(ns_uint))
                                log.info(f"Using stored VPN DNS: {ns} -> {ns_uint}")
                        except:
                            pass

                # Method 3: Fall back to resolv.conf
                if not dns_servers:
                    try:
                        result = subprocess.run(['cat', '/etc/resolv.conf'], capture_output=True, text=True)
                        for line in result.stdout.split('\n'):
                            if line.startswith('nameserver '):
                                ns = line.split()[1]
                                try:
                                    ns_parts = [int(x) for x in ns.split('.')]
                                    if len(ns_parts) == 4:
                                        # Convert IP to uint32 in host byte order (little-endian on x86)
                                        ns_uint = ns_parts[0] | (ns_parts[1] << 8) | (ns_parts[2] << 16) | (ns_parts[3] << 24)
                                        dns_servers.append(dbus.UInt32(ns_uint))
                                        log.info(f"Found DNS from resolv.conf: {ns} -> {ns_uint}")
                                except:
                                    pass  # Skip non-IPv4 nameservers
                    except:
                        pass

                log.info(f"Total DNS servers found: {len(dns_servers)}")

                # Build addresses array: each address is [addr, prefix, gateway]
                # For point-to-point VPN, gateway in address is typically 0
                addr_array = dbus.Array([
                    dbus.Array([dbus.UInt32(ip_uint), dbus.UInt32(prefix), dbus.UInt32(0)], signature='u')
                ], signature='au')

                # Build routes array: empty since OpenConnect handles routes via vpnc-script
                routes_array = dbus.Array([], signature='au')

                ip4_config = dbus.Dictionary({
                    'addresses': addr_array,
                    'routes': routes_array,
                    'dns': dbus.Array(dns_servers[:3], signature='u') if dns_servers else dbus.Array([], signature='u'),
                    'domains': dbus.Array([], signature='s'),
                }, signature='sv')
                self.Ip4Config(ip4_config)
                log.info(f"Emitted Ip4Config signal: addr={ip_addr}/{prefix}, dns={len(dns_servers)} servers")

            # Now set state to started
            self._set_state(NM_VPN_SERVICE_STATE_STARTED)
        except Exception as e:
            log.info(f"Error emitting config: {e}")
            import traceback
            traceback.print_exc()
            self._set_state(NM_VPN_SERVICE_STATE_STARTED)

        return False

    def _emit_disconnected(self):
        """Emit disconnected state (called from main thread)."""
        self._set_state(NM_VPN_SERVICE_STATE_STOPPED)
        return False

    def _emit_failure(self, message):
        """Emit failure (called from main thread)."""
        self.Failure(NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED)
        self._set_state(NM_VPN_SERVICE_STATE_STOPPED)
        return False

    # D-Bus methods
    @dbus.service.method(NM_VPN_DBUS_PLUGIN_INTERFACE,
                         in_signature='a{sa{sv}}', out_signature='')
    def Connect(self, connection):
        """Start VPN connection."""
        log.info("Connect called")
        self._reset_inactivity_timeout()

        self._set_state(NM_VPN_SERVICE_STATE_STARTING)

        # Convert D-Bus types to Python
        settings = {str(k): {str(k2): v2 for k2, v2 in v.items()} for k, v in connection.items()}

        # Start connection in background thread
        self.connection_thread = threading.Thread(target=self._connect_thread, args=(settings,))
        self.connection_thread.daemon = True
        self.connection_thread.start()

    @dbus.service.method(NM_VPN_DBUS_PLUGIN_INTERFACE,
                         in_signature='a{sa{sv}}a{sv}', out_signature='')
    def ConnectInteractive(self, connection, details):
        """Start interactive VPN connection."""
        log.info("ConnectInteractive called")
        self.Connect(connection)

    @dbus.service.method(NM_VPN_DBUS_PLUGIN_INTERFACE,
                         in_signature='', out_signature='')
    def Disconnect(self):
        """Disconnect VPN."""
        log.info("Disconnect called")
        self._reset_inactivity_timeout()
        self.cancel_requested = True

        self._set_state(NM_VPN_SERVICE_STATE_STOPPING)

        # Kill openconnect process with SIGKILL to preserve session cookie
        # SIGTERM causes OpenConnect to send a logout message which invalidates the cookie
        if self.vpn_process and self.vpn_process.poll() is None:
            log.info("Killing openconnect with SIGKILL to preserve session cookie")
            self.vpn_process.kill()  # SIGKILL - no graceful logout
            try:
                self.vpn_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass  # Already sent SIGKILL, nothing more we can do

        # Also kill any other openconnect processes with SIGKILL
        subprocess.run(['pkill', '-KILL', '-x', 'openconnect'], capture_output=True)

        self._set_state(NM_VPN_SERVICE_STATE_STOPPED)

    @dbus.service.method(NM_VPN_DBUS_PLUGIN_INTERFACE,
                         in_signature='a{sa{sv}}', out_signature='s')
    def NeedSecrets(self, settings):
        """Check if secrets are needed."""
        log.info("NeedSecrets called")
        self._reset_inactivity_timeout()

        # Check if we have secrets
        vpn_settings = settings.get('vpn', {})
        vpn_secrets = vpn_settings.get('secrets', {})

        if not vpn_secrets.get('password'):
            return 'vpn'

        return ''

    @dbus.service.method(NM_VPN_DBUS_PLUGIN_INTERFACE,
                         in_signature='a{sa{sv}}', out_signature='')
    def NewSecrets(self, connection):
        """New secrets provided."""
        log.info("NewSecrets called")
        self._reset_inactivity_timeout()

    @dbus.service.method(NM_VPN_DBUS_PLUGIN_INTERFACE,
                         in_signature='a{sv}', out_signature='')
    def SetConfig(self, config):
        """Set VPN configuration."""
        log.info("SetConfig called")

    @dbus.service.method(NM_VPN_DBUS_PLUGIN_INTERFACE,
                         in_signature='a{sv}', out_signature='')
    def SetIp4Config(self, config):
        """Set IPv4 configuration."""
        log.info("SetIp4Config called")

    @dbus.service.method(NM_VPN_DBUS_PLUGIN_INTERFACE,
                         in_signature='a{sv}', out_signature='')
    def SetIp6Config(self, config):
        """Set IPv6 configuration."""
        log.info("SetIp6Config called")

    @dbus.service.method(NM_VPN_DBUS_PLUGIN_INTERFACE,
                         in_signature='s', out_signature='')
    def SetFailure(self, reason):
        """Set failure reason."""
        log.info(f"SetFailure called: {reason}")

    # D-Bus signals
    @dbus.service.signal(NM_VPN_DBUS_PLUGIN_INTERFACE, signature='u')
    def StateChanged(self, state):
        """Emit state change signal."""
        log.info(f"State changed to {state}")

    @dbus.service.signal(NM_VPN_DBUS_PLUGIN_INTERFACE, signature='a{sv}')
    def Config(self, config):
        """Emit configuration signal."""
        pass

    @dbus.service.signal(NM_VPN_DBUS_PLUGIN_INTERFACE, signature='a{sv}')
    def Ip4Config(self, config):
        """Emit IPv4 configuration signal."""
        pass

    @dbus.service.signal(NM_VPN_DBUS_PLUGIN_INTERFACE, signature='a{sv}')
    def Ip6Config(self, config):
        """Emit IPv6 configuration signal."""
        pass

    @dbus.service.signal(NM_VPN_DBUS_PLUGIN_INTERFACE, signature='u')
    def Failure(self, reason):
        """Emit failure signal."""
        log.info(f"Failure: {reason}")

    @dbus.service.signal(NM_VPN_DBUS_PLUGIN_INTERFACE, signature='s')
    def SecretsRequired(self, message):
        """Emit secrets required signal."""
        pass

    # D-Bus Properties interface implementation
    @dbus.service.method(dbus.PROPERTIES_IFACE, in_signature='ss', out_signature='v')
    def Get(self, interface, prop):
        """Get a property value."""
        if interface == NM_VPN_DBUS_PLUGIN_INTERFACE:
            if prop == 'State':
                return dbus.UInt32(self.state)
        raise dbus.exceptions.DBusException(
            f"org.freedesktop.DBus.Error.UnknownProperty: Property '{prop}' not found")

    @dbus.service.method(dbus.PROPERTIES_IFACE, in_signature='s', out_signature='a{sv}')
    def GetAll(self, interface):
        """Get all properties."""
        if interface == NM_VPN_DBUS_PLUGIN_INTERFACE:
            return {'State': dbus.UInt32(self.state)}
        return {}

    @dbus.service.method(dbus.PROPERTIES_IFACE, in_signature='ssv', out_signature='')
    def Set(self, interface, prop, value):
        """Set a property value."""
        # All properties are read-only
        raise dbus.exceptions.DBusException(
            f"org.freedesktop.DBus.Error.PropertyReadOnly: Property '{prop}' is read-only")

    def run(self, mainloop):
        """Run the service main loop."""
        self.mainloop = mainloop
        # Plugin starts in INIT state (already set in __init__)
        # NetworkManager will call Connect() or NeedSecrets() when ready
        mainloop.run()


def main():
    """Main entry point."""
    log.info("Starting VPN plugin service")

    # Set up D-Bus main loop
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

    # Get system bus
    try:
        bus = dbus.SystemBus()
    except dbus.exceptions.DBusException as e:
        log.info(f"Failed to connect to system bus: {e}")
        sys.exit(1)

    # Create and run service
    service = VPNPluginService(bus)

    # Set up signal handlers
    mainloop = GLib.MainLoop()

    def signal_handler(signum, frame):
        log.info(f"Received signal {signum}, shutting down")
        service.Disconnect()
        mainloop.quit()

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    try:
        service.run(mainloop)
    except KeyboardInterrupt:
        pass

    log.info("Service stopped")


if __name__ == '__main__':
    main()
