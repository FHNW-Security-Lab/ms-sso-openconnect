#!/usr/bin/env python3
"""
NetworkManager VPN Plugin Service for MS SSO OpenConnect

This service implements the org.freedesktop.NetworkManager.VPN.Plugin
D-Bus interface to handle VPN connections via NetworkManager.

It reuses the existing ms-sso-openconnect.py module for:
- SAML authentication via headless browser
- OpenConnect VPN connection
- Keyring credential storage
- TOTP generation
"""

import os
import sys
import signal
import subprocess
import json
import importlib.util
import threading
import time

import gi
gi.require_version('NM', '1.0')
from gi.repository import GLib, NM

import dbus
import dbus.service
import dbus.mainloop.glib

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


def find_vpn_core_module():
    """Find and load the ms-sso-openconnect.py module."""
    search_paths = [
        # Development: relative to this script
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "ms-sso-openconnect.py"),
        # System install locations
        "/usr/share/ms-sso-openconnect/ms-sso-openconnect.py",
        "/usr/lib/ms-sso-openconnect/ms-sso-openconnect.py",
        "/opt/ms-sso-vpn/ms-sso-openconnect.py",
    ]

    for path in search_paths:
        if os.path.exists(path):
            return path
    return None


def load_vpn_core():
    """Load the VPN core module dynamically."""
    module_path = find_vpn_core_module()
    if not module_path:
        raise RuntimeError("Cannot find ms-sso-openconnect.py module")

    spec = importlib.util.spec_from_file_location("vpn_core", module_path)
    vpn_core = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vpn_core)
    return vpn_core


class VPNPluginService(dbus.service.Object):
    """NetworkManager VPN Plugin D-Bus Service."""

    def __init__(self, bus):
        self.bus = bus
        self.state = NM_VPN_SERVICE_STATE_INIT
        self.vpn_process = None
        self.connection_thread = None
        self.vpn_core = None
        self.mainloop = None
        self.inactivity_timeout = None
        # Store connection info for config emission
        self.current_gateway = None
        self.current_tun_device = None

        # Register on D-Bus
        bus_name = dbus.service.BusName(NM_DBUS_SERVICE, bus=bus)
        dbus.service.Object.__init__(self, bus_name, NM_VPN_DBUS_PLUGIN_PATH)

        # Load VPN core module
        try:
            self.vpn_core = load_vpn_core()
            print(f"[nm-ms-sso] Loaded VPN core module")
        except Exception as e:
            print(f"[nm-ms-sso] Error loading VPN core: {e}")

        # Set initial state
        self._set_state(NM_VPN_SERVICE_STATE_INIT)

        # Start inactivity timeout (quit after 2 minutes of inactivity)
        self._reset_inactivity_timeout()

    def _reset_inactivity_timeout(self):
        """Reset the inactivity timeout."""
        if self.inactivity_timeout:
            GLib.source_remove(self.inactivity_timeout)
        self.inactivity_timeout = GLib.timeout_add_seconds(120, self._on_inactivity_timeout)

    def _on_inactivity_timeout(self):
        """Called when the service has been inactive for too long."""
        if self.state in (NM_VPN_SERVICE_STATE_INIT, NM_VPN_SERVICE_STATE_STOPPED):
            print("[nm-ms-sso] Inactivity timeout, shutting down")
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
        print(f"[nm-ms-sso] Full settings keys: {list(settings.keys())}")

        # Get VPN settings
        vpn_settings = settings.get('vpn', {})
        vpn_data = vpn_settings.get('data', {})
        vpn_secrets = vpn_settings.get('secrets', {})

        print(f"[nm-ms-sso] VPN settings keys: {list(vpn_settings.keys())}")
        print(f"[nm-ms-sso] VPN data: {vpn_data}")
        print(f"[nm-ms-sso] VPN secrets keys: {list(vpn_secrets.keys())}")

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
            print(f"[nm-ms-sso] Secrets not in connection, trying keyring...")
            conn_uuid = settings.get('connection', {}).get('uuid', '')
            print(f"[nm-ms-sso] Connection UUID for keyring: {conn_uuid}")
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
                            print(f"[nm-ms-sso] Found password in keyring")
                        else:
                            print(f"[nm-ms-sso] Password not found in keyring")

                    if not secrets['totp_secret']:
                        totp = Secret.password_lookup_sync(
                            schema, {"connection-id": conn_uuid, "secret-type": "totp-secret"}, None
                        )
                        if totp:
                            secrets['totp_secret'] = totp
                            print(f"[nm-ms-sso] Found TOTP secret in keyring")
                        else:
                            print(f"[nm-ms-sso] TOTP secret not found in keyring")

                except Exception as ke:
                    print(f"[nm-ms-sso] Keyring error: {ke}")
                    import traceback
                    traceback.print_exc()

        return secrets

    def _connect_thread(self, settings):
        """Worker thread for VPN connection."""
        try:
            self._reset_inactivity_timeout()

            # Check if VPN core module is loaded
            if not self.vpn_core:
                raise Exception("VPN core module not loaded. Check if ms-sso-openconnect.py is installed.")

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

            print(f"[nm-ms-sso] Connecting to {gateway} via {protocol}")
            print(f"[nm-ms-sso] Username: {username}")
            print(f"[nm-ms-sso] Password: {'(set)' if password else '(not set)'}")
            print(f"[nm-ms-sso] TOTP: {'(set)' if totp_secret else '(not set)'}")

            # Store gateway for config emission
            self.current_gateway = gateway

            # Connection name for cookie cache
            connection_name = f"nm-{gateway}"

            # Try connection with retry on cookie rejection
            max_attempts = 2
            for attempt in range(max_attempts):
                # Try cached cookies first (only on first attempt)
                cookies = None
                used_cache = False

                if attempt == 0:
                    cached = self.vpn_core.get_stored_cookies(connection_name, max_age_hours=12)
                    if cached:
                        cookies, _ = cached[0], cached[1] if len(cached) > 1 else None
                        used_cache = True
                        print(f"[nm-ms-sso] Trying cached cookies...")

                # If no cached cookies or this is a retry, authenticate
                if not cookies:
                    print(f"[nm-ms-sso] Performing SAML authentication...")
                    cookies = self.vpn_core.do_saml_auth(
                        vpn_server=gateway,
                        username=username,
                        password=password,
                        totp_secret_or_code=totp_secret,
                        auto_totp=True,
                        headless=True,
                        debug=False
                    )

                    if not cookies:
                        raise Exception("SAML authentication failed")

                    # Store fresh cookies
                    self.vpn_core.store_cookies(connection_name, cookies, usergroup='portal:prelogin-cookie')
                    print(f"[nm-ms-sso] Cookies stored for future connections")

                # Try to connect with these cookies
                success, error_msg = self._attempt_vpn_connection(gateway, protocol, cookies)

                if success:
                    break  # Connection successful
                elif used_cache and attempt < max_attempts - 1:
                    # Cookie was rejected, clear cache and retry with fresh auth
                    print(f"[nm-ms-sso] Cookie rejected, clearing cache and re-authenticating...")
                    self.vpn_core.clear_stored_cookies(connection_name)
                    continue
                else:
                    raise Exception(error_msg or "VPN connection failed")

        except Exception as e:
            error_msg = str(e)
            print(f"[nm-ms-sso] Connection error: {error_msg}")
            import traceback
            traceback.print_exc()
            GLib.idle_add(lambda msg=error_msg: self._emit_failure(msg))

    def _attempt_vpn_connection(self, gateway, protocol, cookies):
        """Attempt to establish VPN connection with given cookies.

        Returns:
            Tuple of (success: bool, error_message: str or None)
        """
        try:

            # Connect to VPN
            # We use subprocess so we can monitor and return control
            proto_flag = self.vpn_core.PROTOCOLS.get(protocol, {}).get('flag', 'anyconnect')

            if protocol == 'gp' and 'prelogin-cookie' in cookies:
                cookie_str = cookies.get('prelogin-cookie', '')
                cmd = [
                    "openconnect",
                    "--verbose",
                    f"--protocol={proto_flag}",
                    "--passwd-on-stdin",
                    "--usergroup=portal:prelogin-cookie",
                    "--os=linux-64",
                    gateway,
                ]
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
                cmd = [
                    "openconnect",
                    "--verbose",
                    f"--protocol={proto_flag}",
                    f"--cookie={cookie_str}",
                    gateway,
                ]
                self.vpn_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT
                )

            print(f"[nm-ms-sso] OpenConnect started (PID {self.vpn_process.pid})")

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
                    raise Exception(f"OpenConnect exited: {output_buffer[-500:]}")

                # Try to read any available output (non-blocking)
                try:
                    chunk = self.vpn_process.stdout.read(4096)
                    if chunk:
                        text = chunk.decode('utf-8', errors='replace')
                        output_buffer += text
                        # Parse for DNS servers (OpenConnect outputs: "Received DNS server X.X.X.X")
                        for line in text.split('\n'):
                            if 'DNS' in line.upper():
                                print(f"[nm-ms-sso] OpenConnect DNS info: {line.strip()}")
                                # Try to extract IP from various formats
                                import re
                                ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
                                for ip in ips:
                                    if ip not in self.vpn_dns_servers:
                                        self.vpn_dns_servers.append(ip)
                                        print(f"[nm-ms-sso] Captured VPN DNS: {ip}")
                            # Also capture search domains
                            if 'domain' in line.lower() or 'search' in line.lower():
                                print(f"[nm-ms-sso] OpenConnect domain info: {line.strip()}")
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
                                print(f"[nm-ms-sso] Found tun device: {self.current_tun_device}")
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

            print(f"[nm-ms-sso] VPN DNS servers captured: {self.vpn_dns_servers}")

            # Emit full IP config now that interface is up
            GLib.idle_add(self._emit_connected)

            # Wait for process to exit
            self.vpn_process.wait()

            # Connection ended
            GLib.idle_add(self._emit_disconnected)

            return (True, None)

        except Exception as e:
            error_msg = str(e)
            print(f"[nm-ms-sso] Attempt error: {error_msg}")
            # Check if it's a cookie rejection error
            if 'cookie' in error_msg.lower() and ('reject' in error_msg.lower() or 'invalid' in error_msg.lower()):
                return (False, "Cookie rejected by server")
            return (False, error_msg)

    def _emit_initial_config(self):
        """Emit initial Config signal before interface is created (called from main thread).

        Note: We DON'T include tundev here because NetworkManager will try to look it up
        immediately and fail if it doesn't exist yet.
        """
        import socket
        import struct

        try:
            gateway = self.current_gateway or ''

            print(f"[nm-ms-sso] Emitting initial config (no tundev), gateway {gateway}")

            # Resolve gateway hostname to IP address
            gateway_ip = None
            try:
                gateway_ip = socket.gethostbyname(gateway)
                print(f"[nm-ms-sso] Resolved gateway {gateway} -> {gateway_ip}")
            except Exception as e:
                print(f"[nm-ms-sso] Failed to resolve gateway {gateway}: {e}")
                if gateway and gateway[0].isdigit():
                    gateway_ip = gateway

            # Convert gateway IP to uint32 (network byte order)
            gateway_uint = 0
            if gateway_ip:
                try:
                    gw_parts = [int(x) for x in gateway_ip.split('.')]
                    if len(gw_parts) == 4:
                        gateway_uint = struct.unpack('!I', bytes(gw_parts))[0]
                        print(f"[nm-ms-sso] Gateway uint32: {gateway_uint} (0x{gateway_uint:08x})")
                except Exception as e:
                    print(f"[nm-ms-sso] Warning: Could not convert gateway IP '{gateway_ip}': {e}")

            # Emit Config signal WITHOUT tundev - just gateway info
            # tundev will be set in the full Config after interface is up
            config = dbus.Dictionary({
                'gateway': dbus.UInt32(gateway_uint),
                'has-ip4': dbus.Boolean(True),
                'has-ip6': dbus.Boolean(False),
            }, signature='sv')
            self.Config(config)
            print(f"[nm-ms-sso] Emitted initial Config signal (gateway only)")

        except Exception as e:
            print(f"[nm-ms-sso] Error emitting initial config: {e}")
            import traceback
            traceback.print_exc()

        return False

    def _emit_connected(self):
        """Emit IP config after interface is up (called from main thread)."""
        import socket
        import struct

        try:
            # Get IP configuration from tun device
            tun_dev = self.current_tun_device or 'tun0'
            gateway = self.current_gateway or ''

            print(f"[nm-ms-sso] Emitting config for {tun_dev}, gateway {gateway}")

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

            print(f"[nm-ms-sso] Detected IP: {ip_addr}/{prefix}")

            # Resolve gateway hostname to IP address
            gateway_ip = None
            try:
                gateway_ip = socket.gethostbyname(gateway)
                print(f"[nm-ms-sso] Resolved gateway {gateway} -> {gateway_ip}")
            except Exception as e:
                print(f"[nm-ms-sso] Failed to resolve gateway {gateway}: {e}")
                # Try to use gateway as-is if it looks like an IP
                if gateway and gateway[0].isdigit():
                    gateway_ip = gateway

            # Convert gateway IP to uint32 (network byte order)
            gateway_uint = 0
            if gateway_ip:
                try:
                    gw_parts = [int(x) for x in gateway_ip.split('.')]
                    if len(gw_parts) == 4:
                        gateway_uint = struct.unpack('!I', bytes(gw_parts))[0]
                        print(f"[nm-ms-sso] Gateway uint32: {gateway_uint} (0x{gateway_uint:08x})")
                except Exception as e:
                    print(f"[nm-ms-sso] Warning: Could not convert gateway IP '{gateway_ip}': {e}")

            if gateway_uint == 0:
                print(f"[nm-ms-sso] ERROR: Gateway is 0, NetworkManager will reject this!")

            # Emit Config signal with tunnel device info
            # gateway must be uint32 (network byte order)
            config = dbus.Dictionary({
                'tundev': dbus.String(tun_dev),
                'gateway': dbus.UInt32(gateway_uint),
                'has-ip4': dbus.Boolean(True),
                'has-ip6': dbus.Boolean(False),
            }, signature='sv')
            self.Config(config)
            print(f"[nm-ms-sso] Emitted Config signal")

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
                                                print(f"[nm-ms-sso] Found DNS from resolvectl: {ns} -> {ns_uint}")
                                        except:
                                            pass
                except Exception as e:
                    print(f"[nm-ms-sso] resolvectl failed: {e}")

                # Method 2: If no DNS yet, check stored DNS from OpenConnect output
                if not dns_servers and hasattr(self, 'vpn_dns_servers') and self.vpn_dns_servers:
                    for ns in self.vpn_dns_servers:
                        try:
                            ns_parts = [int(x) for x in ns.split('.')]
                            if len(ns_parts) == 4:
                                # Convert IP to uint32 in host byte order (little-endian on x86)
                                ns_uint = ns_parts[0] | (ns_parts[1] << 8) | (ns_parts[2] << 16) | (ns_parts[3] << 24)
                                dns_servers.append(dbus.UInt32(ns_uint))
                                print(f"[nm-ms-sso] Using stored VPN DNS: {ns} -> {ns_uint}")
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
                                        print(f"[nm-ms-sso] Found DNS from resolv.conf: {ns} -> {ns_uint}")
                                except:
                                    pass  # Skip non-IPv4 nameservers
                    except:
                        pass

                print(f"[nm-ms-sso] Total DNS servers found: {len(dns_servers)}")

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
                print(f"[nm-ms-sso] Emitted Ip4Config signal: addr={ip_addr}/{prefix}, dns={len(dns_servers)} servers")

            # Now set state to started
            self._set_state(NM_VPN_SERVICE_STATE_STARTED)
        except Exception as e:
            print(f"[nm-ms-sso] Error emitting config: {e}")
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
        print("[nm-ms-sso] Connect called")
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
        print("[nm-ms-sso] ConnectInteractive called")
        self.Connect(connection)

    @dbus.service.method(NM_VPN_DBUS_PLUGIN_INTERFACE,
                         in_signature='', out_signature='')
    def Disconnect(self):
        """Disconnect VPN."""
        print("[nm-ms-sso] Disconnect called")
        self._reset_inactivity_timeout()

        self._set_state(NM_VPN_SERVICE_STATE_STOPPING)

        # Kill openconnect process
        if self.vpn_process and self.vpn_process.poll() is None:
            self.vpn_process.terminate()
            try:
                self.vpn_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.vpn_process.kill()

        # Also kill any other openconnect processes
        subprocess.run(['pkill', '-TERM', '-x', 'openconnect'], capture_output=True)

        self._set_state(NM_VPN_SERVICE_STATE_STOPPED)

    @dbus.service.method(NM_VPN_DBUS_PLUGIN_INTERFACE,
                         in_signature='a{sa{sv}}', out_signature='s')
    def NeedSecrets(self, settings):
        """Check if secrets are needed."""
        print("[nm-ms-sso] NeedSecrets called")
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
        print("[nm-ms-sso] NewSecrets called")
        self._reset_inactivity_timeout()

    @dbus.service.method(NM_VPN_DBUS_PLUGIN_INTERFACE,
                         in_signature='a{sv}', out_signature='')
    def SetConfig(self, config):
        """Set VPN configuration."""
        print("[nm-ms-sso] SetConfig called")

    @dbus.service.method(NM_VPN_DBUS_PLUGIN_INTERFACE,
                         in_signature='a{sv}', out_signature='')
    def SetIp4Config(self, config):
        """Set IPv4 configuration."""
        print("[nm-ms-sso] SetIp4Config called")

    @dbus.service.method(NM_VPN_DBUS_PLUGIN_INTERFACE,
                         in_signature='a{sv}', out_signature='')
    def SetIp6Config(self, config):
        """Set IPv6 configuration."""
        print("[nm-ms-sso] SetIp6Config called")

    @dbus.service.method(NM_VPN_DBUS_PLUGIN_INTERFACE,
                         in_signature='s', out_signature='')
    def SetFailure(self, reason):
        """Set failure reason."""
        print(f"[nm-ms-sso] SetFailure called: {reason}")

    # D-Bus signals
    @dbus.service.signal(NM_VPN_DBUS_PLUGIN_INTERFACE, signature='u')
    def StateChanged(self, state):
        """Emit state change signal."""
        print(f"[nm-ms-sso] State changed to {state}")

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
        print(f"[nm-ms-sso] Failure: {reason}")

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
    print("[nm-ms-sso] Starting VPN plugin service")

    # Set up D-Bus main loop
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

    # Get system bus
    try:
        bus = dbus.SystemBus()
    except dbus.exceptions.DBusException as e:
        print(f"[nm-ms-sso] Failed to connect to system bus: {e}")
        sys.exit(1)

    # Create and run service
    service = VPNPluginService(bus)

    # Set up signal handlers
    mainloop = GLib.MainLoop()

    def signal_handler(signum, frame):
        print(f"[nm-ms-sso] Received signal {signum}, shutting down")
        service.Disconnect()
        mainloop.quit()

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    try:
        service.run(mainloop)
    except KeyboardInterrupt:
        pass

    print("[nm-ms-sso] Service stopped")


if __name__ == '__main__':
    main()
