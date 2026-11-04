"""Session-owned macOS routes and DNS for the privileged VPN helper.

OpenConnect owns the tunnel and ordinary vpnc-script routes. This module owns
only its marked IPv6 reject routes and its unique dynamic-store DNS entry.
"""

import contextlib
import fcntl
import functools
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import tempfile
import time

import network_dns


STATE_DIR = Path("/var/run/ms-sso-openconnect/network")
SESSION_ENV = "MS_SSO_NETWORK_SESSION"
BASE_SCRIPTS = ("/opt/homebrew/etc/vpnc/vpnc-script",
                "/usr/local/etc/vpnc/vpnc-script", "/etc/vpnc/vpnc-script")
ROUTE = "/sbin/route"
GUARD_PREFIXES = ("::/1", "8000::/1")
GUARD_FLAGS = {"REJECT", "STATIC", "PROTO1", "PROTO2"}
FAILURE_MESSAGE = "VPN network protection could not be configured"


class NetworkPolicyError(RuntimeError):
    pass


def _public(function):
    @functools.wraps(function)
    def guarded(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except NetworkPolicyError:
            raise
        except (OSError, ValueError, TypeError, KeyError, network_dns.NetworkDNSError) as exc:
            raise NetworkPolicyError(FAILURE_MESSAGE) from exc
    return guarded


def _run(argv, **kwargs):
    try:
        return subprocess.run(argv, capture_output=True, text=True,
                              timeout=15, check=False, **kwargs)
    except (OSError, subprocess.SubprocessError) as exc:
        raise NetworkPolicyError(FAILURE_MESSAGE) from exc


def _require_root():
    if os.geteuid() != 0:
        raise NetworkPolicyError("VPN network configuration requires the installed helper")


def _token(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{32}", value):
        raise NetworkPolicyError("Invalid VPN network session")
    return value


def _state_directory():
    _require_root()
    STATE_DIR.mkdir(mode=0o700, parents=False, exist_ok=True)
    info = STATE_DIR.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise NetworkPolicyError("VPN network state directory is not private")


@contextlib.contextmanager
def _locked(token):
    _token(token)
    _state_directory()
    fd = os.open(STATE_DIR / (token + ".lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise NetworkPolicyError("VPN network lock is not private")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _load(token):
    try:
        fd = os.open(STATE_DIR / (token + ".json"), os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "r") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 262144):
            raise NetworkPolicyError("VPN network journal is not private")
        try:
            state = json.load(stream)
        except (ValueError, TypeError) as exc:
            raise NetworkPolicyError("VPN network journal is invalid") from exc
    if not isinstance(state, dict) or state.get("token") != token or state.get("schema") != 1:
        raise NetworkPolicyError("VPN network journal is invalid")
    return state


def _save(state):
    token = _token(state["token"])
    fd, name = tempfile.mkstemp(prefix=token + ".", suffix=".tmp", dir=STATE_DIR)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(state, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, STATE_DIR / (token + ".json"))
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def _process_info(pid):
    result = _run(["/bin/ps", "-p", str(pid), "-o", "uid=", "-o", "ppid=",
                   "-o", "lstart=", "-o", "comm="])
    if result.returncode:
        return None
    fields = result.stdout.strip().split(None, 7)
    if len(fields) != 8 or not fields[0].isdigit() or not fields[1].isdigit():
        raise NetworkPolicyError("Cannot verify VPN process ownership")
    return {"uid": int(fields[0]), "ppid": int(fields[1]),
            "identity": " ".join(fields[2:]), "command": fields[7]}


def _process_matches(pid, identity):
    info = _process_info(pid) if isinstance(pid, int) and pid > 1 else None
    return bool(info and info["uid"] == 0 and info["identity"] == identity)


def _vpn_process_matches(state):
    info = _process_info(state["vpn_pid"]) if state["vpn_pid"] else None
    return bool(info and info["uid"] == 0
                and info["identity"] == state["vpn_identity"]
                and Path(info["command"]).name == "openconnect")


@_public
def new_session():
    _state_directory()
    token = secrets.token_hex(16)
    owner = _process_info(os.getpid())
    if not owner:
        raise NetworkPolicyError("Cannot verify VPN helper ownership")
    with _locked(token):
        _save({"schema": 1, "token": token, "owner_pid": os.getpid(),
               "owner_identity": owner["identity"], "status": "pending",
               "vpn_pid": None, "vpn_identity": None, "routes": [],
               "dns": None, "env": {}})
    return token


def _bind(state, pid):
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
        raise NetworkPolicyError("Invalid VPN process")
    info = _process_info(pid)
    if not info or info["uid"] != 0 or Path(info["command"]).name != "openconnect":
        raise NetworkPolicyError("Cannot verify VPN process ownership")
    if state["vpn_pid"] is not None:
        if state["vpn_pid"] != pid or state["vpn_identity"] != info["identity"]:
            raise NetworkPolicyError("VPN network session belongs to another process")
        return
    if (info["ppid"] != state["owner_pid"]
            or not _process_matches(state["owner_pid"], state["owner_identity"])):
        raise NetworkPolicyError("VPN process is not owned by this helper")
    state["vpn_pid"], state["vpn_identity"] = pid, info["identity"]
    _save(state)


@_public
def bind_session(token, pid):
    with _locked(token):
        state = _load(token)
        if state is None:
            raise NetworkPolicyError("VPN network session is missing")
        _bind(state, pid)


def _integer(value, low, high):
    if not isinstance(value, str) or not value.isascii() or not value.isdigit():
        raise NetworkPolicyError("Invalid VPN network configuration")
    number = int(value)
    if not low <= number <= high:
        raise NetworkPolicyError("Invalid VPN network configuration")
    return number


def _validated_env(source):
    reason = source.get("reason")
    if reason not in {"pre-init", "connect", "disconnect", "attempt-reconnect", "reconnect"}:
        raise NetworkPolicyError("Invalid VPN network event")
    env = {"reason": reason, "VPNPID": str(_integer(source.get("VPNPID"), 2, 2**31 - 1))}
    tun = source.get("TUNDEV", "")
    if not re.fullmatch(r"utun[0-9]{1,4}", tun) and not (reason == "pre-init" and not tun):
        raise NetworkPolicyError("Invalid VPN tunnel interface")
    env["TUNDEV"] = tun
    try:
        for name, version in (("VPNGATEWAY", None), ("INTERNAL_IP4_ADDRESS", 4),
                              ("INTERNAL_IP6_ADDRESS", 6)):
            value = source.get(name, "")
            if value:
                address = ipaddress.ip_address(value)
                if (version and address.version != version) or "%" in value:
                    raise ValueError
                env[name] = str(address)
        if "VPNGATEWAY" not in env:
            raise ValueError
        if source.get("INTERNAL_IP4_NETMASK"):
            env["INTERNAL_IP4_NETMASK"] = str(ipaddress.IPv4Network(
                "0.0.0.0/" + source["INTERNAL_IP4_NETMASK"]).netmask)
        if source.get("INTERNAL_IP4_NETMASKLEN"):
            length = _integer(source["INTERNAL_IP4_NETMASKLEN"], 0, 32)
            env["INTERNAL_IP4_NETMASKLEN"] = str(length)
            network = ipaddress.IPv4Network(env.get("INTERNAL_IP4_ADDRESS", "") + "/" + str(length), strict=False)
            if env.get("INTERNAL_IP4_NETMASK", str(network.netmask)) != str(network.netmask):
                raise ValueError
            if source.get("INTERNAL_IP4_NETADDR", str(network.network_address)) != str(network.network_address):
                raise ValueError
            env["INTERNAL_IP4_NETADDR"] = str(network.network_address)
        elif source.get("INTERNAL_IP4_NETADDR"):
            env["INTERNAL_IP4_NETADDR"] = str(ipaddress.IPv4Address(source["INTERNAL_IP4_NETADDR"]))
        if source.get("INTERNAL_IP6_NETMASK"):
            env["INTERNAL_IP6_NETMASK"] = str(ipaddress.IPv6Interface(source["INTERNAL_IP6_NETMASK"]))
        if source.get("INTERNAL_IP4_MTU"):
            env["INTERNAL_IP4_MTU"] = str(_integer(source["INTERNAL_IP4_MTU"], 576, 65535))
        for family, version in (("CISCO", 4), ("CISCO_IPV6", 6)):
            for kind in ("INC", "EXC"):
                name = family + "_SPLIT_" + kind
                if source.get(name, "") == "":
                    continue
                count = _integer(source[name], 0, 256)
                env[name] = str(count)
                for index in range(count):
                    prefix = name + "_" + str(index)
                    length = _integer(source.get(prefix + "_MASKLEN"), 0, 32 if version == 4 else 128)
                    network = ipaddress.ip_network(source.get(prefix + "_ADDR", "") + "/" + str(length), strict=False)
                    if network.version != version:
                        raise ValueError
                    env[prefix + "_ADDR"] = str(network.network_address)
                    env[prefix + "_MASKLEN"] = str(length)
                    if version == 4:
                        supplied = source.get(prefix + "_MASK")
                        if supplied and supplied != str(network.netmask):
                            raise ValueError
                        env[prefix + "_MASK"] = str(network.netmask)
    except (TypeError, ValueError) as exc:
        raise NetworkPolicyError("Invalid VPN network configuration") from exc
    # The DNS module validates these separately; never persist other server
    # fields, banners, authentication cookies, or the caller's environment.
    for name in ("INTERNAL_IP4_DNS", "INTERNAL_IP6_DNS", "CISCO_DEF_DOMAIN", "CISCO_SPLIT_DNS"):
        value = source.get(name, "")
        if not isinstance(value, str) or len(value) > 16384 or any(c in value for c in "\r\n\0"):
            raise NetworkPolicyError("Invalid VPN DNS configuration")
        env[name] = value
    return env


def _full_tunnel(env, version):
    address_key = "INTERNAL_IP4_ADDRESS" if version == 4 else "INTERNAL_IP6_ADDRESS"
    if not env.get(address_key) and not (version == 6 and env.get("INTERNAL_IP6_NETMASK")):
        return False
    name = "CISCO_SPLIT_INC" if version == 4 else "CISCO_IPV6_SPLIT_INC"
    if name not in env:
        return True
    networks = [ipaddress.ip_network(env[f"{name}_{i}_ADDR"] + "/" + env[f"{name}_{i}_MASKLEN"])
                for i in range(int(env[name]))]
    return any(network.prefixlen == 0 for network in ipaddress.collapse_addresses(networks))


def _base_script(env, reason=None):
    path = next((path for path in BASE_SCRIPTS if os.path.isfile(path) and os.access(path, os.X_OK)), None)
    if not path:
        raise NetworkPolicyError("OpenConnect network script is unavailable")
    base_env = dict(env, INTERNAL_IP4_DNS="", INTERNAL_IP6_DNS="", LC_ALL="C", LANG="C",
                    PATH="/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin")
    if reason:
        base_env["reason"] = reason
    result = _run([path], env=base_env)
    if result.returncode:
        raise NetworkPolicyError("OpenConnect network configuration failed")


def _route_lookup(destination, version=6):
    result = _run([ROUTE, "-n", "get", "-inet6" if version == 6 else "-inet", destination])
    if result.returncode:
        return None
    values = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.strip().partition(":")
        if separator:
            values[key] = value.strip()
    if not values.get("destination") or not values.get("interface"):
        raise NetworkPolicyError("Cannot verify VPN routes")
    try:
        destination_value = values["destination"]
        if destination_value == "default":
            destination_value = "::" if version == 6 else "0.0.0.0"
        mask = values.get("mask")
        if mask == "default":
            length = 0
        elif mask:
            bits = bin(int(ipaddress.ip_address(mask)))[2:].zfill(128 if version == 6 else 32)
            if "01" in bits:
                raise ValueError
            length = bits.count("1")
        else:
            length = 128 if version == 6 else 32
        values["prefix"] = str(ipaddress.ip_network(destination_value.split("%")[0] + "/" + str(length), strict=False))
        values["flags"] = set(values.get("flags", "").strip("<>").split(","))
    except ValueError as exc:
        raise NetworkPolicyError("Cannot verify VPN routes") from exc
    return values


def _guard_matches(route, prefix):
    return bool(route and route["prefix"] == prefix and route.get("gateway") == "::1"
                and route["interface"] == "lo0" and GUARD_FLAGS <= route["flags"]
                and not {"IFSCOPE", "HOST"} & route["flags"])


def _exact_guard_route(prefix):
    # `route get` is a longest-prefix lookup: a legitimate /128 could hide our
    # /1 and make cleanup lose ownership. Inspect the exact unscoped table row.
    result = _run(["/usr/sbin/netstat", "-rn", "-f", "inet6"])
    if result.returncode or not re.search(r"Destination\s+Gateway\s+Flags\s+Netif", result.stdout):
        raise NetworkPolicyError("Cannot inspect IPv6 route ownership")
    matches = []
    names = {"U": "UP", "G": "GATEWAY", "R": "REJECT", "S": "STATIC",
             "1": "PROTO1", "2": "PROTO2", "H": "HOST", "I": "IFSCOPE", "B": "BLACKHOLE"}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        destination, gateway, flags, interface = fields[:4]
        if "I" in flags or "%" in destination:
            continue
        try:
            network = str(ipaddress.IPv6Network(destination, strict=False))
        except ValueError:
            continue
        if network == prefix:
            matches.append({"prefix": prefix, "gateway": gateway, "interface": interface,
                            "flags": {names[flag] for flag in flags if flag in names}})
    if len(matches) > 1:
        raise NetworkPolicyError("Ambiguous IPv6 route ownership")
    return matches[0] if matches else None


def _ensure_guard(state, prefix):
    owned = prefix in state["routes"]
    existing = _exact_guard_route(prefix)
    if existing and existing["prefix"] == prefix:
        if owned and _guard_matches(existing, prefix):
            return
        raise NetworkPolicyError("An existing IPv6 route conflicts with VPN protection")
    if not owned:
        # Write intent first so a crash after a successful add is recoverable.
        state["routes"].append(prefix)
        _save(state)
    result = _run([ROUTE, "-n", "add", "-inet6", "-net", prefix, "::1", "-reject", "-proto1", "-proto2"])
    if result.returncode or not _guard_matches(_exact_guard_route(prefix), prefix):
        raise NetworkPolicyError("IPv6 protection could not be installed")


def _remove_guards(state):
    for prefix in list(state["routes"]):
        if prefix not in GUARD_PREFIXES:
            raise NetworkPolicyError("VPN route journal is invalid")
        existing = _exact_guard_route(prefix)
        if existing and existing["prefix"] == prefix:
            if not _guard_matches(existing, prefix):
                raise NetworkPolicyError("VPN route ownership changed; preserving the route")
            result = _run([ROUTE, "-n", "delete", "-inet6", "-net", prefix, "::1"])
            if result.returncode or _guard_matches(_exact_guard_route(prefix), prefix):
                raise NetworkPolicyError("VPN IPv6 protection could not be removed")
        state["routes"].remove(prefix)
        _save(state)


def _verify_tunnel_routes(env, version):
    destinations = ("1.1.1.1", "129.1.1.1") if version == 4 else ("2001:4860:4860::8888", "9000::1")
    name = "CISCO_SPLIT_EXC" if version == 4 else "CISCO_IPV6_SPLIT_EXC"
    excluded = [ipaddress.ip_network(env[f"{name}_{i}_ADDR"] + "/" + env[f"{name}_{i}_MASKLEN"])
                for i in range(int(env.get(name, "0")))]
    for destination in destinations:
        # Choose a representative outside explicit server exclusions; a valid
        # VPN may deliberately exclude the usual public probe address.
        candidate = ipaddress.ip_address(destination)
        half = ipaddress.ip_network(str(candidate) + "/1", strict=False)
        for _ in range(len(excluded) + 1):
            overlap = next((network for network in excluded if candidate in network), None)
            if overlap is None:
                break
            next_address = int(overlap.broadcast_address) + 1
            if next_address > int(half.broadcast_address):
                candidate = half.network_address + 1
            else:
                candidate = type(candidate)(next_address)
        if any(candidate in network for network in excluded):
            continue
        destination = str(candidate)
        route = _route_lookup(destination, version)
        if not route or route["interface"] != env["TUNDEV"] or {"REJECT", "BLACKHOLE"} & route["flags"]:
            raise NetworkPolicyError("VPN full-tunnel routes could not be verified")


def _verify_outer_gateway(env):
    address = ipaddress.ip_address(env["VPNGATEWAY"])
    if address.version != 6:
        return
    route = _route_lookup(str(address))
    if (not route or route["prefix"] != str(address) + "/128"
            or route["interface"] in {env["TUNDEV"], "lo0"}
            or {"REJECT", "BLACKHOLE"} & route["flags"]):
        raise NetworkPolicyError("VPN IPv6 gateway exception could not be verified")


def _verify_dns_routes(env, config):
    if _full_tunnel(env, 4) and config is not None:
        for address in config["ServerAddresses"]:
            route = _route_lookup(address, ipaddress.ip_address(address).version)
            if not route or route["interface"] != env["TUNDEV"] or {"REJECT", "BLACKHOLE"} & route["flags"]:
                raise NetworkPolicyError("VPN DNS routes could not be verified")


def _apply_policy(state):
    env = state["env"]
    full4, full6 = _full_tunnel(env, 4), _full_tunnel(env, 6)
    if full4:
        _verify_tunnel_routes(env, 4)
    if full6:
        _verify_tunnel_routes(env, 6)
    protect = full4 and not full6
    if protect:
        _verify_outer_gateway(env)
        for prefix in GUARD_PREFIXES:
            _ensure_guard(state, prefix)
    else:
        _remove_guards(state)
    config = network_dns.build_dns_config(env)
    _verify_dns_routes(env, config)
    if state["dns"] and state["dns"]["config"] != config:
        network_dns.remove_dns(state["dns"]["key"], state["dns"]["config"])
        state["dns"] = None
        _save(state)
    if config is not None:
        key = "State:/Network/Service/com.github.ms-sso-openconnect." + state["token"] + "/DNS"
        state["dns"] = {"key": key, "config": config}
        _save(state)
        network_dns.apply_dns(key, config)
    state["protect_ipv6"] = protect
    state["status"] = "ready"
    _save(state)


def _cleanup_owned(state):
    if state["dns"]:
        network_dns.remove_dns(state["dns"]["key"], state["dns"]["config"])
        state["dns"] = None
        _save(state)
    _remove_guards(state)


@_public
def cleanup_session(token):
    with _locked(token):
        state = _load(token)
        if state is None:
            return
        if _vpn_process_matches(state):
            raise NetworkPolicyError("VPN process is still running; retaining network protection")
        _cleanup_owned(state)
        (STATE_DIR / (token + ".json")).unlink()


@_public
def cleanup_stale_sessions():
    _state_directory()
    for path in STATE_DIR.glob("*.json"):
        token = _token(path.stem)
        with _locked(token):
            state = _load(token)
            if state is None:
                continue
            if _process_matches(state["owner_pid"], state["owner_identity"]):
                raise NetworkPolicyError("A VPN network session is still owned by a running helper")
            live_child = _vpn_process_matches(state)
        if live_child:
            # Release the journal lock before signaling: OpenConnect's normal
            # disconnect callback needs that lock to restore its networking.
            try:
                os.kill(state["vpn_pid"], signal.SIGTERM)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 10
            while _vpn_process_matches(state) and time.monotonic() < deadline:
                time.sleep(0.1)
            if _vpn_process_matches(state):
                raise NetworkPolicyError("Previous VPN process is still stopping; retaining network protection")
        cleanup_session(token)


@_public
def session_failure(token):
    # Atomic journal replacement permits nonblocking read-only status while a
    # script holds the lock during network setup. Disconnect must stay usable.
    _token(token)
    _state_directory()
    state = _load(token)
    return FAILURE_MESSAGE if not state or state["status"] == "failed" else None


@_public
def session_ready(token):
    _token(token)
    _state_directory()
    state = _load(token)
    if not state or state["status"] != "ready" or not _vpn_process_matches(state):
        return False
    try:
        if state.get("protect_ipv6"):
            if state["routes"] != list(GUARD_PREFIXES):
                return False
            if not all(_guard_matches(_exact_guard_route(prefix), prefix) for prefix in GUARD_PREFIXES):
                return False
            _verify_outer_gateway(state["env"])
        if _full_tunnel(state["env"], 4):
            _verify_tunnel_routes(state["env"], 4)
        if _full_tunnel(state["env"], 6):
            _verify_tunnel_routes(state["env"], 6)
        dns = state["dns"]
        if dns:
            _verify_dns_routes(state["env"], dns["config"])
        return not dns or network_dns.verify_dns(dns["key"], dns["config"])
    except (NetworkPolicyError, network_dns.NetworkDNSError):
        return False


def run_network_script():
    token = None
    try:
        _require_root()
        token = _token(os.environ.get(SESSION_ENV))
        with _locked(token):
            state = _load(token)
            if state is None:
                raise NetworkPolicyError("VPN network session is missing")
            env = _validated_env(os.environ)
            _bind(state, int(env["VPNPID"]))
            reason = env["reason"]
            if reason == "disconnect":
                try:
                    _base_script(state["env"] or env, reason="disconnect")
                finally:
                    _cleanup_owned(state)
                state["status"] = "closed"
                _save(state)
                return 0
            if reason == "pre-init":
                _base_script(env)
                return 0
            if reason == "attempt-reconnect":
                # The physical network may be down. Keep the previous guards
                # and DNS, and let base refresh only its VPN gateway exception.
                _base_script(env)
                return 0
            state["env"] = env
            state["status"] = "configuring"
            _save(state)
            _base_script(env)
            _apply_policy(state)
            return 0
    except Exception:
        # Never forward server-controlled text, subprocess output, or addresses.
        if token:
            try:
                with _locked(token):
                    state = _load(token)
                    if state:
                        state["status"] = "failed"
                        _save(state)
                        # OpenConnect ignores script failures. Keep protection
                        # until the helper stops its child, then rolls back.
            except Exception:
                pass
        return 1
