"""Validated, session-owned macOS DNS settings for the network policy helper."""

from __future__ import annotations

import ipaddress
import re
import subprocess
from collections.abc import Mapping


DNS_KEY_PREFIX = "State:/Network/Service/com.github.ms-sso-openconnect."
_KEY_PATTERN = re.compile(re.escape(DNS_KEY_PREFIX) + r"[0-9a-f]{32}/DNS\Z")
_DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_ARRAY_FIELDS = frozenset({"ServerAddresses", "SearchDomains", "SupplementalMatchDomains"})
_FIELDS = _ARRAY_FIELDS | {"DomainName", "SupplementalMatchDomainsNoSearch"}
_MAX_ITEMS = 32


class NetworkDNSError(RuntimeError):
    """The requested DNS policy could not be safely installed or verified."""


def _text(value: object) -> str:
    if not isinstance(value, str) or len(value) > 8192 or any(ord(c) < 32 for c in value):
        raise NetworkDNSError("Invalid VPN DNS configuration")
    return value.strip()


def _address(value: object) -> str:
    text = _text(value)
    if "%" in text:
        raise NetworkDNSError("Scoped VPN DNS addresses are unsupported")
    try:
        address = ipaddress.ip_address(text)
    except ValueError as error:
        raise NetworkDNSError("Invalid VPN DNS server address") from error
    if address.is_unspecified or address.is_multicast:
        raise NetworkDNSError("Invalid VPN DNS server address")
    if address.version == 6 and address.is_link_local:
        raise NetworkDNSError("Scoped VPN DNS addresses are unsupported")
    return str(address)


def _domain(value: object) -> str:
    text = _text(value).rstrip(".").lower()
    if not text or len(text) > 253 or not all(_DOMAIN_LABEL.fullmatch(label) for label in text.split(".")):
        raise NetworkDNSError("Invalid VPN DNS domain")
    return text


def _unique(values):
    result = list(dict.fromkeys(values))
    if len(result) > _MAX_ITEMS:
        raise NetworkDNSError("Too many VPN DNS entries")
    return result


def _domains(value: object) -> list[str]:
    text = _text(value)
    if not text:
        return []
    values = [item for item in re.split(r"[, ]+", text) if item]
    if not values:
        raise NetworkDNSError("Invalid VPN DNS domain list")
    return _unique(_domain(item) for item in values)


def _full_ipv4_tunnel(env: Mapping) -> bool:
    address = _text(env.get("INTERNAL_IP4_ADDRESS", ""))
    if not address:
        return False
    try:
        ipaddress.IPv4Address(address)
    except ValueError as error:
        raise NetworkDNSError("Invalid VPN IPv4 address") from error
    count = env.get("CISCO_SPLIT_INC")
    if count is None or _text(count) == "":
        return True
    count = _text(count)
    if not re.fullmatch(r"[0-9]{1,4}", count) or int(count) > 1024:
        raise NetworkDNSError("Invalid VPN IPv4 route count")
    if int(count) == 0:
        return False
    routes = []
    for index in range(int(count)):
        prefix = f"CISCO_SPLIT_INC_{index}_"
        network = _text(env.get(prefix + "ADDR", ""))
        mask = _text(env.get(prefix + "MASKLEN", env.get(prefix + "MASK", "")))
        if not network or not mask:
            raise NetworkDNSError("Incomplete VPN IPv4 route")
        try:
            routes.append(ipaddress.IPv4Network(f"{network}/{mask}", strict=False))
        except ValueError as error:
            raise NetworkDNSError("Invalid VPN IPv4 route") from error
    return list(ipaddress.collapse_addresses(routes)) == [ipaddress.IPv4Network("0.0.0.0/0")]


def _ipv6_dns_route_matches(address: str, env: Mapping) -> bool:
    assigned = _text(env.get("INTERNAL_IP6_ADDRESS", "")) or _text(env.get("INTERNAL_IP6_NETMASK", ""))
    if not assigned:
        return False
    try:
        ipaddress.IPv6Interface(assigned)
    except ValueError as error:
        raise NetworkDNSError("Invalid VPN IPv6 address") from error

    def routes(kind: str, missing_default: bool):
        prefix = "CISCO_IPV6_SPLIT_" + kind
        raw = env.get(prefix)
        if raw is None or _text(raw) == "":
            return [ipaddress.IPv6Network("::/0")] if missing_default else []
        raw = _text(raw)
        if not re.fullmatch(r"[0-9]{1,4}", raw) or int(raw) > 1024:
            raise NetworkDNSError("Invalid VPN IPv6 route count")
        result = []
        for index in range(int(raw)):
            network = _text(env.get(f"{prefix}_{index}_ADDR", ""))
            mask = _text(env.get(f"{prefix}_{index}_MASKLEN", ""))
            if not network or not mask:
                raise NetworkDNSError("Incomplete VPN IPv6 route")
            try:
                result.append(ipaddress.IPv6Network(f"{network}/{mask}", strict=False))
            except ValueError as error:
                raise NetworkDNSError("Invalid VPN IPv6 route") from error
        return result

    server = ipaddress.IPv6Address(address)
    return any(server in route for route in routes("INC", True)) and not any(
        server in route for route in routes("EXC", False)
    )


def build_dns_config(env: Mapping) -> dict | None:
    """Derive DNS policy without interpreting a search domain as split-DNS intent."""
    if not isinstance(env, Mapping):
        raise NetworkDNSError("Invalid VPN DNS environment")
    addresses = _unique(
        _address(item)
        for field in ("INTERNAL_IP4_DNS", "INTERNAL_IP6_DNS")
        for item in _text(env.get(field, "")).split()
    )
    if not addresses:
        return None
    addresses = [address for address in addresses if ":" not in address or _ipv6_dns_route_matches(address, env)]
    if not addresses:
        raise NetworkDNSError("VPN DNS servers have no usable tunnel route")
    search_domains = _domains(env.get("CISCO_DEF_DOMAIN", ""))
    split_domains = _domains(env.get("CISCO_SPLIT_DNS", ""))
    if split_domains:
        match_domains = _unique(split_domains + search_domains)
    elif _full_ipv4_tunnel(env):
        match_domains = _unique([""] + search_domains)
    else:
        match_domains = search_domains
    if not match_domains:
        # An ambiguous/split route without domain policy must not capture all DNS.
        return None
    config = {
        "ServerAddresses": addresses,
        "SupplementalMatchDomains": match_domains,
        # macOS expands supplemental resolvers and drops their SearchDomains.
        # Nonempty matches must also contribute to the native search list.
        "SupplementalMatchDomainsNoSearch": 0,
    }
    if search_domains:
        config["DomainName"] = search_domains[0]
        config["SearchDomains"] = search_domains
    return config


def _validated_config(config: Mapping) -> dict:
    if not isinstance(config, Mapping) or set(config) - _FIELDS:
        raise NetworkDNSError("Invalid VPN DNS dictionary")
    result = {}
    for field in _ARRAY_FIELDS:
        if field not in config:
            if field == "SearchDomains":
                continue
            raise NetworkDNSError("Incomplete VPN DNS dictionary")
        values = config[field]
        if not isinstance(values, list) or not values or len(values) > _MAX_ITEMS:
            raise NetworkDNSError("Invalid VPN DNS array")
        if field == "ServerAddresses":
            result[field] = _unique(_address(value) for value in values)
        elif field == "SupplementalMatchDomains":
            result[field] = _unique("" if value == "" else _domain(value) for value in values)
        else:
            result[field] = _unique(_domain(value) for value in values)
    if "DomainName" in config:
        result["DomainName"] = _domain(config["DomainName"])
    if type(config.get("SupplementalMatchDomainsNoSearch")) is not int or config["SupplementalMatchDomainsNoSearch"] != 0:
        raise NetworkDNSError("Invalid VPN DNS match policy")
    result["SupplementalMatchDomainsNoSearch"] = 0
    return result


def _key(key: str) -> str:
    if not isinstance(key, str) or not _KEY_PATTERN.fullmatch(key):
        raise NetworkDNSError("Invalid VPN DNS ownership key")
    return key


def _run(script: str, runner) -> str:
    try:
        result = runner(["/usr/sbin/scutil"], input=script + "quit\n", text=True,
                        capture_output=True, timeout=5, check=False)
    except (OSError, subprocess.SubprocessError) as error:
        raise NetworkDNSError("macOS DNS command failed") from error
    if result.returncode != 0 or result.stderr.strip():
        raise NetworkDNSError("macOS DNS command failed")
    if len(result.stdout) > 65536:
        raise NetworkDNSError("Unexpected macOS DNS command output")
    return result.stdout


def _read_dns(key: str, runner) -> dict | None:
    output = _run(f"show {_key(key)}\n", runner).strip()
    if output == "No such key":
        return None
    lines = output.splitlines()
    if not lines or lines[0].strip() != "<dictionary> {" or lines[-1].strip() != "}":
        raise NetworkDNSError("Could not inspect macOS VPN DNS settings")
    config = {}
    index = 1
    while index < len(lines) - 1:
        match = re.fullmatch(r"\s*([A-Za-z]+)\s*:\s*(.*?)\s*", lines[index])
        if not match or match[1] not in _FIELDS or match[1] in config:
            raise NetworkDNSError("Unexpected macOS VPN DNS settings")
        field, value = match.groups()
        index += 1
        if field in _ARRAY_FIELDS:
            if value != "<array> {":
                raise NetworkDNSError("Unexpected macOS VPN DNS array")
            values = []
            while index < len(lines) - 1 and lines[index].strip() != "}":
                item = re.fullmatch(r"\s*([0-9]+)\s*:\s*(.*?)\s*", lines[index])
                if not item or int(item[1]) != len(values) or len(values) >= _MAX_ITEMS:
                    raise NetworkDNSError("Unexpected macOS VPN DNS array")
                values.append(item[2])
                index += 1
            if index >= len(lines) - 1:
                raise NetworkDNSError("Incomplete macOS VPN DNS array")
            index += 1
            config[field] = values
        elif field == "SupplementalMatchDomainsNoSearch":
            if value != "0":
                raise NetworkDNSError("Unexpected macOS VPN DNS match policy")
            config[field] = 0
        else:
            config[field] = value
    return _validated_config(config)


def apply_dns(key: str, config: Mapping, runner=subprocess.run) -> None:
    key = _key(key)
    config = _validated_config(config)
    current = _read_dns(key, runner)
    if current is not None and current != config:
        raise NetworkDNSError("VPN DNS settings changed; refusing to overwrite them")
    commands = ["d.init"]
    for field, value in sorted(config.items()):
        if isinstance(value, list):
            # Inputs above contain no quoting metacharacters. The empty string
            # explicitly creates a catch-all domain instead of an empty array.
            commands.append(f"d.add {field} * " + " ".join('""' if item == "" else item for item in value))
        elif isinstance(value, int):
            commands.append(f"d.add {field} # {value}")
        else:
            commands.append(f"d.add {field} {value}")
    commands.append(f"set {key}")
    _run("\n".join(commands) + "\n", runner)
    if not verify_dns(key, config, runner):
        raise NetworkDNSError("macOS VPN DNS settings did not apply")


def verify_dns(key: str, config: Mapping, runner=subprocess.run) -> bool:
    config = _validated_config(config)
    return _read_dns(_key(key), runner) == config


def remove_dns(key: str, config: Mapping, runner=subprocess.run) -> None:
    key = _key(key)
    config = _validated_config(config)
    current = _read_dns(key, runner)
    if current is None:
        return
    if current != config:
        raise NetworkDNSError("VPN DNS settings changed; refusing to remove them")
    _run(f"remove {key}\n", runner)
    if _read_dns(key, runner) is not None:
        raise NetworkDNSError("macOS VPN DNS settings did not clear")
