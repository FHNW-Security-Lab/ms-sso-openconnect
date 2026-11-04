"""macOS DNS policy tests using an in-memory scutil command runner."""

import copy
import importlib.util
from pathlib import Path
import shlex
import subprocess
import unittest
from types import SimpleNamespace


MODULE = Path(__file__).resolve().parents[1] / "frontends/osx/daemon/network_dns.py"
SPEC = importlib.util.spec_from_file_location("network_dns_test_module", MODULE)
dns = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dns)
KEY = dns.DNS_KEY_PREFIX + "1" * 32 + "/DNS"


class MemoryScutil:
    """Model command/readback behavior without starting any system process."""

    def __init__(self):
        self.store = {}
        self.calls = []
        self.ignore_set = False
        self.ignore_remove = False
        self.returncode = 0
        self.stderr = ""

    @staticmethod
    def show(config):
        if config is None:
            return "  No such key\n"
        lines = ["<dictionary> {"]
        for key, value in sorted(config.items()):
            if isinstance(value, list):
                lines.append(f"  {key} : <array> {{")
                lines.extend(f"    {index} : {item}" for index, item in enumerate(value))
                lines.append("  }")
            else:
                lines.append(f"  {key} : {value}")
        lines.append("}")
        return "\n".join(lines) + "\n"

    def __call__(self, argv, **kwargs):
        if argv != ["/usr/sbin/scutil"] or kwargs.get("timeout") != 5:
            raise AssertionError("Only the bounded absolute scutil command is allowed")
        self.calls.append(kwargs["input"])
        current = {}
        output = ""
        for line in kwargs["input"].splitlines():
            tokens = shlex.split(line)
            if not tokens or tokens[0] == "quit":
                continue
            if tokens[0] == "d.init":
                current = {}
            elif tokens[0] == "d.add":
                if tokens[2] == "*":
                    current[tokens[1]] = tokens[3:]
                elif tokens[2] == "#":
                    current[tokens[1]] = int(tokens[3])
                else:
                    current[tokens[1]] = tokens[2]
            elif tokens[0] == "set" and not self.ignore_set:
                self.store[tokens[1]] = copy.deepcopy(current)
            elif tokens[0] == "remove" and not self.ignore_remove:
                self.store.pop(tokens[1], None)
            elif tokens[0] == "show":
                output = self.show(self.store.get(tokens[1]))
        return SimpleNamespace(returncode=self.returncode, stderr=self.stderr, stdout=output)


def environment(**changes):
    return {
        "INTERNAL_IP4_ADDRESS": "192.0.2.10",
        "INTERNAL_IP4_DNS": "192.0.2.53 192.0.2.54",
        "CISCO_DEF_DOMAIN": "corp.example.test",
    } | changes


class DNSConfigTests(unittest.TestCase):
    def test_missing_split_count_uses_catchall_but_explicit_zero_does_not(self):
        full = dns.build_dns_config(environment())
        self.assertEqual(full["SupplementalMatchDomains"], ["", "corp.example.test"])
        self.assertEqual(full["SupplementalMatchDomainsNoSearch"], 0)
        zero = dns.build_dns_config(environment(CISCO_SPLIT_INC="0"))
        self.assertEqual(zero["SupplementalMatchDomains"], ["corp.example.test"])
        self.assertIsNone(dns.build_dns_config(environment(CISCO_SPLIT_INC="0", CISCO_DEF_DOMAIN="")))

    def test_explicit_default_and_two_half_routes_are_full_tunnel(self):
        routes = (
            {"CISCO_SPLIT_INC": "1", "CISCO_SPLIT_INC_0_ADDR": "0.0.0.0", "CISCO_SPLIT_INC_0_MASKLEN": "0"},
            {"CISCO_SPLIT_INC": "2", "CISCO_SPLIT_INC_0_ADDR": "0.0.0.0", "CISCO_SPLIT_INC_0_MASKLEN": "1",
             "CISCO_SPLIT_INC_1_ADDR": "128.0.0.0", "CISCO_SPLIT_INC_1_MASKLEN": "1"},
        )
        for route_env in routes:
            with self.subTest(route_env=route_env):
                self.assertIn("", dns.build_dns_config(environment(**route_env))["SupplementalMatchDomains"])

    def test_genuine_split_routes_remain_domain_scoped(self):
        config = dns.build_dns_config(environment(
            CISCO_SPLIT_INC="1", CISCO_SPLIT_INC_0_ADDR="10.0.0.0", CISCO_SPLIT_INC_0_MASK="255.0.0.0",
        ))
        self.assertEqual(config["SupplementalMatchDomains"], ["corp.example.test"])

    def test_explicit_split_dns_prevents_catchall_on_full_ipv4(self):
        config = dns.build_dns_config(environment(CISCO_SPLIT_DNS="corp.example.test,internal.example.test"))
        self.assertEqual(config["SupplementalMatchDomains"], ["corp.example.test", "internal.example.test"])
        self.assertEqual(config["SearchDomains"], ["corp.example.test"])
        separate_search = dns.build_dns_config(environment(CISCO_SPLIT_DNS="internal.example.test"))
        self.assertEqual(separate_search["SupplementalMatchDomains"], ["internal.example.test", "corp.example.test"])

    def test_ipv6_route_policy_does_not_globalize_split_ipv4(self):
        config = dns.build_dns_config(environment(
            CISCO_SPLIT_INC="0", INTERNAL_IP6_ADDRESS="2001:db8::10", CISCO_IPV6_SPLIT_INC="1",
            CISCO_IPV6_SPLIT_INC_0_ADDR="::", CISCO_IPV6_SPLIT_INC_0_MASKLEN="0",
        ))
        self.assertNotIn("", config["SupplementalMatchDomains"])
        full = dns.build_dns_config(environment(CISCO_IPV6_SPLIT_INC="0"))
        self.assertIn("", full["SupplementalMatchDomains"])

    def test_dns_addresses_from_both_variables_are_canonical_and_unique(self):
        config = dns.build_dns_config(environment(
            INTERNAL_IP4_DNS="192.0.2.53 2001:0db8::53", INTERNAL_IP6_DNS="2001:db8::53 2001:db8::54",
            INTERNAL_IP6_ADDRESS="2001:db8::10",
        ))
        self.assertEqual(config["ServerAddresses"], ["192.0.2.53", "2001:db8::53", "2001:db8::54"])

    def test_unroutable_ipv6_dns_is_filtered_and_no_usable_servers_is_an_error(self):
        values = environment(INTERNAL_IP6_DNS="2001:db8::53")
        self.assertEqual(dns.build_dns_config(values)["ServerAddresses"], ["192.0.2.53", "192.0.2.54"])
        with self.assertRaises(dns.NetworkDNSError):
            dns.build_dns_config(values | {"INTERNAL_IP4_DNS": ""})
        assigned = values | {"INTERNAL_IP6_ADDRESS": "2001:db8::10", "CISCO_IPV6_SPLIT_INC": "0"}
        self.assertNotIn("2001:db8::53", dns.build_dns_config(assigned)["ServerAddresses"])

    def test_only_ipv6_servers_covered_by_tunnel_routes_are_kept(self):
        values = environment(INTERNAL_IP6_ADDRESS="2001:db8::10",
                             INTERNAL_IP6_DNS="2001:db8:1::53 2001:db8:2::53",
                             CISCO_IPV6_SPLIT_INC="1", CISCO_IPV6_SPLIT_INC_0_ADDR="2001:db8:1::",
                             CISCO_IPV6_SPLIT_INC_0_MASKLEN="64")
        self.assertEqual(dns.build_dns_config(values)["ServerAddresses"],
                         ["192.0.2.53", "192.0.2.54", "2001:db8:1::53"])
        values.update(CISCO_IPV6_SPLIT_EXC="1", CISCO_IPV6_SPLIT_EXC_0_ADDR="2001:db8:1::53",
                      CISCO_IPV6_SPLIT_EXC_0_MASKLEN="128")
        self.assertEqual(dns.build_dns_config(values)["ServerAddresses"], ["192.0.2.53", "192.0.2.54"])

    def test_no_vpn_dns_produces_no_override(self):
        self.assertIsNone(dns.build_dns_config(environment(INTERNAL_IP4_DNS="")))

    def test_catchall_and_search_domains_share_the_match_array_limit(self):
        domains = [f"domain{index}.example.test" for index in range(32)]
        with self.assertRaises(dns.NetworkDNSError):
            dns.build_dns_config(environment(CISCO_DEF_DOMAIN=" ".join(domains)))
        config = dns.build_dns_config(environment(CISCO_DEF_DOMAIN=" ".join(domains[:-1])))
        self.assertEqual(len(config["SupplementalMatchDomains"]), 32)

    def test_invalid_and_injected_environment_is_rejected(self):
        invalid = (
            {"INTERNAL_IP4_DNS": "192.0.2.53\nremove State:/Network/Global/DNS"},
            {"INTERNAL_IP4_DNS": "not-an-address"},
            {"INTERNAL_IP4_DNS": "0.0.0.0"},
            {"INTERNAL_IP6_DNS": "ff02::1"},
            {"INTERNAL_IP6_DNS": "fe80::1%en0"},
            {"INTERNAL_IP6_DNS": "fe80::53"},
            {"CISCO_DEF_DOMAIN": 'corp.example.test";remove'},
            {"CISCO_SPLIT_DNS": ",,,"},
            {"CISCO_SPLIT_DNS": "*"},
            {"CISCO_SPLIT_INC": "1;remove"},
            {"CISCO_SPLIT_INC": "-1"},
            {"CISCO_SPLIT_INC": "1"},
            {"CISCO_SPLIT_INC": "1", "CISCO_SPLIT_INC_0_ADDR": "0.0.0.0", "CISCO_SPLIT_INC_0_MASKLEN": "33"},
        )
        for values in invalid:
            with self.subTest(values=values):
                with self.assertRaises(dns.NetworkDNSError):
                    dns.build_dns_config(environment(**values))


class DNSStoreTests(unittest.TestCase):
    def setUp(self):
        self.runner = MemoryScutil()
        self.config = dns.build_dns_config(environment())

    def test_apply_roundtrips_actual_empty_domain_and_removes_only_owned_key(self):
        unrelated = "State:/Network/Service/other/DNS"
        self.runner.store[unrelated] = {"ServerAddresses": ["198.51.100.53"]}
        dns.apply_dns(KEY, self.config, self.runner)
        self.assertEqual(self.runner.store[KEY], self.config)
        self.assertTrue(any('d.add SupplementalMatchDomains * ""' in call for call in self.runner.calls))
        self.assertTrue(dns.verify_dns(KEY, self.config, self.runner))
        dns.remove_dns(KEY, self.config, self.runner)
        dns.remove_dns(KEY, self.config, self.runner)
        self.assertEqual(self.runner.store, {unrelated: {"ServerAddresses": ["198.51.100.53"]}})

    def test_missing_or_changed_readback_prevents_success(self):
        self.runner.ignore_set = True
        with self.assertRaises(dns.NetworkDNSError):
            dns.apply_dns(KEY, self.config, self.runner)
        self.assertFalse(dns.verify_dns(KEY, self.config, self.runner))
        self.runner.store[KEY] = self.config | {"ServerAddresses": ["198.51.100.53"]}
        with self.assertRaises(dns.NetworkDNSError):
            dns.remove_dns(KEY, self.config, self.runner)
        self.assertFalse(any(call.startswith("remove ") for call in self.runner.calls))

    def test_failed_delete_is_detected_by_readback(self):
        self.runner.store[KEY] = self.config
        self.runner.ignore_remove = True
        with self.assertRaises(dns.NetworkDNSError):
            dns.remove_dns(KEY, self.config, self.runner)

    def test_existing_conflicting_dictionary_cannot_be_overwritten(self):
        changed = self.config | {"ServerAddresses": ["198.51.100.53"]}
        self.runner.store[KEY] = changed
        with self.assertRaises(dns.NetworkDNSError):
            dns.apply_dns(KEY, self.config, self.runner)
        self.assertEqual(self.runner.store[KEY], changed)
        self.assertEqual(len(self.runner.calls), 1)

    def test_command_errors_and_unexpected_output_fail_closed(self):
        for runner in (
            lambda *args, **kwargs: SimpleNamespace(returncode=1, stderr="", stdout=""),
            lambda *args, **kwargs: SimpleNamespace(returncode=0, stderr="error", stdout=""),
            lambda *args, **kwargs: SimpleNamespace(returncode=0, stderr="", stdout="unexpected"),
        ):
            with self.assertRaises(dns.NetworkDNSError):
                dns.verify_dns(KEY, self.config, runner)
        def timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired("scutil", 5)
        with self.assertRaises(dns.NetworkDNSError):
            dns.apply_dns(KEY, self.config, timeout)

    def test_unknown_dictionary_fields_prevent_cleanup(self):
        self.runner.store[KEY] = self.config | {"Unexpected": "other owner"}
        with self.assertRaises(dns.NetworkDNSError):
            dns.remove_dns(KEY, self.config, self.runner)
        self.assertEqual(len(self.runner.calls), 1)

    def test_invalid_key_or_dictionary_cannot_reach_runner(self):
        for key in ("State:/Network/Global/DNS", KEY + "\nremove other", KEY.replace("1" * 32, "../escape")):
            with self.assertRaises(dns.NetworkDNSError):
                dns.apply_dns(key, self.config, self.runner)
        for bad in (
            self.config | {"ServerAddresses": ['192.0.2.53"\nremove other']},
            self.config | {"SupplementalMatchDomains": ["", "bad;domain"]},
            self.config | {"Unexpected": "injected"},
        ):
            with self.assertRaises(dns.NetworkDNSError):
                dns.apply_dns(KEY, bad, self.runner)
        self.assertEqual(self.runner.calls, [])


if __name__ == "__main__":
    unittest.main()
