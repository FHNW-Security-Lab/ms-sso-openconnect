"""Nonprivileged route/DNS lifecycle tests; all system commands are fakes."""

from contextlib import ExitStack
import ipaddress
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "frontends/osx/daemon"))
import network_policy as policy
sys.path.pop(0)


class FakeNetwork:
    def __init__(self):
        self.routes = {}
        self.calls = []
        self.dns = {}
        self.tunnel = False
        self.full6 = False
        self.fail_add = None
        self.fail_dns = False
        self.outer_exception = True

    def route(self, prefix, *, interface="lo0", gateway="::1", flags=None):
        return {"prefix": prefix, "interface": interface, "gateway": gateway,
                "flags": flags or {"UP", "GATEWAY", "STATIC", "REJECT", "PROTO1", "PROTO2"}}

    def run(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        if argv[0] == "/usr/sbin/netstat":
            names = {"UP": "U", "GATEWAY": "G", "REJECT": "R", "STATIC": "S", "PROTO1": "1",
                     "PROTO2": "2", "HOST": "H", "IFSCOPE": "I", "BLACKHOLE": "B"}
            rows = ["Destination Gateway Flags Netif Expire"]
            for route in self.routes.values():
                if ipaddress.ip_network(route["prefix"]).version == 6:
                    flags = "".join(names[flag] for flag in sorted(route["flags"]) if flag in names)
                    rows.append(f"{route['prefix']} {route['gateway']} {flags} {route['interface']}")
            return subprocess.CompletedProcess(argv, 0, "\n".join(rows), "")
        if argv[0] != policy.ROUTE:
            env = kwargs["env"]
            if env["reason"] == "connect":
                self.tunnel = True
            elif env["reason"] == "disconnect":
                self.tunnel = False
            if ":" in env["VPNGATEWAY"] and self.outer_exception:
                prefix = env["VPNGATEWAY"] + "/128"
                self.routes[prefix] = self.route(prefix, interface="en0", gateway="fe80::1%en0",
                                                 flags={"UP", "GATEWAY", "HOST", "STATIC"})
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[2] == "add":
            prefix = argv[5]
            if prefix == self.fail_add or prefix in self.routes:
                return subprocess.CompletedProcess(argv, 1, "", "fake add failure")
            self.routes[prefix] = self.route(prefix)
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[2] == "delete":
            self.routes.pop(argv[5], None)
            return subprocess.CompletedProcess(argv, 0, "", "")
        self.assert_get(argv)
        version = 6 if argv[3] == "-inet6" else 4
        address = ipaddress.ip_address(argv[4].split("/")[0])
        matching = [route for prefix, route in self.routes.items()
                    if ipaddress.ip_network(prefix).version == version
                    and address in ipaddress.ip_network(prefix)]
        if matching:
            route = max(matching, key=lambda value: ipaddress.ip_network(value["prefix"]).prefixlen)
        else:
            interface = "utun4" if self.tunnel and (version == 4 or self.full6) else "en0"
            route = self.route("::/0" if version == 6 else "0.0.0.0/0", interface=interface,
                               gateway="fe80::1%en0" if version == 6 else "192.0.2.1",
                               flags={"UP", "GATEWAY"})
        network = ipaddress.ip_network(route["prefix"])
        output = (f"destination: {network.network_address}\n"
                  f"mask: {'default' if network.prefixlen == 0 else network.netmask}\n"
                  f"gateway: {route['gateway']}\ninterface: {route['interface']}\n"
                  f"flags: <{','.join(sorted(route['flags']))}>\n")
        return subprocess.CompletedProcess(argv, 0, output, "")

    @staticmethod
    def assert_get(argv):
        if argv[2] != "get":
            raise AssertionError("Unexpected command in isolated test")

    def apply_dns(self, key, config):
        if self.fail_dns:
            raise policy.network_dns.NetworkDNSError("fake DNS failure")
        if key in self.dns and self.dns[key] != config:
            raise policy.network_dns.NetworkDNSError("fake DNS conflict")
        self.dns[key] = config

    def verify_dns(self, key, config):
        return self.dns.get(key) == config

    def remove_dns(self, key, config):
        if key in self.dns and self.dns[key] != config:
            raise policy.network_dns.NetworkDNSError("fake ownership conflict")
        self.dns.pop(key, None)


class NetworkPolicyTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        directory = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix="msso-policy-test-")))
        self.state_dir = directory / "state"
        self.base_script = directory / "base-script"
        self.base_script.write_text("#!/bin/sh\nexit 99\n")
        self.base_script.chmod(0o700)
        self.network = FakeNetwork()
        self.child_alive = True
        self.owner_alive = True
        self.child_identity = "fixture child identity"
        for name, value in (("STATE_DIR", self.state_dir),
                            ("BASE_SCRIPTS", (str(self.base_script),)),
                            ("_require_root", lambda: None),
                            ("_run", self.network.run),
                            ("_process_info", self.process_info)):
            self.stack.enter_context(patch.object(policy, name, value))
        for name in ("apply_dns", "verify_dns", "remove_dns"):
            self.stack.enter_context(patch.object(policy.network_dns, name, getattr(self.network, name)))
        # Last-line protection against accidentally introducing real commands
        # or signals as this implementation evolves.
        self.stack.enter_context(patch.object(subprocess, "run", side_effect=AssertionError("Real command forbidden")))
        self.signal_mock = self.stack.enter_context(patch.object(os, "kill", side_effect=AssertionError("Real signal forbidden")))
        self.token = policy.new_session()
        self.env = {policy.SESSION_ENV: self.token, "reason": "connect", "VPNPID": "424242",
                    "TUNDEV": "utun4", "VPNGATEWAY": "198.51.100.10",
                    "INTERNAL_IP4_ADDRESS": "10.1.2.3", "INTERNAL_IP4_DNS": "10.2.3.4",
                    "CISCO_DEF_DOMAIN": "fixture.test"}

    def process_info(self, pid):
        if pid == os.getpid() and self.owner_alive:
            return {"uid": 0, "ppid": 1, "identity": "fixture helper identity", "command": "helper"}
        if pid == 424242 and self.child_alive:
            return {"uid": 0, "ppid": os.getpid(), "identity": self.child_identity,
                    "command": "/opt/homebrew/bin/openconnect"}
        return None

    def script(self, **changes):
        with patch.dict(os.environ, self.env | changes, clear=True):
            return policy.run_network_script()

    def state(self):
        return json.loads((self.state_dir / (self.token + ".json")).read_text())

    def connect(self, **changes):
        self.assertEqual(self.script(**changes), 0)
        self.assertTrue(policy.session_ready(self.token))

    def test_full_ipv4_installs_owned_guards_and_dns_before_ack(self):
        self.assertFalse(policy.session_ready(self.token))
        self.connect()
        self.assertEqual(self.state()["routes"], list(policy.GUARD_PREFIXES))
        self.assertEqual(set(self.network.routes), set(policy.GUARD_PREFIXES))
        self.assertEqual(len(self.network.dns), 1)
        base_env = self.network.calls[0][1]["env"]
        self.assertEqual(base_env["INTERNAL_IP4_DNS"], "")
        self.assertEqual(base_env["INTERNAL_IP6_DNS"], "")

    def test_wrapper_can_bind_before_parent_without_race(self):
        self.assertEqual(self.script(reason="pre-init", TUNDEV=""), 0)
        policy.bind_session(self.token, 424242)
        self.connect()
        with self.assertRaises(policy.NetworkPolicyError):
            policy.bind_session(self.token, 999999)

    def test_split_and_explicit_zero_includes_do_not_block_ipv6(self):
        for count in ("0", "1"):
            with self.subTest(count=count):
                self.connect(CISCO_SPLIT_INC=count, CISCO_SPLIT_INC_0_ADDR="10.0.0.0",
                             CISCO_SPLIT_INC_0_MASKLEN="8", CISCO_SPLIT_INC_0_MASK="255.0.0.0")
                self.assertEqual(self.state()["routes"], [])
                self.assertEqual(self.network.routes, {})

    def test_two_ipv4_halves_are_a_full_tunnel(self):
        self.connect(CISCO_SPLIT_INC="2", CISCO_SPLIT_INC_0_ADDR="0.0.0.0",
                     CISCO_SPLIT_INC_0_MASKLEN="1", CISCO_SPLIT_INC_1_ADDR="128.0.0.0",
                     CISCO_SPLIT_INC_1_MASKLEN="1")
        self.assertEqual(self.state()["routes"], list(policy.GUARD_PREFIXES))

    def test_verified_full_ipv6_is_preserved(self):
        self.network.full6 = True
        self.connect(INTERNAL_IP6_ADDRESS="fd00::123")
        self.assertEqual(self.state()["routes"], [])

    def test_ipv6_address_with_only_split_routes_still_needs_guard(self):
        self.connect(INTERNAL_IP6_ADDRESS="fd00::123", CISCO_IPV6_SPLIT_INC="1",
                     CISCO_IPV6_SPLIT_INC_0_ADDR="fd00::", CISCO_IPV6_SPLIT_INC_0_MASKLEN="64")
        self.assertEqual(self.state()["routes"], list(policy.GUARD_PREFIXES))

    def test_ipv6_outer_gateway_requires_specific_physical_route(self):
        self.connect(VPNGATEWAY="2001:db8::10")
        self.assertIn("2001:db8::10/128", self.network.routes)
        self.child_alive = False
        policy.cleanup_session(self.token)
        self.assertEqual(set(self.network.routes), {"2001:db8::10/128"})

    def test_missing_ipv6_outer_exception_fails_without_guards(self):
        self.network.outer_exception = False
        self.assertEqual(self.script(VPNGATEWAY="2001:db8::10"), 1)
        self.assertIsNotNone(policy.session_failure(self.token))
        self.assertEqual(self.network.routes, {})

    def test_preexisting_identical_route_is_not_adopted_or_deleted(self):
        self.network.routes["::/1"] = self.network.route("::/1")
        self.assertEqual(self.script(), 1)
        self.assertEqual(self.state()["routes"], [])
        self.child_alive = False
        policy.cleanup_session(self.token)
        self.assertEqual(set(self.network.routes), {"::/1"})

    def test_partial_failure_keeps_protection_until_child_exits_then_rolls_back(self):
        self.network.fail_add = "8000::/1"
        self.assertEqual(self.script(), 1)
        self.assertEqual(set(self.network.routes), {"::/1"})
        self.assertIsNotNone(policy.session_failure(self.token))
        with self.assertRaises(policy.NetworkPolicyError):
            policy.cleanup_session(self.token)
        self.child_alive = False
        policy.cleanup_session(self.token)
        self.assertEqual(self.network.routes, {})
        self.assertEqual(self.network.dns, {})

    def test_external_route_change_is_preserved_on_cleanup(self):
        self.connect()
        self.network.routes["::/1"]["gateway"] = "2001:db8::1"
        self.child_alive = False
        with self.assertRaises(policy.NetworkPolicyError):
            policy.cleanup_session(self.token)
        self.assertEqual(self.network.routes["::/1"]["gateway"], "2001:db8::1")

    def test_reconnect_reconciles_missing_guard_without_claiming_other_routes(self):
        self.connect()
        del self.network.routes["8000::/1"]
        self.assertFalse(policy.session_ready(self.token))
        self.assertEqual(self.script(reason="attempt-reconnect"), 0)
        self.assertFalse(policy.session_ready(self.token))
        self.assertEqual(self.script(reason="reconnect"), 0)
        self.assertTrue(policy.session_ready(self.token))
        self.assertEqual(set(self.network.routes), set(policy.GUARD_PREFIXES))

    def test_reconnect_dns_failure_retains_working_guards(self):
        self.connect()
        self.network.fail_dns = True
        self.assertEqual(self.script(reason="reconnect"), 1)
        self.assertEqual(set(self.network.routes), set(policy.GUARD_PREFIXES))
        self.assertFalse(policy.session_ready(self.token))
        self.assertIsNotNone(policy.session_failure(self.token))

    def test_disconnect_and_parent_cleanup_are_idempotent(self):
        self.connect()
        self.assertEqual(self.script(reason="disconnect"), 0)
        self.assertEqual(self.network.routes, {})
        self.assertEqual(self.network.dns, {})
        self.child_alive = False
        policy.cleanup_session(self.token)
        policy.cleanup_session(self.token)
        base_calls = [kwargs["env"] for argv, kwargs in self.network.calls if argv[0] == str(self.base_script)]
        self.assertTrue(all(env["INTERNAL_IP4_DNS"] == env["INTERNAL_IP6_DNS"] == "" for env in base_calls))

    def test_stale_live_owned_child_gets_only_sigterm_before_cleanup(self):
        self.connect()
        self.owner_alive = False
        self.signal_mock.side_effect = lambda pid, signum: setattr(self, "child_alive", False)
        policy.cleanup_stale_sessions()
        self.signal_mock.assert_called_once_with(424242, signal.SIGTERM)
        self.assertEqual(self.network.routes, {})

    def test_stale_child_timeout_retains_protection(self):
        self.connect()
        self.owner_alive = False
        self.signal_mock.side_effect = None
        with patch.object(policy.time, "monotonic", side_effect=[0, 11]):
            with self.assertRaises(policy.NetworkPolicyError):
                policy.cleanup_stale_sessions()
        self.signal_mock.assert_called_once_with(424242, signal.SIGTERM)
        self.assertEqual(set(self.network.routes), set(policy.GUARD_PREFIXES))

    def test_reused_pid_is_never_signaled(self):
        self.connect()
        self.owner_alive = False
        self.child_identity = "different process birth identity"
        policy.cleanup_stale_sessions()
        self.signal_mock.assert_not_called()

    def test_spawn_failure_unbound_session_can_be_cleaned(self):
        policy.cleanup_session(self.token)
        self.assertFalse((self.state_dir / (self.token + ".json")).exists())

    def test_journal_contains_only_validated_network_fields(self):
        self.connect(COOKIE="private-cookie-fixture", CISCO_BANNER="private-banner-fixture",
                     OTHER_SECRET="private-secret-fixture")
        raw = (self.state_dir / (self.token + ".json")).read_text()
        self.assertNotIn("private-", raw)
        self.assertEqual(self.state_dir.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.state_dir / (self.token + ".json")).stat().st_mode & 0o777, 0o600)

    def test_invalid_network_fields_fail_before_system_commands(self):
        cases = ({"TUNDEV": "en0"}, {"VPNGATEWAY": "-interface"},
                 {"CISCO_SPLIT_INC": "$(id)"}, {"INTERNAL_IP4_ADDRESS": "10.0.0.1\nother"})
        for case in cases:
            with self.subTest(case=next(iter(case))):
                self.assertEqual(self.script(**case), 1)
        self.assertEqual(self.network.calls, [])

    def test_unprivileged_entry_rejects_before_any_commands(self):
        with patch.object(policy, "_require_root", side_effect=policy.NetworkPolicyError("root required")):
            self.assertEqual(self.script(), 1)
        self.assertEqual(self.network.calls, [])

    def test_exact_guard_ownership_survives_more_specific_shadow_route(self):
        self.network.routes["8000::/64"] = self.network.route(
            "8000::/64", interface="en0", gateway="fe80::1%en0", flags={"UP", "GATEWAY"})
        self.connect()
        self.child_alive = False
        policy.cleanup_session(self.token)
        self.assertEqual(set(self.network.routes), {"8000::/64"})

    def test_full_tunnel_dns_cannot_escape_on_more_specific_physical_route(self):
        self.network.routes["10.2.3.4/32"] = self.network.route(
            "10.2.3.4/32", interface="en0", gateway="192.0.2.1", flags={"UP", "GATEWAY", "HOST"})
        self.assertEqual(self.script(), 1)
        self.assertEqual(self.network.dns, {})
        self.assertIsNotNone(policy.session_failure(self.token))

    def test_public_cleanup_normalizes_dns_error(self):
        self.connect()
        self.child_alive = False
        with patch.object(policy.network_dns, "remove_dns", side_effect=policy.network_dns.NetworkDNSError("fixture failure")):
            with self.assertRaises(policy.NetworkPolicyError):
                policy.cleanup_session(self.token)

    def test_status_reads_do_not_take_script_lock(self):
        self.connect()
        with patch.object(policy, "_locked", side_effect=AssertionError("Status must not lock")):
            self.assertTrue(policy.session_ready(self.token))
            self.assertIsNone(policy.session_failure(self.token))


if __name__ == "__main__":
    unittest.main()
