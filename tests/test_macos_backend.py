"""macOS helper IPC and worker regressions without privileges or VPN traffic."""

import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "codebase"), str(ROOT / "codebase/ui/src")]

# Import shared dependencies on the real host before selecting the backend branch.
import vpn_ui.backend.shared
from vpn_ui.worker import VPNConnectWorker
from vpn_ui.backend.base import VPNConnectionError


def load_backend(platform):
    spec = importlib.util.spec_from_file_location(
        f"vpn_ui.platform._test_{platform}_backend",
        ROOT / "codebase/ui/src/vpn_ui/platform/backend.py",
    )
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, "platform", platform):
        spec.loader.exec_module(module)
    return module


macos = load_backend("darwin")
linux = load_backend("linux")
HEALTH = {"pong": True, "version": "1.2.0"}


def response(result):
    return json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}).encode() + b"\n"


class FakeSocket:
    def __init__(self, reply=b"", *, failure=None, fragment_size=65536):
        self.reply = reply
        self.failure = failure
        self.fragment_size = fragment_size
        self.sent = b""
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def settimeout(self, value):
        pass

    def connect(self, path):
        self.path = path
        if self.failure:
            raise self.failure

    def sendall(self, data):
        self.sent += data

    def recv(self, size):
        count = min(size, self.fragment_size)
        chunk, self.reply = self.reply[:count], self.reply[count:]
        return chunk


class MacOSBackendTests(unittest.TestCase):
    def setUp(self):
        self.backend = macos.VPNBackend()

    def test_healthy_helper_connect_disconnect_and_status_need_no_process(self):
        sockets = [FakeSocket(response(result)) for result in (
            HEALTH, HEALTH,
            {"success": True, "message": "Connected"},
            {"connected": True, "connection_name": "work", "pid": 123},
            {"success": True, "message": "Disconnected"},
        )]
        with patch.object(macos.socket, "socket", side_effect=sockets), \
                patch("subprocess.Popen") as spawn, patch("subprocess.run") as run, \
                patch.object(self.backend, "clear_stored_cookies") as clear:
            self.backend.ensure_helper_available()
            self.assertTrue(self.backend.connect_vpn(
                "vpn.example.test", "anyconnect", {"webvpn": "fixture"},
                connection_name="work", allow_fallback=True,
            ))
            self.assertTrue(self.backend.is_connected())
            self.assertTrue(self.backend.disconnect(force=True))
            clear.assert_called_once_with()
            spawn.assert_not_called()
            run.assert_not_called()
        self.assertTrue(all(sock.closed for sock in sockets))
        requests = [json.loads(sock.sent) for sock in sockets]
        self.assertEqual([r["method"] for r in requests], ["ping", "ping", "connect", "status", "disconnect"])
        self.assertEqual(requests[2]["params"]["cookies"], {"webvpn": "fixture"})

    def test_unavailable_helper_never_starts_an_admin_fallback(self):
        for failure in (FileNotFoundError(), PermissionError(), ConnectionRefusedError(), socket.timeout()):
            for operation in ("connect", "disconnect"):
                with self.subTest(failure=type(failure).__name__, operation=operation):
                    sock = FakeSocket(failure=failure)
                    with patch.object(macos.socket, "socket", return_value=sock), \
                            patch("subprocess.Popen") as spawn, patch("subprocess.run") as run:
                        with self.assertRaisesRegex(macos.MacOSHelperUnavailable, "Install or reinstall"):
                            if operation == "connect":
                                self.backend.connect_vpn("vpn.example.test", "anyconnect", {}, allow_fallback=True)
                            else:
                                self.backend.disconnect()
                        spawn.assert_not_called()
                        run.assert_not_called()
                    self.assertTrue(sock.closed)

    def test_fragmented_large_response_and_large_cookie_are_framed(self):
        sock = FakeSocket(response({"success": True, "message": "x" * 100000}), fragment_size=137)
        with patch.object(macos.socket, "socket", side_effect=[FakeSocket(response(HEALTH)), sock]):
            self.assertTrue(self.backend.connect_vpn(
                "vpn.example.test", "anyconnect", {"webvpn": "x" * 100000},
            ))
        self.assertEqual(len(json.loads(sock.sent)["params"]["cookies"]["webvpn"]), 100000)
        self.assertTrue(sock.sent.endswith(b"\n"))
        self.assertTrue(sock.closed)

    def test_request_size_is_bounded_before_sending_credentials(self):
        with patch.object(macos.socket, "socket", return_value=FakeSocket(response(HEALTH))) as socket_factory:
            with self.assertRaises(macos.MacOSHelperUnavailable):
                self.backend.connect_vpn("vpn.example.test", "anyconnect", {
                    "webvpn": "x" * macos.MAX_DAEMON_MESSAGE,
                })
            self.assertEqual(socket_factory.call_count, 1)

    def test_invalid_or_incomplete_responses_fail_closed_and_close_socket(self):
        replies = (
            b"", response({"success": True})[:-1], b"not json\n", b"[]\n",
            b'{"jsonrpc":"2.0","id":2,"result":{"success":true}}\n',
            b'{"jsonrpc":"2.0","id":1,"error":{"message":"failed"}}\n',
            response({"error": "failed"}), response({"success": "yes"}),
            b"x" * macos.MAX_DAEMON_MESSAGE,
        )
        for reply in replies:
            with self.subTest(size=len(reply), prefix=reply[:30]):
                sock = FakeSocket(reply)
                with patch.object(macos.socket, "socket", side_effect=[FakeSocket(response(HEALTH)), sock]):
                    with self.assertRaises(macos.MacOSHelperUnavailable):
                        self.backend.connect_vpn("vpn.example.test", "anyconnect", {})
                self.assertTrue(sock.closed)

    def test_status_is_quiet_for_tray_but_strict_for_active_worker(self):
        with patch.object(self.backend, "_daemon_request", side_effect=macos.MacOSHelperUnavailable("offline")):
            self.assertFalse(self.backend.is_connected())
            with self.assertRaisesRegex(macos.MacOSHelperUnavailable, "offline"):
                self.backend.is_connected(require_helper=True)

    def test_known_failures_preserve_diagnostic_and_retry_policy(self):
        for code, retryable, message in (
            ("openconnect_missing", False, "OpenConnect is not installed in a standard location"),
            ("openconnect_exit", True, "OpenConnect exited before the VPN tunnel was ready"),
        ):
            with self.subTest(code=code), patch.object(self.backend, "_daemon_request", side_effect=[
                {"result": HEALTH}, {"result": {"success": False, "error_code": code,
                    "retryable": retryable, "message": "cookie=secret-should-not-be-used"}},
            ]):
                with self.assertRaises(VPNConnectionError) as error:
                    self.backend.connect_vpn("vpn.example.test", "anyconnect", {})
                self.assertEqual(str(error.exception), message)
                self.assertEqual(error.exception.retryable, retryable)
                self.assertNotIn("secret", str(error.exception))

    def test_unknown_helper_failure_does_not_expose_raw_output_or_retry(self):
        with patch.object(self.backend, "_daemon_request", side_effect=[
            {"result": HEALTH}, {"result": {"success": False, "retryable": True,
                "message": "Set-Cookie: webvpn=secret"}},
        ]):
            with self.assertRaises(VPNConnectionError) as error:
                self.backend.connect_vpn("vpn.example.test", "anyconnect", {})
            self.assertNotIn("secret", str(error.exception))
            self.assertFalse(error.exception.retryable)

    def test_globalprotect_options_are_forwarded_to_helper(self):
        with patch.object(self.backend, "_daemon_request", side_effect=[
            {"result": HEALTH}, {"result": {"success": True}},
        ]) as rpc:
            self.assertTrue(self.backend.connect_vpn(
                "vpn.example.test", "gp", {"prelogin-cookie": "fixture"},
                gp_auth_interface="gateway", gp_os_version="macOS 15.0",
            ))
        self.assertEqual(rpc.call_args.args[1]["gp_auth_interface"], "gateway")
        self.assertEqual(rpc.call_args.args[1]["gp_os_version"], "macOS 15.0")

    def test_cancel_before_connect_or_during_preflight_never_sends_connect(self):
        cancelled = [True]
        with patch.object(self.backend, "_daemon_request") as rpc:
            with self.assertRaisesRegex(VPNConnectionError, "Connection cancelled"):
                self.backend.connect_vpn("vpn.example.test", "anyconnect", {},
                                         cancel_callback=lambda: cancelled[0])
            rpc.assert_not_called()
        cancelled[0] = False
        def ping(*args):
            cancelled[0] = True
            return {"result": HEALTH}
        with patch.object(self.backend, "_daemon_request", side_effect=ping) as rpc:
            with self.assertRaisesRegex(VPNConnectionError, "Connection cancelled"):
                self.backend.connect_vpn("vpn.example.test", "anyconnect", {},
                                         cancel_callback=lambda: cancelled[0])
            rpc.assert_called_once_with("ping", None)

    def test_cancel_after_request_cleans_up_only_an_accepted_connection(self):
        for accepted in (True, False):
            with self.subTest(accepted=accepted):
                cancelled = [False]
                def reply(method, params=None):
                    if method == "ping":
                        return {"result": HEALTH}
                    if method == "connect":
                        cancelled[0] = True
                        return {"result": {"success": accepted, "error_code": "already_connected"}}
                    return {"result": {"success": True}}
                with patch.object(self.backend, "_daemon_request", side_effect=reply) as rpc:
                    with self.assertRaises(VPNConnectionError):
                        self.backend.connect_vpn("vpn.example.test", "anyconnect", {},
                                                 cancel_callback=lambda: cancelled[0])
                methods = [call.args[0] for call in rpc.call_args_list]
                self.assertEqual(methods, ["ping", "connect", "disconnect"] if accepted else ["ping", "connect"])

    def test_linux_backend_keeps_owned_privileged_connection_path(self):
        backend = linux.VPNBackend()
        with patch.object(linux, "core_connect_vpn", return_value=True) as connect:
            self.assertTrue(backend.connect_vpn("vpn.example.test", "gp", {"prelogin-cookie": "fixture"}))
        self.assertTrue(connect.call_args.kwargs["use_pkexec"])


class MacOSWorkerTests(unittest.TestCase):
    def setUp(self):
        self.backend = macos.VPNBackend()
        for method, result in (
            ("get_config", ("work", "vpn.example.test", "anyconnect", "fixture", "fixture", "")),
            ("get_connection", {}), ("get_stored_cookies", None),
            ("do_saml_auth", {"webvpn": "fixture"}), ("store_cookies", True),
            ("clear_stored_cookies", True),
        ):
            setattr(self.backend, method, Mock(return_value=result))
        self.worker = VPNConnectWorker(self.backend, "work")
        self.errors = []
        self.finished = []
        self.worker.error.connect(self.errors.append)
        self.worker.finished.connect(lambda *args: self.finished.append(args))
        self.enterContext(patch.object(sys, "platform", "darwin"))
        self.enterContext(patch.dict(os.environ, {
            "MS_SSO_RECONNECT_DELAY_SECONDS": "0", "MS_SSO_RECONNECT_MAX_ATTEMPTS": "0",
        }))

    def test_missing_helper_stops_before_authentication(self):
        with patch.object(self.backend, "_daemon_request", return_value={"error": {"message": "offline"}}) as rpc:
            self.worker.run()
        rpc.assert_called_once_with("ping", None)
        self.backend.do_saml_auth.assert_not_called()
        self.backend.store_cookies.assert_not_called()
        self.assertEqual(len(self.errors), 1)
        self.assertEqual(self.finished, [(False, self.errors[0])])

    def test_legacy_helper_requires_package_update_before_authentication(self):
        for version in ("1.0.0", "1.1.0", None, "invalid"):
            with self.subTest(version=version):
                self.errors.clear()
                self.finished.clear()
                with patch.object(self.backend, "_daemon_request", return_value={
                    "result": {"pong": True, "version": version},
                }) as rpc:
                    self.worker.run()
                rpc.assert_called_once_with("ping", None)
                self.backend.do_saml_auth.assert_not_called()
                self.assertEqual(len(self.errors), 1)
                self.assertIn("needs an update", self.errors[0])
                self.assertEqual(self.finished, [(False, self.errors[0])])

    def test_cancel_during_worker_preflight_never_authenticates(self):
        def ping(*args):
            self.worker.cancel()
            return {"result": HEALTH}
        with patch.object(self.backend, "_daemon_request", side_effect=ping) as rpc:
            self.worker.run()
        rpc.assert_called_once_with("ping", None)
        self.backend.do_saml_auth.assert_not_called()
        self.assertEqual(self.finished, [(False, "Cancelled")])

    def test_late_cancel_stops_accepted_tunnel_without_announcing_connected(self):
        connected = []
        self.worker.connected.connect(connected.append)
        def reply(method, params=None):
            if method == "ping":
                return {"result": HEALTH}
            if method == "connect":
                self.worker.cancel()
            return {"result": {"success": True}}
        with patch.object(self.backend, "_daemon_request", side_effect=reply) as rpc:
            self.worker.run()
        self.assertEqual([call.args[0] for call in rpc.call_args_list],
                         ["ping", "ping", "connect", "disconnect"])
        self.assertEqual(connected, [])
        self.assertEqual(self.errors, [])
        self.assertEqual(self.finished, [(False, "Cancelled")])

    def test_helper_loss_during_connected_session_stops_reauthentication(self):
        with patch.object(self.backend, "_daemon_request", side_effect=[
            {"result": HEALTH}, {"result": HEALTH},
            {"result": {"success": True}},
            {"error": {"message": "offline"}},
        ]) as rpc:
            self.worker.run()
        self.assertEqual([call.args[0] for call in rpc.call_args_list], ["ping", "ping", "connect", "status"])
        self.backend.do_saml_auth.assert_called_once()
        self.backend.clear_stored_cookies.assert_not_called()
        self.assertEqual(len(self.errors), 1)

    def test_helper_is_checked_again_before_reauthentication(self):
        with patch.object(self.backend, "_daemon_request", side_effect=[
            {"result": HEALTH}, {"result": HEALTH},
            {"result": {"success": False, "error_code": "openconnect_exit", "retryable": True}},
            {"error": {"message": "offline"}},
        ]) as rpc:
            self.worker.run()
        self.assertEqual([call.args[0] for call in rpc.call_args_list], ["ping", "ping", "connect", "ping"])
        self.backend.do_saml_auth.assert_called_once()
        self.assertEqual(len(self.errors), 1)

    def test_globalprotect_gateway_and_os_settings_reach_helper_without_cached_prelogin(self):
        self.backend.get_config.return_value = (
            "work", "vpn.example.test", "gp", "fixture", "fixture", "",
        )
        self.backend.get_connection.return_value = {
            "gp_auth_interface": "gateway", "gp_os_version": "macOS 15.0", "auto_reconnect": False,
        }
        self.backend.get_stored_cookies.return_value = ({"prelogin-cookie": "stale"}, "gateway:prelogin-cookie")
        self.backend.do_saml_auth.return_value = {"prelogin-cookie": "fresh", "saml-username": "normalized"}
        with patch.object(self.backend, "_daemon_request", side_effect=[
            {"result": HEALTH}, {"result": HEALTH}, {"result": {"success": True}},
            {"result": {"connected": False}},
        ]) as rpc:
            self.worker.run()
        params = rpc.call_args_list[2].args[1]
        self.assertEqual(params["gp_auth_interface"], "gateway")
        self.assertEqual(params["gp_os_version"], "macOS 15.0")
        self.assertEqual(params["cookies"], {"prelogin-cookie": "fresh", "saml-username": "normalized"})
        self.backend.do_saml_auth.assert_called_once()
        self.assertEqual(self.errors, [])

    def test_permanent_connection_error_is_reported_once_without_retry(self):
        with patch.object(self.backend, "_daemon_request", side_effect=[
            {"result": HEALTH}, {"result": HEALTH}, {"result": {
                "success": False, "error_code": "openconnect_missing", "retryable": False,
            }},
        ]) as rpc:
            self.worker.run()
        self.assertEqual(rpc.call_count, 3)
        self.assertEqual(self.errors, ["OpenConnect is not installed in a standard location"])
        self.assertEqual(self.finished, [(False, self.errors[0])])
        self.backend.do_saml_auth.assert_called_once()

    def test_transient_failure_is_visible_immediately_and_in_final_result(self):
        progress = []
        self.worker.progress.connect(progress.append)
        with patch.dict(os.environ, {"MS_SSO_RECONNECT_MAX_ATTEMPTS": "1"}), \
                patch.object(self.backend, "_daemon_request", side_effect=[
                    {"result": HEALTH}, {"result": HEALTH}, {"result": {
                        "success": False, "error_code": "openconnect_exit", "retryable": True,
                        "exit_status": 1, "message": "Set-Cookie: webvpn=secret",
                    }},
                ]):
            self.worker.run()
        expected = "OpenConnect exited before the VPN tunnel was ready (exit status 1)"
        self.assertIn(expected, progress)
        self.assertIn(expected, self.finished[0][1])
        self.assertFalse(any("secret" in message for message in progress))
        self.assertEqual(self.errors, [])

    def test_linux_worker_does_not_require_macos_helper(self):
        with patch.object(sys, "platform", "linux"), \
                patch.object(self.backend, "ensure_helper_available") as preflight, \
                patch.object(self.backend, "connect_vpn", return_value=True):
            self.worker.run()
        preflight.assert_not_called()
        self.backend.do_saml_auth.assert_called_once()
        self.assertEqual(self.errors, [])
        self.assertEqual(self.finished, [(False, "Disconnected")])


class MacOSApplicationTests(unittest.TestCase):
    def setUp(self):
        from vpn_ui.main import VPNApplication
        self.app = VPNApplication.__new__(VPNApplication)
        self.app.app = Mock()
        self.app.backend = Mock()
        self.app.backend.is_connected.return_value = False
        self.app.notifications = Mock()
        self.app.tray = Mock()
        self.app._worker_thread = None
        self.app._retired_threads = []
        self.app._disconnecting = False
        self.app._quitting = False
        self.app._number_match_dialog = None
        self.app._current_connection = "work"

    def test_handover_helper_failure_is_reported_without_starting_another_connection(self):
        from PyQt6.QtWidgets import QMessageBox
        self.app.tray.get_status.return_value = "connected"
        self.app.backend.disconnect.side_effect = macos.MacOSHelperUnavailable("Helper unavailable")
        with patch("vpn_ui.main.QMessageBox.question", return_value=QMessageBox.StandardButton.Yes), \
                patch("vpn_ui.main.create_connect_thread") as create:
            self.app._on_connect_requested("other")
        self.app.notifications.error.assert_called_once_with("Helper unavailable")
        self.app.backend.clear_active_connection.assert_not_called()
        create.assert_not_called()
        self.assertEqual(self.app._current_connection, "work")

    def test_idle_app_quits_without_contacting_missing_helper_for_disconnect(self):
        with patch("vpn_ui.main.create_disconnect_thread") as create:
            self.app._quit()
        create.assert_not_called()
        self.app.backend.disconnect.assert_not_called()
        self.app.app.quit.assert_called_once_with()

    def test_failed_disconnect_restores_tray_and_still_allows_idle_quit(self):
        self.app._quitting = True
        self.app._disconnecting = True
        self.app._on_disconnect_finished(False, "Helper unavailable")
        self.assertFalse(self.app._quitting)
        self.app.tray.show.assert_called_once_with()
        self.app.notifications.error.assert_called_once_with("Helper unavailable")
        self.app.backend.clear_active_connection.assert_not_called()
        with patch("vpn_ui.main.create_disconnect_thread") as create:
            self.app._quit()
        create.assert_not_called()
        self.app.app.quit.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
