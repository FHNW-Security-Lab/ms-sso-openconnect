"""Safe, durable connection diagnostics without real authentication or notifications."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch
from urllib.parse import quote

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "codebase"), str(ROOT / "codebase/ui/src")]

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication
from vpn_ui.main import VPNApplication
from vpn_ui.tray import VPNTrayIcon
from vpn_ui.worker import VPNConnectWorker, sanitize_failure


class SanitizerTests(unittest.TestCase):
    def test_playwright_multiline_call_log_is_not_exposed(self):
        message = "Locator.fill: Timeout 2000ms exceeded.\nCall log:\n  fill('private-value')"
        self.assertEqual(sanitize_failure(message), "Locator.fill: Timeout 2000ms exceeded.")

    def test_authentication_urls_keep_location_without_credentials_or_query(self):
        result = sanitize_failure(
            "Page.goto failed at https://user:private@example.test/login?code=private#token-value"
        )
        self.assertEqual(result, "Page.goto failed at https://example.test/login?[redacted]")

    def test_known_secrets_and_escaped_encoded_variants_are_removed(self):
        secret = 'example "password"/with\\spaces'
        variants = (secret, json.dumps(secret)[1:-1], quote(secret, safe=""))
        for variant in variants:
            with self.subTest(variant=variant):
                result = sanitize_failure(f"Authentication rejected {variant}", (secret,))
                self.assertEqual(result, "Authentication rejected [redacted]")

    def test_headers_and_named_tokens_are_removed_and_output_is_bounded(self):
        self.assertNotIn("private", sanitize_failure("Authentication error; Cookie: webvpn=private; x=private"))
        self.assertNotIn("private", sanitize_failure("Authentication error access_token=private"))
        result = sanitize_failure("Authentication error " + "x" * 1000)
        self.assertLessEqual(len(result), 300)
        self.assertTrue(result.endswith("…"))


class AuthFailureTests(unittest.TestCase):
    def setUp(self):
        self.backend = Mock()
        self.backend.get_config.return_value = (
            "work", "vpn.example.test", "gp", "fixture-user", "fixture-password", "fixture-totp",
        )
        self.backend.get_connection.return_value = {}
        self.backend.get_stored_cookies.return_value = None
        self.worker = VPNConnectWorker(self.backend, "work")
        self.finished, self.progress, self.errors = [], [], []
        self.worker.finished.connect(lambda *args: self.finished.append(args))
        self.worker.progress.connect(self.progress.append)
        self.worker.error.connect(self.errors.append)
        self.enterContext(patch.dict(os.environ, {
            "MS_SSO_RECONNECT_MAX_ATTEMPTS": "2", "MS_SSO_RECONNECT_DELAY_SECONDS": "0",
        }))

    def test_first_authentication_cause_survives_retry_exhaustion_safely(self):
        self.backend.do_saml_auth.side_effect = [
            RuntimeError("Page.goto: DNS lookup failed at https://login.example.test/?token=private\nCall log: fixture-password"),
            RuntimeError("Later authentication failure: fixture-totp"),
        ]
        self.worker.run()
        message = self.finished[0][1]
        self.assertIn("DNS lookup failed", message)
        self.assertNotIn("Later authentication failure", message)
        self.assertNotIn("private", message)
        self.assertNotIn("fixture-password", " ".join(self.progress))
        self.assertNotIn("fixture-totp", " ".join(self.progress))
        self.assertNotIn("Call log", message)
        self.assertLessEqual(len(message), 300)
        retry_messages = [value for value in self.progress if value.startswith("Connection lost")]
        self.assertEqual(len(retry_messages), 1)
        self.assertIn("DNS lookup failed", retry_messages[0])
        self.backend.connect_vpn.assert_not_called()
        self.assertEqual(self.errors, [])

    def test_config_and_cached_cookie_secrets_are_removed_from_terminal_errors(self):
        self.backend.get_config.return_value = (
            "work", "vpn.example.test", "anyconnect", "fixture-user", "fixture-password", "fixture-totp",
        )
        self.backend.get_stored_cookies.return_value = ({"webvpn": "fixture-cookie"}, None)
        self.backend.connect_vpn.side_effect = RuntimeError(
            "Unexpected fixture-password fixture-cookie failure\nPlaywright full call log"
        )
        self.worker.run()
        self.assertEqual(self.errors, ["Unexpected [redacted] [redacted] failure"])
        self.assertEqual(self.finished, [(False, self.errors[0])])

    def test_explicit_visible_authentication_does_not_automatically_retry(self):
        self.worker.visible = True
        self.worker.single_attempt = True
        self.backend.do_saml_auth.side_effect = RuntimeError("Visible sign-in did not finish")
        self.worker.run()
        self.backend.do_saml_auth.assert_called_once()
        self.assertFalse(self.backend.do_saml_auth.call_args.kwargs["headless"])
        self.assertIn("Visible sign-in did not finish", self.finished[0][1])
        self.backend.connect_vpn.assert_not_called()

    def test_visible_session_loss_does_not_reset_reauthentication_budget(self):
        self.worker.visible = True
        self.worker.single_attempt = True
        self.backend.do_saml_auth.return_value = {"prelogin-cookie": "fixture-cookie"}
        now = [0]
        def connect(**kwargs):
            if self.backend.connect_vpn.call_count > 1:
                raise AssertionError("Unexpected automatic visible sign-in")
            kwargs["connected_callback"]()
            now[0] = 120
            return False
        self.backend.connect_vpn.side_effect = connect
        with patch.object(sys, "platform", "linux"), \
                patch("vpn_ui.worker.time.monotonic", side_effect=lambda: now[0]):
            self.worker.run()
        self.backend.do_saml_auth.assert_called_once()
        self.backend.connect_vpn.assert_called_once()
        self.assertEqual(self.errors, [])

    def test_normal_visible_globalprotect_keeps_reconnect_after_stable_session(self):
        self.worker.visible = True
        self.backend.do_saml_auth.return_value = {"prelogin-cookie": "fixture-cookie"}
        self.backend.connect_vpn.side_effect = [True, False, False]
        now = [0]
        def disconnected(**kwargs):
            now[0] = 120
            return False
        self.backend.is_connected.side_effect = disconnected
        with patch.object(sys, "platform", "darwin"), \
                patch("vpn_ui.worker.time.monotonic", side_effect=lambda: now[0]):
            self.worker.run()
        self.assertEqual(self.backend.do_saml_auth.call_count, 3)
        self.assertEqual(self.backend.connect_vpn.call_count, 3)
        self.assertFalse(self.backend.do_saml_auth.call_args.kwargs["headless"])
        self.assertEqual(self.errors, [])


class NativeNotificationTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location(
            "test_macos_notifications", ROOT / "codebase/ui/src/vpn_ui/platform/notifications.py",
        )
        self.module = importlib.util.module_from_spec(spec)
        self.enterContext(patch.object(sys, "platform", "darwin"))
        spec.loader.exec_module(self.module)
        self.tray = Mock()
        self.manager = self.module.NotificationManager(self.tray)

    def test_quotes_backslashes_and_newlines_are_arguments_not_applescript(self):
        title, message = 'VPN "Error"', 'Failure "quoted" \\ text\nsecond line'
        with patch.object(self.module.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
            self.manager.show(title, message, critical=True)
        argv = run.call_args.args[0]
        self.assertEqual(argv[-2:], [title, message])
        self.assertNotIn(title, argv[2])
        self.assertNotIn(message, argv[2])
        self.assertIn("item 2 of argv", argv[2])
        self.tray.showMessage.assert_not_called()

    def test_nonzero_exit_and_timeout_fall_back_to_qt_notification(self):
        for outcome in (subprocess.CompletedProcess([], 1), subprocess.TimeoutExpired("osascript", 5)):
            with self.subTest(outcome=type(outcome).__name__):
                self.tray.reset_mock()
                kwargs = {"side_effect": outcome} if isinstance(outcome, Exception) else {"return_value": outcome}
                with patch.object(self.module.subprocess, "run", **kwargs):
                    self.manager.error("Safe diagnostic")
                self.tray.showMessage.assert_called_once()
                self.assertEqual(self.tray.showMessage.call_args.args[1], "Safe diagnostic")


class ErrorDialogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.qt_app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.app = VPNApplication.__new__(VPNApplication)
        self.app.app = self.qt_app
        self.app.backend = Mock()
        self.app.backend.is_connected.return_value = False
        self.app.notifications = Mock()
        self.app.tray = Mock()
        self.app.tray.get_status.return_value = "disconnected"
        self.app._worker_thread = None
        self.app._retired_threads = []
        self.app._number_match_dialog = None
        self.app._error_dialog = None
        self.app._last_reported_error = None
        self.app._quitting = False
        self.app._disconnecting = False
        self.app._current_connection = "work"

    def tearDown(self):
        self.app._quitting = True
        self.app._close_error_dialog()
        self.qt_app.processEvents()

    def test_error_and_finished_signals_show_one_persistent_plaintext_nonmodal_dialog(self):
        with patch("vpn_ui.main.create_connect_thread") as create:
            self.app._on_error("Sign-in unavailable: <fixture error>")
            self.app._on_connect_finished(False, "Sign-in unavailable: <fixture error>")
            self.qt_app.processEvents()
            create.assert_not_called()
        self.app.notifications.error.assert_called_once_with("Sign-in unavailable: <fixture error>")
        dialog = self.app._error_dialog
        self.assertIsNotNone(dialog)
        self.assertTrue(dialog.isVisible())
        self.assertFalse(dialog.isModal())
        self.assertEqual(dialog.textFormat(), Qt.TextFormat.PlainText)
        self.assertEqual(dialog.text(), "Sign-in unavailable: <fixture error>")
        self.qt_app.processEvents()
        self.assertIs(self.app._error_dialog, dialog)
        dialog.close()
        self.qt_app.processEvents()
        self.assertIsNone(self.app._error_dialog)

    def test_progress_does_not_open_error_dialog_and_quitting_cancels_pending_dialog(self):
        self.app._on_progress("Sign-in unavailable: temporary failure")
        self.qt_app.processEvents()
        self.assertIsNone(self.app._error_dialog)
        self.app.notifications.error.assert_not_called()
        self.app._report_error("Terminal failure")
        self.app._quitting = True
        self.qt_app.processEvents()
        self.assertIsNone(self.app._error_dialog)

    def test_new_manual_attempt_can_report_same_failure_again(self):
        self.app._report_error("Repeated failure")
        self.qt_app.processEvents()
        with patch("vpn_ui.main.create_connect_thread", return_value=Mock()):
            self.app._on_connect_requested("work")
        self.assertIsNone(self.app._error_dialog)
        self.app._on_error("Repeated failure")
        self.qt_app.processEvents()
        self.assertEqual(self.app.notifications.error.call_count, 2)
        self.assertTrue(self.app._error_dialog.isVisible())

    def test_browser_retry_preserves_failed_profile_after_connection_state_clears(self):
        self.app._current_connection = "Unibas"
        with patch("vpn_ui.main.create_connect_thread", return_value=Mock()) as create:
            self.app._on_error("Microsoft sign-in did not finish")
            self.app._on_connect_finished(False, "Microsoft sign-in did not finish")
            self.qt_app.processEvents()
            self.assertIsNone(self.app._current_connection)
            create.assert_not_called()
            dialog = self.app._error_dialog
            self.assertEqual(dialog.property("connectionName"), "Unibas")
            self.assertTrue(dialog.retry_browser_button.isVisible())
            dialog.retry_browser_button.click()
            create.assert_called_once()
        self.assertEqual(create.call_args.args[1], "Unibas")
        self.assertTrue(create.call_args.kwargs["visible"])
        self.assertTrue(create.call_args.kwargs["no_cache"])
        self.assertTrue(create.call_args.kwargs["single_attempt"])
        self.assertEqual(self.app._current_connection, "Unibas")

    def test_browser_retry_respects_running_retired_thread_guard(self):
        self.app._report_error("Microsoft sign-in did not finish", connection_name="Unibas")
        self.qt_app.processEvents()
        self.app._retired_threads = [Mock()]
        self.app._retired_threads[0].isRunning.return_value = True
        with patch("vpn_ui.main.create_connect_thread") as create, \
                patch("vpn_ui.main.QMessageBox.warning") as warn:
            self.app._error_dialog.retry_browser_button.click()
        create.assert_not_called()
        warn.assert_called_once()

    def test_explicit_browser_connect_and_normal_connect_keep_distinct_defaults(self):
        with patch("vpn_ui.main.create_connect_thread", return_value=Mock()) as create:
            self.app._on_browser_connect_requested("Unibas")
        self.assertTrue(create.call_args.kwargs["visible"])
        self.assertTrue(create.call_args.kwargs["no_cache"])
        self.assertTrue(create.call_args.kwargs["single_attempt"])
        self.app._worker_thread = None
        with patch("vpn_ui.main.create_connect_thread", return_value=Mock()) as create:
            self.app._on_connect_requested("Unibas")
        self.assertFalse(create.call_args.kwargs["visible"])
        self.assertFalse(create.call_args.kwargs["no_cache"])
        self.assertFalse(create.call_args.kwargs["single_attempt"])

    def test_normal_mac_globalprotect_opens_browser_without_disabling_reconnect_or_cache(self):
        for platform, protocol, visible in (("darwin", "gp", True), ("darwin", "anyconnect", False),
                                            ("linux", "gp", False), ("linux", "anyconnect", False)):
            with self.subTest(platform=platform, protocol=protocol):
                self.app._worker_thread = None
                self.app.backend.get_connection.return_value = {"protocol": protocol}
                with patch.object(sys, "platform", platform), \
                        patch("vpn_ui.main.create_connect_thread", return_value=Mock()) as create:
                    self.app._on_connect_requested("Unibas")
                self.assertEqual(create.call_args.kwargs["visible"], visible)
                self.assertFalse(create.call_args.kwargs["single_attempt"])
                self.assertFalse(create.call_args.kwargs["no_cache"])

    def test_nonconnection_error_has_no_browser_retry_action(self):
        self.app._report_error("Unable to disconnect the previous VPN")
        self.qt_app.processEvents()
        self.assertFalse(self.app._error_dialog.retry_browser_button.isVisible())


class BrowserMenuTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.qt_app = QApplication.instance() or QApplication([])

    def test_browser_connection_action_is_explicit_and_follows_status_availability(self):
        tray = VPNTrayIcon()
        normal, visible = [], []
        tray.connect_requested.connect(normal.append)
        tray.connect_with_browser_requested.connect(visible.append)
        try:
            tray.update_connections({"Unibas": {"protocol": "gp"}, "Work": {"protocol": "anyconnect"}})
            self.assertEqual(visible, [])
            tray._browser_connections_menu.actions()[0].trigger()
            self.assertEqual(visible, ["Unibas"])
            self.assertEqual(normal, [])
            tray._connections_menu.actions()[1].trigger()
            self.assertEqual(normal, ["Work"])
            for status in ("connecting", "connected"):
                tray.set_status(status, "Unibas")
                self.assertFalse(tray._browser_connections_menu.isEnabled())
            tray.set_status("disconnected")
            self.assertTrue(tray._browser_connections_menu.isEnabled())
            tray.update_connections({})
            self.assertFalse(tray._browser_connections_menu.isEnabled())
            self.assertEqual(tray._browser_connections_menu.actions(), [])
        finally:
            tray.menu.close()
            tray.deleteLater()
            self.qt_app.processEvents()


if __name__ == "__main__":
    unittest.main()
