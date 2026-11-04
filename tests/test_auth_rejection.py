"""Credential rejection evidence, using only fake credentials and routed pages."""

import ast
import sys
import time
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "codebase"))
from core import auth
from playwright.sync_api import sync_playwright


def _nested_auth_function(name, **overrides):
    """Exercise the actual late guard without starting an authentication flow."""
    tree = ast.parse(Path(auth.__file__).read_text())
    function = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    namespace = dict(vars(auth))
    namespace.update(overrides)
    exec(compile(ast.Module(body=[function], type_ignores=[]), auth.__file__, "exec"), namespace)
    return namespace[name]


class CredentialErrorProbeTests(unittest.TestCase):
    def test_only_observed_boolean_results_are_conclusive(self):
        for value in (True, False, None, "true", {}, 0, 1):
            with self.subTest(value=value):
                page = Mock()
                page.evaluate.return_value = value
                expected = value if isinstance(value, bool) else None
                self.assertIs(auth._probe_top_page_credential_error(page), expected)

    def test_navigation_read_failure_is_unknown_instead_of_rejected(self):
        page = Mock()
        page.evaluate.side_effect = RuntimeError(
            "Execution context was destroyed, most likely because of a navigation"
        )
        self.assertIsNone(auth._probe_top_page_credential_error(page))

    def test_late_password_guard_blocks_unknown_or_rejected_page(self):
        origin = "https://login.microsoftonline.com"
        control = auth._PasswordControlSecurityEvidence(
            identity="document:password",
            value_known=True,
            value_empty=True,
            https_origin=origin,
            form_identity="document:form",
            form_signature="fixture-form",
            form_action_origin=origin,
            form_method="post",
        )
        authorization = auth._GpClientPasswordStageAuthorization(
            route="client",
            main_navigation_generation=0,
            unsafe_write_generation=0,
            taint_generation=0,
            document_generation=0,
            federated_navigation_generation=0,
            authorized_origin=origin,
            control_identity=control.identity,
            control_origin=origin,
            top_origin=origin,
            form_identity=control.form_identity,
            form_signature=control.form_signature,
            form_action_origin=origin,
            form_method="post",
        )
        dispatch = SimpleNamespace(
            main_frame_navigation_request_generation=0,
            unsafe_write_request_generation=0,
            credential_taint_generation=0,
            main_document_generation=0,
            pending_main_frame_navigation_count=0,
        )
        for error_state in (None, True, False):
            with self.subTest(error_state=error_state):
                guard = _nested_auth_function(
                    "_validate_gp_client_password_stage",
                    _password_control_security_evidence=lambda locator: control,
                    _top_page_https_origin=lambda: origin,
                    _top_page_credential_error_visible=lambda: error_state,
                    _gp_password_stage_origin_policy_valid=lambda *args: True,
                    sensitive_dispatch_evidence=dispatch,
                    vpn_server_host="vpn.fixture.test",
                )
                if error_state is False:
                    guard(object(), authorization, require_empty=True)
                else:
                    with self.assertRaises(auth._SensitiveActionUncertainError):
                        guard(object(), authorization, require_empty=True)


class CredentialErrorBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.playwright = sync_playwright().start()
        try:
            cls.browser = cls.playwright.chromium.launch(
                headless=True, args=["--no-sandbox"]
            )
        except Exception:
            cls.playwright.stop()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()

    def test_only_rendered_error_text_counts_across_all_evidence_readers(self):
        security_probe = _nested_auth_function("_password_control_security_evidence")
        fixtures = (
            ("<div id='passwordError' style='height:20px'>"
             "<span style='display:none'>Your password is incorrect</span></div>", False),
            ("<div id='passwordError' style='display:none'>"
             "Your password is incorrect</div>", False),
            ("<div id='passwordError'>Your password is incorrect</div>", True),
        )
        page = self.browser.new_page()
        try:
            for markup, expected in fixtures:
                with self.subTest(markup=markup):
                    page.set_content(
                        "<form method='post'><input type='password'>" + markup + "</form>"
                    )
                    self.assertIs(auth._probe_top_page_credential_error(page), expected)
                    self.assertIs(
                        security_probe(page.locator("input")).credential_error_visible,
                        expected,
                    )
                    snapshot = auth._capture_rendered_auth_ui(page)
                    self.assertIs(
                        auth._snapshot_selector_has_nonempty_text(
                            snapshot, auth.MICROSOFT_CREDENTIAL_ERROR_TEXT_SELECTORS
                        ),
                        expected,
                    )
        finally:
            page.close()

    def _run_password_flow_with_unreadable_page(
        self, *, persistent, callback_at_deadline=False,
    ):
        context = self.browser.new_context()
        page = context.new_page()
        posts = []
        probe_attempts = []

        def route_request(route):
            if route.request.method == "POST":
                posts.append(route.request.url)
                route.fulfill(content_type="text/html", body="<h1>Signing in...</h1>")
            elif "/+CSCOE+/" in route.request.url:
                route.fulfill(content_type="text/html", body="""<script>
                    location.replace('https://login.microsoftonline.com/local-fixture');
                </script>""")
            else:
                route.fulfill(content_type="text/html", body="""
                    <form method="post" action="/password">
                      <input id="i0118" name="passwd" type="password"
                        autocomplete="current-password">
                      <button type="submit">Sign in</button>
                    </form>""")

        context.route("**/*", route_request)
        original_evaluate = page.evaluate

        def complete_vpn_callback():
            # A local stand-in for the VPN's successful SAML callback.
            context.add_cookies([
                {"name": name, "value": "fixture-only", "url": "https://vpn.fixture.test"}
                for name in ("webvpn", "webvpnc")
            ])

        def navigation_sensitive_evaluate(expression, *args, **kwargs):
            if expression == auth._TOP_PAGE_CREDENTIAL_ERROR_SCRIPT and posts:
                probe_attempts.append(time.monotonic())
                if persistent or len(probe_attempts) == 1:
                    if callback_at_deadline:
                        complete_vpn_callback()
                    raise RuntimeError(
                        "Execution context was destroyed, most likely because of a navigation"
                    )
                result = original_evaluate(expression, *args, **kwargs)
                complete_vpn_callback()
                return result
            return original_evaluate(expression, *args, **kwargs)

        chromium = SimpleNamespace(
            executable_path=self.playwright.chromium.executable_path,
            launch_persistent_context=lambda *args, **kwargs: context,
        )
        deadline = time.monotonic() + 15
        inspection_window = 0.0 if callback_at_deadline else (0.2 if persistent else 8.0)
        try:
            with patch.object(page, "evaluate", side_effect=navigation_sensitive_evaluate), \
                 patch.object(auth, "sync_playwright", return_value=nullcontext(
                     SimpleNamespace(chromium=chromium)
                 )), patch.object(auth, "SAML_UI_STALL_WINDOW_SECONDS", inspection_window):
                try:
                    result = auth.do_saml_auth(
                        "vpn.fixture.test", "fixture@example.test", "fixture-password",
                        disable_browser_session_cache=True,
                        cancel_callback=lambda: time.monotonic() > deadline,
                    )
                except auth.SamlSensitiveActionError as error:
                    result = error
        finally:
            context.close()
        self.assertEqual(posts, ["https://login.microsoftonline.com/password"])
        if callback_at_deadline:
            self.assertEqual(len(probe_attempts), 1)
        else:
            self.assertGreaterEqual(len(probe_attempts), 2)
        return result

    def test_transient_navigation_read_failure_recovers_without_password_replay(self):
        result = self._run_password_flow_with_unreadable_page(persistent=False)
        self.assertIsInstance(result, dict)
        self.assertEqual(set(result), {"webvpn", "webvpnc"})

    def test_callback_during_failed_inspection_at_deadline_still_succeeds(self):
        result = self._run_password_flow_with_unreadable_page(
            persistent=False, callback_at_deadline=True,
        )
        self.assertIsInstance(result, dict)
        self.assertEqual(set(result), {"webvpn", "webvpnc"})

    def test_persistent_unreadability_reports_uncertain_outcome_without_replay(self):
        result = self._run_password_flow_with_unreadable_page(persistent=True)
        self.assertIsInstance(result, auth.SamlSensitiveActionError)
        self.assertEqual(
            str(result),
            "Could not inspect the sign-in page after submission; "
            "the authentication outcome is uncertain",
        )
        self.assertNotIn("rejected", str(result).lower())


if __name__ == "__main__":
    unittest.main()
