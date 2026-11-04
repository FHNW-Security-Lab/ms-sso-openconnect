"""Local GP federation timing fixtures; all requests and credentials are fake."""

import base64
import functools
import sys
import time
import unittest
from contextlib import ExitStack, nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "codebase"))
from core import auth
from playwright.sync_api import sync_playwright


class GlobalProtectObservationTests(unittest.TestCase):
    OBSERVATION_SECONDS = 1.5
    STALL_SECONDS = 0.6
    FEDERATION_DELAY_MS = 1100

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

    def _run_fixture(self, *, federated=False, recover=False):
        context = self.browser.new_context()
        page = context.new_page()
        start_url = "https://login.microsoftonline.com/local-start"
        institutional_url = "https://login.fixture.test/adfs/ls/"
        start_visits = []
        password_inputs = []
        password_posts = []
        progress = []
        primed_documents = []

        context.expose_binding(
            "fixturePasswordInput",
            lambda source, host: password_inputs.append(host),
        )

        def password_form(*, institutional):
            input_id = "passwordInput" if institutional else "i0118"
            username_field = (
                '<input id="userNameInput" name="UserName" type="text">'
                if institutional else ""
            )
            markup = f"""
                <form method="post" action="/password">
                  {username_field}
                  <input id="{input_id}" name="passwd" type="password"
                    autocomplete="current-password">
                  <button type="submit">Sign in</button>
                </form>
                <script>
                  document.querySelector('input[type=password]').addEventListener(
                    'input', () => fixturePasswordInput(location.hostname));
                </script>"""
            if federated and not institutional:
                markup += f"""<script>
                    setTimeout(() => location.replace('{institutional_url}'),
                               {self.FEDERATION_DELAY_MS});
                </script>"""
            return markup

        def route_request(route):
            parsed = urlsplit(route.request.url)
            if route.request.method == "POST" and parsed.path == "/password":
                password_posts.append((parsed.hostname, time.monotonic()))
                # Model the IdP's successful callback without a network service.
                route.fulfill(content_type="text/html", body="""
                    <form method="post" action="https://vpn.fixture.test/callback">
                      <input name="prelogin-cookie" value="fixture-only">
                    </form><script>document.querySelector('form').submit();</script>
                """)
            elif parsed.hostname == "vpn.fixture.test":
                route.fulfill(content_type="text/html", body="<p>Connected</p>")
            elif route.request.url == start_url:
                start_visits.append(time.monotonic())
                body = (
                    "<h1>Loading sign-in page</h1>"
                    if recover and len(start_visits) == 1
                    else password_form(institutional=False)
                )
                route.fulfill(content_type="text/html", body=body)
            elif route.request.url == institutional_url:
                route.fulfill(
                    content_type="text/html", body=password_form(institutional=True)
                )
            else:
                route.abort()

        context.route("**/*", route_request)
        original_prime = auth._prime_gp_microsoft_federation_render

        def prime_federation(browser_page, protocol, host):
            result = original_prime(browser_page, protocol, host)
            if result:
                primed_documents.append(len(start_visits))
            return result

        chromium = SimpleNamespace(
            executable_path=self.playwright.chromium.executable_path,
            launch_persistent_context=lambda *args, **kwargs: context,
        )
        observation = functools.partial(
            auth._gp_initial_password_observation_required,
            observation_seconds=self.OBSERVATION_SECONDS,
            navigation_max_seconds=3.0,
        )
        stale_recovery = functools.partial(
            auth._stale_ui_recovery_action, stall_window=self.STALL_SECONDS,
        )
        deadline = time.monotonic() + 10
        try:
            with ExitStack() as stack:
                for target, value in (
                    ("sync_playwright", lambda: nullcontext(SimpleNamespace(chromium=chromium))),
                    ("_get_gp_prelogin", lambda *args, **kwargs: (
                        None, base64.b64encode(start_url.encode()).decode(), None,
                    )),
                    ("_parse_saml_timeout", lambda protocol: 8.0),
                    ("_gp_initial_password_observation_required", observation),
                    ("_stale_ui_recovery_action", stale_recovery),
                    ("_prime_gp_microsoft_federation_render", prime_federation),
                    ("MICROSOFT_PASSWORD_STABILITY_SECONDS", 0.1),
                ):
                    stack.enter_context(patch.object(auth, target, value))
                result = auth.do_saml_auth(
                    "vpn.fixture.test", "fixture@example.test", "fixture-password",
                    protocol="gp", disable_browser_session_cache=True,
                    cancel_callback=lambda: time.monotonic() > deadline,
                    progress_callback=progress.append,
                )
        except Exception as error:
            self.fail(
                f"Local GP fixture failed: {error}; progress={progress}; "
                f"password_hosts={[host for host, _ in password_posts]}"
            )
        finally:
            context.close()
        self.assertEqual(result.get("prelogin-cookie"), "fixture-only")
        return SimpleNamespace(
            start_visits=start_visits,
            password_inputs=password_inputs,
            password_posts=password_posts,
            progress=progress,
            primed_documents=primed_documents,
        )

    def test_observation_expiry_submits_real_microsoft_password_once_without_reload(self):
        outcome = self._run_fixture()
        self.assertEqual(len(outcome.start_visits), 1)
        self.assertNotIn("saml-ui-recovery", outcome.progress)
        self.assertIn("gp-initial-password-observation", outcome.progress)
        self.assertEqual(
            [host for host, _ in outcome.password_posts], ["login.microsoftonline.com"]
        )
        elapsed = outcome.password_posts[0][1] - outcome.start_visits[0]
        self.assertGreaterEqual(elapsed, self.OBSERVATION_SECONDS)
        self.assertLess(elapsed, 5.0)

    def test_delayed_federation_enters_password_only_at_institution(self):
        outcome = self._run_fixture(federated=True)
        self.assertEqual(len(outcome.start_visits), 1)
        self.assertNotIn("saml-ui-recovery", outcome.progress)
        self.assertIn("gp-initial-password-observation", outcome.progress)
        self.assertNotIn("login.microsoftonline.com", outcome.password_inputs)
        self.assertEqual(
            [host for host, _ in outcome.password_posts], ["login.fixture.test"]
        )

    def test_presecret_recovery_reprimes_and_observes_fresh_federation_page(self):
        outcome = self._run_fixture(federated=True, recover=True)
        self.assertEqual(len(outcome.start_visits), 2)
        self.assertEqual(outcome.progress.count("saml-ui-recovery"), 1)
        self.assertEqual(outcome.primed_documents, [1, 2])
        self.assertLess(
            outcome.progress.index("saml-ui-recovery"),
            outcome.progress.index("gp-initial-password-observation"),
        )
        self.assertNotIn("login.microsoftonline.com", outcome.password_inputs)
        self.assertEqual(
            [host for host, _ in outcome.password_posts], ["login.fixture.test"]
        )


if __name__ == "__main__":
    unittest.main()
