"""Real Chromium telemetry classification with fully intercepted fake traffic."""

import base64
import functools
import json
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


class TelemetryBrowserTests(unittest.TestCase):
    TELEMETRY_URL = "https://browser.events.data.microsoft.com/collect"
    SAFE_STREAM = '{"name":"page-performance"}\n{"name":"render-complete"}\n'
    FIXTURE_PASSWORD = "synthetic-fixture-password"

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

    def _send_telemetry(self, transport, payload):
        context = self.browser.new_context()
        page = context.new_page()
        tracker = auth._SensitiveDispatchEvidenceTracker()

        def route_request(route):
            if route.request.url == self.TELEMETRY_URL:
                route.fulfill(status=204, body="")
            else:
                route.fulfill(content_type="text/html", body="<p>Local fixture</p>")

        context.route("**/*", route_request)
        try:
            page.goto("https://login.microsoftonline.com/local-fixture")
            page.on("request", lambda request: tracker.request_started(
                request, main_frame=page.main_frame,
                expected_secret=self.FIXTURE_PASSWORD,
            ))
            with page.expect_request(self.TELEMETRY_URL) as request_event:
                accepted = page.evaluate("""async ({url, payload, transport}) => {
                    if (transport === 'beacon') return navigator.sendBeacon(url, payload);
                    await fetch(url, {method: 'POST', body: payload, mode: 'no-cors'});
                    return true;
                }""", {"url": self.TELEMETRY_URL, "payload": payload, "transport": transport})
            request = request_event.value
            self.assertTrue(accepted)
            self.assertEqual(request.method, "POST")
            self.assertFalse(request.is_navigation_request())
            resource_type = request.resource_type
            inspection = tracker._inspect_request_password(request, self.FIXTURE_PASSWORD)
        finally:
            context.close()
        self.assertEqual(tracker.outbound_request_generation, 1)
        self.assertEqual(tracker.write_request_generation, 1)
        return tracker, resource_type, inspection

    def test_real_sendbeacon_stream_is_ping_and_does_not_taint(self):
        tracker, resource_type, inspection = self._send_telemetry("beacon", self.SAFE_STREAM)
        self.assertEqual(resource_type, "ping")
        self.assertEqual(inspection, (False, True))
        self.assertEqual(tracker.unsafe_write_request_generation, 0)
        self.assertEqual(tracker.credential_taint_generation, 0)

    def test_real_fetch_stream_remains_credential_free(self):
        tracker, resource_type, inspection = self._send_telemetry("fetch", self.SAFE_STREAM)
        self.assertEqual(resource_type, "fetch")
        self.assertEqual(inspection, (False, True))
        self.assertEqual(tracker.unsafe_write_request_generation, 0)
        self.assertEqual(tracker.credential_taint_generation, 0)

    def test_credential_bearing_sendbeacon_still_taints(self):
        payload = self.SAFE_STREAM + json.dumps({"password": self.FIXTURE_PASSWORD}) + "\n"
        tracker, resource_type, inspection = self._send_telemetry("beacon", payload)
        self.assertEqual(resource_type, "ping")
        self.assertEqual(inspection, (True, True))
        self.assertEqual(tracker.unsafe_write_request_generation, 1)
        self.assertGreater(tracker.credential_taint_generation, 0)

    def test_malformed_sendbeacon_still_taints_even_without_password(self):
        tracker, resource_type, inspection = self._send_telemetry(
            "beacon", '{"name":"first"}\n{malformed-json}\n',
        )
        self.assertEqual(resource_type, "ping")
        self.assertEqual(inspection, (False, True))
        self.assertEqual(tracker.unsafe_write_request_generation, 1)
        self.assertGreater(tracker.credential_taint_generation, 0)

    def test_safe_beacon_allows_one_federated_password_stage(self):
        context = self.browser.new_context()
        page = context.new_page()
        start_url = "https://login.microsoftonline.com/local-start"
        institutional_url = "https://login.unibas.ch/adfs/ls/"
        discovery_actions = []
        beacon_types = []
        credential_posts = []
        progress = []
        context.expose_binding(
            "fixtureDiscoveryAction", lambda source: discovery_actions.append(True),
        )

        def route_request(route):
            request = route.request
            parsed = urlsplit(request.url)
            if request.url == self.TELEMETRY_URL:
                beacon_types.append(request.resource_type)
                self.assertEqual(request.post_data, self.SAFE_STREAM)
                route.fulfill(status=204, body="")
            elif request.method == "POST" and parsed.path == "/password":
                credential_posts.append(parsed.hostname)
                route.fulfill(content_type="text/html", body="""
                    <form method="post" action="https://vpn.unibas.ch/callback">
                      <input name="prelogin-cookie" value="fixture-only">
                    </form><script>document.querySelector('form').submit();</script>
                """)
            elif parsed.hostname == "vpn.unibas.ch":
                route.fulfill(content_type="text/html", body="<p>Connected</p>")
            elif request.url == start_url:
                # This first password-shaped form performs discovery only. Its
                # input value is never included in any outbound request.
                route.fulfill(content_type="text/html", body=f"""
                    <form method="post" action="/password">
                      <input id="i0118" name="passwd" type="password"
                        autocomplete="current-password">
                      <button id="idSIButton9" type="submit">Sign in</button>
                    </form><script>
                      document.querySelector('form').onsubmit = event => {{
                        event.preventDefault();
                        fixtureDiscoveryAction();
                        navigator.sendBeacon({json.dumps(self.TELEMETRY_URL)},
                                             {json.dumps(self.SAFE_STREAM)});
                        setTimeout(() => location.replace({json.dumps(institutional_url)}), 150);
                      }};
                    </script>""")
            elif request.url == institutional_url:
                route.fulfill(content_type="text/html", body="""
                    <form method="post" action="/password">
                      <input id="userNameInput" name="UserName" type="text">
                      <input id="passwordInput" name="Password" type="password"
                        autocomplete="current-password">
                      <button type="submit">Sign in</button>
                    </form>""")
            else:
                route.abort()

        context.route("**/*", route_request)
        chromium = SimpleNamespace(
            executable_path=self.playwright.chromium.executable_path,
            launch_persistent_context=lambda *args, **kwargs: context,
        )
        observation = functools.partial(
            auth._gp_initial_password_observation_required,
            observation_seconds=0.0,
        )
        deadline = time.monotonic() + 12
        try:
            with ExitStack() as stack:
                for name, value in (
                    ("sync_playwright", lambda: nullcontext(SimpleNamespace(chromium=chromium))),
                    ("_get_gp_prelogin", lambda *args, **kwargs: (
                        None, base64.b64encode(start_url.encode()).decode(), None,
                    )),
                    ("_parse_saml_timeout", lambda protocol: 10.0),
                    ("_gp_initial_password_observation_required", observation),
                    ("MICROSOFT_PASSWORD_STABILITY_SECONDS", 0.1),
                ):
                    stack.enter_context(patch.object(auth, name, value))
                result = auth.do_saml_auth(
                    "vpn.unibas.ch", "fixture@example.test", self.FIXTURE_PASSWORD,
                    protocol="gp", disable_browser_session_cache=True,
                    cancel_callback=lambda: time.monotonic() > deadline,
                    progress_callback=progress.append,
                )
        except Exception as error:
            self.fail(
                f"Local federation fixture failed: {error}; progress={progress}; "
                f"credential_posts={credential_posts}; beacon_types={beacon_types}"
            )
        finally:
            context.close()
        self.assertEqual(result.get("prelogin-cookie"), "fixture-only")
        self.assertEqual(discovery_actions, [True])
        self.assertEqual(beacon_types, ["ping"])
        self.assertEqual(credential_posts, ["login.unibas.ch"])
        self.assertIn("password-federated-replacement", progress)
        self.assertNotIn("password-alternate-dispatch", progress)
        self.assertNotIn("saml-ui-recovery", progress)


if __name__ == "__main__":
    unittest.main()
