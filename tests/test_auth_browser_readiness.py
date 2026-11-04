"""Real Chromium regression fixtures; all HTTP requests are served locally."""
import sys
import time
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'codebase'))
from core.auth import (
    _password_form_hydrated, _combined_action_pattern,
    MICROSOFT_PASSWORD_METHOD_LABELS, MICROSOFT_TOTP_DIRECT_SELECTORS,
    do_saml_auth, SamlSensitiveActionError,
)
from playwright.sync_api import sync_playwright


class BrowserReadinessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.playwright = sync_playwright().start()
        try:
            cls.browser = cls.playwright.chromium.launch(headless=True, args=['--no-sandbox'])
        except Exception:
            cls.playwright.stop()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()

    def setUp(self):
        self.page = self.browser.new_page()
        self.page.route('**/*', lambda route: route.fulfill(body='<html><body></body></html>', content_type='text/html'))
        self.page.goto('https://login.microsoftonline.com/local-fixture')

    def tearDown(self):
        self.page.close()

    def test_visible_password_waits_for_binding_then_submits_once(self):
        self.page.set_content('''<form data-bind="submit: login">
          <input type="password" autocomplete="current-password">
          <button type="submit">Anmelden</button></form>
          <script>window.ko = {contextFor: () => window.bound ? {} : undefined};
          window.submissions = 0;</script>''')
        password = self.page.locator('input[type=password]')
        self.assertTrue(password.is_visible())
        self.assertTrue(password.is_enabled())
        self.assertFalse(_password_form_hydrated(password, 'anyconnect'))
        self.page.evaluate('''() => {
          document.querySelector('form').onsubmit = e => {
            e.preventDefault(); window.submissions++;
          };
          window.bound = true;
        }''')
        self.assertTrue(_password_form_hydrated(password, 'anyconnect'))
        password.fill('fixture-only')
        self.page.get_by_role('button', name='Anmelden').click()
        self.assertEqual(self.page.evaluate('window.submissions'), 1)

    def test_changed_ids_and_ready_non_knockout_form_take_fast_path(self):
        self.page.set_content('<form><input id="new-password-id" type="password"></form>')
        self.assertTrue(_password_form_hydrated(self.page.locator('input'), 'anyconnect'))

    def test_detached_field_is_reacquired_instead_of_entered(self):
        self.page.set_content('<form><input type="password"></form>')
        old = self.page.query_selector('input')
        self.page.evaluate("document.querySelector('input').remove()")
        self.assertFalse(_password_form_hydrated(old, 'anyconnect'))

    def test_other_provider_and_gp_do_not_wait_for_microsoft_binding(self):
        self.page.set_content('''<input type="password" data-bind="value: pass">
            <script>window.ko = {contextFor: () => undefined};</script>''')
        self.assertTrue(_password_form_hydrated(self.page.locator('input'), 'gp'))
        self.page.goto('https://vpn.example.test/local-fixture')
        self.page.set_content('<input type="password">')
        self.assertTrue(_password_form_hydrated(self.page.locator('input'), 'anyconnect'))

    def test_translated_password_choices_use_real_role_controls(self):
        for label in ('Use my password', 'Mein Kennwort verwenden',
                      'Utiliser mon mot de passe', 'Usa la password'):
            with self.subTest(label=label):
                self.page.set_content('<button></button>')
                self.page.locator('button').evaluate('(el, label) => el.textContent = label', label)
                self.assertEqual(self.page.get_by_role('button', name=_combined_action_pattern(
                    MICROSOFT_PASSWORD_METHOD_LABELS)).count(), 1)

    def test_totp_metadata_survives_unknown_language_and_changed_id(self):
        self.page.set_content('<button id="new-totp-choice" data-value="PhoneAppOTP">確認コード</button>')
        self.assertEqual(self.page.locator(','.join(MICROSOFT_TOTP_DIRECT_SELECTORS)).count(), 1)

    def test_rejected_password_is_typed_and_submitted_only_once(self):
        context = self.browser.new_context()
        posts = []

        def route_request(route):
            if route.request.method == 'POST':
                posts.append(route.request.url)
                route.fulfill(content_type='text/html', body='<p>Your password is incorrect</p>')
            elif '/+CSCOE+/' in route.request.url:
                route.fulfill(content_type='text/html', body='''<script>
                    location.replace('https://login.microsoftonline.com/local-fixture');
                </script>''')
            else:
                route.fulfill(content_type='text/html', body='''
                    <form method="post" action="/password">
                      <input id="i0118" name="passwd" type="password"
                        autocomplete="current-password">
                      <button type="submit">Sign in</button>
                    </form>''')

        context.route('**/*', route_request)
        chromium = SimpleNamespace(
            executable_path=self.playwright.chromium.executable_path,
            launch_persistent_context=lambda *args, **kwargs: context,
        )
        deadline = time.monotonic() + 15
        try:
            with patch('core.auth.sync_playwright', return_value=nullcontext(
                SimpleNamespace(chromium=chromium)
            )), self.assertRaises(SamlSensitiveActionError):
                do_saml_auth(
                    'vpn.fixture.test', 'fixture@example.test', 'fixture-password',
                    disable_browser_session_cache=True,
                    cancel_callback=lambda: time.monotonic() > deadline,
                )
        finally:
            context.close()
        self.assertEqual(posts, ['https://login.microsoftonline.com/password'])

    def test_number_match_callback_delivers_code_to_standalone_frontend(self):
        context = self.browser.new_context()
        numbers = []
        progress = []

        def route_request(route):
            if '/+CSCOE+/' in route.request.url:
                route.fulfill(content_type='text/html', body='''<script>
                    location.replace('https://login.microsoftonline.com/local-fixture');
                </script>''')
            else:
                route.fulfill(content_type='text/html', body='''
                    <h1>Check your Authenticator app</h1>
                    <div id="idRichContext_DisplaySign">42</div>''')

        def notify(number):
            numbers.append(number)
            # Simulate the IdP callback after the user approves the challenge.
            context.add_cookies([
                {'name': name, 'value': 'fixture-only', 'url': 'https://vpn.fixture.test'}
                for name in ('webvpn', 'webvpnc')
            ])
            return True

        context.route('**/*', route_request)
        chromium = SimpleNamespace(
            executable_path=self.playwright.chromium.executable_path,
            launch_persistent_context=lambda *args, **kwargs: context,
        )
        deadline = time.monotonic() + 20
        try:
            with patch('core.auth.sync_playwright', return_value=nullcontext(
                SimpleNamespace(chromium=chromium)
            )):
                cookies = do_saml_auth(
                    'vpn.fixture.test', 'fixture@example.test', 'fixture-password',
                    mfa_preference='push', disable_browser_session_cache=True,
                    number_match_callback=notify, progress_callback=progress.append,
                    cancel_callback=lambda: time.monotonic() > deadline,
                )
        finally:
            context.close()
        self.assertEqual(numbers, ['42'])
        self.assertEqual(set(cookies), {'webvpn', 'webvpnc'})
        self.assertIn('mfa-number-match-notified', progress)
        self.assertFalse(any('42' in event for event in progress))

    def test_check_authenticator_prompt_leaves_pending_password_for_totp(self):
        """Run the real auth loop against a local, fully routed Microsoft flow."""
        context = self.browser.new_context()
        posts = []
        progress = []

        def route_request(route):
            request = route.request
            if request.method == 'POST':
                posts.append(request.url)
            if '/+CSCOE+/' in request.url:
                route.fulfill(content_type='text/html', body='''<script>
                    location.replace('https://login.microsoftonline.com/local-fixture');
                </script>''')
            elif request.url.endswith('/local-fixture'):
                route.fulfill(content_type='text/html', body='''
                    <form method="post" action="/password">
                      <input id="i0118" name="passwd" type="password"
                        autocomplete="current-password">
                      <button type="submit">Sign in</button>
                    </form>''')
            elif request.url.endswith('/password'):
                route.fulfill(content_type='text/html', body='''
                    <h1>Check your Authenticator app</h1>
                    <div id="idRichContext_DisplaySign">42</div>
                    <button id="idA_SAASTO_Proofs">Sign in another way</button>
                    <script>
                      document.querySelector('button').onclick = () => {
                        document.body.innerHTML =
                          '<button data-value="PhoneAppOTP">Use a verification code</button>';
                        document.querySelector('button').onclick = () => {
                          document.body.innerHTML =
                            '<form method="post" action="https://vpn.fixture.test/success">' +
                            '<input id="idTxtBx_SAOTCC_OTC" name="otc" autocomplete="one-time-code">' +
                            '<button type="submit">Verify</button></form>';
                        };
                      };
                    </script>''')
            elif request.url == 'https://vpn.fixture.test/success':
                context.add_cookies([
                    {'name': name, 'value': 'fixture-only',
                     'url': 'https://vpn.fixture.test'}
                    for name in ('webvpn', 'webvpnc')
                ])
                route.fulfill(content_type='text/html', body='<p>Connected</p>')
            else:
                route.abort()

        context.route('**/*', route_request)
        chromium = SimpleNamespace(
            executable_path=self.playwright.chromium.executable_path,
            launch_persistent_context=lambda *args, **kwargs: context,
        )
        deadline = time.monotonic() + 20
        try:
            with patch('core.auth.sync_playwright', return_value=nullcontext(
                SimpleNamespace(chromium=chromium)
            )), patch('core.auth.generate_totp', return_value='123456'), patch(
                'core.auth.seconds_until_totp_rotation', return_value=20
            ):
                cookies = do_saml_auth(
                    'vpn.fixture.test', 'fixture@example.test', 'fixture-password',
                    totp_secret='fixture-only', mfa_preference='totp',
                    disable_browser_session_cache=True,
                    cancel_callback=lambda: time.monotonic() > deadline,
                    progress_callback=progress.append,
                )
        except Exception as exc:
            self.fail(f'Fixture failed: {exc}; progress={progress}; posts={posts}')
        finally:
            context.close()

        self.assertEqual(set(cookies), {'webvpn', 'webvpnc'})
        self.assertEqual(posts, [
            'https://login.microsoftonline.com/password',
            'https://vpn.fixture.test/success',
        ])
        self.assertIn('mfa-number-match-detected', progress)
        self.assertIn('mfa-alternate-methods-opened', progress)
        self.assertIn('mfa-totp-submitted', progress)
        self.assertEqual(progress.count('password-action-submitted'), 1)
        self.assertEqual(progress.count('mfa-totp-submitted'), 1)


if __name__ == '__main__':
    unittest.main()
