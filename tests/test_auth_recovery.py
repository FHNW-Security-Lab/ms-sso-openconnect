"""Shared frontend recovery must never replay a sensitive sign-in action."""

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "codebase"))
from core.auth import SamlUiStalledError, do_saml_auth_with_recovery


class AuthRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {"MS_SSO_DISABLE_BROWSER_SESSION_CACHE": "",
                                          "MS_SSO_ENABLE_BROWSER_SESSION_CACHE": "",
                                          "MS_SSO_MFA_PREFERENCE": ""})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.args = dict(vpn_server="vpn.example.test", username="alice", password="fixture")

    def test_cached_anyconnect_stall_gets_one_ephemeral_retry(self):
        progress = Mock()
        cancel = Mock(return_value=False)
        cookies = {"webvpn": "fixture-session"}
        with patch("core.auth.do_saml_auth", side_effect=[SamlUiStalledError("stalled"), cookies]) as auth:
            self.assertEqual(do_saml_auth_with_recovery(**self.args, cancel_callback=cancel,
                                                       progress_callback=progress), cookies)
        self.assertEqual(auth.call_count, 2)
        first, retry = [call.kwargs for call in auth.call_args_list]
        self.assertFalse(first["disable_browser_session_cache"])
        self.assertEqual(retry, dict(first, disable_browser_session_cache=True))
        progress.assert_called_once_with("retrying-with-clean-browser-session")

    def test_failed_ephemeral_retry_is_final(self):
        with patch("core.auth.do_saml_auth", side_effect=SamlUiStalledError("stalled")) as auth:
            with self.assertRaises(SamlUiStalledError):
                do_saml_auth_with_recovery(**self.args)
        self.assertEqual(auth.call_count, 2)

    def test_sensitive_auth_error_is_never_retried(self):
        with patch("core.auth.do_saml_auth", side_effect=RuntimeError("password dispatched")) as auth:
            with self.assertRaisesRegex(RuntimeError, "password dispatched"):
                do_saml_auth_with_recovery(**self.args)
        auth.assert_called_once()

    def test_globalprotect_ephemeral_and_cancelled_attempts_are_not_retried(self):
        for options in ({"protocol": "gp"}, {"disable_browser_session_cache": True},
                        {"cancel_callback": lambda: True}):
            with self.subTest(options=options):
                with patch("core.auth.do_saml_auth", side_effect=SamlUiStalledError("stalled")) as auth:
                    with self.assertRaises(SamlUiStalledError):
                        do_saml_auth_with_recovery(**self.args, **options)
                auth.assert_called_once()

    def test_environment_cache_override_is_respected(self):
        with patch.dict(os.environ, {"MS_SSO_DISABLE_BROWSER_SESSION_CACHE": "true"}):
            with patch("core.auth.do_saml_auth", side_effect=SamlUiStalledError("stalled")) as auth:
                with self.assertRaises(SamlUiStalledError):
                    do_saml_auth_with_recovery(**self.args)
            auth.assert_called_once()

    def test_positional_callers_and_number_match_callback_are_supported(self):
        notify = Mock(return_value=True)
        with patch("core.auth.do_saml_auth", return_value={"webvpn": "session"}) as auth:
            do_saml_auth_with_recovery("vpn.example.test", "alice", "fixture", number_match_callback=notify)
        self.assertIs(auth.call_args.kwargs["number_match_callback"], notify)
        self.assertEqual(auth.call_args.kwargs["username"], "alice")

    def test_explicit_totp_uses_clean_browser_without_second_attempt(self):
        with patch("core.auth.do_saml_auth", side_effect=SamlUiStalledError("stalled")) as auth:
            with self.assertRaises(SamlUiStalledError):
                do_saml_auth_with_recovery(**self.args, mfa_preference="totp", totp_secret="fixture")
        auth.assert_called_once()
        self.assertTrue(auth.call_args.kwargs["disable_browser_session_cache"])

    def test_browser_cache_enable_override_preserves_existing_session(self):
        with patch.dict(os.environ, {"MS_SSO_ENABLE_BROWSER_SESSION_CACHE": "true"}), patch(
            "core.auth.do_saml_auth", return_value={"webvpn": "session"}
        ) as auth:
            do_saml_auth_with_recovery(**self.args, mfa_preference="totp", totp_secret="fixture")
        self.assertFalse(auth.call_args.kwargs["disable_browser_session_cache"])


if __name__ == "__main__":
    unittest.main()
