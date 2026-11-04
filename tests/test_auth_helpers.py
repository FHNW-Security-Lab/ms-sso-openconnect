#!/usr/bin/env python3

import json
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "codebase"))

from core.auth import (  # noqa: E402
    GP_INITIAL_MICROSOFT_PASSWORD_NAVIGATION_MAX_SECONDS,
    GP_INITIAL_MICROSOFT_PASSWORD_OBSERVATION_SECONDS,
    MICROSOFT_CREDENTIAL_LOOKUP_MAX_SECONDS,
    MICROSOFT_CREDENTIAL_LOOKUP_TIMEOUT_SECONDS,
    MICROSOFT_ALTERNATE_MFA_LABELS,
    MICROSOFT_ALTERNATE_MFA_SELECTORS,
    MICROSOFT_AUTH_UI_PROCESSING_SELECTORS,
    MICROSOFT_AUTHENTICATOR_PUSH_MARKERS,
    MICROSOFT_KMSI_ACCEPT_LABELS,
    MICROSOFT_KMSI_MARKERS,
    MICROSOFT_NUMBER_MATCH_MARKERS,
    MICROSOFT_NUMBER_MATCH_TOTP_ALTERNATE_LABELS,
    MICROSOFT_METHOD_PICKER_SETTLE_SECONDS,
    MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS,
    MICROSOFT_PUSH_DELIVERY_MAX_RETRIES,
    MICROSOFT_TOTP_MAX_SUBMISSIONS,
    MICROSOFT_PASSKEY_MARKERS,
    MICROSOFT_PASSKEY_APP_FALLBACK_LABELS,
    MICROSOFT_PASSWORD_DIRECT_SELECTORS,
    MICROSOFT_PASSWORD_DISPATCH_CONFIRM_SECONDS,
    MICROSOFT_PASSWORD_METHOD_LABELS,
    MICROSOFT_PRIMARY_CREDENTIAL_PICKER_SELECTORS,
    MICROSOFT_PRIMARY_METHOD_PICKER_MARKERS,
    MICROSOFT_PUSH_DELIVERY_FAILURE_MARKERS,
    MICROSOFT_PUSH_DIRECT_SELECTORS,
    MICROSOFT_PUSH_METHOD_LABELS,
    MICROSOFT_TOTP_DIRECT_SELECTORS,
    MICROSOFT_EXACT_TOTP_METHOD_LABELS,
    MICROSOFT_TOTP_METHOD_LABELS,
    SAML_UI_MAX_RECOVERIES,
    SAML_UI_MAX_PROCESSING_EXTENSIONS,
    SAML_UI_MAX_SUBMIT_WAIT_SECONDS,
    SAML_UI_POST_SUBMIT_GRACE_SECONDS,
    SAML_UI_PROCESSING_EXTENSION_SECONDS,
    SAML_PERSISTENT_PROFILE_PRE_SENSITIVE_MAX_SECONDS,
    SAML_UI_STALL_WINDOW_SECONDS,
    SamlUiStalledError,
    _MicrosoftCredentialLookupTracker,
    _SensitiveActionLedger,
    _SensitiveActionUncertainError,
    _SensitiveDispatchEvidenceTracker,
    _account_tile_matches_username,
    _action_patterns,
    _anyconnect_password_dispatch_is_ambiguous,
    _anyconnect_retained_password_continuation_ready,
    _anyconnect_retained_password_guard_unchanged,
    _attempt_locator_click,
    _attempt_locator_press,
    _detect_desktop_user,
    _discard_stale_browser_profile,
    _adaptive_mfa_action,
    _allows_partial_action_label,
    _browser_session_cache_key,
    _canonical_https_origin,
    _capture_rendered_auth_ui,
    _combined_action_pattern,
    _exact_action_pattern,
    _enter_password_value,
    _extend_processing_grace,
    _fill_totp_code_control,
    _get_gp_prelogin,
    _gp_password_client_replacement_ready,
    _gp_initial_password_observation_required,
    _gp_password_federated_replacement_ready,
    _gp_password_navigation_hard_cap_reached,
    _gp_password_navigation_replacement_ready,
    _gp_password_replacement_authorization_route,
    _gp_password_stage_origin_policy_valid,
    _has_number_match_evidence,
    _https_origin_matches_vpn_institution,
    _institution_domain,
    _is_actionable_control,
    _is_known_microsoft_telemetry_host,
    _is_usable_input_state,
    _latch_sensitive_authenticator_challenge,
    _latch_sensitive_cached_account_selection,
    _merge_saml_artifacts,
    _otp_control_is_progress,
    _parse_saml_timeout,
    _password_field_completes_submission_transition,
    _password_alternate_dispatch_allowed,
    _password_control_is_progress,
    _password_discovery_classification_deferred,
    _password_discovery_method_picker_ready,
    _password_discovery_replacement_ready,
    _password_discovery_replacement_allowed,
    _password_discovery_supported,
    _password_entry_uses_key_events,
    _password_fallback_input_allowed,
    _password_bridge_transition_action,
    _password_bridge_allowed,
    _passkey_fallback_route,
    _passkey_password_transition_action,
    _password_submission_uses_strict_owning_form,
    _password_submission_classification_deadline,
    _password_submission_classification_delay,
    _password_transition_evidence_message,
    _password_transition_blocks_alternate_dispatch,
    _persistent_profile_pre_sensitive_expired,
    _prefer_totp_for_number_match,
    _prime_gp_microsoft_federation_render,
    _remaining_timeout_ms,
    _submission_hard_deadline,
    _should_notify_number_match,
    _should_extend_submission_grace,
    _should_submit_totp_counter,
    _should_submit_totp_for_control,
    _stale_ui_recovery_action,
    _standalone_two_digit_numbers,
    _snapshot_has_text,
    _snapshot_probe_texts,
    _snapshot_selector_actionable,
    _snapshot_selector_visible,
    _ui_stall_exception,
    _username_fallback_wait_required,
)
from core.totp import generate_totp, seconds_until_totp_rotation  # noqa: E402


class AuthDeadlineTests(unittest.TestCase):
    def test_remaining_timeout_uses_single_deadline(self):
        self.assertEqual(_remaining_timeout_ms(12.5, now=10.0), 2500)

    def test_expired_deadline_never_becomes_negative(self):
        self.assertEqual(_remaining_timeout_ms(9.0, now=10.0), 0)

    def test_invalid_timeout_uses_safe_protocol_default(self):
        self.assertEqual(_parse_saml_timeout("anyconnect", "invalid"), 300)
        self.assertEqual(_parse_saml_timeout("anyconnect", "0"), 300)
        self.assertEqual(_parse_saml_timeout("gp", "30"), 240)


class TotpControlHydrationTests(unittest.TestCase):
    def test_hidden_microsoft_session_input_is_never_filled(self):
        hidden = Mock()
        hidden.is_visible.return_value = False

        self.assertFalse(_fill_totp_code_control(hidden, "123456"))
        hidden.fill.assert_not_called()

    def test_retargeted_locator_is_rediscovered_after_bounded_fill(self):
        replaced = Mock()
        replaced.is_visible.return_value = True
        replaced.is_enabled.return_value = True
        replaced.is_editable.return_value = True
        replaced.fill.side_effect = TimeoutError("DOM replaced")

        self.assertFalse(_fill_totp_code_control(replaced, "123456"))
        replaced.fill.assert_called_once_with("123456", timeout=1000)

    def test_visible_editable_totp_control_is_filled(self):
        visible = Mock()
        visible.is_visible.return_value = True
        visible.is_enabled.return_value = True
        visible.is_editable.return_value = True

        self.assertTrue(_fill_totp_code_control(visible, "123456"))
        visible.fill.assert_called_once_with("123456", timeout=1000)


class BrowserSessionIsolationTests(unittest.TestCase):
    def test_cache_key_normalizes_identity_without_exposing_it(self):
        first = _browser_session_cache_key(
            " GP ",
            "https://VPN.Example.EDU.:443/ssl-vpn/login.esp",
            " Alice@Example.EDU ",
        )
        second = _browser_session_cache_key(
            "gp",
            "vpn.example.edu",
            "alice@example.edu",
        )

        self.assertEqual(first, second)
        self.assertRegex(first, r"^v2-[0-9a-f]{64}$")
        self.assertNotIn("vpn", first)
        self.assertNotIn("alice", first)
        self.assertNotIn("example", first)

    def test_cache_key_isolates_protocol_gateway_and_username(self):
        baseline = _browser_session_cache_key(
            "gp",
            "vpn.example.edu",
            "alice@example.edu",
        )
        variants = {
            _browser_session_cache_key(
                "anyconnect", "vpn.example.edu", "alice@example.edu"
            ),
            _browser_session_cache_key(
                "gp", "other.example.edu", "alice@example.edu"
            ),
            _browser_session_cache_key(
                "gp", "vpn.example.edu", "bob@example.edu"
            ),
        }

        self.assertEqual(len(variants), 3)
        self.assertNotIn(baseline, variants)

    def test_stale_profile_discard_removes_only_the_selected_profile(self):
        with tempfile.TemporaryDirectory() as root:
            selected = Path(root, "selected-profile")
            unrelated = Path(root, "unrelated-profile")
            selected.mkdir()
            unrelated.mkdir()
            Path(selected, "state").write_text("stale", encoding="utf-8")
            Path(unrelated, "state").write_text("healthy", encoding="utf-8")

            self.assertTrue(
                _discard_stale_browser_profile(str(selected), None)
            )
            self.assertFalse(selected.exists())
            self.assertTrue(unrelated.exists())

    def test_stale_profile_discard_never_removes_ephemeral_session(self):
        with tempfile.TemporaryDirectory() as root:
            ephemeral = Path(root, "ephemeral")
            ephemeral.mkdir()

            self.assertFalse(
                _discard_stale_browser_profile(
                    str(ephemeral),
                    str(ephemeral),
                )
            )
            self.assertTrue(ephemeral.exists())


class BrowserUiRecoveryTests(unittest.TestCase):
    def test_generic_next_waits_for_configured_username_control(self):
        self.assertTrue(
            _username_fallback_wait_required(
                "alice@example.test",
                False,
                False,
            )
        )
        self.assertFalse(
            _username_fallback_wait_required(
                "alice@example.test",
                True,
                False,
            )
        )
        self.assertFalse(
            _username_fallback_wait_required(
                "alice@example.test",
                False,
                True,
            )
        )
        self.assertFalse(
            _username_fallback_wait_required(None, False, False)
        )

    def test_microsoft_vpn_password_entry_uses_key_events(self):
        self.assertTrue(_password_entry_uses_key_events("anyconnect"))
        self.assertTrue(_password_entry_uses_key_events("ANYCONNECT"))
        self.assertTrue(_password_entry_uses_key_events("gp"))
        self.assertFalse(_password_entry_uses_key_events("pulse"))

    def test_gp_entry_change_does_not_change_its_submit_strategy(self):
        self.assertTrue(
            _password_submission_uses_strict_owning_form("anyconnect")
        )
        self.assertFalse(_password_submission_uses_strict_owning_form("gp"))

    def test_anyconnect_and_gp_password_entry_emit_key_events(self):
        class PasswordField:
            def __init__(self):
                self.calls = []

            def fill(self, value):
                self.calls.append(("fill", value))

            def press_sequentially(self, value, *, delay):
                self.calls.append(("press_sequentially", value, delay))

        anyconnect_field = PasswordField()
        _enter_password_value(anyconnect_field, "test-password", "anyconnect")
        self.assertEqual(
            anyconnect_field.calls,
            [
                ("fill", ""),
                ("press_sequentially", "test-password", 15),
            ],
        )

        gp_field = PasswordField()
        _enter_password_value(gp_field, "test-password", "gp")
        self.assertEqual(
            gp_field.calls,
            [
                ("fill", ""),
                ("press_sequentially", "test-password", 15),
            ],
        )

    def test_password_discovery_allows_exactly_one_replacement_control(self):
        self.assertTrue(
            _password_discovery_replacement_ready(
                "anyconnect",
                False,
                True,
                "document:2",
                "document:1",
            )
        )
        self.assertTrue(
            _password_discovery_replacement_ready(
                "gp",
                False,
                True,
                "document:2",
                "document:1",
            )
        )
        for protocol, completed, lookup, current, submitted in (
            ("pulse", False, True, "document:2", "document:1"),
            ("anyconnect", True, True, "document:2", "document:1"),
            ("anyconnect", False, False, "document:2", "document:1"),
            ("anyconnect", False, True, "document:1", "document:1"),
            ("anyconnect", False, True, None, "document:1"),
        ):
            self.assertFalse(
                _password_discovery_replacement_ready(
                    protocol,
                    completed,
                    lookup,
                    current,
                    submitted,
                )
            )

    def test_anyconnect_discovery_classification_waits_for_full_lookup_window(self):
        self.assertEqual(
            _password_submission_classification_delay("anyconnect", False),
            MICROSOFT_CREDENTIAL_LOOKUP_MAX_SECONDS,
        )
        self.assertEqual(
            _password_submission_classification_deadline(
                "anyconnect",
                False,
                100.0,
                400.0,
            ),
            100.0 + MICROSOFT_CREDENTIAL_LOOKUP_MAX_SECONDS,
        )
        self.assertTrue(
            _password_discovery_classification_deferred(
                "anyconnect",
                False,
                "password-unknown",
                129.9,
                130.0,
            )
        )
        self.assertFalse(
            _password_discovery_classification_deferred(
                "anyconnect",
                False,
                "password-unknown",
                130.0,
                130.0,
            )
        )

    def test_gp_initial_password_observation_is_bounded_and_gp_only(self):
        common = {
            "protocol": "gp",
            "discovery_completed": False,
            "recovery_attempts": 0,
            "password_action_attempts": 0,
            "password_dispatched": False,
            "observation_started": True,
            "password_stage_authorized": True,
            "password_control_visible": True,
            "credential_error_visible": False,
            "elapsed_seconds": (
                GP_INITIAL_MICROSOFT_PASSWORD_OBSERVATION_SECONDS - 0.1
            ),
            "navigation_pending": False,
        }
        self.assertTrue(
            _gp_initial_password_observation_required(**common)
        )
        self.assertTrue(
            _gp_initial_password_observation_required(
                **(common | {"recovery_attempts": 1})
            )
        )
        self.assertFalse(
            _gp_initial_password_observation_required(
                **(
                    common
                    | {
                        "elapsed_seconds": (
                            GP_INITIAL_MICROSOFT_PASSWORD_OBSERVATION_SECONDS
                        )
                    }
                )
            )
        )
        self.assertTrue(
            _gp_initial_password_observation_required(
                **(
                    common
                    | {
                        "elapsed_seconds": (
                            GP_INITIAL_MICROSOFT_PASSWORD_OBSERVATION_SECONDS
                        ),
                        "navigation_pending": True,
                    }
                )
            )
        )
        self.assertTrue(
            _gp_initial_password_observation_required(
                **(
                    common
                    | {
                        "elapsed_seconds": (
                            GP_INITIAL_MICROSOFT_PASSWORD_NAVIGATION_MAX_SECONDS
                            - 0.1
                        ),
                        "navigation_pending": True,
                    }
                )
            )
        )
        self.assertFalse(
            _gp_initial_password_observation_required(
                **(
                    common
                    | {
                        "elapsed_seconds": (
                            GP_INITIAL_MICROSOFT_PASSWORD_NAVIGATION_MAX_SECONDS
                        ),
                        "navigation_pending": True,
                    }
                )
            )
        )
        self.assertTrue(
            _gp_initial_password_observation_required(
                **(
                    common
                    | {
                        "password_stage_authorized": False,
                        "password_control_visible": False,
                        "elapsed_seconds": 20.0,
                        "navigation_pending": True,
                    }
                )
            )
        )
        for name, override in {
            "fhnw-unchanged": {"protocol": "anyconnect"},
            "discovery-complete": {"discovery_completed": True},
            "after-action": {"password_action_attempts": 1},
            "already-dispatched": {"password_dispatched": True},
            "not-observed": {"observation_started": False},
            "unauthorized-stage": {"password_stage_authorized": False},
            "no-password-control": {"password_control_visible": False},
            "credential-error": {"credential_error_visible": True},
        }.items():
            with self.subTest(name=name):
                self.assertFalse(
                    _gp_initial_password_observation_required(
                        **(common | override)
                    )
                )

    def test_gp_password_navigation_hard_cap_is_exact_and_gp_only(self):
        common = {
            "protocol": "gp",
            "discovery_completed": False,
            "password_action_attempts": 0,
            "password_dispatched": False,
            "navigation_pending": True,
        }
        self.assertFalse(
            _gp_password_navigation_hard_cap_reached(
                **common,
                elapsed_seconds=(
                    GP_INITIAL_MICROSOFT_PASSWORD_NAVIGATION_MAX_SECONDS
                    - 0.001
                ),
            )
        )
        self.assertTrue(
            _gp_password_navigation_hard_cap_reached(
                **common,
                elapsed_seconds=(
                    GP_INITIAL_MICROSOFT_PASSWORD_NAVIGATION_MAX_SECONDS
                ),
            )
        )
        for name, override in {
            "fhnw": {"protocol": "anyconnect"},
            "discovery-complete": {"discovery_completed": True},
            "after-action": {"password_action_attempts": 1},
            "already-dispatched": {"password_dispatched": True},
            "settled": {"navigation_pending": False},
        }.items():
            with self.subTest(name=name):
                self.assertFalse(
                    _gp_password_navigation_hard_cap_reached(
                        **(common | override),
                        elapsed_seconds=60.0,
                    )
                )

    def test_gp_render_prime_is_in_memory_and_protocol_scoped(self):
        page = Mock()
        self.assertTrue(
            _prime_gp_microsoft_federation_render(
                page,
                "gp",
                "login.microsoftonline.com",
            )
        )
        page.evaluate.assert_called_once()
        page.screenshot.assert_called_once_with(
            type="png",
            clip={"x": 0, "y": 0, "width": 1, "height": 1},
            timeout=2000,
        )
        page.reset_mock()
        self.assertFalse(
            _prime_gp_microsoft_federation_render(
                page,
                "anyconnect",
                "login.microsoftonline.com",
            )
        )
        page.screenshot.assert_not_called()

    def test_gp_render_prime_failure_is_nonfatal(self):
        page = Mock()
        page.screenshot.side_effect = RuntimeError("compositor unavailable")
        self.assertFalse(
            _prime_gp_microsoft_federation_render(
                page,
                "gp",
                "login.microsoftonline.com",
            )
        )


    def test_anyconnect_retained_password_continuation_matches_live_hydration(self):
        common = {
            "protocol": "anyconnect",
            "submission_kind": "password-unknown",
            "attempts": 1,
            "elapsed_seconds": MICROSOFT_PASSWORD_DISPATCH_CONFIRM_SECONDS,
            "lookup_observed": False,
            "dispatch_observed": True,
            "safe_navigation_observed": False,
            "credential_tainted": False,
            "document_replaced": True,
            "main_navigation_request_observed": False,
            "write_request_observed": True,
            "unsafe_write_request_observed": False,
            "navigation_pending_at_baseline": False,
            "navigation_pending_now": False,
            "strong_owning_form": True,
            "strong_password_input": True,
            "current_identity": "document:replacement",
            "submitted_identity": "document:original",
            "value_retained": True,
            "original_control_origin": "https://login.microsoftonline.com",
            "original_top_origin": "https://login.microsoftonline.com",
            "original_form_action_origin": "https://login.microsoftonline.com",
            "original_form_signature": "microsoft-post-form",
            "original_form_method": "post",
            "current_control_origin": "https://login.microsoftonline.com",
            "current_top_origin": "https://login.microsoftonline.com",
            "current_form_action_origin": "https://login.microsoftonline.com",
            "current_form_signature": "microsoft-post-form",
            "current_form_method": "post",
            "credential_error_visible": False,
        }
        self.assertTrue(
            _anyconnect_retained_password_continuation_ready(**common)
        )

    def test_anyconnect_retained_password_continuation_fails_closed(self):
        common = {
            "protocol": "anyconnect",
            "submission_kind": "password-unknown",
            "attempts": 1,
            "elapsed_seconds": MICROSOFT_PASSWORD_DISPATCH_CONFIRM_SECONDS,
            "lookup_observed": False,
            "dispatch_observed": True,
            "safe_navigation_observed": False,
            "credential_tainted": False,
            "document_replaced": True,
            "main_navigation_request_observed": False,
            "write_request_observed": True,
            "unsafe_write_request_observed": False,
            "navigation_pending_at_baseline": False,
            "navigation_pending_now": False,
            "strong_owning_form": True,
            "strong_password_input": True,
            "current_identity": "document:replacement",
            "submitted_identity": "document:original",
            "value_retained": True,
            "original_control_origin": "https://login.microsoftonline.com",
            "original_top_origin": "https://login.microsoftonline.com",
            "original_form_action_origin": "https://login.microsoftonline.com",
            "original_form_signature": "microsoft-post-form",
            "original_form_method": "post",
            "current_control_origin": "https://login.microsoftonline.com",
            "current_top_origin": "https://login.microsoftonline.com",
            "current_form_action_origin": "https://login.microsoftonline.com",
            "current_form_signature": "microsoft-post-form",
            "current_form_method": "post",
            "credential_error_visible": False,
        }
        cases = {
            "globalprotect-unchanged": {"protocol": "gp"},
            "wrong-kind": {"submission_kind": "password"},
            "second-gesture-used": {"attempts": 2},
            "too-early": {
                "elapsed_seconds": (
                    MICROSOFT_PASSWORD_DISPATCH_CONFIRM_SECONDS - 0.01
                )
            },
            "lookup-started": {"lookup_observed": True},
            "no-document-event": {"dispatch_observed": False},
            "safe-navigation": {"safe_navigation_observed": True},
            "credential-request": {"credential_tainted": True},
            "same-document": {"document_replaced": False},
            "navigation-request": {
                "main_navigation_request_observed": True
            },
            "unsafe-write": {"unsafe_write_request_observed": True},
            "pending-at-baseline": {
                "navigation_pending_at_baseline": True
            },
            "pending-now": {"navigation_pending_now": True},
            "original-control-origin": {
                "original_control_origin": "https://example.test"
            },
            "original-top-origin": {
                "original_top_origin": "https://example.test"
            },
            "original-action-origin": {
                "original_form_action_origin": "https://example.test"
            },
            "original-method": {"original_form_method": "get"},
            "current-control-origin": {
                "current_control_origin": "https://example.test"
            },
            "current-top-origin": {
                "current_top_origin": "https://example.test"
            },
            "current-action-origin": {
                "current_form_action_origin": "https://example.test"
            },
            "current-method": {"current_form_method": "get"},
            "weak-form": {"strong_owning_form": False},
            "weak-input": {"strong_password_input": False},
            "missing-current": {"current_identity": None},
            "missing-submitted": {"submitted_identity": None},
            "fallback-current": {"current_identity": "fallback:current"},
            "fallback-submitted": {
                "submitted_identity": "fallback:submitted"
            },
            "same-control": {"current_identity": "document:original"},
            "empty-value": {"value_retained": False},
            "form-mismatch": {
                "current_form_signature": "different-form"
            },
            "credential-error": {"credential_error_visible": True},
        }
        for name, override in cases.items():
            with self.subTest(name=name):
                self.assertFalse(
                    _anyconnect_retained_password_continuation_ready(
                        **(common | override)
                    )
                )


    def test_retained_password_late_guard_revalidates_async_evidence(self):
        common = {
            "expected_lookup_generation": 4,
            "expected_lookup_pending_count": 0,
            "expected_safe_navigation_generation": 7,
            "expected_unsafe_write_generation": 2,
            "current_lookup_generation": 4,
            "current_lookup_pending_count": 0,
            "current_safe_navigation_generation": 7,
            "current_unsafe_write_generation": 2,
        }
        self.assertTrue(
            _anyconnect_retained_password_guard_unchanged(**common)
        )
        cases = {
            "lookup-started": {"current_lookup_generation": 5},
            "lookup-pending": {"current_lookup_pending_count": 1},
            "invalid-snapshot": {"expected_lookup_pending_count": 1},
            "safe-navigation-completed": {
                "current_safe_navigation_generation": 8
            },
            "unsafe-write-started": {
                "current_unsafe_write_generation": 3
            },
        }
        for name, override in cases.items():
            with self.subTest(name=name):
                self.assertFalse(
                    _anyconnect_retained_password_guard_unchanged(
                        **(common | override)
                    )
                )

    def test_anyconnect_hydration_dispatch_expires_as_ambiguous(self):
        common = {
            "protocol": "anyconnect",
            "submission_kind": "password-unknown",
            "dispatch_observed": True,
            "credential_tainted": False,
            "unsafe_write_request_observed": False,
            "main_navigation_request_observed": False,
        }
        self.assertTrue(
            _anyconnect_password_dispatch_is_ambiguous(**common)
        )
        cases = {
            "gp-semantics-unchanged": {"protocol": "gp"},
            "known-password-stage": {"submission_kind": "password"},
            "no-dispatch": {"dispatch_observed": False},
            "credential-taint": {"credential_tainted": True},
            "unsafe-write": {"unsafe_write_request_observed": True},
            "main-navigation": {
                "main_navigation_request_observed": True
            },
        }
        for name, override in cases.items():
            with self.subTest(name=name):
                self.assertFalse(
                    _anyconnect_password_dispatch_is_ambiguous(
                        **(common | override)
                    )
                )


    def test_discovery_classification_supports_gp_without_delaying_stage_two(self):
        self.assertTrue(_password_discovery_supported("anyconnect"))
        self.assertTrue(_password_discovery_supported("gp"))
        self.assertFalse(_password_discovery_supported("pulse"))
        self.assertEqual(
            _password_submission_classification_deadline(
                "gp",
                False,
                100.0,
                400.0,
            ),
            400.0,
        )
        self.assertTrue(
            _password_discovery_classification_deferred(
                "gp",
                False,
                "password-unknown",
                399.9,
                400.0,
            )
        )
        self.assertEqual(
            _password_submission_classification_delay("anyconnect", True),
            1.0,
        )
        self.assertEqual(
            _password_submission_classification_delay("gp", True),
            1.0,
        )
        for protocol, completed, kind in (
            ("pulse", False, "password-unknown"),
            ("anyconnect", True, "password-unknown"),
            ("anyconnect", False, "password"),
        ):
            self.assertFalse(
                _password_discovery_classification_deferred(
                    protocol,
                    completed,
                    kind,
                    101.0,
                    115.0,
                )
            )

    def test_gp_navigation_replacement_requires_fresh_empty_error_free_control(self):
        common = {
            "protocol": "gp",
            "discovery_completed": False,
            "dispatch_observed": True,
            "safe_navigation_observed": True,
            "credential_tainted": False,
            "document_replaced": True,
            "current_page_is_microsoft": True,
            "current_identity": "document:2",
            "submitted_identity": "document:1",
            "current_value_empty": True,
            "credential_error_visible": False,
        }
        self.assertTrue(_gp_password_navigation_replacement_ready(**common))
        for override in (
            {"protocol": "anyconnect"},
            {"discovery_completed": True},
            {"dispatch_observed": False},
            {"safe_navigation_observed": False},
            {"credential_tainted": True},
            {"document_replaced": False},
            {"current_page_is_microsoft": False},
            {"current_identity": "document:1"},
            {"current_value_empty": False},
            {"credential_error_visible": True},
        ):
            self.assertFalse(
                _gp_password_navigation_replacement_ready(
                    **(common | override)
                )
            )

    def test_gp_client_replacement_requires_transport_free_new_control(self):
        common = {
            "protocol": "gp",
            "discovery_completed": False,
            "dispatch_observed": True,
            "safe_navigation_observed": False,
            "credential_tainted": False,
            "document_replaced": True,
            "main_frame_navigation_request_observed": False,
            "write_request_observed": False,
            "navigation_pending_at_baseline": False,
            "trusted_origin_continuity": True,
            "strong_owning_form": True,
            "current_identity": "document:2",
            "submitted_identity": "document:1",
            "current_value_empty": True,
            "credential_error_visible": False,
        }
        self.assertTrue(_gp_password_client_replacement_ready(**common))
        for name, override in (
            ("wrong-protocol", {"protocol": "anyconnect"}),
            ("completed", {"discovery_completed": True}),
            ("no-frame-transition", {"dispatch_observed": False}),
            ("safe-navigation", {"safe_navigation_observed": True}),
            ("tainted", {"credential_tainted": True}),
            ("no-document", {"document_replaced": False}),
            (
                "navigation-request",
                {"main_frame_navigation_request_observed": True},
            ),
            (
                "write-request",
                {"write_request_observed": True},
            ),
            (
                "pending-navigation",
                {"navigation_pending_at_baseline": True},
            ),
            (
                "origin-changed",
                {"trusted_origin_continuity": False},
            ),
            ("missing-form", {"strong_owning_form": False}),
            ("missing-current", {"current_identity": None}),
            ("missing-submitted", {"submitted_identity": None}),
            ("fallback-current", {"current_identity": "fallback:current"}),
            (
                "fallback-submitted",
                {"submitted_identity": "fallback:submitted"},
            ),
            ("same-control", {"current_identity": "document:1"}),
            ("nonempty-current", {"current_value_empty": False}),
            ("credential-error", {"credential_error_visible": True}),
        ):
            with self.subTest(name=name):
                self.assertFalse(
                    _gp_password_client_replacement_ready(
                        **(common | override)
                    )
                )

    def test_gp_federated_replacement_requires_complete_safe_transition(self):
        common = {
            "protocol": "gp",
            "discovery_completed": False,
            "dispatch_observed": True,
            "federated_navigation_completed": True,
            "document_replaced": True,
            "main_frame_navigation_request_observed": True,
            "credential_tainted": False,
            "unsafe_write_request_observed": False,
            "navigation_pending_at_baseline": False,
            "navigation_pending_now": False,
            "original_form_action_origin": (
                "https://login.microsoftonline.com"
            ),
            "original_top_origin": "https://login.microsoftonline.com",
            "original_control_origin": (
                "https://login.microsoftonline.com"
            ),
            "committed_federated_origin": "https://login.unibas.ch",
            "current_top_origin": "https://login.unibas.ch",
            "current_control_origin": "https://login.unibas.ch",
            "current_form_action_origin": "https://login.unibas.ch",
            "current_form_method": "post",
            "strong_owning_form": True,
            "strong_password_input": True,
            "current_identity": "document:2",
            "submitted_identity": "document:1",
            "current_value_empty": True,
            "credential_error_visible": False,
            "vpn_hostname": "vpn.unibas.ch",
        }
        self.assertTrue(_gp_password_federated_replacement_ready(**common))
        self.assertTrue(
            _gp_password_federated_replacement_ready(
                **(common | {"original_form_action_origin": None})
            )
        )
        for name, override in (
            ("wrong-protocol", {"protocol": "anyconnect"}),
            ("completed", {"discovery_completed": True}),
            ("no-dispatch", {"dispatch_observed": False}),
            (
                "no-correlated-completion",
                {"federated_navigation_completed": False},
            ),
            ("no-document", {"document_replaced": False}),
            (
                "no-main-navigation",
                {"main_frame_navigation_request_observed": False},
            ),
            ("tainted", {"credential_tainted": True}),
            (
                "unsafe-write-request",
                {"unsafe_write_request_observed": True},
            ),
            (
                "pending-at-baseline",
                {"navigation_pending_at_baseline": True},
            ),
            ("pending-now", {"navigation_pending_now": True}),
            ("weak-form", {"strong_owning_form": False}),
            ("weak-input", {"strong_password_input": False}),
            ("wrong-method", {"current_form_method": "get"}),
            ("missing-current", {"current_identity": None}),
            ("missing-submitted", {"submitted_identity": None}),
            ("fallback-current", {"current_identity": "fallback:2"}),
            (
                "fallback-submitted",
                {"submitted_identity": "fallback:1"},
            ),
            ("same-control", {"current_identity": "document:1"}),
            ("nonempty-current", {"current_value_empty": False}),
            ("credential-error", {"credential_error_visible": True}),
        ):
            with self.subTest(name=name):
                self.assertFalse(
                    _gp_password_federated_replacement_ready(
                        **(common | override)
                    )
                )

    def test_gp_federated_replacement_requires_exact_approved_origins(self):
        common = {
            "protocol": "gp",
            "discovery_completed": False,
            "dispatch_observed": True,
            "federated_navigation_completed": True,
            "document_replaced": True,
            "main_frame_navigation_request_observed": True,
            "credential_tainted": False,
            "unsafe_write_request_observed": False,
            "navigation_pending_at_baseline": False,
            "navigation_pending_now": False,
            "original_form_action_origin": (
                "https://login.microsoftonline.com"
            ),
            "original_top_origin": "https://login.microsoftonline.com",
            "original_control_origin": (
                "https://login.microsoftonline.com"
            ),
            "committed_federated_origin": "https://login.unibas.ch",
            "current_top_origin": "https://login.unibas.ch",
            "current_control_origin": "https://login.unibas.ch",
            "current_form_action_origin": "https://login.unibas.ch",
            "current_form_method": "post",
            "strong_owning_form": True,
            "strong_password_input": True,
            "current_identity": "document:2",
            "submitted_identity": "document:1",
            "current_value_empty": True,
            "credential_error_visible": False,
            "vpn_hostname": "vpn.unibas.ch",
        }
        for name, override in (
            (
                "original-action-not-microsoft",
                {"original_form_action_origin": "https://unibas.ch"},
            ),
            (
                "original-top-not-microsoft",
                {"original_top_origin": "https://login.windows.net"},
            ),
            (
                "original-control-lookalike",
                {
                    "original_control_origin": (
                        "https://login.microsoftonline.com.evil.test"
                    )
                },
            ),
            (
                "insecure-commit",
                {"committed_federated_origin": "http://login.unibas.ch"},
            ),
            (
                "nondefault-commit-port",
                {
                    "committed_federated_origin": (
                        "https://login.unibas.ch:8443"
                    ),
                    "current_top_origin": "https://login.unibas.ch:8443",
                    "current_control_origin": (
                        "https://login.unibas.ch:8443"
                    ),
                    "current_form_action_origin": (
                        "https://login.unibas.ch:8443"
                    ),
                },
            ),
            (
                "different-top-origin",
                {"current_top_origin": "https://portal.unibas.ch"},
            ),
            (
                "different-control-origin",
                {"current_control_origin": "https://portal.unibas.ch"},
            ),
            (
                "different-form-action-origin",
                {"current_form_action_origin": "https://portal.unibas.ch"},
            ),
            (
                "suffix-lookalike",
                {
                    "committed_federated_origin": (
                        "https://login.evilunibas.ch"
                    ),
                    "current_top_origin": "https://login.evilunibas.ch",
                    "current_control_origin": "https://login.evilunibas.ch",
                    "current_form_action_origin": (
                        "https://login.evilunibas.ch"
                    ),
                },
            ),
            ("unapproved-vpn-domain", {"vpn_hostname": "vpn.fhnw.ch"}),
        ):
            with self.subTest(name=name):
                self.assertFalse(
                    _gp_password_federated_replacement_ready(
                        **(common | override)
                    )
                )

        canonical = common | {
            "original_form_action_origin": (
                "HTTPS://LOGIN.MICROSOFTONLINE.COM:443/authorize"
            ),
            "committed_federated_origin": (
                "HTTPS://LOGIN.UNIBAS.CH:443/auth/continue"
            ),
        }
        self.assertTrue(
            _gp_password_federated_replacement_ready(**canonical)
                )

    def test_gp_generic_replacement_requires_and_receives_strict_route(self):
        self.assertFalse(
            _password_discovery_replacement_allowed("gp", True, False)
        )
        self.assertTrue(
            _password_discovery_replacement_allowed("gp", True, True)
        )
        self.assertTrue(
            _password_discovery_replacement_allowed(
                "anyconnect",
                True,
                False,
            )
        )
        self.assertEqual(
            _gp_password_replacement_authorization_route(
                "gp",
                True,
                False,
                False,
                False,
            ),
            "client",
        )
        self.assertEqual(
            _gp_password_replacement_authorization_route(
                "gp",
                True,
                True,
                True,
                True,
            ),
            "federated",
        )
        self.assertIsNone(
            _gp_password_replacement_authorization_route(
                "anyconnect",
                True,
                False,
                False,
                False,
            )
        )

    def test_gp_promoted_password_stage_origin_policy_is_route_bound(self):
        self.assertTrue(
            _gp_password_stage_origin_policy_valid(
                "client",
                "https://login.microsoftonline.com",
                "https://login.microsoftonline.com",
                "https://login.microsoftonline.com",
                "https://login.microsoftonline.com",
                "vpn.unibas.ch",
            )
        )
        self.assertTrue(
            _gp_password_stage_origin_policy_valid(
                "federated",
                "https://login.unibas.ch",
                "https://login.unibas.ch",
                "https://login.unibas.ch",
                "https://login.unibas.ch",
                "vpn.unibas.ch",
            )
        )
        for name, args in (
            (
                "unknown-route",
                ("other",) + ("https://login.unibas.ch",) * 4,
            ),
            (
                "client-control-changed",
                (
                    "client",
                    "https://login.microsoftonline.com",
                    "https://login.microsoftonline.com",
                    "https://evil.test",
                    "https://login.microsoftonline.com",
                ),
            ),
            (
                "federated-action-changed",
                (
                    "federated",
                    "https://login.unibas.ch",
                    "https://login.unibas.ch",
                    "https://login.unibas.ch",
                    "https://portal.unibas.ch",
                ),
            ),
            (
                "federated-lookalike",
                ("federated",) + ("https://evilunibas.ch",) * 4,
            ),
        ):
            with self.subTest(name=name):
                self.assertFalse(
                    _gp_password_stage_origin_policy_valid(
                        *args,
                        "vpn.unibas.ch",
                    )
                )

    def test_password_transition_diagnostic_is_fixed_field_and_secret_free(self):
        diagnostic = _password_transition_evidence_message(
            2,
            1,
            -1,
            1,
            0,
            0,
            0,
            0,
            federated_navigation_delta=1,
            federated_origin_match=True,
            unsafe_write_request_delta=0,
            lookup_observed=True,
            lookup_pending=False,
            classification_deferred=True,
            same_control=False,
            same_ui=False,
            value_retained=False,
            discovery_completed=False,
            error_visible=False,
            current_page_is_microsoft=True,
            origin_continuity=True,
            strong_form=True,
            strong_control=True,
            control_https=True,
            top_https=True,
            passkey_visible=True,
            primary_picker_visible=False,
            method_choice_visible=True,
            alternate_method_visible=True,
            authenticator_visible=False,
            otp_visible=False,
            processing_visible=True,
        )

        self.assertEqual(
            diagnostic,
            "password-transition-evidence nav=2 safe-nav=1 fed-nav=1 taint=0 "
            "document=1 main-nav-request=0 write=0 unsafe-write=0 outbound=0 "
            "pending-baseline=0 lookup=1 "
            "lookup-pending=0 deferred=1 "
            "same-control=0 same-ui=0 filled=0 discovery=0 error=0 "
            "microsoft=1 origin-continuity=1 strong-form=1 "
            "strong-control=1 control-tls=1 top-tls=1 fed-origin=1 "
            "passkey=1 primary-picker=0 method-choice=1 alternate-method=1 "
            "authenticator=0 otp=0 processing=1",
        )
        for forbidden in ("http", "@", "password=", "secret"):
            self.assertNotIn(forbidden, diagnostic.casefold())

    def test_idle_persistent_profile_has_a_short_pre_sensitive_hard_cap(self):
        deadline = 100.0 + SAML_PERSISTENT_PROFILE_PRE_SENSITIVE_MAX_SECONDS
        self.assertLessEqual(
            SAML_PERSISTENT_PROFILE_PRE_SENSITIVE_MAX_SECONDS,
            20.0,
        )
        self.assertFalse(
            _persistent_profile_pre_sensitive_expired(
                deadline - 0.1,
                deadline,
                force_ephemeral_browser_session=False,
                sensitive_submission_started=False,
                actionable_auth_state_visible=False,
            )
        )
        self.assertTrue(
            _persistent_profile_pre_sensitive_expired(
                deadline,
                deadline,
                force_ephemeral_browser_session=False,
                sensitive_submission_started=False,
                actionable_auth_state_visible=False,
            )
        )

    def test_profile_cap_never_retries_ephemeral_or_sensitive_auth(self):
        common = {
            "now": 120.0,
            "hard_deadline": 120.0,
        }
        self.assertFalse(
            _persistent_profile_pre_sensitive_expired(
                **common,
                force_ephemeral_browser_session=True,
                sensitive_submission_started=False,
                actionable_auth_state_visible=False,
            )
        )
        self.assertFalse(
            _persistent_profile_pre_sensitive_expired(
                **common,
                force_ephemeral_browser_session=False,
                sensitive_submission_started=True,
                actionable_auth_state_visible=False,
            )
        )
        self.assertFalse(
            _persistent_profile_pre_sensitive_expired(
                **common,
                force_ephemeral_browser_session=False,
                sensitive_submission_started=False,
                actionable_auth_state_visible=True,
            )
        )

    def test_gp_never_uses_anyconnect_persistent_profile_fast_cap(self):
        self.assertFalse(
            _persistent_profile_pre_sensitive_expired(
                now=120.0,
                hard_deadline=120.0,
                protocol="gp",
                force_ephemeral_browser_session=False,
                sensitive_submission_started=False,
                actionable_auth_state_visible=False,
            )
        )

    def test_explanatory_text_is_not_an_actionable_control(self):
        self.assertFalse(_is_actionable_control("div"))
        self.assertFalse(_is_actionable_control("p"))
        self.assertFalse(_is_actionable_control("input", input_type="text"))

    def test_short_submit_label_does_not_match_alternate_method_link(self):
        pattern = _exact_action_pattern("Anmelden")
        self.assertIsNotNone(pattern.search("Anmelden"))
        self.assertIsNotNone(pattern.search("  ANMELDEN  "))
        self.assertIsNone(pattern.search("Auf andere Weise anmelden"))
        self.assertFalse(_allows_partial_action_label("Anmelden"))
        self.assertTrue(_allows_partial_action_label(
            "Ich kann meine Microsoft Authenticator-App nicht verwenden"
        ))

    def test_only_enabled_button_link_or_submit_controls_are_actionable(self):
        self.assertTrue(_is_actionable_control("button"))
        self.assertTrue(_is_actionable_control("span", role="button"))
        self.assertTrue(_is_actionable_control("a", role="link"))
        self.assertTrue(_is_actionable_control("input", input_type="submit"))
        self.assertTrue(_is_actionable_control("a", has_href=True))
        self.assertTrue(_is_actionable_control("div", has_click_handler=True))
        self.assertTrue(_is_actionable_control("div", has_data_value=True))
        self.assertTrue(_is_actionable_control("div", tab_index=0))
        self.assertTrue(_is_actionable_control("div", pointer_cursor=True))
        self.assertFalse(_is_actionable_control("div", tab_index=-1))
        self.assertFalse(_is_actionable_control("button", disabled=True))

    def test_only_enabled_editable_inputs_are_usable(self):
        self.assertTrue(_is_usable_input_state(True, True))
        self.assertFalse(_is_usable_input_state(False, True))
        self.assertFalse(_is_usable_input_state(True, False))

    def test_submitted_password_never_becomes_actionable_on_dom_replacement(self):
        self.assertTrue(
            _password_control_is_progress("document:1", None, False)
        )
        self.assertFalse(
            _password_control_is_progress(
                "document:1",
                "document:1",
                True,
            )
        )
        self.assertFalse(
            _password_control_is_progress(
                "document:2",
                "document:1",
                True,
            )
        )
        self.assertFalse(
            _password_control_is_progress("document:2", None, True)
        )

    def test_sensitive_click_failure_is_one_shot_and_fail_closed(self):
        class FailingLocator:
            def __init__(self):
                self.calls = []

            def click(self, **kwargs):
                self.calls.append(kwargs)
                raise TimeoutError("navigation outcome unknown")

        locator = FailingLocator()
        with self.assertRaises(_SensitiveActionUncertainError):
            _attempt_locator_click(
                locator,
                timeout_ms=1500,
                sensitive=True,
                action_name="TOTP submission",
            )
        self.assertEqual(len(locator.calls), 1)
        self.assertEqual(locator.calls[0]["timeout"], 1500)
        self.assertTrue(locator.calls[0]["no_wait_after"])

    def test_sensitive_enter_failure_is_one_shot_and_fail_closed(self):
        class FailingLocator:
            def __init__(self):
                self.calls = []

            def press(self, key, **kwargs):
                self.calls.append((key, kwargs))
                raise TimeoutError("submission outcome unknown")

        locator = FailingLocator()
        with self.assertRaises(_SensitiveActionUncertainError):
            _attempt_locator_press(
                locator,
                "Enter",
                sensitive=True,
                action_name="password submission",
            )
        self.assertEqual(len(locator.calls), 1)
        self.assertEqual(locator.calls[0][0], "Enter")
        self.assertTrue(locator.calls[0][1]["no_wait_after"])

    def test_submitted_otp_never_becomes_actionable_on_dom_replacement(self):
        self.assertTrue(_otp_control_is_progress(None, None, False))
        self.assertFalse(
            _otp_control_is_progress("document:1", "document:1", True)
        )
        self.assertFalse(
            _otp_control_is_progress("document:2", "document:1", True)
        )
        self.assertFalse(
            _should_submit_totp_for_control(False, 100, 101)
        )
        self.assertFalse(
            _should_submit_totp_for_control(True, 100, 101)
        )

    def test_sensitive_action_ledger_is_flow_wide_not_dom_scoped(self):
        ledger = _SensitiveActionLedger()
        actions = (
            "password",
            "cached-account-selection",
            "totp",
            "kmsi",
            "push",
            "passkey-registration-skip",
        )
        for action in actions:
            self.assertFalse(ledger.dispatched(action))
            ledger.record(action)
            self.assertTrue(ledger.dispatched(action))
        self.assertTrue(ledger.dispatched("password-unknown"))
        self.assertTrue(ledger.dispatched("credential-lookup"))

    def test_password_alternate_requires_unchanged_filled_form_and_no_dispatch(self):
        elapsed = MICROSOFT_PASSWORD_DISPATCH_CONFIRM_SECONDS
        self.assertTrue(
            _password_alternate_dispatch_allowed(
                1,
                elapsed,
                outbound_dispatch_observed=False,
                same_filled_form=True,
            )
        )
        for attempts, dispatched, same_form in (
            (2, False, True),
            (1, True, True),
            (1, False, False),
        ):
            self.assertFalse(
                _password_alternate_dispatch_allowed(
                    attempts,
                    elapsed,
                    outbound_dispatch_observed=dispatched,
                    same_filled_form=same_form,
                )
            )
        self.assertFalse(
            _password_alternate_dispatch_allowed(
                1,
                elapsed - 0.01,
                outbound_dispatch_observed=False,
                same_filled_form=True,
            )
        )

    def test_inflight_navigation_blocks_password_alternate_dispatch(self):
        self.assertFalse(
            _password_transition_blocks_alternate_dispatch(
                False,
                False,
                False,
            )
        )
        for evidence in (
            (True, False, False),
            (False, True, False),
            (False, False, True),
        ):
            with self.subTest(evidence=evidence):
                self.assertTrue(
                    _password_transition_blocks_alternate_dispatch(*evidence)
                )

    @staticmethod
    def _dispatch_request(
        *,
        url="https://login.microsoftonline.com/common/login",
        method="POST",
        is_navigation=False,
        frame=None,
        post_data=None,
        resource_type="xhr",
    ):
        return SimpleNamespace(
            url=url,
            method=method,
            post_data=post_data,
            is_navigation_request=lambda: is_navigation,
            frame=frame,
            resource_type=resource_type,
        )

    def test_gp_federated_domain_matching_is_explicit_and_label_bound(self):
        self.assertEqual(_institution_domain("VPN.UNIBAS.CH."), "unibas.ch")
        self.assertEqual(_institution_domain("login.unibas.ch"), "unibas.ch")
        for hostname in (
            "evilunibas.ch",
            "unibas.ch.evil.test",
            "unibas.example",
            "",
            None,
        ):
            with self.subTest(hostname=hostname):
                self.assertIsNone(_institution_domain(hostname))

        self.assertTrue(
            _https_origin_matches_vpn_institution(
                "https://login.unibas.ch",
                "vpn.unibas.ch",
            )
        )
        for origin, vpn_hostname in (
            ("http://login.unibas.ch", "vpn.unibas.ch"),
            ("https://login.unibas.ch:8443", "vpn.unibas.ch"),
            ("https://evilunibas.ch", "vpn.unibas.ch"),
            ("https://login.unibas.ch.evil.test", "vpn.unibas.ch"),
            ("https://login.unibas.ch", "vpn.fhnw.ch"),
        ):
            with self.subTest(origin=origin, vpn_hostname=vpn_hostname):
                self.assertFalse(
                    _https_origin_matches_vpn_institution(
                        origin,
                        vpn_hostname,
                    )
                )

    def test_https_origin_canonicalization_discards_url_details(self):
        self.assertEqual(
            _canonical_https_origin(
                "HTTPS://LOGIN.UNIBAS.CH:443/path?opaque=state#fragment"
            ),
            "https://login.unibas.ch",
        )
        self.assertEqual(
            _canonical_https_origin("https://login.unibas.ch:8443/path"),
            "https://login.unibas.ch:8443",
        )
        for value in (
            "http://login.unibas.ch",
            "https://user@login.unibas.ch",
            "https://login.unibas.ch:invalid",
            "not-an-origin",
            None,
        ):
            with self.subTest(value=value):
                self.assertIsNone(_canonical_https_origin(value))

    def test_federated_safe_navigation_requires_response_and_matching_commit(self):
        for method in ("GET", "HEAD"):
            with self.subTest(method=method):
                tracker = _SensitiveDispatchEvidenceTracker()
                main_frame = object()
                baseline = (
                    tracker.federated_safe_navigation_request_generation
                )
                request = self._dispatch_request(
                    url=(
                        "https://login.unibas.ch/auth/continue"
                        "?opaque=relay-state"
                    ),
                    method=method,
                    is_navigation=True,
                    frame=main_frame,
                )

                tracker.request_started(
                    request,
                    main_frame=main_frame,
                    expected_secret="sentinel-secret",
                )
                self.assertGreater(
                    tracker.federated_safe_navigation_request_generation,
                    baseline,
                )
                self.assertEqual(
                    tracker.federated_safe_navigation_generation,
                    baseline,
                )
                tracker.response_received(
                    SimpleNamespace(request=request, status=200)
                )
                self.assertEqual(
                    tracker.federated_safe_navigation_generation,
                    baseline,
                )

                tracker.main_frame_navigated(
                    "https://login.unibas.ch/password?ignored=1"
                )

                self.assertGreater(
                    tracker.federated_safe_navigation_generation,
                    baseline,
                )
                self.assertEqual(
                    tracker.federated_safe_navigation_origin,
                    "https://login.unibas.ch",
                )

    def test_prebaseline_federated_response_cannot_become_new_evidence(self):
        tracker = _SensitiveDispatchEvidenceTracker()
        main_frame = object()
        request = self._dispatch_request(
            url="https://login.unibas.ch/password",
            method="GET",
            is_navigation=True,
            frame=main_frame,
        )
        tracker.request_started(request, main_frame=main_frame)
        baseline = tracker.federated_safe_navigation_request_generation

        tracker.response_received(SimpleNamespace(request=request, status=200))
        tracker.main_frame_navigated("https://login.unibas.ch/password")

        self.assertEqual(
            tracker.federated_safe_navigation_generation,
            baseline,
        )
        self.assertFalse(
            tracker.federated_safe_navigation_generation > baseline
        )

    def test_federated_redirect_response_never_qualifies(self):
        tracker = _SensitiveDispatchEvidenceTracker()
        main_frame = object()
        redirect_request = self._dispatch_request(
            url="https://portal.unibas.ch/redirect",
            method="GET",
            is_navigation=True,
            frame=main_frame,
        )
        tracker.request_started(redirect_request, main_frame=main_frame)
        tracker.response_received(
            SimpleNamespace(request=redirect_request, status=302)
        )
        tracker.main_frame_navigated("https://portal.unibas.ch/redirect")
        self.assertEqual(tracker.federated_safe_navigation_generation, 0)
        self.assertIsNone(tracker.federated_safe_navigation_origin)

        final_request = self._dispatch_request(
            url="https://login.unibas.ch/password",
            method="GET",
            is_navigation=True,
            frame=main_frame,
        )
        tracker.request_started(final_request, main_frame=main_frame)
        tracker.response_received(
            SimpleNamespace(request=final_request, status=200)
        )
        tracker.main_frame_navigated("https://login.unibas.ch/password")
        self.assertEqual(
            tracker.federated_safe_navigation_origin,
            "https://login.unibas.ch",
        )

    def test_federated_cached_document_304_can_qualify_on_exact_commit(self):
        tracker = _SensitiveDispatchEvidenceTracker()
        main_frame = object()
        request = self._dispatch_request(
            url="https://login.unibas.ch/password",
            method="GET",
            is_navigation=True,
            frame=main_frame,
        )
        tracker.request_started(request, main_frame=main_frame)
        tracker.response_received(SimpleNamespace(request=request, status=304))
        tracker.main_frame_navigated("https://login.unibas.ch/password")

        self.assertEqual(tracker.federated_safe_navigation_generation, 1)
        self.assertEqual(
            tracker.federated_safe_navigation_origin,
            "https://login.unibas.ch",
        )

    def test_federated_error_response_is_cleaned_without_qualification(self):
        tracker = _SensitiveDispatchEvidenceTracker()
        main_frame = object()
        request = self._dispatch_request(
            url="https://login.unibas.ch/password",
            method="GET",
            is_navigation=True,
            frame=main_frame,
        )
        tracker.request_started(request, main_frame=main_frame)
        tracker.response_received(SimpleNamespace(request=request, status=401))
        tracker.main_frame_navigated("https://login.unibas.ch/password")

        self.assertEqual(tracker.federated_safe_navigation_generation, 0)
        self.assertIsNone(tracker.federated_safe_navigation_origin)
        self.assertFalse(
            tracker._pending_federated_safe_navigation_requests
        )
        self.assertFalse(
            tracker._successful_federated_safe_navigation_responses
        )

    def test_federated_response_cannot_authorize_a_different_commit(self):
        tracker = _SensitiveDispatchEvidenceTracker()
        main_frame = object()
        request = self._dispatch_request(
            url="https://login.unibas.ch/password",
            method="GET",
            is_navigation=True,
            frame=main_frame,
        )
        tracker.request_started(request, main_frame=main_frame)
        tracker.response_received(SimpleNamespace(request=request, status=200))

        tracker.main_frame_navigated("https://other.unibas.ch/password")
        self.assertEqual(tracker.federated_safe_navigation_generation, 0)
        self.assertIsNone(tracker.federated_safe_navigation_origin)

        # The successful response was consumed by the mismatched commit and
        # cannot be replayed by a later same-origin client-side transition.
        tracker.main_frame_navigated("https://login.unibas.ch/password")
        self.assertEqual(tracker.federated_safe_navigation_generation, 0)

    def test_ambiguous_same_origin_federated_responses_fail_closed(self):
        tracker = _SensitiveDispatchEvidenceTracker()
        main_frame = object()
        requests = [
            self._dispatch_request(
                url=f"https://login.unibas.ch/password?attempt={index}",
                method="GET",
                is_navigation=True,
                frame=main_frame,
            )
            for index in range(2)
        ]
        for request in requests:
            tracker.request_started(request, main_frame=main_frame)
            tracker.response_received(
                SimpleNamespace(request=request, status=200)
            )

        tracker.main_frame_navigated("https://login.unibas.ch/password")

        self.assertEqual(tracker.federated_safe_navigation_generation, 0)
        self.assertIsNone(tracker.federated_safe_navigation_origin)
        self.assertFalse(
            tracker._successful_federated_safe_navigation_responses
        )

    def test_federated_navigation_candidates_are_cleaned_and_bounded(self):
        tracker = _SensitiveDispatchEvidenceTracker()
        main_frame = object()
        requests = [
            self._dispatch_request(
                url=f"https://login.unibas.ch/password?request={index}",
                method="GET",
                is_navigation=True,
                frame=main_frame,
            )
            for index in range(80)
        ]
        for request in requests:
            tracker.request_started(request, main_frame=main_frame)
        self.assertLessEqual(
            len(tracker._pending_federated_safe_navigation_requests),
            tracker._MAX_TRACKED_NAVIGATIONS,
        )

        for request in requests:
            tracker.response_received(
                SimpleNamespace(request=request, status=200)
            )
        self.assertFalse(
            tracker._pending_federated_safe_navigation_requests
        )
        self.assertLessEqual(
            len(tracker._successful_federated_safe_navigation_responses),
            tracker._MAX_TRACKED_NAVIGATIONS,
        )

        tracker.main_frame_navigated("https://login.unibas.ch/password")
        self.assertFalse(
            tracker._successful_federated_safe_navigation_responses
        )

        failed_request = self._dispatch_request(
            url="https://login.unibas.ch/failed",
            method="GET",
            is_navigation=True,
            frame=main_frame,
        )
        tracker.request_started(failed_request, main_frame=main_frame)
        tracker.request_failed(failed_request)
        self.assertNotIn(
            tracker._request_key(failed_request),
            tracker._pending_federated_safe_navigation_requests,
        )

    def test_ineligible_federated_requests_never_become_candidates(self):
        main_frame = object()
        cases = (
            {
                "url": "http://login.unibas.ch/password",
                "method": "GET",
                "is_navigation": True,
                "frame": main_frame,
            },
            {
                "url": "https://login.unibas.ch/password",
                "method": "POST",
                "is_navigation": True,
                "frame": main_frame,
            },
            {
                "url": "https://login.unibas.ch/password",
                "method": "GET",
                "is_navigation": True,
                "frame": object(),
            },
            {
                "url": (
                    "https://login.unibas.ch/password"
                    "?password=sentinel-secret"
                ),
                "method": "GET",
                "is_navigation": True,
                "frame": main_frame,
            },
            {
                "url": "https://user@login.unibas.ch/password",
                "method": "GET",
                "is_navigation": True,
                "frame": main_frame,
            },
        )
        for case in cases:
            with self.subTest(case=case):
                tracker = _SensitiveDispatchEvidenceTracker()
                tracker.request_started(
                    self._dispatch_request(**case),
                    main_frame=main_frame,
                    expected_secret="sentinel-secret",
                )
                self.assertEqual(
                    tracker.federated_safe_navigation_request_generation,
                    0,
                )
                self.assertFalse(
                    tracker._pending_federated_safe_navigation_requests
                )

    def test_microsoft_redirect_safe_navigation_behavior_is_preserved(self):
        tracker = _SensitiveDispatchEvidenceTracker()
        main_frame = object()
        request = self._dispatch_request(
            url="https://login.microsoftonline.com/common/login",
            method="GET",
            is_navigation=True,
            frame=main_frame,
        )
        baseline = tracker.safe_navigation_request_generation
        tracker.request_started(request, main_frame=main_frame)

        self.assertTrue(
            tracker.response_received(
                SimpleNamespace(request=request, status=302)
            )
        )
        self.assertGreater(tracker.safe_navigation_generation, baseline)
        tracker.main_frame_navigated(
            "https://login.microsoftonline.com/common/redirect"
        )
        self.assertEqual(tracker.federated_safe_navigation_generation, 0)

    def test_sensitive_dispatch_tracker_ignores_background_telemetry_post(self):
        tracker = _SensitiveDispatchEvidenceTracker()
        main_frame = object()
        self.assertFalse(
            tracker.request_started(
                self._dispatch_request(
                    url="https://login.microsoftonline.com/common/telemetry",
                    method="POST",
                    is_navigation=False,
                    frame=main_frame,
                ),
                main_frame=main_frame,
            )
        )
        self.assertFalse(
            tracker.request_started(
                self._dispatch_request(
                    url="https://telemetry.example.test/event",
                    is_navigation=True,
                    frame=main_frame,
                ),
                main_frame=main_frame,
            )
        )
        self.assertEqual(tracker.generation, 0)

    def test_sensitive_dispatch_tracker_counts_main_frame_navigation_requests(self):
        tracker = _SensitiveDispatchEvidenceTracker()
        main_frame = object()
        for method in ("GET", "POST"):
            self.assertTrue(
                tracker.request_started(
                    self._dispatch_request(
                        method=method,
                        is_navigation=True,
                        frame=main_frame,
                    ),
                    main_frame=main_frame,
                )
            )
        self.assertEqual(tracker.generation, 2)

    def test_tracker_frame_transition_has_no_request_or_write_evidence(self):
        tracker = _SensitiveDispatchEvidenceTracker()
        baseline = tracker.transition_snapshot()

        tracker.main_frame_navigated()

        self.assertEqual(tracker.main_document_generation, baseline[3] + 1)
        self.assertEqual(
            tracker.main_frame_navigation_request_generation,
            baseline[4],
        )
        self.assertEqual(tracker.write_request_generation, baseline[5])
        self.assertEqual(tracker.outbound_request_generation, baseline[6])
        self.assertEqual(
            tracker.pending_main_frame_navigation_count,
            baseline[7],
        )
        self.assertEqual(tracker.credential_taint_generation, baseline[2])

    def test_tracker_main_frame_get_counts_navigation_but_not_write(self):
        tracker = _SensitiveDispatchEvidenceTracker()
        main_frame = object()

        tracker.request_started(
            self._dispatch_request(
                method="GET",
                is_navigation=True,
                frame=main_frame,
            ),
            main_frame=main_frame,
        )

        self.assertEqual(
            tracker.main_frame_navigation_request_generation,
            1,
        )
        self.assertEqual(tracker.write_request_generation, 0)
        self.assertEqual(tracker.outbound_request_generation, 1)
        self.assertEqual(tracker.pending_main_frame_navigation_count, 1)

    def test_tracker_preexisting_navigation_stays_pending_until_frame_commit(self):
        tracker = _SensitiveDispatchEvidenceTracker()
        main_frame = object()
        request = self._dispatch_request(
            method="GET",
            is_navigation=True,
            frame=main_frame,
        )

        tracker.request_started(request, main_frame=main_frame)
        baseline = tracker.transition_snapshot()
        tracker.response_received(
            SimpleNamespace(request=request, status=200)
        )

        self.assertEqual(baseline[7], 1)
        self.assertEqual(tracker.pending_main_frame_navigation_count, 1)
        tracker.main_frame_navigated()
        self.assertEqual(tracker.pending_main_frame_navigation_count, 0)

    def test_tracker_lookup_post_counts_write_without_navigation_or_taint(self):
        tracker = _SensitiveDispatchEvidenceTracker()
        main_frame = object()

        tracker.request_started(
            self._dispatch_request(
                url=(
                    "https://login.microsoftonline.com/common/"
                    "GetCredentialType"
                ),
                method="POST",
                is_navigation=False,
                frame=main_frame,
                post_data=json.dumps(
                    {
                        "username": "alice@example.test",
                        "flowToken": "opaque-state",
                        "isFidoSupported": True,
                    }
                ),
            ),
            main_frame=main_frame,
            expected_secret="sentinel-secret",
        )

        self.assertEqual(
            tracker.main_frame_navigation_request_generation,
            0,
        )
        self.assertEqual(tracker.write_request_generation, 1)
        self.assertEqual(tracker.unsafe_write_request_generation, 0)
        self.assertEqual(tracker.outbound_request_generation, 1)
        self.assertEqual(tracker.credential_taint_generation, 0)

    def test_tracker_lookup_password_or_opaque_payload_is_unsafe_and_tainted(self):
        class OpaqueLookupRequest:
            url = (
                "https://login.microsoftonline.com/common/"
                "GetCredentialType"
            )
            method = "POST"
            resource_type = "xhr"
            frame = None

            @staticmethod
            def is_navigation_request():
                return False

            @property
            def post_data(self):
                raise RuntimeError("opaque payload")

        requests = (
            self._dispatch_request(
                url=(
                    "https://login.microsoftonline.com/common/"
                    "GetCredentialType"
                ),
                method="POST",
                post_data=json.dumps(
                    {
                        "username": "alice@example.test",
                        "password": "sentinel-secret",
                    }
                ),
            ),
            self._dispatch_request(
                url=(
                    "https://login.microsoftonline.com/common/"
                    "GetCredentialType"
                ),
                method="POST",
                post_data=(
                    '{"username":"alice@example.test",'
                    '"opaque":"sentinel-\\u0073ecret"}'
                ),
            ),
            OpaqueLookupRequest(),
        )
        for request in requests:
            with self.subTest(request=type(request).__name__):
                tracker = _SensitiveDispatchEvidenceTracker()
                tracker.request_started(
                    request,
                    main_frame=object(),
                    expected_secret="sentinel-secret",
                )
                self.assertEqual(tracker.write_request_generation, 1)
                self.assertEqual(
                    tracker.unsafe_write_request_generation,
                    1,
                )
                self.assertGreater(
                    tracker.credential_taint_generation,
                    0,
                )

    def test_tracker_unrelated_write_is_unsafe(self):
        tracker = _SensitiveDispatchEvidenceTracker()
        tracker.request_started(
            self._dispatch_request(
                url="https://login.microsoftonline.com/common/other",
                method="POST",
                post_data=json.dumps({"username": "alice@example.test"}),
            ),
            main_frame=object(),
            expected_secret="sentinel-secret",
        )

        self.assertEqual(tracker.write_request_generation, 1)
        self.assertEqual(tracker.unsafe_write_request_generation, 1)

    def test_tracker_ignores_known_telemetry_write_but_counts_outbound(self):
        self.assertTrue(
            _is_known_microsoft_telemetry_host(
                "browser.events.data.microsoft.com"
            )
        )
        self.assertFalse(
            _is_known_microsoft_telemetry_host("login.microsoftonline.com")
        )
        safe_payloads = (
            "event=page-performance",
            json.dumps(
                [
                    {"name": "page-performance"},
                    {"isPasswordless": False},
                ]
            ),
            '{"name":"first"}\n{"name":"second"}\n',
        )
        for post_data in safe_payloads:
            with self.subTest(payload_length=len(post_data)):
                tracker = _SensitiveDispatchEvidenceTracker()
                main_frame = object()
                tracker.request_started(
                    self._dispatch_request(
                        url=(
                            "https://browser.events.data.microsoft.com/"
                            "collect"
                        ),
                        method="POST",
                        is_navigation=False,
                        frame=main_frame,
                        post_data=post_data,
                    ),
                    main_frame=main_frame,
                    expected_secret="sentinel-secret",
                )

                self.assertEqual(tracker.write_request_generation, 1)
                self.assertEqual(
                    tracker.unsafe_write_request_generation,
                    0,
                )
                self.assertEqual(tracker.outbound_request_generation, 1)
                self.assertEqual(tracker.credential_taint_generation, 0)

    def test_telemetry_request_carrying_password_still_taints(self):
        tracker = _SensitiveDispatchEvidenceTracker()
        main_frame = object()

        tracker.request_started(
            self._dispatch_request(
                url="https://browser.events.data.microsoft.com/collect",
                method="POST",
                is_navigation=False,
                frame=main_frame,
                post_data="password=sentinel-secret",
            ),
            main_frame=main_frame,
            expected_secret="sentinel-secret",
        )

        self.assertEqual(tracker.write_request_generation, 1)
        self.assertEqual(tracker.unsafe_write_request_generation, 1)
        self.assertGreater(tracker.credential_taint_generation, 0)

    def test_opaque_telemetry_write_is_tainted_and_counted(self):
        class OpaqueTelemetryRequest:
            url = "https://browser.events.data.microsoft.com/collect"
            method = "POST"
            frame = None

            @staticmethod
            def is_navigation_request():
                return False

            @property
            def post_data(self):
                raise RuntimeError("opaque payload")

        tracker = _SensitiveDispatchEvidenceTracker()
        tracker.request_started(
            OpaqueTelemetryRequest(),
            main_frame=object(),
            expected_secret="sentinel-secret",
        )

        self.assertEqual(tracker.write_request_generation, 1)
        self.assertEqual(tracker.unsafe_write_request_generation, 1)
        self.assertGreater(tracker.credential_taint_generation, 0)

    def test_tracker_main_frame_post_counts_navigation_and_write(self):
        tracker = _SensitiveDispatchEvidenceTracker()
        main_frame = object()

        tracker.request_started(
            self._dispatch_request(
                method="POST",
                is_navigation=True,
                frame=main_frame,
                post_data="opaque=1",
            ),
            main_frame=main_frame,
        )

        self.assertEqual(
            tracker.main_frame_navigation_request_generation,
            1,
        )
        self.assertEqual(tracker.write_request_generation, 1)
        self.assertEqual(tracker.outbound_request_generation, 1)
        self.assertEqual(tracker.pending_main_frame_navigation_count, 1)

    def test_gp_safe_get_requires_response_and_new_document(self):
        tracker = _SensitiveDispatchEvidenceTracker()
        main_frame = object()
        baseline = tracker.snapshot()
        request = self._dispatch_request(
            method="GET",
            is_navigation=True,
            frame=main_frame,
        )

        self.assertTrue(
            tracker.request_started(
                request,
                main_frame=main_frame,
                expected_secret="sentinel-secret",
            )
        )
        self.assertEqual(tracker.safe_navigation_generation, baseline[1])
        self.assertTrue(
            tracker.response_received(
                SimpleNamespace(request=request, status=200)
            )
        )
        tracker.main_frame_navigated()

        self.assertGreater(tracker.safe_navigation_generation, baseline[1])
        self.assertEqual(tracker.credential_taint_generation, baseline[2])
        self.assertGreater(tracker.main_document_generation, baseline[3])

    def test_preexisting_get_response_cannot_authorize_password_replacement(self):
        tracker = _SensitiveDispatchEvidenceTracker()
        main_frame = object()
        request = self._dispatch_request(
            method="GET",
            is_navigation=True,
            frame=main_frame,
        )
        tracker.request_started(
            request,
            main_frame=main_frame,
            expected_secret="sentinel-secret",
        )
        baseline = tracker.snapshot()
        tracker.response_received(
            SimpleNamespace(request=request, status=200)
        )
        tracker.main_frame_navigated()

        self.assertEqual(tracker.safe_navigation_generation, baseline[1])
        self.assertGreater(tracker.main_document_generation, baseline[3])
        self.assertFalse(
            _gp_password_navigation_replacement_ready(
                "gp",
                False,
                True,
                tracker.safe_navigation_generation > baseline[1],
                False,
                True,
                True,
                "document:2",
                "document:1",
                True,
                False,
            )
        )

    def test_password_post_then_get_redirect_remains_tainted(self):
        tracker = _SensitiveDispatchEvidenceTracker()
        main_frame = object()
        baseline = tracker.snapshot()
        post_request = self._dispatch_request(
            method="POST",
            is_navigation=True,
            frame=main_frame,
            post_data="passwd=sentinel-secret",
        )
        tracker.request_started(
            post_request,
            main_frame=main_frame,
            expected_secret="sentinel-secret",
        )
        get_request = self._dispatch_request(
            method="GET",
            is_navigation=True,
            frame=main_frame,
        )
        tracker.request_started(
            get_request,
            main_frame=main_frame,
            expected_secret="sentinel-secret",
        )
        tracker.response_received(
            SimpleNamespace(request=get_request, status=200)
        )
        tracker.main_frame_navigated()

        self.assertGreater(tracker.safe_navigation_generation, baseline[1])
        self.assertGreater(tracker.credential_taint_generation, baseline[2])
        self.assertFalse(
            _gp_password_navigation_replacement_ready(
                "gp",
                False,
                True,
                True,
                True,
                True,
                True,
                "document:2",
                "document:1",
                True,
                False,
            )
        )
        self.assertNotIn("sentinel-secret", repr(tracker))

    def test_get_query_with_password_is_tainted_not_safe(self):
        tracker = _SensitiveDispatchEvidenceTracker()
        main_frame = object()
        request = self._dispatch_request(
            url=(
                "https://login.microsoftonline.com/common/login"
                "?passwd=sentinel-secret"
            ),
            method="GET",
            is_navigation=True,
            frame=main_frame,
        )
        tracker.request_started(
            request,
            main_frame=main_frame,
            expected_secret="sentinel-secret",
        )
        self.assertGreater(tracker.credential_taint_generation, 0)
        self.assertFalse(
            tracker.response_received(
                SimpleNamespace(request=request, status=200)
            )
        )
        self.assertEqual(tracker.safe_navigation_generation, 0)

    def test_getcredentialtype_without_password_does_not_taint(self):
        tracker = _SensitiveDispatchEvidenceTracker()
        main_frame = object()
        request = self._dispatch_request(
            url=(
                "https://login.microsoftonline.com/common/"
                "GetCredentialType"
            ),
            method="POST",
            is_navigation=False,
            frame=main_frame,
            post_data=json.dumps({"username": "alice@example.test"}),
        )
        self.assertFalse(
            tracker.request_started(
                request,
                main_frame=main_frame,
                expected_secret="sentinel-secret",
            )
        )
        self.assertEqual(tracker.credential_taint_generation, 0)
        self.assertEqual(tracker.unsafe_write_request_generation, 0)

    def test_sensitive_dispatch_tracker_ignores_subframe_navigation(self):
        tracker = _SensitiveDispatchEvidenceTracker()
        main_frame = object()
        self.assertTrue(
            tracker.request_started(
                self._dispatch_request(
                    is_navigation=True,
                    frame=main_frame,
                ),
                main_frame=main_frame,
            )
        )
        self.assertEqual(tracker.generation, 1)
        self.assertFalse(
            tracker.request_started(
                self._dispatch_request(
                    is_navigation=True,
                    frame=object(),
                ),
                main_frame=main_frame,
            )
        )
        tracker.main_frame_navigated()
        self.assertEqual(tracker.generation, 2)

    def test_account_tile_requires_complete_username_identity(self):
        username = "alice@fhnw.ch"
        self.assertTrue(
            _account_tile_matches_username(
                "Alice Example\nalice@fhnw.ch",
                username,
            )
        )
        self.assertFalse(
            _account_tile_matches_username("Alice Example", username)
        )
        self.assertFalse(
            _account_tile_matches_username("bob@fhnw.ch", username)
        )
        self.assertFalse(
            _account_tile_matches_username("malice@fhnw.ch", username)
        )

    def test_authenticator_challenge_immediately_latches_sensitive_state(self):
        self.assertTrue(
            _latch_sensitive_authenticator_challenge(False, True)
        )
        self.assertTrue(
            _latch_sensitive_authenticator_challenge(True, False)
        )
        self.assertFalse(
            _latch_sensitive_authenticator_challenge(False, False)
        )

    def test_cached_account_selection_immediately_latches_sensitive_state(self):
        self.assertTrue(
            _latch_sensitive_cached_account_selection(False, True)
        )
        self.assertTrue(
            _latch_sensitive_cached_account_selection(True, False)
        )
        self.assertFalse(
            _latch_sensitive_cached_account_selection(False, False)
        )


    def test_submission_grace_requires_processing_or_sensitive_action(self):
        self.assertTrue(_should_extend_submission_grace(True, "generic"))
        self.assertTrue(_should_extend_submission_grace(False, "password"))
        self.assertTrue(_should_extend_submission_grace(False, "totp"))
        self.assertTrue(_should_extend_submission_grace(False, "kmsi"))
        self.assertTrue(
            _should_extend_submission_grace(
                False,
                "passkey-registration-skip",
            )
        )
        self.assertTrue(
            _should_extend_submission_grace(
                False,
                "cached-account-selection",
            )
        )
        self.assertFalse(_should_extend_submission_grace(False, "username"))
        self.assertFalse(_should_extend_submission_grace(False, "generic"))

    def test_cached_account_password_form_completes_transition_wait(self):
        self.assertTrue(
            _password_field_completes_submission_transition(
                "cached-account-selection",
                True,
            )
        )
        self.assertTrue(
            _password_field_completes_submission_transition("username", True)
        )
        self.assertFalse(
            _password_field_completes_submission_transition(
                "cached-account-selection",
                False,
            )
        )
        self.assertFalse(
            _password_field_completes_submission_transition("password", True)
        )

    def test_only_pre_sensitive_ui_stall_allows_clean_session_retry(self):
        self.assertIsInstance(
            _ui_stall_exception("stalled", False),
            SamlUiStalledError,
        )
        sensitive_error = _ui_stall_exception("stalled", True)
        self.assertIsInstance(sensitive_error, RuntimeError)
        self.assertNotIsInstance(sensitive_error, SamlUiStalledError)

    def test_stale_ui_recovery_is_fast_but_honors_submit_grace(self):
        self.assertEqual(SAML_UI_MAX_RECOVERIES, 1)
        self.assertLessEqual(SAML_UI_STALL_WINDOW_SECONDS, 8.0)
        self.assertGreaterEqual(SAML_UI_POST_SUBMIT_GRACE_SECONDS, 20.0)
        self.assertEqual(
            _stale_ui_recovery_action(
                100.0,
                100.0 + SAML_UI_STALL_WINDOW_SECONDS - 0.1,
                0,
            ),
            "wait",
        )
        self.assertEqual(
            _stale_ui_recovery_action(
                100.0,
                100.0 + SAML_UI_STALL_WINDOW_SECONDS,
                0,
            ),
            "recover",
        )
        self.assertEqual(
            _stale_ui_recovery_action(
                100.0,
                100.0 + SAML_UI_STALL_WINDOW_SECONDS,
                0,
                grace_until=100.0 + SAML_UI_POST_SUBMIT_GRACE_SECONDS,
            ),
            "wait",
        )
        self.assertEqual(
            _stale_ui_recovery_action(
                100.0,
                100.0 + SAML_UI_STALL_WINDOW_SECONDS,
                1,
            ),
            "fail",
        )

    def test_unresolved_submission_gets_progressive_bounded_extensions(self):
        self.assertEqual(SAML_UI_MAX_PROCESSING_EXTENSIONS, 6)
        deadline, used = _extend_processing_grace(
            now=120.0,
            grace_until=120.0,
            processing_visible=True,
            extensions_used=0,
            hard_deadline=180.0,
        )
        self.assertEqual(deadline, 120.0 + SAML_UI_PROCESSING_EXTENSION_SECONDS)
        self.assertEqual(used, 1)
        deadline, used = _extend_processing_grace(
            now=deadline,
            grace_until=deadline,
            processing_visible=True,
            extensions_used=used,
            hard_deadline=180.0,
        )
        self.assertEqual(deadline, 150.0)
        self.assertEqual(used, 2)
        deadline, used = _extend_processing_grace(
            now=deadline,
            grace_until=deadline,
            processing_visible=True,
            extensions_used=used,
            hard_deadline=180.0,
        )
        self.assertEqual(deadline, 180.0)
        self.assertEqual(used, 3)
        self.assertEqual(
            _extend_processing_grace(
                now=deadline,
                grace_until=deadline,
                processing_visible=True,
                extensions_used=used,
                hard_deadline=180.0,
            ),
            (deadline, used),
        )

    def test_submission_deadline_is_immutable_and_protocol_clamped(self):
        self.assertEqual(SAML_UI_MAX_SUBMIT_WAIT_SECONDS, 180.0)
        self.assertEqual(
            _submission_hard_deadline(100.0, 400.0),
            280.0,
        )
        self.assertEqual(
            _submission_hard_deadline(100.0, 200.0),
            200.0,
        )


class MicrosoftCredentialLookupTrackerTests(unittest.TestCase):
    @staticmethod
    def _request(path="/common/GetCredentialType"):
        return SimpleNamespace(
            url=f"https://login.microsoftonline.com{path}",
            method="POST",
            resource_type="xhr",
            is_navigation_request=lambda: False,
        )

    def test_tracks_concrete_requests_until_the_matching_request_finishes(self):
        tracker = _MicrosoftCredentialLookupTracker()
        first = self._request()
        second = self._request()

        self.assertTrue(tracker.started(first, now=10.0))
        self.assertTrue(tracker.started(second, now=11.0))
        self.assertEqual(tracker.pending_count, 2)
        self.assertEqual(tracker.generation, 2)
        self.assertFalse(tracker.finished(self._request(), now=12.0))
        self.assertEqual(tracker.pending_count, 2)
        self.assertTrue(tracker.finished(first, now=12.0))
        self.assertEqual(tracker.pending_count, 1)

    def test_playwright_wrappers_for_same_request_share_tracking_identity(self):
        tracker = _MicrosoftCredentialLookupTracker()
        implementation = object()
        started = self._request()
        finished = self._request()
        started._impl_obj = implementation
        finished._impl_obj = implementation
        tracker.started(started, now=10.0)
        self.assertTrue(tracker.finished(finished, now=11.0))
        self.assertEqual(tracker.pending_count, 0)

    def test_unrelated_requests_do_not_enter_lookup_wait(self):
        tracker = _MicrosoftCredentialLookupTracker()
        self.assertFalse(
            tracker.started(
                SimpleNamespace(url="https://example.com/GetCredentialType"),
                now=0.0,
            )
        )
        self.assertEqual(tracker.pending_count, 0)

    def test_lookup_transport_classifier_is_exact_and_fail_closed(self):
        valid = self._request()
        self.assertTrue(
            _MicrosoftCredentialLookupTracker._is_lookup_request(valid)
        )
        invalid = (
            SimpleNamespace(
                **(vars(valid) | {"url": valid.url.replace("https:", "http:")})
            ),
            SimpleNamespace(
                **(vars(valid) | {"url": valid.url.replace(".com", ".com:8443")})
            ),
            SimpleNamespace(**(vars(valid) | {"method": "GET"})),
            SimpleNamespace(**(vars(valid) | {"resource_type": "document"})),
            SimpleNamespace(
                **(
                    vars(valid)
                    | {"is_navigation_request": lambda: True}
                )
            ),
            SimpleNamespace(
                **(
                    vars(valid)
                    | {
                        "url": (
                            "https://login.microsoftonline.com/common/"
                            "nested/GetCredentialType"
                        )
                    }
                )
            ),
            SimpleNamespace(
                **(
                    vars(valid)
                    | {
                        "url": (
                            "https://user@login.microsoftonline.com/common/"
                            "GetCredentialType"
                        )
                    }
                )
            ),
        )
        for request in invalid:
            with self.subTest(url=request.url):
                self.assertFalse(
                    _MicrosoftCredentialLookupTracker._is_lookup_request(
                        request
                    )
                )

    def test_live_lookup_without_spinner_extends_in_steps_to_hard_cap(self):
        tracker = _MicrosoftCredentialLookupTracker()
        tracker.started(self._request(), now=100.0)
        for elapsed in (
            MICROSOFT_CREDENTIAL_LOOKUP_TIMEOUT_SECONDS,
            MICROSOFT_CREDENTIAL_LOOKUP_TIMEOUT_SECONDS + 5.0,
            MICROSOFT_CREDENTIAL_LOOKUP_TIMEOUT_SECONDS + 10.0,
        ):
            waiting, expired = tracker.wait_state(
                100.0 + elapsed,
                usable_ui_visible=False,
                processing_visible=False,
            )
            self.assertTrue(waiting)
            self.assertFalse(expired)
        waiting, expired = tracker.wait_state(
            100.0 + MICROSOFT_CREDENTIAL_LOOKUP_MAX_SECONDS,
            usable_ui_visible=False,
            processing_visible=False,
        )
        self.assertFalse(waiting)
        self.assertTrue(expired)

    def test_visible_processing_extends_lookup_but_never_past_hard_cap(self):
        tracker = _MicrosoftCredentialLookupTracker()
        tracker.started(self._request(), now=100.0)

        waiting, expired = tracker.wait_state(
            100.0 + MICROSOFT_CREDENTIAL_LOOKUP_TIMEOUT_SECONDS - 1.0,
            usable_ui_visible=False,
            processing_visible=True,
        )
        self.assertTrue(waiting)
        self.assertFalse(expired)
        waiting, expired = tracker.wait_state(
            100.0 + MICROSOFT_CREDENTIAL_LOOKUP_MAX_SECONDS,
            usable_ui_visible=False,
            processing_visible=True,
        )
        self.assertFalse(waiting)
        self.assertTrue(expired)

    def test_usable_dom_state_overrides_and_clears_stale_network_latch(self):
        tracker = _MicrosoftCredentialLookupTracker()
        tracker.started(self._request(), now=100.0)
        waiting, expired = tracker.wait_state(
            101.0,
            usable_ui_visible=True,
            processing_visible=False,
        )
        self.assertFalse(waiting)
        self.assertFalse(expired)
        self.assertEqual(tracker.pending_count, 0)

    def test_expiration_survives_an_overlapping_settle_wait(self):
        tracker = _MicrosoftCredentialLookupTracker(
            timeout_seconds=1.0,
            max_seconds=1.0,
            settle_seconds=2.0,
        )
        expired_request = self._request()
        completed_request = self._request()
        tracker.started(expired_request, now=10.0)
        tracker.started(completed_request, now=10.0)
        tracker.finished(completed_request, now=10.5)
        waiting, expired = tracker.wait_state(
            11.0,
            usable_ui_visible=False,
            processing_visible=False,
        )
        self.assertTrue(waiting)
        self.assertTrue(expired)
        waiting, expired = tracker.wait_state(
            12.5,
            usable_ui_visible=False,
            processing_visible=False,
        )
        self.assertFalse(waiting)
        self.assertTrue(expired)

    def test_navigation_reset_clears_pending_without_rewinding_generation(self):
        tracker = _MicrosoftCredentialLookupTracker()
        tracker.started(self._request(), now=100.0)
        tracker.reset()
        self.assertEqual(tracker.pending_count, 0)
        self.assertEqual(tracker.generation, 1)


class CombinedActionPatternTests(unittest.TestCase):
    def test_combined_action_pattern_preserves_individual_pattern_semantics(self):
        labels = (
            "Next",
            "Use a verification code",
            "Prüfcode aus meiner mobilen App verwenden",
        )
        combined = _combined_action_pattern(labels)
        individual = _action_patterns(labels)
        candidates = (
            "Next",
            "  next  ",
            "Next step",
            "Use a verification code",
            "Use a verification code instead",
            "Prüfcode aus meiner mobilen App verwenden",
            "Jetzt Prüfcode aus meiner mobilen App verwenden",
            "Approve a request",
            "",
        )

        for candidate in candidates:
            with self.subTest(candidate=candidate):
                self.assertEqual(
                    bool(combined.search(candidate)),
                    any(pattern.search(candidate) for pattern in individual),
                )

    def test_combined_action_pattern_with_no_labels_never_matches(self):
        self.assertIsNone(_combined_action_pattern(()).search("Next"))


class MicrosoftAuthUiTests(unittest.TestCase):
    class Frame:
        def __init__(self, url, payload=None, error=None):
            self.url = url
            self.payload = payload
            self.error = error
            self.evaluate_calls = []

        def evaluate(self, script, argument):
            self.evaluate_calls.append((script, argument))
            if self.error is not None:
                raise self.error
            return self.payload

    @staticmethod
    def _payload(*, control_id="i0118"):
        return {
            "renderedText": (
                "Geben Sie die angezeigte Zahl ein\n65\n"
                "Angemeldet bleiben"
            ),
            "controls": [
                {
                    "tag": "input",
                    "id": control_id,
                    "name": "passwd",
                    "type": "password",
                    "role": "",
                    "autocomplete": "current-password",
                    "disabled": False,
                    "hasValue": True,
                    "ariaLabel": "Password",
                    "label": "never-retain-this-secret",
                    "value": "never-retain-this-secret",
                },
            ],
            "probes": {
                "[data-value='PhoneAppOTP']": [
                    {
                        "text": "Use a verification code",
                        "tagName": "div",
                        "role": "button",
                        "inputType": "",
                        "disabled": False,
                        "hasHref": False,
                        "hasClickHandler": True,
                        "hasDataValue": True,
                        "tabIndex": 0,
                        "pointerCursor": True,
                    },
                ],
                "#idRichContext_DisplaySign": [
                    {
                        "text": "65",
                        "tagName": "div",
                        "role": "",
                        "inputType": "",
                        "disabled": False,
                        "hasHref": False,
                        "hasClickHandler": False,
                        "hasDataValue": False,
                        "tabIndex": -1,
                        "pointerCursor": False,
                    },
                ],
                "[role='progressbar']": [
                    {
                        "text": "",
                        "tagName": "div",
                        "role": "progressbar",
                        "inputType": "",
                        "disabled": False,
                        "hasHref": False,
                        "hasClickHandler": False,
                        "hasDataValue": False,
                        "tabIndex": -1,
                        "pointerCursor": False,
                    },
                ],
            },
        }

    def test_one_capture_per_frame_is_reused_by_all_read_helpers(self):
        first = self.Frame("https://login.example/", self._payload())
        second = self.Frame(
            "https://idp.example/",
            {"renderedText": "Use your passkey", "controls": [], "probes": {}},
        )
        page = SimpleNamespace(frames=[first, second], url=first.url)

        snapshot = _capture_rendered_auth_ui(page)

        self.assertTrue(snapshot.complete)
        self.assertEqual(len(first.evaluate_calls), 1)
        self.assertEqual(len(second.evaluate_calls), 1)
        self.assertTrue(_snapshot_has_text(snapshot, ["angezeigte Zahl"]))
        self.assertTrue(_snapshot_has_text(snapshot, ["use   your passkey"]))
        self.assertTrue(_snapshot_selector_actionable(
            snapshot,
            ["[data-value='PhoneAppOTP']"],
        ))
        self.assertTrue(_snapshot_selector_visible(
            snapshot,
            MICROSOFT_AUTH_UI_PROCESSING_SELECTORS,
        ))
        self.assertEqual(
            _snapshot_probe_texts(snapshot, ["#idRichContext_DisplaySign"]),
            ("65",),
        )
        self.assertEqual(len(first.evaluate_calls), 1)
        self.assertEqual(len(second.evaluate_calls), 1)

    def test_snapshot_never_retains_text_entry_values(self):
        frame = self.Frame("https://login.example/", self._payload())
        snapshot = _capture_rendered_auth_ui(
            SimpleNamespace(frames=[frame], url=frame.url)
        )

        serialized = json.dumps(snapshot.frames)
        self.assertNotIn("never-retain-this-secret", serialized)
        control = snapshot.frames[0]["controls"][0]
        self.assertEqual(control["label"], "Password")
        self.assertTrue(control["hasValue"])

    def test_failed_frame_is_marked_for_legacy_fallback(self):
        failed = self.Frame(
            "https://broken.example/",
            error=RuntimeError("execution context unavailable"),
        )
        healthy = self.Frame("https://login.example/", self._payload())

        snapshot = _capture_rendered_auth_ui(
            SimpleNamespace(frames=[failed, healthy], url=healthy.url)
        )

        self.assertFalse(snapshot.complete)
        self.assertEqual(snapshot.failed_frames, (failed,))
        self.assertEqual(len(failed.evaluate_calls), 1)
        self.assertEqual(len(healthy.evaluate_calls), 1)
        self.assertTrue(_snapshot_has_text(snapshot, ["Angemeldet bleiben"]))

    def test_fingerprint_changes_with_safe_control_metadata(self):
        first = self.Frame("https://login.example/", self._payload(control_id="i0118"))
        second = self.Frame("https://login.example/", self._payload(control_id="passwordInput"))

        first_snapshot = _capture_rendered_auth_ui(
            SimpleNamespace(frames=[first], url=first.url)
        )
        second_snapshot = _capture_rendered_auth_ui(
            SimpleNamespace(frames=[second], url=second.url)
        )

        self.assertNotEqual(first_snapshot.fingerprint, second_snapshot.fingerprint)

    def test_fhnw_german_authenticator_fallback_is_supported(self):
        self.assertIn(
            "I can't use my Microsoft Authenticator app right now",
            MICROSOFT_ALTERNATE_MFA_LABELS,
        )
        self.assertIn(
            "Ich kann meine Microsoft Authenticator-App im Moment nicht verwenden",
            MICROSOFT_ALTERNATE_MFA_LABELS,
        )
        self.assertIn("Use a verification code", MICROSOFT_TOTP_METHOD_LABELS)
        self.assertIn(
            "I can't use my Microsoft Authenticator app right now",
            MICROSOFT_NUMBER_MATCH_TOTP_ALTERNATE_LABELS,
        )
        self.assertIn(
            "Use a verification code",
            MICROSOFT_EXACT_TOTP_METHOD_LABELS,
        )

    def test_microsoft_totp_method_has_stable_selector(self):
        self.assertIn("[data-value='PhoneAppOTP']", MICROSOFT_TOTP_DIRECT_SELECTORS)

    def test_current_password_and_alternate_selectors_are_supported(self):
        self.assertIn("#idA_PWD_SwitchToPassword", MICROSOFT_PASSWORD_DIRECT_SELECTORS)
        self.assertNotIn(
            "#idA_PWD_SwitchToCredPicker",
            MICROSOFT_ALTERNATE_MFA_SELECTORS,
        )
        self.assertIn(
            "#idA_PWD_SwitchToCredPicker",
            MICROSOFT_PRIMARY_CREDENTIAL_PICKER_SELECTORS,
        )
        self.assertIn("Use my password", MICROSOFT_PASSWORD_METHOD_LABELS)
        self.assertIn("Mein Kennwort verwenden", MICROSOFT_PASSWORD_METHOD_LABELS)
        self.assertIn(
            "Choose a way to sign in",
            MICROSOFT_PRIMARY_METHOD_PICKER_MARKERS,
        )

    def test_german_stay_signed_in_prompt_is_supported(self):
        self.assertIn("Angemeldet bleiben", MICROSOFT_KMSI_MARKERS)
        self.assertIn("Ja", MICROSOFT_KMSI_ACCEPT_LABELS)

    def test_gp_saml_username_and_portal_cookie_are_preserved(self):
        result = _merge_saml_artifacts(
            {"SESSID": "session"},
            {
                "saml_response": "response",
                "prelogin_cookie": "prelogin",
                "portal_userauthcookie": "portal",
                "saml_username": "returned-user",
            },
            "gp",
            gp_prelogin_cookie="fallback",
            gp_gateway_ip="192.0.2.10",
        )

        self.assertEqual(result["prelogin-cookie"], "prelogin")
        self.assertEqual(result["portal-userauthcookie"], "portal")
        self.assertEqual(result["saml-username"], "returned-user")
        self.assertEqual(result["_gateway_ip"], "192.0.2.10")

    @patch("core.auth.urllib.request.urlopen")
    def test_gp_gateway_prelogin_uses_gateway_endpoint(self, urlopen):
        response = urlopen.return_value.__enter__.return_value
        response.status = 200
        response.read.return_value = (
            b"<response><saml-request>request</saml-request>"
            b"<server-ip>192.0.2.10</server-ip></response>"
        )

        _cookie, saml_request, gateway_ip = _get_gp_prelogin(
            "vpn.example.edu",
            gp_auth_interface="gateway",
        )

        request = urlopen.call_args.args[0]
        self.assertEqual(
            request.full_url,
            "https://vpn.example.edu/ssl-vpn/prelogin.esp",
        )
        self.assertEqual(saml_request, "request")
        self.assertEqual(gateway_ip, "192.0.2.10")

    @patch("core.auth.get_gp_os_version", return_value="Detected Linux")
    @patch("core.auth.urllib.request.urlopen")
    def test_gp_auto_os_version_uses_detection(self, urlopen, detected):
        response = urlopen.return_value.__enter__.return_value
        response.status = 200
        response.read.return_value = b"<response><saml-request>request</saml-request></response>"
        _get_gp_prelogin("vpn.example.edu", gp_os_version="auto")
        self.assertIn(b"os-version=Detected+Linux", urlopen.call_args.args[0].data)
        detected.assert_called_once()

    def test_push_passkey_and_number_match_states_are_supported(self):
        self.assertIn("[data-value='PhoneAppNotification']", MICROSOFT_PUSH_DIRECT_SELECTORS)
        self.assertIn("Passkey verwenden", MICROSOFT_PASSKEY_MARKERS)
        self.assertIn(
            "Face, fingerprint, PIN or security key",
            MICROSOFT_PASSKEY_MARKERS,
        )
        self.assertIn("Geben Sie die Nummer ein", MICROSOFT_NUMBER_MATCH_MARKERS)
        self.assertIn("Geben Sie die angezeigte Zahl ein", MICROSOFT_NUMBER_MATCH_MARKERS)
        self.assertIn(
            "Approve a sign-in request",
            MICROSOFT_AUTHENTICATOR_PUSH_MARKERS,
        )
        self.assertNotIn(
            "Approve a sign-in request",
            MICROSOFT_NUMBER_MATCH_MARKERS,
        )

    def test_number_match_extraction_requires_unique_standalone_value(self):
        self.assertEqual(_standalone_two_digit_numbers("Approve\n65\nContinue"), {"65"})
        self.assertEqual(_standalone_two_digit_numbers("Code 65\n2026\n123456"), set())
        self.assertEqual(_standalone_two_digit_numbers("12\n65"), {"12", "65"})

    def test_number_match_container_requires_a_number_without_known_wording(self):
        self.assertTrue(_has_number_match_evidence(False, True, True))
        self.assertTrue(_has_number_match_evidence(True, False, False))
        self.assertFalse(_has_number_match_evidence(False, True, False))
        self.assertFalse(_has_number_match_evidence(False, False, True))

    def test_password_fallback_rejects_username_like_text_controls(self):
        self.assertFalse(_password_fallback_input_allowed("text", "username", 9))
        self.assertFalse(_password_fallback_input_allowed("email", "email", 9))
        self.assertFalse(_password_fallback_input_allowed("text", "", 3))
        self.assertTrue(_password_fallback_input_allowed("password", "", 8))
        self.assertTrue(
            _password_fallback_input_allowed("text", "current-password", 6)
        )
        self.assertFalse(_password_fallback_input_allowed("password", "", 0))

    def test_safe_lookup_can_promote_primary_password_picker(self):
        common = {
            "protocol": "anyconnect",
            "submission_kind": "password-unknown",
            "lookup_observed": True,
            "credential_tainted": False,
            "unsafe_write_observed": False,
            "primary_picker_visible": True,
            "password_method_visible": True,
        }
        self.assertTrue(_password_discovery_method_picker_ready(**common))
        for override in (
            {"protocol": "pulse"},
            {"submission_kind": "password"},
            {"lookup_observed": False},
            {"credential_tainted": True},
            {"unsafe_write_observed": True},
            {"primary_picker_visible": False},
            {"password_method_visible": False},
        ):
            with self.subTest(override=override):
                self.assertFalse(
                    _password_discovery_method_picker_ready(
                        **(common | override)
                    )
                )

    def test_auto_and_totp_switch_number_match_to_totp(self):
        self.assertTrue(_prefer_totp_for_number_match("auto", True, False))
        self.assertFalse(_prefer_totp_for_number_match("push", True, False))
        self.assertTrue(_prefer_totp_for_number_match("totp", True, False))
        self.assertFalse(_prefer_totp_for_number_match("totp", True, True))

    def test_number_notification_is_only_a_phone_fallback(self):
        self.assertFalse(_should_notify_number_match("auto", True))
        self.assertTrue(_should_notify_number_match("auto", False))
        self.assertTrue(_should_notify_number_match("push", True))
        self.assertFalse(_should_notify_number_match("totp", False))

    def test_number_match_adaptively_prefers_each_totp_path(self):
        self.assertEqual(
            _adaptive_mfa_action(True, True, True, False, False),
            "submit-totp",
        )
        self.assertEqual(
            _adaptive_mfa_action(True, False, True, True, False),
            "select-totp",
        )
        self.assertEqual(
            _adaptive_mfa_action(True, False, True, False, True),
            "wait-for-picker",
        )
        self.assertEqual(
            _adaptive_mfa_action(True, False, True, False, False),
            "open-alternate-methods",
        )
        self.assertEqual(
            _adaptive_mfa_action(False, False, True, True, False),
            "phone",
        )
        self.assertEqual(
            _adaptive_mfa_action(True, False, False, False, False),
            "none",
        )

    def test_password_bridge_can_continue_through_revealed_totp_picker(self):
        self.assertEqual(
            _password_bridge_transition_action(True, False, True),
            "select-totp",
        )
        self.assertEqual(
            _password_bridge_transition_action(True, True, True),
            "select-totp",
        )

    def test_password_bridge_keeps_password_continuation_available(self):
        self.assertEqual(
            _password_bridge_transition_action(False, True, True),
            "accept-password",
        )
        self.assertEqual(
            _password_bridge_transition_action(False, False, True),
            "wait",
        )
        self.assertEqual(
            _password_bridge_transition_action(False, False, False),
            "fail",
        )
        self.assertTrue(_password_bridge_allowed("auto"))
        self.assertFalse(_password_bridge_allowed("totp"))
        self.assertFalse(_password_bridge_allowed("push"))

    def test_post_password_passkey_stays_on_explicit_totp_route(self):
        self.assertEqual(_passkey_fallback_route(True, True), "totp")
        self.assertEqual(_passkey_fallback_route(False, True), "password")
        self.assertEqual(_passkey_fallback_route(True, False), "password")
        self.assertIn(
            "Use an app instead",
            MICROSOFT_PASSKEY_APP_FALLBACK_LABELS,
        )
        self.assertIn(
            "Eine Anforderung in meiner Microsoft Authenticator-App bestätigen",
            MICROSOFT_PUSH_METHOD_LABELS,
        )
        self.assertIn(
            "Die Anforderung wurde nicht gesendet",
            MICROSOFT_PUSH_DELIVERY_FAILURE_MARKERS,
        )

    def test_passkey_password_transition_is_bounded(self):
        self.assertEqual(
            _passkey_password_transition_action(True, True),
            "accept-password",
        )
        self.assertEqual(
            _passkey_password_transition_action(False, True),
            "wait",
        )
        self.assertEqual(
            _passkey_password_transition_action(False, False),
            "fail",
        )

    def test_mfa_transition_allows_slow_spa_rendering(self):
        self.assertGreaterEqual(MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS, 15.0)
        self.assertGreaterEqual(MICROSOFT_METHOD_PICKER_SETTLE_SECONDS, 5.0)
        self.assertEqual(MICROSOFT_PUSH_DELIVERY_MAX_RETRIES, 1)

    def test_totp_rotation_alone_never_authorizes_a_second_submission(self):
        self.assertEqual(MICROSOFT_TOTP_MAX_SUBMISSIONS, 1)
        self.assertTrue(_should_submit_totp_counter(None, 100))
        self.assertFalse(_should_submit_totp_counter(100, 100))
        self.assertTrue(_should_submit_totp_counter(100, 101))
        self.assertFalse(_should_submit_totp_for_control(True, 100, 101))

    @patch("core.auth.subprocess.run")
    def test_desktop_user_comes_from_unique_active_graphical_session(self, run):
        def fake_run(command, **_kwargs):
            if command[1] == "list-sessions":
                return SimpleNamespace(returncode=0, stdout="2 1000 alice seat0\n3 1000 alice -\n")
            if command[2] == "2":
                return SimpleNamespace(
                    returncode=0,
                    stdout=(
                        "Active=yes\nRemote=no\nType=wayland\nClass=user\n"
                        "User=1000\nName=alice\n"
                    ),
                )
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    "Active=yes\nRemote=no\nType=unspecified\nClass=manager\n"
                    "User=1000\nName=alice\n"
                ),
            )

        run.side_effect = fake_run
        self.assertEqual(_detect_desktop_user(), "alice")

    @patch("core.auth.subprocess.run")
    def test_multiple_active_desktop_users_fail_closed(self, run):
        def fake_run(command, **_kwargs):
            if command[1] == "list-sessions":
                return SimpleNamespace(returncode=0, stdout="2 1000 alice seat0\n4 1001 bob seat1\n")
            user = "alice" if command[2] == "2" else "bob"
            uid = "1000" if user == "alice" else "1001"
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    "Active=yes\nRemote=no\nType=wayland\nClass=user\n"
                    f"User={uid}\nName={user}\n"
                ),
            )

        run.side_effect = fake_run
        self.assertIsNone(_detect_desktop_user())


class TotpTests(unittest.TestCase):
    def test_rfc_6238_sha1_vector(self):
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        self.assertEqual(generate_totp(secret, digits=8, timestamp=59), "94287082")

    def test_rotation_window(self):
        self.assertEqual(seconds_until_totp_rotation(timestamp=28.5), 1.5)
        self.assertEqual(seconds_until_totp_rotation(timestamp=30), 30.0)


if __name__ == "__main__":
    unittest.main()
