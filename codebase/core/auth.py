"""SAML authentication via headless Playwright with heuristic form handling."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import ssl
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import unicodedata
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Callable, Optional

from playwright.sync_api import sync_playwright

from .platform_info import get_gp_client_os, get_gp_os_version
from .totp import generate_totp, seconds_until_totp_rotation


MICROSOFT_TOTP_DIRECT_SELECTORS = (
    "#idA_SAASTO_TOTP",
    "[data-value='PhoneAppOTP']",
    "[data-value='SoftwareOath']",
)

MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS = 25.0
# The FHNW flow replaces the number-match panel with a second method picker.
# Give that picker time to expose "Use a verification code" before considering
# a retained password control from an earlier primary sign-in screen.
MICROSOFT_METHOD_PICKER_SETTLE_SECONDS = 8.0
MICROSOFT_PASSWORD_STABILITY_SECONDS = 0.5
GP_INITIAL_MICROSOFT_PASSWORD_OBSERVATION_SECONDS = 15.0
GP_INITIAL_MICROSOFT_PASSWORD_NAVIGATION_MAX_SECONDS = 30.0
MICROSOFT_CREDENTIAL_LOOKUP_TIMEOUT_SECONDS = 15.0
MICROSOFT_CREDENTIAL_LOOKUP_MAX_SECONDS = 30.0
MICROSOFT_CREDENTIAL_LOOKUP_EXTENSION_SECONDS = 5.0
MICROSOFT_CREDENTIAL_LOOKUP_SETTLE_SECONDS = 0.5
MICROSOFT_PASSWORD_DISPATCH_CONFIRM_SECONDS = 2.0
MICROSOFT_TOTP_MAX_SUBMISSIONS = 1
MICROSOFT_PUSH_DELIVERY_MAX_RETRIES = 1
SAML_UI_STALL_WINDOW_SECONDS = 8.0
SAML_UI_POST_SUBMIT_GRACE_SECONDS = 20.0
SAML_UI_PROCESSING_EXTENSION_SECONDS = 10.0
SAML_UI_MAX_PROCESSING_EXTENSIONS = 6
SAML_UI_MAX_SUBMIT_WAIT_SECONDS = 180.0
SAML_UI_MAX_RECOVERIES = 1
SAML_PERSISTENT_PROFILE_PRE_SENSITIVE_MAX_SECONDS = 20.0

MICROSOFT_TOTP_METHOD_LABELS = (
    'Utiliser un code de vérification',
    'Entrer un code de vérification',
    'Usa un codice di verifica',
    'Utilizza un codice di verifica',
    'Usar un código de verificación',
    "Use a verification code",
    "Enter a verification code",
    "Use a code from my authenticator app",
    "Use a code from your authenticator app",
    "Use a verification code from my mobile app",
    "Code aus meiner Microsoft Authenticator-App verwenden",
    "Prüfcode aus meiner mobilen App verwenden",
    "Prüfcode verwenden",
    "Bestätigungscode verwenden",
    "Einen Prüfcode verwenden",
    "Code aus der Authenticator-App verwenden",
)

MICROSOFT_ALTERNATE_MFA_LABELS = (
    'Se connecter d’une autre manière',
    "Se connecter d'une autre manière",
    'Autres méthodes de connexion',
    'Accedi in un altro modo',
    'Altre opzioni di accesso',
    'Iniciar sesión de otra forma',
    "I can't use my Microsoft Authenticator app right now",
    "Sign in another way",
    "Other ways to sign in",
    "Sign-in options",
    "Use a different verification option",
    "Use another verification method",
    "Use a different method",
    "Ich kann meine Microsoft Authenticator-App im Moment nicht verwenden",
    "Auf andere Weise anmelden",
    "Andere Anmeldemöglichkeiten",
    "Anmeldeoptionen",
    "Andere Möglichkeit zur Anmeldung",
    "Andere Überprüfungsoption verwenden",
    "Andere Methode verwenden",
    "Weitere Anmeldemethoden",
)

MICROSOFT_NUMBER_MATCH_TOTP_ALTERNATE_LABELS = (
    'Je ne peux pas utiliser mon application Microsoft Authenticator pour le moment',
    'Non posso usare l’app Microsoft Authenticator in questo momento',
    "I can't use my Microsoft Authenticator app right now",
    "Ich kann meine Microsoft Authenticator-App im Moment nicht verwenden",
)

MICROSOFT_PASSKEY_APP_FALLBACK_LABELS = (
    'Utiliser une application à la place',
    'Usa invece un’app',
    "Use an app instead",
    "Stattdessen eine App verwenden",
)

MICROSOFT_PRIMARY_METHOD_PICKER_MARKERS = (
    'Choisissez une méthode de connexion',
    'Choisir une méthode de connexion',
    'Scegli un modo per accedere',
    'Elija una forma de iniciar sesión',
    "Choose a way to sign in",
    "Methode für die Anmeldung auswählen",
)

MICROSOFT_EXACT_TOTP_METHOD_LABELS = (
    'Utiliser un code de vérification',
    'Usa un codice di verifica',
    'Usar un código de verificación',
    "Use a verification code",
    "Prüfcode verwenden",
    "Bestätigungscode verwenden",
)

MICROSOFT_ALTERNATE_MFA_SELECTORS = (
    "#idA_SAASTO_Proofs",
    "#idA_SAOTCS_SwitchProof",
    "#idA_SAASTO_SwitchProof",
)

MICROSOFT_PRIMARY_CREDENTIAL_PICKER_SELECTORS = (
    "#idA_PWD_SwitchToCredPicker",
)

MICROSOFT_PUSH_DIRECT_SELECTORS = (
    "[data-value='PhoneAppNotification']",
    "[data-value='PhoneAppNotificationWithCode']",
)

MICROSOFT_PUSH_METHOD_LABELS = (
    "Approve a request on my Microsoft Authenticator app",
    "Send a notification to my Microsoft Authenticator app",
    "Microsoft Authenticator notification",
    "Anforderung in meiner Microsoft Authenticator-App genehmigen",
    "Benachrichtigung an meine Microsoft Authenticator-App senden",
    "Microsoft Authenticator-Benachrichtigung",
    "Eine Anforderung in meiner Microsoft Authenticator-App bestätigen",
)

MICROSOFT_PASSWORD_METHOD_LABELS = (
    'Utiliser mon mot de passe',
    'Utiliser votre mot de passe',
    'Usa la password',
    'Usa invece la password',
    'Usar mi contraseña',
    "Use my password",
    "Use your password instead",
    "Use password instead",
    "Sign in with your password",
    "Stattdessen Kennwort verwenden",
    "Mit Kennwort anmelden",
    "Mit Ihrem Kennwort anmelden",
    "Mein Kennwort verwenden",
    "Stattdessen Ihr Kennwort verwenden",
)

MICROSOFT_PASSWORD_DIRECT_SELECTORS = (
    "#idA_PWD_SwitchToPassword",
    "[data-value='Password' i]",
)

MICROSOFT_PASSKEY_MARKERS = (
    "Use your passkey",
    "Sign in with a passkey",
    "Face, fingerprint, PIN, or security key",
    "Face, fingerprint, PIN or security key",
    "Passkey verwenden",
    "Mit einem Passkey anmelden",
    "Gesichtserkennung, Fingerabdruck, PIN oder Sicherheitsschlüssel",
    "Mit Ihrem Passkey anmelden",
    "Mit einem Hauptschlüssel anmelden",
    "Anmeldung mit einem Hauptschlüssel",
    "Gesicht, Fingerabdruck, PIN oder Sicherheitsschlüssel",
)

MICROSOFT_CREDENTIAL_ERROR_MARKERS = (
    "Your account or password is incorrect",
    "Your password is incorrect",
    "The user name or password is incorrect",
    "Enter a valid password",
    "Incorrect user ID or password",
    "Ihr Konto oder Kennwort ist falsch",
    "Das Kennwort ist falsch",
    "Benutzername oder Kennwort ist falsch",
    "Geben Sie ein gültiges Kennwort ein",
)

# Language-independent Microsoft error affordances.  Container selectors must
# contain rendered text before they count as an error; aria-invalid is itself a
# concrete validation signal.
MICROSOFT_CREDENTIAL_ERROR_TEXT_SELECTORS = (
    "#passwordError",
    "#usernameError",
    "#passwordErrorText",
)

MICROSOFT_CREDENTIAL_INVALID_SELECTORS = (
    "#i0118[aria-invalid='true']",
    "#passwordInput[aria-invalid='true']",
    "input[type='password'][aria-invalid='true']",
)

MICROSOFT_NUMBER_MATCH_MARKERS = (
    "Enter the number shown to sign in",
    "Geben Sie die Nummer ein",
    "Geben Sie die angezeigte Zahl ein",
)

MICROSOFT_AUTHENTICATOR_PUSH_MARKERS = (
    "Approve sign in request",
    "Approve a sign-in request",
    "Check your Authenticator app",
    "Anmeldeanforderung bestätigen",
    "Anmeldeanforderung genehmigen",
)

MICROSOFT_PUSH_DELIVERY_FAILURE_MARKERS = (
    "The request wasn't sent",
    "The request was not sent",
    "We couldn't send a notification",
    "Die Anforderung wurde nicht gesendet",
    "Wir konnten zurzeit keine Benachrichtigung senden",
)

MICROSOFT_NUMBER_MATCH_SELECTORS = (
    "#idRichContext_DisplaySign",
    "[data-testid='displaySign']",
    "[data-test-id='displaySign']",
    ".displaySign",
)

MICROSOFT_PASSKEY_REGISTRATION_MARKERS = (
    "Set up a passkey",
    "Create a passkey",
    "Passkey einrichten",
    "Passkey erstellen",
)

MICROSOFT_SKIP_OPTIONAL_LABELS = (
    "Skip for now",
    "Not now",
    "Maybe later",
    "Vorerst überspringen",
    "Jetzt nicht",
    "Später",
)

MICROSOFT_KMSI_MARKERS = (
    "Stay signed in",
    "Angemeldet bleiben",
    "Rester connecté",
    "Rimanere connesso",
    "Mantener la sesión iniciada",
)

MICROSOFT_KMSI_ACCEPT_LABELS = (
    "Yes",
    "Ja",
    "Oui",
    "Sì",
    "Sí",
)

MICROSOFT_AUTH_UI_PROCESSING_SELECTORS = (
    "[aria-busy='true']",
    "[role='progressbar']",
    "[data-testid*='progress' i]",
    "[data-testid*='spinner' i]",
    "[class*='progress' i]",
    "[class*='spinner' i]",
    "[class*='loading' i]",
    "#idDiv_PWD_Progress",
    "#idDiv_SAOTCS_Progress",
    "#idDiv_SAOTCC_Progress",
)

MICROSOFT_AUTH_UI_SNAPSHOT_PROBE_SELECTORS = tuple(dict.fromkeys(
    MICROSOFT_TOTP_DIRECT_SELECTORS
    + MICROSOFT_PUSH_DIRECT_SELECTORS
    + MICROSOFT_PASSWORD_DIRECT_SELECTORS
    + MICROSOFT_ALTERNATE_MFA_SELECTORS
    + MICROSOFT_NUMBER_MATCH_SELECTORS
    + MICROSOFT_AUTH_UI_PROCESSING_SELECTORS
    + MICROSOFT_CREDENTIAL_ERROR_TEXT_SELECTORS
    + MICROSOFT_CREDENTIAL_INVALID_SELECTORS
    + ("#userNameInput", "#passwordInput")
))


@dataclass(frozen=True)
class _RenderedAuthUiSnapshot:
    """One immutable, privacy-safe view of the rendered authentication UI."""

    frames: tuple[dict, ...]
    failed_frames: tuple[object, ...]
    fingerprint: str

    @property
    def complete(self) -> bool:
        return not self.failed_frames


@dataclass(frozen=True)
class _PasswordControlSecurityEvidence:
    identity: Optional[str] = None
    value_known: bool = False
    value_empty: bool = False
    https_origin: Optional[str] = None
    form_identity: Optional[str] = None
    form_signature: Optional[str] = None
    form_action_origin: Optional[str] = None
    form_method: Optional[str] = None
    credential_error_visible: bool = False


@dataclass(frozen=True)
class _GpClientPasswordStageAuthorization:
    route: str
    main_navigation_generation: int
    unsafe_write_generation: int
    taint_generation: int
    document_generation: int
    federated_navigation_generation: int
    authorized_origin: str
    control_identity: str
    control_origin: str
    top_origin: str
    form_identity: str
    form_signature: str
    form_action_origin: str
    form_method: str


@dataclass(frozen=True)
class _AnyConnectRetainedPasswordStageAuthorization:
    """Bind a retained password click to DOM and asynchronous evidence."""

    password_stage: _GpClientPasswordStageAuthorization
    lookup_generation: int
    lookup_pending_count: int
    safe_navigation_generation: int
    unsafe_write_generation: int


_AUTH_UI_SNAPSHOT_SCRIPT = r"""
(probeSelectors) => {
    const isVisible = (element) => {
        const rect = element.getBoundingClientRect();
        const style = window.getComputedStyle(element);
        return style.visibility !== 'hidden' &&
            style.display !== 'none' &&
            rect.width > 0 && rect.height > 0;
    };
    const traits = (element) => ({
        text: (typeof element.innerText === 'string'
            ? element.innerText : (element.textContent || '')).slice(0, 500),
        tagName: element.tagName.toLowerCase(),
        role: element.getAttribute('role') || '',
        inputType: element.getAttribute('type') || '',
        disabled: element.matches(':disabled') || !!element.disabled ||
            element.getAttribute('aria-disabled') === 'true',
        hasHref: element.tagName.toLowerCase() === 'a' &&
            !!element.getAttribute('href'),
        hasClickHandler: typeof element.onclick === 'function' ||
            element.hasAttribute('onclick'),
        hasDataValue: element.hasAttribute('data-value'),
        tabIndex: Number.isInteger(element.tabIndex) ? element.tabIndex : null,
        pointerCursor: window.getComputedStyle(element).cursor === 'pointer',
    });
    const controls = Array.from(document.querySelectorAll(
        "input, button, a[href], [role='button'], [role='link']"
    )).filter(isVisible).slice(0, 50).map((element) => {
        const tag = element.tagName.toLowerCase();
        const type = (element.getAttribute('type') || '').toLowerCase();
        const acceptsUserInput = tag === 'textarea' ||
            (tag === 'input' && !['button', 'submit', 'reset'].includes(type));
        return {
            tag,
            id: element.id || '',
            name: element.getAttribute('name') || '',
            type,
            role: element.getAttribute('role') || '',
            autocomplete: element.getAttribute('autocomplete') || '',
            disabled: element.matches(':disabled') || !!element.disabled ||
                element.getAttribute('aria-disabled') === 'true',
            hasValue: 'value' in element ? !!element.value : null,
            ariaLabel: element.getAttribute('aria-label') || '',
            label: (element.getAttribute('aria-label') ||
                (acceptsUserInput ? '' : element.getAttribute('value')) ||
                element.innerText || '').replace(/\s+/g, ' ').trim().slice(0, 120),
        };
    });
    const probes = {};
    for (const selector of probeSelectors) {
        probes[selector] = Array.from(document.querySelectorAll(selector))
            .filter(isVisible).slice(0, 20).map(traits);
    }
    return {
        renderedText: document.body && document.body.innerText
            ? document.body.innerText : '',
        controls,
        probes,
    };
}
"""


_TOP_PAGE_CREDENTIAL_ERROR_SCRIPT = r"""
credentialErrorMarkers => {
    const visible = candidate => {
        if (!candidate) return false;
        const style = getComputedStyle(candidate);
        const rect = candidate.getBoundingClientRect();
        return style.display !== 'none' && style.visibility !== 'hidden' &&
            rect.width > 0 && rect.height > 0;
    };
    const invalid = Array.from(document.querySelectorAll(
        "input[type='password'][aria-invalid='true']"
    )).some(visible);
    const rendered = ['#passwordError', '#usernameError', '#passwordErrorText']
        .some(selector => Array.from(document.querySelectorAll(selector)).some(
            candidate => visible(candidate) && Boolean((
                typeof candidate.innerText === 'string'
                    ? candidate.innerText : (candidate.textContent || '')
            ).trim())
        ));
    const normalizedBody = (
        document.body && document.body.innerText ? document.body.innerText : ''
    ).toLocaleLowerCase();
    const markerError = credentialErrorMarkers.some(marker =>
        normalizedBody.includes(String(marker).toLocaleLowerCase())
    );
    return invalid || rendered || markerError;
}
"""


def _probe_top_page_credential_error(page) -> Optional[bool]:
    """Return observed error state, or None when navigation prevents inspection."""
    try:
        result = page.evaluate(
            _TOP_PAGE_CREDENTIAL_ERROR_SCRIPT,
            list(MICROSOFT_CREDENTIAL_ERROR_MARKERS),
        )
        return result if isinstance(result, bool) else None
    except Exception:
        return None


def _sanitize_auth_ui_frame_payload(url: str, payload: object) -> dict:
    """Whitelist snapshot fields and never retain text-entry control values."""
    raw = payload if isinstance(payload, dict) else {}
    controls = []
    for value in raw.get("controls", ()):
        if not isinstance(value, dict):
            continue
        tag = str(value.get("tag") or "").lower()
        input_type = str(value.get("type") or "").lower()
        accepts_user_input = tag == "textarea" or (
            tag == "input"
            and input_type not in {"button", "submit", "reset"}
        )
        aria_label = str(value.get("ariaLabel") or "")
        controls.append({
            "tag": tag,
            "id": str(value.get("id") or ""),
            "name": str(value.get("name") or ""),
            "type": input_type,
            "role": str(value.get("role") or ""),
            "autocomplete": str(value.get("autocomplete") or ""),
            "disabled": bool(value.get("disabled")),
            "hasValue": bool(value.get("hasValue"))
            if value.get("hasValue") is not None else None,
            "label": aria_label if accepts_user_input else str(
                value.get("label") or aria_label
            ),
        })

    probes = {}
    raw_probes = raw.get("probes", {})
    if isinstance(raw_probes, dict):
        for selector, matches in raw_probes.items():
            sanitized_matches = []
            if isinstance(matches, (list, tuple)):
                for match in matches:
                    if not isinstance(match, dict):
                        continue
                    sanitized_matches.append({
                        "text": str(match.get("text") or ""),
                        "tagName": str(match.get("tagName") or ""),
                        "role": str(match.get("role") or ""),
                        "inputType": str(match.get("inputType") or ""),
                        "disabled": bool(match.get("disabled")),
                        "hasHref": bool(match.get("hasHref")),
                        "hasClickHandler": bool(match.get("hasClickHandler")),
                        "hasDataValue": bool(match.get("hasDataValue")),
                        "tabIndex": match.get("tabIndex"),
                        "pointerCursor": bool(match.get("pointerCursor")),
                    })
            probes[str(selector)] = tuple(sanitized_matches)

    return {
        "url": str(url or ""),
        "renderedText": str(raw.get("renderedText") or ""),
        "controls": tuple(controls),
        "probes": probes,
    }


def _capture_rendered_auth_ui(
    page,
    probe_selectors=MICROSOFT_AUTH_UI_SNAPSHOT_PROBE_SELECTORS,
) -> _RenderedAuthUiSnapshot:
    """Capture each frame in one browser round trip and hash safe UI metadata."""
    snapshots = []
    failed_frames = []
    for frame in tuple(page.frames):
        try:
            payload = frame.evaluate(
                _AUTH_UI_SNAPSHOT_SCRIPT,
                list(probe_selectors),
            )
            snapshots.append(
                _sanitize_auth_ui_frame_payload(frame.url, payload)
            )
        except Exception:
            failed_frames.append(frame)

    fingerprint_source = [
        [snapshot["url"], snapshot["controls"]]
        for snapshot in snapshots
    ]
    if not fingerprint_source:
        fingerprint_source.append([str(getattr(page, "url", "") or ""), []])
    fingerprint = hashlib.sha256(json.dumps(
        fingerprint_source,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    return _RenderedAuthUiSnapshot(
        frames=tuple(snapshots),
        failed_frames=tuple(failed_frames),
        fingerprint=fingerprint,
    )


def _normalize_rendered_ui_text(value: object) -> str:
    return " ".join(
        unicodedata.normalize("NFKC", str(value or "")).casefold().split()
    )


def _snapshot_has_text(
    snapshot: _RenderedAuthUiSnapshot,
    texts,
) -> bool:
    needles = tuple(
        normalized
        for normalized in (
            _normalize_rendered_ui_text(text) for text in texts
        )
        if normalized
    )
    return any(
        needle in _normalize_rendered_ui_text(frame.get("renderedText"))
        for frame in snapshot.frames
        for needle in needles
    )


def _snapshot_selector_visible(
    snapshot: _RenderedAuthUiSnapshot,
    selectors,
) -> bool:
    return any(
        frame.get("probes", {}).get(selector)
        for frame in snapshot.frames
        for selector in selectors
    )


def _snapshot_selector_actionable(
    snapshot: _RenderedAuthUiSnapshot,
    selectors,
) -> bool:
    for frame in snapshot.frames:
        probes = frame.get("probes", {})
        for selector in selectors:
            for match in probes.get(selector, ()):
                if _is_actionable_control(
                    match.get("tagName"),
                    role=match.get("role"),
                    input_type=match.get("inputType"),
                    disabled=bool(match.get("disabled")),
                    has_href=bool(match.get("hasHref")),
                    has_click_handler=bool(match.get("hasClickHandler")),
                    has_data_value=bool(match.get("hasDataValue")),
                    tab_index=match.get("tabIndex"),
                    pointer_cursor=bool(match.get("pointerCursor")),
                ):
                    return True
    return False


def _snapshot_probe_texts(
    snapshot: _RenderedAuthUiSnapshot,
    selectors,
) -> tuple[str, ...]:
    return tuple(
        str(match.get("text") or "")
        for frame in snapshot.frames
        for selector in selectors
        for match in frame.get("probes", {}).get(selector, ())
    )


def _snapshot_selector_has_nonempty_text(
    snapshot: _RenderedAuthUiSnapshot,
    selectors,
) -> bool:
    """Recognize a visible structural status/error in any language."""
    return any(
        bool(_normalize_rendered_ui_text(text))
        for text in _snapshot_probe_texts(snapshot, selectors)
    )


class SamlUiStalledError(RuntimeError):
    """Raised when the browser login UI remains unchanged after recovery."""


class SamlSensitiveActionError(RuntimeError):
    """Authentication failed after a sensitive action; require user intervention."""


class _SensitiveActionUncertainError(SamlSensitiveActionError):
    """Raised when an effectful browser action may already have been dispatched."""


class _SensitiveActionLedger:
    """Remember effectful actions for the lifetime of one browser auth flow.

    DOM nodes and page fingerprints are transition evidence only.  They must
    never authorize replaying credentials or another effectful MFA action.
    """

    _ALIASES = {
        "password-unknown": "password",
        "credential-lookup": "password",
    }

    def __init__(self) -> None:
        self._dispatched: set[str] = set()

    @classmethod
    def _canonical_action(cls, action: str) -> str:
        return cls._ALIASES.get(action, action)

    def record(self, action: str) -> None:
        self._dispatched.add(self._canonical_action(action))

    def dispatched(self, action: str) -> bool:
        return self._canonical_action(action) in self._dispatched


def _is_known_microsoft_telemetry_host(hostname: Optional[str]) -> bool:
    """Identify Microsoft telemetry origins that cannot authenticate a user."""
    host = str(hostname or "").strip(".").casefold()
    return bool(
        host == "events.data.microsoft.com"
        or host.endswith(".events.data.microsoft.com")
        or host == "dc.services.visualstudio.com"
        or host == "aria.microsoft.com"
        or host.endswith(".aria.microsoft.com")
    )


_GP_FEDERATED_IDP_DOMAINS = frozenset({"unibas.ch"})


def _canonical_https_origin(value: Optional[str]) -> Optional[str]:
    """Return one credential-free HTTPS origin, never a URL path or query."""
    try:
        parsed = urllib.parse.urlsplit(str(value or ""))
        if (
            parsed.scheme.casefold() != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            return None
        port = parsed.port
        host = parsed.hostname.encode("idna").decode("ascii").casefold()
    except Exception:
        return None
    if not host:
        return None
    serialized_host = f"[{host}]" if ":" in host else host
    return f"https://{serialized_host}" + (
        f":{port}" if port not in {None, 443} else ""
    )


def _institution_domain(hostname: Optional[str]) -> Optional[str]:
    """Match a label-bound, explicitly approved GP institution domain."""
    try:
        normalized = (
            str(hostname or "")
            .strip(".")
            .encode("idna")
            .decode("ascii")
            .casefold()
        )
    except Exception:
        return None
    for domain in _GP_FEDERATED_IDP_DOMAINS:
        if normalized == domain or normalized.endswith(f".{domain}"):
            return domain
    return None


def _https_origin_matches_vpn_institution(
    origin: Optional[str],
    vpn_hostname: Optional[str],
) -> bool:
    canonical_origin = _canonical_https_origin(origin)
    if canonical_origin is None:
        return False
    try:
        parsed = urllib.parse.urlsplit(canonical_origin)
        if parsed.port not in {None, 443}:
            return False
    except Exception:
        return False
    vpn_domain = _institution_domain(vpn_hostname)
    origin_domain = _institution_domain(parsed.hostname)
    return bool(vpn_domain and origin_domain == vpn_domain)


class _SensitiveDispatchEvidenceTracker:
    """Track privacy-safe evidence around a possible password dispatch.

    Generations are monotonic and retain no request objects, URLs, bodies,
    field names, secrets, or hashes.  Request payloads are inspected only
    transiently so a credential-bearing POST can never be reinterpreted as a
    harmless GET redirect followed by a fresh password form.
    """

    _PASSWORD_FIELD_NAMES = frozenset({
        "passwd",
        "password",
        "passwordinput",
        "pwd",
    })
    _AUTH_PATH_MARKERS = (
        "/login",
        "/kmsi",
        "/oauth2/",
        "/authorize",
        "/processauth",
        "/sas/",
    )
    _MAX_TRACKED_NAVIGATIONS = 64

    def __init__(self) -> None:
        self.generation = 0
        self.safe_navigation_request_generation = 0
        self.safe_navigation_generation = 0
        self.credential_taint_generation = 0
        self.main_document_generation = 0
        self.main_frame_navigation_request_generation = 0
        self.write_request_generation = 0
        self.unsafe_write_request_generation = 0
        self.outbound_request_generation = 0
        self.federated_safe_navigation_request_generation = 0
        self.federated_safe_navigation_generation = 0
        self.federated_safe_navigation_origin: Optional[str] = None
        self._pending_safe_navigation_requests: dict[int, int] = {}
        self._pending_federated_safe_navigation_requests: dict[
            int,
            tuple[int, str],
        ] = {}
        self._successful_federated_safe_navigation_responses: dict[
            int,
            tuple[int, str],
        ] = {}
        self._pending_main_frame_navigation_requests: set[int] = set()

    @staticmethod
    def _request_key(request) -> int:
        return id(getattr(request, "_impl_obj", None) or request)

    @classmethod
    def _serialized_value_carries_password(
        cls,
        value: object,
        expected_secret: Optional[str],
    ) -> bool:
        """Inspect one serialized value without retaining or exposing it."""
        serialized = str(value or "")
        if not serialized:
            return False
        try:
            decoded = urllib.parse.unquote_plus(serialized)
        except Exception:
            decoded = serialized
        secret = str(expected_secret or "")
        if secret and (secret in serialized or secret in decoded):
            return True
        for candidate in (serialized, decoded):
            try:
                fields = urllib.parse.parse_qsl(
                    candidate,
                    keep_blank_values=True,
                    strict_parsing=False,
                )
            except Exception:
                fields = ()
            if any(
                str(name or "").strip().casefold()
                in cls._PASSWORD_FIELD_NAMES
                and bool(str(field_value or ""))
                for name, field_value in fields
            ):
                return True
        return False

    @classmethod
    def _inspect_request_password(
        cls,
        request,
        expected_secret: Optional[str],
    ) -> tuple[bool, bool]:
        """Return (carries_password, fully_inspected)."""
        try:
            parsed = urllib.parse.urlsplit(request.url)
        except Exception:
            return False, False
        if cls._serialized_value_carries_password(
            parsed.query,
            expected_secret,
        ):
            return True, True
        try:
            post_data = request.post_data
        except Exception:
            return False, False
        return (
            bool(
                post_data is not None
                and cls._serialized_value_carries_password(
                post_data,
                expected_secret,
                )
            ),
            True,
        )

    @classmethod
    def _structured_payload_is_credential_free(
        cls,
        serialized: object,
        expected_secret: Optional[str],
        *,
        required_string_field: Optional[str] = None,
    ) -> bool:
        """Positively classify a bounded JSON or form payload as secret-free."""
        if not isinstance(serialized, str) or not serialized or len(serialized) > 262144:
            return False

        secret = str(expected_secret or "")
        sensitive_field_markers = frozenset({
            "password",
            "passwd",
            "passwordinput",
            "pwd",
            "passphrase",
            "secret",
            "clientsecret",
            "otp",
            "totp",
            "passcode",
        })
        nodes_seen = 0

        def _field_is_sensitive(value: object) -> bool:
            normalized = re.sub(
                r"[^a-z0-9]",
                "",
                str(value or "").casefold(),
            )
            return bool(
                normalized in sensitive_field_markers
                or "password" in normalized
                or "passwd" in normalized
            )

        def _value_is_safe(value: object, depth: int = 0) -> bool:
            nonlocal nodes_seen
            nodes_seen += 1
            if depth > 8 or nodes_seen > 1024:
                return False
            if value is None or isinstance(value, (bool, int, float)):
                return True
            if isinstance(value, str):
                return len(value) <= 131072 and not (
                    secret and secret in value
                )
            if isinstance(value, list):
                return len(value) <= 256 and all(
                    _value_is_safe(item, depth + 1) for item in value
                )
            if isinstance(value, dict):
                if len(value) > 256:
                    return False
                for key, item in value.items():
                    if not isinstance(key, str) or len(key) > 128:
                        return False
                    if _field_is_sensitive(key) and item not in (
                        None,
                        False,
                        0,
                        "",
                    ):
                        return False
                    if not _value_is_safe(item, depth + 1):
                        return False
                return True
            return False

        try:
            payload = json.loads(serialized)
        except (TypeError, ValueError):
            lines = tuple(
                line for line in serialized.splitlines() if line.strip()
            )
            if 1 < len(lines) <= 256:
                try:
                    payload = [json.loads(line) for line in lines]
                except (TypeError, ValueError):
                    return False
            else:
                try:
                    fields = urllib.parse.parse_qsl(
                        serialized,
                        keep_blank_values=True,
                        strict_parsing=True,
                    )
                except (TypeError, ValueError):
                    return False
                if not fields:
                    return False
                payload = dict(fields)

        if not isinstance(payload, (dict, list)) or not _value_is_safe(payload):
            return False
        if required_string_field is None:
            return True
        if not isinstance(payload, dict):
            return False
        required_value = payload.get(required_string_field)
        return bool(
            isinstance(required_value, str)
            and required_value.strip()
            and len(required_value) <= 512
        )

    @classmethod
    def _credential_free_lookup_write(
        cls,
        request,
        expected_secret: Optional[str],
    ) -> bool:
        if not _MicrosoftCredentialLookupTracker._is_lookup_request(request):
            return False
        try:
            serialized = request.post_data
        except Exception:
            return False
        try:
            payload = json.loads(serialized)
        except (TypeError, ValueError):
            return False
        if not isinstance(payload, dict):
            return False
        return cls._structured_payload_is_credential_free(
            serialized,
            expected_secret,
            required_string_field="username",
        )

    @classmethod
    def _credential_free_telemetry_write(
        cls,
        request,
        parsed: urllib.parse.SplitResult,
        expected_secret: Optional[str],
    ) -> bool:
        try:
            method = str(request.method or "").upper()
            resource_type = str(request.resource_type or "").casefold()
            is_navigation_request = request.is_navigation_request()
            serialized = request.post_data
            port = parsed.port
        except Exception:
            return False
        return bool(
            parsed.scheme.casefold() == "https"
            and port in {None, 443}
            and _is_known_microsoft_telemetry_host(parsed.hostname)
            and method == "POST"
            and resource_type in {"fetch", "xhr", "ping"}
            and not is_navigation_request
            and cls._structured_payload_is_credential_free(
                serialized,
                expected_secret,
            )
            and (
                resource_type != "ping"
                or cls._request_payload_shape(request)
                in {"json-object", "json-list", "json-stream"}
            )
        )

    @staticmethod
    def _request_payload_shape(request) -> str:
        """Return a fixed, privacy-safe payload format label for diagnostics."""
        try:
            serialized = request.post_data
        except Exception:
            return "opaque"
        if serialized is None:
            return "none"
        if not isinstance(serialized, str):
            return "nontext"
        if not serialized:
            return "empty"
        try:
            payload = json.loads(serialized)
        except (TypeError, ValueError):
            lines = tuple(
                line for line in serialized.splitlines() if line.strip()
            )
            if 1 < len(lines) <= 256:
                try:
                    for line in lines:
                        json.loads(line)
                    return "json-stream"
                except (TypeError, ValueError):
                    pass
            try:
                fields = urllib.parse.parse_qsl(
                    serialized,
                    keep_blank_values=True,
                    strict_parsing=True,
                )
            except (TypeError, ValueError):
                fields = ()
            return "form" if fields else "other"
        if isinstance(payload, dict):
            return "json-object"
        if isinstance(payload, list):
            return "json-list"
        return "json-scalar"

    def _taint(self) -> None:
        self.credential_taint_generation += 1

    def snapshot(self) -> tuple[int, int, int, int]:
        """Return an integer-only evidence baseline before password entry."""
        return (
            self.generation,
            self.safe_navigation_request_generation,
            self.credential_taint_generation,
            self.main_document_generation,
        )

    def transition_snapshot(
        self,
    ) -> tuple[int, int, int, int, int, int, int, int, int, int]:
        """Return the password-transition baseline, including transport classes."""
        return (
            *self.snapshot(),
            self.main_frame_navigation_request_generation,
            self.write_request_generation,
            self.outbound_request_generation,
            len(self._pending_main_frame_navigation_requests),
            self.federated_safe_navigation_request_generation,
            self.unsafe_write_request_generation,
        )

    @property
    def pending_main_frame_navigation_count(self) -> int:
        return len(self._pending_main_frame_navigation_requests)

    def request_started(
        self,
        request,
        *,
        main_frame,
        expected_secret: Optional[str] = None,
    ) -> bool:
        try:
            parsed = urllib.parse.urlsplit(request.url)
            _request_port = parsed.port
            method = str(request.method or "").upper()
            is_navigation_request = request.is_navigation_request()
            request_frame = request.frame
        except Exception:
            # An opaque request during a password epoch is never positive
            # discovery evidence.  Earlier events are absorbed by the epoch's
            # integer baseline, so monotonic taint is safe here.
            self._taint()
            return False

        self.outbound_request_generation += 1
        carries_password, password_inspection_complete = (
            self._inspect_request_password(
                request,
                expected_secret,
            )
        )
        telemetry_write = bool(
            method not in {"GET", "HEAD"}
            and _is_known_microsoft_telemetry_host(parsed.hostname)
        )
        is_write = method not in {"GET", "HEAD"}
        lookup_endpoint = (
            _MicrosoftCredentialLookupTracker._is_lookup_endpoint(request)
        )
        safe_lookup_write = bool(
            is_write
            and password_inspection_complete
            and not carries_password
            and self._credential_free_lookup_write(
                request,
                expected_secret,
            )
        )
        safe_telemetry_write = bool(
            telemetry_write
            and password_inspection_complete
            and not carries_password
            and self._credential_free_telemetry_write(
                request,
                parsed,
                expected_secret,
            )
        )
        unsafe_write = bool(
            is_write
            and not safe_lookup_write
            and not safe_telemetry_write
        )
        if is_write:
            self.write_request_generation += 1
        if unsafe_write:
            self.unsafe_write_request_generation += 1
        if is_navigation_request and request_frame == main_frame:
            self.main_frame_navigation_request_generation += 1
            self._pending_main_frame_navigation_requests.add(
                self._request_key(request)
            )
            federated_origin = _canonical_https_origin(request.url)
            if (
                method in {"GET", "HEAD"}
                and federated_origin is not None
                and not carries_password
                and password_inspection_complete
            ):
                request_key = self._request_key(request)
                self.federated_safe_navigation_request_generation += 1
                self._pending_federated_safe_navigation_requests[
                    request_key
                ] = (
                    self.federated_safe_navigation_request_generation,
                    federated_origin,
                )
                while len(
                    self._pending_federated_safe_navigation_requests
                ) > self._MAX_TRACKED_NAVIGATIONS:
                    oldest = next(
                        iter(self._pending_federated_safe_navigation_requests)
                    )
                    self._pending_federated_safe_navigation_requests.pop(
                        oldest,
                        None,
                    )

        tainted = False
        if (
            carries_password
            or (telemetry_write and not safe_telemetry_write)
            or (lookup_endpoint and is_write and not safe_lookup_write)
        ):
            self._taint()
            tainted = True

        if parsed.hostname != "login.microsoftonline.com":
            return False

        is_lookup = _MicrosoftCredentialLookupTracker._is_lookup_request(request)
        if (
            not is_navigation_request
            or request_frame != main_frame
        ):
            auth_request = any(
                marker in parsed.path.casefold()
                for marker in self._AUTH_PATH_MARKERS
            )
            if (
                method not in {"GET", "HEAD"}
                and auth_request
                and not is_lookup
                and not tainted
            ):
                self._taint()
            return False

        self.generation += 1
        if (
            method in {"GET", "HEAD"}
            and not carries_password
        ):
            request_key = self._request_key(request)
            self.safe_navigation_request_generation += 1
            self._pending_safe_navigation_requests[request_key] = (
                self.safe_navigation_request_generation
            )
            while len(self._pending_safe_navigation_requests) > 64:
                oldest = next(iter(self._pending_safe_navigation_requests))
                self._pending_safe_navigation_requests.pop(oldest, None)
        elif not tainted:
            # A correlated non-GET or otherwise ambiguous navigation is a
            # possible credential submission even if its body is unavailable.
            self._taint()
        return True

    def response_received(self, response) -> bool:
        try:
            request = response.request
            status = int(response.status)
        except Exception:
            return False
        request_key = self._request_key(request)
        federated_request = (
            self._pending_federated_safe_navigation_requests.pop(
                request_key,
                None,
            )
        )
        if federated_request is not None and (
            200 <= status < 300 or status == 304
        ):
            self._successful_federated_safe_navigation_responses[
                request_key
            ] = federated_request
            while len(
                self._successful_federated_safe_navigation_responses
            ) > self._MAX_TRACKED_NAVIGATIONS:
                oldest = next(
                    iter(
                        self._successful_federated_safe_navigation_responses
                    )
                )
                self._successful_federated_safe_navigation_responses.pop(
                    oldest,
                    None,
                )

        safe_request_generation = self._pending_safe_navigation_requests.pop(
            request_key,
            None,
        )
        if safe_request_generation is None:
            return False
        if 200 <= status < 400:
            self.safe_navigation_generation = max(
                self.safe_navigation_generation,
                safe_request_generation,
            )
            return True
        return False

    def request_failed(self, request) -> None:
        request_key = self._request_key(request)
        self._pending_safe_navigation_requests.pop(request_key, None)
        self._pending_federated_safe_navigation_requests.pop(
            request_key,
            None,
        )
        self._successful_federated_safe_navigation_responses.pop(
            request_key,
            None,
        )
        self._pending_main_frame_navigation_requests.discard(request_key)

    def main_frame_navigated(
        self,
        committed_origin: Optional[str] = None,
    ) -> None:
        self.generation += 1
        self.main_document_generation += 1
        canonical_origin = _canonical_https_origin(committed_origin)
        matching_responses = tuple(
            evidence
            for evidence in (
                self._successful_federated_safe_navigation_responses.values()
            )
            if evidence[1] == canonical_origin
        )
        # Origin is the strongest correlation exposed by Playwright's frame
        # commit callback. Multiple successful same-origin navigations are
        # ambiguous, so fail closed instead of guessing which one committed.
        if canonical_origin is not None and len(matching_responses) == 1:
            request_generation, response_origin = matching_responses[0]
            if request_generation > self.federated_safe_navigation_generation:
                self.federated_safe_navigation_generation = request_generation
                self.federated_safe_navigation_origin = response_origin
        self._successful_federated_safe_navigation_responses.clear()
        # A main-frame request remains pending through its response so a
        # request started before a password epoch cannot commit afterward and
        # masquerade as a transport-free client-side transition. Redirect
        # chains share one final document commit, so consume the whole chain.
        self._pending_main_frame_navigation_requests.clear()


def _attempt_locator_click(
    locator,
    *,
    timeout_ms: Optional[int] = None,
    sensitive: bool = False,
    action_name: str = "authentication action",
) -> bool:
    """Click once, failing closed when a sensitive outcome is ambiguous."""
    kwargs = {}
    if timeout_ms is not None:
        kwargs["timeout"] = timeout_ms
    if sensitive:
        # The surrounding state machine observes the resulting transition.  Do
        # not let a slow navigation turn a dispatched credential/MFA click into
        # an exception that causes another selector to be tried.
        kwargs["no_wait_after"] = True
    try:
        locator.click(**kwargs)
        return True
    except Exception as exc:
        if sensitive:
            raise _SensitiveActionUncertainError(
                f"{action_name} may already have been submitted; refusing to retry"
            ) from exc
        return False


def _attempt_locator_press(
    locator,
    key: str,
    *,
    sensitive: bool = False,
    action_name: str = "authentication action",
) -> bool:
    """Press once, failing closed when it may have submitted sensitive data."""
    kwargs = {"no_wait_after": True} if sensitive else {}
    try:
        locator.press(key, **kwargs)
        return True
    except Exception as exc:
        if sensitive:
            raise _SensitiveActionUncertainError(
                f"{action_name} may already have been submitted; refusing to retry"
            ) from exc
        return False


class _MicrosoftCredentialLookupTracker:
    """Bound waits to the concrete Microsoft GetCredentialType requests seen."""

    def __init__(
        self,
        timeout_seconds: float = MICROSOFT_CREDENTIAL_LOOKUP_TIMEOUT_SECONDS,
        max_seconds: float = MICROSOFT_CREDENTIAL_LOOKUP_MAX_SECONDS,
        extension_seconds: float = MICROSOFT_CREDENTIAL_LOOKUP_EXTENSION_SECONDS,
        settle_seconds: float = MICROSOFT_CREDENTIAL_LOOKUP_SETTLE_SECONDS,
    ) -> None:
        self.timeout_seconds = max(0.0, timeout_seconds)
        self.max_seconds = max(self.timeout_seconds, max_seconds)
        self.extension_seconds = max(0.0, extension_seconds)
        self.settle_seconds = max(0.0, settle_seconds)
        self._pending: dict[int, tuple[float, float]] = {}
        self.generation = 0
        self.settle_until = 0.0
        self._expiration_pending = False

    @staticmethod
    def _is_lookup_endpoint(request) -> bool:
        try:
            parsed = urllib.parse.urlsplit(request.url)
            port = parsed.port
        except Exception:
            return False
        return bool(
            parsed.scheme.casefold() == "https"
            and parsed.hostname == "login.microsoftonline.com"
            and parsed.username is None
            and parsed.password is None
            and port in {None, 443}
            and re.fullmatch(
                r"/[a-z0-9.-]{1,128}/getcredentialtype/?",
                parsed.path.casefold(),
            )
        )

    @classmethod
    def _is_lookup_request(cls, request) -> bool:
        if not cls._is_lookup_endpoint(request):
            return False
        try:
            method = str(request.method or "").upper()
            resource_type = str(request.resource_type or "").casefold()
            is_navigation_request = request.is_navigation_request()
        except Exception:
            return False
        return bool(
            method == "POST"
            and resource_type in {"fetch", "xhr"}
            and not is_navigation_request
        )

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    @staticmethod
    def _request_key(request) -> int:
        """Prefer Playwright's stable implementation object across callbacks."""
        return id(getattr(request, "_impl_obj", None) or request)

    def started(self, request, now: Optional[float] = None) -> bool:
        if not self._is_lookup_request(request):
            return False
        current_time = time.monotonic() if now is None else now
        self._pending[self._request_key(request)] = (
            current_time,
            current_time + self.timeout_seconds,
        )
        self.generation += 1
        return True

    def finished(self, request, now: Optional[float] = None) -> bool:
        if not self._is_lookup_request(request):
            return False
        if self._pending.pop(self._request_key(request), None) is None:
            return False
        current_time = time.monotonic() if now is None else now
        self.settle_until = max(
            self.settle_until,
            current_time + self.settle_seconds,
        )
        return True

    def reset(self) -> None:
        """Forget navigation-scoped requests without rewinding the generation."""
        self._pending.clear()
        self.settle_until = 0.0
        self._expiration_pending = False

    def wait_state(
        self,
        now: float,
        *,
        usable_ui_visible: bool,
        processing_visible: bool,
    ) -> tuple[bool, bool]:
        """Return (waiting, expired), letting real usable UI outrank bookkeeping.

        A concrete request that remains live earns five-second extensions up to
        the hard cap even if Microsoft's current page does not expose a spinner.
        """
        if usable_ui_visible:
            self.reset()
            return False, False

        expired = False
        for request_id, (started_at, request_deadline) in list(
            self._pending.items()
        ):
            hard_deadline = started_at + self.max_seconds
            while (
                now >= request_deadline
                and request_deadline < hard_deadline
                and self.extension_seconds > 0.0
            ):
                request_deadline = min(
                    hard_deadline,
                    request_deadline + self.extension_seconds,
                )
            self._pending[request_id] = (started_at, request_deadline)
            if now >= request_deadline:
                expired = True
                self._expiration_pending = True
                self._pending.pop(request_id, None)

        waiting = bool(self._pending or now < self.settle_until)
        if not waiting and self._expiration_pending:
            expired = True
            self._expiration_pending = False
        return waiting, expired


def _normalize_session_identity(value: Optional[str]) -> str:
    """Normalize a cache identity component without exposing it in a path."""
    return unicodedata.normalize("NFKC", str(value or "")).strip().casefold()


def _normalize_gateway_identity(gateway: Optional[str]) -> str:
    """Return a stable host/port identity for a VPN gateway."""
    text = unicodedata.normalize("NFKC", str(gateway or "")).strip()
    try:
        parsed = urllib.parse.urlsplit(text if "://" in text else f"//{text}")
        host = (parsed.hostname or text).strip().rstrip(".").casefold()
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            pass
        try:
            port = parsed.port
        except ValueError:
            port = None
        if port and port != 443:
            return f"{host}:{port}"
        return host
    except Exception:
        return text.rstrip(".").casefold()


def _browser_session_cache_key(
    protocol: Optional[str],
    gateway: Optional[str],
    username: Optional[str],
) -> str:
    """Return an opaque deterministic key for one VPN/account browser profile."""
    identity = json.dumps(
        [
            _normalize_session_identity(protocol),
            _normalize_gateway_identity(gateway),
            _normalize_session_identity(username),
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    # Bump the opaque namespace when browser-profile semantics change so an
    # upgrade cannot inherit a pre-fix Microsoft page that was mid-transition.
    return f"v2-{hashlib.sha256(identity.encode('utf-8')).hexdigest()}"


def _is_actionable_control(
    tag_name: Optional[str],
    role: Optional[str] = None,
    input_type: Optional[str] = None,
    disabled: bool = False,
    has_href: bool = False,
    has_click_handler: bool = False,
    has_data_value: bool = False,
    tab_index: Optional[int] = None,
    pointer_cursor: bool = False,
) -> bool:
    """Classify semantic and non-semantic controls that are genuinely interactive."""
    if disabled:
        return False
    tag = str(tag_name or "").strip().casefold()
    normalized_role = str(role or "").strip().casefold()
    normalized_type = str(input_type or "").strip().casefold()
    return (
        normalized_role in {"button", "link"}
        or tag == "button"
        or (tag == "a" and has_href)
        or (tag == "input" and normalized_type in {"button", "submit"})
        or has_click_handler
        or has_data_value
        or (tab_index is not None and tab_index >= 0)
        or pointer_cursor
    )


def _exact_action_pattern(label: str) -> re.Pattern:
    """Match one complete control label, ignoring case and edge whitespace."""
    return re.compile(rf"^\s*{re.escape(str(label or '').strip())}\s*$", re.IGNORECASE)


def _allows_partial_action_label(label: str) -> bool:
    """Allow partial matching only for long labels specific enough to be safe."""
    return len(str(label or "").strip()) >= 12


def _action_patterns(labels) -> list[re.Pattern]:
    """Prefer exact labels, then permit specific long-label variants."""
    patterns = [_exact_action_pattern(label) for label in labels]
    patterns.extend(
        re.compile(re.escape(str(label).strip()), re.IGNORECASE)
        for label in labels
        if _allows_partial_action_label(label)
    )
    return patterns


def _combined_action_pattern(labels) -> re.Pattern:
    """Match the same labels as ``_action_patterns`` in one browser query."""
    patterns = _action_patterns(labels)
    if not patterns:
        return re.compile(r"(?!x)x")
    return re.compile(
        "(?:" + "|".join(f"(?:{pattern.pattern})" for pattern in patterns) + ")",
        re.IGNORECASE,
    )


def _stale_ui_recovery_action(
    last_substantive_progress: float,
    now: float,
    recovery_attempts: int,
    grace_until: float = 0.0,
    stall_window: float = SAML_UI_STALL_WINDOW_SECONDS,
    max_recoveries: int = SAML_UI_MAX_RECOVERIES,
) -> str:
    """Choose a bounded recovery action based only on substantive UI progress."""
    if now < grace_until or now - last_substantive_progress < max(0.0, stall_window):
        return "wait"
    return "recover" if recovery_attempts < max(0, max_recoveries) else "fail"


def _persistent_profile_pre_sensitive_expired(
    now: float,
    hard_deadline: float,
    *,
    protocol: str = "anyconnect",
    force_ephemeral_browser_session: bool,
    sensitive_submission_started: bool,
    actionable_auth_state_visible: bool,
) -> bool:
    """Bound only an idle cached profile before credentials or MFA can run."""
    return bool(
        protocol == "anyconnect"
        and not force_ephemeral_browser_session
        and not sensitive_submission_started
        and not actionable_auth_state_visible
        and now >= hard_deadline
    )


def _discard_stale_browser_profile(
    cache_dir: str,
    session_tmp_dir: Optional[str],
) -> bool:
    """Remove one persistent profile while never touching an ephemeral session."""
    if session_tmp_dir:
        return False
    try:
        shutil.rmtree(cache_dir)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return True


def _persistent_profile_should_be_discarded_after_stall(
    protocol: str,
    force_ephemeral_browser_session: bool,
) -> bool:
    """Discard stalled AnyConnect state so the next activation starts clean."""
    return bool(
        str(protocol or "").casefold() == "anyconnect"
        and not force_ephemeral_browser_session
    )


def _extend_processing_grace(
    now: float,
    grace_until: float,
    processing_visible: bool,
    extensions_used: int,
    extension_seconds: float = SAML_UI_PROCESSING_EXTENSION_SECONDS,
    max_extensions: int = SAML_UI_MAX_PROCESSING_EXTENSIONS,
    hard_deadline: Optional[float] = None,
) -> tuple[float, int]:
    """Progressively extend an expired grace while submitted UI is unresolved."""
    if (
        not processing_visible
        or now < grace_until
        or (hard_deadline is not None and now >= hard_deadline)
        or extensions_used >= max(0, max_extensions)
    ):
        return grace_until, extensions_used
    # Back off from the fast initial check without imposing the longest wait on
    # ordinary logins: 10s, 20s, 30s, 40s, 50s, then 60s as needed.
    next_extension = max(0.0, extension_seconds) * (extensions_used + 1)
    next_deadline = now + next_extension
    if hard_deadline is not None:
        next_deadline = min(next_deadline, hard_deadline)
    return next_deadline, extensions_used + 1


def _is_usable_input_state(enabled: bool, editable: bool) -> bool:
    """Return whether an input can be safely filled in the current DOM state."""
    return bool(enabled and editable)


def _fill_totp_code_control(otp_loc, totp_code: str) -> bool:
    """Fill only a currently visible TOTP control; tolerate DOM replacement."""
    try:
        if not otp_loc.is_visible() or not _is_usable_input_state(
            otp_loc.is_enabled(),
            otp_loc.is_editable(),
        ):
            return False
        # Microsoft replaces MFA panels in place. Keep this bounded so an
        # index-based Playwright locator that was retargeted to a hidden session
        # field is rediscovered on the next auth loop instead of failing login.
        otp_loc.fill(totp_code, timeout=1000)
        return True
    except Exception:
        return False


def _username_fallback_wait_required(
    username: Optional[str],
    filled_username: bool,
    password_input_visible: bool,
) -> bool:
    """Do not click generic Next while Microsoft's username field hydrates."""
    return bool(
        username
        and not filled_username
        and not password_input_visible
    )


def _password_control_is_progress(
    current_identity: Optional[str],
    submitted_identity: Optional[str],
    password_control_submitted: bool,
) -> bool:
    """Accept only the initial password control as actionable progress.

    Microsoft frequently replaces a submitted control with a new DOM node.
    That replacement can prove a transition, but it cannot make a second
    password submission safe.
    """
    if not current_identity:
        return False
    return not password_control_submitted


def _password_alternate_dispatch_allowed(
    attempts: int,
    elapsed_seconds: float,
    *,
    outbound_dispatch_observed: bool,
    same_filled_form: bool,
    confirm_seconds: float = MICROSOFT_PASSWORD_DISPATCH_CONFIRM_SECONDS,
) -> bool:
    """Allow one alternate gesture only when the first click did nothing."""
    return bool(
        attempts == 1
        and elapsed_seconds >= max(0.0, confirm_seconds)
        and not outbound_dispatch_observed
        and same_filled_form
    )


def _password_transition_blocks_alternate_dispatch(
    dispatch_observed: bool,
    main_navigation_request_observed: bool,
    navigation_pending: bool,
) -> bool:
    """Treat an in-flight main-frame transition as a dispatched gesture."""
    return bool(
        dispatch_observed
        or main_navigation_request_observed
        or navigation_pending
    )


def _prime_gp_microsoft_federation_render(
    page,
    protocol: Optional[str],
    page_host: Optional[str],
) -> bool:
    """Force one headless compositor paint without persisting auth pixels."""
    if (
        str(protocol or "").casefold() != "gp"
        or str(page_host or "").strip(".").casefold()
        != "login.microsoftonline.com"
    ):
        return False
    try:
        page.evaluate(
            "() => document.documentElement.getBoundingClientRect().width"
        )
        # UniBas's Microsoft page can defer its credential-free federation
        # navigation until Chromium performs a compositor paint.  A 1x1
        # in-memory capture exercises that lifecycle without writing the
        # authentication page to disk.
        page.screenshot(
            type="png",
            clip={"x": 0, "y": 0, "width": 1, "height": 1},
            timeout=2000,
        )
    except Exception:
        return False
    return True


def _gp_initial_password_observation_required(
    protocol: Optional[str],
    discovery_completed: bool,
    recovery_attempts: int,
    password_action_attempts: int,
    password_dispatched: bool,
    observation_started: bool,
    password_stage_authorized: bool,
    password_control_visible: bool,
    credential_error_visible: bool,
    elapsed_seconds: float,
    navigation_pending: bool,
    observation_seconds: float = (
        GP_INITIAL_MICROSOFT_PASSWORD_OBSERVATION_SECONDS
    ),
    navigation_max_seconds: float = (
        GP_INITIAL_MICROSOFT_PASSWORD_NAVIGATION_MAX_SECONDS
    ),
) -> bool:
    """Give each fresh GP Microsoft page a bounded federation window."""
    observation_limit = max(0.0, observation_seconds)
    navigation_limit = max(observation_limit, navigation_max_seconds)
    return bool(
        str(protocol or "").casefold() == "gp"
        and not discovery_completed
        and password_action_attempts == 0
        and not password_dispatched
        and observation_started
        and (
            (
                password_stage_authorized
                and password_control_visible
                and not credential_error_visible
                and elapsed_seconds < observation_limit
            )
            or (
                navigation_pending
                and elapsed_seconds < navigation_limit
            )
        )
    )


def _gp_password_navigation_hard_cap_reached(
    protocol: Optional[str],
    discovery_completed: bool,
    password_action_attempts: int,
    password_dispatched: bool,
    navigation_pending: bool,
    elapsed_seconds: float,
    max_seconds: float = (
        GP_INITIAL_MICROSOFT_PASSWORD_NAVIGATION_MAX_SECONDS
    ),
) -> bool:
    """Bound a pre-credential GP main-frame navigation independently of UI churn."""
    return bool(
        str(protocol or "").casefold() == "gp"
        and not discovery_completed
        and password_action_attempts == 0
        and not password_dispatched
        and navigation_pending
        and elapsed_seconds >= max(0.0, max_seconds)
    )


def _anyconnect_retained_password_continuation_ready(
    protocol: Optional[str],
    submission_kind: Optional[str],
    attempts: int,
    elapsed_seconds: float,
    *,
    lookup_observed: bool,
    dispatch_observed: bool,
    safe_navigation_observed: bool,
    credential_tainted: bool,
    document_replaced: bool,
    main_navigation_request_observed: bool,
    write_request_observed: bool,
    unsafe_write_request_observed: bool,
    navigation_pending_at_baseline: bool,
    navigation_pending_now: bool,
    strong_owning_form: bool,
    strong_password_input: bool,
    current_identity: Optional[str],
    submitted_identity: Optional[str],
    value_retained: bool,
    original_control_origin: Optional[str],
    original_top_origin: Optional[str],
    original_form_action_origin: Optional[str],
    original_form_signature: Optional[str],
    original_form_method: Optional[str],
    current_control_origin: Optional[str],
    current_top_origin: Optional[str],
    current_form_action_origin: Optional[str],
    current_form_signature: Optional[str],
    current_form_method: Optional[str],
    credential_error_visible: bool,
    confirm_seconds: float = MICROSOFT_PASSWORD_DISPATCH_CONFIRM_SECONDS,
) -> bool:
    """Authorize one retained-form gesture after a credential-free DOM swap.

    FHNW's Microsoft page can commit an already-started document hydration just
    after the owning submit control is clicked.  That replaces the DOM node but
    retains its filled value without issuing a credential request.  Only this
    fully transport- and origin-bound AnyConnect state may continue once, using
    the retained value rather than entering the password again.
    """
    # Microsoft telemetry is a recognized credential-free write.  It may occur
    # while the retained form is stable, so only the separately tracked unsafe
    # write generation is a blocker.
    _ = write_request_observed
    return bool(
        str(protocol or "").casefold() == "anyconnect"
        and submission_kind == "password-unknown"
        and attempts == 1
        and elapsed_seconds >= max(0.0, confirm_seconds)
        and not lookup_observed
        and dispatch_observed
        and not safe_navigation_observed
        and not credential_tainted
        and document_replaced
        and not main_navigation_request_observed
        and not unsafe_write_request_observed
        and not navigation_pending_at_baseline
        and not navigation_pending_now
        and strong_owning_form
        and strong_password_input
        and current_identity
        and submitted_identity
        and not current_identity.startswith("fallback:")
        and not submitted_identity.startswith("fallback:")
        and current_identity != submitted_identity
        and value_retained
        and original_control_origin
        == "https://login.microsoftonline.com"
        and original_top_origin
        == "https://login.microsoftonline.com"
        and original_form_action_origin
        == "https://login.microsoftonline.com"
        and original_form_signature
        and original_form_signature == current_form_signature
        and original_form_method == "post"
        and current_control_origin
        == "https://login.microsoftonline.com"
        and current_top_origin
        == "https://login.microsoftonline.com"
        and current_form_action_origin
        == "https://login.microsoftonline.com"
        and current_form_method == "post"
        and not credential_error_visible
    )


def _anyconnect_retained_password_guard_unchanged(
    *,
    expected_lookup_generation: int,
    expected_lookup_pending_count: int,
    expected_safe_navigation_generation: int,
    expected_unsafe_write_generation: int,
    current_lookup_generation: int,
    current_lookup_pending_count: int,
    current_safe_navigation_generation: int,
    current_unsafe_write_generation: int,
) -> bool:
    """Reject a retained click when asynchronous discovery evidence changed."""
    return bool(
        expected_lookup_pending_count == 0
        and current_lookup_pending_count == 0
        and current_lookup_generation == expected_lookup_generation
        and current_safe_navigation_generation
        == expected_safe_navigation_generation
        and current_unsafe_write_generation
        == expected_unsafe_write_generation
    )


def _anyconnect_password_dispatch_is_ambiguous(
    protocol: Optional[str],
    submission_kind: Optional[str],
    *,
    dispatch_observed: bool,
    credential_tainted: bool,
    unsafe_write_request_observed: bool,
    main_navigation_request_observed: bool,
) -> bool:
    """Keep hydration-only AnyConnect evidence from proving a password POST."""
    return bool(
        str(protocol or "").casefold() == "anyconnect"
        and submission_kind == "password-unknown"
        and dispatch_observed
        and not credential_tainted
        and not unsafe_write_request_observed
        and not main_navigation_request_observed
    )


def _password_entry_uses_key_events(protocol: Optional[str]) -> bool:
    """Drive Microsoft-backed VPN password fields through reactive handlers."""
    return str(protocol or "").casefold() in {"anyconnect", "gp"}


def _password_submission_uses_strict_owning_form(
    protocol: Optional[str],
) -> bool:
    """Keep AnyConnect's narrowed submit strategy separate from GP entry."""
    return str(protocol or "").casefold() == "anyconnect"


def _password_discovery_supported(protocol: Optional[str]) -> bool:
    """Return whether the protocol can carry Microsoft's two-stage reauth UI."""
    return str(protocol or "").casefold() in {"anyconnect", "gp"}


def _password_discovery_replacement_ready(
    protocol: Optional[str],
    discovery_completed: bool,
    lookup_observed: bool,
    current_identity: Optional[str],
    submitted_identity: Optional[str],
    credential_tainted: bool = False,
) -> bool:
    """Allow one Microsoft discovery-to-password transition on a new control."""
    return bool(
        _password_discovery_supported(protocol)
        and not discovery_completed
        and lookup_observed
        and not credential_tainted
        and current_identity
        and submitted_identity
        and current_identity != submitted_identity
    )


def _password_discovery_classification_deferred(
    protocol: Optional[str],
    discovery_completed: bool,
    submission_kind: Optional[str],
    now: float,
    classify_until: float,
) -> bool:
    """Keep a first Microsoft password-page action open for one lookup window."""
    return bool(
        _password_discovery_supported(protocol)
        and not discovery_completed
        and submission_kind == "password-unknown"
        and classify_until > 0.0
        and now < classify_until
    )


def _gp_password_navigation_replacement_ready(
    protocol: Optional[str],
    discovery_completed: bool,
    dispatch_observed: bool,
    safe_navigation_observed: bool,
    credential_tainted: bool,
    document_replaced: bool,
    current_page_is_microsoft: bool,
    current_identity: Optional[str],
    submitted_identity: Optional[str],
    current_value_empty: bool,
    credential_error_visible: bool,
) -> bool:
    """Recognize Unibas's error-free navigation to a fresh password control."""
    return bool(
        str(protocol or "").casefold() == "gp"
        and not discovery_completed
        and dispatch_observed
        and safe_navigation_observed
        and not credential_tainted
        and document_replaced
        and current_page_is_microsoft
        and current_identity
        and submitted_identity
        and current_identity != submitted_identity
        and current_value_empty
        and not credential_error_visible
    )


def _gp_password_client_replacement_ready(
    protocol: Optional[str],
    discovery_completed: bool,
    dispatch_observed: bool,
    safe_navigation_observed: bool,
    credential_tainted: bool,
    document_replaced: bool,
    main_frame_navigation_request_observed: bool,
    write_request_observed: bool,
    navigation_pending_at_baseline: bool,
    trusted_origin_continuity: bool,
    strong_owning_form: bool,
    current_identity: Optional[str],
    submitted_identity: Optional[str],
    current_value_empty: bool,
    credential_error_visible: bool,
) -> bool:
    """Recognize Unibas's transport-free client-side password-stage change."""
    return bool(
        str(protocol or "").casefold() == "gp"
        and not discovery_completed
        and dispatch_observed
        and not safe_navigation_observed
        and not credential_tainted
        and document_replaced
        and not main_frame_navigation_request_observed
        and not write_request_observed
        and not navigation_pending_at_baseline
        and trusted_origin_continuity
        and strong_owning_form
        and current_identity
        and submitted_identity
        and not current_identity.startswith("fallback:")
        and not submitted_identity.startswith("fallback:")
        and current_identity != submitted_identity
        and current_value_empty
        and not credential_error_visible
    )


def _gp_password_federated_replacement_ready(
    protocol: Optional[str],
    discovery_completed: bool,
    dispatch_observed: bool,
    federated_navigation_completed: bool,
    document_replaced: bool,
    main_frame_navigation_request_observed: bool,
    credential_tainted: bool,
    unsafe_write_request_observed: bool,
    navigation_pending_at_baseline: bool,
    navigation_pending_now: bool,
    original_form_action_origin: Optional[str],
    original_top_origin: Optional[str],
    original_control_origin: Optional[str],
    committed_federated_origin: Optional[str],
    current_top_origin: Optional[str],
    current_control_origin: Optional[str],
    current_form_action_origin: Optional[str],
    current_form_method: Optional[str],
    strong_owning_form: bool,
    strong_password_input: bool,
    current_identity: Optional[str],
    submitted_identity: Optional[str],
    current_value_empty: bool,
    credential_error_visible: bool,
    vpn_hostname: Optional[str],
) -> bool:
    """Recognize a correlated Microsoft-to-institution GP password stage."""
    microsoft_origin = "https://login.microsoftonline.com"
    original_origins = tuple(
        _canonical_https_origin(origin)
        for origin in (
            original_form_action_origin,
            original_top_origin,
            original_control_origin,
        )
    )
    committed_origin = _canonical_https_origin(
        committed_federated_origin
    )
    final_origins = tuple(
        _canonical_https_origin(origin)
        for origin in (
            current_top_origin,
            current_control_origin,
            current_form_action_origin,
        )
    )
    return bool(
        str(protocol or "").casefold() == "gp"
        and not discovery_completed
        and dispatch_observed
        and federated_navigation_completed
        and document_replaced
        and main_frame_navigation_request_observed
        and not credential_tainted
        and not unsafe_write_request_observed
        and not navigation_pending_at_baseline
        and not navigation_pending_now
        and original_origins[0] in {None, microsoft_origin}
        and all(
            origin == microsoft_origin
            for origin in original_origins[1:]
        )
        and committed_origin is not None
        and all(origin == committed_origin for origin in final_origins)
        and _https_origin_matches_vpn_institution(
            committed_origin,
            vpn_hostname,
        )
        and str(current_form_method or "").casefold() == "post"
        and strong_owning_form
        and strong_password_input
        and current_identity
        and submitted_identity
        and not current_identity.startswith("fallback:")
        and not submitted_identity.startswith("fallback:")
        and current_identity != submitted_identity
        and current_value_empty
        and not credential_error_visible
    )


def _gp_password_stage_origin_policy_valid(
    route: Optional[str],
    authorized_origin: Optional[str],
    top_origin: Optional[str],
    control_origin: Optional[str],
    form_action_origin: Optional[str],
    vpn_hostname: Optional[str],
) -> bool:
    """Validate the bound origin policy for a promoted GP password stage."""
    normalized_route = str(route or "").casefold()
    canonical_authorized = _canonical_https_origin(authorized_origin)
    observed_origins = tuple(
        _canonical_https_origin(origin)
        for origin in (
            top_origin,
            control_origin,
            form_action_origin,
        )
    )
    if canonical_authorized is None or not all(
        origin == canonical_authorized for origin in observed_origins
    ):
        return False
    if normalized_route == "client":
        return canonical_authorized == "https://login.microsoftonline.com"
    if normalized_route == "federated":
        return bool(
            canonical_authorized != "https://login.microsoftonline.com"
            and _https_origin_matches_vpn_institution(
                canonical_authorized,
                vpn_hostname,
            )
        )
    return False


def _password_discovery_replacement_allowed(
    protocol: Optional[str],
    replacement_ready: bool,
    gp_microsoft_stage_authorized: bool,
) -> bool:
    """Prevent generic GP lookup evidence from bypassing route authorization."""
    if not replacement_ready:
        return False
    if str(protocol or "").casefold() == "gp":
        return bool(gp_microsoft_stage_authorized)
    return True


def _gp_password_replacement_authorization_route(
    protocol: Optional[str],
    generic_replacement: bool,
    navigation_replacement: bool,
    client_replacement: bool,
    federated_replacement: bool,
) -> Optional[str]:
    """Choose the one strict GP authorization route for a promoted control."""
    if str(protocol or "").casefold() != "gp":
        return None
    if federated_replacement:
        return "federated"
    if generic_replacement or navigation_replacement or client_replacement:
        return "client"
    return None


def _password_transition_evidence_message(
    navigation_delta: int,
    safe_navigation_delta: int,
    taint_delta: int,
    document_delta: int,
    main_navigation_request_delta: int,
    write_request_delta: int,
    outbound_request_delta: int,
    navigation_pending_at_baseline: int,
    *,
    unsafe_write_request_delta: int,
    federated_navigation_delta: int,
    federated_origin_match: bool,
    lookup_observed: bool,
    lookup_pending: bool,
    classification_deferred: bool,
    same_control: bool,
    same_ui: bool,
    value_retained: bool,
    discovery_completed: bool,
    error_visible: bool,
    current_page_is_microsoft: bool,
    origin_continuity: bool,
    strong_form: bool,
    strong_control: bool,
    control_https: bool,
    top_https: bool,
    passkey_visible: bool = False,
    primary_picker_visible: bool = False,
    method_choice_visible: bool = False,
    alternate_method_visible: bool = False,
    authenticator_visible: bool = False,
    otp_visible: bool = False,
    processing_visible: bool = False,
) -> str:
    """Format a privacy-safe, fixed-field password-transition diagnostic."""
    return (
        "password-transition-evidence "
        f"nav={max(0, int(navigation_delta))} "
        f"safe-nav={max(0, int(safe_navigation_delta))} "
        f"fed-nav={max(0, int(federated_navigation_delta))} "
        f"taint={max(0, int(taint_delta))} "
        f"document={max(0, int(document_delta))} "
        f"main-nav-request={max(0, int(main_navigation_request_delta))} "
        f"write={max(0, int(write_request_delta))} "
        f"unsafe-write={max(0, int(unsafe_write_request_delta))} "
        f"outbound={max(0, int(outbound_request_delta))} "
        f"pending-baseline={int(bool(navigation_pending_at_baseline))} "
        f"lookup={int(bool(lookup_observed))} "
        f"lookup-pending={int(bool(lookup_pending))} "
        f"deferred={int(bool(classification_deferred))} "
        f"same-control={int(bool(same_control))} "
        f"same-ui={int(bool(same_ui))} "
        f"filled={int(bool(value_retained))} "
        f"discovery={int(bool(discovery_completed))} "
        f"error={int(bool(error_visible))} "
        f"microsoft={int(bool(current_page_is_microsoft))} "
        f"origin-continuity={int(bool(origin_continuity))} "
        f"strong-form={int(bool(strong_form))} "
        f"strong-control={int(bool(strong_control))} "
        f"control-tls={int(bool(control_https))} "
        f"top-tls={int(bool(top_https))} "
        f"fed-origin={int(bool(federated_origin_match))} "
        f"passkey={int(bool(passkey_visible))} "
        f"primary-picker={int(bool(primary_picker_visible))} "
        f"method-choice={int(bool(method_choice_visible))} "
        f"alternate-method={int(bool(alternate_method_visible))} "
        f"authenticator={int(bool(authenticator_visible))} "
        f"otp={int(bool(otp_visible))} "
        f"processing={int(bool(processing_visible))}"
    )


def _password_submission_classification_delay(
    protocol: Optional[str],
    discovery_completed: bool,
) -> float:
    """Allow delayed GetCredentialType without delaying a real second stage."""
    normalized_protocol = str(protocol or "").casefold()
    if normalized_protocol == "anyconnect" and not discovery_completed:
        return MICROSOFT_CREDENTIAL_LOOKUP_MAX_SECONDS
    return 1.0


def _password_submission_classification_deadline(
    protocol: Optional[str],
    discovery_completed: bool,
    submitted_at: float,
    auth_deadline: float,
) -> float:
    """Keep GP discovery eligible dynamically until the auth deadline."""
    if (
        str(protocol or "").casefold() == "gp"
        and not discovery_completed
    ):
        return auth_deadline
    return min(
        auth_deadline,
        submitted_at
        + _password_submission_classification_delay(
            protocol,
            discovery_completed,
        ),
    )


def _password_form_hydrated(password_loc, protocol: Optional[str]) -> bool:
    """Do not type into Microsoft's visible but not yet bound password form.

    Playwright's actionability checks cannot tell whether a reactive submit
    handler exists. Wait for the owning document and, when exposed by the page,
    its Knockout binding. This is a readiness probe, not a fixed sleep; already
    ready forms take the existing fast path. The outer SAML deadline bounds it.
    """
    if str(protocol or "").casefold() != "anyconnect":
        return True
    try:
        return bool(password_loc.evaluate("""element => {
            const doc = element.ownerDocument;
            const view = doc.defaultView;
            if (view.location.hostname !== 'login.microsoftonline.com')
                return true;
            if (!element.isConnected || doc.readyState !== 'complete')
                return false;
            const bound = element.closest('[data-bind]');
            if (bound && view.ko && typeof view.ko.contextFor === 'function')
                return !!view.ko.contextFor(element);
            return true;
        }"""))
    except Exception:
        # Navigation or a detached input means the next loop must reacquire it.
        return False


def _enter_password_value(password_loc, password: str, protocol: Optional[str]) -> None:
    """Drive reactive Microsoft fields with keys; bulk-fill other providers."""
    if not _password_entry_uses_key_events(protocol):
        password_loc.fill(password)
        return

    password_loc.fill("")
    press_sequentially = getattr(password_loc, "press_sequentially", None)
    if callable(press_sequentially):
        press_sequentially(password, delay=15)
    else:
        # Compatibility with older Playwright releases used by some Arch/Nix
        # package sets.
        password_loc.type(password, delay=15)


def _otp_control_is_progress(
    current_identity: Optional[str],
    submitted_identity: Optional[str],
    otp_control_submitted: bool,
) -> bool:
    """Accept only the initial OTP form as actionable progress.

    A replacement control or a new TOTP time window is not semantic evidence
    that Microsoft requested another code.
    """
    return not otp_control_submitted


def _account_tile_matches_username(
    tile_text: Optional[str],
    username: Optional[str],
) -> bool:
    """Match one complete account identity, never a local-part or domain fragment."""
    target = unicodedata.normalize("NFKC", str(username or "")).strip().casefold()
    text = unicodedata.normalize("NFKC", str(tile_text or "")).casefold()
    if not target:
        return False
    if "@" not in target:
        return text.strip() == target
    tokens = {
        token.rstrip(".,;:")
        for token in re.findall(
            r"[\w.!#$%&'*+/=?^`{|}~-]+@[\w.-]+",
            text,
        )
    }
    return target in tokens


def _latch_sensitive_authenticator_challenge(
    sensitive_submission_started: bool,
    authenticator_challenge_visible: bool,
) -> bool:
    """An already-issued phone challenge must never be replayed automatically."""
    return bool(
        sensitive_submission_started
        or authenticator_challenge_visible
    )


def _latch_sensitive_cached_account_selection(
    sensitive_submission_started: bool,
    cached_account_selected: bool,
) -> bool:
    """A cached account can dispatch MFA immediately, so selection is sensitive."""
    return bool(
        sensitive_submission_started
        or cached_account_selected
    )


def _is_sensitive_submission_kind(kind: Optional[str]) -> bool:
    """Identify actions that must not be replayed through a clean-browser retry."""
    return kind in {
        "password",
        "password-unknown",
        "credential-lookup",
        "totp",
        "kmsi",
        "push",
        "passkey-registration-skip",
        "cached-account-selection",
    }


def _should_extend_submission_grace(
    processing_visible: bool,
    submission_kind: Optional[str],
) -> bool:
    """Extend only semantic processing or a credential/MFA submission."""
    return bool(
        processing_visible
        or _is_sensitive_submission_kind(submission_kind)
    )


def _password_field_completes_submission_transition(
    submission_kind: Optional[str],
    usable_password_control_progress: bool,
) -> bool:
    """Recognize account-discovery transitions that land on a password form."""
    return bool(
        usable_password_control_progress
        and submission_kind
        in {
            "username",
            "credential-lookup",
            "cached-account-selection",
        }
    )


def _ui_stall_exception(
    message: str,
    sensitive_submission_started: bool,
) -> RuntimeError:
    """Classify only pre-credential UI stalls as safe for clean-session retry."""
    error_type = SamlSensitiveActionError if sensitive_submission_started else SamlUiStalledError
    return error_type(message)


def _submission_hard_deadline(
    submitted_at: float,
    auth_deadline: float,
    max_wait_seconds: float = SAML_UI_MAX_SUBMIT_WAIT_SECONDS,
) -> float:
    """Clamp one submitted form to both its own cap and the auth deadline."""
    return min(auth_deadline, submitted_at + max(0.0, max_wait_seconds))


def _remaining_timeout_ms(deadline: float, now: Optional[float] = None) -> int:
    """Return the non-negative milliseconds remaining before a monotonic deadline."""
    current_time = time.monotonic() if now is None else now
    return max(0, int((deadline - current_time) * 1000))


def _standalone_two_digit_numbers(text: Optional[str]) -> set[str]:
    """Return unique standalone two-digit lines from rendered prompt text."""
    numbers = set()
    for line in (text or "").splitlines():
        match = re.fullmatch(r"\s*([0-9]{2})\s*", line)
        if match:
            numbers.add(match.group(1))
    return numbers


def _prefer_totp_for_number_match(
    mfa_preference: str,
    totp_available: bool,
    totp_disabled: bool,
) -> bool:
    """Prefer a stored TOTP unless phone approval was explicitly requested."""
    return mfa_preference != "push" and totp_available and not totp_disabled


def _should_notify_number_match(
    mfa_preference: str,
    totp_available: bool,
) -> bool:
    """Use phone approval only explicitly, or when adaptive mode has no TOTP."""
    return mfa_preference == "push" or (
        mfa_preference == "auto" and not totp_available
    )


def _has_number_match_evidence(
    marker_visible: bool,
    selector_contains_number: bool,
    authenticator_context_visible: bool,
) -> bool:
    """Require explicit wording or a numbered control on an Authenticator page."""
    return marker_visible or (
        selector_contains_number and authenticator_context_visible
    )


def _password_fallback_input_allowed(
    input_type: Optional[str],
    autocomplete: Optional[str],
    score: int,
) -> bool:
    """Keep a heuristic password fallback from selecting a username field."""
    normalized_type = str(input_type or "").strip().casefold()
    normalized_autocomplete = str(autocomplete or "").strip().casefold()
    return bool(
        score > 0
        and (
            normalized_type == "password"
            or normalized_autocomplete in {"current-password", "password"}
        )
    )


def _password_discovery_method_picker_ready(
    protocol: str,
    submission_kind: Optional[str],
    lookup_observed: bool,
    credential_tainted: bool,
    unsafe_write_observed: bool,
    primary_picker_visible: bool,
    password_method_visible: bool,
) -> bool:
    """Promote a credential-free lookup that lands on Microsoft's method picker."""
    return bool(
        _password_discovery_supported(protocol)
        and submission_kind == "password-unknown"
        and lookup_observed
        and not credential_tainted
        and not unsafe_write_observed
        and primary_picker_visible
        and password_method_visible
    )


def _adaptive_mfa_action(
    prefer_totp: bool,
    otp_input_visible: bool,
    authenticator_challenge_visible: bool,
    totp_choice_visible: bool,
    picker_transition_pending: bool,
) -> str:
    """Choose the next adaptive action without ever preferring phone over TOTP."""
    if prefer_totp and otp_input_visible:
        return "submit-totp"
    if not authenticator_challenge_visible:
        return "select-totp" if prefer_totp and totp_choice_visible else "none"
    if not prefer_totp:
        return "phone"
    if totp_choice_visible:
        return "select-totp"
    if picker_transition_pending:
        return "wait-for-picker"
    return "open-alternate-methods"


def _password_bridge_transition_action(
    totp_choice_visible: bool,
    password_input_visible: bool,
    transition_pending: bool,
) -> str:
    """Continue either route exposed after Microsoft's password bridge."""
    if totp_choice_visible:
        return "select-totp"
    if password_input_visible:
        return "accept-password"
    return "wait" if transition_pending else "fail"


def _password_bridge_allowed(mfa_preference: str) -> bool:
    """Never leave an explicitly requested TOTP route for password."""
    return str(mfa_preference or "").casefold() == "auto"


def _passkey_fallback_route(
    password_already_submitted: bool,
    prefer_totp: bool,
) -> str:
    """Keep a post-password passkey prompt on the requested MFA route."""
    if password_already_submitted and prefer_totp:
        return "totp"
    return "password"


def _passkey_password_transition_action(
    password_input_visible: bool,
    transition_pending: bool,
) -> str:
    """Wait for the password form without replaying the passkey fallback."""
    if password_input_visible:
        return "accept-password"
    return "wait" if transition_pending else "fail"


def _should_submit_totp_counter(
    last_submitted_counter: Optional[int],
    current_counter: int,
) -> bool:
    """Submit once per TOTP window and allow a fresh window to recover a stall."""
    return (
        last_submitted_counter is None
        or last_submitted_counter != current_counter
    )


def _should_submit_totp_for_control(
    control_is_progress: bool,
    last_submitted_counter: Optional[int],
    current_counter: int,
) -> bool:
    """Allow one code; control replacement and rotation never authorize replay."""
    return bool(
        control_is_progress
        and last_submitted_counter is None
    )


def _merge_saml_artifacts(
    cookies: dict[str, str],
    saml_result: dict,
    protocol: str,
    gp_prelogin_cookie: Optional[str] = None,
    gp_gateway_ip: Optional[str] = None,
) -> dict[str, str]:
    """Merge captured SAML/GP headers without dropping their paired username."""
    merged = dict(cookies)
    if saml_result.get("saml_response"):
        merged["SAMLResponse"] = saml_result["saml_response"]
    if saml_result.get("prelogin_cookie"):
        merged["prelogin-cookie"] = saml_result["prelogin_cookie"]
    if protocol == "gp":
        if saml_result.get("portal_userauthcookie"):
            merged["portal-userauthcookie"] = saml_result["portal_userauthcookie"]
        if saml_result.get("saml_username"):
            merged["saml-username"] = saml_result["saml_username"]
        if gp_prelogin_cookie and "prelogin-cookie" not in merged:
            merged["prelogin-cookie"] = gp_prelogin_cookie
        if gp_gateway_ip:
            merged["_gateway_ip"] = gp_gateway_ip
    return merged


def _parse_saml_timeout(protocol: str, value: Optional[str] = None) -> int:
    """Return a safe SAML timeout for the selected protocol."""
    # Bound the complete browser flow while leaving time for interactive MFA.
    # Successful flows finish as soon as the VPN callback arrives.
    default_timeout = 240 if protocol == "gp" else 300
    raw_value = os.environ.get("MS_SSO_SAML_TIMEOUT", "") if value is None else value
    try:
        timeout = int(str(raw_value).strip()) if str(raw_value).strip() else default_timeout
    except (TypeError, ValueError):
        timeout = default_timeout
    if timeout <= 0:
        timeout = default_timeout
    return max(timeout, default_timeout) if protocol == "gp" else timeout


def _detect_desktop_user() -> Optional[str]:
    """Return the unique active, local graphical user reported by logind."""
    try:
        result = subprocess.run(
            ["loginctl", "list-sessions", "--no-legend"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            return None

        candidates = set()
        for line in result.stdout.splitlines():
            parts = line.split()
            if not parts:
                continue
            session_id = parts[0]
            details = subprocess.run(
                [
                    "loginctl",
                    "show-session",
                    session_id,
                    "-p", "Active",
                    "-p", "Remote",
                    "-p", "Type",
                    "-p", "Class",
                    "-p", "User",
                    "-p", "Name",
                    "--no-pager",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if details.returncode != 0:
                continue
            properties = {}
            for property_line in details.stdout.splitlines():
                key, separator, value = property_line.partition("=")
                if separator:
                    properties[key] = value
            try:
                uid = int(properties.get("User", "-1"))
            except ValueError:
                continue
            if (
                properties.get("Active") == "yes"
                and properties.get("Remote") == "no"
                and properties.get("Type") in {"wayland", "x11"}
                and properties.get("Class") == "user"
                and uid >= 1000
                and properties.get("Name")
            ):
                candidates.add(properties["Name"])
        return next(iter(candidates)) if len(candidates) == 1 else None
    except Exception:
        return None


def _get_gp_prelogin(
    server: str,
    debug: bool = False,
    gp_os_version: Optional[str] = None,
    gp_auth_interface: str = "portal",
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Get prelogin-cookie and SAML request for GlobalProtect."""
    gp_auth_interface = str(gp_auth_interface or "portal").strip().lower()
    if gp_auth_interface not in {"portal", "gateway"}:
        gp_auth_interface = "portal"
    prelogin_path = (
        "ssl-vpn/prelogin.esp"
        if gp_auth_interface == "gateway"
        else "global-protect/prelogin.esp"
    )
    url = f"https://{server}/{prelogin_path}"
    retry_env = os.environ.get("MS_SSO_GP_PRELOGIN_RETRIES", "3").strip()
    delay_env = os.environ.get("MS_SSO_GP_PRELOGIN_DELAY", "2").strip()
    client_os = get_gp_client_os()
    os_version = str(gp_os_version or "").strip()
    if not os_version or os_version.lower() == "auto":
        os_version = get_gp_os_version()
    host_id = socket.gethostname() or "localhost"
    request_params = {
        "tmp": "tmp",
        "clientVer": "4100",
        "clientos": client_os,
        "os-version": os_version,
        "host-id": host_id,
        "ipv6-support": "yes",
        "default-browser": "1",
        "cas-support": "yes",
    }
    request_body = urllib.parse.urlencode(request_params).encode("utf-8")
    try:
        retries = max(1, int(retry_env))
    except Exception:
        retries = 3
    try:
        retry_delay = max(0.0, float(delay_env))
    except Exception:
        retry_delay = 2.0

    last_err = None
    for attempt in range(1, retries + 1):
        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(url, data=request_body, method="POST")
            req.add_header("User-Agent", "PAN GlobalProtect")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                if resp.status != 200:
                    raise Exception(f"prelogin.esp returned HTTP {resp.status}")
                content = resp.read().decode("utf-8")
                root = ET.fromstring(content)
                prelogin_cookie = None
                saml_request = None
                gateway_ip = None
                for elem in root.iter():
                    if elem.tag == "prelogin-cookie":
                        prelogin_cookie = elem.text
                    elif elem.tag == "saml-request":
                        saml_request = elem.text
                    elif elem.tag == "server-ip":
                        gateway_ip = elem.text
                return prelogin_cookie, saml_request, gateway_ip
        except Exception as e:
            last_err = e
            if debug:
                print(f"[DEBUG] prelogin.esp error (attempt {attempt}/{retries}): {e}")
            if attempt < retries:
                time.sleep(retry_delay)

    # Some portals are stricter and still expect the legacy GET prelogin call.
    fallback_url = f"{url}?{urllib.parse.urlencode(request_params)}"
    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(fallback_url)
        req.add_header("User-Agent", "PAN GlobalProtect")
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            if resp.status != 200:
                raise Exception(f"legacy prelogin.esp returned HTTP {resp.status}")
            content = resp.read().decode("utf-8")
            root = ET.fromstring(content)
            prelogin_cookie = None
            saml_request = None
            gateway_ip = None
            for elem in root.iter():
                if elem.tag == "prelogin-cookie":
                    prelogin_cookie = elem.text
                elif elem.tag == "saml-request":
                    saml_request = elem.text
                elif elem.tag == "server-ip":
                    gateway_ip = elem.text
            if debug:
                print(
                    "[DEBUG] Falling back to legacy GP prelogin request "
                    f"(clientos={client_os}, os-version={os_version}, host-id={host_id})"
                )
            return prelogin_cookie, saml_request, gateway_ip
    except Exception as fallback_err:
        last_err = fallback_err

    if debug and last_err is not None:
        print(f"[DEBUG] prelogin.esp failed after {retries} attempts: {last_err}")
    return None, None, None


def do_saml_auth(
    vpn_server: str,
    username: str,
    password: str,
    totp_secret: Optional[str] = None,
    protocol: str = "anyconnect",
    auto_totp: bool = True,
    headless: bool = True,
    debug: bool = False,
    vpn_server_ip: Optional[str] = None,
    disable_browser_session_cache: bool = False,
    gp_os_version: Optional[str] = None,
    gp_auth_interface: str = "portal",
    cancel_callback: Optional[Callable[[], bool]] = None,
    progress_callback: Optional[Callable[[str], None]] = None,
    mfa_preference: Optional[str] = None,
    notification_helper_path: Optional[str] = None,
    number_match_callback: Optional[Callable[[str], bool]] = None,
):
    """Complete Microsoft SAML authentication and return cookies."""
    last_reported_progress = None
    vpn_server_raw = vpn_server
    try:
        parsed_server = urllib.parse.urlparse(vpn_server_raw if "://" in vpn_server_raw else f"//{vpn_server_raw}")
        vpn_server_host = parsed_server.hostname or vpn_server_raw
        vpn_server_netloc = parsed_server.netloc or vpn_server_raw
    except Exception:
        vpn_server_host = vpn_server_raw
        vpn_server_netloc = vpn_server_raw

    vpn_url = f"https://{vpn_server_netloc}"
    mfa_preference = str(
        mfa_preference or os.environ.get("MS_SSO_MFA_PREFERENCE") or "auto"
    ).strip().lower()
    if mfa_preference not in {"auto", "totp", "push"}:
        mfa_preference = "auto"

    def _cancelled() -> bool:
        if not cancel_callback:
            return False
        try:
            return bool(cancel_callback())
        except Exception:
            return False

    def _raise_if_cancelled() -> None:
        if _cancelled():
            raise RuntimeError("SAML authentication cancelled")

    def _report_progress(event: str) -> None:
        """Report privacy-safe flow state without credentials, codes, or URLs."""
        nonlocal last_reported_progress
        if not progress_callback:
            return
        if event == last_reported_progress:
            return
        try:
            progress_callback(event)
            last_reported_progress = event
        except Exception:
            pass

    gp_prelogin_cookie, gp_saml_request, gp_gateway_ip = None, None, None
    if protocol == "gp":
        print("  [1/6] Getting GlobalProtect prelogin info...")
        gp_prelogin_cookie, gp_saml_request, gp_gateway_ip = _get_gp_prelogin(
            vpn_server,
            debug,
            gp_os_version=gp_os_version,
            gp_auth_interface=gp_auth_interface,
        )
        if debug:
            print(f"    [DEBUG] prelogin-cookie present: {bool(gp_prelogin_cookie)}")
            print(f"    [DEBUG] gateway_ip: {gp_gateway_ip}")
    else:
        print("  [1/6] Using AnyConnect SAML URL...")

    real_user = os.environ.get("SUDO_USER", os.environ.get("USER", "root"))
    home = os.path.expanduser("~")

    def _is_truthy(value) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    def _ensure_writable_dir(path: str) -> bool:
        try:
            os.makedirs(path, exist_ok=True)
            probe = os.path.join(path, ".write-test")
            with open(probe, "w", encoding="utf-8") as f:
                f.write("ok")
            os.remove(probe)
            return True
        except OSError:
            return False

    def _looks_like_playwright_browser_dir(path: str) -> bool:
        try:
            return any(
                entry.startswith(("chromium-", "chromium_headless_shell-", "firefox-", "webkit-"))
                for entry in os.listdir(path)
            )
        except OSError:
            return False

    def _install_playwright_chromium(browser_path: str) -> bool:
        if _is_truthy(os.environ.get("MS_SSO_DISABLE_PLAYWRIGHT_AUTO_INSTALL")):
            return False

        env = os.environ.copy()
        env["PLAYWRIGHT_BROWSERS_PATH"] = browser_path
        commands = []
        playwright_bin = shutil.which("playwright")
        if playwright_bin:
            commands.append([playwright_bin, "install", "chromium"])
        commands.append([sys.executable, "-m", "playwright", "install", "chromium"])

        os.makedirs(browser_path, exist_ok=True)
        for command in commands:
            try:
                if debug:
                    print(f"    [DEBUG] Installing Playwright Chromium into {browser_path}: {' '.join(command)}")
                result = subprocess.run(
                    command,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    check=False,
                )
                if result.returncode == 0:
                    return True
                if debug:
                    output = (result.stderr or result.stdout or "").strip()
                    print(f"    [DEBUG] Playwright install failed ({result.returncode}): {output}")
            except Exception as e:
                if debug:
                    print(f"    [DEBUG] Playwright install command failed: {e}")
        return False

    force_ephemeral_browser_session = (
        _is_truthy(disable_browser_session_cache)
        or _is_truthy(os.environ.get("MS_SSO_DISABLE_BROWSER_SESSION_CACHE"))
    )

    if real_user == "root":
        detected_user = _detect_desktop_user()
        if detected_user:
            real_user = detected_user
            if debug:
                print(f"    [DEBUG] Detected desktop user: {real_user}")
    if real_user != "root":
        try:
            import pwd
            home = pwd.getpwnam(real_user).pw_dir
        except Exception:
            pass

    number_match_notification_id = 0

    def _notification_request(request: dict) -> Optional[int]:
        """Run the unprivileged notification helper with data on stdin only."""
        helper_path = (
            os.environ.get("MS_SSO_NOTIFICATION_HELPER", "").strip()
            or (notification_helper_path or "").strip()
        )
        if not helper_path or not os.path.isfile(helper_path):
            return None
        try:
            import pwd

            account = pwd.getpwnam(real_user)
            runtime_dir = f"/run/user/{account.pw_uid}"
            user_bus = os.path.join(runtime_dir, "bus")
            if not os.path.exists(user_bus):
                return None
            safe_path = os.environ.get(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            notification_env = {
                "PATH": safe_path,
                "HOME": account.pw_dir,
                "USER": account.pw_name,
                "LOGNAME": account.pw_name,
                "XDG_RUNTIME_DIR": runtime_dir,
                "DBUS_SESSION_BUS_ADDRESS": f"unix:path={user_bus}",
                "LANG": os.environ.get("LANG", "C.UTF-8"),
            }

            if os.geteuid() == 0 and account.pw_uid != 0:
                runuser = shutil.which("runuser")
                env_bin = shutil.which("env")
                if not runuser or not env_bin:
                    return None
                command = [
                    runuser,
                    "-u",
                    account.pw_name,
                    "--",
                    env_bin,
                    "-i",
                    f"PATH={safe_path}",
                    f"HOME={account.pw_dir}",
                    f"USER={account.pw_name}",
                    f"LOGNAME={account.pw_name}",
                    f"XDG_RUNTIME_DIR={runtime_dir}",
                    f"DBUS_SESSION_BUS_ADDRESS=unix:path={user_bus}",
                    f"LANG={notification_env['LANG']}",
                    helper_path,
                ]
            else:
                command = [helper_path]

            result = subprocess.run(
                command,
                input=json.dumps(request),
                env=notification_env,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode != 0:
                return None
            notification_id = int(result.stdout.strip())
            return notification_id if 0 <= notification_id <= 0xFFFFFFFF else None
        except Exception:
            return None

    def _notify_number_match(number: str) -> bool:
        nonlocal number_match_notification_id
        if not re.fullmatch(r"[0-9]{2}", number or ""):
            return False
        if number_match_callback:
            try:
                return bool(number_match_callback(number))
            except Exception:
                return False
        notification_id = _notification_request({
            "action": "show",
            "code": number,
            "replaces_id": number_match_notification_id,
        })
        if notification_id is None:
            return False
        number_match_notification_id = notification_id
        return True

    def _close_number_match_notification() -> None:
        nonlocal number_match_notification_id
        if not number_match_notification_id:
            return
        _notification_request({
            "action": "close",
            "id": number_match_notification_id,
        })
        number_match_notification_id = 0

    browser_path_candidates = []
    existing_env_browser_path = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if existing_env_browser_path:
        browser_path_candidates.append(existing_env_browser_path)
    if home:
        browser_path_candidates.append(os.path.join(home, ".cache", "ms-playwright"))
    browser_path_candidates.extend([
        "/var/cache/ms-playwright",
        "/opt/ms-playwright",
        "/usr/share/ms-playwright",
    ])

    for browser_path in browser_path_candidates:
        if _looks_like_playwright_browser_dir(browser_path):
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = browser_path
            if debug:
                print(f"    [DEBUG] Using Playwright browsers from: {browser_path}")
            break

    with sync_playwright() as p:
        _raise_if_cancelled()
        session_tmp_dir = None
        if force_ephemeral_browser_session:
            session_tmp_dir = tempfile.mkdtemp(prefix="ms-sso-openconnect-auth-")
            cache_dir = session_tmp_dir
            if debug:
                print(f"    [DEBUG] Using ephemeral browser session dir: {cache_dir}")
        else:
            cache_dir = None
            cache_roots = []
            if real_user != "root":
                cache_roots.append(
                    os.path.join(home, ".cache", "ms-sso-openconnect", "browser-session")
                )
            cache_roots.extend([
                "/var/cache/ms-sso-openconnect/browser-session",
                "/tmp/ms-sso-openconnect/browser-session",
            ])
            cache_key = _browser_session_cache_key(
                protocol,
                vpn_server_netloc,
                username,
            )

            for root in cache_roots:
                candidate = os.path.join(root, cache_key)
                if _ensure_writable_dir(candidate):
                    cache_dir = candidate
                    if debug:
                        print(f"    [DEBUG] Using browser session dir: {cache_dir}")
                    break

            if not cache_dir:
                session_tmp_dir = tempfile.mkdtemp(prefix="ms-sso-openconnect-auth-")
                cache_dir = os.path.join(session_tmp_dir, "browser-session")
                os.makedirs(cache_dir, exist_ok=True)
                if debug:
                    print(f"    [DEBUG] Falling back to temporary browser session dir: {cache_dir}")

        def _chromium_executable_path() -> Optional[str]:
            configured = os.environ.get("MS_SSO_PLAYWRIGHT_EXECUTABLE", "").strip()
            if configured:
                return configured
            try:
                executable = p.chromium.executable_path
                if executable and os.path.exists(executable):
                    return executable
            except Exception:
                pass
            return None

        def _launch_context():
            executable_path = _chromium_executable_path()
            if debug and executable_path:
                print(f"    [DEBUG] Using Chromium executable: {executable_path}")
            browser_locale = (
                os.environ.get("MS_SSO_BROWSER_LOCALE", "en-US").strip()
                or "en-US"
            )
            return p.chromium.launch_persistent_context(
                cache_dir,
                headless=headless,
                executable_path=executable_path,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-blink-features=AutomationControlled",
                    "--window-size=1280,720",
                ],
                viewport={"width": 1280, "height": 720},
                user_agent=(
                    # Match the user's Linux browser. Pretending to be Windows
                    # makes Microsoft inject Windows Hello/passkey into FHNW's
                    # proof picker, and its alternate-method link then routes
                    # back to primary credentials instead of verification code.
                    "Mozilla/5.0 (X11; Linux x86_64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/122.0.0.0 Safari/537.36"
                ),
                # FHNW's German Microsoft flow maps "Auf andere Weise
                # anmelden" to the primary credential picker. The English
                # flow exposes the distinct Authenticator fallback that leads
                # to "Use a verification code", matching the supported manual
                # route. Keep an environment override for other tenants.
                locale=browser_locale,
            )

        try:
            context = _launch_context()
        except Exception as e:
            message = str(e)
            browser_path = os.environ.get("PLAYWRIGHT_BROWSERS_PATH") or os.path.join(home, ".cache", "ms-playwright")
            if "Executable doesn't exist" not in message or not _install_playwright_chromium(browser_path):
                raise
            if debug:
                print("    [DEBUG] Retrying Playwright launch after Chromium runtime install")
            context = _launch_context()
        try:
            context.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined});")
        except Exception:
            pass
        page = context.pages[0] if context.pages else context.new_page()
        page.set_default_timeout(5000)
        page.set_default_navigation_timeout(20000)

        def _page_host() -> str:
            try:
                return urllib.parse.urlparse(page.url).hostname or "unknown"
            except Exception:
                return "unknown"

        def _secure_screenshot(path: str) -> None:
            page.screenshot(path=path)
            os.chmod(path, 0o600)

        discard_persistent_profile_on_close = False
        sensitive_submission_started = False

        def _close_context() -> None:
            try:
                _close_number_match_notification()
                context.close()
            finally:
                if session_tmp_dir:
                    shutil.rmtree(session_tmp_dir, ignore_errors=True)
                elif discard_persistent_profile_on_close:
                    _discard_stale_browser_profile(cache_dir, session_tmp_dir)

        def _raise_profile_stall(message: str) -> None:
            """Invalidate stale persistent state without replaying credentials."""
            nonlocal discard_persistent_profile_on_close
            if _persistent_profile_should_be_discarded_after_stall(
                protocol,
                force_ephemeral_browser_session,
            ):
                discard_persistent_profile_on_close = True
                _report_progress("saml-persistent-profile-invalidated")
            raise _ui_stall_exception(message, sensitive_submission_started)

        saml_result = {
            "prelogin_cookie": None,
            "saml_username": None,
            "saml_response": None,
            "portal_userauthcookie": None,
        }

        allowed_hosts = {vpn_server_host}
        if gp_gateway_ip:
            allowed_hosts.add(gp_gateway_ip)
        if vpn_server_ip:
            allowed_hosts.add(vpn_server_ip)

        def _is_vpn_url(url: str) -> bool:
            try:
                host = urllib.parse.urlparse(url).hostname or ""
            except Exception:
                host = ""
            return host in allowed_hosts

        def _cookie_domain_matches(domain: str) -> bool:
            domain_no_dot = domain.lstrip(".")
            if domain_no_dot == vpn_server_host:
                return True
            if vpn_server_host.endswith(f".{domain_no_dot}"):
                return True
            if vpn_server_ip and domain_no_dot == vpn_server_ip:
                return True
            return False

        def _collect_vpn_cookies() -> dict[str, str]:
            vpn_cookies = {}
            for c in context.cookies():
                if c.get("value") and _cookie_domain_matches(c.get("domain", "")):
                    vpn_cookies[c["name"]] = c["value"]
            return vpn_cookies

        def _has_usable_auth_artifact(cookies: Optional[dict[str, str]] = None) -> bool:
            cookies = cookies or {}
            if protocol == "anyconnect":
                # OpenConnect's --cookie path cannot use a bare SAMLResponse. It
                # needs the final Cisco WebVPN session cookies; otherwise the
                # gateway rejects the cookie immediately.
                return bool(
                    cookies.get("webvpn")
                    and (cookies.get("webvpnc") or cookies.get("webvpnaac") or cookies.get("SVPNCOOKIE"))
                )
            return bool(
                saml_result.get("prelogin_cookie")
                or saml_result.get("portal_userauthcookie")
                or cookies.get("prelogin-cookie")
                or cookies.get("portal-userauthcookie")
                or cookies.get("SVPNCOOKIE")
            )

        def _auth_capture_complete() -> bool:
            if protocol == "anyconnect":
                return _has_usable_auth_artifact(_collect_vpn_cookies())
            return bool(
                saml_result.get("prelogin_cookie")
                or saml_result.get("portal_userauthcookie")
            )

        vpn_request_event = threading.Event()
        ui_change_event = threading.Event()
        microsoft_credential_lookup = _MicrosoftCredentialLookupTracker()
        sensitive_dispatch_evidence = _SensitiveDispatchEvidenceTracker()
        last_transport_request_evidence = None
        rendered_ui_snapshot: Optional[_RenderedAuthUiSnapshot] = None

        def _refresh_rendered_ui_snapshot() -> _RenderedAuthUiSnapshot:
            nonlocal rendered_ui_snapshot
            rendered_ui_snapshot = _capture_rendered_auth_ui(page)
            return rendered_ui_snapshot

        def _current_rendered_ui_snapshot() -> _RenderedAuthUiSnapshot:
            if rendered_ui_snapshot is None:
                return _refresh_rendered_ui_snapshot()
            return rendered_ui_snapshot

        def _invalidate_rendered_ui_snapshot() -> None:
            nonlocal rendered_ui_snapshot
            rendered_ui_snapshot = None

        def _wait_for_vpn_callback(timeout_ms: int = 60000) -> None:
            _raise_if_cancelled()
            if _is_vpn_url(page.url) and protocol != "anyconnect":
                return
            if _auth_capture_complete():
                return
            deadline = time.time() + (timeout_ms / 1000.0)
            while time.time() < deadline:
                _raise_if_cancelled()
                if _auth_capture_complete():
                    return
                if _is_vpn_url(page.url) and protocol != "anyconnect":
                    return
                if vpn_request_event.wait(timeout=0.05):
                    if protocol != "anyconnect" or _auth_capture_complete():
                        return
                    vpn_request_event.clear()

        def handle_request(request):
            nonlocal last_transport_request_evidence
            tracker_accepted = sensitive_dispatch_evidence.request_started(
                request,
                main_frame=page.main_frame,
                expected_secret=password,
            )
            if debug:
                try:
                    parsed_diagnostic_url = urllib.parse.urlsplit(request.url)
                    if parsed_diagnostic_url.hostname == "login.microsoftonline.com":
                        diagnostic_host = "microsoft"
                    elif _is_known_microsoft_telemetry_host(
                        parsed_diagnostic_url.hostname
                    ):
                        diagnostic_host = "telemetry"
                    elif _is_vpn_url(request.url):
                        diagnostic_host = "vpn"
                    else:
                        diagnostic_host = "other"
                    diagnostic_method = str(request.method or "").upper()
                    if diagnostic_method in {"GET", "HEAD"}:
                        diagnostic_method = "read"
                    elif diagnostic_method:
                        diagnostic_method = "write"
                    else:
                        diagnostic_method = "unknown"
                    diagnostic_resource = str(
                        getattr(request, "resource_type", "") or "unknown"
                    ).casefold()
                    if diagnostic_resource not in {
                        "document",
                        "xhr",
                        "fetch",
                    }:
                        diagnostic_resource = "other"
                    diagnostic_navigation = bool(
                        request.is_navigation_request()
                    )
                    diagnostic_main_frame = bool(
                        request.frame == page.main_frame
                    )
                    diagnostic_payload_shape = (
                        sensitive_dispatch_evidence._request_payload_shape(
                            request
                        )
                        if diagnostic_method == "write"
                        else "none"
                    )
                    transport_request_evidence = (
                        diagnostic_host,
                        diagnostic_method,
                        diagnostic_resource,
                        diagnostic_navigation,
                        diagnostic_main_frame,
                        bool(tracker_accepted),
                        sensitive_dispatch_evidence.safe_navigation_request_generation,
                        sensitive_dispatch_evidence.credential_taint_generation,
                        sensitive_dispatch_evidence.outbound_request_generation,
                        sensitive_dispatch_evidence.pending_main_frame_navigation_count,
                        diagnostic_payload_shape,
                        sensitive_dispatch_evidence.write_request_generation,
                        sensitive_dispatch_evidence.unsafe_write_request_generation,
                    )
                    if (
                        diagnostic_resource == "document"
                        or diagnostic_navigation
                        or diagnostic_method == "write"
                    ) and transport_request_evidence != last_transport_request_evidence:
                        last_transport_request_evidence = transport_request_evidence
                        _report_progress(
                            "transport-evidence "
                            f"host={transport_request_evidence[0]} "
                            f"method={transport_request_evidence[1]} "
                            f"resource={transport_request_evidence[2]} "
                            f"navigation={int(transport_request_evidence[3])} "
                            f"main-frame={int(transport_request_evidence[4])} "
                            f"accepted={int(transport_request_evidence[5])} "
                            f"safe-request={transport_request_evidence[6]} "
                            f"taint={transport_request_evidence[7]} "
                            f"outbound={transport_request_evidence[8]} "
                            f"pending-nav={transport_request_evidence[9]} "
                            f"payload={transport_request_evidence[10]} "
                            f"write={transport_request_evidence[11]} "
                            f"unsafe-write={transport_request_evidence[12]}"
                        )
                except Exception:
                    pass
            if debug:
                parsed_request = urllib.parse.urlsplit(request.url)
                if (
                    parsed_request.hostname == "login.microsoftonline.com"
                    and request.method.upper() != "GET"
                ):
                    print(
                        "    [DEBUG] Microsoft request: "
                        f"path={parsed_request.path or '/'} method={request.method}"
                    )
            microsoft_credential_lookup.started(request)
            if _is_vpn_url(request.url):
                vpn_request_event.set()
                ui_change_event.set()
                if debug:
                    parsed_request = urllib.parse.urlsplit(request.url)
                    print(
                        "    [DEBUG] Request to VPN: "
                        f"host={parsed_request.hostname or 'unknown'} "
                        f"path={parsed_request.path or '/'}"
                    )
                    print(f"    [DEBUG] Request method: {request.method}")
                if request.post_data:
                    try:
                        params = urllib.parse.parse_qs(request.post_data)
                        if debug:
                            print(f"    [DEBUG] POST params: {list(params.keys())}")
                        if "SAMLResponse" in params:
                            saml_result["saml_response"] = params["SAMLResponse"][0]
                            if debug:
                                print(f"    [DEBUG] Captured SAMLResponse ({len(saml_result['saml_response'])} chars)")
                        if "prelogin-cookie" in params:
                            saml_result["prelogin_cookie"] = params["prelogin-cookie"][0]
                            if debug:
                                print(f"    [DEBUG] Captured prelogin-cookie from POST")
                    except Exception as e:
                        if debug:
                            print(f"    [DEBUG] Error parsing POST: {e}")

        def handle_response(response):
            sensitive_dispatch_evidence.response_received(response)
            parsed_response = urllib.parse.urlsplit(response.url)
            if not _is_vpn_url(response.url):
                if debug:
                    if (
                        parsed_response.hostname == "login.microsoftonline.com"
                        and response.request.method.upper() != "GET"
                    ):
                        print(
                            "    [DEBUG] Microsoft response: "
                            f"path={parsed_response.path or '/'} "
                            f"status={response.status}"
                        )
                return
            ui_change_event.set()
            try:
                headers = response.headers
                if debug:
                    parsed_response = urllib.parse.urlsplit(response.url)
                    print(
                        "    [DEBUG] Response from VPN: "
                        f"host={parsed_response.hostname or 'unknown'} "
                        f"path={parsed_response.path or '/'} status={response.status}"
                    )
                    auth_header_names = [
                        h for h in [
                            "prelogin-cookie",
                            "saml-username",
                            "portal-userauthcookie",
                            "set-cookie",
                            "location",
                        ]
                        if h in headers
                    ]
                    if auth_header_names:
                        print(
                            "    [DEBUG] Auth response headers present: "
                            f"{auth_header_names}"
                        )
                if "prelogin-cookie" in headers:
                    saml_result["prelogin_cookie"] = headers["prelogin-cookie"]
                if "saml-username" in headers:
                    saml_result["saml_username"] = headers["saml-username"]
                if "portal-userauthcookie" in headers:
                    saml_result["portal_userauthcookie"] = headers["portal-userauthcookie"]
            except Exception:
                pass

        def handle_request_failed(request):
            sensitive_dispatch_evidence.request_failed(request)
            if microsoft_credential_lookup.finished(request):
                ui_change_event.set()

        def handle_request_finished(request):
            if microsoft_credential_lookup.finished(request):
                ui_change_event.set()

        def handle_frame_navigated(frame):
            committed_origin = None
            try:
                is_main_frame = frame == page.main_frame
                if is_main_frame:
                    committed_origin = _canonical_https_origin(frame.url)
            except Exception:
                is_main_frame = False
            if is_main_frame:
                microsoft_credential_lookup.reset()
                sensitive_dispatch_evidence.main_frame_navigated(
                    committed_origin
                )
            _invalidate_rendered_ui_snapshot()
            ui_change_event.set()

        page.on("request", handle_request)
        page.on("response", handle_response)
        page.on("requestfailed", handle_request_failed)
        page.on("requestfinished", handle_request_finished)
        page.on("load", lambda *_: ui_change_event.set())
        page.on("domcontentloaded", lambda *_: ui_change_event.set())
        page.on("framenavigated", handle_frame_navigated)

        def _first_visible(locator, limit: int = 20):
            try:
                count = min(locator.count(), limit)
            except Exception:
                return None
            for index in range(count):
                candidate = locator.nth(index)
                try:
                    if candidate.is_visible():
                        return candidate
                except Exception:
                    continue
            return None

        def _first_usable_input(locator, limit: int = 20):
            """Return a visible, enabled, editable input and ignore stale panels."""
            try:
                count = min(locator.count(), limit)
            except Exception:
                return None
            for index in range(count):
                candidate = locator.nth(index)
                try:
                    if (
                        candidate.is_visible()
                        and _is_usable_input_state(
                            candidate.is_enabled(),
                            candidate.is_editable(),
                        )
                    ):
                        return candidate
                except Exception:
                    continue
            return None

        def _find_visible_in_frames(selectors: list[str], *, frames=None):
            search_frames = page.frames if frames is None else frames
            for frame in search_frames:
                for sel in selectors:
                    try:
                        candidate = _first_visible(frame.locator(sel))
                        if candidate is not None:
                            return candidate
                    except Exception:
                        continue
            return None

        def _find_usable_input_by_ids(ids: list[str]):
            for frame in page.frames:
                for element_id in ids:
                    try:
                        candidate = _first_usable_input(frame.locator(f"#{element_id}"))
                        if candidate is not None:
                            return candidate
                    except Exception:
                        continue
            return None

        def _find_usable_input_by_labels(labels: list[str]):
            patterns = [re.compile(re.escape(label), re.IGNORECASE) for label in labels]
            for frame in page.frames:
                for pattern in patterns:
                    try:
                        candidate = _first_usable_input(frame.get_by_label(pattern))
                        if candidate is not None:
                            return candidate
                    except Exception:
                        continue
            return None

        def _normalize_text(value: Optional[str]) -> str:
            return (value or "").strip().lower()

        def _iter_visible_inputs(frame, limit: int = 60):
            try:
                inputs = frame.locator("input")
                count = min(inputs.count(), limit)
            except Exception:
                return
            for idx in range(count):
                loc = inputs.nth(idx)
                try:
                    if not loc.is_visible():
                        continue
                    input_type = _normalize_text(loc.get_attribute("type"))
                    if input_type in {"hidden", "submit", "button", "checkbox", "radio", "file"}:
                        continue
                    yield loc
                except Exception:
                    continue

        def _score_input(attrs: dict[str, str], kind: str) -> int:
            name = _normalize_text(attrs.get("name"))
            input_id = _normalize_text(attrs.get("id"))
            placeholder = _normalize_text(attrs.get("placeholder"))
            aria_label = _normalize_text(attrs.get("aria-label"))
            autocomplete = _normalize_text(attrs.get("autocomplete"))
            input_type = _normalize_text(attrs.get("type"))
            input_mode = _normalize_text(attrs.get("inputmode"))
            data_test = _normalize_text(attrs.get("data-test") or attrs.get("data-testid"))

            haystack = "|".join([name, input_id, placeholder, aria_label, data_test])
            score = 0

            if kind == "username":
                if input_type == "email":
                    score += 6
                if autocomplete in {"username", "email"}:
                    score += 6
                if input_type in {"text", "email"}:
                    score += 1
                for hint in [
                    "user",
                    "login",
                    "email",
                    "username",
                    "account",
                    "loginfmt",
                    "i0116",
                    "identifier",
                    "okta",
                    "adfs",
                ]:
                    if hint in haystack:
                        score += 3
            elif kind == "password":
                if input_type == "password":
                    score += 8
                if autocomplete in {"current-password", "password"}:
                    score += 6
                for hint in [
                    "pass",
                    "password",
                    "passwd",
                    "pwd",
                    "i0118",
                ]:
                    if hint in haystack:
                        score += 3
            elif kind == "otp":
                if autocomplete == "one-time-code":
                    score += 8
                if input_mode == "numeric":
                    score += 1
                if input_type == "tel":
                    score += 1
                for hint in [
                    "otp",
                    "otc",
                    "mfa",
                    "2fa",
                    "totp",
                    "authenticator",
                    "verification",
                    "code",
                    "security code",
                ]:
                    if hint in haystack:
                        score += 3
            return score

        def _find_best_input(kind: str):
            best_score = 0
            best_loc = None
            for frame in page.frames:
                for loc in _iter_visible_inputs(frame):
                    try:
                        if not _is_usable_input_state(
                            loc.is_enabled(),
                            loc.is_editable(),
                        ):
                            continue
                        attrs = {
                            "type": loc.get_attribute("type") or "",
                            "name": loc.get_attribute("name") or "",
                            "id": loc.get_attribute("id") or "",
                            "placeholder": loc.get_attribute("placeholder") or "",
                            "aria-label": loc.get_attribute("aria-label") or "",
                            "autocomplete": loc.get_attribute("autocomplete") or "",
                            "inputmode": loc.get_attribute("inputmode") or "",
                            "data-test": loc.get_attribute("data-test") or "",
                            "data-testid": loc.get_attribute("data-testid") or "",
                        }
                        score = _score_input(attrs, kind)
                        if score > best_score:
                            best_score = score
                            best_loc = loc
                    except Exception:
                        continue
            # A generic numeric or telephone input is not enough evidence for an
            # OTP field (Microsoft number-matching pages can contain such controls).
            if kind == "otp" and best_score < 3:
                return None
            # Known password IDs and labels are handled before this fallback.
            # A generic candidate must still carry browser-level password
            # semantics; a password-like test attribute is not enough.
            if kind == "password" and best_loc is not None:
                try:
                    if not _password_fallback_input_allowed(
                        best_loc.get_attribute("type"),
                        best_loc.get_attribute("autocomplete"),
                        best_score,
                    ):
                        return None
                except Exception:
                    return None
            return best_loc

        def _find_otp_input():
            return (
                _find_usable_input_by_ids(["idTxtBx_SAOTCC_OTC", "idTxtBx_SAOTCC_OTP", "otp", "otc", "code"])
                or _find_usable_input_by_labels([
                    "Verification code",
                    "Security code",
                    "Code",
                    "OTP",
                    "Einmalcode",
                    "Prüfcode",
                    "Bestätigungscode",
                    "Sicherheitscode",
                    "Code eingeben",
                ])
                or _find_best_input("otp")
            )

        def _totp_error_signature(otp_loc) -> Optional[str]:
            stable_selectors = [
                "#idSpan_SAOTCC_Error",
                "#idDiv_SAOTCC_Error",
                "#idTD_Error",
            ]
            form_selectors = [
                "[role='alert']",
                "[aria-live='assertive']",
                "input[aria-invalid='true']",
            ]
            messages = []

            # Microsoft's stable error elements are sometimes siblings of the
            # OTP form rather than descendants. They are specific enough to
            # inspect across frames while generic alerts remain form-scoped.
            for selector in stable_selectors:
                candidate = _find_visible_in_frames([selector])
                if candidate is None:
                    continue
                try:
                    text_value = _normalize_text(candidate.text_content(timeout=500))
                    messages.append(text_value or selector)
                except Exception:
                    continue

            try:
                described_by = otp_loc.get_attribute("aria-describedby") or ""
            except Exception:
                described_by = ""
            for element_id in described_by.split():
                if not re.fullmatch(r"[A-Za-z0-9_.:-]+", element_id):
                    continue
                candidate = _find_visible_in_frames([f"#{element_id}"])
                if candidate is None:
                    continue
                try:
                    text_value = _normalize_text(candidate.text_content(timeout=500))
                    messages.append(text_value or f"#{element_id}")
                except Exception:
                    continue

            try:
                form = _first_visible(otp_loc.locator("xpath=ancestor::form[1]"), limit=1)
            except Exception:
                form = None
            if form is not None:
                for selector in form_selectors:
                    try:
                        candidate = _first_visible(form.locator(selector))
                        if candidate is None:
                            continue
                        text_value = _normalize_text(candidate.text_content(timeout=500))
                        messages.append(text_value or selector)
                    except Exception:
                        continue
            if not messages:
                return None
            return "|".join(sorted(set(messages)))

        def _input_value_empty(loc) -> bool:
            try:
                return not _normalize_text(loc.input_value())
            except Exception:
                return False

        def _input_value_present(loc) -> bool:
            """Fail closed when checking whether a sensitive value remains filled."""
            try:
                return bool(loc.input_value())
            except Exception:
                return False

        def _locator_is_actionable(loc) -> bool:
            try:
                if not loc.is_visible() or not loc.is_enabled():
                    return False
                traits = loc.evaluate(
                    """element => ({
                        tagName: element.tagName.toLowerCase(),
                        role: element.getAttribute('role') || '',
                        inputType: element.getAttribute('type') || '',
                        disabled: !!element.disabled ||
                            element.getAttribute('aria-disabled') === 'true',
                        hasHref: element.tagName.toLowerCase() === 'a' &&
                            !!element.getAttribute('href'),
                        hasClickHandler: typeof element.onclick === 'function' ||
                            element.hasAttribute('onclick'),
                        hasDataValue: element.hasAttribute('data-value'),
                        tabIndex: Number.isInteger(element.tabIndex) ?
                            element.tabIndex : null,
                        pointerCursor: window.getComputedStyle(element).cursor === 'pointer',
                    })"""
                )
                return _is_actionable_control(
                    traits.get("tagName"),
                    role=traits.get("role"),
                    input_type=traits.get("inputType"),
                    disabled=bool(traits.get("disabled")),
                    has_href=bool(traits.get("hasHref")),
                    has_click_handler=bool(traits.get("hasClickHandler")),
                    has_data_value=bool(traits.get("hasDataValue")),
                    tab_index=traits.get("tabIndex"),
                    pointer_cursor=bool(traits.get("pointerCursor")),
                )
            except Exception:
                return False

        def _find_actionable_text_control(frame, pattern, *, limit: int = 20):
            """Return a matching text node's nearest genuinely interactive control."""
            try:
                matches = frame.get_by_text(pattern, exact=False)
                match_count = min(matches.count(), limit)
            except Exception:
                return None
            for match_index in range(match_count):
                text_match = matches.nth(match_index)
                try:
                    if not text_match.is_visible():
                        continue
                    controls = text_match.locator("xpath=ancestor-or-self::*")
                    for control_index in range(controls.count() - 1, -1, -1):
                        control = controls.nth(control_index)
                        if _locator_is_actionable(control):
                            return control
                except Exception:
                    continue
            return None

        def _click_actionable_text_control(
            frame,
            pattern,
            *,
            sensitive: bool = False,
            action_name: str = "authentication action",
        ) -> bool:
            """Click the first working text control, skipping stale duplicates."""
            try:
                matches = frame.get_by_text(pattern, exact=False)
                match_count = min(matches.count(), 20)
            except Exception:
                return False
            for match_index in range(match_count):
                text_match = matches.nth(match_index)
                try:
                    if not text_match.is_visible():
                        continue
                    controls = text_match.locator("xpath=ancestor-or-self::*")
                    for control_index in range(controls.count() - 1, -1, -1):
                        control = controls.nth(control_index)
                        if not _locator_is_actionable(control):
                            continue
                        if _attempt_locator_click(
                            control,
                            timeout_ms=1500,
                            sensitive=sensitive,
                            action_name=action_name,
                        ):
                            return True
                except _SensitiveActionUncertainError:
                    raise
                except Exception:
                    continue
            return False

        def _click_action(
            labels: list[str],
            *,
            sensitive: bool = False,
            action_name: str = "authentication action",
        ) -> bool:
            # A negative accessible-name/text probe is intentionally batched.
            # If it is positive, retain the ordered exact-then-partial click
            # path below so sensitive action selection semantics do not change.
            if not _action_available(labels):
                return False
            patterns = _action_patterns(labels)
            for frame in page.frames:
                for pattern in patterns:
                    for role in ["button", "link"]:
                        try:
                            matches = frame.get_by_role(role, name=pattern)
                            for index in range(min(matches.count(), 20)):
                                candidate = matches.nth(index)
                                if not _locator_is_actionable(candidate):
                                    continue
                                if _attempt_locator_click(
                                    candidate,
                                    timeout_ms=1500,
                                    sensitive=sensitive,
                                    action_name=action_name,
                                ):
                                    return True
                        except RuntimeError:
                            raise
                        except Exception:
                            continue
                    try:
                        loc = frame.locator("input[type='submit']")
                        if loc.count() > 0:
                            for idx in range(min(loc.count(), 10)):
                                candidate = loc.nth(idx)
                                try:
                                    value = _normalize_text(candidate.get_attribute("value"))
                                    if (
                                        value
                                        and pattern.search(value)
                                        and _locator_is_actionable(candidate)
                                    ):
                                        if _attempt_locator_click(
                                            candidate,
                                            timeout_ms=1500,
                                            sensitive=sensitive,
                                            action_name=action_name,
                                        ):
                                            return True
                                except _SensitiveActionUncertainError:
                                    raise
                                except Exception:
                                    continue
                    except _SensitiveActionUncertainError:
                        raise
                    except Exception:
                        continue
                    if _click_actionable_text_control(
                        frame,
                        pattern,
                        sensitive=sensitive,
                        action_name=action_name,
                    ):
                        return True
            return False

        def _action_available(labels: list[str]) -> bool:
            """Find only visible, enabled controls; explanatory text is not an action."""
            patterns = _action_patterns(labels)
            pattern = _combined_action_pattern(labels)
            role_limit = max(20, 20 * len(patterns))
            submit_limit = max(10, 10 * len(patterns))
            for frame in page.frames:
                for role in ("button", "link"):
                    try:
                        matches = frame.get_by_role(role, name=pattern)
                        for index in range(min(matches.count(), role_limit)):
                            if _locator_is_actionable(matches.nth(index)):
                                return True
                    except Exception:
                        continue
                try:
                    submits = frame.locator(
                        "input[type='submit'], input[type='button'], button[type='submit']"
                    )
                    for index in range(min(submits.count(), submit_limit)):
                        candidate = submits.nth(index)
                        tag_name = candidate.evaluate(
                            "element => element.tagName.toLowerCase()"
                        )
                        input_type = candidate.get_attribute("type")
                        label = _normalize_text(
                            candidate.get_attribute("value")
                            or candidate.text_content(timeout=500)
                        )
                        if (
                            label
                            and pattern.search(label)
                            and candidate.is_visible()
                            and candidate.is_enabled()
                            and _is_actionable_control(
                                tag_name,
                                input_type=input_type,
                            )
                        ):
                            return True
                except Exception:
                    continue
                if _find_actionable_text_control(
                    frame,
                    pattern,
                    limit=role_limit,
                ) is not None:
                    return True
            return False

        def _click_known_ids(
            ids: list[str],
            *,
            sensitive: bool = False,
            action_name: str = "authentication action",
        ) -> bool:
            for frame in page.frames:
                for element_id in ids:
                    try:
                        matches = frame.locator(f"#{element_id}")
                        for index in range(min(matches.count(), 20)):
                            candidate = matches.nth(index)
                            if not _locator_is_actionable(candidate):
                                continue
                            if _attempt_locator_click(
                                candidate,
                                timeout_ms=1000,
                                sensitive=sensitive,
                                action_name=action_name,
                            ):
                                return True
                    except _SensitiveActionUncertainError:
                        raise
                    except Exception:
                        continue
            return False

        def _find_actionable_in_frames(selectors, *, frames=None) -> Optional[object]:
            """Find an enabled actionable match without stale duplicates shadowing it."""
            search_frames = page.frames if frames is None else frames
            for frame in search_frames:
                for selector in selectors:
                    try:
                        matches = frame.locator(selector)
                        count = min(matches.count(), 20)
                    except Exception:
                        continue
                    for index in range(count):
                        candidate = matches.nth(index)
                        if _locator_is_actionable(candidate):
                            return candidate
            return None

        def _actionable_selector_visible(selectors) -> bool:
            """Use the iteration snapshot, probing only frames that failed capture."""
            snapshot = _current_rendered_ui_snapshot()
            if _snapshot_selector_actionable(snapshot, selectors):
                return True
            return _find_actionable_in_frames(
                selectors,
                frames=snapshot.failed_frames,
            ) is not None

        def _click_first_selector(
            selectors,
            *,
            sensitive: bool = False,
            action_name: str = "authentication action",
        ) -> bool:
            for frame in page.frames:
                for selector in selectors:
                    try:
                        matches = frame.locator(selector)
                        count = min(matches.count(), 20)
                    except Exception:
                        continue
                    for index in range(count):
                        candidate = matches.nth(index)
                        if not _locator_is_actionable(candidate):
                            continue
                        if _attempt_locator_click(
                            candidate,
                            timeout_ms=1000,
                            sensitive=sensitive,
                            action_name=action_name,
                        ):
                            return True
            return False

        def _submit_owned_form(
            input_loc,
            labels: list[str],
            ids: list[str],
            *,
            allow_unlabelled_submit: bool = True,
            allow_known_ids: bool = True,
            allow_enter: bool = True,
            sensitive: bool = False,
            action_name: str = "authentication action",
            pre_sensitive_action_guard: Optional[Callable[[object], None]] = None,
        ) -> bool:
            """Submit the form owning an input before trying page-level fallbacks."""
            try:
                form = _first_visible(
                    input_loc.locator("xpath=ancestor::form[1]"),
                    limit=1,
                )
            except Exception:
                form = None
            if form is not None:
                for label in labels:
                    pattern = _exact_action_pattern(label)
                    try:
                        buttons = form.get_by_role("button", name=pattern)
                        for index in range(min(buttons.count(), 20)):
                            button = buttons.nth(index)
                            if not _locator_is_actionable(button):
                                continue
                            if pre_sensitive_action_guard is not None:
                                pre_sensitive_action_guard(button)
                            if _attempt_locator_click(
                                button,
                                sensitive=sensitive,
                                action_name=action_name,
                            ):
                                if debug:
                                    print("    [DEBUG] Submitted owning form via exact button")
                                return True
                    except _SensitiveActionUncertainError:
                        raise
                    except Exception:
                        continue
                if allow_unlabelled_submit:
                    try:
                        submits = form.locator(
                            "input[type='submit'], button[type='submit']"
                        )
                        for index in range(min(submits.count(), 20)):
                            submit = submits.nth(index)
                            if not _locator_is_actionable(submit):
                                continue
                            if pre_sensitive_action_guard is not None:
                                pre_sensitive_action_guard(submit)
                            if _attempt_locator_click(
                                submit,
                                sensitive=sensitive,
                                action_name=action_name,
                            ):
                                if debug:
                                    print(
                                        "    [DEBUG] Submitted owning form via submit control"
                                    )
                                return True
                    except _SensitiveActionUncertainError:
                        raise
                    except Exception:
                        pass
            if (
                allow_known_ids
                and pre_sensitive_action_guard is None
                and _click_known_ids(
                ids,
                sensitive=sensitive,
                action_name=action_name,
                )
            ):
                if debug:
                    print("    [DEBUG] Submitted form via known control id")
                return True
            if not allow_enter:
                return False
            if pre_sensitive_action_guard is not None:
                pre_sensitive_action_guard(input_loc)
            if _attempt_locator_press(
                input_loc,
                "Enter",
                sensitive=sensitive,
                action_name=action_name,
            ):
                if debug:
                    print("    [DEBUG] Submitted form via Enter")
                return True
            return False

        def _submit_otp(otp_loc) -> bool:
            """Submit only the form that owns the OTP input."""
            if sensitive_action_ledger.dispatched("totp"):
                return False
            return _submit_owned_form(
                otp_loc,
                [
                    "Verify",
                    "Überprüfen",
                    "Bestätigen",
                    "Continue",
                    "Weiter",
                    "Next",
                    "Submit",
                ],
                [
                "idSubmit_SAOTCC_Continue",
                "idSIButton9",
                "submitButton",
                ],
                sensitive=True,
                action_name="Microsoft verification-code submission",
            )

        def _submit_password(
            password_loc,
            authorization: Optional[
                _GpClientPasswordStageAuthorization
            ] = None,
        ) -> bool:
            """Submit the password form without matching alternate-login links."""
            if (
                sensitive_action_ledger.dispatched("password")
                or password_action_attempts > 0
            ):
                return False
            labels = [
                "Anmelden",
                "Sign in",
                "Connexion",
                "Accedi",
                "Continue",
                "Next",
            ]
            if authorization is not None:
                submitted = _submit_owned_form(
                    password_loc,
                    labels,
                    [],
                    allow_unlabelled_submit=True,
                    allow_known_ids=False,
                    allow_enter=True,
                    sensitive=True,
                    action_name="client-side password submission",
                    pre_sensitive_action_guard=lambda action_loc: (
                        _validate_gp_client_password_stage(
                            password_loc,
                            authorization,
                            require_empty=False,
                            submitter_loc=action_loc,
                        )
                    ),
                )
                if not submitted:
                    raise _SensitiveActionUncertainError(
                        "The authorized client-side password form has no exact "
                        "owning submit control; refusing a page-level fallback"
                    )
                return True
            if _password_submission_uses_strict_owning_form(protocol):
                # FHNW's branded Microsoft page attaches credential-discovery
                # behavior to the real submit control.  Native requestSubmit()
                # bypasses that handler and can reload the unchanged password
                # form.  Click only the owning form's control, with one Enter
                # fallback when the page genuinely has no actionable submitter.
                submitted = _submit_owned_form(
                    password_loc,
                    labels,
                    ["idSIButton9", "submitButton"],
                    allow_unlabelled_submit=True,
                    allow_known_ids=True,
                    allow_enter=True,
                    sensitive=True,
                    action_name="password submission",
                )
                if submitted and debug:
                    print(
                        "    [DEBUG] Submitted AnyConnect password through "
                        "its owning form control"
                    )
                return submitted
            if _submit_owned_form(
                password_loc,
                labels,
                [],
                allow_unlabelled_submit=False,
                allow_known_ids=False,
                allow_enter=False,
                sensitive=True,
                action_name="password submission",
            ):
                if debug:
                    print("    [DEBUG] Submitted password via exact owning-form control")
                return True
            if _click_action(
                labels,
                sensitive=True,
                action_name="password submission",
            ):
                if debug:
                    print("    [DEBUG] Submitted password via exact page control")
                return True
            return _submit_owned_form(
                password_loc,
                labels,
                ["idSIButton9", "submitButton"],
                sensitive=True,
                action_name="password submission",
            )

        def _page_has_text(texts: list[str]) -> bool:
            snapshot = _current_rendered_ui_snapshot()
            if _snapshot_has_text(snapshot, texts):
                return True
            # Preserve the legacy Playwright text semantics only for frames
            # whose single-round-trip snapshot could not be captured.
            for frame in snapshot.failed_frames:
                for t in texts:
                    try:
                        if _first_visible(frame.get_by_text(t, exact=False)) is not None:
                            return True
                    except Exception:
                        continue
                try:
                    body_text = frame.evaluate(
                        "() => document.body && document.body.innerText "
                        "? document.body.innerText : ''"
                    )
                    body_normalized = _normalize_rendered_ui_text(body_text)
                    if any(
                        _normalize_rendered_ui_text(text) in body_normalized
                        for text in texts
                    ):
                        return True
                except Exception:
                    pass
            return False

        def _find_password_input():
            return (
                _find_usable_input_by_ids([
                    "passwordInput",
                    "password",
                    "i0118",
                    "passwd",
                    "Passwd",
                ])
                or _find_usable_input_by_labels([
                    "Kennwort",
                    "Passwort",
                    "Password",
                    "Mot de passe",
                ])
                or _find_best_input("password")
            )

        def _form_control_identity(control_loc) -> Optional[str]:
            """Return a document-scoped identity that changes with the DOM node."""
            try:
                return str(control_loc.evaluate(
                    """element => {
                        if (!globalThis.__msSsoDocumentIdentity) {
                            globalThis.__msSsoDocumentIdentity =
                                (globalThis.crypto && crypto.randomUUID)
                                    ? crypto.randomUUID()
                                    : `${Date.now()}-${Math.random()}`;
                        }
                        if (!globalThis.__msSsoElementIdentities) {
                            globalThis.__msSsoElementIdentities = new WeakMap();
                            globalThis.__msSsoNextElementIdentity = 1;
                        }
                        if (!globalThis.__msSsoElementIdentities.has(element)) {
                            globalThis.__msSsoElementIdentities.set(
                                element,
                                globalThis.__msSsoNextElementIdentity++,
                            );
                        }
                        return `${globalThis.__msSsoDocumentIdentity}:` +
                            globalThis.__msSsoElementIdentities.get(element);
                    }"""
                ))
            except Exception:
                try:
                    fallback = [
                        control_loc.get_attribute("id") or "",
                        control_loc.get_attribute("name") or "",
                        control_loc.get_attribute("type") or "",
                        control_loc.get_attribute("autocomplete") or "",
                    ]
                    return "fallback:" + hashlib.sha256(
                        json.dumps(fallback, separators=(",", ":")).encode("utf-8")
                    ).hexdigest()
                except Exception:
                    return None

        def _password_control_security_evidence(
            control_loc,
        ) -> _PasswordControlSecurityEvidence:
            """Read input, owning form, origin, and error state in one round trip."""
            if control_loc is None:
                return _PasswordControlSecurityEvidence()
            try:
                evidence = control_loc.evaluate(
                    """(element, credentialErrorMarkers) => {
                        if (!globalThis.__msSsoDocumentIdentity) {
                            globalThis.__msSsoDocumentIdentity =
                                (globalThis.crypto && crypto.randomUUID)
                                    ? crypto.randomUUID()
                                    : `${Date.now()}-${Math.random()}`;
                        }
                        if (!globalThis.__msSsoElementIdentities) {
                            globalThis.__msSsoElementIdentities = new WeakMap();
                            globalThis.__msSsoNextElementIdentity = 1;
                        }
                        const identityFor = candidate => {
                            if (!candidate) return null;
                            if (!globalThis.__msSsoElementIdentities.has(candidate)) {
                                globalThis.__msSsoElementIdentities.set(
                                    candidate,
                                    globalThis.__msSsoNextElementIdentity++,
                                );
                            }
                            return `${globalThis.__msSsoDocumentIdentity}:` +
                                globalThis.__msSsoElementIdentities.get(candidate);
                        };
                        const visible = candidate => {
                            if (!candidate) return false;
                            const style = getComputedStyle(candidate);
                            const rect = candidate.getBoundingClientRect();
                            return style.display !== 'none' &&
                                style.visibility !== 'hidden' &&
                                rect.width > 0 && rect.height > 0;
                        };
                        const form = element.form || element.closest('form');
                        const valueKnown = typeof element.value === 'string';
                        const formSignature = form ? JSON.stringify([
                            form.action || '',
                            (form.method || 'get').toLowerCase(),
                            (form.enctype || '').toLowerCase(),
                            form.target || '',
                        ]) : null;
                        const formAction = form
                            ? new URL(form.action || location.href, location.href)
                            : null;
                        const invalidPassword =
                            element.getAttribute('aria-invalid') === 'true' ||
                            Array.from(document.querySelectorAll(
                                "input[type='password'][aria-invalid='true']"
                            )).some(visible);
                        const renderedError = [
                            '#passwordError',
                            '#usernameError',
                            '#passwordErrorText',
                        ].some(selector => Array.from(
                            document.querySelectorAll(selector)
                        ).some(candidate => visible(candidate) &&
                            Boolean((typeof candidate.innerText === 'string'
                                ? candidate.innerText : (candidate.textContent || '')).trim())
                        ));
                        const normalizedBody = (
                            document.body && document.body.innerText
                                ? document.body.innerText : ''
                        ).toLocaleLowerCase();
                        const markerError = credentialErrorMarkers.some(marker =>
                            normalizedBody.includes(String(marker).toLocaleLowerCase())
                        );
                        return {
                            identity: identityFor(element),
                            valueKnown,
                            valueEmpty: valueKnown && element.value.length === 0,
                            httpsOrigin:
                                location.protocol === 'https:' ? location.origin : null,
                            formIdentity: identityFor(form),
                            formSignature,
                            formActionOrigin:
                                formAction && formAction.protocol === 'https:'
                                    ? formAction.origin : null,
                            formMethod:
                                form ? (form.method || 'get').toLowerCase() : null,
                            credentialErrorVisible:
                                invalidPassword || renderedError || markerError,
                        };
                    }""",
                    list(MICROSOFT_CREDENTIAL_ERROR_MARKERS),
                )
            except Exception:
                return _PasswordControlSecurityEvidence()
            if not isinstance(evidence, dict):
                return _PasswordControlSecurityEvidence()

            def _optional_string(key: str) -> Optional[str]:
                value = evidence.get(key)
                return value if isinstance(value, str) and value else None

            return _PasswordControlSecurityEvidence(
                identity=_optional_string("identity"),
                value_known=bool(evidence.get("valueKnown")),
                value_empty=bool(evidence.get("valueEmpty")),
                https_origin=_optional_string("httpsOrigin"),
                form_identity=_optional_string("formIdentity"),
                form_signature=_optional_string("formSignature"),
                form_action_origin=_optional_string("formActionOrigin"),
                form_method=_optional_string("formMethod"),
                credential_error_visible=bool(
                    evidence.get("credentialErrorVisible")
                ),
            )

        def _top_page_https_origin() -> Optional[str]:
            try:
                origin = page.evaluate("location.origin")
            except Exception:
                return None
            if not isinstance(origin, str) or origin == "null":
                return None
            return _canonical_https_origin(origin)

        def _top_page_credential_error_visible() -> Optional[bool]:
            """Distinguish observed rejection from an unreadable browser page."""
            return _probe_top_page_credential_error(page)

        def _submitter_form_security_evidence(action_loc) -> tuple[
            Optional[str],
            Optional[str],
            Optional[str],
            Optional[str],
            Optional[str],
            Optional[str],
        ]:
            """Bind the selected submitter to the already-authorized form."""
            try:
                evidence = action_loc.evaluate(
                    """element => {
                        if (!globalThis.__msSsoDocumentIdentity ||
                            !globalThis.__msSsoElementIdentities) return null;
                        const identityFor = candidate => {
                            if (!candidate) return null;
                            if (!globalThis.__msSsoElementIdentities.has(candidate)) {
                                globalThis.__msSsoElementIdentities.set(
                                    candidate,
                                    globalThis.__msSsoNextElementIdentity++,
                                );
                            }
                            return `${globalThis.__msSsoDocumentIdentity}:` +
                                globalThis.__msSsoElementIdentities.get(candidate);
                        };
                        const form = element.form || element.closest('form');
                        if (!form) return null;
                        const signature = JSON.stringify([
                            form.action || '',
                            (form.method || 'get').toLowerCase(),
                            (form.enctype || '').toLowerCase(),
                            form.target || '',
                        ]);
                        const effectiveAction = element.hasAttribute('formaction')
                            ? element.formAction : (form.action || location.href);
                        const effectiveMethod = (element.hasAttribute('formmethod')
                            ? element.formMethod : (form.method || 'get')
                        ).toLowerCase();
                        const effectiveSignature = JSON.stringify([
                            effectiveAction,
                            effectiveMethod,
                            (element.hasAttribute('formenctype')
                                ? element.formEnctype : (form.enctype || '')
                            ).toLowerCase(),
                            element.hasAttribute('formtarget')
                                ? element.formTarget : (form.target || ''),
                        ]);
                        return {
                            formIdentity: identityFor(form),
                            formSignature: signature,
                            effectiveSignature,
                            effectiveActionOrigin: new URL(
                                effectiveAction,
                                location.href
                            ).protocol === 'https:' ? new URL(
                                effectiveAction,
                                location.href
                            ).origin : null,
                            effectiveMethod,
                            httpsOrigin:
                                location.protocol === 'https:' ? location.origin : null,
                        };
                    }"""
                )
            except Exception:
                evidence = None
            if not isinstance(evidence, dict):
                return None, None, None, None, None, None

            def _optional_string(key: str) -> Optional[str]:
                value = evidence.get(key)
                return value if isinstance(value, str) and value else None

            return (
                _optional_string("formIdentity"),
                _optional_string("formSignature"),
                _optional_string("effectiveSignature"),
                _optional_string("httpsOrigin"),
                _optional_string("effectiveActionOrigin"),
                _optional_string("effectiveMethod"),
            )

        def _validate_gp_client_password_stage(
            control_loc,
            authorization: _GpClientPasswordStageAuthorization,
            *,
            require_empty: bool,
            submitter_loc=None,
        ) -> None:
            """Revalidate the exact promoted GP control after every UI read."""
            control = _password_control_security_evidence(control_loc)
            top_origin = _top_page_https_origin()
            submitter = (
                _submitter_form_security_evidence(submitter_loc)
                if submitter_loc is not None
                else None
            )
            top_error_visible = _top_page_credential_error_visible()
            if (
                sensitive_dispatch_evidence.main_frame_navigation_request_generation
                != authorization.main_navigation_generation
                or sensitive_dispatch_evidence.unsafe_write_request_generation
                != authorization.unsafe_write_generation
                or sensitive_dispatch_evidence.credential_taint_generation
                != authorization.taint_generation
                or sensitive_dispatch_evidence.main_document_generation
                != authorization.document_generation
                or control.identity != authorization.control_identity
                or control.https_origin != authorization.control_origin
                or top_origin != authorization.top_origin
                or not _gp_password_stage_origin_policy_valid(
                    authorization.route,
                    authorization.authorized_origin,
                    top_origin,
                    control.https_origin,
                    control.form_action_origin,
                    vpn_server_host,
                )
                or (
                    authorization.route == "federated"
                    and (
                        sensitive_dispatch_evidence.federated_safe_navigation_generation
                        != authorization.federated_navigation_generation
                        or sensitive_dispatch_evidence.federated_safe_navigation_origin
                        != authorization.authorized_origin
                    )
                )
                or control.form_identity != authorization.form_identity
                or control.form_signature != authorization.form_signature
                or control.form_action_origin
                != authorization.form_action_origin
                or control.form_method != authorization.form_method
                or authorization.form_method != "post"
                or not control.value_known
                or control.value_empty != require_empty
                or control.credential_error_visible
                or top_error_visible is not False
                or sensitive_dispatch_evidence.pending_main_frame_navigation_count
                > 0
                or (
                    submitter is not None
                    and (
                        submitter[0] != authorization.form_identity
                        or submitter[1] != authorization.form_signature
                        or submitter[2] != authorization.form_signature
                        or submitter[3] != authorization.control_origin
                        or submitter[4] != authorization.form_action_origin
                        or submitter[5] != "post"
                    )
                )
            ):
                raise _SensitiveActionUncertainError(
                    "The authorized password stage changed; "
                    "refusing to enter or submit credentials"
                )

        def _validate_anyconnect_retained_password_stage(
            control_loc,
            authorization: _AnyConnectRetainedPasswordStageAuthorization,
            *,
            submitter_loc,
        ) -> None:
            """Run the retained-form late guard immediately before its click."""
            _validate_gp_client_password_stage(
                control_loc,
                authorization.password_stage,
                require_empty=False,
                submitter_loc=submitter_loc,
            )
            if not _anyconnect_retained_password_guard_unchanged(
                expected_lookup_generation=authorization.lookup_generation,
                expected_lookup_pending_count=(
                    authorization.lookup_pending_count
                ),
                expected_safe_navigation_generation=(
                    authorization.safe_navigation_generation
                ),
                expected_unsafe_write_generation=(
                    authorization.unsafe_write_generation
                ),
                current_lookup_generation=(
                    microsoft_credential_lookup.generation
                ),
                current_lookup_pending_count=(
                    microsoft_credential_lookup.pending_count
                ),
                current_safe_navigation_generation=(
                    sensitive_dispatch_evidence.safe_navigation_generation
                ),
                current_unsafe_write_generation=(
                    sensitive_dispatch_evidence.unsafe_write_request_generation
                ),
            ):
                raise _SensitiveActionUncertainError(
                    "Microsoft discovery evidence changed before the retained "
                    "password submit; refusing the click"
                )

        def _credential_error_visible() -> bool:
            """Recognize credential rejection without logging localized text."""
            if _page_has_text(list(MICROSOFT_CREDENTIAL_ERROR_MARKERS)):
                return True
            snapshot = _current_rendered_ui_snapshot()
            if _snapshot_selector_visible(
                snapshot,
                MICROSOFT_CREDENTIAL_INVALID_SELECTORS,
            ):
                return True
            if _snapshot_selector_has_nonempty_text(
                snapshot,
                MICROSOFT_CREDENTIAL_ERROR_TEXT_SELECTORS,
            ):
                return True
            for frame in snapshot.failed_frames:
                for selector in MICROSOFT_CREDENTIAL_INVALID_SELECTORS:
                    try:
                        if _first_visible(frame.locator(selector)) is not None:
                            return True
                    except Exception:
                        continue
                for selector in MICROSOFT_CREDENTIAL_ERROR_TEXT_SELECTORS:
                    try:
                        matches = frame.locator(selector)
                        for index in range(min(matches.count(), 20)):
                            candidate = matches.nth(index)
                            if not candidate.is_visible():
                                continue
                            if _normalize_rendered_ui_text(
                                candidate.inner_text()
                            ):
                                return True
                    except Exception:
                        continue
            return False

        def _open_alternate_methods(
            *,
            include_primary_credential_picker: bool = False,
        ) -> bool:
            if _click_first_selector(MICROSOFT_ALTERNATE_MFA_SELECTORS):
                return True
            if (
                include_primary_credential_picker
                and _click_first_selector(
                    MICROSOFT_PRIMARY_CREDENTIAL_PICKER_SELECTORS
                )
            ):
                return True
            return _click_action(list(MICROSOFT_ALTERNATE_MFA_LABELS))

        def _exact_visible_text_available(labels: tuple[str, ...]) -> bool:
            """Recognize exact tenant controls even when their tile lacks ARIA roles."""
            for frame in page.frames:
                for label in labels:
                    try:
                        matches = frame.get_by_text(label, exact=True)
                        for index in range(min(matches.count(), 20)):
                            if matches.nth(index).is_visible():
                                return True
                    except Exception:
                        continue
            return False

        def _click_exact_visible_text(labels: tuple[str, ...]) -> bool:
            """Click an exact tenant label without generic text heuristics."""
            for frame in page.frames:
                for label in labels:
                    try:
                        matches = frame.get_by_text(label, exact=True)
                        count = min(matches.count(), 20)
                    except Exception:
                        continue
                    for index in range(count):
                        candidate = matches.nth(index)
                        try:
                            if not candidate.is_visible():
                                continue
                        except Exception:
                            continue
                        if _attempt_locator_click(candidate, timeout_ms=1500):
                            return True
            return False

        def _debug_visible_auth_controls(stage: str) -> None:
            """Log only redacted visible control metadata during explicit debugging."""
            if not debug:
                return
            controls = []
            for frame in page.frames:
                try:
                    matches = frame.locator(
                        "a, button, [role='button'], [role='link'], "
                        "input[type='button'], input[type='submit']"
                    )
                    count = min(matches.count(), 40)
                except Exception:
                    continue
                for index in range(count):
                    candidate = matches.nth(index)
                    try:
                        if not candidate.is_visible():
                            continue
                        metadata = candidate.evaluate(
                            """element => ({
                                tag: element.tagName.toLowerCase(),
                                id: element.id || '',
                                role: element.getAttribute('role') || '',
                                value: element.getAttribute('data-value') || '',
                                label: element.getAttribute('aria-label') ||
                                    element.innerText || element.value || ''
                            })"""
                        )
                    except Exception:
                        continue
                    label = _normalize_rendered_ui_text(metadata.get("label"))
                    label = re.sub(
                        r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}",
                        "<account>",
                        label,
                    )
                    label = re.sub(r"\b\d{2,}\b", "<number>", label)
                    controls.append(
                        "|".join(
                            (
                                str(metadata.get("tag") or ""),
                                str(metadata.get("id") or ""),
                                str(metadata.get("role") or ""),
                                str(metadata.get("value") or ""),
                                label[:160],
                            )
                        )
                    )
            print(
                f"    [DEBUG] Auth controls ({stage}): {controls}",
                flush=True,
            )

        def _open_number_match_totp_methods() -> bool:
            _debug_visible_auth_controls("before number-match alternate")
            if _click_exact_visible_text(
                MICROSOFT_NUMBER_MATCH_TOTP_ALTERNATE_LABELS
            ):
                return True
            return _open_alternate_methods()

        def _method_picker_context_visible() -> bool:
            """Require multiple known choices before trusting non-semantic tile text."""
            method_groups = (
                MICROSOFT_PASSKEY_MARKERS,
                MICROSOFT_TOTP_METHOD_LABELS,
                MICROSOFT_PUSH_METHOD_LABELS,
                MICROSOFT_PASSWORD_METHOD_LABELS,
            )
            return sum(
                1 for labels in method_groups if _page_has_text(list(labels))
            ) >= 2

        def _actionable_method_choice_visible() -> bool:
            """Recognize one concrete method control without trusting body text."""
            direct_selectors = (
                MICROSOFT_TOTP_DIRECT_SELECTORS
                + MICROSOFT_PUSH_DIRECT_SELECTORS
                + MICROSOFT_PASSWORD_DIRECT_SELECTORS
            )
            return bool(
                _actionable_selector_visible(direct_selectors)
                or _action_available(list(
                    MICROSOFT_TOTP_METHOD_LABELS
                    + MICROSOFT_PUSH_METHOD_LABELS
                    + MICROSOFT_PASSWORD_METHOD_LABELS
                ))
            )

        def _known_method_label_visible(labels: tuple[str, ...]) -> bool:
            """Recognize a vetted label only inside a verified method picker."""
            return (
                _method_picker_context_visible()
                and _page_has_text(list(labels))
            )

        def _click_known_method_label(
            labels: tuple[str, ...],
            *,
            sensitive: bool = False,
            action_name: str = "authentication action",
        ) -> bool:
            """Click only vetted credential/MFA labels as a non-semantic tile fallback."""
            if not _method_picker_context_visible():
                return False
            patterns = _action_patterns(labels)
            for frame in page.frames:
                for pattern in patterns:
                    if _click_actionable_text_control(
                        frame,
                        pattern,
                        sensitive=sensitive,
                        action_name=action_name,
                    ):
                        return True
            return False

        def _totp_method_visible() -> bool:
            if _actionable_selector_visible(MICROSOFT_TOTP_DIRECT_SELECTORS):
                return True
            if _exact_visible_text_available(MICROSOFT_EXACT_TOTP_METHOD_LABELS):
                return True
            return (
                _action_available(list(MICROSOFT_TOTP_METHOD_LABELS))
                or _known_method_label_visible(MICROSOFT_TOTP_METHOD_LABELS)
            )

        def _push_method_visible() -> bool:
            if _actionable_selector_visible(MICROSOFT_PUSH_DIRECT_SELECTORS):
                return True
            return (
                _action_available(list(MICROSOFT_PUSH_METHOD_LABELS))
                or _known_method_label_visible(MICROSOFT_PUSH_METHOD_LABELS)
            )

        def _password_method_visible() -> bool:
            if _actionable_selector_visible(MICROSOFT_PASSWORD_DIRECT_SELECTORS):
                return True
            return (
                _action_available(list(MICROSOFT_PASSWORD_METHOD_LABELS))
                or _known_method_label_visible(MICROSOFT_PASSWORD_METHOD_LABELS)
            )

        def _select_totp_method() -> bool:
            if _click_first_selector(MICROSOFT_TOTP_DIRECT_SELECTORS):
                return True
            if _click_exact_visible_text(MICROSOFT_EXACT_TOTP_METHOD_LABELS):
                return True
            return (
                _click_action(list(MICROSOFT_TOTP_METHOD_LABELS))
                or _click_known_method_label(MICROSOFT_TOTP_METHOD_LABELS)
            )

        def _select_push_method() -> bool:
            if sensitive_action_ledger.dispatched("push"):
                return False
            if _click_first_selector(
                MICROSOFT_PUSH_DIRECT_SELECTORS,
                sensitive=True,
                action_name="Microsoft Authenticator push selection",
            ):
                return True
            return (
                _click_action(
                    list(MICROSOFT_PUSH_METHOD_LABELS),
                    sensitive=True,
                    action_name="Microsoft Authenticator push selection",
                )
                or _click_known_method_label(
                    MICROSOFT_PUSH_METHOD_LABELS,
                    sensitive=True,
                    action_name="Microsoft Authenticator push selection",
                )
            )

        def _select_password_method() -> bool:
            # FHNW renders the primary password choice as an id-less role-button.
            # Prefer that visible picker tile over Microsoft's hidden fallback
            # link, which can remain mounted without changing the page.
            if _click_known_method_label(MICROSOFT_PASSWORD_METHOD_LABELS):
                return True
            if _click_exact_visible_text(MICROSOFT_PASSWORD_METHOD_LABELS):
                return True
            if _click_first_selector(MICROSOFT_PASSWORD_DIRECT_SELECTORS):
                return True
            return _click_action(list(MICROSOFT_PASSWORD_METHOD_LABELS))

        def _number_match_state() -> tuple[bool, Optional[str]]:
            snapshot = _current_rendered_ui_snapshot()
            marker_visible = _page_has_text(list(MICROSOFT_NUMBER_MATCH_MARKERS))
            selector_visible = _snapshot_selector_visible(
                snapshot,
                MICROSOFT_NUMBER_MATCH_SELECTORS,
            )
            candidates = set()
            for text in _snapshot_probe_texts(
                snapshot,
                MICROSOFT_NUMBER_MATCH_SELECTORS,
            ):
                candidates.update(_standalone_two_digit_numbers(text))
            for frame in snapshot.failed_frames:
                for selector in MICROSOFT_NUMBER_MATCH_SELECTORS:
                    try:
                        candidate = _first_visible(frame.locator(selector))
                        if candidate is None:
                            continue
                        selector_visible = True
                        candidates.update(_standalone_two_digit_numbers(
                            candidate.text_content(timeout=500)
                        ))
                    except Exception:
                        continue

            selector_contains_number = bool(selector_visible and candidates)
            authenticator_context_visible = _page_has_text(
                list(MICROSOFT_AUTHENTICATOR_PUSH_MARKERS)
            )
            if not _has_number_match_evidence(
                marker_visible,
                selector_contains_number,
                authenticator_context_visible,
            ):
                return False, None

            # Microsoft has changed the display selector across releases. On a
            # confirmed number-match page, a standalone two-digit line is the
            # generated approval number shown to the user.
            if marker_visible and not candidates:
                for frame_snapshot in snapshot.frames:
                    candidates.update(_standalone_two_digit_numbers(
                        frame_snapshot.get("renderedText")
                    ))
                for frame in snapshot.failed_frames:
                    try:
                        body_text = frame.evaluate(
                            "() => document.body && document.body.innerText "
                            "? document.body.innerText : ''"
                        )
                        candidates.update(_standalone_two_digit_numbers(body_text))
                    except Exception:
                        pass
            number = next(iter(candidates)) if len(candidates) == 1 else None
            return True, number

        def _leave_passkey_prompt(
            *,
            prefer_totp_fallback: bool = False,
        ) -> Optional[str]:
            if not _page_has_text(list(MICROSOFT_PASSKEY_MARKERS)):
                return None
            try:
                page.keyboard.press("Escape")
            except Exception:
                pass
            if prefer_totp_fallback:
                if _select_totp_method():
                    return "passkey-totp-method-selected"
                # FHNW's post-password picker contains passkey, Authenticator
                # push, and password. TOTP is only exposed after entering the
                # Authenticator route and opening its alternate methods.
                if _select_push_method():
                    return "passkey-authenticator-app-selected"
                if _click_action(list(MICROSOFT_PASSKEY_APP_FALLBACK_LABELS)):
                    return "passkey-authenticator-app-selected"
                if _open_alternate_methods():
                    return "passkey-mfa-alternate-methods-opened"
                return None
            if _select_password_method():
                return "passkey-password-fallback-selected"
            if _open_alternate_methods(include_primary_credential_picker=True):
                return "passkey-alternate-methods-opened"
            return None

        def _click_account_tile(username_value: str) -> bool:
            """Click only one unique tile containing the complete account identity."""
            if sensitive_action_ledger.dispatched("cached-account-selection"):
                return False
            pattern = re.compile(re.escape(username_value), re.IGNORECASE)

            def _tile_matches(tile) -> bool:
                try:
                    text_parts = [
                        tile.text_content(timeout=500) or "",
                        tile.get_attribute("aria-label") or "",
                    ]
                except Exception:
                    return False
                return _account_tile_matches_username(
                    " ".join(text_parts),
                    username_value,
                )

            def _actionable_matches(queries) -> list[object]:
                matches = []
                seen_identities = set()
                for query in queries:
                    try:
                        count = min(query.count(), 20)
                    except Exception:
                        continue
                    for index in range(count):
                        tile = query.nth(index)
                        if _locator_is_actionable(tile) and _tile_matches(tile):
                            identity = _form_control_identity(tile)
                            stable_identity = bool(
                                identity
                                and not identity.startswith("fallback:")
                            )
                            if stable_identity and identity in seen_identities:
                                continue
                            if stable_identity:
                                seen_identities.add(identity)
                            matches.append(tile)
                return matches

            tile_queries = []
            for frame in page.frames:
                for role in ("button", "link"):
                    try:
                        tile_queries.append(frame.get_by_role(role, name=pattern))
                    except Exception:
                        continue
                for selector in ("[data-test-id='tile']", "[role='listitem']"):
                    try:
                        tile_queries.append(
                            frame.locator(selector).filter(has_text=pattern)
                        )
                    except Exception:
                        continue
            tiles = _actionable_matches(tile_queries)
            if len(tiles) != 1:
                # Never guess between duplicate/current and stale account tiles.
                return False
            return _attempt_locator_click(
                tiles[0],
                sensitive=True,
                action_name="cached account selection",
            )

        def _auth_ui_ready() -> bool:
            selectors = [
                "input",
                "button",
                "input[type='submit']",
                "#idSIButton9",
                "#submitButton",
                "#i0116",
                "#i0118",
                "#userNameInput",
                "#passwordInput",
                "#idTxtBx_SAOTCC_OTC",
            ]
            for frame in page.frames:
                for sel in selectors:
                    try:
                        if _first_visible(frame.locator(sel)) is not None:
                            return True
                    except Exception:
                        continue
            return False

        def _auth_ui_fingerprint() -> str:
            """Hash relevant browser state so credentials never enter logs or paths."""
            return _current_rendered_ui_snapshot().fingerprint

        def _auth_ui_processing() -> bool:
            """Detect a visible semantic loading state without reading page secrets."""
            snapshot = _current_rendered_ui_snapshot()
            if _snapshot_selector_visible(
                snapshot,
                MICROSOFT_AUTH_UI_PROCESSING_SELECTORS,
            ):
                return True
            return _find_visible_in_frames(
                list(MICROSOFT_AUTH_UI_PROCESSING_SELECTORS),
                frames=snapshot.failed_frames,
            ) is not None

        def _usable_auth_page() -> bool:
            """Reject Chromium error UI while preserving a partially loaded IdP form."""
            try:
                if urllib.parse.urlparse(page.url).scheme not in {"http", "https"}:
                    return False
            except Exception:
                return False
            if _is_vpn_url(page.url):
                return True
            known_selectors = [
                "form input",
                "input[type='email']",
                "input[type='password']",
                "input[autocomplete='username']",
                "input[autocomplete='one-time-code']",
                "#idSIButton9",
                "#i0116",
                "#i0118",
                "#userNameInput",
                "#passwordInput",
                "#idTxtBx_SAOTCC_OTC",
                "[data-test-id='tile']",
            ]
            return _find_visible_in_frames(known_selectors) is not None

        def _wait_until_ready(timeout_seconds: float = 1.0) -> None:
            deadline = time.monotonic() + timeout_seconds
            while time.monotonic() < deadline:
                _raise_if_cancelled()
                if (
                    _is_vpn_url(page.url)
                    or saml_result.get("saml_response")
                    or saml_result.get("prelogin_cookie")
                    or saml_result.get("portal_userauthcookie")
                    or _auth_ui_ready()
                ):
                    return
                remaining = max(0.0, deadline - time.monotonic())
                ui_change_event.wait(timeout=min(0.05, remaining))
                ui_change_event.clear()

        def _interruptible_pause(seconds: float) -> None:
            deadline = time.monotonic() + max(0.0, seconds)
            while time.monotonic() < deadline:
                _raise_if_cancelled()
                remaining = deadline - time.monotonic()
                time.sleep(min(0.05, max(0.0, remaining)))

        def _is_adfs_page() -> bool:
            url = page.url.lower()
            if "adfs" in url and "/ls" in url:
                return True
            selectors = ("#userNameInput", "#passwordInput")
            snapshot = _current_rendered_ui_snapshot()
            if _snapshot_selector_visible(snapshot, selectors):
                return True
            return _find_visible_in_frames(
                list(selectors),
                frames=snapshot.failed_frames,
            ) is not None

        def _goto_with_retries(url: str, deadline: float) -> None:
            errors = []
            for attempt in range(2):
                _raise_if_cancelled()
                remaining_ms = _remaining_timeout_ms(deadline)
                if remaining_ms <= 0:
                    break
                try:
                    page.goto(
                        url,
                        timeout=min(20000, remaining_ms),
                        wait_until="domcontentloaded",
                    )
                    _wait_until_ready(0.5)
                    return
                except Exception as exc:
                    errors.append(exc)
                    if _auth_capture_complete() or _usable_auth_page():
                        return
                    error_text = str(exc)
                    transient = any(token in error_text for token in (
                        "Timeout",
                        "ERR_NETWORK_CHANGED",
                        "ERR_TIMED_OUT",
                        "ERR_CONNECTION_RESET",
                        "ERR_CONNECTION_CLOSED",
                    ))
                    if debug:
                        action = "retrying" if transient and attempt == 0 else "stopping"
                        print(f"    [DEBUG] Page.goto failed; {action} ({attempt + 1}/2)")
                    if not transient:
                        raise
                _wait_until_ready(0.2)
            raise errors[-1] if errors else Exception("Page.goto failed")

        timeout_seconds = _parse_saml_timeout(protocol)
        deadline = time.monotonic() + timeout_seconds

        try:
            _raise_if_cancelled()
            if protocol == "gp" and gp_saml_request:
                try:
                    start_url = base64.b64decode(gp_saml_request).decode("utf-8")
                    if not start_url.startswith("http"):
                        start_url = vpn_url
                except Exception:
                    start_url = vpn_url
            elif protocol == "anyconnect":
                start_url = f"https://{vpn_server_netloc}/+CSCOE+/saml/sp/login?tgname=DefaultWEBVPNGroup"
            else:
                start_url = vpn_url

            print("  [1/6] Opening SAML portal...")
            _goto_with_retries(start_url, deadline)
            _report_progress(f"portal-ready host={_page_host()}")

            if _prime_gp_microsoft_federation_render(
                page,
                protocol,
                _page_host(),
            ):
                _report_progress("gp-federation-render-primed")

            if debug:
                try:
                    _secure_screenshot("/tmp/vpn-step1-portal.png")
                    print("    [DEBUG] Screenshot: /tmp/vpn-step1-portal.png")
                except Exception:
                    print("    [DEBUG] Portal screenshot unavailable; continuing")

            _wait_until_ready(0.5)
            _raise_if_cancelled()
            if _is_vpn_url(page.url):
                all_cookies = context.cookies()
                session_cookies = {}
                for c in all_cookies:
                    if c.get("value") and _cookie_domain_matches(c.get("domain", "")):
                        session_cookies[c["name"]] = c["value"]

                has_session = (
                    _has_usable_auth_artifact(session_cookies)
                )
                if has_session:
                    print("  -> Already authenticated (SSO session valid)")
                    session_cookies = _merge_saml_artifacts(
                        session_cookies,
                        saml_result,
                        protocol,
                        gp_prelogin_cookie,
                        gp_gateway_ip,
                    )
                    _close_context()
                    return session_cookies

            filled_username = False
            filled_password = False
            sensitive_action_ledger = _SensitiveActionLedger()
            last_totp_counter = None
            totp_submission_attempts = 0
            adfs_submit_attempts = 0
            blank_login_reloads = 0
            last_progress_time = time.monotonic()
            last_mfa_switch_time = 0.0
            last_wait_report_time = 0.0
            otp_input_reported = False
            totp_disabled_for_attempt = False
            totp_error_before_submit = None
            last_number_match = None
            otp_alternate_attempts = 0
            method_selection_pending = None
            mfa_picker_pending_until = 0.0
            mfa_picker_settle_until = 0.0
            mfa_picker_open_attempts = 0
            mfa_picker_debug_reported = False
            mfa_method_pending_until = 0.0
            number_match_switch_deadline = 0.0
            number_match_detected_reported = False
            primary_credential_picker_pending_until = 0.0
            passkey_password_pending_until = 0.0
            password_bridge_pending_until = 0.0
            password_bridge_attempts = 0
            push_delivery_retry_attempts = 0
            primary_picker_password_attempts = 0
            gp_initial_password_observation_started_at = None
            gp_initial_password_observation_pending = False
            gp_password_navigation_pending_started_at = None
            password_input_ready_since = 0.0
            password_input_identity = None
            password_action_attempts = 0
            password_action_pending_since = 0.0
            password_action_dispatch_generation = 0
            password_action_safe_navigation_generation = 0
            password_action_federated_safe_navigation_generation = 0
            password_action_credential_taint_generation = 0
            password_action_document_generation = 0
            password_action_main_navigation_request_generation = 0
            password_action_write_request_generation = 0
            password_action_unsafe_write_request_generation = 0
            password_action_outbound_request_generation = 0
            password_action_navigation_pending_count = 0
            password_action_control_identity = None
            password_action_control_origin = None
            password_action_top_origin = None
            password_action_form_action_origin = None
            password_action_form_signature = None
            password_action_form_method = None
            password_action_ui_fingerprint = None
            last_password_transition_evidence = None
            password_discovery_completed = False
            password_discovery_authorized_taint_generation = None
            password_discovery_authorized_client_stage = None
            password_control_submitted = False
            submitted_password_control_identity = None
            otp_control_submitted = False
            submitted_otp_control_identity = None
            password_submission_lookup_generation = 0
            password_lookup_seen_for_submission = False
            password_submission_classify_until = 0.0
            ui_recovery_attempts = 0
            last_ui_fingerprint = _auth_ui_fingerprint()
            last_substantive_progress_time = time.monotonic()
            persistent_pre_sensitive_hard_deadline = (
                last_substantive_progress_time
                + SAML_PERSISTENT_PROFILE_PRE_SENSITIVE_MAX_SECONDS
            )
            post_submit_grace_until = 0.0
            processing_extensions_used = 0
            form_submission_fingerprint = None
            form_submission_kind = None
            form_submission_hard_deadline = 0.0
            sensitive_submission_started = False
            credential_inspection_deadline = None

            def _recover_stale_browser_ui(
                now: float,
                *,
                force: bool = False,
            ) -> bool:
                """Re-enter the SAML flow once, then surface a bounded stall."""
                nonlocal filled_username
                nonlocal filled_password
                nonlocal adfs_submit_attempts
                nonlocal last_progress_time
                nonlocal last_mfa_switch_time
                nonlocal otp_input_reported
                nonlocal otp_alternate_attempts
                nonlocal method_selection_pending
                nonlocal mfa_picker_pending_until
                nonlocal mfa_picker_settle_until
                nonlocal mfa_picker_open_attempts
                nonlocal mfa_picker_debug_reported
                nonlocal mfa_method_pending_until
                nonlocal number_match_switch_deadline
                nonlocal number_match_detected_reported
                nonlocal primary_credential_picker_pending_until
                nonlocal passkey_password_pending_until
                nonlocal password_bridge_pending_until
                nonlocal push_delivery_retry_attempts
                nonlocal primary_picker_password_attempts
                nonlocal gp_initial_password_observation_started_at
                nonlocal gp_initial_password_observation_pending
                nonlocal gp_password_navigation_pending_started_at
                nonlocal password_input_ready_since
                nonlocal password_input_identity
                nonlocal password_control_submitted
                nonlocal submitted_password_control_identity
                nonlocal otp_control_submitted
                nonlocal submitted_otp_control_identity
                nonlocal password_submission_lookup_generation
                nonlocal password_lookup_seen_for_submission
                nonlocal password_submission_classify_until
                nonlocal password_action_safe_navigation_generation
                nonlocal password_action_federated_safe_navigation_generation
                nonlocal password_action_credential_taint_generation
                nonlocal password_action_document_generation
                nonlocal password_action_main_navigation_request_generation
                nonlocal password_action_write_request_generation
                nonlocal password_action_unsafe_write_request_generation
                nonlocal password_action_outbound_request_generation
                nonlocal password_action_navigation_pending_count
                nonlocal password_action_control_origin
                nonlocal password_action_top_origin
                nonlocal password_action_form_action_origin
                nonlocal password_action_form_signature
                nonlocal password_action_form_method
                nonlocal password_discovery_authorized_taint_generation
                nonlocal password_discovery_authorized_client_stage
                nonlocal last_number_match
                nonlocal ui_recovery_attempts
                nonlocal last_ui_fingerprint
                nonlocal last_substantive_progress_time
                nonlocal post_submit_grace_until
                nonlocal processing_extensions_used
                nonlocal form_submission_fingerprint
                nonlocal form_submission_kind
                nonlocal form_submission_hard_deadline

                if force:
                    recovery_action = (
                        "recover"
                        if ui_recovery_attempts < SAML_UI_MAX_RECOVERIES
                        else "fail"
                    )
                else:
                    recovery_action = _stale_ui_recovery_action(
                        last_substantive_progress_time,
                        now,
                        ui_recovery_attempts,
                        grace_until=post_submit_grace_until,
                    )
                if recovery_action == "wait":
                    return False
                if sensitive_submission_started:
                    _raise_profile_stall(
                        "Microsoft authentication UI did not make substantive progress",
                    )
                if (
                    protocol == "anyconnect"
                    and not force_ephemeral_browser_session
                ):
                    _raise_profile_stall(
                        "Cached SAML browser profile did not make substantive progress"
                    )
                if recovery_action == "fail":
                    _raise_profile_stall(
                        "SAML login UI did not make substantive progress after recovery",
                    )

                ui_recovery_attempts += 1
                filled_username = False
                filled_password = False
                adfs_submit_attempts = 0
                last_mfa_switch_time = 0.0
                otp_input_reported = False
                otp_alternate_attempts = 0
                method_selection_pending = None
                mfa_picker_pending_until = 0.0
                mfa_picker_settle_until = 0.0
                mfa_picker_open_attempts = 0
                mfa_picker_debug_reported = False
                mfa_method_pending_until = 0.0
                number_match_switch_deadline = 0.0
                number_match_detected_reported = False
                primary_credential_picker_pending_until = 0.0
                passkey_password_pending_until = 0.0
                password_bridge_pending_until = 0.0
                push_delivery_retry_attempts = 0
                primary_picker_password_attempts = 0
                gp_initial_password_observation_started_at = None
                gp_initial_password_observation_pending = False
                gp_password_navigation_pending_started_at = None
                password_input_ready_since = 0.0
                password_input_identity = None
                password_control_submitted = False
                submitted_password_control_identity = None
                otp_control_submitted = False
                submitted_otp_control_identity = None
                password_submission_lookup_generation = 0
                password_lookup_seen_for_submission = False
                password_submission_classify_until = 0.0
                password_action_safe_navigation_generation = 0
                password_action_federated_safe_navigation_generation = 0
                password_action_credential_taint_generation = 0
                password_action_document_generation = 0
                password_action_main_navigation_request_generation = 0
                password_action_write_request_generation = 0
                password_action_unsafe_write_request_generation = 0
                password_action_outbound_request_generation = 0
                password_action_navigation_pending_count = 0
                password_action_control_origin = None
                password_action_top_origin = None
                password_action_form_action_origin = None
                password_action_form_signature = None
                password_action_form_method = None
                password_discovery_authorized_taint_generation = None
                password_discovery_authorized_client_stage = None
                post_submit_grace_until = 0.0
                processing_extensions_used = 0
                form_submission_fingerprint = None
                form_submission_kind = None
                form_submission_hard_deadline = 0.0
                microsoft_credential_lookup.reset()
                if last_number_match is not None:
                    _close_number_match_notification()
                    last_number_match = None

                _report_progress("saml-ui-recovery")
                if debug:
                    print(
                        "    [DEBUG] SAML login UI stalled; re-entering the start flow"
                    )
                try:
                    _goto_with_retries(start_url, deadline)
                except Exception as exc:
                    raise SamlUiStalledError(
                        "SAML login UI recovery could not re-enter the start flow"
                    ) from exc
                if _prime_gp_microsoft_federation_render(
                    page,
                    protocol,
                    _page_host(),
                ):
                    _report_progress("gp-federation-render-primed")
                _refresh_rendered_ui_snapshot()
                last_ui_fingerprint = _auth_ui_fingerprint()
                last_substantive_progress_time = time.monotonic()
                last_progress_time = last_substantive_progress_time
                return True

            def _arm_submission_wait(
                kind: str,
                submitted_at: float,
                *,
                submitted_password_identity: Optional[str] = None,
                submitted_otp_identity: Optional[str] = None,
            ) -> None:
                """Latch one form submit so it is polled but never replayed."""
                nonlocal last_progress_time
                nonlocal last_substantive_progress_time
                nonlocal post_submit_grace_until
                nonlocal processing_extensions_used
                nonlocal form_submission_fingerprint
                nonlocal form_submission_kind
                nonlocal form_submission_hard_deadline
                nonlocal sensitive_submission_started
                nonlocal password_control_submitted
                nonlocal submitted_password_control_identity
                nonlocal otp_control_submitted
                nonlocal submitted_otp_control_identity

                last_progress_time = submitted_at
                last_substantive_progress_time = submitted_at
                gp_discovery_probe = bool(
                    str(protocol or "").casefold() == "gp"
                    and kind == "password-unknown"
                    and not password_discovery_completed
                )
                form_submission_hard_deadline = (
                    deadline
                    if gp_discovery_probe
                    else _submission_hard_deadline(
                        submitted_at,
                        deadline,
                    )
                )
                # GP's first password-shaped page can make a credential-free
                # GET transition at any point before the outer auth deadline.
                # Poll it continuously and promote immediately on safe evidence.
                post_submit_grace_until = (
                    form_submission_hard_deadline
                    if gp_discovery_probe
                    else min(
                        submitted_at + SAML_UI_POST_SUBMIT_GRACE_SECONDS,
                        form_submission_hard_deadline,
                    )
                )
                processing_extensions_used = 0
                form_submission_kind = kind
                if (
                    _is_sensitive_submission_kind(kind)
                    and kind != "password-unknown"
                ):
                    sensitive_action_ledger.record(kind)
                sensitive_submission_started = bool(
                    sensitive_submission_started
                    or _is_sensitive_submission_kind(kind)
                )
                if kind in {"password", "password-unknown"}:
                    password_control_submitted = True
                    submitted_password_control_identity = (
                        submitted_password_identity
                    )
                elif kind == "totp":
                    otp_control_submitted = True
                    submitted_otp_control_identity = submitted_otp_identity
                # Preserve the pre-action baseline. Capturing after the click
                # can miss a transition that renders inside the 250 ms pause.
                form_submission_fingerprint = last_ui_fingerprint

            while time.monotonic() < deadline:
                _raise_if_cancelled()
                if _auth_capture_complete():
                    break
                if _is_vpn_url(page.url) and protocol != "anyconnect":
                    break

                _refresh_rendered_ui_snapshot()
                progressed = False
                form_submitted = False
                submitted_form_kind = None
                password_entered_this_loop = False
                password_control_identity_this_loop = None
                password_evidence_baseline_this_loop = None
                password_lookup_generation_before_this_loop = None
                otp_control_identity_this_loop = None
                adfs_mode = _is_adfs_page()

                totp_available = bool(totp_secret and auto_totp)
                otp_loc = _find_otp_input()
                usable_otp_identity = (
                    _form_control_identity(otp_loc)
                    if otp_loc is not None
                    else None
                )
                otp_control_identity_this_loop = usable_otp_identity
                usable_otp_control_progress = bool(
                    otp_loc is not None
                    and _otp_control_is_progress(
                        usable_otp_identity,
                        submitted_otp_control_identity,
                        otp_control_submitted,
                    )
                )
                retained_submitted_otp = bool(
                    otp_loc is not None
                    and otp_control_submitted
                    and not usable_otp_control_progress
                )
                # Microsoft's MFA panels can retain the previous controls for
                # several seconds while the next method loads. Do not click or
                # reinterpret that stale panel during the transition.
                now = time.monotonic()
                current_ui_fingerprint = _auth_ui_fingerprint()
                fingerprint_changed = current_ui_fingerprint != last_ui_fingerprint
                if fingerprint_changed:
                    last_ui_fingerprint = current_ui_fingerprint
                    last_substantive_progress_time = now
                    if form_submission_fingerprint is None:
                        processing_extensions_used = 0
                processing_visible = _auth_ui_processing()
                previous_grace_until = post_submit_grace_until
                post_submit_grace_until, processing_extensions_used = (
                    _extend_processing_grace(
                        now,
                        post_submit_grace_until,
                        _should_extend_submission_grace(
                            processing_visible,
                            form_submission_kind,
                        ),
                        processing_extensions_used,
                        hard_deadline=(
                            form_submission_hard_deadline or None
                        ),
                    )
                )
                if post_submit_grace_until > previous_grace_until:
                    _report_progress(
                        "saml-ui-processing-extended"
                        if processing_visible
                        else "saml-ui-submit-wait-extended"
                    )
                if form_submission_fingerprint is None:
                    post_submit_grace_until = 0.0
                    processing_extensions_used = 0
                can_switch_mfa = (
                    now - last_mfa_switch_time
                    >= MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS
                )
                actual_number_match_detected, number_match = _number_match_state()
                authenticator_push_detected = (
                    actual_number_match_detected
                    or _page_has_text(list(MICROSOFT_AUTHENTICATOR_PUSH_MARKERS))
                )
                number_match_detected = authenticator_push_detected
                sensitive_submission_started = (
                    _latch_sensitive_authenticator_challenge(
                        sensitive_submission_started,
                        number_match_detected,
                    )
                )
                if number_match_detected:
                    # The IdP has already issued a phone challenge, even when a
                    # cached session reached it without an explicit method click.
                    sensitive_action_ledger.record("push")
                usable_password_input = _find_password_input()
                usable_password_identity = (
                    _form_control_identity(usable_password_input)
                    if usable_password_input is not None
                    else None
                )
                usable_password_control_progress = bool(
                    usable_password_input is not None
                    and _password_control_is_progress(
                        usable_password_identity,
                        submitted_password_control_identity,
                        password_control_submitted,
                    )
                )
                usable_method_choice_visible = _actionable_method_choice_visible()
                alternate_method_control_visible = bool(
                    _actionable_selector_visible(
                        MICROSOFT_ALTERNATE_MFA_SELECTORS
                    )
                    or _action_available(list(MICROSOFT_ALTERNATE_MFA_LABELS))
                )
                passkey_prompt_visible = _page_has_text(
                    list(MICROSOFT_PASSKEY_MARKERS)
                )
                usable_passkey_fallback_visible = bool(
                    alternate_method_control_visible and passkey_prompt_visible
                )
                primary_method_picker_visible = _page_has_text(
                    list(MICROSOFT_PRIMARY_METHOD_PICKER_MARKERS)
                )
                credential_lookup_waiting, credential_lookup_expired = (
                    microsoft_credential_lookup.wait_state(
                        now,
                        usable_ui_visible=bool(
                            usable_otp_control_progress
                            or usable_password_control_progress
                            or number_match_detected
                            or usable_method_choice_visible
                            or usable_passkey_fallback_visible
                        ),
                        processing_visible=processing_visible,
                    )
                )
                password_discovery_classification_deferred = (
                    _password_discovery_classification_deferred(
                        protocol,
                        password_discovery_completed,
                        form_submission_kind,
                        now,
                        password_submission_classify_until,
                    )
                )
                credential_error_visible = _credential_error_visible()
                password_security = _password_control_security_evidence(
                    usable_password_input
                )
                current_top_origin = _top_page_https_origin()
                top_credential_error_visible = (
                    _top_page_credential_error_visible()
                    if password_action_attempts > 0
                    else False
                )
                if top_credential_error_visible is None:
                    # The callback can complete during the failing browser
                    # read. Accepted auth artifacts take precedence over UI
                    # inspection timeouts, including at their deadline.
                    if _auth_capture_complete():
                        break
                    # A navigation can invalidate evaluate() without the IdP
                    # rejecting anything. Keep the submitted action latched:
                    # no replacement authorization, fills, clicks, or reloads
                    # may run until a fresh inspection succeeds.
                    inspection_now = time.monotonic()
                    if credential_inspection_deadline is None:
                        credential_inspection_deadline = min(
                            deadline,
                            inspection_now + SAML_UI_STALL_WINDOW_SECONDS,
                            form_submission_hard_deadline
                            if form_submission_hard_deadline > 0.0 else deadline,
                        )
                        _report_progress("saml-ui-inspection-unavailable")
                    if inspection_now >= credential_inspection_deadline:
                        _raise_profile_stall(
                            "Could not inspect the sign-in page after submission; "
                            "the authentication outcome is uncertain",
                        )
                    _interruptible_pause(min(
                        0.1, credential_inspection_deadline - inspection_now,
                    ))
                    continue
                credential_inspection_deadline = None
                current_page_is_microsoft = bool(
                    current_top_origin == "https://login.microsoftonline.com"
                )
                password_origin_continuity = bool(
                    password_action_control_origin
                    and password_action_top_origin
                    and password_security.https_origin
                    == password_action_control_origin
                    and current_top_origin == password_action_top_origin
                )
                password_has_strong_owning_form = bool(
                    password_security.form_identity
                    and password_security.form_signature
                    and password_security.form_method == "post"
                    and password_security.form_action_origin
                    in {
                        password_security.https_origin,
                        current_top_origin,
                    }
                )
                password_has_strong_input = bool(
                    password_security.identity
                    and not password_security.identity.startswith("fallback:")
                )
                gp_microsoft_password_stage_authorized = bool(
                    str(protocol or "").casefold() == "gp"
                    and password_has_strong_owning_form
                    and password_has_strong_input
                    and _gp_password_stage_origin_policy_valid(
                        "client",
                        "https://login.microsoftonline.com",
                        current_top_origin,
                        password_security.https_origin,
                        password_security.form_action_origin,
                        vpn_server_host,
                    )
                )
                credential_error_visible = bool(
                    credential_error_visible
                    or password_security.credential_error_visible
                    or top_credential_error_visible is True
                )
                same_password_control = bool(
                    usable_password_input is not None
                    and usable_password_identity
                    == password_action_control_identity
                )
                same_password_ui = bool(
                    current_ui_fingerprint
                    == password_action_ui_fingerprint
                )
                password_value_retained = bool(
                    usable_password_input is not None
                    and password_security.value_known
                    and not password_security.value_empty
                )
                same_filled_password_form = bool(
                    same_password_control
                    and same_password_ui
                    and password_value_retained
                )
                # Freeze transport generations only after every Playwright UI
                # read above. No browser call may occur before the client-stage
                # predicate is consumed or the next late guard runs.
                password_lookup_generation_snapshot = (
                    microsoft_credential_lookup.generation
                )
                password_lookup_pending_count_snapshot = (
                    microsoft_credential_lookup.pending_count
                )
                password_transition_snapshot = (
                    sensitive_dispatch_evidence.generation,
                    sensitive_dispatch_evidence.safe_navigation_generation,
                    sensitive_dispatch_evidence.credential_taint_generation,
                    sensitive_dispatch_evidence.main_document_generation,
                    sensitive_dispatch_evidence.main_frame_navigation_request_generation,
                    sensitive_dispatch_evidence.write_request_generation,
                    sensitive_dispatch_evidence.outbound_request_generation,
                    sensitive_dispatch_evidence.pending_main_frame_navigation_count,
                    sensitive_dispatch_evidence.safe_navigation_request_generation,
                    sensitive_dispatch_evidence.federated_safe_navigation_generation,
                    sensitive_dispatch_evidence.federated_safe_navigation_request_generation,
                    sensitive_dispatch_evidence.unsafe_write_request_generation,
                )
                password_lookup_observed = bool(
                    form_submission_kind == "password-unknown"
                    and (
                        password_lookup_generation_snapshot
                        > password_submission_lookup_generation
                        or password_lookup_pending_count_snapshot > 0
                    )
                )
                if password_lookup_observed:
                    password_lookup_seen_for_submission = True
                password_lookup_transition_pending = bool(
                    _password_discovery_supported(protocol)
                    and not password_discovery_completed
                    and password_lookup_observed
                )
                password_federated_navigation_origin = (
                    sensitive_dispatch_evidence.federated_safe_navigation_origin
                )
                password_dispatch_observed = bool(
                    password_action_attempts > 0
                    and password_transition_snapshot[0]
                    > password_action_dispatch_generation
                )
                password_safe_navigation_observed = bool(
                    password_action_attempts > 0
                    and password_transition_snapshot[1]
                    > password_action_safe_navigation_generation
                )
                password_credential_tainted = bool(
                    password_action_attempts > 0
                    and password_transition_snapshot[2]
                    > password_action_credential_taint_generation
                )
                password_document_replaced = bool(
                    password_action_attempts > 0
                    and password_transition_snapshot[3]
                    > password_action_document_generation
                )
                password_main_navigation_request_observed = bool(
                    password_action_attempts > 0
                    and password_transition_snapshot[4]
                    > password_action_main_navigation_request_generation
                )
                password_write_request_observed = bool(
                    password_action_attempts > 0
                    and password_transition_snapshot[5]
                    > password_action_write_request_generation
                )
                password_unsafe_write_request_observed = bool(
                    password_action_attempts > 0
                    and password_transition_snapshot[11]
                    > password_action_unsafe_write_request_generation
                )
                password_navigation_pending_at_baseline = bool(
                    password_action_attempts > 0
                    and password_action_navigation_pending_count > 0
                )
                password_federated_navigation_completed = bool(
                    password_action_attempts > 0
                    and password_transition_snapshot[9]
                    > password_action_federated_safe_navigation_generation
                )
                gp_password_navigation_replacement = (
                    _gp_password_navigation_replacement_ready(
                        protocol,
                        password_discovery_completed,
                        password_dispatch_observed,
                        password_safe_navigation_observed,
                        password_credential_tainted,
                        password_document_replaced,
                        current_page_is_microsoft,
                        usable_password_identity,
                        submitted_password_control_identity,
                        password_security.value_empty,
                        credential_error_visible,
                    )
                )
                gp_password_client_replacement = (
                    _gp_password_client_replacement_ready(
                        protocol,
                        password_discovery_completed,
                        password_dispatch_observed,
                        password_safe_navigation_observed,
                        password_credential_tainted,
                        password_document_replaced,
                        password_main_navigation_request_observed,
                        password_write_request_observed,
                        password_navigation_pending_at_baseline,
                        (
                            password_origin_continuity
                            and current_page_is_microsoft
                        ),
                        password_has_strong_owning_form,
                        password_security.identity,
                        submitted_password_control_identity,
                        password_security.value_empty,
                        credential_error_visible,
                    )
                )
                gp_password_navigation_replacement = bool(
                    gp_password_navigation_replacement
                    and gp_microsoft_password_stage_authorized
                )
                gp_password_client_replacement = bool(
                    gp_password_client_replacement
                    and gp_microsoft_password_stage_authorized
                )
                gp_password_federated_replacement = (
                    _gp_password_federated_replacement_ready(
                        protocol=protocol,
                        discovery_completed=password_discovery_completed,
                        dispatch_observed=password_dispatch_observed,
                        federated_navigation_completed=(
                            password_federated_navigation_completed
                        ),
                        document_replaced=password_document_replaced,
                        main_frame_navigation_request_observed=(
                            password_main_navigation_request_observed
                        ),
                        credential_tainted=password_credential_tainted,
                        unsafe_write_request_observed=(
                            password_unsafe_write_request_observed
                        ),
                        navigation_pending_at_baseline=(
                            password_navigation_pending_at_baseline
                        ),
                        navigation_pending_now=bool(
                            password_transition_snapshot[7]
                        ),
                        original_form_action_origin=(
                            password_action_form_action_origin
                        ),
                        original_top_origin=password_action_top_origin,
                        original_control_origin=password_action_control_origin,
                        committed_federated_origin=(
                            password_federated_navigation_origin
                        ),
                        current_top_origin=current_top_origin,
                        current_control_origin=password_security.https_origin,
                        current_form_action_origin=(
                            password_security.form_action_origin
                        ),
                        current_form_method=password_security.form_method,
                        strong_owning_form=password_has_strong_owning_form,
                        strong_password_input=password_has_strong_input,
                        current_identity=password_security.identity,
                        submitted_identity=(
                            submitted_password_control_identity
                        ),
                        current_value_empty=password_security.value_empty,
                        credential_error_visible=credential_error_visible,
                        vpn_hostname=vpn_server_host,
                    )
                )
                anyconnect_retained_password_continuation = (
                    _anyconnect_retained_password_continuation_ready(
                        protocol,
                        form_submission_kind,
                        password_action_attempts,
                        now - password_action_pending_since,
                        lookup_observed=password_lookup_observed,
                        dispatch_observed=password_dispatch_observed,
                        safe_navigation_observed=(
                            password_safe_navigation_observed
                        ),
                        credential_tainted=password_credential_tainted,
                        document_replaced=password_document_replaced,
                        main_navigation_request_observed=(
                            password_main_navigation_request_observed
                        ),
                        write_request_observed=(
                            password_write_request_observed
                        ),
                        unsafe_write_request_observed=(
                            password_unsafe_write_request_observed
                        ),
                        navigation_pending_at_baseline=(
                            password_navigation_pending_at_baseline
                        ),
                        navigation_pending_now=bool(
                            password_transition_snapshot[7]
                        ),
                        strong_owning_form=password_has_strong_owning_form,
                        strong_password_input=password_has_strong_input,
                        current_identity=password_security.identity,
                        submitted_identity=(
                            submitted_password_control_identity
                        ),
                        value_retained=password_value_retained,
                        original_control_origin=(
                            password_action_control_origin
                        ),
                        original_top_origin=password_action_top_origin,
                        original_form_action_origin=(
                            password_action_form_action_origin
                        ),
                        original_form_signature=(
                            password_action_form_signature
                        ),
                        original_form_method=password_action_form_method,
                        current_control_origin=password_security.https_origin,
                        current_top_origin=current_top_origin,
                        current_form_action_origin=(
                            password_security.form_action_origin
                        ),
                        current_form_signature=(
                            password_security.form_signature
                        ),
                        current_form_method=password_security.form_method,
                        credential_error_visible=credential_error_visible,
                    )
                )
                password_already_dispatched = (
                    sensitive_action_ledger.dispatched("password")
                )
                gp_current_password_stage_authorization = None
                if (
                    str(protocol or "").casefold() == "gp"
                    and not password_discovery_completed
                    and password_action_attempts == 0
                    and not password_already_dispatched
                    and gp_microsoft_password_stage_authorized
                    and usable_password_input is not None
                    and password_security.value_known
                    and password_security.value_empty
                    and not credential_error_visible
                    and not password_transition_snapshot[7]
                ):
                    gp_current_password_stage_authorization = (
                        _GpClientPasswordStageAuthorization(
                            route="client",
                            main_navigation_generation=(
                                password_transition_snapshot[4]
                            ),
                            unsafe_write_generation=(
                                password_transition_snapshot[11]
                            ),
                            taint_generation=password_transition_snapshot[2],
                            document_generation=password_transition_snapshot[3],
                            federated_navigation_generation=(
                                password_transition_snapshot[9]
                            ),
                            authorized_origin=(
                                "https://login.microsoftonline.com"
                            ),
                            control_identity=str(password_security.identity),
                            control_origin=str(password_security.https_origin),
                            top_origin=str(current_top_origin),
                            form_identity=str(password_security.form_identity),
                            form_signature=str(
                                password_security.form_signature
                            ),
                            form_action_origin=str(
                                password_security.form_action_origin
                            ),
                            form_method=str(password_security.form_method),
                        )
                    )
                    if gp_initial_password_observation_started_at is None:
                        gp_initial_password_observation_started_at = now

                gp_password_navigation_pending = bool(
                    str(protocol or "").casefold() == "gp"
                    and not password_discovery_completed
                    and password_action_attempts == 0
                    and not password_already_dispatched
                    and password_transition_snapshot[7]
                )
                if gp_password_navigation_pending:
                    if gp_password_navigation_pending_started_at is None:
                        gp_password_navigation_pending_started_at = now
                else:
                    gp_password_navigation_pending_started_at = None

                gp_initial_password_observation_elapsed = (
                    0.0
                    if gp_initial_password_observation_started_at is None
                    else max(
                        0.0,
                        now - gp_initial_password_observation_started_at,
                    )
                )
                previous_gp_password_observation_pending = (
                    gp_initial_password_observation_pending
                )
                gp_initial_password_observation_pending = (
                    _gp_initial_password_observation_required(
                        protocol,
                        password_discovery_completed,
                        ui_recovery_attempts,
                        password_action_attempts,
                        password_already_dispatched,
                        (
                            gp_initial_password_observation_started_at
                            is not None
                        ),
                        gp_microsoft_password_stage_authorized,
                        usable_password_input is not None,
                        credential_error_visible,
                        gp_initial_password_observation_elapsed,
                        gp_password_navigation_pending,
                    )
                )
                if (
                    previous_gp_password_observation_pending
                    and not gp_initial_password_observation_pending
                ):
                    # Finishing the intentional, bounded observation is not a
                    # stale UI. Give the settled page one fresh idle window so
                    # generic recovery cannot reload it before password-stage
                    # validation. Neither observation nor auth deadlines move.
                    last_substantive_progress_time = now
                    last_progress_time = now
                gp_navigation_cap_anchor = (
                    gp_password_navigation_pending_started_at
                )
                if (
                    gp_navigation_cap_anchor is not None
                    and gp_initial_password_observation_started_at is not None
                ):
                    gp_navigation_cap_anchor = min(
                        gp_navigation_cap_anchor,
                        gp_initial_password_observation_started_at,
                    )
                gp_password_navigation_hard_cap = (
                    _gp_password_navigation_hard_cap_reached(
                        protocol,
                        password_discovery_completed,
                        password_action_attempts,
                        password_already_dispatched,
                        gp_password_navigation_pending,
                        (
                            0.0
                            if gp_navigation_cap_anchor is None
                            else max(0.0, now - gp_navigation_cap_anchor)
                        ),
                    )
                )
                if gp_password_navigation_hard_cap:
                    _report_progress("gp-password-navigation-timeout")
                    if _recover_stale_browser_ui(now, force=True):
                        continue
                if (
                    password_action_attempts > 0
                    and not sensitive_action_ledger.dispatched("password")
                ):
                    if debug or protocol == "anyconnect":
                        transition_evidence = (
                            max(
                                0,
                                password_transition_snapshot[0]
                                - password_action_dispatch_generation,
                            ),
                            max(
                                0,
                                password_transition_snapshot[1]
                                - password_action_safe_navigation_generation,
                            ),
                            max(
                                0,
                                password_transition_snapshot[2]
                                - password_action_credential_taint_generation,
                            ),
                            max(
                                0,
                                password_transition_snapshot[3]
                                - password_action_document_generation,
                            ),
                            max(
                                0,
                                password_transition_snapshot[4]
                                - password_action_main_navigation_request_generation,
                            ),
                            max(
                                0,
                                password_transition_snapshot[5]
                                - password_action_write_request_generation,
                            ),
                            max(
                                0,
                                password_transition_snapshot[6]
                                - password_action_outbound_request_generation,
                            ),
                            password_navigation_pending_at_baseline,
                            password_lookup_observed,
                            password_lookup_transition_pending,
                            password_discovery_classification_deferred,
                            same_password_control,
                            same_password_ui,
                            password_value_retained,
                            password_discovery_completed,
                            credential_error_visible,
                            current_page_is_microsoft,
                            password_origin_continuity,
                            password_has_strong_owning_form,
                            bool(
                                password_security.identity
                                and not password_security.identity.startswith(
                                    "fallback:"
                                )
                            ),
                            bool(password_security.https_origin),
                            bool(current_top_origin),
                            max(
                                0,
                                password_transition_snapshot[9]
                                - password_action_federated_safe_navigation_generation,
                            ),
                            _gp_password_stage_origin_policy_valid(
                                "federated",
                                password_federated_navigation_origin,
                                current_top_origin,
                                password_security.https_origin,
                                password_security.form_action_origin,
                                vpn_server_host,
                            ),
                            max(
                                0,
                                password_transition_snapshot[11]
                                - password_action_unsafe_write_request_generation,
                            ),
                            passkey_prompt_visible,
                            primary_method_picker_visible,
                            usable_method_choice_visible,
                            alternate_method_control_visible,
                            number_match_detected,
                            usable_otp_control_progress,
                            processing_visible,
                        )
                        if transition_evidence != last_password_transition_evidence:
                            last_password_transition_evidence = transition_evidence
                            _report_progress(
                                _password_transition_evidence_message(
                                    transition_evidence[0],
                                    transition_evidence[1],
                                    transition_evidence[2],
                                    transition_evidence[3],
                                    transition_evidence[4],
                                    transition_evidence[5],
                                    transition_evidence[6],
                                    transition_evidence[7],
                                    unsafe_write_request_delta=(
                                        transition_evidence[24]
                                    ),
                                    federated_navigation_delta=(
                                        transition_evidence[22]
                                    ),
                                    federated_origin_match=(
                                        transition_evidence[23]
                                    ),
                                    lookup_observed=transition_evidence[8],
                                    lookup_pending=transition_evidence[9],
                                    classification_deferred=transition_evidence[10],
                                    same_control=transition_evidence[11],
                                    same_ui=transition_evidence[12],
                                    value_retained=transition_evidence[13],
                                    discovery_completed=transition_evidence[14],
                                    error_visible=transition_evidence[15],
                                    current_page_is_microsoft=(
                                        transition_evidence[16]
                                    ),
                                    origin_continuity=transition_evidence[17],
                                    strong_form=transition_evidence[18],
                                    strong_control=transition_evidence[19],
                                    control_https=transition_evidence[20],
                                    top_https=transition_evidence[21],
                                    passkey_visible=transition_evidence[25],
                                    primary_picker_visible=transition_evidence[26],
                                    method_choice_visible=transition_evidence[27],
                                    alternate_method_visible=transition_evidence[28],
                                    authenticator_visible=transition_evidence[29],
                                    otp_visible=transition_evidence[30],
                                    processing_visible=transition_evidence[31],
                                )
                            )
                    if password_credential_tainted:
                        # A POST, opaque auth dispatch, or request containing
                        # the password permanently consumes this action epoch.
                        # A later GET redirect or empty field cannot undo it.
                        sensitive_action_ledger.record("password")
                        _report_progress("password-dispatch-confirmed")
                    elif (
                        password_lookup_transition_pending
                        or gp_password_navigation_replacement
                        or gp_password_client_replacement
                        or gp_password_federated_replacement
                    ):
                        # GetCredentialType is the non-password discovery stage
                        # used by FHNW.  Wait for its replacement control before
                        # authorizing the one real password submission.
                        pass
                    elif anyconnect_retained_password_continuation:
                        # A document hydration replaced the password DOM node
                        # without issuing a credential or unsafe write request.
                        # Submit its retained value once; never type the secret
                        # again and bind the click to the exact replacement form.
                        retained_authorization = (
                            _AnyConnectRetainedPasswordStageAuthorization(
                                password_stage=(
                                    _GpClientPasswordStageAuthorization(
                                        route="client",
                                        main_navigation_generation=(
                                            password_transition_snapshot[4]
                                        ),
                                        unsafe_write_generation=(
                                            password_transition_snapshot[11]
                                        ),
                                        taint_generation=(
                                            password_transition_snapshot[2]
                                        ),
                                        document_generation=(
                                            password_transition_snapshot[3]
                                        ),
                                        federated_navigation_generation=(
                                            password_transition_snapshot[9]
                                        ),
                                        authorized_origin=(
                                            "https://login.microsoftonline.com"
                                        ),
                                        control_identity=str(
                                            password_security.identity
                                        ),
                                        control_origin=str(
                                            password_security.https_origin
                                        ),
                                        top_origin=str(current_top_origin),
                                        form_identity=str(
                                            password_security.form_identity
                                        ),
                                        form_signature=str(
                                            password_security.form_signature
                                        ),
                                        form_action_origin=str(
                                            password_security.form_action_origin
                                        ),
                                        form_method=str(
                                            password_security.form_method
                                        ),
                                    )
                                ),
                                lookup_generation=(
                                    password_lookup_generation_snapshot
                                ),
                                lookup_pending_count=(
                                    password_lookup_pending_count_snapshot
                                ),
                                safe_navigation_generation=(
                                    password_transition_snapshot[1]
                                ),
                                unsafe_write_generation=(
                                    password_transition_snapshot[11]
                                ),
                            )
                        )
                        retained_submitted = _submit_owned_form(
                            usable_password_input,
                            [
                                "Anmelden",
                                "Sign in",
                                "Connexion",
                                "Accedi",
                                "Continue",
                                "Next",
                            ],
                            [],
                            allow_unlabelled_submit=True,
                            allow_known_ids=False,
                            allow_enter=True,
                            sensitive=True,
                            action_name=(
                                "retained AnyConnect password form submission"
                            ),
                            pre_sensitive_action_guard=lambda action_loc: (
                                _validate_anyconnect_retained_password_stage(
                                    usable_password_input,
                                    retained_authorization,
                                    submitter_loc=action_loc,
                                )
                            ),
                        )
                        if not retained_submitted:
                            raise RuntimeError(
                                "The retained Microsoft password form has no "
                                "validated owning submit control"
                            )
                        password_action_attempts = 2
                        password_action_pending_since = time.monotonic()
                        password_action_dispatch_generation = (
                            password_transition_snapshot[0]
                        )
                        password_action_safe_navigation_generation = (
                            password_transition_snapshot[1]
                        )
                        password_action_federated_safe_navigation_generation = (
                            password_transition_snapshot[9]
                        )
                        password_action_credential_taint_generation = (
                            password_transition_snapshot[2]
                        )
                        password_action_document_generation = (
                            password_transition_snapshot[3]
                        )
                        password_action_main_navigation_request_generation = (
                            password_transition_snapshot[4]
                        )
                        password_action_write_request_generation = (
                            password_transition_snapshot[5]
                        )
                        password_action_unsafe_write_request_generation = (
                            password_transition_snapshot[11]
                        )
                        password_action_outbound_request_generation = (
                            password_transition_snapshot[6]
                        )
                        password_action_navigation_pending_count = (
                            password_transition_snapshot[7]
                        )
                        password_action_control_identity = (
                            password_security.identity
                        )
                        password_action_control_origin = (
                            password_security.https_origin
                        )
                        password_action_top_origin = current_top_origin
                        password_action_form_action_origin = (
                            password_security.form_action_origin
                        )
                        password_action_form_signature = (
                            password_security.form_signature
                        )
                        password_action_form_method = (
                            password_security.form_method
                        )
                        password_submission_lookup_generation = (
                            microsoft_credential_lookup.generation
                        )
                        password_submission_classify_until = (
                            _password_submission_classification_deadline(
                                protocol,
                                password_discovery_completed,
                                password_action_pending_since,
                                deadline,
                            )
                        )
                        _interruptible_pause(0.25)
                        _refresh_rendered_ui_snapshot()
                        password_action_ui_fingerprint = (
                            _auth_ui_fingerprint()
                        )
                        _report_progress(
                            "password-retained-form-submitted"
                        )
                        _arm_submission_wait(
                            "password-unknown",
                            password_action_pending_since,
                            submitted_password_identity=(
                                password_security.identity
                            ),
                        )
                        continue
                    elif (
                        password_discovery_classification_deferred
                        and (
                            password_dispatch_observed
                            or not same_filled_password_form
                        )
                    ):
                        # Generic main-frame navigation is ambiguous here: the
                        # Microsoft discovery handler can emit it several seconds
                        # before GetCredentialType and the replacement field.
                        # It suppresses the Enter fallback but must not consume
                        # the one real password submission yet.
                        pass
                    elif _anyconnect_password_dispatch_is_ambiguous(
                        protocol,
                        form_submission_kind,
                        dispatch_observed=password_dispatch_observed,
                        credential_tainted=password_credential_tainted,
                        unsafe_write_request_observed=(
                            password_unsafe_write_request_observed
                        ),
                        main_navigation_request_observed=(
                            password_main_navigation_request_observed
                        ),
                    ):
                        # A document commit or safe telemetry can change the UI
                        # without carrying the password. At classification expiry
                        # consume the epoch fail-closed, but never report that
                        # ambiguous evidence as a confirmed credential dispatch.
                        sensitive_action_ledger.record("password")
                        _report_progress("password-dispatch-uncertain")
                    elif password_dispatch_observed:
                        sensitive_action_ledger.record("password")
                        _report_progress("password-dispatch-confirmed")
                    elif not same_filled_password_form:
                        # A client-side transition is not proof of an outbound
                        # credential request, but it makes replay unsafe.
                        sensitive_action_ledger.record("password")
                        _report_progress("password-dispatch-uncertain")
                    elif _password_alternate_dispatch_allowed(
                        password_action_attempts,
                        now - password_action_pending_since,
                        outbound_dispatch_observed=(
                            _password_transition_blocks_alternate_dispatch(
                                password_dispatch_observed,
                                password_main_navigation_request_observed,
                                bool(password_transition_snapshot[7]),
                            )
                        ),
                        same_filled_form=same_filled_password_form,
                    ):
                        alternate_generation_before = (
                            sensitive_dispatch_evidence.generation
                        )
                        if not _attempt_locator_press(
                            usable_password_input,
                            "Enter",
                            sensitive=True,
                            action_name="password alternate submission",
                        ):
                            raise RuntimeError(
                                "Could not dispatch the filled password form"
                            )
                        password_action_attempts = 2
                        password_action_pending_since = time.monotonic()
                        password_action_dispatch_generation = (
                            alternate_generation_before
                        )
                        password_action_control_identity = (
                            usable_password_identity
                        )
                        _interruptible_pause(0.25)
                        _refresh_rendered_ui_snapshot()
                        password_action_ui_fingerprint = (
                            _auth_ui_fingerprint()
                        )
                        _report_progress("password-alternate-dispatch")
                        _arm_submission_wait(
                            (
                                "password-unknown"
                                if (
                                    _password_discovery_supported(protocol)
                                    and not password_discovery_completed
                                )
                                else "password"
                            ),
                            password_action_pending_since,
                            submitted_password_identity=(
                                usable_password_identity
                            ),
                        )
                        continue
                actionable_pre_sensitive_state_visible = bool(
                    usable_otp_control_progress
                    or usable_password_control_progress
                    or number_match_detected
                    or usable_method_choice_visible
                    or usable_passkey_fallback_visible
                )
                if _persistent_profile_pre_sensitive_expired(
                    now,
                    persistent_pre_sensitive_hard_deadline,
                    protocol=protocol,
                    force_ephemeral_browser_session=(
                        force_ephemeral_browser_session
                    ),
                    sensitive_submission_started=sensitive_submission_started,
                    actionable_auth_state_visible=(
                        actionable_pre_sensitive_state_visible
                    ),
                ):
                    _raise_profile_stall(
                        "Cached SAML browser profile exceeded the pre-sensitive "
                        "progress limit"
                    )
                if credential_lookup_expired and not credential_lookup_waiting:
                    _report_progress("credential-lookup-timeout")
                    if _recover_stale_browser_ui(now, force=True):
                        continue

                if (
                    form_submission_fingerprint is not None
                    and form_submission_kind == "password-unknown"
                ):
                    replacement_password_control = (
                        _password_discovery_replacement_ready(
                            protocol,
                            password_discovery_completed,
                            password_lookup_observed,
                            usable_password_identity,
                            submitted_password_control_identity,
                            password_credential_tainted,
                        )
                    )
                    replacement_password_control = (
                        _password_discovery_replacement_allowed(
                            protocol,
                            replacement_password_control,
                            gp_microsoft_password_stage_authorized,
                        )
                    )
                    if (
                        replacement_password_control
                        or gp_password_navigation_replacement
                        or gp_password_client_replacement
                        or gp_password_federated_replacement
                    ):
                        password_discovery_completed = True
                        password_discovery_authorized_taint_generation = (
                            password_transition_snapshot[2]
                        )
                        promoted_gp_password_route = (
                            _gp_password_replacement_authorization_route(
                                protocol,
                                replacement_password_control,
                                gp_password_navigation_replacement,
                                gp_password_client_replacement,
                                gp_password_federated_replacement,
                            )
                        )
                        password_discovery_authorized_client_stage = (
                            _GpClientPasswordStageAuthorization(
                                route=promoted_gp_password_route,
                                main_navigation_generation=(
                                    password_transition_snapshot[4]
                                ),
                                unsafe_write_generation=(
                                    password_transition_snapshot[11]
                                ),
                                taint_generation=password_transition_snapshot[2],
                                document_generation=password_transition_snapshot[3],
                                federated_navigation_generation=(
                                    password_transition_snapshot[9]
                                ),
                                authorized_origin=str(
                                    password_federated_navigation_origin
                                    if promoted_gp_password_route == "federated"
                                    else current_top_origin
                                ),
                                control_identity=str(password_security.identity),
                                control_origin=str(password_security.https_origin),
                                top_origin=str(current_top_origin),
                                form_identity=str(password_security.form_identity),
                                form_signature=str(password_security.form_signature),
                                form_action_origin=str(
                                    password_security.form_action_origin
                                ),
                                form_method=str(password_security.form_method),
                            )
                            if promoted_gp_password_route is not None
                            else None
                        )
                        filled_password = False
                        password_action_attempts = 0
                        password_action_pending_since = 0.0
                        password_action_dispatch_generation = (
                            password_transition_snapshot[0]
                        )
                        password_action_safe_navigation_generation = (
                            password_transition_snapshot[8]
                        )
                        password_action_federated_safe_navigation_generation = (
                            password_transition_snapshot[10]
                        )
                        password_action_credential_taint_generation = (
                            password_transition_snapshot[2]
                        )
                        password_action_document_generation = (
                            password_transition_snapshot[3]
                        )
                        password_action_main_navigation_request_generation = (
                            password_transition_snapshot[4]
                        )
                        password_action_write_request_generation = (
                            password_transition_snapshot[5]
                        )
                        password_action_unsafe_write_request_generation = (
                            password_transition_snapshot[11]
                        )
                        password_action_outbound_request_generation = (
                            password_transition_snapshot[6]
                        )
                        password_action_navigation_pending_count = (
                            password_transition_snapshot[7]
                        )
                        password_action_control_identity = None
                        password_action_control_origin = None
                        password_action_top_origin = None
                        password_action_form_action_origin = None
                        password_action_form_signature = None
                        password_action_form_method = None
                        password_action_ui_fingerprint = None
                        password_input_ready_since = 0.0
                        password_input_identity = None
                        password_control_submitted = False
                        submitted_password_control_identity = None
                        password_lookup_seen_for_submission = False
                        password_submission_classify_until = 0.0
                        post_submit_grace_until = 0.0
                        processing_extensions_used = 0
                        form_submission_fingerprint = None
                        form_submission_kind = None
                        form_submission_hard_deadline = 0.0
                        microsoft_credential_lookup.reset()
                        last_progress_time = now
                        last_substantive_progress_time = now
                        _report_progress(
                            "credential-lookup-submitted"
                            if replacement_password_control
                            else (
                                "password-client-replacement"
                                if gp_password_client_replacement
                                else (
                                    "password-federated-replacement"
                                    if gp_password_federated_replacement
                                    else "password-navigation-replacement"
                                )
                            )
                        )
                        continue
                    if (
                        not password_lookup_transition_pending
                        and not password_lookup_seen_for_submission
                        and not password_discovery_classification_deferred
                        and (
                            sensitive_action_ledger.dispatched("password")
                            or now >= password_submission_classify_until
                        )
                    ):
                        sensitive_action_ledger.record("password")
                        form_submission_kind = "password"
                        password_submission_classify_until = 0.0
                        _report_progress("password-submitted")

                if (
                    form_submission_fingerprint is not None
                    and credential_error_visible
                ):
                    raise RuntimeError(
                        "The identity provider rejected the submitted credentials or code"
                    )

                password_field_visible = (
                    _password_field_completes_submission_transition(
                        form_submission_kind,
                        usable_password_control_progress,
                    )
                )

                account_state_visible = _page_has_text([
                    "Pick an account",
                    "issue looking up your account",
                    "Use another account",
                    "Anderes Konto verwenden",
                ])
                password_submission_pending = form_submission_kind in {
                    "password",
                    "password-unknown",
                }
                if (
                    password_submission_pending
                    and fingerprint_changed
                    and account_state_visible
                ):
                    raise RuntimeError(
                        "Microsoft returned to account selection after password submission"
                    )

                if password_submission_pending:
                    recognized_post_submit_state = bool(
                        usable_otp_control_progress
                        or number_match_detected
                        or (
                            fingerprint_changed
                            and (
                                _page_has_text(list(MICROSOFT_KMSI_MARKERS))
                                or _page_has_text(
                                    list(MICROSOFT_PASSKEY_REGISTRATION_MARKERS)
                                )
                                or _actionable_method_choice_visible()
                                or _method_picker_context_visible()
                            )
                        )
                    )
                else:
                    recognized_post_submit_state = bool(
                        usable_otp_control_progress
                        or number_match_detected
                        or password_field_visible
                        or (
                            fingerprint_changed
                            and (
                                _page_has_text(list(MICROSOFT_PASSKEY_MARKERS))
                                or _page_has_text(list(MICROSOFT_KMSI_MARKERS))
                                or account_state_visible
                                or _actionable_method_choice_visible()
                                or _method_picker_context_visible()
                            )
                        )
                    )
                discovery_primary_picker_visible = _page_has_text(
                    list(MICROSOFT_PRIMARY_METHOD_PICKER_MARKERS)
                )
                discovery_password_method_visible = _password_method_visible()
                discovery_method_picker_ready = (
                    _password_discovery_method_picker_ready(
                        protocol,
                        form_submission_kind,
                        password_lookup_seen_for_submission,
                        password_credential_tainted,
                        password_unsafe_write_request_observed,
                        discovery_primary_picker_visible,
                        discovery_password_method_visible,
                    )
                )
                credential_free_lookup_pending = bool(
                    form_submission_kind == "password-unknown"
                    and password_lookup_seen_for_submission
                    and not password_credential_tainted
                    and not password_unsafe_write_request_observed
                )
                if discovery_method_picker_ready:
                    # FHNW's first password-shaped Microsoft page performs only
                    # GetCredentialType. The resulting chooser authorizes the
                    # actual password stage, but only because transport evidence
                    # proves that no credential or unsafe write left the browser.
                    password_discovery_completed = True
                    password_discovery_authorized_taint_generation = (
                        password_transition_snapshot[2]
                    )
                    password_discovery_authorized_client_stage = None
                    filled_password = False
                    password_action_attempts = 0
                    password_action_pending_since = 0.0
                    password_input_ready_since = 0.0
                    password_input_identity = None
                    password_control_submitted = False
                    submitted_password_control_identity = None
                    password_lookup_seen_for_submission = False
                    password_submission_classify_until = 0.0
                    post_submit_grace_until = 0.0
                    processing_extensions_used = 0
                    form_submission_fingerprint = None
                    form_submission_kind = None
                    form_submission_hard_deadline = 0.0
                    microsoft_credential_lookup.reset()
                    last_progress_time = now
                    last_substantive_progress_time = now
                    _report_progress("credential-lookup-method-picker")
                    continue
                if credential_free_lookup_pending:
                    # Generic actionable markup briefly appears between the
                    # completed lookup and the concrete method picker. It is
                    # not proof that the password was sent and must not consume
                    # the one real password stage.
                    recognized_post_submit_state = False
                if recognized_post_submit_state:
                    if password_submission_pending:
                        # A concrete MFA/KMSI/method-picker transition proves
                        # that this was the real password stage without waiting
                        # for the discovery-classification deadline.
                        sensitive_action_ledger.record("password")
                        if form_submission_kind == "password-unknown":
                            _report_progress("password-submitted")
                    post_submit_grace_until = 0.0
                    form_submission_fingerprint = None
                    form_submission_kind = None
                    form_submission_hard_deadline = 0.0
                    password_submission_classify_until = 0.0
                if otp_loc:
                    password_bridge_pending_until = 0.0
                    passkey_password_pending_until = 0.0

                # Inspect an explicitly rejected code even while the submitted
                # OTP control remains mounted.  Without a new error, that same
                # control stays latched as an in-flight sensitive submission.
                if otp_loc and last_totp_counter is not None:
                    current_error = _totp_error_signature(otp_loc)
                    totp_rejected = bool(
                        current_error
                        and current_error != totp_error_before_submit
                    )
                    if totp_rejected:
                        totp_disabled_for_attempt = True
                        _report_progress("mfa-totp-rejected")
                        raise RuntimeError(
                            "Microsoft rejected the configured TOTP code; update the TOTP "
                            "secret, or explicitly set mfa-preference=push to use the phone"
                        )

                if retained_submitted_otp and _page_has_text(
                    list(MICROSOFT_KMSI_MARKERS)
                ):
                    # A stale OTP panel must not hide a real post-auth prompt.
                    otp_loc = None
                    retained_submitted_otp = False

                if (
                    form_submission_fingerprint is not None
                    and form_submission_hard_deadline > 0.0
                    and now >= form_submission_hard_deadline
                ):
                    # A submitted credential or MFA form is not a stale static
                    # page. Reloading it can duplicate a sign-in or phone prompt,
                    # so stop only at its immutable, protocol-clamped deadline.
                    _raise_profile_stall(
                        "Microsoft did not complete the submitted sign-in within "
                        "the adaptive processing limit",
                    )

                form_submission_pending = bool(
                    form_submission_fingerprint is not None
                    and now < post_submit_grace_until
                )

                intentional_transition_pending = bool(
                    otp_loc
                    or number_match_detected
                    or form_submission_pending
                    or (
                        last_mfa_switch_time > 0.0
                        and not can_switch_mfa
                    )
                    or now < mfa_picker_pending_until
                    or now < mfa_method_pending_until
                    or now < number_match_switch_deadline
                    or now < primary_credential_picker_pending_until
                    or now < passkey_password_pending_until
                    or now < password_bridge_pending_until
                    or credential_lookup_waiting
                    or gp_initial_password_observation_pending
                )
                if (
                    not intentional_transition_pending
                    and _recover_stale_browser_ui(now)
                ):
                    continue
                if form_submission_pending and not (
                    usable_otp_control_progress or number_match_detected
                ):
                    _interruptible_pause(0.1)
                    continue
                if credential_lookup_waiting:
                    _report_progress("credential-lookup-waiting")
                    _interruptible_pause(0.1)
                    continue
                if not otp_loc and password_bridge_pending_until > 0.0:
                    password_bridge_action = _password_bridge_transition_action(
                        _totp_method_visible(),
                        usable_password_control_progress,
                        now < password_bridge_pending_until,
                    )
                    if password_bridge_action == "select-totp":
                        if not _select_totp_method():
                            raise RuntimeError(
                                "Microsoft exposed TOTP after the password bridge, "
                                "but the method could not be selected"
                            )
                        password_bridge_pending_until = 0.0
                        method_selection_pending = "TOTP"
                        mfa_method_pending_until = (
                            now + MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS
                        )
                        _report_progress("mfa-totp-after-password-bridge-selected")
                        last_mfa_switch_time = now
                        _interruptible_pause(0.25)
                        continue
                    if password_bridge_action == "accept-password":
                        password_bridge_pending_until = 0.0
                        filled_password = False
                        password_input_ready_since = 0.0
                        password_input_identity = None
                    elif password_bridge_action == "wait":
                        _interruptible_pause(0.2)
                        continue
                    else:
                        raise RuntimeError(
                            "Microsoft did not expose TOTP or password entry after "
                            "selecting the password bridge"
                        )

                # The old OTP form can remain visible while Microsoft's method
                # picker becomes ready. Once the picker is genuinely visible,
                # stop treating that retained input as the active MFA state.
                if (
                    otp_loc
                    and (
                        otp_alternate_attempts
                        or method_selection_pending == "Authenticator push"
                    )
                    and _push_method_visible()
                ):
                    otp_loc = None

                if totp_disabled_for_attempt and otp_loc:
                    # Never let generic Continue/Next handling resubmit a code
                    # after the automatic TOTP path has been abandoned.
                    _wait_until_ready(0.2)
                    continue

                if (
                    otp_loc
                    and not number_match_detected
                    and last_totp_counter is None
                    and (mfa_preference == "push" or not totp_available)
                ):
                    if method_selection_pending == "Authenticator push":
                        if not can_switch_mfa:
                            _interruptible_pause(0.2)
                            continue
                        raise RuntimeError(
                            "Microsoft did not transition to Authenticator phone approval"
                        )
                    if not can_switch_mfa:
                        _interruptible_pause(0.2)
                        continue
                    if otp_alternate_attempts < 2:
                        otp_alternate_attempts += 1
                        if _open_alternate_methods():
                            _report_progress("mfa-alternate-methods-opened")
                            last_mfa_switch_time = time.monotonic()
                            _interruptible_pause(0.25)
                            continue
                        if otp_alternate_attempts < 2:
                            _interruptible_pause(0.5)
                            continue
                    if mfa_preference == "push":
                        raise RuntimeError(
                            "Microsoft requires a verification code and did not offer "
                            "Authenticator push approval"
                        )
                    if not totp_available:
                        raise RuntimeError(
                            "Microsoft requires a verification code but no TOTP secret is configured"
                        )

                if not otp_loc and _page_has_text(
                    list(MICROSOFT_PASSKEY_REGISTRATION_MARKERS)
                ):
                    if sensitive_action_ledger.dispatched(
                        "passkey-registration-skip"
                    ):
                        _interruptible_pause(0.1)
                        continue
                    if _click_action(
                        list(MICROSOFT_SKIP_OPTIONAL_LABELS),
                        sensitive=True,
                        action_name="passkey-registration skip",
                    ):
                        _report_progress("passkey-registration-skipped")
                        submitted_at = time.monotonic()
                        _arm_submission_wait(
                            "passkey-registration-skip",
                            submitted_at,
                        )
                        _interruptible_pause(0.25)
                        continue
                    raise RuntimeError(
                        "Microsoft requires interactive passkey registration, which cannot "
                        "be completed by the headless VPN login"
                    )

                should_prefer_totp = _prefer_totp_for_number_match(
                    mfa_preference,
                    totp_available,
                    totp_disabled_for_attempt,
                )
                totp_choice_visible = bool(
                    not otp_loc and _totp_method_visible()
                )
                picker_transition_pending = now < mfa_picker_pending_until
                adaptive_action = _adaptive_mfa_action(
                    prefer_totp=should_prefer_totp,
                    otp_input_visible=bool(otp_loc),
                    authenticator_challenge_visible=number_match_detected,
                    totp_choice_visible=totp_choice_visible,
                    picker_transition_pending=picker_transition_pending,
                )

                # A real verification-code input always wins over stale text
                # left behind by the previous Authenticator challenge panel.
                if adaptive_action == "submit-totp":
                    number_match_detected = False
                    method_selection_pending = None
                    mfa_picker_pending_until = 0.0
                    mfa_picker_settle_until = 0.0
                    mfa_method_pending_until = 0.0
                    number_match_switch_deadline = 0.0
                    number_match_detected_reported = False

                if number_match_detected:
                    if should_prefer_totp:
                        if not number_match_detected_reported:
                            _report_progress(
                                "mfa-number-match-detected"
                                if actual_number_match_detected
                                else "mfa-authenticator-push-detected"
                            )
                            number_match_detected_reported = True
                        if number_match_switch_deadline <= 0.0:
                            number_match_switch_deadline = (
                                now + MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS
                            )
                        if method_selection_pending == "TOTP":
                            if now < mfa_method_pending_until:
                                _interruptible_pause(0.2)
                                continue
                            raise RuntimeError(
                                "Microsoft did not transition to the configured TOTP method"
                            )

                        if adaptive_action == "select-totp":
                            if _select_totp_method():
                                method_selection_pending = "TOTP"
                                mfa_method_pending_until = (
                                    now + MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS
                                )
                                mfa_picker_pending_until = 0.0
                                mfa_picker_settle_until = 0.0
                                mfa_picker_open_attempts = 0
                                number_match_switch_deadline = 0.0
                                _report_progress("mfa-totp-direct-selected")
                                last_mfa_switch_time = now
                                _interruptible_pause(0.25)
                                continue
                        elif adaptive_action == "wait-for-picker":
                            if (
                                now >= mfa_picker_settle_until
                                and mfa_picker_open_attempts < 2
                                and _open_number_match_totp_methods()
                            ):
                                mfa_picker_open_attempts += 1
                                mfa_picker_settle_until = (
                                    now + MICROSOFT_METHOD_PICKER_SETTLE_SECONDS
                                )
                                _report_progress("mfa-alternate-methods-reopened")
                                last_mfa_switch_time = now
                                _interruptible_pause(0.25)
                                continue
                            _interruptible_pause(0.2)
                            continue
                        elif (
                            adaptive_action == "open-alternate-methods"
                            and now < number_match_switch_deadline
                        ):
                            if _open_number_match_totp_methods():
                                mfa_picker_open_attempts = 1
                                mfa_picker_debug_reported = False
                                _report_progress("mfa-alternate-methods-opened")
                                last_mfa_switch_time = now
                                mfa_picker_pending_until = (
                                    now + MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS
                                )
                                mfa_picker_settle_until = (
                                    now + MICROSOFT_METHOD_PICKER_SETTLE_SECONDS
                                )
                                _interruptible_pause(0.25)
                                continue
                            if (
                                password_bridge_attempts < 1
                                and _password_method_visible()
                                and _select_password_method()
                            ):
                                password_bridge_attempts += 1
                                password_bridge_pending_until = (
                                    now + MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS
                                )
                                number_match_switch_deadline = 0.0
                                _report_progress("mfa-password-bridge-selected")
                                last_mfa_switch_time = now
                                _interruptible_pause(0.25)
                                continue
                        if now < number_match_switch_deadline:
                            _interruptible_pause(0.5)
                            continue
                        raise RuntimeError(
                            "Microsoft showed Authenticator number matching but did not "
                            "offer the configured TOTP method after switching sign-in methods"
                        )

                    if not _should_notify_number_match(
                        mfa_preference,
                        totp_available,
                    ):
                        raise RuntimeError(
                            "Phone approval is disabled while a TOTP secret is configured; "
                            "update the TOTP secret or explicitly set mfa-preference=push"
                        )
                    # Re-entering the SAML flow from here can dispatch a second
                    # Authenticator request. Treat the existing phone challenge
                    # as sensitive even when a cached SSO session skipped the
                    # password form in this browser run.
                    sensitive_submission_started = True
                    if actual_number_match_detected and not number_match:
                        raise RuntimeError(
                            "Microsoft Authenticator number matching is required, but the "
                            "two-digit approval number could not be read unambiguously"
                        )
                    if not actual_number_match_detected:
                        # Ordinary approve/deny push has no two-digit value.
                        # Explicit push mode waits for the IdP callback.
                        _interruptible_pause(0.2)
                        continue
                    if number_match != last_number_match:
                        if _notify_number_match(number_match):
                            _report_progress("mfa-number-match-notified")
                        else:
                            raise RuntimeError(
                                "Microsoft Authenticator number matching is required, but the "
                                "desktop approval notification could not be shown"
                            )
                        last_number_match = number_match
                        totp_disabled_for_attempt = True
                        method_selection_pending = None
                    _interruptible_pause(0.2)
                    continue
                else:
                    number_match_detected_reported = False
                    if not picker_transition_pending:
                        number_match_switch_deadline = 0.0

                if last_number_match is not None:
                    _close_number_match_notification()
                    last_number_match = None

                # After clicking away from number matching, Microsoft can leave
                # a blank or partially rendered panel before the TOTP tile
                # appears. Poll that transition without running generic clicks.
                if not otp_loc and should_prefer_totp and picker_transition_pending:
                    if (
                        debug
                        and not mfa_picker_debug_reported
                        and now >= mfa_picker_settle_until
                    ):
                        _debug_visible_auth_controls("TOTP picker transition")
                        mfa_picker_debug_reported = True
                    if totp_choice_visible and _select_totp_method():
                        method_selection_pending = "TOTP"
                        mfa_method_pending_until = (
                            now + MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS
                        )
                        mfa_picker_pending_until = 0.0
                        mfa_picker_settle_until = 0.0
                        mfa_picker_open_attempts = 0
                        _report_progress("mfa-totp-method-selected")
                        last_mfa_switch_time = now
                        _interruptible_pause(0.25)
                        continue
                    if (
                        _password_bridge_allowed(mfa_preference)
                        and _password_method_visible()
                    ):
                        if now < mfa_picker_settle_until:
                            _interruptible_pause(0.2)
                            continue
                        if (
                            password_bridge_attempts < 1
                            and _select_password_method()
                        ):
                            password_bridge_attempts += 1
                            filled_password = False
                            password_input_ready_since = 0.0
                            password_input_identity = None
                            mfa_picker_pending_until = 0.0
                            mfa_picker_settle_until = 0.0
                            mfa_picker_open_attempts = 0
                            number_match_switch_deadline = 0.0
                            password_bridge_pending_until = (
                                now + MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS
                            )
                            last_mfa_switch_time = now
                            _report_progress("mfa-password-bridge-selected")
                            _interruptible_pause(0.25)
                            continue
                    _interruptible_pause(0.2)
                    continue
                if (
                    not otp_loc
                    and should_prefer_totp
                    and mfa_picker_pending_until > 0.0
                ):
                    raise RuntimeError(
                        "Microsoft did not render the configured TOTP method after "
                        "opening alternate sign-in methods"
                    )

                if (
                    not otp_loc
                    and method_selection_pending == "Authenticator push"
                    and _page_has_text(
                        list(MICROSOFT_PUSH_DELIVERY_FAILURE_MARKERS)
                    )
                ):
                    if (
                        push_delivery_retry_attempts
                        < MICROSOFT_PUSH_DELIVERY_MAX_RETRIES
                        and _click_first_selector(
                            ("#idSIButton9",),
                            sensitive=True,
                            action_name="Authenticator delivery retry",
                        )
                    ):
                        push_delivery_retry_attempts += 1
                        mfa_method_pending_until = (
                            now + MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS
                        )
                        _report_progress("mfa-push-delivery-retried")
                        last_mfa_switch_time = now
                        _interruptible_pause(0.25)
                        continue
                    _debug_visible_auth_controls("before failed-push alternate")
                    if not _open_alternate_methods():
                        raise RuntimeError(
                            "Microsoft could not send the Authenticator request and "
                            "did not offer another verification method"
                        )
                    method_selection_pending = None
                    mfa_method_pending_until = 0.0
                    mfa_picker_open_attempts = 1
                    mfa_picker_debug_reported = False
                    mfa_picker_pending_until = (
                        now + MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS
                    )
                    mfa_picker_settle_until = (
                        now + MICROSOFT_METHOD_PICKER_SETTLE_SECONDS
                    )
                    _report_progress("mfa-push-failed-alternate-methods-opened")
                    last_mfa_switch_time = now
                    _interruptible_pause(0.25)
                    continue

                # Once a method is selected, suppress unrelated account and
                # generic form actions until its input appears or the bounded
                # transition expires.
                if not otp_loc and method_selection_pending:
                    if now < mfa_method_pending_until:
                        _interruptible_pause(0.2)
                        continue
                    raise RuntimeError(
                        f"Microsoft did not transition after selecting {method_selection_pending}"
                    )

                if not otp_loc and passkey_password_pending_until > 0.0:
                    passkey_password_action = _passkey_password_transition_action(
                        usable_password_control_progress,
                        now < passkey_password_pending_until,
                    )
                    if passkey_password_action == "accept-password":
                        passkey_password_pending_until = 0.0
                        filled_password = False
                        password_input_ready_since = 0.0
                        password_input_identity = None
                    elif passkey_password_action == "wait":
                        _interruptible_pause(0.2)
                        continue
                    else:
                        raise RuntimeError(
                            "Microsoft did not render password entry after leaving "
                            "the passkey prompt"
                        )

                if not otp_loc and primary_credential_picker_pending_until > 0.0:
                    if _password_method_visible() and _select_password_method():
                        primary_credential_picker_pending_until = 0.0
                        passkey_password_pending_until = (
                            now + MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS
                        )
                        _report_progress("passkey-password-fallback-selected")
                        _interruptible_pause(0.25)
                        continue
                    if now < primary_credential_picker_pending_until:
                        _interruptible_pause(0.2)
                        continue
                    raise RuntimeError(
                        "Microsoft did not offer password sign-in after leaving the passkey prompt"
                    )

                if (
                    not otp_loc
                    and should_prefer_totp
                    and primary_picker_password_attempts < 1
                    and _page_has_text(
                        list(MICROSOFT_PRIMARY_METHOD_PICKER_MARKERS)
                    )
                    and _password_method_visible()
                ):
                    if not _select_password_method():
                        raise RuntimeError(
                            "Microsoft exposed the password method but it "
                            "could not be selected"
                        )
                    primary_picker_password_attempts += 1
                    passkey_password_pending_until = (
                        now + MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS
                    )
                    _report_progress("primary-picker-password-selected")
                    last_mfa_switch_time = now
                    _interruptible_pause(0.25)
                    continue

                if not otp_loc and _page_has_text(list(MICROSOFT_PASSKEY_MARKERS)):
                    passkey_route = _passkey_fallback_route(
                        password_control_submitted,
                        should_prefer_totp,
                    )
                    passkey_action = _leave_passkey_prompt(
                        prefer_totp_fallback=passkey_route == "totp",
                    )
                    if passkey_action:
                        _report_progress(passkey_action)
                        last_mfa_switch_time = now
                        if passkey_action == "passkey-alternate-methods-opened":
                            primary_credential_picker_pending_until = (
                                now + MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS
                            )
                        elif passkey_action == "passkey-password-fallback-selected":
                            passkey_password_pending_until = (
                                now + MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS
                            )
                        elif passkey_action == "passkey-mfa-alternate-methods-opened":
                            mfa_picker_open_attempts = 1
                            mfa_picker_debug_reported = False
                            mfa_picker_pending_until = (
                                now + MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS
                            )
                            mfa_picker_settle_until = (
                                now + MICROSOFT_METHOD_PICKER_SETTLE_SECONDS
                            )
                        elif passkey_action == "passkey-totp-method-selected":
                            method_selection_pending = "TOTP"
                            mfa_method_pending_until = (
                                now + MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS
                            )
                        elif passkey_action == "passkey-authenticator-app-selected":
                            sensitive_action_ledger.record("push")
                            method_selection_pending = "Authenticator push"
                            mfa_method_pending_until = (
                                now + MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS
                            )
                        _interruptible_pause(0.25)
                    else:
                        raise RuntimeError(
                            "Microsoft requested an interactive passkey and did not offer "
                            "password or another sign-in method"
                        )
                    continue

                prefer_totp = (
                    mfa_preference != "push"
                    and totp_available
                    and not totp_disabled_for_attempt
                )
                requested_method_visible = (
                    _totp_method_visible() if prefer_totp else _push_method_visible()
                )
                if not otp_loc and requested_method_visible:
                    otp_alternate_attempts = 0
                    requested_method = "TOTP" if prefer_totp else "Authenticator push"
                    selected = _select_totp_method() if prefer_totp else _select_push_method()
                    if selected:
                        if not prefer_totp:
                            # Selecting the push tile can send the notification
                            # immediately, so it must never be replayed by the
                            # clean-profile fallback.
                            submitted_at = time.monotonic()
                            _arm_submission_wait("push", submitted_at)
                        method_selection_pending = requested_method
                        mfa_method_pending_until = (
                            now + MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS
                        )
                        _report_progress(
                            "mfa-totp-method-selected"
                            if prefer_totp
                            else "mfa-authenticator-push-selected"
                        )
                        last_mfa_switch_time = time.monotonic()
                        _interruptible_pause(0.25)
                        continue
                    raise RuntimeError(
                        f"Microsoft did not offer the requested {requested_method} MFA method"
                    )

                if otp_loc:
                    method_selection_pending = None
                    mfa_method_pending_until = 0.0

                # Step 2: account selection / alternate account
                if _page_has_text(["Pick an account", "issue looking up your account"]):
                    cached_account_selected = bool(
                        username and _click_account_tile(username)
                    )
                    if cached_account_selected:
                        sensitive_submission_started = (
                            _latch_sensitive_cached_account_selection(
                                sensitive_submission_started,
                                cached_account_selected,
                            )
                        )
                        _report_progress("cached-account-selected")
                        submitted_at = time.monotonic()
                        _arm_submission_wait(
                            "cached-account-selection",
                            submitted_at,
                        )
                        _interruptible_pause(0.25)
                        continue
                    elif _click_action([
                        "Use another account",
                        "Sign in with another account",
                        "Use a different account",
                        "Add another account",
                        "Mit einem anderen Konto anmelden",
                        "Anderes Konto verwenden",
                    ]):
                        progressed = True
                    elif _click_action(["Next", "Weiter"]):
                        progressed = True
                    elif _click_known_ids(["idSIButton9"]):
                        progressed = True
                else:
                    cached_account_selected = bool(
                        username and _click_account_tile(username)
                    )
                    if cached_account_selected:
                        sensitive_submission_started = (
                            _latch_sensitive_cached_account_selection(
                                sensitive_submission_started,
                                cached_account_selected,
                            )
                        )
                        _report_progress("cached-account-selected")
                        submitted_at = time.monotonic()
                        _arm_submission_wait(
                            "cached-account-selection",
                            submitted_at,
                        )
                        _interruptible_pause(0.25)
                        continue

                    if not progressed:
                        if _click_action([
                            "Use another account",
                            "Sign in with another account",
                            "Use a different account",
                            "Add another account",
                            "Mit einem anderen Konto anmelden",
                            "Anderes Konto verwenden",
                        ]):
                            progressed = True

                # Step 3: username field (prefer explicit "Use another account" if no field yet)
                if username and (adfs_mode or not filled_username):
                    user_loc = (
                        _find_usable_input_by_ids(["userNameInput", "username", "loginfmt", "i0116", "identifierId", "email"])
                        or _find_usable_input_by_labels(["Benutzername", "Benutzer-ID", "Benutzer ID", "User name", "Username", "E-Mail", "Email"])
                        or _find_best_input("username")
                    )
                    if user_loc:
                        pass_loc = _find_best_input("password")
                        pass_present = pass_loc is not None
                        try:
                            current_value = _normalize_text(user_loc.input_value())
                        except Exception:
                            current_value = ""
                        try:
                            if adfs_mode or username.lower() not in current_value:
                                user_loc.fill(username)
                            filled_username = True
                            progressed = True
                            if not pass_present:
                                form_submitted = _submit_owned_form(
                                    user_loc,
                                    [
                                        "Next",
                                        "Weiter",
                                        "Continue",
                                        "Suivant",
                                        "Avanti",
                                    ],
                                    ["idSIButton9"],
                                    action_name="username submission",
                                )
                                if form_submitted:
                                    submitted_form_kind = "username"
                                    _report_progress("username-submitted")
                        except RuntimeError:
                            raise
                        except Exception:
                            pass
                    else:
                        if _click_action(["Use another account", "Sign in with another account"]):
                            progressed = True

                # Microsoft resolves the account with GetCredentialType before
                # replacing the username panel. Never inspect or submit a
                # password control in the same loop as that asynchronous click.
                if form_submitted and submitted_form_kind == "username":
                    submitted_at = time.monotonic()
                    _arm_submission_wait("username", submitted_at)
                    _interruptible_pause(0.25)
                    continue

                # Step 4: password field
                if (
                    password
                    and (adfs_mode or not filled_password)
                    and not sensitive_action_ledger.dispatched("password")
                    and password_action_attempts == 0
                ):
                    pass_loc = usable_password_input
                    if pass_loc:
                        if gp_initial_password_observation_pending:
                            _report_progress(
                                "gp-initial-password-observation"
                            )
                            _interruptible_pause(0.1)
                            continue
                        if gp_password_navigation_pending:
                            _report_progress("gp-password-navigation-pending")
                            _interruptible_pause(0.1)
                            continue
                        if not _password_form_hydrated(pass_loc, protocol):
                            password_input_ready_since = 0.0
                            password_input_identity = None
                            _report_progress("password-form-hydrating")
                            _interruptible_pause(0.1)
                            continue
                        password_now = time.monotonic()
                        current_password_identity = _form_control_identity(pass_loc)
                        password_control_identity_this_loop = (
                            current_password_identity
                        )
                        if (
                            password_input_ready_since <= 0.0
                            or (
                                current_password_identity is not None
                                and current_password_identity
                                != password_input_identity
                            )
                        ):
                            password_input_identity = current_password_identity
                            password_input_ready_since = password_now
                            _interruptible_pause(0.1)
                            continue
                        if (
                            password_now - password_input_ready_since
                            < MICROSOFT_PASSWORD_STABILITY_SECONDS
                        ):
                            _interruptible_pause(0.1)
                            continue
                        gp_password_stage_authorization = (
                            password_discovery_authorized_client_stage
                            or gp_current_password_stage_authorization
                        )
                        if gp_password_stage_authorization is not None:
                            password_control_identity_this_loop = (
                                gp_password_stage_authorization.control_identity
                            )
                        password_entry_started = False
                        try:
                            if (
                                password_discovery_completed
                                and password_discovery_authorized_taint_generation
                                is not None
                            ):
                                if (
                                    sensitive_dispatch_evidence.credential_taint_generation
                                    != password_discovery_authorized_taint_generation
                                ):
                                    sensitive_action_ledger.record("password")
                                    raise _SensitiveActionUncertainError(
                                        "A credential request appeared after password "
                                        "discovery; refusing another password action"
                                    )
                            if gp_password_stage_authorization is not None:
                                try:
                                    _validate_gp_client_password_stage(
                                        pass_loc,
                                        gp_password_stage_authorization,
                                        require_empty=True,
                                    )
                                except _SensitiveActionUncertainError:
                                    # No credential has been entered yet. A
                                    # late telemetry/navigation/DOM change is
                                    # safe to observe again from a new frozen
                                    # stage instead of failing the activation.
                                    password_input_ready_since = 0.0
                                    password_input_identity = None
                                    _report_progress(
                                        "gp-password-stage-revalidating"
                                    )
                                    _interruptible_pause(0.1)
                                    continue
                            lookup_generation_before = (
                                microsoft_credential_lookup.generation
                            )
                            password_lookup_generation_before_this_loop = (
                                lookup_generation_before
                            )
                            (
                                dispatch_generation_before,
                                safe_navigation_generation_before,
                                credential_taint_generation_before,
                                document_generation_before,
                                main_navigation_request_generation_before,
                                write_request_generation_before,
                                outbound_request_generation_before,
                                navigation_pending_count_before,
                                federated_safe_navigation_generation_before,
                                unsafe_write_request_generation_before,
                            ) = (
                                sensitive_dispatch_evidence.transition_snapshot()
                            )
                            password_evidence_baseline_this_loop = (
                                dispatch_generation_before,
                                safe_navigation_generation_before,
                                credential_taint_generation_before,
                                document_generation_before,
                                main_navigation_request_generation_before,
                                write_request_generation_before,
                                outbound_request_generation_before,
                                navigation_pending_count_before,
                                federated_safe_navigation_generation_before,
                                unsafe_write_request_generation_before,
                            )
                            if _password_entry_uses_key_events(protocol):
                                password_entry_started = True
                                _enter_password_value(pass_loc, password, protocol)
                            elif adfs_mode or _input_value_empty(pass_loc):
                                password_entry_started = True
                                _enter_password_value(pass_loc, password, protocol)
                            if gp_password_stage_authorization is not None:
                                _validate_gp_client_password_stage(
                                    pass_loc,
                                    gp_password_stage_authorization,
                                    require_empty=False,
                                )
                            if (
                                sensitive_dispatch_evidence.credential_taint_generation
                                > credential_taint_generation_before
                            ):
                                sensitive_action_ledger.record("password")
                                sensitive_submission_started = True
                                raise _SensitiveActionUncertainError(
                                    "Password entry triggered a credential request; "
                                    "refusing an additional submit gesture"
                                )
                            if (
                                password_discovery_completed
                                and password_discovery_authorized_client_stage
                                is None
                            ):
                                password_discovery_authorized_taint_generation = None
                            password_entered_this_loop = True
                            progressed = True
                            form_submitted = _submit_password(
                                pass_loc,
                                authorization=(
                                    gp_password_stage_authorization
                                ),
                            )
                            if form_submitted:
                                password_discovery_authorized_taint_generation = None
                                password_discovery_authorized_client_stage = None
                                password_action_attempts = 1
                                password_action_pending_since = time.monotonic()
                                password_action_dispatch_generation = (
                                    dispatch_generation_before
                                )
                                password_action_safe_navigation_generation = (
                                    safe_navigation_generation_before
                                )
                                password_action_federated_safe_navigation_generation = (
                                    federated_safe_navigation_generation_before
                                )
                                password_action_credential_taint_generation = (
                                    credential_taint_generation_before
                                )
                                password_action_document_generation = (
                                    document_generation_before
                                )
                                password_action_main_navigation_request_generation = (
                                    main_navigation_request_generation_before
                                )
                                password_action_write_request_generation = (
                                    write_request_generation_before
                                )
                                password_action_unsafe_write_request_generation = (
                                    unsafe_write_request_generation_before
                                )
                                password_action_outbound_request_generation = (
                                    outbound_request_generation_before
                                )
                                password_action_navigation_pending_count = (
                                    navigation_pending_count_before
                                )
                                if gp_password_stage_authorization is not None:
                                    password_action_control_identity = (
                                        gp_password_stage_authorization.control_identity
                                    )
                                    password_action_control_origin = (
                                        gp_password_stage_authorization.control_origin
                                    )
                                    password_action_top_origin = (
                                        gp_password_stage_authorization.top_origin
                                    )
                                    password_action_form_action_origin = (
                                        gp_password_stage_authorization.form_action_origin
                                    )
                                    password_action_form_signature = (
                                        gp_password_stage_authorization.form_signature
                                    )
                                    password_action_form_method = (
                                        gp_password_stage_authorization.form_method
                                    )
                                else:
                                    password_action_control_identity = (
                                        current_password_identity
                                    )
                                    password_action_control_origin = (
                                        password_security.https_origin
                                    )
                                    password_action_top_origin = (
                                        current_top_origin
                                    )
                                    password_action_form_action_origin = (
                                        password_security.form_action_origin
                                    )
                                    password_action_form_signature = (
                                        password_security.form_signature
                                    )
                                    password_action_form_method = (
                                        password_security.form_method
                                    )
                                password_input_ready_since = 0.0
                                password_input_identity = None
                                filled_password = True
                                password_submission_lookup_generation = (
                                    lookup_generation_before
                                )
                                password_submission_classify_until = (
                                    _password_submission_classification_deadline(
                                        protocol,
                                        password_discovery_completed,
                                        time.monotonic(),
                                        deadline,
                                    )
                                )
                                submitted_form_kind = (
                                    "password"
                                    if (
                                        _password_discovery_supported(protocol)
                                        and password_discovery_completed
                                    )
                                    else "password-unknown"
                                )
                                _report_progress("password-action-submitted")
                        except _SensitiveActionUncertainError:
                            raise
                        except Exception as exc:
                            if password_entry_started:
                                sensitive_action_ledger.record("password")
                                sensitive_submission_started = True
                                raise _SensitiveActionUncertainError(
                                    "Password entry did not complete cleanly; "
                                    "refusing to enter or submit it again"
                                ) from exc
                    else:
                        password_input_ready_since = 0.0
                        password_input_identity = None

                if form_submitted:
                    submitted_at = time.monotonic()
                    _interruptible_pause(0.25)
                    armed_form_kind = submitted_form_kind or "generic"
                    if armed_form_kind == "password-unknown":
                        _refresh_rendered_ui_snapshot()
                        password_action_ui_fingerprint = (
                            _auth_ui_fingerprint()
                        )
                    _arm_submission_wait(
                        armed_form_kind,
                        submitted_at,
                        submitted_password_identity=(
                            password_control_identity_this_loop
                            if armed_form_kind
                            in {"password", "password-unknown"}
                            else None
                        ),
                    )
                    continue

                # ADFS direct submit fallback (JS-based)
                if (
                    adfs_mode
                    and username
                    and password
                    and not progressed
                    and adfs_submit_attempts < 3
                    and not sensitive_action_ledger.dispatched("password")
                ):
                    try:
                        result = page.evaluate(
                            """(creds) => {
                                const user = document.getElementById('userNameInput') || document.querySelector('input[name="UserName"]');
                                const pass = document.getElementById('passwordInput') || document.querySelector('input[name="Password"]');
                                if (user) user.value = creds.user;
                                if (pass) pass.value = creds.pass;
                                const btn = document.getElementById('submitButton') || document.querySelector('input[type="submit"]');
                                if (btn) btn.click();
                                return {hasUser: !!user, hasPass: !!pass, hasBtn: !!btn};
                            }""",
                            {"user": username, "pass": password},
                        )
                        adfs_submit_attempts += 1
                        if result.get("hasUser") or result.get("hasPass") or result.get("hasBtn"):
                            progressed = True
                            if result.get("hasBtn"):
                                submitted_at = time.monotonic()
                                _arm_submission_wait(
                                    "password",
                                    submitted_at,
                                    submitted_password_identity=(
                                        password_input_identity
                                    ),
                                )
                                _interruptible_pause(0.25)
                                continue
                    except Exception as exc:
                        raise _SensitiveActionUncertainError(
                            "ADFS password submission outcome is uncertain; refusing to retry"
                        ) from exc

                # Step 5: OTP / MFA
                totp_submitted = False
                waiting_for_fresh_totp = False
                if retained_submitted_otp and otp_loc is not None:
                    _interruptible_pause(0.1)
                    continue
                if totp_secret and auto_totp and not totp_disabled_for_attempt:
                    if otp_loc:
                        # The loop performs several Microsoft-state probes after
                        # first finding the field. Re-resolve it immediately
                        # before use because an nth() locator can otherwise move
                        # to a hidden session input when the panel hydrates.
                        otp_loc = _find_otp_input()
                        if otp_loc is None:
                            otp_input_reported = False
                            _interruptible_pause(0.1)
                            continue
                        otp_control_identity_this_loop = (
                            _form_control_identity(otp_loc)
                        )
                        otp_submission_control_progress = (
                            _otp_control_is_progress(
                                otp_control_identity_this_loop,
                                submitted_otp_control_identity,
                                otp_control_submitted,
                            )
                        )
                        if not otp_input_reported:
                            _report_progress("mfa-totp-input-found")
                            otp_input_reported = True
                        try:
                            totp_counter = int(time.time() // 30)
                            if _should_submit_totp_for_control(
                                otp_submission_control_progress,
                                last_totp_counter,
                                totp_counter,
                            ):
                                if (
                                    totp_submission_attempts
                                    >= MICROSOFT_TOTP_MAX_SUBMISSIONS
                                ):
                                    raise RuntimeError(
                                        "Microsoft TOTP form attempted more than its "
                                        "single allowed submission"
                                    )
                                # Avoid submitting a code that will expire while the
                                # Microsoft form is processing it.
                                valid_for = seconds_until_totp_rotation()
                                if valid_for < 5.0:
                                    _interruptible_pause(valid_for + 0.1)
                                    totp_counter = int(time.time() // 30)
                                if _should_submit_totp_for_control(
                                    otp_submission_control_progress,
                                    last_totp_counter,
                                    totp_counter,
                                ):
                                    totp_code = generate_totp(totp_secret)
                                    if not re.fullmatch(r"[0-9]{6,8}", totp_code or ""):
                                        raise ValueError("invalid generated TOTP")
                                    if not _fill_totp_code_control(
                                        otp_loc,
                                        totp_code,
                                    ):
                                        otp_input_reported = False
                                        _report_progress(
                                            "mfa-totp-control-replaced"
                                        )
                                        _interruptible_pause(0.1)
                                        continue
                                    totp_error_before_submit = _totp_error_signature(otp_loc)
                                    progressed = True
                                    submitted = _submit_otp(otp_loc)
                                    if not submitted:
                                        raise RuntimeError("Could not submit the Microsoft verification code form")
                                    if submitted:
                                        last_totp_counter = totp_counter
                                        totp_submission_attempts += 1
                                        totp_submitted = True
                                        _report_progress("mfa-totp-submitted")
                                else:
                                    waiting_for_fresh_totp = True
                            else:
                                waiting_for_fresh_totp = True
                        except RuntimeError:
                            raise
                        except Exception as exc:
                            raise RuntimeError(
                                "Could not generate or submit the configured TOTP code"
                            ) from exc
                    else:
                        otp_input_reported = False

                if totp_submitted:
                    submitted_at = time.monotonic()
                    _arm_submission_wait(
                        "totp",
                        submitted_at,
                        submitted_otp_identity=otp_control_identity_this_loop,
                    )
                    _interruptible_pause(0.25)
                    continue

                if waiting_for_fresh_totp:
                    # Do not let generic Continue/Next fallbacks resubmit the
                    # same code while Microsoft is still processing it.
                    _interruptible_pause(0.1)
                    continue

                # Microsoft can present a localized "Stay signed in?" page
                # after TOTP succeeds. Accepting it is appropriate for the
                # plugin's dedicated persistent browser profile and avoids a
                # full login on the next connection.
                if _page_has_text(list(MICROSOFT_KMSI_MARKERS)):
                    if sensitive_action_ledger.dispatched("kmsi"):
                        _interruptible_pause(0.1)
                        continue
                    kmsi_submitted = _click_action(
                        list(MICROSOFT_KMSI_ACCEPT_LABELS),
                        sensitive=True,
                        action_name="Microsoft stay-signed-in acceptance",
                    )
                    if not kmsi_submitted:
                        kmsi_submitted = _click_known_ids(
                            [
                                "idSIButton9",
                                "acceptButton",
                                "primaryButton",
                            ],
                            sensitive=True,
                            action_name="Microsoft stay-signed-in acceptance",
                        )
                    if not kmsi_submitted:
                        kmsi_submitted = _click_first_selector(
                            [
                                "button[type='submit']",
                                "input[type='submit']",
                            ],
                            sensitive=True,
                            action_name="Microsoft stay-signed-in acceptance",
                        )
                    if kmsi_submitted:
                        _report_progress("microsoft-kmsi-accepted")
                        submitted_at = time.monotonic()
                        _arm_submission_wait("kmsi", submitted_at)
                        _interruptible_pause(0.25)
                        continue

                # Fallback clicks for common prompts
                if _username_fallback_wait_required(
                    username,
                    filled_username,
                    usable_password_input is not None,
                ):
                    # Microsoft can render the Next button before hydrating its
                    # username input.  Clicking it in that gap submits an empty
                    # account name and creates a false credential failure.
                    _interruptible_pause(0.1)
                    continue
                if _click_action(["Use your password instead", "Use password instead"]):
                    last_progress_time = time.monotonic()
                    _interruptible_pause(0.25)
                    continue
                if (
                    usable_password_input is not None
                    and (
                        password_action_attempts > 0
                        or sensitive_action_ledger.dispatched("password")
                    )
                ):
                    # Never let a generic page-level button resubmit a retained
                    # or replacement password form.
                    _interruptible_pause(0.1)
                    continue
                if password_discovery_authorized_client_stage is not None:
                    raise _SensitiveActionUncertainError(
                        "The authorized client-side password stage lost its exact "
                        "owning form; refusing a generic submit fallback"
                    )
                fallback_password_submission = bool(
                    password_entered_this_loop
                    and password_action_attempts == 0
                    and not sensitive_action_ledger.dispatched("password")
                )
                fallback_evidence_baseline = (
                    password_evidence_baseline_this_loop
                    or sensitive_dispatch_evidence.transition_snapshot()
                )
                (
                    fallback_dispatch_generation_before,
                    fallback_safe_navigation_generation_before,
                    fallback_credential_taint_generation_before,
                    fallback_document_generation_before,
                    fallback_main_navigation_request_generation_before,
                    fallback_write_request_generation_before,
                    fallback_outbound_request_generation_before,
                    fallback_navigation_pending_count_before,
                    fallback_federated_safe_navigation_generation_before,
                    fallback_unsafe_write_request_generation_before,
                ) = fallback_evidence_baseline
                if (
                    fallback_password_submission
                    and sensitive_dispatch_evidence.credential_taint_generation
                    > fallback_credential_taint_generation_before
                ):
                    sensitive_action_ledger.record("password")
                    sensitive_submission_started = True
                    raise _SensitiveActionUncertainError(
                        "A credential request appeared before the password "
                        "submit fallback; refusing an additional gesture"
                    )
                fallback_submitted = _click_action(
                    [
                        "OK",
                        "Continue",
                        "Next",
                        "Weiter",
                    ],
                    sensitive=fallback_password_submission,
                    action_name="password submission",
                )
                if not fallback_submitted:
                    fallback_submitted = _click_known_ids(
                        ["idSIButton9", "submitButton"],
                        sensitive=fallback_password_submission,
                        action_name="password submission",
                    )
                if fallback_submitted:
                    submitted_at = time.monotonic()
                    fallback_form_kind = (
                        "password-unknown"
                        if fallback_password_submission
                        else "generic"
                    )
                    if fallback_password_submission:
                        password_action_attempts = 1
                        password_action_pending_since = submitted_at
                        password_action_dispatch_generation = (
                            fallback_dispatch_generation_before
                        )
                        password_action_safe_navigation_generation = (
                            fallback_safe_navigation_generation_before
                        )
                        password_action_federated_safe_navigation_generation = (
                            fallback_federated_safe_navigation_generation_before
                        )
                        password_action_credential_taint_generation = (
                            fallback_credential_taint_generation_before
                        )
                        password_action_document_generation = (
                            fallback_document_generation_before
                        )
                        password_action_main_navigation_request_generation = (
                            fallback_main_navigation_request_generation_before
                        )
                        password_action_write_request_generation = (
                            fallback_write_request_generation_before
                        )
                        password_action_unsafe_write_request_generation = (
                            fallback_unsafe_write_request_generation_before
                        )
                        password_action_outbound_request_generation = (
                            fallback_outbound_request_generation_before
                        )
                        password_action_navigation_pending_count = (
                            fallback_navigation_pending_count_before
                        )
                        password_submission_lookup_generation = (
                            password_lookup_generation_before_this_loop
                            if password_lookup_generation_before_this_loop
                            is not None
                            else microsoft_credential_lookup.generation
                        )
                        password_submission_classify_until = (
                            _password_submission_classification_deadline(
                                protocol,
                                password_discovery_completed,
                                submitted_at,
                                deadline,
                            )
                        )
                        password_action_control_identity = (
                            password_control_identity_this_loop
                        )
                        password_action_control_origin = (
                            password_security.https_origin
                        )
                        password_action_top_origin = current_top_origin
                        password_action_form_action_origin = (
                            password_security.form_action_origin
                        )
                        password_action_form_signature = (
                            password_security.form_signature
                        )
                        password_action_form_method = (
                            password_security.form_method
                        )
                        _interruptible_pause(0.25)
                        _refresh_rendered_ui_snapshot()
                        password_action_ui_fingerprint = (
                            _auth_ui_fingerprint()
                        )
                    _arm_submission_wait(
                        fallback_form_kind,
                        submitted_at,
                        submitted_password_identity=(
                            password_control_identity_this_loop
                            if fallback_password_submission
                            else None
                        ),
                    )
                    if not fallback_password_submission:
                        _interruptible_pause(0.25)
                    continue
                progressed = progressed or fallback_submitted

                if progressed:
                    last_progress_time = time.monotonic()
                    try:
                        remaining_ms = _remaining_timeout_ms(deadline)
                        if remaining_ms > 0:
                            page.wait_for_load_state(
                                "domcontentloaded",
                                timeout=min(1500, remaining_ms),
                            )
                    except Exception:
                        pass
                    _wait_until_ready(0.2)
                else:
                    now = time.monotonic()
                    if now - last_wait_report_time >= 5.0:
                        _report_progress(
                            f"waiting host={_page_host()} ui={'yes' if _auth_ui_ready() else 'no'}"
                        )
                        last_wait_report_time = now
                    if (
                        blank_login_reloads < 2
                        and "login.microsoftonline.com" in page.url.lower()
                        and not _auth_ui_ready()
                        and time.monotonic() - last_progress_time > 8
                    ):
                        try:
                            blank_login_reloads += 1
                            last_progress_time = time.monotonic()
                            _report_progress("microsoft-blank-page-reload")
                            if debug:
                                print("    [DEBUG] Microsoft login page stayed blank; reloading")
                            remaining_ms = _remaining_timeout_ms(deadline)
                            if remaining_ms <= 0:
                                break
                            page.reload(timeout=min(15000, remaining_ms), wait_until="domcontentloaded")
                            _wait_until_ready(1.0)
                            continue
                        except Exception as reload_error:
                            if debug:
                                print(f"    [DEBUG] Microsoft login reload failed: {reload_error}")
                    _wait_until_ready(0.1)

            if (
                credential_inspection_deadline is not None
                and not _auth_capture_complete()
                and not _is_vpn_url(page.url)
            ):
                _raise_profile_stall(
                    "Could not inspect the sign-in page after submission; "
                    "the authentication outcome is uncertain",
                )

            if (
                form_submission_fingerprint is not None
                and not _auth_capture_complete()
                and not _is_vpn_url(page.url)
            ):
                _raise_profile_stall(
                    "Microsoft did not complete the submitted sign-in within "
                    "the adaptive processing limit",
                )

            remaining_ms = _remaining_timeout_ms(deadline)
            if remaining_ms > 0:
                _report_progress(f"waiting-for-vpn-callback host={_page_host()}")
                _wait_for_vpn_callback(remaining_ms)
            _raise_if_cancelled()
            if (
                not _auth_capture_complete()
                and (
                    protocol == "anyconnect"
                    or not _is_vpn_url(page.url)
                )
            ):
                _raise_profile_stall(
                    "SAML authentication did not complete before the protocol deadline",
                )

            # Collect cookies
            all_cookies = context.cookies()
            vpn_cookies = _collect_vpn_cookies()

            vpn_cookies = _merge_saml_artifacts(
                vpn_cookies,
                saml_result,
                protocol,
                gp_prelogin_cookie,
                gp_gateway_ip,
            )

            # Avoid returning only helper metadata without a real auth artifact
            if set(vpn_cookies.keys()) == {"_gateway_ip"}:
                vpn_cookies = {}
            if protocol == "anyconnect" and not _has_usable_auth_artifact(vpn_cookies):
                _report_progress(f"authentication-incomplete host={_page_host()}")
                if debug:
                    print(
                        "    [DEBUG] Ignoring incomplete AnyConnect auth result "
                        f"(cookies={list(vpn_cookies.keys())})"
                    )
                    try:
                        _secure_screenshot("/tmp/vpn-auth-incomplete.png")
                        print("    [DEBUG] Screenshot: /tmp/vpn-auth-incomplete.png")
                    except Exception:
                        pass
                vpn_cookies = {}

            if debug:
                final_url_parts = urllib.parse.urlsplit(page.url)
                debug_out = {
                    "vpn_server": vpn_server,
                    "vpn_server_host": vpn_server_host,
                    "vpn_server_netloc": vpn_server_netloc,
                    "vpn_server_ip": vpn_server_ip,
                    "final_host": final_url_parts.hostname or "unknown",
                    "final_path": final_url_parts.path or "/",
                    "cookies": list(vpn_cookies.keys()),
                    "cookie_domains": sorted({c.get("domain", "") for c in all_cookies}),
                    "saml_response": bool(saml_result["saml_response"]),
                    "prelogin_cookie": bool(vpn_cookies.get("prelogin-cookie")),
                }
                try:
                    with open("/tmp/ms-sso-vpn-auth-debug.json", "w") as f:
                        json.dump(debug_out, f, indent=2)
                    os.chmod("/tmp/ms-sso-vpn-auth-debug.json", 0o600)
                except Exception:
                    pass

            _close_context()
            return vpn_cookies
        except Exception as e:
            if debug:
                try:
                    _secure_screenshot("/tmp/vpn-auth-error.png")
                except Exception:
                    pass
            _close_context()
            if sensitive_submission_started and not _cancelled() and not isinstance(e, SamlSensitiveActionError):
                raise SamlSensitiveActionError(str(e)) from e
            raise


def do_saml_auth_with_recovery(
    vpn_server: str,
    username: str,
    password: str,
    totp_secret: Optional[str] = None,
    protocol: str = "anyconnect",
    auto_totp: bool = True,
    headless: bool = True,
    debug: bool = False,
    vpn_server_ip: Optional[str] = None,
    disable_browser_session_cache: bool = False,
    gp_os_version: Optional[str] = None,
    gp_auth_interface: str = "portal",
    cancel_callback: Optional[Callable[[], bool]] = None,
    progress_callback: Optional[Callable[[str], None]] = None,
    mfa_preference: Optional[str] = None,
    notification_helper_path: Optional[str] = None,
    number_match_callback: Optional[Callable[[str], bool]] = None,
):
    """Repair one cached AnyConnect UI stall before any sensitive action.

    Authentication errors after a password, TOTP, or Authenticator request are
    deliberately not retried. GlobalProtect retains its original prelogin flow.
    """
    auth_kwargs = dict(locals())
    # Explicit TOTP authentication is self-contained: a retained Microsoft page
    # adds no value and can hold a half-finished sign-in after cancellation.
    effective_mfa = str(mfa_preference or os.environ.get("MS_SSO_MFA_PREFERENCE") or "auto").strip().lower()
    cache_enabled = os.environ.get("MS_SSO_ENABLE_BROWSER_SESSION_CACHE", "").strip().lower() in {
        "1", "true", "yes", "on"
    }
    if protocol == "anyconnect" and effective_mfa == "totp" and totp_secret and not cache_enabled:
        auth_kwargs["disable_browser_session_cache"] = True
    try:
        return do_saml_auth(**auth_kwargs)
    except SamlUiStalledError:
        cache_disabled = str(auth_kwargs["disable_browser_session_cache"]).strip().lower() in {
            "1", "true", "yes", "on"
        } or os.environ.get("MS_SSO_DISABLE_BROWSER_SESSION_CACHE", "").strip().lower() in {
            "1", "true", "yes", "on"
        }
        if protocol != "anyconnect" or cache_disabled:
            raise
        if cancel_callback and cancel_callback():
            raise
        if progress_callback:
            try:
                progress_callback("retrying-with-clean-browser-session")
            except Exception:
                pass
        auth_kwargs["disable_browser_session_cache"] = True
        return do_saml_auth(**auth_kwargs)
