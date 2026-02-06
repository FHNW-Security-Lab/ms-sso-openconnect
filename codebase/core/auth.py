"""SAML authentication via headless Playwright with heuristic form handling."""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import ssl
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from typing import Optional

from playwright.sync_api import sync_playwright

from .totp import generate_totp


def _detect_desktop_user() -> Optional[str]:
    """Detect the active desktop user when running as root."""
    import glob
    import subprocess

    for user_dir in glob.glob("/run/user/*"):
        try:
            uid = int(os.path.basename(user_dir))
            if uid >= 1000:
                import pwd
                user = pwd.getpwuid(uid).pw_name
                session_dir = f"/home/{user}/.cache/ms-sso-openconnect/browser-session"
                if os.path.isdir(session_dir):
                    return user
        except Exception:
            continue

    try:
        result = subprocess.run(
            ["loginctl", "list-sessions", "--no-legend"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                parts = line.split()
                if len(parts) >= 3:
                    session_id = parts[0]
                    user = parts[2]
                    type_result = subprocess.run(
                        ["loginctl", "show-session", session_id, "-p", "Type"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    if "x11" in type_result.stdout or "wayland" in type_result.stdout:
                        return user
    except Exception:
        pass

    try:
        result = subprocess.run(["who"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                if "(:0)" in line or "(:" in line:
                    return line.split()[0]
    except Exception:
        pass

    return None


def _get_gp_prelogin(server: str, debug: bool = False) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Get prelogin-cookie and SAML request for GlobalProtect."""
    url = f"https://{server}/global-protect/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Linux"
    retry_env = os.environ.get("MS_SSO_GP_PRELOGIN_RETRIES", "3").strip()
    delay_env = os.environ.get("MS_SSO_GP_PRELOGIN_DELAY", "2").strip()
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
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "PAN GlobalProtect")
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                if resp.status != 200:
                    return None, None, None
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
):
    """Complete Microsoft SAML authentication and return cookies."""
    vpn_server_raw = vpn_server
    try:
        parsed_server = urllib.parse.urlparse(vpn_server_raw if "://" in vpn_server_raw else f"//{vpn_server_raw}")
        vpn_server_host = parsed_server.hostname or vpn_server_raw
        vpn_server_netloc = parsed_server.netloc or vpn_server_raw
    except Exception:
        vpn_server_host = vpn_server_raw
        vpn_server_netloc = vpn_server_raw

    vpn_url = f"https://{vpn_server_netloc}"

    gp_prelogin_cookie, gp_saml_request, gp_gateway_ip = None, None, None
    if protocol == "gp":
        print("  [1/6] Getting GlobalProtect prelogin info...")
        gp_prelogin_cookie, gp_saml_request, gp_gateway_ip = _get_gp_prelogin(vpn_server, debug)
        if debug:
            print(f"    [DEBUG] prelogin-cookie: {gp_prelogin_cookie[:20] if gp_prelogin_cookie else None}...")
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
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = f"{home}/.cache/ms-playwright"
        except Exception:
            pass
    else:
        for pw_path in ["/var/cache/ms-playwright", "/opt/ms-playwright", "/usr/share/ms-playwright"]:
            if os.path.isdir(pw_path):
                os.environ["PLAYWRIGHT_BROWSERS_PATH"] = pw_path
                break

    with sync_playwright() as p:
        session_tmp_dir = None
        if force_ephemeral_browser_session:
            session_tmp_dir = tempfile.mkdtemp(prefix="ms-sso-openconnect-auth-")
            cache_dir = session_tmp_dir
            if debug:
                print(f"    [DEBUG] Using ephemeral browser session dir: {cache_dir}")
        elif real_user != "root":
            cache_dir = os.path.join(home, ".cache", "ms-sso-openconnect", "browser-session")
        else:
            cache_dir = None
            for base in ["/var/cache", "/tmp"]:
                test_dir = os.path.join(base, "ms-sso-openconnect", "browser-session")
                try:
                    os.makedirs(test_dir, exist_ok=True)
                    test_file = os.path.join(test_dir, ".write-test")
                    with open(test_file, "w") as f:
                        f.write("test")
                    os.remove(test_file)
                    cache_dir = test_dir
                    break
                except Exception:
                    continue
            if not cache_dir:
                cache_dir = f"/tmp/ms-sso-openconnect-{os.getpid()}/browser-session"
        os.makedirs(cache_dir, exist_ok=True)

        context = p.chromium.launch_persistent_context(
            cache_dir,
            headless=headless,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        )
        page = context.pages[0] if context.pages else context.new_page()

        def _close_context() -> None:
            try:
                context.close()
            finally:
                if session_tmp_dir:
                    shutil.rmtree(session_tmp_dir, ignore_errors=True)

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

        vpn_request_event = threading.Event()

        def _wait_for_vpn_callback(timeout_ms: int = 60000) -> None:
            if _is_vpn_url(page.url):
                return
            if saml_result.get("saml_response") or saml_result.get("prelogin_cookie") or saml_result.get("portal_userauthcookie"):
                return
            deadline = time.time() + (timeout_ms / 1000.0)
            while time.time() < deadline:
                if saml_result.get("saml_response") or saml_result.get("prelogin_cookie") or saml_result.get("portal_userauthcookie"):
                    return
                if _is_vpn_url(page.url):
                    return
                if vpn_request_event.wait(timeout=0.25):
                    return

        def handle_request(request):
            if _is_vpn_url(request.url):
                vpn_request_event.set()
                if debug:
                    print(f"    [DEBUG] Request to VPN: {request.url[:80]}...")
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
            if not _is_vpn_url(response.url):
                return
            try:
                headers = response.headers
                if debug:
                    print(f"    [DEBUG] Response from VPN: {response.url[:80]}... status={response.status}")
                    for h in ["prelogin-cookie", "saml-username", "portal-userauthcookie", "set-cookie", "location"]:
                        if h in headers:
                            val = headers[h][:80] if len(headers[h]) > 80 else headers[h]
                            print(f"    [DEBUG] Header {h}: {val}...")
                if "prelogin-cookie" in headers:
                    saml_result["prelogin_cookie"] = headers["prelogin-cookie"]
                if "saml-username" in headers:
                    saml_result["saml_username"] = headers["saml-username"]
                if "portal-userauthcookie" in headers:
                    saml_result["portal_userauthcookie"] = headers["portal-userauthcookie"]
            except Exception:
                pass

        page.on("request", handle_request)
        page.on("response", handle_response)

        def _find_visible_in_frames(selectors: list[str]):
            for frame in page.frames:
                for sel in selectors:
                    loc = frame.locator(sel)
                    try:
                        if loc.count() > 0 and loc.first.is_visible():
                            return loc.first
                    except Exception:
                        continue
            return None

        def _find_input_by_ids(ids: list[str]):
            for frame in page.frames:
                for element_id in ids:
                    try:
                        loc = frame.locator(f"#{element_id}")
                        if loc.count() > 0 and loc.first.is_visible():
                            return loc.first
                    except Exception:
                        continue
            return None

        def _find_input_by_labels(labels: list[str]):
            patterns = [re.compile(re.escape(label), re.IGNORECASE) for label in labels]
            for frame in page.frames:
                for pattern in patterns:
                    try:
                        loc = frame.get_by_label(pattern)
                        if loc.count() > 0 and loc.first.is_visible():
                            return loc.first
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
                    score += 2
                if input_type == "tel":
                    score += 2
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
            return best_loc

        def _input_value_empty(loc) -> bool:
            try:
                return not _normalize_text(loc.input_value())
            except Exception:
                return False

        def _click_action(labels: list[str]) -> bool:
            patterns = [re.compile(re.escape(label), re.IGNORECASE) for label in labels]
            for frame in page.frames:
                for pattern in patterns:
                    for role in ["button", "link"]:
                        try:
                            loc = frame.get_by_role(role, name=pattern)
                            if loc.count() > 0 and loc.first.is_visible():
                                loc.first.click()
                                return True
                        except Exception:
                            continue
                    try:
                        loc = frame.locator("input[type='submit']")
                        if loc.count() > 0:
                            for idx in range(min(loc.count(), 10)):
                                candidate = loc.nth(idx)
                                try:
                                    value = _normalize_text(candidate.get_attribute("value"))
                                    if value and pattern.search(value) and candidate.is_visible():
                                        candidate.click()
                                        return True
                                except Exception:
                                    continue
                    except Exception:
                        continue
                    try:
                        loc = frame.get_by_text(pattern, exact=False)
                        if loc.count() > 0 and loc.first.is_visible():
                            loc.first.click()
                            return True
                    except Exception:
                        continue
            return False

        def _click_known_ids(ids: list[str]) -> bool:
            for frame in page.frames:
                for element_id in ids:
                    try:
                        loc = frame.locator(f"#{element_id}")
                        if loc.count() > 0 and loc.first.is_visible():
                            loc.first.click()
                            return True
                    except Exception:
                        continue
            return False

        def _page_has_text(texts: list[str]) -> bool:
            for frame in page.frames:
                for t in texts:
                    try:
                        loc = frame.get_by_text(t, exact=False)
                        if loc.count() > 0:
                            return True
                    except Exception:
                        continue
            try:
                body_text = page.evaluate("() => document.body && document.body.innerText ? document.body.innerText : ''")
                body_lower = (body_text or "").lower()
                for t in texts:
                    if t.lower() in body_lower:
                        return True
            except Exception:
                pass
            return False

        def _is_adfs_page() -> bool:
            url = page.url.lower()
            if "adfs" in url and "/ls" in url:
                return True
            return _page_has_text(["ADFS", "user name", "username", "Sign in", "Anmelden"])

        def _goto_with_retries(url: str, timeout_ms: int = 60000) -> None:
            errors = []
            wait_targets = ["domcontentloaded", "load", "networkidle"]
            for attempt in range(3):
                for wait_until in wait_targets:
                    try:
                        page.goto(url, timeout=timeout_ms, wait_until=wait_until)
                        return
                    except Exception as exc:
                        errors.append(exc)
                        if "ERR_NETWORK_CHANGED" in str(exc):
                            if debug:
                                print("    [DEBUG] Page.goto hit ERR_NETWORK_CHANGED; retrying")
                            time.sleep(1)
                            continue
                time.sleep(1)
            raise errors[-1] if errors else Exception("Page.goto failed")

        def _click_first_text(texts: list[str]):
            for frame in page.frames:
                for t in texts:
                    loc = frame.get_by_text(t, exact=False)
                    try:
                        if loc.count() > 0 and loc.first.is_visible():
                            loc.first.click()
                            return True
                    except Exception:
                        continue
            return False

        try:
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
            _goto_with_retries(start_url, timeout_ms=60000)

            if debug:
                page.screenshot(path="/tmp/vpn-step1-portal.png")
                print("    [DEBUG] Screenshot: /tmp/vpn-step1-portal.png")

            time.sleep(1)
            if _is_vpn_url(page.url):
                all_cookies = context.cookies()
                session_cookies = {}
                for c in all_cookies:
                    if c.get("value") and _cookie_domain_matches(c.get("domain", "")):
                        session_cookies[c["name"]] = c["value"]

                has_session = (
                    session_cookies.get("webvpn")
                    or session_cookies.get("SVPNCOOKIE")
                    or saml_result.get("saml_response")
                    or saml_result.get("prelogin_cookie")
                )
                if has_session:
                    print("  -> Already authenticated (SSO session valid)")
                    if saml_result["saml_response"]:
                        session_cookies["SAMLResponse"] = saml_result["saml_response"]
                    if saml_result["prelogin_cookie"]:
                        session_cookies["prelogin-cookie"] = saml_result["prelogin_cookie"]
                    if gp_prelogin_cookie and "prelogin-cookie" not in session_cookies:
                        session_cookies["prelogin-cookie"] = gp_prelogin_cookie
                    _close_context()
                    return session_cookies

            filled_username = False
            filled_password = False
            filled_otp = False
            adfs_submit_attempts = 0

            timeout_seconds = int(os.environ.get("MS_SSO_SAML_TIMEOUT", "90"))
            if protocol == "gp":
                timeout_seconds = max(timeout_seconds, 180)
            deadline = time.time() + timeout_seconds
            while time.time() < deadline:
                if saml_result.get("saml_response") or saml_result.get("prelogin_cookie") or saml_result.get("portal_userauthcookie"):
                    break
                if _is_vpn_url(page.url):
                    break

                progressed = False
                adfs_mode = _is_adfs_page()

                # Step 2: account selection / alternate account
                if _page_has_text(["Pick an account", "issue looking up your account"]):
                    if _click_action([
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
                    elif username:
                        candidates = [username]
                        if "@" in username:
                            local_part, domain_part = username.split("@", 1)
                            candidates.append(local_part)
                            candidates.append(f"@{domain_part}")
                        for frame in page.frames:
                            for candidate in candidates:
                                try:
                                    loc = frame.get_by_text(candidate, exact=False)
                                    if loc.count() > 0 and loc.first.is_visible():
                                        loc.first.click()
                                        progressed = True
                                        _click_action(["Next", "Weiter"])
                                        _click_known_ids(["idSIButton9"])
                                        break
                                except Exception:
                                    continue
                            if progressed:
                                break
                else:
                    if username:
                        for frame in page.frames:
                            try:
                                # Prefer exact account tile (email) over other UI text
                                loc = frame.get_by_text(username, exact=True)
                                if loc.count() > 0 and loc.first.is_visible():
                                    loc.first.click()
                                    progressed = True
                                    break
                            except Exception:
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
                        _find_input_by_ids(["userNameInput", "username", "loginfmt", "i0116", "identifierId", "email"])
                        or _find_input_by_labels(["Benutzername", "Benutzer-ID", "Benutzer ID", "User name", "Username", "E-Mail", "Email"])
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
                                _click_action(["Next", "Weiter", "Continue", "Suivant", "Avanti"])
                                _click_known_ids(["idSIButton9"])
                        except Exception:
                            pass
                    else:
                        if _click_action(["Use another account", "Sign in with another account"]):
                            progressed = True

                # Step 4: password field
                if password and (adfs_mode or not filled_password):
                    pass_loc = (
                        _find_input_by_ids(["passwordInput", "password", "i0118", "passwd", "Passwd"])
                        or _find_input_by_labels(["Kennwort", "Passwort", "Password", "Mot de passe"])
                        or _find_best_input("password")
                    )
                    if pass_loc:
                        try:
                            if adfs_mode or _input_value_empty(pass_loc):
                                pass_loc.fill(password)
                            filled_password = True
                            progressed = True
                            # Include German "Anmelden" label used by Unibas
                            _click_action(["Anmelden", "Sign in", "Connexion", "Accedi", "Continue", "Next"])
                            _click_known_ids(["idSIButton9", "submitButton"])
                            try:
                                pass_loc.press("Enter")
                            except Exception:
                                pass
                        except Exception:
                            pass

                # ADFS direct submit fallback (JS-based)
                if adfs_mode and username and password and not progressed and adfs_submit_attempts < 3:
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
                    except Exception:
                        pass

                # Step 5: OTP / MFA
                if totp_secret and auto_totp and not filled_otp:
                    otp_loc = (
                        _find_input_by_ids(["idTxtBx_SAOTCC_OTC", "idTxtBx_SAOTCC_OTP", "otp", "otc", "code"])
                        or _find_input_by_labels(["Verification code", "Security code", "Code", "OTP", "Einmalcode"])
                        or _find_best_input("otp")
                    )
                    if otp_loc:
                        try:
                            otp_loc.fill(generate_totp(totp_secret))
                            filled_otp = True
                            progressed = True
                            _click_action(["Verify", "Überprüfen", "Continue", "Next", "Submit"])
                            _click_known_ids(["idSubmit_SAOTCC_Continue", "idSIButton9", "submitButton"])
                        except Exception:
                            pass

                # Fallback clicks for common prompts
                if _click_action(["Use your password instead", "Use password instead"]):
                    progressed = True
                if _click_action([
                    "Use a different verification option",
                    "Use a verification code",
                    "Use another method",
                    "Use a different method",
                    "I can't use my Microsoft Authenticator app right now",
                ]):
                    progressed = True
                if _click_action(["Stay signed in", "Yes", "No", "OK", "Continue", "Next", "Weiter"]):
                    progressed = True
                if _click_known_ids(["idSIButton9", "submitButton"]):
                    progressed = True

                if progressed:
                    try:
                        page.wait_for_load_state("domcontentloaded", timeout=5000)
                    except Exception:
                        pass
                    time.sleep(0.3)
                else:
                    time.sleep(1)

            _wait_for_vpn_callback(timeout_seconds * 1000)

            # Collect cookies
            all_cookies = context.cookies()
            vpn_cookies = {}
            for c in all_cookies:
                if c.get("value") and _cookie_domain_matches(c.get("domain", "")):
                    vpn_cookies[c["name"]] = c["value"]

            if saml_result["saml_response"]:
                vpn_cookies["SAMLResponse"] = saml_result["saml_response"]
            if saml_result["prelogin_cookie"]:
                vpn_cookies["prelogin-cookie"] = saml_result["prelogin_cookie"]
            if gp_prelogin_cookie and "prelogin-cookie" not in vpn_cookies:
                vpn_cookies["prelogin-cookie"] = gp_prelogin_cookie
            if gp_gateway_ip:
                vpn_cookies["_gateway_ip"] = gp_gateway_ip

            # Avoid returning only helper metadata without a real auth artifact
            if set(vpn_cookies.keys()) == {"_gateway_ip"}:
                vpn_cookies = {}

            if debug:
                debug_out = {
                    "vpn_server": vpn_server,
                    "vpn_server_host": vpn_server_host,
                    "vpn_server_netloc": vpn_server_netloc,
                    "vpn_server_ip": vpn_server_ip,
                    "final_url": page.url,
                    "cookies": list(vpn_cookies.keys()),
                    "cookie_domains": sorted({c.get("domain", "") for c in all_cookies}),
                    "saml_response": bool(saml_result["saml_response"]),
                    "prelogin_cookie": bool(vpn_cookies.get("prelogin-cookie")),
                }
                try:
                    with open("/tmp/nm-vpn-auth-debug.json", "w") as f:
                        json.dump(debug_out, f, indent=2)
                except Exception:
                    pass

            _close_context()
            return vpn_cookies
        except Exception as e:
            if debug:
                try:
                    page.screenshot(path="/tmp/vpn-auth-error.png")
                except Exception:
                    pass
            _close_context()
            raise e
