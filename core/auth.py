"""SAML authentication via headless browser.

Combines:
- Persistent browser context for SSO session caching (from macos branch)
- 2FA error recovery with page refresh (from main branch)
- Number matching prompt handling (from main branch)
- SSO session detection for early exit (from main branch)
"""

import base64
import os
import ssl
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from typing import Optional

from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

from .totp import generate_totp


def _get_gp_prelogin(server: str, debug: bool = False) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Get prelogin-cookie from GlobalProtect prelogin.esp.

    Returns:
        (prelogin_cookie, saml_request, gateway_ip)
    """
    url = f"https://{server}/global-protect/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Linux"

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
        if debug:
            print(f"[DEBUG] prelogin.esp error: {e}")
        return None, None, None


def do_saml_auth(
    vpn_server: str,
    username: str,
    password: str,
    totp_secret: str,
    protocol: str = "anyconnect",
    auto_totp: bool = True,
    headless: bool = True,
    debug: bool = False,
) -> Optional[dict]:
    """Complete Microsoft SAML authentication.

    Args:
        vpn_server: VPN server hostname
        username: Microsoft email
        password: Password
        totp_secret: Base32 TOTP secret (auto-generates codes)
        protocol: Protocol type ('anyconnect' or 'gp')
        auto_totp: Whether to auto-fill TOTP codes
        headless: Run browser in headless mode
        debug: Enable debug output/screenshots

    Returns:
        Dict with cookies/tokens or None on failure
    """
    vpn_url = f"https://{vpn_server}"

    # Protocol-specific setup
    gp_prelogin_cookie, gp_saml_request, gp_gateway_ip = None, None, None
    if protocol == "gp":
        print(f"  [1/6] Getting GlobalProtect prelogin info...")
        gp_prelogin_cookie, gp_saml_request, gp_gateway_ip = _get_gp_prelogin(vpn_server, debug)
        if debug:
            print(f"    [DEBUG] prelogin-cookie: {gp_prelogin_cookie[:20] if gp_prelogin_cookie else None}...")
            print(f"    [DEBUG] gateway_ip: {gp_gateway_ip}")
    else:
        print(f"  [1/6] Using AnyConnect SAML URL...")

    # Ensure Playwright uses real user's browser cache
    real_user = os.environ.get("SUDO_USER", os.environ.get("USER", "root"))
    home = os.path.expanduser("~")
    if real_user != "root":
        try:
            import pwd
            home = pwd.getpwnam(real_user).pw_dir
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = f"{home}/.cache/ms-playwright"
        except (KeyError, ImportError):
            pass
    else:
        # Running as root - check for Playwright in common locations
        for pw_path in ["/var/cache/ms-playwright", "/opt/ms-playwright", "/usr/share/ms-playwright"]:
            if os.path.isdir(pw_path):
                os.environ["PLAYWRIGHT_BROWSERS_PATH"] = pw_path
                break

    with sync_playwright() as p:
        # Persistent context for SSO session reuse
        # Use appropriate cache directory based on permissions
        if real_user != "root":
            cache_dir = os.path.join(home, ".cache", "ms-sso-openconnect", "browser-session")
        else:
            # Running as root (e.g., NM plugin) - use writable system location
            cache_dir = None
            for base in ["/var/cache", "/tmp"]:
                test_dir = os.path.join(base, "ms-sso-openconnect", "browser-session")
                try:
                    os.makedirs(test_dir, exist_ok=True)
                    # Test if writable
                    test_file = os.path.join(test_dir, ".write-test")
                    with open(test_file, "w") as f:
                        f.write("test")
                    os.remove(test_file)
                    cache_dir = test_dir
                    break
                except (OSError, IOError):
                    continue
            if not cache_dir:
                # Last resort: use /tmp with a unique name
                cache_dir = f"/tmp/ms-sso-openconnect-{os.getpid()}/browser-session"
        os.makedirs(cache_dir, exist_ok=True)

        context = p.chromium.launch_persistent_context(
            cache_dir,
            headless=headless,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        )

        page = context.pages[0] if context.pages else context.new_page()

        # Capture SAML response
        saml_result = {
            "prelogin_cookie": None,
            "saml_username": None,
            "saml_response": None,
            "portal_userauthcookie": None,
        }

        def handle_request(request):
            if vpn_server in request.url:
                if debug:
                    print(f"    [DEBUG] Request to VPN: {request.url[:80]}...")
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
            if vpn_server not in response.url:
                return
            try:
                headers = response.headers
                if debug:
                    print(f"    [DEBUG] Response from VPN: {response.url[:80]}... status={response.status}")
                    # Log GP-related headers
                    for h in ["prelogin-cookie", "saml-username", "portal-userauthcookie", "set-cookie"]:
                        if h in headers:
                            val = headers[h][:50] if len(headers[h]) > 50 else headers[h]
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

        try:
            # Determine start URL based on protocol
            if protocol == "gp" and gp_saml_request:
                try:
                    start_url = base64.b64decode(gp_saml_request).decode("utf-8")
                    if not start_url.startswith("http"):
                        start_url = vpn_url
                except Exception:
                    start_url = vpn_url
            elif protocol == "anyconnect":
                start_url = f"https://{vpn_server}/+CSCOE+/saml/sp/login?tgname=DefaultWEBVPNGroup"
            else:
                start_url = vpn_url

            # Step 1: Open portal
            print(f"  [1/6] Opening SAML portal...")
            page.goto(start_url, timeout=30000, wait_until="networkidle")
            if debug:
                page.screenshot(path="/tmp/vpn-step1-portal.png")
                print("    [DEBUG] Screenshot: /tmp/vpn-step1-portal.png")

            # Check if already authenticated (SSO session valid)
            time.sleep(1)
            current_url = page.url
            if vpn_server in current_url:
                all_cookies = context.cookies()
                session_cookies = {}
                for c in all_cookies:
                    domain = c.get('domain', '')
                    name = c['name']
                    if (domain == vpn_server or domain == f'.{vpn_server}') and c.get('value'):
                        session_cookies[name] = c['value']

                has_session = (
                    session_cookies.get('webvpn') or
                    session_cookies.get('SVPNCOOKIE') or
                    saml_result.get('saml_response') or
                    saml_result.get('prelogin_cookie')
                )

                if has_session:
                    print("  -> Already authenticated (SSO session valid)")
                    if debug:
                        print(f"    [DEBUG] Session cookies: {list(session_cookies.keys())}")
                    context.close()
                    if saml_result['saml_response']:
                        session_cookies['SAMLResponse'] = saml_result['saml_response']
                    if saml_result['prelogin_cookie']:
                        session_cookies['prelogin-cookie'] = saml_result['prelogin_cookie']
                    if gp_prelogin_cookie and 'prelogin-cookie' not in session_cookies:
                        session_cookies['prelogin-cookie'] = gp_prelogin_cookie
                    return session_cookies

            # Handle "Pick an account" screen (when multiple accounts are cached)
            pick_account_text = page.locator('text="Pick an account"')
            if pick_account_text.count() > 0:
                if debug:
                    print("    [DEBUG] Detected account picker screen")
                    page.screenshot(path="/tmp/vpn-step1b-accountpicker.png")

                # Check if the desired username is already listed (case-insensitive)
                username_email = username.lower()
                account_found = False

                # Try multiple selectors to find matching account tile
                # MS login shows email in various elements depending on account state
                account_selectors = [
                    f'div[data-test-id*="tile"]:has-text("{username_email}")',
                    f'small:text-is("{username_email}")',
                    f'div.table-cell:has-text("{username_email}")',
                    f'div[role="button"]:has-text("{username_email}")',
                    f'*[data-test-id]:has-text("{username_email}")',
                ]

                for sel in account_selectors:
                    try:
                        account_tile = page.locator(sel)
                        if account_tile.count() > 0 and account_tile.first.is_visible():
                            print(f"  [2/6] Selecting existing account: {username}")
                            account_tile.first.click()
                            account_found = True
                            if debug:
                                print(f"    [DEBUG] Clicked account with selector: {sel}")
                            break
                    except Exception as e:
                        if debug:
                            print(f"    [DEBUG] Selector {sel} failed: {e}")
                        continue

                if account_found:
                    page.wait_for_load_state("domcontentloaded")
                    time.sleep(2)

                    # Check if clicking signed-in account completed auth (no password needed)
                    current_url = page.url
                    if vpn_server in current_url:
                        print("  -> Fast reconnect: account session still valid!")
                        all_cookies = context.cookies()
                        session_cookies = {}
                        for c in all_cookies:
                            domain = c.get('domain', '')
                            name = c['name']
                            if (domain == vpn_server or domain == f'.{vpn_server}') and c.get('value'):
                                session_cookies[name] = c['value']
                        if saml_result['saml_response']:
                            session_cookies['SAMLResponse'] = saml_result['saml_response']
                        if saml_result['prelogin_cookie']:
                            session_cookies['prelogin-cookie'] = saml_result['prelogin_cookie']
                        if gp_prelogin_cookie and 'prelogin-cookie' not in session_cookies:
                            session_cookies['prelogin-cookie'] = gp_prelogin_cookie
                        if session_cookies:
                            context.close()
                            return session_cookies
                else:
                    # Click "Use another account" - try multiple selectors
                    print("  [2/6] Clicking 'Use another account'...")
                    other_selectors = [
                        'div[data-test-id="otherTile"]',
                        '#otherTile',
                        'div:has-text("Use another account")',
                        'text="Use another account"',
                    ]
                    clicked = False
                    for sel in other_selectors:
                        try:
                            elem = page.locator(sel)
                            if elem.count() > 0 and elem.first.is_visible():
                                elem.first.click(force=True)
                                clicked = True
                                if debug:
                                    print(f"    [DEBUG] Clicked: {sel}")
                                break
                        except Exception as e:
                            if debug:
                                print(f"    [DEBUG] Failed to click {sel}: {e}")
                            continue

                    if clicked:
                        page.wait_for_load_state("domcontentloaded")
                        time.sleep(2)
                        if debug:
                            page.screenshot(path="/tmp/vpn-step1c-otheraccount.png")

            # Check if login form is present
            login_form = page.locator('input[name="loginfmt"]')
            if login_form.count() > 0:
                # Step 2: Enter username
                print("  [2/6] Entering username...")
                page.fill('input[name="loginfmt"]', username)
                time.sleep(0.5)
                if debug:
                    page.screenshot(path="/tmp/vpn-step2-username.png")
                _click_submit(page)
                page.wait_for_load_state("domcontentloaded")

                # Step 3: Enter password
                print("  [3/6] Entering password...")
                password_field = _wait_for_password_field(page, debug)
                if not password_field:
                    raise Exception("Password field not found")

                password_field.fill(password)
                time.sleep(0.5)
                if debug:
                    page.screenshot(path="/tmp/vpn-step3-password.png")
                _click_submit(page)
                page.wait_for_load_state("domcontentloaded")

                # Step 4: Handle 2FA with error recovery
                print("  [4/6] Handling 2FA...")
                time.sleep(3)

                # Check for auth error and refresh if needed
                def check_and_handle_auth_error():
                    """Check for authentication error and refresh page if found."""
                    error_selectors = [
                        'div:has-text("An error occurred")',
                        'div:has-text("Authentication attempt failed")',
                        '*:has-text("Select a different sign in option")',
                        '#errorText',
                        '.error-message',
                    ]

                    for selector in error_selectors:
                        try:
                            error_elem = page.query_selector(selector)
                            if error_elem and error_elem.is_visible():
                                error_text = error_elem.inner_text()[:100] if error_elem else "Unknown error"
                                print(f"    -> Detected auth error: {error_text}...")
                                print("    -> Refreshing page to retry...")
                                if debug:
                                    page.screenshot(path="/tmp/vpn-step4-auth-error.png")
                                page.reload(wait_until="domcontentloaded")
                                time.sleep(2)
                                return True
                        except:
                            continue
                    return False

                error_recovered = check_and_handle_auth_error()
                if error_recovered and debug:
                    page.screenshot(path="/tmp/vpn-step4-after-refresh.png")

                # Handle number matching prompt
                def handle_number_matching_prompt():
                    """Handle the number matching prompt by clicking 'Use a different verification option'."""
                    number_match_indicators = [
                        '*:has-text("tap the number you see")',
                        '*:has-text("tap the number")',
                        '*:has-text("Open your Microsoft Authenticator app")',
                        'div.display-sign-container',
                        '#displaySign',
                    ]

                    is_number_matching = False
                    for selector in number_match_indicators:
                        try:
                            elem = page.query_selector(selector)
                            if elem and elem.is_visible():
                                is_number_matching = True
                                break
                        except:
                            continue

                    if is_number_matching:
                        print("    -> Detected number matching prompt, looking for alternative option...")
                        if debug:
                            page.screenshot(path="/tmp/vpn-step4-number-match.png")

                        different_option_selectors = [
                            'a:has-text("Use a different verification option")',
                            'a:has-text("different verification option")',
                            '#signInAnotherWay',
                            'a#signInAnotherWay',
                            'a:has-text("I can\'t use my Microsoft Authenticator app right now")',
                            'a:has-text("Sign in another way")',
                        ]

                        for selector in different_option_selectors:
                            try:
                                link = page.query_selector(selector)
                                if link and link.is_visible():
                                    link.click(force=True)
                                    time.sleep(1)
                                    page.wait_for_load_state("domcontentloaded")
                                    print(f"    -> Clicked: '{selector}'")
                                    return True
                            except:
                                continue
                    return False

                number_prompt_handled = handle_number_matching_prompt()
                if number_prompt_handled:
                    time.sleep(1)

                if auto_totp and totp_secret:
                    _handle_2fa(page, totp_secret, debug)

                # Step 5: "Stay signed in?"
                print("  [5/6] Confirming login...")
                try:
                    page.wait_for_selector("#idSIButton9", timeout=8000)
                    page.click("#idSIButton9")
                except PWTimeout:
                    pass

                page.wait_for_load_state("domcontentloaded")

                # Step 6: Get cookies
                print("  [6/6] Collecting cookies...")
                try:
                    page.wait_for_url(f"**{vpn_server}**", timeout=15000)
                except PWTimeout:
                    pass

            time.sleep(0.5)
            cookies = context.cookies()

            if debug:
                print(f"    [DEBUG] Browser cookies ({len(cookies)} total):")
                for c in cookies:
                    if vpn_server in c.get("domain", ""):
                        print(f"      - {c['name']}: {str(c['value'])[:30]}... (domain={c.get('domain')})")

            # Filter VPN cookies
            vpn_cookies = {}
            gp_names = ["portal-userauthcookie", "portal-prelogonuserauthcookie", "user", "prelogin-cookie"]

            for c in cookies:
                name, domain = c["name"], c.get("domain", "")
                if name.lower() in [n.lower() for n in gp_names]:
                    vpn_cookies[name] = c["value"]
                elif domain == vpn_server or domain == f".{vpn_server}":
                    vpn_cookies[name] = c["value"]

            # Add captured SAML data
            if saml_result["saml_response"]:
                vpn_cookies["SAMLResponse"] = saml_result["saml_response"]
            if saml_result["prelogin_cookie"]:
                vpn_cookies["prelogin-cookie"] = saml_result["prelogin_cookie"]
            if saml_result["portal_userauthcookie"]:
                vpn_cookies["portal-userauthcookie"] = saml_result["portal_userauthcookie"]
            if saml_result["saml_username"]:
                vpn_cookies["saml-username"] = saml_result["saml_username"]

            # Add prelogin from prelogin.esp
            if gp_prelogin_cookie and "prelogin-cookie" not in vpn_cookies:
                vpn_cookies["prelogin-cookie"] = gp_prelogin_cookie
            if gp_gateway_ip:
                vpn_cookies["_gateway_ip"] = gp_gateway_ip

            if debug:
                print(f"    [DEBUG] Final VPN cookies to return:")
                for k, v in vpn_cookies.items():
                    print(f"      - {k}: {str(v)[:40]}...")
                print(f"    [DEBUG] saml_result: prelogin={saml_result['prelogin_cookie'] is not None}, "
                      f"saml_response={saml_result['saml_response'] is not None}, "
                      f"portal_userauthcookie={saml_result['portal_userauthcookie'] is not None}")

            context.close()
            return vpn_cookies if vpn_cookies else None

        except Exception as e:
            if debug:
                try:
                    page.screenshot(path="/tmp/vpn-error.png")
                except Exception:
                    pass
            context.close()
            raise


def _click_submit(page) -> bool:
    """Click submit button or press Enter."""
    selectors = [
        "#idSIButton9", "#submitButton", "span#submitButton",
        'input[type="submit"]', 'button[type="submit"]',
        'span:has-text("Sign in")', 'button:has-text("Sign in")',
    ]
    for sel in selectors:
        try:
            btn = page.query_selector(sel)
            if btn and btn.is_visible():
                btn.click(force=True)
                return True
        except Exception:
            continue
    page.keyboard.press("Enter")
    return False


def _wait_for_password_field(page, debug: bool, timeout: int = 30):
    """Wait for password field to appear (handles federated login redirect)."""
    selectors = [
        'input[name="passwd"]', 'input[name="password"]', 'input[type="password"]',
        "#passwordInput", "#password", "#i0118",
    ]

    def find_field():
        for s in selectors:
            try:
                pf = page.query_selector(s)
                if pf and pf.is_visible():
                    box = pf.bounding_box()
                    if box and box["width"] > 50:
                        return pf
            except Exception:
                continue
        return None

    initial_url = page.url
    field = find_field()
    waited = 0

    while not field and waited < timeout:
        time.sleep(0.5)
        waited += 0.5

        if page.url != initial_url:
            time.sleep(1)
            page.wait_for_load_state("domcontentloaded")

        field = find_field()

        # Try clicking "Use password" if visible
        if waited % 3 == 0:
            for sel in ["#idA_PWD_SwitchToPassword", 'a:has-text("password instead")']:
                try:
                    link = page.query_selector(sel)
                    if link and link.is_visible():
                        link.click()
                        time.sleep(1)
                        field = find_field()
                        break
                except Exception:
                    continue

    return field


def _handle_2fa(page, totp_secret: str, debug: bool):
    """Handle 2FA code entry."""
    otp_selectors = [
        "#idTxtBx_SAOTCC_OTC", 'input[name="otc"]',
        'input[placeholder*="code"]', 'input[aria-label*="code"]',
    ]

    def find_otp():
        for s in otp_selectors:
            try:
                inp = page.query_selector(s)
                if inp and inp.is_visible():
                    return inp
            except Exception:
                continue
        return None

    def enter_code(inp):
        code = generate_totp(totp_secret)
        print(f"    -> Entering TOTP code: {code}")
        inp.fill(code)
        time.sleep(0.3)
        for s in ["#idSubmit_SAOTCC_Continue", 'input[type="submit"]']:
            try:
                btn = page.query_selector(s)
                if btn and btn.is_visible():
                    btn.click(force=True)
                    return
            except Exception:
                continue
        page.keyboard.press("Enter")

    # Try direct OTP input
    otp = find_otp()
    if otp:
        enter_code(otp)
        return

    # Try "Sign in another way" flow
    step1_selectors = [
        "#signInAnotherWay", 'a:has-text("I can\'t use my Microsoft Authenticator")',
        'a:has-text("Sign in another way")', "#idA_SAASTO_LookupLink",
    ]

    for sel in step1_selectors:
        try:
            link = page.query_selector(sel)
            if link and link.is_visible():
                link.click(force=True)
                time.sleep(0.8)
                break
        except Exception:
            continue

    otp = find_otp()
    if otp:
        enter_code(otp)
        return

    # Try selecting TOTP option
    step2_selectors = [
        'div[data-value="PhoneAppOTP"]',
        'div:has-text("verification code")',
        'div:has-text("Use a verification code")',
    ]

    for sel in step2_selectors:
        try:
            opt = page.query_selector(sel)
            if opt and opt.is_visible():
                opt.click(force=True)
                time.sleep(0.8)
                break
        except Exception:
            continue

    otp = find_otp()
    if otp:
        enter_code(otp)
