#!/usr/bin/env python3
"""
MS SSO OpenConnect - Headless Browser Authentication

Connects to VPNs using Microsoft SSO via a headless browser,
supporting both Cisco AnyConnect and GlobalProtect protocols.

Features:
- Multiple VPN connections (identified by name)
- Multiple credentials per server (different names, same address)
- Support for AnyConnect and GlobalProtect protocols
- Credentials stored securely in GNOME keyring
- TOTP codes generated automatically from stored secret
- Session cookies cached for fast reconnection
- Automatic re-authentication when cookies expire

Usage:
    ./ms-sso-openconnect --setup            (add/edit VPN connection)
    ./ms-sso-openconnect                    (connect to default/only connection)
    ./ms-sso-openconnect <name>             (connect by connection name)
    ./ms-sso-openconnect --list             (list saved connections)
    ./ms-sso-openconnect --no-cache         (force re-authentication)
    ./ms-sso-openconnect --visible          (show browser for debugging)
    ./ms-sso-openconnect -d                 (disconnect, keep session alive)
    ./ms-sso-openconnect --force-disconnect (disconnect and terminate session)
"""

import subprocess
import sys
import os
import getpass
import argparse
import time
import json
import tempfile
import shlex
import re

KEYRING_SERVICE = "ms-sso-openconnect"
CONNECTIONS_KEY = "connections"

# Supported protocols
PROTOCOLS = {
    "anyconnect": {"name": "Cisco AnyConnect", "flag": "anyconnect"},
    "gp": {"name": "GlobalProtect", "flag": "gp"},
}

# Colors
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BOLD = "\033[1m"
NC = "\033[0m"


def print_header():
    print(f"{GREEN}========================================{NC}")
    print(f"{GREEN}    MS SSO OpenConnect - VPN Client{NC}")
    print(f"{GREEN}========================================{NC}")
    print()


def get_all_connections():
    """Retrieve all stored VPN connections from keyring."""
    try:
        import keyring
        data = keyring.get_password(KEYRING_SERVICE, CONNECTIONS_KEY)
        if data:
            return json.loads(data)
    except Exception as e:
        print(f"{YELLOW}Keyring error: {e}{NC}")
    return {}


def save_all_connections(connections):
    """Save all VPN connections to keyring."""
    try:
        import keyring
        keyring.set_password(KEYRING_SERVICE, CONNECTIONS_KEY, json.dumps(connections))
        return True
    except Exception as e:
        print(f"{RED}Failed to save connections: {e}{NC}")
        return False


def get_connection(name):
    """Get a specific connection by name."""
    connections = get_all_connections()
    return connections.get(name)


def save_connection(name, address, protocol, username, password, totp_secret):
    """Save a single connection."""
    connections = get_all_connections()
    connections[name] = {
        "address": address,
        "protocol": protocol,
        "username": username,
        "password": password,
        "totp_secret": totp_secret,
    }
    return save_all_connections(connections)


def delete_connection(name):
    """Delete a connection."""
    connections = get_all_connections()
    if name in connections:
        del connections[name]
        save_all_connections(connections)
        # Also clear cookies for this connection
        clear_stored_cookies(name)
        return True
    return False


def generate_totp(totp_secret):
    """Generate current TOTP code from secret."""
    import pyotp
    totp = pyotp.TOTP(totp_secret)
    return totp.now()


def _get_cache_dir():
    """Get cache directory path."""
    real_user = os.environ.get('SUDO_USER', os.environ.get('USER', 'root'))
    if real_user != 'root':
        import pwd
        try:
            home = pwd.getpwnam(real_user).pw_dir
        except KeyError:
            home = os.path.expanduser("~")
    else:
        home = os.path.expanduser("~")

    cache_dir = os.path.join(home, ".cache", "ms-sso-openconnect")
    os.makedirs(cache_dir, mode=0o700, exist_ok=True)
    return cache_dir


def _get_cookie_file(name):
    """Get path to cookie cache file for a specific connection."""
    cache_dir = _get_cache_dir()
    # Sanitize name for filename
    safe_name = name.replace("/", "_").replace(":", "_").replace(" ", "_")
    return os.path.join(cache_dir, f"session_{safe_name}.json")


def store_cookies(name, cookies, usergroup=None):
    """Store session cookies in a secure file.

    Args:
        name: Connection name
        cookies: Cookie dictionary
        usergroup: Optional usergroup (e.g., 'portal:prelogin-cookie' or 'portal:portal-userauthcookie')
    """
    try:
        cookie_file = _get_cookie_file(name)
        data = {
            "cookies": cookies,
            "timestamp": int(time.time())
        }
        if usergroup:
            data["usergroup"] = usergroup
        with open(cookie_file, 'w') as f:
            json.dump(data, f)
        os.chmod(cookie_file, 0o600)

        # If running as root via sudo, chown to the real user
        real_user = os.environ.get('SUDO_USER')
        if real_user and os.geteuid() == 0:
            import pwd
            try:
                pw = pwd.getpwnam(real_user)
                os.chown(cookie_file, pw.pw_uid, pw.pw_gid)
                cache_dir = os.path.dirname(cookie_file)
                os.chown(cache_dir, pw.pw_uid, pw.pw_gid)
            except (KeyError, OSError):
                pass

        print(f"{GREEN}Session cookie cached.{NC}")
        return True
    except Exception as e:
        print(f"{YELLOW}Could not cache cookies: {e}{NC}")
        return False


def get_stored_cookies(name, max_age_hours=12):
    """Retrieve cached session cookies from file.

    Returns:
        Tuple of (cookies_dict, usergroup) or None if no valid cache.
        usergroup may be None if not set.
    """
    try:
        cookie_file = _get_cookie_file(name)
        if not os.path.exists(cookie_file):
            return None

        with open(cookie_file, 'r') as f:
            data = json.load(f)

        age_seconds = int(time.time()) - data.get("timestamp", 0)
        if age_seconds > max_age_hours * 3600:
            clear_stored_cookies(name)
            return None

        cookies = data.get("cookies")
        usergroup = data.get("usergroup")
        return (cookies, usergroup)
    except Exception:
        return None


def clear_stored_cookies(name=None):
    """Clear cached cookies file(s)."""
    try:
        if name:
            cookie_file = _get_cookie_file(name)
            if os.path.exists(cookie_file):
                os.remove(cookie_file)
        else:
            # Clear all cookies
            cache_dir = _get_cache_dir()
            for f in os.listdir(cache_dir):
                if f.startswith("session_") and f.endswith(".json"):
                    os.remove(os.path.join(cache_dir, f))
    except Exception:
        pass


def list_connections():
    """List all saved VPN connections."""
    connections = get_all_connections()
    if not connections:
        print(f"{YELLOW}No saved connections. Use --setup to add one.{NC}")
        return

    print(f"{CYAN}Saved VPN Connections:{NC}\n")
    for name, config in connections.items():
        address = config.get("address", "")
        protocol = PROTOCOLS.get(config.get("protocol", "anyconnect"), {}).get("name", "Unknown")
        username = config.get("username", "")
        print(f"  {BOLD}{name}{NC}")
        print(f"    Server:   {address}")
        print(f"    Protocol: {protocol}")
        print(f"    Username: {username}")
        print()


def setup_config(edit_name=None):
    """Interactive setup to add or edit a VPN connection."""
    print(f"{CYAN}=== MS SSO OpenConnect Setup ==={NC}\n")
    if sys.platform == "darwin":
        keyring_name = "Apple Keychain"
    elif sys.platform == "linux":
        keyring_name = "system keyring (GNOME Keyring/KWallet)"
    else:
        keyring_name = "system keychain"
    print(f"Your configuration will be stored securely in {keyring_name}.\n")

    connections = get_all_connections()

    # Connection name
    print(f"{CYAN}Connection Configuration:{NC}")
    if edit_name:
        name = edit_name
        print(f"Editing: {name}")
        existing = connections.get(name, {})
    else:
        name = input("Connection Name (e.g., work, office, client-vpn): ").strip()
        if not name:
            print(f"{RED}Error: Connection name cannot be empty{NC}")
            return False
        existing = connections.get(name, {})
        if existing:
            print(f"{YELLOW}Connection '{name}' exists. Will update.{NC}")

    # VPN Server address
    default_addr = existing.get("address", "")
    if default_addr:
        address = input(f"VPN Server Address [{default_addr}]: ").strip() or default_addr
    else:
        address = input("VPN Server Address (e.g., vpn.example.com): ").strip()
    if not address:
        print(f"{RED}Error: Server address cannot be empty{NC}")
        return False

    # Protocol selection
    print(f"\n{CYAN}VPN Protocol:{NC}")
    print("  1) Cisco AnyConnect")
    print("  2) GlobalProtect")
    default_proto = "1" if existing.get("protocol", "anyconnect") == "anyconnect" else "2"
    proto_choice = input(f"Select protocol [{default_proto}]: ").strip() or default_proto
    protocol = "anyconnect" if proto_choice == "1" else "gp"

    # Username
    print(f"\n{CYAN}Microsoft SSO Credentials:{NC}")
    default_user = existing.get("username", "")
    if default_user:
        username = input(f"Username (email) [{default_user}]: ").strip() or default_user
    else:
        username = input("Username (email): ").strip()
    if not username:
        print(f"{RED}Error: Username cannot be empty{NC}")
        return False

    # Password
    password = getpass.getpass("Password (leave empty to keep existing): ")
    if not password and existing.get("password"):
        password = existing["password"]
    elif not password:
        print(f"{RED}Error: Password cannot be empty{NC}")
        return False

    # TOTP Secret
    print(f"\n{CYAN}TOTP Secret Setup:{NC}")
    print("Enter your Microsoft Authenticator TOTP secret key.")
    print("(Leave empty to keep existing)\n")

    totp_secret = input("TOTP Secret (base32, no spaces): ").strip().replace(" ", "").upper()
    if not totp_secret and existing.get("totp_secret"):
        totp_secret = existing["totp_secret"]
    elif not totp_secret:
        print(f"{RED}Error: TOTP secret cannot be empty{NC}")
        return False

    # Validate TOTP secret
    try:
        import pyotp
        totp = pyotp.TOTP(totp_secret)
        test_code = totp.now()
        print(f"\n{GREEN}TOTP secret valid. Current code: {test_code}{NC}")
    except Exception as e:
        print(f"{RED}Invalid TOTP secret: {e}{NC}")
        return False

    # Save connection
    if save_connection(name, address, protocol, username, password, totp_secret):
        print(f"\n{GREEN}Connection '{name}' saved!{NC}")
        print(f"Run './ms-sso-openconnect {name}' to connect.")
        return True
    return False


def delete_config(name=None):
    """Remove stored connection(s) from keyring."""
    if name:
        if delete_connection(name):
            print(f"{GREEN}Connection '{name}' deleted.{NC}")
        else:
            print(f"{YELLOW}Connection '{name}' not found.{NC}")
    else:
        # Clear all
        try:
            import keyring
            keyring.delete_password(KEYRING_SERVICE, CONNECTIONS_KEY)
            clear_stored_cookies()
            print(f"{GREEN}All connections deleted.{NC}")
        except Exception as e:
            print(f"{RED}Error deleting configuration: {e}{NC}")


def select_connection():
    """Interactive connection selection if multiple exist."""
    connections = get_all_connections()

    if not connections:
        print(f"{YELLOW}No saved connections. Use --setup to add one.{NC}")
        sys.exit(1)

    if len(connections) == 1:
        return list(connections.keys())[0]

    print(f"{CYAN}Select VPN connection:{NC}\n")
    names = list(connections.keys())
    for i, name in enumerate(names, 1):
        address = connections[name].get("address", "")
        protocol = PROTOCOLS.get(connections[name].get("protocol", "anyconnect"), {}).get("name", "Unknown")
        print(f"  {i}) {name} ({address}, {protocol})")

    print()
    while True:
        try:
            choice = input("Enter number: ").strip()
            idx = int(choice) - 1
            if 0 <= idx < len(names):
                return names[idx]
        except ValueError:
            pass
        print(f"{RED}Invalid selection{NC}")


def get_config(name):
    """Get config for a specific connection.

    Returns: (name, address, protocol, username, password, totp_secret)
    """
    conn = get_connection(name)
    if conn:
        return (
            name,
            conn.get("address"),
            conn.get("protocol", "anyconnect"),
            conn.get("username"),
            conn.get("password"),
            conn.get("totp_secret"),
        )
    return None, None, None, None, None, None


def get_gp_prelogin_cookie(vpn_server, debug=False):
    """
    Get the prelogin-cookie from GlobalProtect's prelogin.esp endpoint.
    This is needed for GP SAML authentication.
    """
    import urllib.request
    import urllib.error
    import ssl
    import xml.etree.ElementTree as ET

    # Use /global-protect/ path (some servers use /ssl-vpn/, but /global-protect/ is more common)
    prelogin_url = f"https://{vpn_server}/global-protect/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Linux"

    try:
        if debug:
            print(f"    [DEBUG] Getting prelogin from {prelogin_url[:60]}...")

        # Create SSL context
        ctx = ssl.create_default_context()

        req = urllib.request.Request(prelogin_url)
        req.add_header('User-Agent', 'PAN GlobalProtect')

        with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
            if response.status == 200:
                content = response.read().decode('utf-8')

                if debug:
                    print(f"    [DEBUG] prelogin.esp response ({len(content)} chars)")
                    # Save for analysis
                    with open('/tmp/vpn-prelogin.xml', 'w') as f:
                        f.write(content)
                    print(f"    [DEBUG] Saved to /tmp/vpn-prelogin.xml")

                # Parse XML response
                root = ET.fromstring(content)

                # Look for prelogin-cookie, saml-request, and gateway info
                prelogin_cookie = None
                saml_request = None
                gateway_ip = None

                for elem in root.iter():
                    if elem.tag == 'prelogin-cookie':
                        prelogin_cookie = elem.text
                    elif elem.tag == 'saml-request':
                        saml_request = elem.text
                    elif elem.tag == 'server-ip':
                        gateway_ip = elem.text

                if debug:
                    if prelogin_cookie:
                        print(f"    [DEBUG] Got prelogin-cookie: {prelogin_cookie[:20]}...")
                    else:
                        print(f"    [DEBUG] No prelogin-cookie in response")
                    if saml_request:
                        print(f"    [DEBUG] Got saml-request ({len(saml_request)} chars)")
                    if gateway_ip:
                        print(f"    [DEBUG] Gateway IP: {gateway_ip}")

                return prelogin_cookie, saml_request, gateway_ip
    except Exception as e:
        if debug:
            print(f"    [DEBUG] prelogin.esp error: {e}")

    return None, None, None


def do_saml_auth(vpn_server, username, password, totp_secret_or_code, auto_totp=False, headless=True, debug=False):
    """
    Complete Microsoft SAML authentication and return the session cookie.
    """
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    import pwd

    vpn_url = f"https://{vpn_server}"

    # For GlobalProtect, try to get prelogin-cookie first
    gp_prelogin_cookie, gp_saml_request, gp_gateway_ip = get_gp_prelogin_cookie(vpn_server, debug)

    # Ensure Playwright uses the real user's browser cache (not root's)
    real_user = os.environ.get('SUDO_USER', os.environ.get('USER', 'root'))
    if real_user != 'root':
        try:
            real_home = pwd.getpwnam(real_user).pw_dir
            os.environ['PLAYWRIGHT_BROWSERS_PATH'] = f"{real_home}/.cache/ms-playwright"
        except KeyError:
            pass

    print(f"\n{GREEN}Authenticating via headless browser...{NC}\n")

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=headless,
            args=['--no-sandbox', '--disable-dev-shm-usage']
        )

        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        page = context.new_page()

        # For GlobalProtect: intercept SAML response and server response
        saml_result = {'prelogin_cookie': None, 'saml_username': None, 'saml_response': None, 'portal_userauthcookie': None}

        def handle_request(request):
            # Look for SAML callback to VPN server
            if vpn_server in request.url:
                post_data = request.post_data
                if post_data:
                    # Parse form data for SAML response
                    import urllib.parse
                    try:
                        params = urllib.parse.parse_qs(post_data)
                        if debug:
                            print(f"    [DEBUG] POST to VPN: {request.url[:60]}...")
                            print(f"    [DEBUG] POST params: {list(params.keys())}")
                        if 'SAMLResponse' in params:
                            saml_result['saml_response'] = params['SAMLResponse'][0]
                            if debug:
                                print(f"    [DEBUG] Captured SAMLResponse ({len(saml_result['saml_response'])} chars)")
                        if 'prelogin-cookie' in params:
                            saml_result['prelogin_cookie'] = params['prelogin-cookie'][0]
                            if debug:
                                print(f"    [DEBUG] Captured prelogin-cookie from request")
                    except Exception as e:
                        if debug:
                            print(f"    [DEBUG] Request parse error: {e}")

        def handle_response(response):
            # Look for prelogin-cookie in response from VPN server
            if vpn_server in response.url:
                try:
                    # Check response headers for prelogin-cookie
                    headers = response.headers
                    if debug and 'SAML' in response.url.upper():
                        print(f"    [DEBUG] Response from VPN: {response.url[:60]}...")

                    # Check for DIRECT custom headers (how gp-saml-gui captures them)
                    # Palo Alto sends these as custom HTTP response headers
                    if 'prelogin-cookie' in headers:
                        saml_result['prelogin_cookie'] = headers['prelogin-cookie']
                        if debug:
                            print(f"    [DEBUG] Got prelogin-cookie from direct header")
                    if 'saml-username' in headers:
                        saml_result['saml_username'] = headers['saml-username']
                        if debug:
                            print(f"    [DEBUG] Got saml-username from header: {headers['saml-username']}")
                    if 'saml-auth-status' in headers:
                        if debug:
                            print(f"    [DEBUG] Got saml-auth-status: {headers['saml-auth-status']}")

                    # Also check Set-Cookie headers as fallback
                    set_cookie = headers.get('set-cookie', '')
                    if 'prelogin-cookie' in set_cookie.lower() and not saml_result.get('prelogin_cookie'):
                        import re
                        match = re.search(r'prelogin-cookie=([^;]+)', set_cookie, re.IGNORECASE)
                        if match:
                            saml_result['prelogin_cookie'] = match.group(1)
                            if debug:
                                print(f"    [DEBUG] Got prelogin-cookie from Set-Cookie header")

                    # Try to parse response body for XML with prelogin-cookie or portal-userauthcookie
                    if 'SAML' in response.url.upper() or 'ACS' in response.url.upper():
                        try:
                            body = response.body()
                            if body:
                                body_text = body.decode('utf-8', errors='ignore')
                                if debug:
                                    print(f"    [DEBUG] Response body ({len(body_text)} chars)")
                                    # Save for analysis
                                    with open('/tmp/vpn-saml-response.txt', 'w') as f:
                                        f.write(body_text)
                                    print(f"    [DEBUG] Saved to /tmp/vpn-saml-response.txt")

                                # Look for prelogin-cookie or portal-userauthcookie in body
                                import re
                                # Check for prelogin-cookie (only if not already set from header)
                                if not saml_result.get('prelogin_cookie'):
                                    match = re.search(r'<prelogin-cookie>([^<]+)</prelogin-cookie>', body_text)
                                    if match:
                                        saml_result['prelogin_cookie'] = match.group(1)
                                        if debug:
                                            print(f"    [DEBUG] Got prelogin-cookie from response body")

                                # Check for portal-userauthcookie
                                match = re.search(r'portal-userauthcookie["\s:=>]+([^"<\s]+)', body_text, re.IGNORECASE)
                                if match and not saml_result.get('portal_userauthcookie'):
                                    saml_result['portal_userauthcookie'] = match.group(1)
                                    if debug:
                                        print(f"    [DEBUG] Got portal-userauthcookie from response body")

                                # Check for userAuthCookie (alternate name)
                                match = re.search(r'userAuthCookie["\s:=>]+([^"<\s]+)', body_text, re.IGNORECASE)
                                if match and not saml_result.get('portal_userauthcookie'):
                                    saml_result['portal_userauthcookie'] = match.group(1)
                                    if debug:
                                        print(f"    [DEBUG] Got userAuthCookie from response body")
                        except Exception as e:
                            if debug:
                                print(f"    [DEBUG] Could not read response body: {e}")

                except Exception as e:
                    if debug:
                        print(f"    [DEBUG] Response parse error: {e}")

        page.on("request", handle_request)
        page.on("response", handle_response)

        try:
            # 0. For GP, show prelogin-cookie status and determine start URL
            start_url = vpn_url
            if gp_saml_request:
                # Decode the saml-request to get the actual SAML auth URL
                import base64
                try:
                    saml_url = base64.b64decode(gp_saml_request).decode('utf-8')
                    if saml_url.startswith('http'):
                        start_url = saml_url
                        print(f"  [0/6] Using SAML URL from prelogin.esp")
                        if debug:
                            print(f"    [DEBUG] SAML URL: {saml_url[:60]}...")
                except Exception as e:
                    if debug:
                        print(f"    [DEBUG] Could not decode saml-request: {e}")

            if gp_prelogin_cookie:
                print(f"  [0/6] Got GP prelogin-cookie from prelogin.esp")
            elif debug and not gp_saml_request:
                print(f"  [0/6] No prelogin-cookie from prelogin.esp")

            # 1. Open VPN portal or SAML URL
            print("  [1/6] Opening VPN portal...")
            page.goto(start_url, timeout=30000, wait_until="domcontentloaded")
            if debug:
                page.screenshot(path="/tmp/vpn-step1-portal.png")
                print("    [DEBUG] Screenshot: /tmp/vpn-step1-portal.png")

            # 2. Enter username on Microsoft login
            print("  [2/6] Entering username...")
            page.wait_for_selector('input[name="loginfmt"]', timeout=10000)
            if debug:
                page.screenshot(path="/tmp/vpn-step2-before-username.png")
                print("    [DEBUG] Screenshot: /tmp/vpn-step2-before-username.png")
            page.fill('input[name="loginfmt"]', username)
            time.sleep(0.5)  # Brief pause for page stability
            # Try multiple submit button selectors
            clicked = False
            for selector in ['#idSIButton9', 'input[type="submit"]', 'button[type="submit"]']:
                try:
                    btn = page.query_selector(selector)
                    if btn and btn.is_visible():
                        btn.click(force=True)
                        clicked = True
                        break
                except:
                    continue
            if not clicked:
                page.keyboard.press('Enter')
            page.wait_for_load_state("domcontentloaded")

            # 3. Handle password entry
            print("  [3/6] Entering password...")

            # Password field selectors (different org pages use different names)
            password_selectors = [
                'input[name="passwd"]',
                'input[name="password"]',
                'input[type="password"]',
                'input[name="Password"]',
                'input[name="Passwd"]',
                '#passwordInput',
                '#password',
                '#i0118',  # Microsoft password field ID
            ]

            def find_password_field():
                """Quick check for any visible password field that's ready for input."""
                for selector in password_selectors:
                    try:
                        pf = page.query_selector(selector)
                        if pf and pf.is_visible():
                            # Make sure it's actually interactable (not in a transitioning page)
                            box = pf.bounding_box()
                            if box and box['width'] > 50 and box['height'] > 10:
                                # Additional check: ensure the page has the password field in focus area
                                return pf
                    except:
                        continue
                return None

            # Track URL to detect redirects
            initial_url = page.url

            # Quick check first (for fast login cases)
            password_field = find_password_field()

            # If not found immediately, wait for redirect/page load (federated login)
            if not password_field:
                print("    -> Waiting for login page...")

                max_wait = 30  # seconds
                waited = 0
                url_changed = False

                while not password_field and waited < max_wait:
                    # Wait a bit then check again
                    time.sleep(0.5)
                    waited += 0.5

                    # Check if URL changed (redirect happened)
                    current_url = page.url
                    if current_url != initial_url and not url_changed:
                        url_changed = True
                        if debug:
                            print(f"    [DEBUG] Redirect detected: {current_url[:80]}...")
                        # Wait extra for new page to fully load
                        time.sleep(1)
                        page.wait_for_load_state("domcontentloaded")

                    password_field = find_password_field()
                    if password_field:
                        break

                    # Every 3 seconds, try clicking "Use password" option if visible
                    if waited % 3 == 0:
                        password_link_selectors = [
                            '#idA_PWD_SwitchToPassword',
                            'a:has-text("Use your password instead")',
                            'a:has-text("password instead")',
                            'a:has-text("Use a password")',
                            '#idA_PWD_SwitchToCredPicker',
                        ]
                        for selector in password_link_selectors:
                            try:
                                link = page.query_selector(selector)
                                if link and link.is_visible():
                                    link.click()
                                    print("    -> Clicked password login option")
                                    time.sleep(1)
                                    password_field = find_password_field()
                                    break
                            except:
                                continue

                    # Debug progress every 5 seconds
                    if debug and waited % 5 == 0:
                        print(f"    -> Still waiting... ({int(waited)}s)")
                        page.screenshot(path=f"/tmp/vpn-step3-wait-{int(waited)}.png")

            if debug:
                page.screenshot(path="/tmp/vpn-step3-before-password.png")
                print("    [DEBUG] Screenshot: /tmp/vpn-step3-before-password.png")
                print(f"    [DEBUG] Current URL: {page.url}")

            if not password_field:
                if debug:
                    page.screenshot(path="/tmp/vpn-password-wait.png")
                    print("    [DEBUG] Screenshot: /tmp/vpn-password-wait.png")
                raise Exception("Password field not found after waiting")

            print("    -> Password field ready")
            password_field.fill(password)
            time.sleep(0.5)  # Brief pause for page stability

            # Wait for page to stabilize after password fill
            time.sleep(0.5)

            if debug:
                page.screenshot(path="/tmp/vpn-step3-after-password-fill.png")
                print("    [DEBUG] Screenshot: /tmp/vpn-step3-after-password-fill.png")
                print(f"    [DEBUG] Current URL for submit: {page.url[:60]}...")

            # Try multiple submit button selectors
            # Order matters: check org-specific first, then generic
            clicked = False
            submit_selectors = [
                # ADFS-specific
                '#submitButton',          # ADFS submit button ID
                'span#submitButton',      # ADFS span with ID
                'span.submit.modifiedSignIn',  # ADFS submit class
                # Microsoft-specific
                '#idSIButton9',           # Microsoft standard
                # Generic fallbacks
                'span:has-text("Sign in")',
                'button:has-text("Sign in")',
                'input[type="submit"]',
                'button[type="submit"]',
                '.button_primary',
            ]
            for selector in submit_selectors:
                try:
                    btn = page.query_selector(selector)
                    if btn and btn.is_visible():
                        if debug:
                            print(f"    [DEBUG] Clicking submit: {selector}")
                        btn.click(force=True)
                        clicked = True
                        break
                except:
                    continue
            if not clicked:
                # Last resort: press Enter
                if debug:
                    print("    [DEBUG] No submit button found, pressing Enter")
                page.keyboard.press('Enter')
            page.wait_for_load_state("domcontentloaded")

            # 4. Handle 2FA
            print("  [4/6] Entering 2FA code...")
            time.sleep(3)  # Wait for 2FA page to fully load
            if debug:
                page.screenshot(path="/tmp/vpn-step4-2fa-page.png")
                print("    [DEBUG] Screenshot: /tmp/vpn-step4-2fa-page.png")
                # Also dump page HTML for selector debugging
                html = page.content()
                with open("/tmp/vpn-step4-2fa-page.html", "w") as f:
                    f.write(html)
                print("    [DEBUG] HTML saved: /tmp/vpn-step4-2fa-page.html")
                # Debug: print current URL
                print(f"    [DEBUG] Current URL: {page.url}")

            # OTP input selectors (used multiple times)
            otp_selectors = [
                '#idTxtBx_SAOTCC_OTC',
                'input[name="otc"]',
                'input[data-testid="otc"]',
                'input[placeholder*="code"]',
                'input[aria-label*="code"]',
            ]

            def find_otp_input():
                """Try to find a visible OTP input field."""
                for selector in otp_selectors:
                    try:
                        otp = page.query_selector(selector)
                        if otp and otp.is_visible():
                            return otp
                    except:
                        continue
                return None

            def enter_otp_code(otp_input):
                """Enter OTP code and submit."""
                if auto_totp:
                    otp = generate_totp(totp_secret_or_code)
                    print(f"    -> Generated TOTP code: {otp}")
                else:
                    otp = totp_secret_or_code
                otp_input.fill(otp)
                print("    -> TOTP code entered")

                # Submit the code
                time.sleep(0.3)
                submit_selectors = ['#idSubmit_SAOTCC_Continue', 'input[type="submit"]', 'button[type="submit"]']
                for selector in submit_selectors:
                    try:
                        btn = page.query_selector(selector)
                        if btn and btn.is_visible():
                            btn.click(force=True)
                            return True
                    except:
                        continue
                # Fallback: press Enter
                page.keyboard.press('Enter')
                return True

            otp_entered = False

            # === PATH 1: Direct OTP input ===
            otp_input = find_otp_input()
            if otp_input:
                print("    -> Found direct TOTP input field")
                enter_otp_code(otp_input)
                otp_entered = True

            # === PATH 2: Menu navigation required (federated 2FA) ===
            if not otp_entered:
                print("    -> Looking for 2FA method selection menu...")

                # Step 1: Click "Sign in another way" / "I can't use my Authenticator app"
                step1_selectors = [
                    '#signInAnotherWay',
                    'a#signInAnotherWay',
                    'a:has-text("I can\'t use my Microsoft Authenticator app right now")',
                    'a:has-text("Sign in another way")',
                    'a:has-text("verify another way")',
                    'a:has-text("Other ways to sign in")',
                    'a:has-text("Having trouble")',
                    'a:has-text("Use a different verification option")',
                    '#idA_SAASTO_LookupLink',
                ]

                step1_clicked = False
                for selector in step1_selectors:
                    try:
                        link = page.query_selector(selector)
                        if link and link.is_visible():
                            link.click(force=True)
                            time.sleep(0.8)
                            page.wait_for_load_state("domcontentloaded")
                            print(f"    -> Clicked: '{selector}'")
                            step1_clicked = True
                            break
                    except:
                        continue

                if not step1_clicked:
                    # Try with wait_for_selector for dynamic elements
                    for selector in step1_selectors:
                        try:
                            link = page.wait_for_selector(selector, timeout=1500)
                            if link and link.is_visible():
                                link.click(force=True)
                                time.sleep(0.8)
                                page.wait_for_load_state("domcontentloaded")
                                print(f"    -> Clicked (waited): '{selector}'")
                                step1_clicked = True
                                break
                        except PWTimeout:
                            continue

                if debug:
                    page.screenshot(path="/tmp/vpn-step4-after-step1.png")
                    print(f"    [DEBUG] Screenshot: /tmp/vpn-step4-after-step1.png (step1_clicked={step1_clicked})")

                # Check if OTP input appeared after step 1
                time.sleep(0.5)
                otp_input = find_otp_input()
                if otp_input:
                    print("    -> Found TOTP input after step 1")
                    enter_otp_code(otp_input)
                    otp_entered = True

                # Step 2: Select TOTP / verification code option
                # Try step 2 even if step 1 didn't click anything - options may be directly visible
                if not otp_entered:
                    print("    -> Looking for verification code option...")
                    step2_selectors = [
                        'div[data-value="PhoneAppOTP"]',
                        '[data-testid="PhoneAppOTP"]',
                        'div.tile:has-text("verification code")',
                        'div.tile:has-text("authenticator app")',
                        'div:has-text("Use a verification code from my mobile app")',
                        'div:has-text("Use a verification code")',
                        'div:has-text("verification code from")',
                        'div:has-text("authenticator app"):not(:has-text("push notification"))',
                        'div:has-text("Enter code")',
                        'div[role="button"]:has-text("code")',
                    ]

                    step2_clicked = False
                    for selector in step2_selectors:
                        try:
                            option = page.query_selector(selector)
                            if option and option.is_visible():
                                option.click(force=True)
                                time.sleep(0.8)
                                page.wait_for_load_state("domcontentloaded")
                                print(f"    -> Selected: '{selector}'")
                                step2_clicked = True
                                break
                        except:
                            continue

                    if debug:
                        page.screenshot(path="/tmp/vpn-step4-after-step2.png")
                        print(f"    [DEBUG] Screenshot: /tmp/vpn-step4-after-step2.png (step2_clicked={step2_clicked})")

                    # Now look for OTP input again
                    time.sleep(0.5)
                    otp_input = find_otp_input()
                    if not otp_input:
                        # Try waiting for it
                        for selector in otp_selectors:
                            try:
                                otp_input = page.wait_for_selector(selector, timeout=3000, state="visible")
                                if otp_input:
                                    break
                            except PWTimeout:
                                continue

                    if otp_input:
                        print("    -> Found TOTP input after step 2")
                        enter_otp_code(otp_input)
                        otp_entered = True

            if not otp_entered:
                print(f"  {YELLOW}Warning: 2FA input not found - may use push notification or no 2FA{NC}")
                if debug:
                    page.screenshot(path="/tmp/vpn-2fa.png")
                # Wait a bit for push notification approval or page to continue
                time.sleep(3)

            # 5. Handle "Stay signed in?"
            print("  [5/6] Completing login...")
            try:
                page.wait_for_selector('#idSIButton9', timeout=8000)
                page.click('#idSIButton9')
                print("    -> Clicked 'Stay signed in'")
            except PWTimeout:
                pass

            page.wait_for_load_state("domcontentloaded")

            # 6. Get cookies
            print("  [6/6] Getting session cookie...")
            try:
                page.wait_for_url(f"**{vpn_server}**", timeout=15000)
            except PWTimeout:
                pass

            time.sleep(0.5)
            cookies = context.cookies()

            if debug:
                print(f"\n    [DEBUG] All cookies ({len(cookies)}):")
                for c in cookies:
                    print(f"      {c['name']}: domain={c.get('domain', 'N/A')}")

            domain_parts = vpn_server.split('.')
            base_domain = '.'.join(domain_parts[-2:]) if len(domain_parts) >= 2 else vpn_server

            vpn_cookies = {}
            # GlobalProtect-specific cookies to look for (in priority order)
            gp_cookie_names = ['portal-userauthcookie', 'portal-prelogonuserauthcookie', 'user', 'prelogin-cookie']

            for c in cookies:
                domain = c.get('domain', '')
                name = c['name']
                # Check if it's a GP-specific cookie from any domain
                if name.lower() in [n.lower() for n in gp_cookie_names]:
                    vpn_cookies[name] = c['value']
                    if debug:
                        print(f"    [DEBUG] Found GP cookie: {name}")
                # Check for exact VPN domain match (strict filtering)
                elif domain == vpn_server or domain == f'.{vpn_server}':
                    vpn_cookies[name] = c['value']
                    if debug:
                        print(f"    [DEBUG] VPN domain cookie: {name} (domain={domain})")

            # Add captured SAML data to cookies dict
            if saml_result['saml_response']:
                vpn_cookies['SAMLResponse'] = saml_result['saml_response']
                if debug:
                    print(f"    [DEBUG] SAMLResponse captured: {len(saml_result['saml_response'])} chars")
            if saml_result['prelogin_cookie']:
                vpn_cookies['prelogin-cookie'] = saml_result['prelogin_cookie']
                if debug:
                    print(f"    [DEBUG] prelogin-cookie from SAML captured")
            if saml_result['portal_userauthcookie']:
                vpn_cookies['portal-userauthcookie'] = saml_result['portal_userauthcookie']
                if debug:
                    print(f"    [DEBUG] portal-userauthcookie captured")
            if saml_result['saml_username']:
                vpn_cookies['saml-username'] = saml_result['saml_username']

            # Add prelogin-cookie from prelogin.esp (obtained before browser auth)
            if gp_prelogin_cookie and 'prelogin-cookie' not in vpn_cookies:
                vpn_cookies['prelogin-cookie'] = gp_prelogin_cookie
                if debug:
                    print(f"    [DEBUG] Using prelogin-cookie from prelogin.esp")

            # Store gateway IP for connection (may be different from portal)
            if gp_gateway_ip:
                vpn_cookies['_gateway_ip'] = gp_gateway_ip
                if debug:
                    print(f"    [DEBUG] Gateway IP stored: {gp_gateway_ip}")

            # NOTE: Do NOT exchange prelogin-cookie for portal-userauthcookie here!
            # This invalidates the prelogin-cookie. gp-saml-gui doesn't do this.
            # openconnect handles the portal config exchange automatically.

            if debug:
                print(f"\n  Cookies for VPN ({vpn_server}): {list(vpn_cookies.keys())}")
                page.screenshot(path="/tmp/vpn-final.png")

            browser.close()

            if vpn_cookies:
                print(f"\n{GREEN}Authentication successful!{NC}")
                return vpn_cookies
            else:
                print(f"\n{RED}No session cookies obtained{NC}")
                return None

        except Exception as e:
            print(f"\n{RED}Authentication error: {e}{NC}")
            if debug:
                try:
                    page.screenshot(path="/tmp/vpn-error.png")
                except:
                    pass
            browser.close()
            return None


def connect_vpn(vpn_server, protocol, cookies, no_dtls=False, username=None, allow_fallback=False,
                connection_name=None, cached_usergroup=None, use_pkexec=False):
    """Connect to VPN using openconnect with the obtained cookie.

    If allow_fallback=True, use subprocess so we can return on failure.
    If allow_fallback=False, use execvp which replaces the process (no return).

    Args:
        connection_name: Connection name for updating cookie cache
        cached_usergroup: Cached usergroup from previous connection (e.g., 'portal:portal-userauthcookie')
        use_pkexec: Use pkexec instead of sudo (for GUI without terminal)
    """

    print(f"\n{GREEN}Connecting to VPN...{NC}\n")

    proto_flag = PROTOCOLS.get(protocol, {}).get("flag", "anyconnect")

    # For GlobalProtect, try different cookie formats
    # Track which cookie type we're using for --usergroup
    gp_cookie_type = None

    # Check if we have a gateway IP to connect to (different from portal)
    gateway_target = cookies.pop('_gateway_ip', None) if protocol == "gp" else None

    if protocol == "gp":
        # GP with SAML: prelogin-cookie from SAML response
        # Based on gp-saml-gui working command:
        # - Use --usergroup=portal:prelogin-cookie (portal mode, not gateway)
        # - Pass cookie via --passwd-on-stdin (not --cookie)
        # - Use --useragent='PAN GlobalProtect'
        # - Use --os=linux-64

        # Use cached usergroup if available (e.g., portal:portal-userauthcookie)
        # This means we have a long-lived cookie from a previous connection
        if cached_usergroup:
            print(f"  Using cached usergroup: {cached_usergroup}")
            gp_cookie_type = cached_usergroup
            # Get the cookie value - try portal-userauthcookie first if usergroup suggests it
            if 'portal-userauthcookie' in cookies:
                cookie_str = cookies['portal-userauthcookie']
                print(f"  Using portal-userauthcookie (long-lived)")
            elif 'prelogin-cookie' in cookies:
                cookie_str = cookies['prelogin-cookie']
                print(f"  Using prelogin-cookie")
            else:
                cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
                print(f"  Using combined cookies")
        elif 'prelogin-cookie' in cookies:
            cookie_str = cookies['prelogin-cookie']
            # Portal mode with prelogin-cookie (matches gp-saml-gui)
            gp_cookie_type = 'portal:prelogin-cookie'
            print(f"  Using prelogin-cookie (portal mode)")
        elif 'portal-userauthcookie' in cookies:
            cookie_str = cookies['portal-userauthcookie']
            # Portal mode with portal-userauthcookie (long-lived)
            gp_cookie_type = 'portal:portal-userauthcookie'
            print(f"  Using portal-userauthcookie (portal mode)")
        elif 'SAMLResponse' in cookies:
            # SAMLResponse as fallback - this is what we POST to VPN, not ideal
            cookie_str = cookies['SAMLResponse']
            gp_cookie_type = 'prelogin-cookie'  # Try as prelogin-cookie
            print(f"  Using SAMLResponse ({len(cookie_str)} chars) - may not work")
        elif 'SESSID' in cookies:
            cookie_str = cookies['SESSID']
            gp_cookie_type = 'portal-userauthcookie'  # SESSID is portal session
            print(f"  Using SESSID - may not work for GP SAML")
        else:
            # Fallback to all cookies in name=value format
            cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
            gp_cookie_type = 'portal-userauthcookie'
            print(f"  Using combined cookies")
    else:
        # AnyConnect uses name=value format
        cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])

    # For GP portal mode, always use the portal hostname (not gateway IP)
    # OpenConnect handles the portal→gateway flow automatically
    connect_target = vpn_server

    # For GP with SAML, use --passwd-on-stdin to pass cookie (like gp-saml-gui)
    use_stdin_cookie = protocol == "gp" and 'prelogin-cookie' in cookies

    if use_stdin_cookie:
        cmd = [
            "openconnect",
            "--verbose",
            f"--protocol={proto_flag}",
            "--passwd-on-stdin",
            connect_target,
        ]
    else:
        cmd = [
            "openconnect",
            "--verbose",
            f"--protocol={proto_flag}",
            f"--cookie={cookie_str}",
            connect_target,
        ]

    # Add username and usergroup for GlobalProtect
    if protocol == "gp":
        # GP needs --os parameter and useragent for proper identification
        # Using linux-64 and 'PAN GlobalProtect' as per gp-saml-gui
        cmd.insert(2, "--os=linux-64")
        cmd.insert(2, "--useragent=PAN GlobalProtect")
        if username:
            cmd.insert(2, f"--user={username}")
        # For GP SAML, specify the cookie type we're using
        if gp_cookie_type:
            cmd.insert(2, f"--usergroup={gp_cookie_type}")

    if no_dtls:
        cmd.insert(2, "--no-dtls")

    display_cmd = f"openconnect --verbose --protocol={proto_flag}"
    if no_dtls:
        display_cmd += " --no-dtls"
    if protocol == "gp":
        display_cmd += " --useragent='PAN GlobalProtect' --os=linux-64"
        if gp_cookie_type:
            display_cmd += f" --usergroup={gp_cookie_type}"
        if username:
            display_cmd += f" --user={username}"
    if use_stdin_cookie:
        display_cmd += f" --passwd-on-stdin {connect_target}"
        print(f"  Running: echo '<cookie>' | {display_cmd}")
        # Debug: show cookie length and first/last chars
        print(f"    [DEBUG] Cookie length: {len(cookie_str)}, starts: {cookie_str[:20]}..., ends: ...{cookie_str[-10:]}")
    else:
        display_cmd += f" --cookie=<session> {connect_target}"
        print(f"  Running: {display_cmd}")
    print()

    if use_stdin_cookie:
        # Write cookie to named file for manual verification
        cookie_file = '/tmp/gp_cookie.txt'
        print(f"    [DEBUG] Writing cookie to {cookie_file}")
        with open(cookie_file, 'w') as f:
            f.write(cookie_str)
            f.write('\n')  # Newline required for openconnect stdin

        # Properly quote command arguments for shell
        cmd_quoted = shlex.join(cmd)

        # Print manual command for testing
        print(f"\n    [DEBUG] MANUAL TEST: Run this command yourself:")
        print(f"    echo {shlex.quote(cookie_str)} | sudo {cmd_quoted}")
        print()

        # Determine privilege escalation command
        if use_pkexec:
            # pkexec for GUI mode - no need to cache credentials, polkit handles it
            priv_cmd = ["pkexec"] + cmd
            print(f"    [DEBUG] Using pkexec for privilege escalation (GUI mode)...")
        else:
            # IMPORTANT: Cache sudo credentials BEFORE redirecting stdin
            # Otherwise sudo will try to read password from the cookie file!
            print(f"    [DEBUG] Caching sudo credentials (required before stdin redirect)...")
            subprocess.run(["sudo", "-v"], check=True)
            priv_cmd = ["sudo"] + cmd

        # Use subprocess with os.pipe() for stdin and stdout capture
        # This allows us to:
        # 1. Pass cookie via stdin
        # 2. Capture stdout to look for portal-userauthcookie (long-lived cookie)
        # 3. Return on failure (allow_fallback)
        print(f"    [DEBUG] Using subprocess with pipe (captures stdout for portal-userauthcookie)...")

        # Create pipe for stdin
        read_fd, write_fd = os.pipe()
        cookie_bytes = (cookie_str + '\n').encode()
        os.write(write_fd, cookie_bytes)
        os.close(write_fd)  # Close write end to signal EOF

        # Run openconnect with stdin from pipe and stdout captured
        process = subprocess.Popen(
            priv_cmd,
            stdin=read_fd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # Combine stderr with stdout
            text=True,
            bufsize=1,  # Line-buffered
        )
        os.close(read_fd)  # Close our copy of read end

        # Read stdout line by line, print to terminal, and look for portal-userauthcookie
        portal_cookie = None
        try:
            for line in process.stdout:
                # Print line to terminal (user can see what's happening)
                print(line, end='')

                # Look for portal-userauthcookie in output
                # OpenConnect outputs: "GlobalProtect login returned portal-userauthcookie=XXX"
                if 'portal-userauthcookie=' in line and protocol == "gp":
                    # Extract cookie value
                    match = re.search(r'portal-userauthcookie=(\S+)', line)
                    if match:
                        portal_cookie = match.group(1)
                        if portal_cookie.lower() != 'empty':
                            print(f"\n    [DEBUG] Captured portal-userauthcookie: {portal_cookie[:20]}...")
        except KeyboardInterrupt:
            # User pressed Ctrl+C, terminate openconnect gracefully
            process.terminate()

        returncode = process.wait()

        # If we got a portal-userauthcookie, update the cache with this long-lived cookie
        if portal_cookie and connection_name and portal_cookie.lower() != 'empty':
            print(f"\n{GREEN}Updating cache with long-lived portal-userauthcookie...{NC}")
            new_cookies = {'portal-userauthcookie': portal_cookie}
            store_cookies(connection_name, new_cookies, usergroup='portal:portal-userauthcookie')
    else:
        # Use sudo/pkexec for openconnect since we're running as normal user
        if use_pkexec:
            if sys.platform == "darwin":
                # macOS: use osascript for GUI sudo prompt
                cmd_str = shlex.join(cmd)
                osa_script = f'do shell script "{cmd_str}" with administrator privileges'
                priv_cmd = ["osascript", "-e", osa_script]
            else:
                priv_cmd = ["pkexec"] + cmd
        else:
            priv_cmd = ["sudo"] + cmd
        process = subprocess.Popen(priv_cmd)
        returncode = process.wait()

    if returncode != 0:
        print(f"\n{YELLOW}Connection failed (exit code {returncode}).{NC}")
        return False
    return True


def disconnect(force=False):
    """Kill any running openconnect process."""
    signal_flag = "-TERM"
    # Use sudo since openconnect runs as root
    result = subprocess.run(["sudo", "pkill", signal_flag, "-f", "openconnect"], capture_output=True)
    if result.returncode == 0:
        if force:
            clear_stored_cookies()
            print(f"{GREEN}VPN disconnected and session terminated.{NC}")
        else:
            print(f"{GREEN}VPN disconnected (session kept alive for reconnect).{NC}")
    else:
        print(f"{YELLOW}No active VPN connection found.{NC}")


def main():
    parser = argparse.ArgumentParser(
        description="OpenConnect VPN with Microsoft SSO authentication (AnyConnect & GlobalProtect)"
    )
    parser.add_argument("name", nargs="?", help="Connection name to connect to")
    parser.add_argument("--visible", action="store_true", help="Show browser window for debugging")
    parser.add_argument("--debug", action="store_true", help="Enable debug output and screenshots")
    parser.add_argument("--disconnect", "-d", action="store_true", help="Disconnect (keep session alive)")
    parser.add_argument("--force-disconnect", action="store_true", help="Disconnect and terminate session")
    parser.add_argument("--setup", "-s", action="store_true", help="Add/edit VPN connection")
    parser.add_argument("--list", "-l", action="store_true", help="List saved connections")
    parser.add_argument("--delete", action="store_true", help="Delete connection from keyring")
    parser.add_argument("--no-cache", action="store_true", help="Force re-authentication")
    parser.add_argument("--no-dtls", action="store_true", help="Disable DTLS (use TCP only)")

    args = parser.parse_args()

    print_header()

    if args.disconnect:
        disconnect(force=False)
        return

    if args.force_disconnect:
        disconnect(force=True)
        return

    if args.list:
        list_connections()
        return

    if args.setup:
        setup_config(edit_name=args.name)
        return

    if args.delete:
        delete_config(name=args.name)
        return

    # New architecture: run EVERYTHING as normal user except openconnect
    # This matches gp-saml-gui which only uses sudo at the very end for execvp

    # Determine which connection to use
    if args.name:
        conn_name = args.name
    else:
        conn_name = select_connection()

    conn_name, address, protocol, username, password, totp_secret = get_config(conn_name)

    if not all([conn_name, address, protocol, username, password, totp_secret]):
        print(f"{RED}Connection not found or incomplete. Use --setup to configure.{NC}")
        sys.exit(1)

    print(f"{GREEN}Connection: {conn_name}{NC}")
    print(f"{GREEN}VPN Server: {address}{NC}")
    print(f"{GREEN}Protocol: {PROTOCOLS.get(protocol, {}).get('name', protocol)}{NC}")
    print(f"{GREEN}Username: {username}{NC}")
    print(f"{GREEN}TOTP code will be generated automatically.{NC}\n")

    # Check for cached cookies
    cached_cookies = None
    cached_usergroup = None
    if not args.no_cache:
        cached_result = get_stored_cookies(conn_name)
        if cached_result:
            cached_cookies, cached_usergroup = cached_result
            print(f"{GREEN}Found cached session cookie.{NC}")
            if cached_usergroup:
                print(f"  Cached usergroup: {cached_usergroup}")

    # Determine no_dtls flag
    no_dtls = args.no_dtls

    # Try cached cookies first (need sudo for openconnect)
    if cached_cookies:
        print(f"{CYAN}Trying cached session cookie...{NC}")
        # Use allow_fallback=True so we can retry with fresh SAML auth if cookie expired
        success = connect_vpn(address, protocol, cached_cookies.copy(), no_dtls=no_dtls,
                             username=username, allow_fallback=True,
                             connection_name=conn_name, cached_usergroup=cached_usergroup)
        if success:
            return
        else:
            print(f"{YELLOW}Cached cookie expired or invalid. Re-authenticating...{NC}\n")
            clear_stored_cookies(conn_name)
            cached_cookies = None

    # Authenticate via browser (runs as normal user - better for Playwright)
    cookies = do_saml_auth(
        address, username, password, totp_secret,
        auto_totp=True,
        headless=not args.visible,
        debug=args.debug
    )

    if cookies:
        # Store with initial usergroup for prelogin-cookie
        store_cookies(conn_name, cookies, usergroup='portal:prelogin-cookie')
        connect_vpn(address, protocol, cookies, no_dtls=no_dtls, username=username,
                   connection_name=conn_name)
    else:
        print(f"\n{RED}Authentication failed.{NC}")
        print(f"Try with --visible to see the browser window.")
        sys.exit(1)


if __name__ == "__main__":
    main()
