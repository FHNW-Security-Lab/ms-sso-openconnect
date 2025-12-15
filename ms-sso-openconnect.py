#!/usr/bin/env python3
"""
MS SSO OpenConnect - Headless Browser Authentication

Connects to any VPN using Microsoft SSO via a headless browser,
then passes the authentication cookie to openconnect.

Features:
- Credentials and VPN domain stored securely in GNOME keyring
- TOTP codes generated automatically from stored secret
- Session cookies cached for fast reconnection
- Automatic re-authentication when cookies expire
- Ctrl+C suspends without terminating session (fast reconnect)

Usage:
    ./ms-sso-openconnect --setup            (configure VPN and credentials)
    ./ms-sso-openconnect                    (connect, uses cached cookie if valid)
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

KEYRING_SERVICE = "ms-sso-openconnect"

# Colors
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
NC = "\033[0m"


def print_header():
    print(f"{GREEN}========================================{NC}")
    print(f"{GREEN}    MS SSO OpenConnect - VPN Client{NC}")
    print(f"{GREEN}========================================{NC}")
    print()


def get_stored_config():
    """Retrieve VPN domain and credentials from GNOME keyring."""
    try:
        import keyring

        vpn_domain = keyring.get_password(KEYRING_SERVICE, "vpn_domain")
        username = keyring.get_password(KEYRING_SERVICE, "username")
        password = keyring.get_password(KEYRING_SERVICE, "password")
        totp_secret = keyring.get_password(KEYRING_SERVICE, "totp_secret")

        return vpn_domain, username, password, totp_secret
    except Exception as e:
        print(f"{YELLOW}Keyring error: {e}{NC}")
        return None, None, None, None


def generate_totp(totp_secret):
    """Generate current TOTP code from secret."""
    import pyotp
    totp = pyotp.TOTP(totp_secret)
    return totp.now()


def _get_cookie_file():
    """Get path to cookie cache file in user's home directory."""
    # Get real user's home even when running as root
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
    return os.path.join(cache_dir, "session.json")


def store_cookies(cookies):
    """Store session cookies in a secure file."""
    try:
        cookie_file = _get_cookie_file()
        data = {
            "cookies": cookies,
            "timestamp": int(time.time())
        }
        # Write with restricted permissions
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
                # Also fix cache directory ownership
                cache_dir = os.path.dirname(cookie_file)
                os.chown(cache_dir, pw.pw_uid, pw.pw_gid)
            except (KeyError, OSError):
                pass

        print(f"{GREEN}Session cookie cached.{NC}")
        return True
    except Exception as e:
        print(f"{YELLOW}Could not cache cookies: {e}{NC}")
        return False


def get_stored_cookies(max_age_hours=12):
    """Retrieve cached session cookies from file."""
    try:
        cookie_file = _get_cookie_file()
        if not os.path.exists(cookie_file):
            return None

        with open(cookie_file, 'r') as f:
            data = json.load(f)

        # Check if cookies are too old
        age_seconds = int(time.time()) - data.get("timestamp", 0)
        if age_seconds > max_age_hours * 3600:
            clear_stored_cookies()
            return None

        return data.get("cookies")
    except Exception:
        return None


def clear_stored_cookies():
    """Clear cached cookies file."""
    try:
        cookie_file = _get_cookie_file()
        if os.path.exists(cookie_file):
            os.remove(cookie_file)
    except Exception:
        pass


def store_config(vpn_domain, username, password, totp_secret):
    """Store VPN config and credentials in GNOME keyring."""
    try:
        import keyring

        keyring.set_password(KEYRING_SERVICE, "vpn_domain", vpn_domain)
        keyring.set_password(KEYRING_SERVICE, "username", username)
        keyring.set_password(KEYRING_SERVICE, "password", password)
        keyring.set_password(KEYRING_SERVICE, "totp_secret", totp_secret)
        print(f"{GREEN}Configuration stored in keyring.{NC}")
        return True
    except Exception as e:
        print(f"{RED}Failed to store configuration: {e}{NC}")
        return False


def setup_config():
    """Interactive setup to store VPN config and credentials in keyring."""
    print(f"{CYAN}=== MS SSO OpenConnect Setup ==={NC}\n")
    print("Your configuration will be stored securely in GNOME keyring.\n")

    # VPN Domain
    print(f"{CYAN}VPN Server Configuration:{NC}")
    vpn_domain = input("VPN Server Domain (e.g., vpn.example.com): ").strip()
    if not vpn_domain:
        print(f"{RED}Error: VPN domain cannot be empty{NC}")
        return False

    # Username
    print(f"\n{CYAN}Microsoft SSO Credentials:{NC}")
    username = input("Username (email): ").strip()
    if not username:
        print(f"{RED}Error: Username cannot be empty{NC}")
        return False

    # Password
    password = getpass.getpass("Password: ")
    if not password:
        print(f"{RED}Error: Password cannot be empty{NC}")
        return False

    # TOTP Secret
    print(f"\n{CYAN}TOTP Secret Setup:{NC}")
    print("Enter your Microsoft Authenticator TOTP secret key.")
    print("This is the secret shown when you set up the authenticator app")
    print("(often shown as a QR code, but also available as text).\n")

    totp_secret = input("TOTP Secret (base32, no spaces): ").strip().replace(" ", "").upper()
    if not totp_secret:
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

    # Store configuration
    if store_config(vpn_domain, username, password, totp_secret):
        print(f"\n{GREEN}Setup complete! Run './ms-sso-openconnect' to connect.{NC}")
        return True
    return False


def clear_config():
    """Remove stored configuration from keyring."""
    try:
        import keyring

        for key in ["vpn_domain", "username", "password", "totp_secret"]:
            try:
                keyring.delete_password(KEYRING_SERVICE, key)
            except keyring.errors.PasswordDeleteError:
                pass
        # Also clear cached cookies
        clear_stored_cookies()
        print(f"{GREEN}Configuration cleared from keyring.{NC}")
    except Exception as e:
        print(f"{RED}Error clearing configuration: {e}{NC}")


def get_config():
    """Get VPN config from keyring or prompt user.

    Returns: (vpn_domain, username, password, totp_secret_or_code, is_auto)
    - is_auto=True means totp_secret_or_code is a secret to generate codes from
    - is_auto=False means totp_secret_or_code is a manual OTP code
    """
    vpn_domain, username, password, totp_secret = get_stored_config()

    if vpn_domain and username and password and totp_secret:
        print(f"{GREEN}VPN Server: {vpn_domain}{NC}")
        print(f"{GREEN}Using stored credentials for: {username}{NC}")
        print(f"{GREEN}TOTP code will be generated automatically.{NC}\n")
        return vpn_domain, username, password, totp_secret, True

    # Fallback to manual entry
    print(f"{YELLOW}No stored configuration found. Use --setup to save configuration.{NC}\n")
    print(f"{CYAN}Enter VPN configuration:{NC}\n")

    if not vpn_domain:
        vpn_domain = input("VPN Server Domain: ").strip()
        if not vpn_domain:
            print(f"{RED}Error: VPN domain cannot be empty{NC}")
            sys.exit(1)

    if not username:
        username = input("Username (email): ").strip()
        if not username:
            print(f"{RED}Error: Username cannot be empty{NC}")
            sys.exit(1)

    if not password:
        password = getpass.getpass("Password: ")
        if not password:
            print(f"{RED}Error: Password cannot be empty{NC}")
            sys.exit(1)

    otp = input("2FA Code: ").strip()
    if not otp:
        print(f"{RED}Error: 2FA code cannot be empty{NC}")
        sys.exit(1)

    return vpn_domain, username, password, otp, False


def do_saml_auth(vpn_server, username, password, totp_secret_or_code, auto_totp=False, headless=True, debug=False):
    """
    Complete Microsoft SAML authentication and return the session cookie.

    Args:
        vpn_server: VPN server domain
        totp_secret_or_code: Either a TOTP secret (if auto_totp=True) or a manual code
        auto_totp: If True, generate TOTP code from secret right when needed
    """
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    import pwd

    vpn_url = f"https://{vpn_server}"

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
        # Launch browser
        browser = p.chromium.launch(
            headless=headless,
            args=[
                '--no-sandbox',
                '--disable-dev-shm-usage',
            ]
        )

        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        page = context.new_page()

        try:
            # 1. Open VPN portal
            print("  [1/6] Opening VPN portal...")
            page.goto(vpn_url, timeout=30000, wait_until="domcontentloaded")

            # 2. Enter username on Microsoft login
            print("  [2/6] Entering username...")
            page.wait_for_selector('input[name="loginfmt"]', timeout=10000)
            page.fill('input[name="loginfmt"]', username)
            page.click('input[type="submit"]')
            page.wait_for_load_state("domcontentloaded")

            # 3. Handle password entry - either direct or via "Use your password instead"
            print("  [3/6] Entering password...")

            # First check if password field is already visible
            password_field = page.query_selector('input[name="passwd"]:visible')

            if not password_field:
                # Password not visible - look for "Use your password instead" link
                print("    -> Looking for password login option...")
                password_link_selectors = [
                    '#idA_PWD_SwitchToPassword',  # Common Microsoft ID
                    'a:has-text("Use your password instead")',
                    'a:has-text("password instead")',
                    'a:has-text("Use a password")',
                    '#idA_PWD_SwitchToCredPicker',
                ]

                link_clicked = False
                for selector in password_link_selectors:
                    try:
                        link = page.wait_for_selector(selector, timeout=3000)
                        if link:
                            link.click()
                            page.wait_for_load_state("domcontentloaded")
                            print("    -> Switched to password login")
                            link_clicked = True
                            break
                    except PWTimeout:
                        continue

                if not link_clicked:
                    # Maybe it's showing authenticator app prompt - wait briefly
                    time.sleep(0.5)
                    password_field = page.query_selector('input[name="passwd"]:visible')

            # Now wait for password field
            try:
                page.wait_for_selector('input[name="passwd"]', timeout=5000, state="visible")
                print("    -> Password field ready")
            except PWTimeout:
                if debug:
                    page.screenshot(path="/tmp/vpn-password-wait.png")
                    print(f"  {YELLOW}Screenshot: /tmp/vpn-password-wait.png{NC}")
                raise

            page.fill('input[name="passwd"]', password)
            page.click('input[type="submit"]')
            page.wait_for_load_state("domcontentloaded")

            # 4. Handle 2FA
            print("  [4/6] Entering 2FA code...")

            # First check if TOTP input is already visible
            otp_input = page.query_selector('#idTxtBx_SAOTCC_OTC:visible, input[name="otc"]:visible')

            if not otp_input:
                # Might be showing Authenticator app approval - switch to TOTP
                print("    -> Looking for TOTP code option...")
                totp_link_selectors = [
                    'a:has-text("I can\'t use my Microsoft Authenticator app right now")',
                    'a:has-text("use a verification code")',
                    'a:has-text("verify another way")',
                    '#signInAnotherWay',
                    'a:has-text("Sign in another way")',
                ]

                for selector in totp_link_selectors:
                    try:
                        link = page.wait_for_selector(selector, timeout=2000)
                        if link:
                            link.click()
                            page.wait_for_load_state("domcontentloaded")
                            print("    -> Switched to TOTP code entry")
                            break
                    except PWTimeout:
                        continue

                # After clicking, need to select "Use a verification code" from the list

                code_option_clicked = False
                code_option_selectors = [
                    'div[data-value="PhoneAppOTP"]',
                    '[data-testid="PhoneAppOTP"]',
                ]

                for selector in code_option_selectors:
                    try:
                        code_option = page.wait_for_selector(selector, timeout=2000)
                        if code_option:
                            code_option.click()
                            code_option_clicked = True
                            print("    -> Selected verification code method")
                            break
                    except PWTimeout:
                        continue

                # Fallback: click by text content
                if not code_option_clicked:
                    try:
                        page.get_by_text("Use a verification code").click()
                        code_option_clicked = True
                        print("    -> Selected verification code method (by text)")
                    except:
                        pass

                page.wait_for_load_state("domcontentloaded")

            # Now try to find and fill TOTP input
            otp_entered = False
            otp_selectors = [
                '#idTxtBx_SAOTCC_OTC',
                'input[name="otc"]',
                'input[data-testid="otc"]',
                'input[placeholder*="code"]',
            ]

            for selector in otp_selectors:
                try:
                    otp_input = page.wait_for_selector(selector, timeout=3000, state="visible")
                    if otp_input:
                        # Generate TOTP code NOW if using auto mode
                        if auto_totp:
                            otp = generate_totp(totp_secret_or_code)
                            print(f"    -> Generated TOTP code: {otp}")
                        else:
                            otp = totp_secret_or_code
                        otp_input.fill(otp)
                        otp_entered = True
                        print("    -> TOTP code entered")
                        break
                except PWTimeout:
                    continue

            if otp_entered:
                # Click submit button
                submit_selectors = [
                    '#idSubmit_SAOTCC_Continue',
                    'input[type="submit"]',
                    'button[type="submit"]',
                ]
                for selector in submit_selectors:
                    try:
                        btn = page.query_selector(selector)
                        if btn:
                            btn.click()
                            break
                    except:
                        continue
            else:
                print(f"  {YELLOW}Warning: 2FA input not found{NC}")
                if debug:
                    page.screenshot(path="/tmp/vpn-2fa.png")
                    print("  Screenshot: /tmp/vpn-2fa.png")

            # 5. Handle "Stay signed in?" - click Yes
            print("  [5/6] Completing login...")
            try:
                page.wait_for_selector('#idSIButton9', timeout=8000)
                page.click('#idSIButton9')  # "Yes" button
                print("    -> Clicked 'Stay signed in'")
            except PWTimeout:
                pass  # No prompt shown

            page.wait_for_load_state("domcontentloaded")

            # 6. Wait for redirect back to VPN and get cookies
            print("  [6/6] Getting session cookie...")

            # Wait for VPN page
            try:
                page.wait_for_url(f"**{vpn_server}**", timeout=15000)
            except PWTimeout:
                pass  # Might already be there

            # Brief wait for cookies to be set
            time.sleep(0.5)

            # Get all cookies
            cookies = context.cookies()

            # Build cookie string for openconnect
            # Extract domain base for cookie matching
            domain_parts = vpn_server.split('.')
            if len(domain_parts) >= 2:
                base_domain = '.'.join(domain_parts[-2:])
            else:
                base_domain = vpn_server

            vpn_cookies = {}
            for c in cookies:
                domain = c.get('domain', '')
                if vpn_server in domain or domain.endswith(f'.{base_domain}') or domain == f'.{base_domain}':
                    vpn_cookies[c['name']] = c['value']

            if debug:
                print(f"\n  Cookies found: {list(vpn_cookies.keys())}")
                page.screenshot(path="/tmp/vpn-final.png")
                print(f"  Screenshot: /tmp/vpn-final.png")

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
                    print("Screenshot: /tmp/vpn-error.png")
                except:
                    pass
            browser.close()
            return None


def connect_vpn(vpn_server, cookies, test_only=False):
    """Connect to VPN using openconnect with the obtained cookie.

    Args:
        vpn_server: VPN server domain
        cookies: Session cookies dict
        test_only: If True, just test the cookie validity without staying connected

    Returns:
        True if connection was successful (or user disconnected), False if auth failed
    """

    print(f"\n{GREEN}Connecting to VPN...{NC}\n")

    # Build the cookie string
    # For Cisco AnyConnect, we need the webvpn cookies
    cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])

    cmd = [
        "openconnect",
        "--protocol=anyconnect",
        f"--cookie={cookie_str}",
        vpn_server,
    ]

    print(f"  Running: openconnect --protocol=anyconnect --cookie=<session> {vpn_server}")
    print()

    process = subprocess.Popen(cmd)
    returncode = process.wait()

    # Check if connection failed due to auth issues
    # returncode 2 = cookie rejected/auth failure
    if returncode == 2:
        print(f"\n{YELLOW}Cookie was rejected by server.{NC}")
        return False
    return True


def disconnect(force=False):
    """Kill any running openconnect process.

    Args:
        force: If True, send SIGTERM (allows BYE packet) and clear cookie cache.
               If False, send SIGKILL (no BYE, session stays valid).
    """
    signal_flag = "-TERM" if force else "-KILL"
    result = subprocess.run(
        ["pkill", signal_flag, "-f", "openconnect"],
        capture_output=True
    )
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
        description="OpenConnect VPN with Microsoft SSO authentication"
    )
    parser.add_argument("--visible", action="store_true",
                        help="Show browser window for debugging")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug output and screenshots")
    parser.add_argument("--disconnect", "-d", action="store_true",
                        help="Disconnect from VPN (keeps session alive for reconnect)")
    parser.add_argument("--force-disconnect", action="store_true",
                        help="Disconnect and terminate session (invalidates cookie)")
    parser.add_argument("--setup", "-s", action="store_true",
                        help="Setup VPN configuration in keyring")
    parser.add_argument("--clear", action="store_true",
                        help="Clear stored configuration from keyring")
    parser.add_argument("--no-cache", action="store_true",
                        help="Force re-authentication, ignore cached cookie")
    # Internal args for passing credentials through sudo
    parser.add_argument("--_domain", help=argparse.SUPPRESS)
    parser.add_argument("--_user", help=argparse.SUPPRESS)
    parser.add_argument("--_pass", help=argparse.SUPPRESS)
    parser.add_argument("--_totp", help=argparse.SUPPRESS)
    parser.add_argument("--_cookies", help=argparse.SUPPRESS)

    args = parser.parse_args()

    print_header()

    if args.disconnect:
        disconnect(force=False)
        return

    if args.force_disconnect:
        disconnect(force=True)
        return

    if args.setup:
        setup_config()
        return

    if args.clear:
        clear_config()
        return

    # Get config BEFORE sudo (keyring access works better as normal user)
    if os.geteuid() != 0:
        # Not root yet - get config now while we can access keyring
        vpn_domain, username, password, totp_secret_or_code, auto_totp = get_config()

        # Check for cached cookies (unless --no-cache)
        cached_cookies = None
        if not args.no_cache:
            cached_cookies = get_stored_cookies()
            if cached_cookies:
                print(f"{GREEN}Found cached session cookie.{NC}")

        print(f"{YELLOW}OpenConnect requires root privileges.{NC}")
        # Pass config through to sudo invocation
        # Explicitly pass DBUS for keyring access as root
        dbus_addr = os.environ.get('DBUS_SESSION_BUS_ADDRESS', f"unix:path=/run/user/{os.getuid()}/bus")
        sudo_args = ["sudo", f"DBUS_SESSION_BUS_ADDRESS={dbus_addr}", sys.executable] + sys.argv
        sudo_args.extend(["--_domain", vpn_domain, "--_user", username, "--_pass", password])
        if auto_totp:
            sudo_args.extend(["--_totp", totp_secret_or_code])
        else:
            sudo_args.extend(["--_totp", f"CODE:{totp_secret_or_code}"])
        if cached_cookies:
            sudo_args.extend(["--_cookies", json.dumps(cached_cookies)])
        os.execvp("sudo", sudo_args)

    # Running as root - get config from args or prompt
    if args._domain and args._user and args._pass and args._totp:
        vpn_domain = args._domain
        username = args._user
        password = args._pass
        if args._totp.startswith("CODE:"):
            totp_secret_or_code = args._totp[5:]
            auto_totp = False
        else:
            totp_secret_or_code = args._totp
            auto_totp = True
        print(f"{GREEN}VPN Server: {vpn_domain}{NC}")
        print(f"{GREEN}Using stored credentials for: {username}{NC}")
        print(f"{GREEN}TOTP code will be generated automatically.{NC}\n")
    else:
        vpn_domain, username, password, totp_secret_or_code, auto_totp = get_config()

    # Check for cached cookies passed from non-root invocation
    cached_cookies = None
    if args._cookies and not args.no_cache:
        try:
            cached_cookies = json.loads(args._cookies)
        except:
            pass

    # Try cached cookies first
    if cached_cookies:
        print(f"{CYAN}Trying cached session cookie...{NC}")
        success = connect_vpn(vpn_domain, cached_cookies)
        if success:
            return  # User disconnected or connection ended normally
        else:
            print(f"{YELLOW}Cached cookie expired or invalid. Re-authenticating...{NC}\n")
            clear_stored_cookies()  # Clear invalid cookies
            cached_cookies = None

    # Authenticate via browser
    cookies = do_saml_auth(
        vpn_domain, username, password, totp_secret_or_code,
        auto_totp=auto_totp,
        headless=not args.visible,
        debug=args.debug
    )

    if cookies:
        # Store cookies for reuse (need to do this as root, will try)
        # Note: This might not work as root, but we try anyway
        store_cookies(cookies)
        connect_vpn(vpn_domain, cookies)
    else:
        print(f"\n{RED}Authentication failed.{NC}")
        print(f"Try with --visible to see the browser window.")
        sys.exit(1)


if __name__ == "__main__":
    main()
