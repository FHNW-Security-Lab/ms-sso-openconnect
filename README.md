# MS SSO OpenConnect

Command-line and Qt desktop clients for Microsoft SSO-protected Cisco AnyConnect
and GlobalProtect VPNs. Both clients use the shared runtime in `codebase/core/`.
The GNOME NetworkManager integration lives in the separate
[gnome-sso-vpn-plugin repository](https://github.com/FHNW-Security-Lab/gnome-sso-vpn-plugin).

## Debian installation

Download the `.deb` from [Releases](https://github.com/FHNW-Security-Lab/ms-sso-openconnect/releases)
and install it with APT so runtime dependencies are resolved:

```bash
sudo apt install ./ms-sso-openconnect-ui_2.1.0-1_all.deb
ms-sso-openconnect-ui
```

The package requires Python 3.10+, Qt 6.5+, and OpenConnect 9.12+. Initial package
configuration needs internet access to install Playwright and Chromium. Upgrades
reuse a working browser runtime. Python, Qt, keyring, OpenConnect, and the
vpnc routing script are managed by APT. An administrator prompt authorizes VPN
startup and teardown. GNOME needs a tray extension such as AppIndicator to show
the tray menu; settings open automatically when no connections are configured.

## Authentication

Add a connection in **Settings** with its gateway, protocol, username, and
password. Credentials use the system keyring; VPN cookies are stored in a
private per-user cache with owner-only file permissions.

- **Automatic MFA** prefers a configured TOTP secret and otherwise supports
  phone approval. The two-digit Authenticator challenge is displayed when needed.
- **Verification code (TOTP)** requires the Base32 secret from authenticator setup.
- **Phone approval** explicitly selects the registered Authenticator method.
- **GP Authentication** defaults to portal discovery. Select **Direct gateway**
  when the gateway itself provides SAML (for example, a UniBas gateway profile).
- **GP OS Version** defaults to the detected operating system. Override it only
  when a gateway requires a compatibility value.

Browser sessions are isolated by protocol, gateway, and account. The client
waits for Microsoft form bindings, recognizes localized MFA choices, and can
recover once from a stale browser page before credentials are submitted. It
never reloads or replays a password/MFA action as part of that in-attempt recovery.
Mandatory hardware passkeys still require a compatible interactive sign-in path.

## Connection lifecycle

The tray shows authentication and retry progress and reports Connected only when
the owned tunnel is ready. Reconnect policy is saved per profile; the choice to
connect is held only for the current application session. Disconnect cancels
pending authentication and retries. A dropped or expired session can require
fresh SSO and another MFA approval. Retries back off from 5 seconds to 5 minutes;
a stable session resets the delay. An uncertain password or MFA submission stops
automatic retries and reports the error so you can reconnect manually. No
connection starts merely because a profile was saved or the computer rebooted.

Set `MS_SSO_RECONNECT_MAX_ATTEMPTS` to a positive number to limit retries (default
`0` keeps retrying), or disable reconnect for a profile in Settings. Disconnect
before switching to another profile. Upgrading from 2.0.0 can require one new
sign-in because ambiguous legacy cookie-cache filenames are no longer reused.

The standalone client uses OpenConnect's vpnc script for routes and DNS and
terminates only its own tracked tunnel. NetworkManager-specific DNS priority,
resolver validation, firewall/IPv6 leak policy, dispatcher crash recovery, and
the boot-local reconnect observer belong to the separate plugin; this package
does not provide those policies. VPN gateways and identity-provider pages can
change, so passing local regression tests does not guarantee successful live SSO.

## Command line

Run the development/bootstrap client from this checkout:

```bash
./ms-sso-openconnect --setup
./ms-sso-openconnect
./ms-sso-openconnect --list
./ms-sso-openconnect --help
```

## Build and validation

```bash
./build/build.sh deb 2.1.0
# Output: dist/linux/deb/ms-sso-openconnect-ui_2.1.0-1_all.deb
```

Other targets: `appimage`, `linux-all`, `pkg` (macOS), and `nix` (`core`, `ui`,
`all`). `make deb VERSION=2.1.0` is equivalent. Debian builds need `debhelper`
and Python; the builder checks its declared prerequisites before staging files.

Run regression tests with Qt and Playwright installed:

```bash
python3 -m venv --system-site-packages .venv
.venv/bin/python -m pip install -e './codebase/ui[dev]'
.venv/bin/python -m playwright install chromium
QT_QPA_PLATFORM=offscreen .venv/bin/python -m unittest discover -s tests
```

Browser tests use local fixtures and do not contact a VPN or identity provider.
The test suite covers MFA/form readiness, profile recovery, cancellation,
connection lifecycle, UI settings, and package installation behavior.

## Layout

```text
codebase/core/           Shared auth, configuration, cookies, and VPN lifecycle
codebase/ui/             Shared Qt frontend
ms-sso-openconnect.py    CLI entry point
ms-sso-openconnect       CLI bootstrap wrapper
frontends/linux/        Linux build and Debian packaging
frontends/osx/          macOS build and daemon
build/                 Unified build entrypoints
nix/                   Nix packaging
```
