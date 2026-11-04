# macOS Frontend

This frontend is the Qt menu bar app with macOS helper packaging (`.pkg`).

## Install and connect

Install OpenConnect separately, then open the `.pkg` and launch **MS SSO
OpenConnect** from Applications:

```bash
brew install openconnect
```

Administrator approval is required when installing or updating the package.
Connecting and disconnecting use the installed background helper and do not
request administrator approval. The app runs as your normal user; only the
helper manages the privileged OpenConnect process. The helper includes its own
Python runtime and starts automatically through `launchd`.

The installer requires the running menu bar app to close before an update.
After installation, launch it again from Applications so the new version is
loaded. Replacing the app's files alone does not update an already-running app.

If the app says the helper is unavailable or needs updating, reinstall the
current package. Installation checks that the helper responds before reporting
success. The app does not fall back to an administrator password dialog or keep
retrying a broken helper. Microsoft sign-in, MFA, and Keychain access are separate
from administrator approval and may still require interaction.

For a GlobalProtect profile that authenticates directly at its gateway, choose
**GP Authentication → Direct gateway** in the connection settings. This is the
mode used by direct UniBas gateway profiles in the Linux plugin. Use **Portal**
when the deployment requires portal discovery. The selected mode applies to both
browser authentication and the subsequent VPN connection; a gateway prelogin
cookie is not reused for reconnects. Leave **GP OS Version** empty for automatic
OS reporting unless the gateway requires an explicit compatibility value.

Normal connections sign in with the bundled browser running headlessly. Saved
credentials and a configured TOTP secret are handled automatically, and the
profile's automatic reconnect setting continues to apply. **Connect with
browser** and the error dialog's **Retry with browser** open a visible browser
for one explicit sign-in attempt without reusing saved VPN cookies. Use those
actions when your identity provider requires interaction.

For an IPv4 full-tunnel connection whose gateway supplies no full IPv6 tunnel,
the helper installs temporary IPv6 reject routes so ordinary Internet traffic
falls back to the VPN's IPv4 connection. Advertised VPN DNS servers handle
general lookups unless the server explicitly requests split DNS. Search domains
are preserved. These settings belong to the VPN session and are removed on
disconnect; saved Wi-Fi DNS and IPv6 settings are not changed.

The helper verifies its routes and DNS before reporting a successful connection,
and removes its owned IPv6 protection and DNS entry after an unexpected
OpenConnect exit or helper restart. Normal disconnect also runs OpenConnect's
ordinary tunnel-route cleanup. Crash recovery does not replay that cleanup
against a potentially reused tunnel interface or another VPN's current routes.
This route-based policy is not a system-wide packet-filter kill switch: local
networks, explicit interface-bound traffic, and more-specific routes retain their
normal routing behavior. A genuine IPv6 tunnel is used when the gateway provides
one; split-tunnel connections keep their advertised routing scope.

## Build

Use the canonical build wrapper:

```bash
./frontends/osx/build.sh [version]
```

Artifacts are collected in `dist/osx/pkg/` with the architecture in the filename,
for example `MS-SSO-OpenConnect-2.1.7-macos-arm64.pkg`. Build with a Python
interpreter matching the Mac's architecture; the output is not a universal
Intel/Apple Silicon package.

The builder uses `python3` by default. Set `PYTHON_BIN` to use a portable Python
runtime instead of a Homebrew Python built for a recent macOS version. For
example, with uv installed:

```bash
uv python install 3.13
PYTHON_BIN="$(uv python find --managed-python 3.13)" ./frontends/osx/build.sh 2.1.7
```

The minimum macOS version is inferred from the native binaries in the app and
helper, including Python, Qt, and Chromium. It is written to both the app metadata
and installer requirements. A portable Python can reduce that minimum, but other
bundled dependencies may require a newer macOS version.

The current builder produces an unsigned, unnotarized installer. PyInstaller uses
ad-hoc code signatures, and the completed app is sealed again after Chromium is
added. These signatures provide integrity checks; they are not Developer ID
signatures.

Validate an existing installer without installing it:

```bash
MS_SSO_TEST_PKG=/path/to/package.pkg python3 -m unittest discover -s tests -p test_macos_packaging.py
```

## Implementation Source

- Shared Qt app source: `codebase/ui/src/vpn_ui/`
- Shared runtime: `codebase/core/`
- macOS daemon source: `frontends/osx/daemon/`
- macOS builder: `frontends/osx/scripts/build-macos.sh`
