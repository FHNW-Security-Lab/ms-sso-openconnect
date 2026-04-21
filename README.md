# MS SSO OpenConnect

VPN connection tool for Microsoft SSO-protected networks. Handles SAML auth via a headless browser, then hands off to `openconnect`.

This repository contains:

- command-line client
- Linux desktop UI (Qt)
- macOS desktop UI (Qt + LaunchDaemon)
- shared core runtime used by CLI and both UIs

The GNOME NetworkManager plugin has moved to a separate repository: `gnome-ms-sso-plugin`.

## Prerequisites

- Python 3.10+
- `openconnect` on PATH (`brew install openconnect` on macOS, `apt install openconnect` on Debian/Ubuntu)

## Command-Line Tool

```bash
./ms-sso-openconnect --setup    # first run: creates venv, installs deps
./ms-sso-openconnect            # connect
./ms-sso-openconnect --list     # list configured connections
```

## Linux UI

Build a `.deb`, `.AppImage`, or both:

```bash
./frontends/linux/build.sh [version] [appimage|deb|all]
```

Artifacts land under `frontends/linux/dist/` and are mirrored to `dist/linux/`.

## macOS UI

Build and install the `.pkg`:

```bash
./frontends/osx/build.sh [version]
```

The script builds the signed/ad-hoc-signed bundle, bundles Chromium for Playwright, writes the LaunchDaemon, and auto-opens the installer. The `.pkg` installs the app to `/Applications/` and the daemon to `/Library/PrivilegedHelperTools/`.

## Nix

```bash
nix build .#ms-sso-openconnect-core
nix build .#ms-sso-openconnect-ui
```

## Layout

```text
codebase/core/           # Shared auth / connect / config / cookies / totp
codebase/ui/             # Shared Qt UI (Linux + macOS)
ms-sso-openconnect.py    # CLI entry point
ms-sso-openconnect       # CLI bootstrap wrapper (creates venv on first run)

frontends/linux/         # Linux packaging (AppImage, .deb)
frontends/osx/           # macOS packaging (.pkg) + LaunchDaemon

nix/                     # Nix packaging
```

See `CLAUDE.md` for architecture details.
