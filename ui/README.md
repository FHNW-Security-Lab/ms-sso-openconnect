# MS SSO OpenConnect UI

A cross-platform GUI for the `ms-sso-openconnect` VPN client, supporting both Cisco AnyConnect and GlobalProtect with Microsoft SSO authentication.

## Features

- System tray/menu bar integration
- Multiple VPN connection profiles
- Secure credential storage via system keychain
- Session caching for fast reconnects
- Desktop notifications

## Linux

### Runtime Dependencies

- Python 3.10+
- OpenConnect
- GNOME Keyring or KWallet

Python dependencies are installed automatically by the build scripts:

```
PyQt6>=6.5.0
keyring>=24.0.0
pyotp>=2.8.0
playwright>=1.40.0
secretstorage>=3.3.0
```

### Build AppImage

```bash
./scripts/build-appimage.sh
```

### Build Debian Package

```bash
./scripts/build-deb.sh
```

### Run From Source

```bash
./scripts/install-dev.sh
source .venv/bin/activate
python -m vpn_ui
```

## macOS

### Requirements

- macOS 11.0 or later
- Python 3.10+ (for building)
- openconnect (`brew install openconnect`)

### Install (Recommended)

Build and install the pkg. This installs the app bundle and a privileged launchd helper, so VPN connections do not require sudo after installation.

```bash
./scripts/build-macos-pkg.sh [version]
```

Install the generated pkg from `dist/`.

### Build .app Bundle

```bash
./scripts/build-macos-app.sh [version]
```

Copy the app to `/Applications` and run:

```bash
/Applications/MS\ SSO\ OpenConnect.app/Contents/Resources/install-launchagent.sh
```

## Autostart

You can toggle autostart from the Settings dialog in the app. On Linux it uses an XDG autostart file; on macOS it uses a LaunchAgent.

## Development

```bash
./scripts/install-dev.sh
source .venv/bin/activate
python -m vpn_ui
```
