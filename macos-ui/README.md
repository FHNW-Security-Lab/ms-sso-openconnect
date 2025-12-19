# MS SSO OpenConnect UI - macOS

A graphical user interface for the MS SSO OpenConnect VPN client on macOS.

## Features

- System tray (menu bar) integration
- Native macOS notifications
- Multiple VPN connection profiles
- TOTP (2FA) support with automatic code generation
- Secure credential storage using macOS Keychain
- Session caching for quick reconnection
- LaunchAgent support for autostart at login

## Requirements

- macOS 11.0 (Big Sur) or later
- Python 3.10 or later
- openconnect (`brew install openconnect`)

## Installation

### From .app Bundle (Recommended)

1. Download the latest release
2. Copy `MS SSO OpenConnect.app` to `/Applications/`
3. Run the app from Launchpad or Spotlight

### From Source

```bash
# Clone the repository
git clone https://github.com/FHNW-Security-Lab/ms-sso-openconnect.git
cd ms-sso-openconnect/macos-ui

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -e .

# Install Playwright browsers
playwright install chromium

# Run
python -m vpn_ui
```

## Building

### Build .app Bundle

```bash
./scripts/build-macos-app.sh [version]
```

The app bundle will be created in `dist/MS SSO OpenConnect.app`.

## Autostart at Login

To have the app start automatically at login:

```bash
/Applications/MS\ SSO\ OpenConnect.app/Contents/Resources/install-launchagent.sh
```

To disable autostart:

```bash
/Applications/MS\ SSO\ OpenConnect.app/Contents/Resources/uninstall-launchagent.sh
```

Or use the Settings dialog in the app to toggle autostart.

## Security

- Credentials are stored in the macOS Keychain
- VPN session cookies are cached locally with expiration
- Administrator password is required for VPN connections (via osascript)

## License

MIT License
