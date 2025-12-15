# MS SSO OpenConnect

A command-line tool to connect to VPNs protected by Microsoft SSO authentication using OpenConnect.

## Features

- **Headless Browser Authentication**: Uses Playwright to automate Microsoft SSO login
- **Secure Credential Storage**: Stores credentials in GNOME Keyring
- **Automatic TOTP Generation**: Generates 2FA codes from stored secret
- **Session Cookie Caching**: Caches session cookies for fast reconnection
- **Auto Re-authentication**: Automatically re-authenticates when cookies expire

## Requirements

- Python 3.8+
- OpenConnect
- GNOME Keyring (for credential storage)

## Installation

```bash
# Clone the repository
git clone https://github.com/FHNW-Security-Lab/ms-sso-openconnect.git
cd ms-sso-openconnect

# Make executable
chmod +x ms-sso-openconnect

# First run will automatically:
# - Create Python virtual environment
# - Install dependencies (playwright, keyring, pyotp)
# - Download Chromium browser
```

## Usage

### Initial Setup

Configure your VPN server and credentials (stored securely in GNOME Keyring):

```bash
./ms-sso-openconnect --setup
```

You'll be prompted for:
- VPN Server Domain (e.g., `vpn.example.com`)
- Microsoft account email
- Password
- TOTP Secret (the base32 secret from your authenticator app setup)

### Connect to VPN

```bash
./ms-sso-openconnect
```

On first connection, it authenticates via headless browser. Subsequent connections use cached session cookies for instant reconnection.

### Disconnect

```bash
# Disconnect but keep session alive (for fast reconnect)
./ms-sso-openconnect -d

# Disconnect and terminate session (invalidates cookie)
./ms-sso-openconnect --force-disconnect
```

### Other Options

```bash
# Force re-authentication (ignore cached cookie)
./ms-sso-openconnect --no-cache

# Show browser window for debugging
./ms-sso-openconnect --visible

# Enable debug output and screenshots
./ms-sso-openconnect --debug

# Clear stored credentials
./ms-sso-openconnect --clear
```

## How It Works

1. **Authentication Flow**:
   - Opens VPN portal in headless Chromium browser
   - Enters Microsoft credentials automatically
   - Handles "Use your password instead" if app-based login is shown
   - Generates and enters TOTP code at the right moment
   - Clicks through "Stay signed in?" prompt
   - Extracts session cookies after successful auth

2. **Cookie Caching**:
   - Session cookies are cached in `~/.cache/ms-sso-openconnect/session.json`
   - Cookies expire after 12 hours or when rejected by server
   - Using `-d` to disconnect keeps the session alive on the server

3. **Credential Storage**:
   - All credentials stored in GNOME Keyring (encrypted)
   - TOTP secret used to generate fresh codes when needed

## Troubleshooting

### Browser not found
The wrapper script automatically installs Chromium. If it fails, run:
```bash
./venv/bin/playwright install chromium
```

### Keyring access issues
Make sure GNOME Keyring is running and unlocked:
```bash
# Check if keyring is available
python3 -c "import keyring; print(keyring.get_keyring())"
```

### Authentication timeout
Use `--visible` to watch the browser and identify where it gets stuck:
```bash
./ms-sso-openconnect --visible
```

### Cookie rejected
If you see "Cookie was rejected by server", the session expired. The tool will automatically re-authenticate.

## Files

- `ms-sso-openconnect` - Bash wrapper (sets up venv, handles sudo)
- `ms-sso-openconnect.py` - Main Python script
- `~/.cache/ms-sso-openconnect/session.json` - Cached session cookies

## Security Notes

- Credentials are stored in GNOME Keyring (encrypted at rest)
- Cookie cache file has 600 permissions (owner read/write only)
- TOTP secrets should be kept secure - treat them like passwords
- The browser runs headless by default for security

## License

MIT License

## Contributing

Contributions welcome! Please open an issue or pull request on GitHub.
