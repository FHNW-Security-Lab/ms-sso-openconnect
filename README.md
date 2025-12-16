# MS SSO OpenConnect

A command-line tool to connect to VPNs protected by Microsoft SSO authentication using OpenConnect.

## Features

- **Named Connections**: Store multiple VPN configurations identified by custom names
- **Multiple Credentials per Server**: Same server can have different credentials under different names
- **Multi-Protocol Support**: Supports both Cisco AnyConnect and GlobalProtect protocols
- **Headless Browser Authentication**: Uses Playwright to automate Microsoft SSO login
- **Secure Credential Storage**: Stores credentials in GNOME Keyring
- **Automatic TOTP Generation**: Generates 2FA codes from stored secret
- **Session Cookie Caching**: Caches session cookies per connection for fast reconnection
- **Auto Re-authentication**: Automatically re-authenticates when cookies expire
- **Dead Peer Detection**: Built-in keepalive settings to prevent connection timeouts

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

Add a VPN connection (credentials stored securely in GNOME Keyring):

```bash
./ms-sso-openconnect --setup
```

You'll be prompted for:
- **Connection Name** (e.g., `work`, `fhnw`, `client-vpn`)
- **VPN Server Address** (e.g., `vpn.example.com`)
- **Protocol** (Cisco AnyConnect or GlobalProtect)
- **Microsoft account email**
- **Password**
- **TOTP Secret** (the base32 secret from your authenticator app setup)

### Connect to VPN

```bash
# Connect to the only/default connection
./ms-sso-openconnect

# Connect by name
./ms-sso-openconnect work
./ms-sso-openconnect fhnw

# If multiple connections exist, you'll be prompted to select one
```

On first connection, it authenticates via headless browser. Subsequent connections use cached session cookies for instant reconnection.

### Manage Connections

```bash
# List all saved connections
./ms-sso-openconnect --list

# Edit an existing connection
./ms-sso-openconnect --setup work

# Delete a specific connection
./ms-sso-openconnect --delete work

# Delete all connections
./ms-sso-openconnect --delete
```

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

# Disable DTLS (use TCP only) - helps with some firewalls
./ms-sso-openconnect --no-dtls
```

## Examples

```bash
# Setup multiple connections to the same server with different accounts
./ms-sso-openconnect --setup
# Name: personal
# Server: vpn.company.com
# ...

./ms-sso-openconnect --setup
# Name: work
# Server: vpn.company.com
# ...

# Connect with specific profile
./ms-sso-openconnect personal
./ms-sso-openconnect work

# List all connections
./ms-sso-openconnect --list
# Output:
#   personal
#     Server:   vpn.company.com
#     Protocol: Cisco AnyConnect
#     Username: john.doe@personal.com
#
#   work
#     Server:   vpn.company.com
#     Protocol: Cisco AnyConnect
#     Username: john.doe@company.com
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
   - Session cookies are cached per connection name in `~/.cache/ms-sso-openconnect/`
   - Cookies expire after 12 hours or when rejected by server
   - Using `-d` to disconnect keeps the session alive on the server

3. **Credential Storage**:
   - All credentials stored in GNOME Keyring (encrypted)
   - Multiple connections supported (identified by name)
   - Same server can have multiple credential sets
   - TOTP secret used to generate fresh codes when needed

4. **Connection Stability**:
   - Dead Peer Detection (DPD) keepalive set to 30 seconds
   - Use `--no-dtls` if you experience connection drops through strict firewalls

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

### Dead Peer Detection errors
If you see "CSTP Dead Peer Detection detected dead peer!", try:
```bash
# Use TCP only mode
./ms-sso-openconnect --no-dtls
```

### Connection drops through firewall
Some firewalls block DTLS (UDP). Use TCP-only mode:
```bash
./ms-sso-openconnect --no-dtls
```

## Files

- `ms-sso-openconnect` - Bash wrapper (sets up venv, handles sudo)
- `ms-sso-openconnect.py` - Main Python script
- `~/.cache/ms-sso-openconnect/session_<name>.json` - Cached session cookies (per connection)

## Security Notes

- Credentials are stored in GNOME Keyring (encrypted at rest)
- Cookie cache files have 600 permissions (owner read/write only)
- TOTP secrets should be kept secure - treat them like passwords
- The browser runs headless by default for security

## License

MIT License

## Contributing

Contributions welcome! Please open an issue or pull request on GitHub.
