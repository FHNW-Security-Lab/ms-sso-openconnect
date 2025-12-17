# MS SSO OpenConnect

A tool to connect to VPNs protected by Microsoft SSO authentication using OpenConnect. Available as both a command-line tool and a GNOME NetworkManager plugin.

## Installation Options

### Option 1: GNOME NetworkManager Plugin (Recommended for Desktop)

The NetworkManager plugin integrates with GNOME Settings, allowing you to manage MS SSO VPN connections like any other VPN.

```bash
cd nm-plugin
./build-deb.sh
sudo dpkg -i dist/network-manager-ms-sso_*.deb
```

After installation:
1. Open **Settings → Network → VPN**
2. Click **+** to add a new VPN
3. Select **MS SSO OpenConnect**
4. Enter your VPN server and credentials

### Option 2: Command-Line Tool

For headless servers or users who prefer the terminal.

## Features (Command-Line)

- **Named Connections**: Store multiple VPN configurations identified by custom names
- **Multiple Credentials per Server**: Same server can have different credentials under different names
- **Multi-Protocol Support**: Supports both Cisco AnyConnect and GlobalProtect protocols
- **Headless Browser Authentication**: Uses Playwright to automate Microsoft SSO login
- **Secure Credential Storage**: Stores credentials in system keychain (GNOME Keyring on Linux, Apple Keychain on macOS)
- **Automatic TOTP Generation**: Generates 2FA codes from stored secret
- **Session Cookie Caching**: Caches session cookies per connection for fast reconnection
- **Auto Re-authentication**: Automatically re-authenticates when cookies expire
- **Dead Peer Detection**: Built-in keepalive settings to prevent connection timeouts

## Requirements

### NetworkManager Plugin
- Ubuntu/Debian-based Linux with GNOME
- NetworkManager
- Python 3.8+ with pip
- Dependencies installed automatically: playwright, keyring, pyotp

### Command-Line Tool
- Python 3.8+
- OpenConnect
- System keychain:
  - **Linux**: GNOME Keyring or KWallet
  - **macOS**: Apple Keychain (built-in)

## Command-Line Installation

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

Add a VPN connection (credentials stored securely in system keychain):

```bash
./ms-sso-openconnect --setup
```

You'll be prompted for:
- **Connection Name** (e.g., `work`, `office`, `client-vpn`)
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
./ms-sso-openconnect office

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
   - All credentials stored in system keychain (GNOME Keyring/KWallet on Linux, Apple Keychain on macOS)
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
Make sure your system keychain is available:
```bash
# Check which keyring backend is being used
python3 -c "import keyring; print(keyring.get_keyring())"
```
On Linux, ensure GNOME Keyring or KWallet is running and unlocked. On macOS, Apple Keychain should work automatically.

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

### Command-Line Tool
- `ms-sso-openconnect` - Bash wrapper (sets up venv, handles sudo)
- `ms-sso-openconnect.py` - Main Python script
- `~/.cache/ms-sso-openconnect/session_<name>.json` - Cached session cookies (per connection)

### NetworkManager Plugin
- `nm-plugin/` - GNOME NetworkManager VPN plugin
- `nm-plugin/build-deb.sh` - Build script for Debian package
- `nm-plugin/src/nm-ms-sso-service.py` - VPN D-Bus service
- `nm-plugin/src/editor/` - GTK4 connection editor for GNOME Settings

## Security Notes

- Credentials are stored in system keychain (encrypted at rest)
- Cookie cache files have 600 permissions (owner read/write only)
- TOTP secrets should be kept secure - treat them like passwords
- The browser runs headless by default for security

## License

MIT License

## Contributing

Contributions welcome! Please open an issue or pull request on GitHub.
