# MS SSO OpenConnect

A tool to connect to VPNs protected by Microsoft SSO authentication using OpenConnect. Available as a command-line tool, a cross-platform GUI application (Linux/macOS), and a GNOME NetworkManager plugin.

## Installation Options

### Option 1: Desktop GUI Application (Linux & macOS)

A system tray application with a simple interface for managing VPN connections.

#### Linux (AppImage - Recommended)
```bash
cd ui
./scripts/build-linux.sh 2.0.0 appimage
./dist/MS-SSO-OpenConnect-UI-2.0.0-x86_64.AppImage
```

#### Linux (Debian Package)
```bash
cd ui
./scripts/build-linux.sh 2.0.0 deb
sudo dpkg -i dist/ms-sso-openconnect-ui_*.deb
```

#### macOS
```bash
cd ui
./scripts/build-macos.sh 2.0.0
# Install the generated .pkg file
```

**Features:**
- System tray icon with connection status
- Quick connect/disconnect from tray menu
- Multiple connection profiles
- Desktop notifications
- Automatic session cookie caching for fast reconnection
- Passwordless operation via PolicyKit (Linux) or LaunchDaemon (macOS)

### Option 2: GNOME NetworkManager Plugin

Integrates with GNOME Settings, allowing you to manage MS SSO VPN connections like any other VPN.

```bash
cd gnome-nm-plugin
./build-deb.sh
sudo dpkg -i dist/network-manager-ms-sso_*.deb
```

After installation:
1. Open **Settings → Network → VPN**
2. Click **+** to add a new VPN
3. Select **MS SSO OpenConnect**
4. Enter your VPN server and credentials

**Note:** This option is for GNOME desktop users who prefer native NetworkManager integration.

### Option 3: NixOS (UI + GNOME NetworkManager Plugin)

Add the local overlay and enable the packages in `/etc/nixos/configuration.nix`:

```nix
{ config, pkgs, ... }:
{
  nixpkgs.overlays = [ (import /path/to/ms-sso-openconnect/nix/overlay.nix) ];

  networking.networkmanager.enable = true;
  networking.networkmanager.plugins = [ pkgs.networkmanager-ms-sso ];

  environment.systemPackages = [ pkgs.ms-sso-openconnect-ui ];
}
```

Alternatively, import the helper module to wire up the overlay and plugin (and
optionally the UI):

```nix
{
  imports = [ /path/to/ms-sso-openconnect/nix/nixos-module.nix ];

  services.ms-sso-openconnect = {
    enable = true;
    withUi = true; # optional
  };
}
```

Minimal usage (module):

```nix
{
  imports = [ /path/to/ms-sso-openconnect/nix/nixos-module.nix ];

  services.ms-sso-openconnect.enable = true;
}
```

Using GitHub instead of a local checkout (pinned commit):

```nix
let
  msSso = builtins.fetchTarball {
    url = "https://github.com/FHNW-Security-Lab/ms-sso-openconnect/archive/REV.tar.gz";
    # sha256 = "...";
  };
in
{
  imports = [ "${msSso}/nix/nixos-module.nix" ];

  services.ms-sso-openconnect = {
    enable = true;
    withUi = true; # optional
  };
}
```

To get the sha256:
```bash
nix store prefetch-file --hash-type sha256 https://github.com/FHNW-Security-Lab/ms-sso-openconnect/archive/REV.tar.gz
```

Notes:
- Ensure NetworkManager is enabled (`networking.networkmanager.enable = true;`) if it is not already.
- The UI package creates a `~/.cache/ms-playwright` symlink to the packaged browsers on first run.
- The NetworkManager plugin provides `/var/cache/ms-playwright` for root runs.
- You can install just the UI (`pkgs.ms-sso-openconnect-ui`) or just the NM plugin
  (`pkgs.networkmanager-ms-sso`) independently.
- If you upgrade and still see `/home/...` read-only errors, a stale `nm-ms-sso-service` process may be running; reboot or run `sudo pkill -f nm-ms-sso-service` once (the module sets `autoKillStale = true`).
- The module cleans up resolvconf DNS entries on VPN disconnect by default; set `autoCleanupDns = false` to disable.
- The module does not auto-enable; set `services.ms-sso-openconnect.enable = true;` when using it.

### Option 4: Command-Line Tool

For headless servers, scripting, or users who prefer the terminal.

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
./ms-sso-openconnect --setup
```

## Features

- **Named Connections**: Store multiple VPN configurations identified by custom names
- **Multiple Credentials per Server**: Same server can have different credentials under different names
- **Multi-Protocol Support**: Supports both Cisco AnyConnect and GlobalProtect protocols
- **Headless Browser Authentication**: Uses Playwright to automate Microsoft SSO login
- **Secure Credential Storage**: Stores credentials in system keychain (GNOME Keyring on Linux, Apple Keychain on macOS)
- **Automatic TOTP Generation**: Generates 2FA codes from stored secret
- **Session Cookie Caching**: Caches session cookies per connection for fast reconnection (12h TTL)
- **Auto Re-authentication**: Automatically re-authenticates when cookies expire
- **Fast Reconnect**: Detects already signed-in Microsoft accounts for instant reconnection

## Requirements

### Desktop GUI (Linux)
- Python 3.10+
- PyQt6
- OpenConnect
- PolicyKit (for passwordless operation)
- System keychain: GNOME Keyring or KWallet

### Desktop GUI (macOS)
- Python 3.10+
- PyQt6
- OpenConnect (via Homebrew)
- Apple Keychain (built-in)

### GNOME NetworkManager Plugin
- Ubuntu/Debian-based Linux with GNOME
- NetworkManager
- Python 3.8+ with pip
- GTK4 for the connection editor

### Command-Line Tool
- Python 3.8+
- OpenConnect
- System keychain (GNOME Keyring/KWallet on Linux, Apple Keychain on macOS)

## Architecture

```
core/                    # Shared authentication & connection logic
├── auth.py             # Microsoft SAML authentication via Playwright
├── config.py           # Credential storage in system keyring
├── connect.py          # OpenConnect subprocess management
├── cookies.py          # Session cookie caching
└── totp.py             # TOTP 2FA code generation

ms-sso-openconnect.py   # CLI entry point

ui/                     # Cross-platform Qt6 GUI (Linux + macOS)
├── src/vpn_ui/         # Application code
│   ├── main.py         # Main application controller
│   ├── tray.py         # System tray icon & menu
│   ├── worker.py       # Async VPN operations (QThread)
│   ├── backend/        # Backend abstraction
│   └── platform/       # Platform-specific code
├── macos/daemon/       # macOS LaunchDaemon for root operations
└── scripts/            # Build scripts

gnome-nm-plugin/        # GNOME NetworkManager integration
├── src/                # D-Bus service & GTK4 editor
├── data/               # D-Bus configuration files
└── packaging/          # Debian packaging
```

## How It Works

### Authentication Flow
1. Opens VPN portal in headless Chromium browser
2. Detects if user is already signed in (fast reconnect)
3. Enters Microsoft credentials automatically if needed
4. Handles "Use your password instead" if app-based login is shown
5. Generates and enters TOTP code at the right moment
6. Clicks through "Stay signed in?" prompt
7. Extracts session cookies after successful auth

### GUI Application (Linux)
- Runs as a system tray application
- Uses **PolicyKit (pkexec)** for privilege escalation when connecting
- Installs a PolicyKit policy for passwordless VPN connections
- Sends **SIGKILL** to disconnect (keeps session alive for fast reconnect)

### GUI Application (macOS)
- Runs as a system tray/menu bar application
- Uses a **LaunchDaemon** running as root for VPN operations
- UI communicates with daemon via Unix socket (JSON-RPC 2.0)
- Sends **SIGTERM** for graceful disconnect (restores network properly)

### GNOME NetworkManager Plugin
- Registers as a VPN plugin with NetworkManager
- Provides a GTK4 connection editor in GNOME Settings
- Runs authentication via D-Bus service
- Credentials stored in GNOME Keyring

### Cookie Caching
- Session cookies cached per connection name
- Linux GUI: `~/.cache/ms-sso-openconnect-ui/`
- macOS GUI: `~/Library/Application Support/ms-sso-openconnect/`
- CLI: `~/.cache/ms-sso-openconnect/`
- Cookies expire after 12 hours or when rejected by server

## CLI Usage

### Initial Setup
```bash
./ms-sso-openconnect --setup
```

You'll be prompted for:
- **Connection Name** (e.g., `work`, `office`)
- **VPN Server Address** (e.g., `vpn.example.com`)
- **Protocol** (Cisco AnyConnect or GlobalProtect)
- **Microsoft account email**
- **Password**
- **TOTP Secret** (base32 secret from authenticator app setup)

### Connect to VPN
```bash
# Connect to the only/default connection
./ms-sso-openconnect

# Connect by name
./ms-sso-openconnect work

# Force re-authentication (ignore cached cookie)
./ms-sso-openconnect --no-cache

# Show browser window for debugging
./ms-sso-openconnect --visible
```

### Disconnect
```bash
# Disconnect but keep session alive (for fast reconnect)
./ms-sso-openconnect -d

# Disconnect and terminate session
./ms-sso-openconnect --force-disconnect
```

### Manage Connections
```bash
# List all saved connections
./ms-sso-openconnect --list

# Edit an existing connection
./ms-sso-openconnect --setup work

# Delete a connection
./ms-sso-openconnect --delete work
```

## Troubleshooting

### Browser not found
```bash
./venv/bin/playwright install chromium
```

### Authentication timeout
Use `--visible` to watch the browser:
```bash
./ms-sso-openconnect --visible
```

### Connection drops through firewall
Some firewalls block DTLS (UDP). Use TCP-only mode:
```bash
./ms-sso-openconnect --no-dtls
```

### PolicyKit password prompts (Linux GUI)
The Debian package installs a PolicyKit policy for passwordless operation. If you're still getting prompts, ensure the policy file is installed:
```bash
ls /usr/share/polkit-1/actions/org.openconnect.policy
```

## Security Notes

- Credentials stored in system keychain (encrypted at rest)
- Cookie cache files have 600 permissions (owner read/write only)
- TOTP secrets should be kept secure - treat them like passwords
- Browser runs headless by default for security
- macOS daemon socket has restricted permissions

## License

MIT License

## Contributing

Contributions welcome! Please open an issue or pull request on GitHub.
