# MS SSO OpenConnect

A tool to connect to VPNs protected by Microsoft SSO authentication using OpenConnect. Available as a command-line tool, a cross-platform GUI application (Linux/macOS), and a GNOME NetworkManager plugin.

## Build and Packaging

Use the unified build entrypoint:

```bash
./build/build.sh <target> [version-or-component]
```

Supported packaging targets:

- `pkg` (macOS package)
- `deb` (Linux Qt frontend)
- `appimage` (Linux Qt frontend)
- `gnome-deb` (GNOME NetworkManager plugin)
- `nix` (Nix package set: `core`, `ui`, `plugin`, `all`)

Optional `make` shortcuts are provided:

```bash
make appimage VERSION=2.0.0
make deb VERSION=2.0.0
make pkg VERSION=2.0.0
make gnome-deb
make nix
```

Build outputs are collected under top-level `dist/`:

- `dist/linux/appimage/`
- `dist/linux/deb/`
- `dist/osx/pkg/`
- `dist/gnome-plugin/deb/`

### NixOS (GNOME NetworkManager Plugin)

Add this to `/etc/nixos/configuration.nix`:

```nix
let
  msSso = builtins.fetchTarball {
    url = "https://github.com/FHNW-Security-Lab/ms-sso-openconnect/archive/a10badc.tar.gz";
  };
in
{
  imports = [ (import "${msSso}/nix/nixos-module.nix") ];

  networking.networkmanager.enable = true;
  nixpkgs.overlays = [ (import "${msSso}/nix/overlay.nix") ];
  services.ms-sso-openconnect.enable = true;

  environment.systemPackages = with pkgs; [
    networkmanager-ms-sso
  ];
}
```

Rebuild:
```bash
sudo nixos-rebuild switch
```

### Command-Line Tool

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
codebase/                # Shared architecture docs and runtime contracts
core/                    # Shared auth/connect logic used by all frontends
ms-sso-openconnect.py    # CLI entry point
ms-sso-openconnect       # CLI bootstrap wrapper

frontends/
├── linux/               # Linux Qt frontend build wrapper
├── osx/                 # macOS Qt frontend build wrapper
└── gnome-plugin/        # GNOME plugin build wrapper

build/                   # Unified build entrypoints
└── build.sh             # Main dispatcher for pkg/deb/appimage/nix

ui/                      # Qt frontend implementation (Linux + macOS)
gnome-nm-plugin/         # GNOME NetworkManager plugin implementation
nix/                     # Nix/NixOS packaging support
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
