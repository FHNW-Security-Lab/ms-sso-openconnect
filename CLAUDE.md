# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MS SSO OpenConnect is a multi-platform VPN connection tool for Microsoft SSO-protected networks. It uses Playwright for headless browser automation to handle Microsoft authentication, then connects via OpenConnect.

**Supported Protocols**: Cisco AnyConnect, GlobalProtect
**Frontends**: CLI, Unified Qt6 GUI (Linux/macOS), GNOME NetworkManager Plugin

## Architecture

```
core/                    # Unified core module (shared by ALL frontends)
├── auth.py             # SAML auth via Playwright headless browser
├── config.py           # Credentials in system keyring
├── connect.py          # openconnect subprocess wrapper
├── cookies.py          # Session cookie caching (12h TTL)
└── totp.py             # TOTP 2FA generation

ms-sso-openconnect.py   # CLI entry point

ui/                     # Unified Qt6 GUI (Linux + macOS)
├── src/vpn_ui/         # Shared UI code
│   ├── main.py         # Application controller
│   ├── tray.py         # System tray
│   ├── worker.py       # Async VPN operations
│   ├── backend/        # Backend abstraction layer
│   └── platform/       # Platform-specific (notifications, autostart, backend)
├── macos/daemon/       # macOS LaunchDaemon (runs as root)
└── scripts/            # Build scripts (build-linux.sh, build-macos.sh)

nm-plugin/              # GNOME NetworkManager VPN plugin (D-Bus + GTK4)
```

**Key Patterns**:
- All frontends import from `core/` - never duplicate core logic
- UI uses platform detection (`sys.platform`) for Linux/macOS differences
- macOS uses LaunchDaemon for passwordless VPN connections (SIGTERM for graceful shutdown)
- Linux uses pkexec for privilege escalation (SIGKILL for fast disconnect)

## Build Commands

### CLI Tool
```bash
chmod +x ms-sso-openconnect
./ms-sso-openconnect --setup  # First run creates venv and installs deps
```

### Unified UI (Linux)
```bash
cd ui
./scripts/build-linux.sh [version]    # Build AppImage + .deb
./scripts/build-linux.sh 2.0.0 appimage  # AppImage only
./scripts/build-linux.sh 2.0.0 deb       # Debian package only
```

### Unified UI (macOS)
```bash
cd ui
./scripts/build-macos.sh [version]    # Build .pkg with daemon
```

### NetworkManager Plugin
```bash
cd nm-plugin
./build-deb.sh                # Build .deb with meson
```

## Testing

```bash
pytest ui/tests/              # Run all tests (when available)
python -m vpn_ui              # Run UI from source
```

## Code Style

- Line length: 100 characters
- Formatter: Black
- Import sorter: isort (black profile)
- Python target: 3.10+

## Platform-Specific Notes

**macOS Daemon Architecture**:
```
[UI App (user)] <--Unix Socket--> [LaunchDaemon (root)] --> [openconnect]
```
- Daemon listens on `/var/run/ms-sso-openconnect/daemon.sock`
- JSON-RPC 2.0 protocol for IPC
- Always uses SIGTERM for graceful disconnect (restores network)

**Linux Privilege Escalation**:
- Uses pkexec (PolicyKit) for GUI password prompts
- Uses SIGKILL for fast disconnect (keeps session alive for reconnect)

**Cookie Storage**:
- Linux: `~/.cache/ms-sso-openconnect-ui/`
- macOS: `~/Library/Application Support/ms-sso-openconnect/`
- NetworkManager (root): `/var/cache/ms-sso-openconnect/`

**Keyring Backends**:
- Linux: GNOME Keyring or KWallet via `keyring` + `secretstorage`
- macOS: Apple Keychain (native `keyring` support)

## Key Files for Understanding Flow

1. `ms-sso-openconnect.py` - CLI entry, shows command patterns
2. `core/auth.py` - SAML browser automation (most complex)
3. `ui/src/vpn_ui/backend/shared.py` - How GUI wraps core module
4. `ui/src/vpn_ui/platform/backend.py` - Platform-specific connect/disconnect
5. `ui/macos/daemon/vpn_daemon.py` - macOS daemon implementation
6. `nm-plugin/src/nm-ms-sso-service.py` - D-Bus VPN service implementation
