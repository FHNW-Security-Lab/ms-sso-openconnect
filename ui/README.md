# MS SSO OpenConnect UI

Cross-platform Qt6 GUI for MS SSO OpenConnect VPN client.

## Platforms

- **Linux**: System tray app with pkexec privilege escalation
- **macOS**: Menu bar app with LaunchDaemon for passwordless connections

## Building

### Linux (AppImage + Debian)

```bash
../frontends/linux/build.sh [version] [appimage|deb|all]
# Output: dist/MS-SSO-OpenConnect-UI-{version}-x86_64.AppImage
#         dist/*.deb
```

### macOS (pkg)

```bash
../frontends/osx/build.sh [version]
# Output: dist/MS-SSO-OpenConnect-{version}.pkg
```

Legacy scripts are still available under `ui/scripts/`.

## Development

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -e ".[dev]"

# Install Playwright browser
playwright install chromium

# Run from source
python -m vpn_ui
```

## Architecture

```
ui/
├── src/vpn_ui/           # Shared code (Qt6 UI)
│   ├── main.py           # Application controller
│   ├── tray.py           # System tray
│   ├── worker.py         # Async VPN operations
│   ├── settings_dialog.py
│   ├── connection_form.py
│   ├── backend/          # Backend abstraction
│   └── platform/         # Platform-specific code
├── macos/daemon/         # macOS LaunchDaemon
└── scripts/              # Build scripts
```

## macOS Daemon

The macOS version includes a LaunchDaemon that runs as root, eliminating
the need for password prompts on each connection. The daemon:

- Starts at boot via LaunchDaemon
- Listens on Unix socket for commands from UI
- Manages openconnect process lifecycle
- Uses SIGTERM for graceful disconnect (restores network)
