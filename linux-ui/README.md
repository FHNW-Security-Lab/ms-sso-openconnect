# MS SSO OpenConnect UI

A graphical user interface for the `ms-sso-openconnect` VPN client tool, supporting both Cisco AnyConnect and GlobalProtect protocols with Microsoft SSO authentication.

## Features

- **System Tray Icon**: Real-time connection status indicator
- **Multiple Connections**: Manage multiple VPN profiles
- **Secure Storage**: Credentials stored in system keychain
- **Session Caching**: Fast reconnection with cached cookies
- **Desktop Notifications**: Connect/disconnect/error notifications
- **Cross-Desktop**: Works on GNOME, KDE, XFCE, and other DEs

## Dependencies

### Runtime Dependencies

| Package | Description |
|---------|-------------|
| `python3` (>=3.10) | Python interpreter |
| `python3-pyqt6` | Qt6 bindings for Python |
| `python3-keyring` | Secure credential storage |
| `python3-secretstorage` | Secret Service D-Bus interface |
| `python3-pyotp` | TOTP code generation (optional) |
| `openconnect` | VPN client |
| `gnome-keyring` or `kwallet` | Secret storage backend |
| `chromium` or `chromium-browser` | Browser for Playwright SSO (optional) |

### Build Dependencies (Debian Package)

Install these before running `./scripts/build-deb.sh`:

```bash
sudo apt install devscripts debhelper dh-python python3-all pybuild-plugin-pyproject
```

| Package | Description |
|---------|-------------|
| `devscripts` | Provides `dpkg-buildpackage` |
| `debhelper` | Debian package helper tools |
| `dh-python` | Python packaging for Debian |
| `python3-all` | All Python 3 versions |
| `pybuild-plugin-pyproject` | PEP 517 build support |

### Build Dependencies (AppImage)

The AppImage build script (`./scripts/build-appimage.sh`) is self-contained and only requires:

```bash
# Required
sudo apt install python3 python3-venv curl
```

The script automatically:
- Creates a Python virtual environment with all dependencies
- Downloads and installs Playwright with Chromium
- Downloads `appimagetool` if not present
- Packages everything into a portable AppImage

### Python Dependencies

These are installed automatically by pip or the build process:

```
PyQt6>=6.5.0
keyring>=24.0.0
pyotp>=2.8.0
playwright>=1.40.0
secretstorage>=3.3.0
```

## Installation

### From AppImage (Recommended)

Download the latest AppImage from releases and run:

```bash
chmod +x MS_SSO_OpenConnect-*.AppImage
./MS_SSO_OpenConnect-*.AppImage
```

### From Debian Package

```bash
sudo dpkg -i ms-sso-openconnect-ui_*.deb
sudo apt install -f  # Install dependencies
```

### From Source (Development)

```bash
cd linux-ui
./scripts/install-dev.sh
source .venv/bin/activate
python -m vpn_ui
```

## Building

### Build AppImage

```bash
./scripts/build-appimage.sh
```

The AppImage will be created in `dist/`.

### Build Debian Package

```bash
./scripts/build-deb.sh
```

The `.deb` file will be created in `dist/`.

## Usage

1. **First Run**: The settings dialog opens automatically if no connections exist
2. **Add Connection**: Click "Add" and fill in:
   - Connection Name (identifier)
   - Server Address (VPN server hostname)
   - Protocol (AnyConnect or GlobalProtect)
   - Username (email)
   - Password
   - TOTP Secret (for 2FA)
3. **Connect**: Right-click tray icon → Connect → Select connection
4. **Disconnect**: Right-click tray icon → Disconnect

## GNOME Shell Users

GNOME Shell hides the system tray by default. Install the AppIndicator extension:

```bash
# Ubuntu/Debian
sudo apt install gnome-shell-extension-appindicator

# Enable it
gnome-extensions enable appindicatorsupport@rgcjonas.gmail.com
```

Then log out and back in.

## Project Structure

```
linux-ui/
├── src/vpn_ui/
│   ├── main.py              # Application controller
│   ├── tray.py              # System tray icon
│   ├── settings_dialog.py   # Settings window
│   ├── connection_form.py   # Connection edit form
│   ├── worker.py            # Async VPN operations
│   ├── vpn_backend.py       # Backend interface
│   └── notifications.py     # Desktop notifications
├── packaging/
│   └── debian/              # Debian packaging
├── desktop/                 # Desktop integration files
└── scripts/                 # Build scripts
```

## License

MIT License - See LICENSE file for details.
