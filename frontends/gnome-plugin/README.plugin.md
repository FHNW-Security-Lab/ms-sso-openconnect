# NetworkManager VPN Plugin for MS SSO OpenConnect

This is a GNOME NetworkManager VPN plugin that integrates MS SSO OpenConnect with native VPN settings in GNOME Shell.

## Features

- Configure VPN connections directly in GNOME Settings
- Support for Cisco AnyConnect and GlobalProtect protocols
- SAML authentication with automatic TOTP
- Credentials stored securely in system keyring
- Session cookie caching for fast reconnection

## Prerequisites

### Build Dependencies

```bash
sudo apt install \
    meson \
    ninja-build \
    pkg-config \
    libnm-dev \
    libgtk-4-dev \
    libglib2.0-dev \
    libsecret-1-dev
```

### Runtime Dependencies

```bash
sudo apt install \
    network-manager \
    openconnect \
    python3 \
    python3-pip \
    python3-gi \
    python3-keyring \
    python3-secretstorage \
    python3-dbus \
    python3-pyotp \
    gir1.2-nm-1.0 \
    gir1.2-gtk-4.0 \
    gir1.2-adw-1 \
    gir1.2-secret-1
```

### Playwright (for SAML authentication)

The plugin uses Playwright for browser-based Microsoft SSO authentication. Install it for the root user (since NetworkManager runs as root):

```bash
sudo pip3 install playwright
sudo playwright install chromium
```

This installs Chromium to `/root/.cache/ms-playwright/`.

## Building

```bash
./frontends/gnome-plugin/build.sh
```

Legacy script is still available:

```bash
cd frontends/gnome-plugin
./build-deb.sh
```

Or manually:

```bash
cd frontends/gnome-plugin
meson setup build
meson compile -C build
```

## Installing

### From .deb package (recommended)

```bash
sudo dpkg -i dist/network-manager-ms-sso_*.deb
sudo apt-get install -f  # Install any missing dependencies
sudo systemctl restart NetworkManager
```

### Manual installation

```bash
sudo meson install -C build
sudo systemctl restart NetworkManager
```

## Usage

After installation:

1. Open **GNOME Settings** → **Network** → **VPN**
2. Click **+** to add a new VPN
3. Select **MS SSO OpenConnect** from the list
4. Configure:
   - **Gateway**: Your VPN server address (e.g., `vpn.company.com`)
   - **Protocol**: Cisco AnyConnect or GlobalProtect
   - **Username**: Your email/username
   - **Password**: Your password
   - **TOTP Secret**: Base32 secret from your authenticator app (optional)
5. Click **Add**
6. Toggle the VPN switch to connect

## Architecture

```
frontends/gnome-plugin/
├── src/
│   ├── nm-ms-sso-service.py      # D-Bus VPN service
│   ├── nm-ms-sso-auth-dialog.py  # GTK4 auth dialog
│   └── editor/
│       ├── nm-ms-sso-editor.c    # GTK4 settings editor
│       └── nm-ms-sso-editor.h
├── data/
│   ├── nm-ms-sso-service.name    # NM plugin registration
│   └── nm-ms-sso-service.conf    # D-Bus policy
└── meson.build                    # Build system
```

### Components

1. **Plugin Registration** (`nm-ms-sso-service.name`)
   - Registers the plugin with NetworkManager
   - Specifies paths to service, editor, and auth dialog

2. **VPN Service** (`nm-ms-sso-service.py`)
   - D-Bus service implementing `org.freedesktop.NetworkManager.VPN.Plugin`
   - Handles Connect/Disconnect operations
   - Uses Playwright for SAML authentication

3. **Editor Plugin** (`nm-ms-sso-editor.c`)
   - GTK4 widget for GNOME Settings
   - Provides form for connection configuration
   - Implements `NMVpnEditor` interface

4. **Auth Dialog** (`nm-ms-sso-auth-dialog.py`)
   - Prompts for credentials when needed
   - Integrates with keyring for saved credentials

## Troubleshooting

### Plugin not appearing in GNOME Settings

```bash
# Check if plugin is registered
cat /usr/lib/NetworkManager/VPN/nm-ms-sso-service.name

# Check NetworkManager logs
journalctl -u NetworkManager -f

# Restart NetworkManager
sudo systemctl restart NetworkManager
```

### Connection fails

```bash
# Check service logs
journalctl -u NetworkManager -f | grep ms-sso

# Check if Playwright is installed for root
sudo ls /root/.cache/ms-playwright/

# If not, install it:
sudo pip3 install playwright
sudo playwright install chromium
```

### Editor library not loading

```bash
# Check library is in correct location
ls -la /usr/lib/*/NetworkManager/libnm-vpn-plugin-ms-sso-editor.so

# Check for missing dependencies
ldd /usr/lib/x86_64-linux-gnu/NetworkManager/libnm-vpn-plugin-ms-sso-editor.so
```

## License

GPL-2.0-or-later
