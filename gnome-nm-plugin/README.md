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
    pkg-config \
    libnm-dev \
    libgtk-4-dev \
    libglib2.0-dev
```

### Runtime Dependencies

```bash
sudo apt install \
    network-manager \
    openconnect \
    python3 \
    python3-gi \
    python3-keyring \
    python3-dbus \
    gir1.2-nm-1.0 \
    gir1.2-gtk-4.0 \
    gir1.2-adw-1
```

Also install the main ms-sso-openconnect package (parent project).

## Building

```bash
cd nm-plugin
meson setup build
meson compile -C build
```

## Installing

```bash
sudo meson install -C build
sudo systemctl restart NetworkManager
```

## Development Installation

For development/testing without full installation:

```bash
# Link files to system locations
sudo ln -sf $(pwd)/src/nm-ms-sso-service.py /usr/libexec/nm-ms-sso-service
sudo ln -sf $(pwd)/src/nm-ms-sso-auth-dialog.py /usr/libexec/nm-ms-sso-auth-dialog
sudo ln -sf $(pwd)/data/nm-ms-sso-service.name /usr/lib/NetworkManager/VPN/
sudo cp data/nm-ms-sso-service.conf /usr/share/dbus-1/system.d/

# Build and install editor library
meson setup build
meson compile -C build
sudo cp build/src/editor/libnm-vpn-plugin-ms-sso-editor.so /usr/lib/x86_64-linux-gnu/NetworkManager/

# Restart NetworkManager
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
nm-plugin/
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
   - Reuses `ms-sso-openconnect.py` for SAML auth

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

# Test SAML auth manually
../ms-sso-openconnect.py --visible <connection-name>
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
