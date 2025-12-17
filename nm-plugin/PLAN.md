# GNOME NetworkManager VPN Plugin for ms-sso-openconnect

## Overview

This plugin integrates ms-sso-openconnect with GNOME's native VPN settings, allowing users to configure and connect to Microsoft SSO-protected VPNs directly from GNOME Settings.

## Architecture

A NetworkManager VPN plugin consists of four main components:

1. **Service Definition (.name file)** - Registers the plugin with NetworkManager
2. **VPN Service (D-Bus daemon)** - Handles connect/disconnect operations
3. **Editor Plugin (GTK4 shared library)** - Provides UI for GNOME Settings
4. **Auth Dialog** - Handles authentication prompts

## Directory Structure

```
nm-plugin/
├── src/
│   ├── nm-ms-sso-service.py           # D-Bus VPN service (Python)
│   ├── nm-ms-sso-auth-dialog.py       # Auth dialog (Python/GTK4)
│   └── editor/                         # Editor plugin
│       ├── nm-ms-sso-editor.c         # GTK4 editor (C)
│       ├── nm-ms-sso-editor.h
│       └── meson.build
├── data/
│   ├── nm-ms-sso-service.name          # Plugin registration
│   └── nm-ms-sso-service.conf          # D-Bus policy
├── packaging/
│   └── debian/
│       ├── control
│       ├── rules
│       └── ...
├── meson.build                         # Build system
└── README.md
```

## Configuration Fields

The plugin supports these connection settings:

| Field | Type | Description |
|-------|------|-------------|
| `gateway` | data | VPN server address |
| `protocol` | data | `anyconnect` or `gp` (GlobalProtect) |
| `username` | data | User email/username |
| `password` | secret | User password (stored in keyring) |
| `totp-secret` | secret | Base32 TOTP secret (stored in keyring) |

## Code Reuse

The plugin reuses the existing ms-sso-openconnect.py module:

- `do_saml_auth()` - SAML authentication via headless browser
- `connect_vpn()` - OpenConnect VPN connection
- `get_all_connections()` - Keyring credential storage
- `generate_totp()` - TOTP code generation

## Installation Locations

- `/usr/lib/NetworkManager/VPN/nm-ms-sso-service.name`
- `/usr/libexec/nm-ms-sso-service`
- `/usr/libexec/nm-ms-sso-auth-dialog`
- `/usr/lib/x86_64-linux-gnu/NetworkManager/libnm-vpn-plugin-ms-sso-editor.so`
- `/usr/share/dbus-1/system.d/nm-ms-sso-service.conf`
- `/usr/share/ms-sso-openconnect/ms-sso-openconnect.py`

## Build & Install

```bash
cd nm-plugin
meson setup build
meson compile -C build
sudo meson install -C build
sudo systemctl restart NetworkManager
```

## Testing

After installation:
1. Open GNOME Settings → Network → VPN
2. Click "+" to add a new VPN
3. Select "MS SSO OpenConnect" from the list
4. Configure gateway, protocol, username, password, and TOTP secret
5. Click "Add" to save
6. Toggle the VPN switch to connect
