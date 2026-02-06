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

## Cache Controls

The GNOME plugin has two independent caches:

1. **VPN session cookie cache** (fast reconnect using VPN cookies)
2. **Browser session cache** (Playwright profile to reuse Microsoft login state)

Default: both caches are enabled (AnyConnect and GlobalProtect).

### Per-connection toggles (`nmcli`)

```bash
# Disable VPN cookie cache for one connection
nmcli connection modify FHNW +vpn.data disable-cookie-cache=yes

# Disable GlobalProtect cookie cache only (default is enabled)
nmcli connection modify Unibas +vpn.data skip-gp-cookie-cache=yes

# Disable browser session reuse for one connection
nmcli connection modify FHNW +vpn.data disable-browser-session-cache=yes

# Force-enable browser session reuse for one connection
nmcli connection modify Unibas +vpn.data enable-browser-session-cache=yes
```

To revert to default behavior, remove the keys:

```bash
nmcli connection modify FHNW -vpn.data disable-cookie-cache
nmcli connection modify Unibas -vpn.data skip-gp-cookie-cache
nmcli connection modify FHNW -vpn.data disable-browser-session-cache
nmcli connection modify Unibas -vpn.data enable-browser-session-cache
```

### Environment toggles (system-wide plugin process)

```bash
# Disable VPN cookie cache globally
MS_SSO_NM_DISABLE_COOKIE_CACHE=1

# Disable GlobalProtect cookie cache globally (default is enabled)
MS_SSO_NM_GP_SKIP_COOKIE_CACHE=1

# Disable browser session cache globally
MS_SSO_NM_DISABLE_BROWSER_SESSION_CACHE=1

# Force-enable browser session cache globally
MS_SSO_NM_ENABLE_BROWSER_SESSION_CACHE=1

# Force-enable browser session cache only for GlobalProtect
MS_SSO_NM_GP_ENABLE_BROWSER_SESSION_CACHE=1
```

## GlobalProtect Timeout Handling

NetworkManager can cancel slow VPN setups after about 60 seconds.  
GlobalProtect SAML/MFA often exceeds that, so the plugin now defaults to
optimistic `STARTED` state during GP authentication to avoid timeout.

Controls:

```bash
# Default behavior (if unset): enabled for GP
MS_SSO_NM_GP_EARLY_STARTED=1

# Keep GNOME UI in "Connecting" until tunnel is really up
MS_SSO_NM_GP_EARLY_STARTED=0

# Optional guard thresholds for keepalive behavior
MS_SSO_NM_AUTH_TIMEOUT_GUARD_SEC=45
MS_SSO_NM_GP_AUTH_TIMEOUT_GUARD_SEC=45
```

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
