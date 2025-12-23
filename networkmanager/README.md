# NetworkManager / GNOME VPN Plugin

This directory contains a NetworkManager VPN plugin that reuses the existing `ms-sso-openconnect.py`
Microsoft SSO (Playwright) authentication logic and then connects using `openconnect`.

It provides:
- A GNOME Settings VPN editor page (Server, Protocol, Username, Password, TOTP secret)
- A NetworkManager VPN service (`nm-ms-sso-openconnect-service`)
- An `openconnect` script helper that forwards tunnel config back to NetworkManager

## Build

```bash
cd networkmanager
meson setup build --prefix=/usr
ninja -C build
```

## Install (system)

```bash
sudo ninja -C networkmanager/build install
sudo systemctl restart NetworkManager
```

## Notes

- The VPN service dynamically imports `ms-sso-openconnect.py`. If it is not installed in a standard
  location, set `MS_SSO_OPENCONNECT_PY=/path/to/ms-sso-openconnect.py` in the service environment.
- Cookie cache defaults to `/var/cache/ms-sso-openconnect-nm/` and can be overridden via
  `MS_SSO_OPENCONNECT_NM_CACHE_DIR`.

