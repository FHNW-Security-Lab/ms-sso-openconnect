# GNOME Plugin Frontend

This frontend is the NetworkManager VPN plugin integration for GNOME.

## Build

Use the canonical build wrapper:

```bash
./frontends/gnome-plugin/build.sh
```

Artifacts are collected in `dist/gnome-plugin/deb/`.

## Implementation Source

- Plugin service/editor source: `gnome-nm-plugin/src/`
- Debian packaging assets: `gnome-nm-plugin/packaging/debian/`
- Legacy build script (still supported): `gnome-nm-plugin/build-deb.sh`
