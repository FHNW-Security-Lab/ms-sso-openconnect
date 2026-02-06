# GNOME Plugin Frontend

This frontend is the NetworkManager VPN plugin integration for GNOME.

## Build

Use the canonical build wrapper:

```bash
./frontends/gnome-plugin/build.sh
```

Artifacts are collected in `dist/gnome-plugin/deb/`.

## Implementation Source

- Plugin service/editor source: `frontends/gnome-plugin/src/`
- Debian packaging assets: `frontends/gnome-plugin/packaging/debian/`
- Shared runtime: `codebase/core/`
- Debian builder: `frontends/gnome-plugin/build-deb.sh`
