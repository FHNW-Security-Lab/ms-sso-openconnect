# Linux Frontend

This frontend is the Qt desktop app for Linux.

## Build

Use the canonical build wrapper:

```bash
./frontends/linux/build.sh [version] [appimage|deb|all]
```

Artifacts are collected in `dist/linux/`.

## Implementation Source

- Qt app source: `ui/src/vpn_ui/`
- Linux packaging assets: `ui/packaging/linux/`
- Legacy build script (still supported): `ui/scripts/build-linux.sh`
