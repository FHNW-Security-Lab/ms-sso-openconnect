# Linux Frontend

This frontend is the Qt desktop app for Linux.

## Build

Use the canonical build wrapper:

```bash
./frontends/linux/build.sh [version] [appimage|deb|all]
```

Artifacts are collected in `dist/linux/`.

## Implementation Source

- Shared Qt app source: `codebase/ui/src/vpn_ui/`
- Shared runtime: `codebase/core/`
- Linux packaging assets: `frontends/linux/packaging/`
- Linux builder: `frontends/linux/scripts/build-linux.sh`
