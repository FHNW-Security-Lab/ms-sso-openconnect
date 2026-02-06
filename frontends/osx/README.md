# macOS Frontend

This frontend is the Qt menu bar app with macOS daemon packaging (`.pkg`).

## Build

Use the canonical build wrapper:

```bash
./frontends/osx/build.sh [version]
```

Artifacts are collected in `dist/osx/pkg/`.

## Implementation Source

- Qt app source: `ui/src/vpn_ui/`
- macOS daemon source: `ui/macos/daemon/`
- Legacy build script (still supported): `ui/scripts/build-macos.sh`
