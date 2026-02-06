# macOS Frontend

This frontend is the Qt menu bar app with macOS daemon packaging (`.pkg`).

## Build

Use the canonical build wrapper:

```bash
./frontends/osx/build.sh [version]
```

Artifacts are collected in `dist/osx/pkg/`.

## Implementation Source

- Shared Qt app source: `codebase/ui/src/vpn_ui/`
- Shared runtime: `codebase/core/`
- macOS daemon source: `frontends/osx/daemon/`
- macOS builder: `frontends/osx/scripts/build-macos.sh`
