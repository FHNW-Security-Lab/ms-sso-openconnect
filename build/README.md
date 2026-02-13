# Build System

Canonical build entrypoint:

```bash
./build/build.sh <target> [version-or-component]
```

## Targets

- `appimage` - build Linux AppImage frontend artifact
- `deb` - build Linux Qt frontend Debian package
- `linux-all` - build both Linux Qt artifacts
- `pkg` - build macOS package (`.pkg`)
- `nix` - build Nix attributes (`core`, `ui`, `all`)

Equivalent `make` targets are available in the top-level `Makefile`.
