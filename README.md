# MS SSO OpenConnect

VPN connection tool for Microsoft SSO-protected networks.

This repository now contains:

- command-line client
- Linux desktop UI (Qt)
- shared core runtime used by CLI/UI

The GNOME NetworkManager plugin has moved to a separate repository: `gnome-ms-sso-plugin`.

## Build and Packaging

Use the unified build entrypoint:

```bash
./build/build.sh <target> [version-or-component]
```

Supported targets:

- `appimage` (Linux UI)
- `deb` (Linux UI)
- `linux-all` (Linux UI AppImage + deb)
- `pkg` (macOS UI package)
- `nix` (`core`, `ui`, `all`)

Optional `make` shortcuts:

```bash
make appimage VERSION=2.0.0
make deb VERSION=2.0.0
make pkg VERSION=2.0.0
make nix
```

## Nix

Build with flakes:

```bash
nix build .#ms-sso-openconnect-core
nix build .#ms-sso-openconnect-ui
```

## Command-Line Tool

```bash
./ms-sso-openconnect --setup
./ms-sso-openconnect
./ms-sso-openconnect --list
```

## Linux UI

Linux packaging assets live in `frontends/linux/`.

## Layout

```text
codebase/                # Shared architecture docs and runtime contracts
codebase/core/           # Shared auth/connect logic used by CLI/UI
codebase/ui/             # Shared Qt codebase used by Linux/macOS frontends
ms-sso-openconnect.py    # CLI entry point
ms-sso-openconnect       # CLI bootstrap wrapper

frontends/
├── linux/               # Linux Qt frontend build wrapper
└── osx/                 # macOS Qt frontend build wrapper

build/                   # Unified build entrypoints
nix/                     # Nix packaging support
```
