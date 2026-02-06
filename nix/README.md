# Nix Packaging

Nix packages are defined in this directory and remain fully supported.

## Build

Use the unified build entrypoint:

```bash
./build/build.sh nix all
```

Or per package:

```bash
./build/build.sh nix core
./build/build.sh nix ui
./build/build.sh nix plugin
```

## NixOS Module

Use `nix/nixos-module.nix` as before. No compatibility was removed.
