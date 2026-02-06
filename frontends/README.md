# Frontends

This directory provides platform-specific frontend entrypoints.

- `frontends/linux/` - Qt desktop app packaging for Linux (`AppImage`, `deb`)
- `frontends/osx/` - Qt desktop app packaging for macOS (`pkg`)
- `frontends/gnome-plugin/` - NetworkManager GNOME plugin packaging (`deb`)

Shared implementation is centralized under `codebase/` and consumed by these frontends. Artifacts are collected under top-level `dist/`.
