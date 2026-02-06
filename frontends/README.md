# Frontends

This directory provides platform-specific frontend entrypoints.

- `frontends/linux/` - Qt desktop app packaging for Linux (`AppImage`, `deb`)
- `frontends/osx/` - Qt desktop app packaging for macOS (`pkg`)
- `frontends/gnome-plugin/` - NetworkManager GNOME plugin packaging (`deb`)

Each frontend wrapper delegates to the implementation code currently located in `ui/` and `gnome-nm-plugin/` and collects artifacts under top-level `dist/`.
