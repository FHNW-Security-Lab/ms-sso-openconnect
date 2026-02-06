#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

"$REPO_ROOT/gnome-nm-plugin/build-deb.sh"

mkdir -p "$REPO_ROOT/dist/gnome-plugin/deb"
find "$REPO_ROOT/gnome-nm-plugin/dist" -maxdepth 1 -type f -name '*.deb' -exec cp -f {} "$REPO_ROOT/dist/gnome-plugin/deb/" \;

echo "GNOME plugin artifacts collected under: $REPO_ROOT/dist/gnome-plugin/deb/"
