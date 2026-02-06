#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VERSION="${1:-2.0.0}"
TARGET="${2:-all}"

"$REPO_ROOT/frontends/linux/scripts/build-linux.sh" "$VERSION" "$TARGET"

mkdir -p "$REPO_ROOT/dist/linux/appimage" "$REPO_ROOT/dist/linux/deb"
find "$REPO_ROOT/frontends/linux/dist" -maxdepth 1 -type f -name '*.AppImage' -exec cp -f {} "$REPO_ROOT/dist/linux/appimage/" \;
find "$REPO_ROOT/frontends/linux/dist" -maxdepth 1 -type f -name '*.deb' -exec cp -f {} "$REPO_ROOT/dist/linux/deb/" \;

echo "Linux artifacts collected under: $REPO_ROOT/dist/linux/"
