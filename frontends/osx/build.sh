#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VERSION="${1:-2.0.0}"

"$REPO_ROOT/frontends/osx/scripts/build-macos.sh" "$VERSION"

mkdir -p "$REPO_ROOT/dist/osx/pkg"
find "$REPO_ROOT/frontends/osx/dist" -maxdepth 1 -type f -name '*.pkg' -exec cp -f {} "$REPO_ROOT/dist/osx/pkg/" \;

echo "macOS artifacts collected under: $REPO_ROOT/dist/osx/pkg/"
