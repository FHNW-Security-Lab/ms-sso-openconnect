#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VERSION="${1:-2.1.3}"

"$REPO_ROOT/frontends/osx/scripts/build-macos.sh" "$VERSION"

mkdir -p "$REPO_ROOT/dist/osx/pkg"
cp "$REPO_ROOT/frontends/osx/dist/MS-SSO-OpenConnect-${VERSION}-macos-$(uname -m).pkg" \
    "$REPO_ROOT/dist/osx/pkg/"

echo "macOS artifacts collected under: $REPO_ROOT/dist/osx/pkg/"
