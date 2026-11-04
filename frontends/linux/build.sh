#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VERSION="${1:-2.1.5}"
TARGET="${2:-all}"

"$REPO_ROOT/frontends/linux/scripts/build-linux.sh" "$VERSION" "$TARGET"

mkdir -p "$REPO_ROOT/dist/linux/appimage" "$REPO_ROOT/dist/linux/deb"
if [[ "$TARGET" == appimage || "$TARGET" == all ]]; then
    cp "$REPO_ROOT/frontends/linux/dist/MS-SSO-OpenConnect-UI-${VERSION}-x86_64.AppImage" "$REPO_ROOT/dist/linux/appimage/"
fi
if [[ "$TARGET" == deb || "$TARGET" == all ]]; then
    cp "$REPO_ROOT/frontends/linux/dist/ms-sso-openconnect-ui_${VERSION}-1_all.deb" "$REPO_ROOT/dist/linux/deb/"
fi

echo "Linux artifacts collected under: $REPO_ROOT/dist/linux/"
