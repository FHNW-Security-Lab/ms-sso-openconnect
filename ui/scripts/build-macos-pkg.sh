#!/bin/bash
#
# Build macOS .pkg installer for MS SSO OpenConnect UI
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR/.."
APP_NAME="MS SSO OpenConnect"
VERSION="${1:-1.0.1}"
DIST_DIR="$PROJECT_DIR/dist"
APP_DIR="$DIST_DIR/${APP_NAME}.app"
PKG_ROOT="$PROJECT_DIR/build/pkg-root"
PKG_SCRIPTS="$PROJECT_DIR/build/pkg-scripts"
PKG_ID="com.github.ms-sso-openconnect-ui"
PKG_FILE="$DIST_DIR/MS-SSO-OpenConnect-UI-${VERSION}.pkg"

echo "=== Building ${APP_NAME} v${VERSION} .pkg ==="
echo ""

check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo "Error: $1 is not installed"
        echo "Install Xcode Command Line Tools: xcode-select --install"
        exit 1
    fi
}

check_tool pkgbuild

# Build the .app bundle first
"$SCRIPT_DIR/build-macos-app.sh" "$VERSION"

if [ ! -d "$APP_DIR" ]; then
    echo "Error: App bundle not found at $APP_DIR"
    exit 1
fi

# Prepare staging root
rm -rf "$PKG_ROOT" "$PKG_SCRIPTS"
mkdir -p "$PKG_ROOT/Applications"
mkdir -p "$PKG_ROOT/Library/LaunchDaemons"
mkdir -p "$PKG_SCRIPTS"

echo "Staging app bundle..."
cp -R "$APP_DIR" "$PKG_ROOT/Applications/"

echo "Staging launchd helper..."
cp "$PROJECT_DIR/packaging/launchd/com.github.ms-sso-openconnect-ui.helper.plist" \
    "$PKG_ROOT/Library/LaunchDaemons/"

cp "$PROJECT_DIR/packaging/pkg/postinstall" "$PKG_SCRIPTS/postinstall"
chmod +x "$PKG_SCRIPTS/postinstall"

mkdir -p "$DIST_DIR"

echo "Building pkg..."
pkgbuild \
    --root "$PKG_ROOT" \
    --identifier "$PKG_ID" \
    --version "$VERSION" \
    --install-location "/" \
    --scripts "$PKG_SCRIPTS" \
    "$PKG_FILE"

echo ""
echo "=== Build complete ==="
echo "Package created: $PKG_FILE"
