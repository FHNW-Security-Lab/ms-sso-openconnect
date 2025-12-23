#!/bin/bash
#
# Build Debian package for NetworkManager MS SSO OpenConnect plugin
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR/.."
BUILD_DIR="$PROJECT_DIR/build/deb"

echo "=== NetworkManager MS SSO OpenConnect - Debian Package Builder ==="
echo ""

check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo "Error: $1 is not installed"
        echo "Install with: sudo apt install $2"
        exit 1
    fi
}

check_tool dpkg-buildpackage "devscripts"
check_tool dh "debhelper"

echo "Creating build directory..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

echo "Copying source files..."
cp -r "$PROJECT_DIR"/* "$BUILD_DIR/" 2>/dev/null || true
cp -r "$PROJECT_DIR/../ms-sso-openconnect.py" "$BUILD_DIR/../" 2>/dev/null || true

echo "Setting up debian directory..."
cp -r "$PROJECT_DIR/packaging/debian" "$BUILD_DIR/debian"

chmod +x "$BUILD_DIR/debian/rules"
chmod +x "$BUILD_DIR/debian/postinst" 2>/dev/null || true
chmod +x "$BUILD_DIR/debian/postrm" 2>/dev/null || true
chmod +x "$BUILD_DIR/debian/prerm" 2>/dev/null || true

echo ""
echo "Building Debian package..."
cd "$BUILD_DIR"
dpkg-buildpackage -us -uc -b

mkdir -p "$PROJECT_DIR/dist"

echo "Cleaning old build artifacts in dist/..."
shopt -s nullglob
rm -f "$PROJECT_DIR/dist/"*.deb "$PROJECT_DIR/dist/"*.changes
shopt -u nullglob

mv "$BUILD_DIR"/../*.deb "$PROJECT_DIR/dist/" 2>/dev/null || true
mv "$BUILD_DIR"/../*.changes "$PROJECT_DIR/dist/" 2>/dev/null || true

echo ""
echo "=== Build Complete ==="
echo ""
echo "Debian package created in: $PROJECT_DIR/dist/"
ls -la "$PROJECT_DIR/dist/"*.deb 2>/dev/null || echo "No .deb found in dist/"
echo ""
LATEST_DEB="$(ls -1t "$PROJECT_DIR/dist/"*.deb 2>/dev/null | head -n 1 || true)"
if [ -n "$LATEST_DEB" ]; then
    echo "Install with: sudo dpkg -i $LATEST_DEB"
else
    echo "Install with: sudo dpkg -i $PROJECT_DIR/dist/<package>.deb"
fi
echo "Then fix dependencies: sudo apt install -f"
