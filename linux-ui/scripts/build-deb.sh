#!/bin/bash
#
# Build Debian package for MS SSO OpenConnect UI
#
# This script creates a .deb package that can be installed on
# Debian, Ubuntu, and derivative distributions.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR/.."
BUILD_DIR="$PROJECT_DIR/build/deb"

echo "=== MS SSO OpenConnect UI - Debian Package Builder ==="
echo ""

# Check for required tools
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo "Error: $1 is not installed"
        echo "Install with: sudo apt install $2"
        exit 1
    fi
}

check_tool dpkg-buildpackage "devscripts"
check_tool dh "debhelper"
check_tool dh_python3 "dh-python"

# Create build directory
echo "Creating build directory..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Copy source files
echo "Copying source files..."
cp -r "$PROJECT_DIR"/* "$BUILD_DIR/" 2>/dev/null || true
cp -r "$PROJECT_DIR/../ms-sso-openconnect.py" "$BUILD_DIR/../" 2>/dev/null || true

# Copy debian directory
echo "Setting up debian directory..."
cp -r "$PROJECT_DIR/packaging/debian" "$BUILD_DIR/"

# Make rules executable
chmod +x "$BUILD_DIR/debian/rules"
chmod +x "$BUILD_DIR/debian/postinst" 2>/dev/null || true
chmod +x "$BUILD_DIR/debian/prerm" 2>/dev/null || true

# Build the package
echo ""
echo "Building Debian package..."
cd "$BUILD_DIR"
dpkg-buildpackage -us -uc -b

# Move output to dist directory
mkdir -p "$PROJECT_DIR/dist"
mv "$BUILD_DIR"/../*.deb "$PROJECT_DIR/dist/" 2>/dev/null || true
mv "$BUILD_DIR"/../*.changes "$PROJECT_DIR/dist/" 2>/dev/null || true

echo ""
echo "=== Build Complete ==="
echo ""
echo "Debian package created in: $PROJECT_DIR/dist/"
ls -la "$PROJECT_DIR/dist/"*.deb 2>/dev/null || echo "No .deb found in dist/"

echo ""
echo "Install with: sudo dpkg -i $PROJECT_DIR/dist/*.deb"
echo "Then fix dependencies: sudo apt install -f"
