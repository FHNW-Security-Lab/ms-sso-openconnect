#!/bin/bash
#
# Build AppImage for MS SSO OpenConnect UI
#
# This script creates a self-contained AppImage that includes:
# - Python and all dependencies
# - Playwright with Chromium browser
# - The VPN UI application
# - The CLI backend tool
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR/.."
BUILD_DIR="$PROJECT_DIR/build/appimage"

echo "=== MS SSO OpenConnect UI - AppImage Builder ==="
echo ""

# Check for required tools
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo "Error: $1 is not installed"
        echo "Install with: $2"
        exit 1
    fi
}

check_tool python3 "apt install python3"
check_tool pip3 "apt install python3-pip"

# Install appimage-builder if not present
if ! command -v appimage-builder &> /dev/null; then
    echo "Installing appimage-builder..."
    pip3 install appimage-builder
fi

# Create build directory
echo "Creating build directory..."
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Copy AppImageBuilder.yml
cp "$PROJECT_DIR/packaging/appimage/AppImageBuilder.yml" .

# Download appimagetool if not present
if [ ! -f "./appimagetool-x86_64.AppImage" ]; then
    echo "Downloading appimagetool..."
    wget -q https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage
    chmod +x appimagetool-x86_64.AppImage
fi

# Build the AppImage
echo ""
echo "Building AppImage..."
echo "This may take several minutes as it downloads and packages all dependencies."
echo ""

appimage-builder --recipe AppImageBuilder.yml --skip-tests

# Move output to dist directory
mkdir -p "$PROJECT_DIR/dist"
mv *.AppImage "$PROJECT_DIR/dist/" 2>/dev/null || true

echo ""
echo "=== Build Complete ==="
echo ""
echo "AppImage created in: $PROJECT_DIR/dist/"
ls -la "$PROJECT_DIR/dist/"*.AppImage 2>/dev/null || echo "No AppImage found in dist/"
