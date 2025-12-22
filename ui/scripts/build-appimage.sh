#!/bin/bash
#
# Build AppImage for MS SSO OpenConnect UI
#
# This script creates a self-contained AppImage that includes:
# - Python and all dependencies
# - Playwright with Chromium browser
# - The VPN UI application
#
# Note: Uses appimagetool directly to bypass apt-key issues with appimage-builder

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR/.."
BUILD_DIR="$PROJECT_DIR/build/appimage"
APPDIR="$BUILD_DIR/AppDir"
VERSION="${1:-1.0.1}"

echo "=== Building MS-SSO-OpenConnect-UI AppImage v${VERSION} ==="

# Check for required tools
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo "Error: $1 is not installed"
        echo "Install with: $2"
        exit 1
    fi
}

check_tool python3 "apt install python3"
check_tool curl "apt install curl"

# Clean previous build
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin"
mkdir -p "$APPDIR/usr/lib/ms-sso-openconnect"
mkdir -p "$APPDIR/usr/lib/playwright"
mkdir -p "$APPDIR/usr/share/applications"
mkdir -p "$APPDIR/usr/share/icons/hicolor/scalable/apps"

# Create Python venv with dependencies
echo "Creating Python virtual environment..."
python3 -m venv "$APPDIR/usr/lib/python-venv"
"$APPDIR/usr/lib/python-venv/bin/pip" install -q --upgrade pip
"$APPDIR/usr/lib/python-venv/bin/pip" install -q playwright keyring pyotp PyQt6

# Install vpn_ui package
echo "Installing vpn_ui..."
"$APPDIR/usr/lib/python-venv/bin/pip" install -q -e "$PROJECT_DIR"

# Install Playwright browsers
echo "Installing Playwright Chromium..."
PLAYWRIGHT_PATH="$(cd "$APPDIR/usr/lib/playwright" && pwd)"
PLAYWRIGHT_BROWSERS_PATH="$PLAYWRIGHT_PATH" "$APPDIR/usr/lib/python-venv/bin/playwright" install chromium

# Copy core module
cp -r "$PROJECT_DIR/../core" "$APPDIR/usr/lib/ms-sso-openconnect/"

# Copy desktop file and icon
cp "$PROJECT_DIR/desktop/ms-sso-openconnect-ui.desktop" "$APPDIR/usr/share/applications/"
cp "$PROJECT_DIR/src/vpn_ui/resources/icons/app-icon.svg" "$APPDIR/usr/share/icons/hicolor/scalable/apps/ms-sso-openconnect-ui.svg"

# Detect Python version for paths
PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")

# Create launcher script
cat > "$APPDIR/usr/bin/ms-sso-openconnect-ui" << LAUNCHER
#!/bin/bash
HERE="\$(dirname "\$(readlink -f "\${0}")")"
export PLAYWRIGHT_BROWSERS_PATH="\${HERE}/../lib/playwright"
export QT_PLUGIN_PATH="\${HERE}/../lib/python-venv/lib/python${PYTHON_VERSION}/site-packages/PyQt6/Qt6/plugins"
export PATH="\${HERE}:\${PATH}"
exec "\${HERE}/../lib/python-venv/bin/python" -m vpn_ui "\$@"
LAUNCHER
chmod +x "$APPDIR/usr/bin/ms-sso-openconnect-ui"

# Create AppRun
cat > "$APPDIR/AppRun" << APPRUN
#!/bin/bash
HERE="\$(dirname "\$(readlink -f "\${0}")")"
export PLAYWRIGHT_BROWSERS_PATH="\${HERE}/usr/lib/playwright"
export QT_PLUGIN_PATH="\${HERE}/usr/lib/python-venv/lib/python${PYTHON_VERSION}/site-packages/PyQt6/Qt6/plugins"
export LD_LIBRARY_PATH="\${HERE}/usr/lib:\${LD_LIBRARY_PATH}"
export PATH="\${HERE}/usr/bin:\${PATH}"
exec "\${HERE}/usr/lib/python-venv/bin/python" -m vpn_ui "\$@"
APPRUN
chmod +x "$APPDIR/AppRun"

# Copy desktop and icon to root
cp "$APPDIR/usr/share/applications/ms-sso-openconnect-ui.desktop" "$APPDIR/"
cp "$APPDIR/usr/share/icons/hicolor/scalable/apps/ms-sso-openconnect-ui.svg" "$APPDIR/"
ln -sf ms-sso-openconnect-ui.svg "$APPDIR/ms-sso-openconnect-ui.png"

# Download appimagetool if not present
if [ ! -f "$BUILD_DIR/appimagetool-x86_64.AppImage" ]; then
    echo "Downloading appimagetool..."
    curl -L -o "$BUILD_DIR/appimagetool-x86_64.AppImage" \
        "https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage"
    chmod +x "$BUILD_DIR/appimagetool-x86_64.AppImage"
fi

# Build AppImage
echo "Building AppImage..."
cd "$BUILD_DIR"
./appimagetool-x86_64.AppImage AppDir "MS-SSO-OpenConnect-UI-${VERSION}-x86_64.AppImage"

# Move to dist
mkdir -p "$PROJECT_DIR/dist"
mv "MS-SSO-OpenConnect-UI-${VERSION}-x86_64.AppImage" "$PROJECT_DIR/dist/"

echo ""
echo "=== Build complete ==="
ls -lh "$PROJECT_DIR/dist/MS-SSO-OpenConnect-UI-${VERSION}-x86_64.AppImage"
