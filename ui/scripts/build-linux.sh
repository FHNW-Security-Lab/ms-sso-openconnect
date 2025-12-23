#!/bin/bash
# Build script for Linux (Debian package and AppImage)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UI_DIR="$SCRIPT_DIR/.."
REPO_ROOT="$UI_DIR/.."
VERSION="${1:-2.0.0}"

echo "=== Building Linux Package v${VERSION} ==="

# Ensure we're on Linux
if [[ "$(uname)" != "Linux" ]]; then
    echo "Error: This script must be run on Linux"
    exit 1
fi

# Create dist directory
mkdir -p "$UI_DIR/dist"

# ===========================================================================
# Build AppImage
# ===========================================================================
build_appimage() {
    echo ""
    echo "=== Building AppImage ==="

    APPDIR="$UI_DIR/build/AppDir"
    rm -rf "$APPDIR"
    mkdir -p "$APPDIR/usr/bin"
    mkdir -p "$APPDIR/usr/share/applications"
    mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"

    # Create virtual environment
    echo "Creating virtual environment..."
    python3 -m venv "$APPDIR/usr/venv"
    source "$APPDIR/usr/venv/bin/activate"

    # Install dependencies
    echo "Installing dependencies..."
    pip install -q --upgrade pip wheel
    pip install -q PyQt6 keyring pyotp playwright secretstorage

    # Install the UI package
    pip install -q "$UI_DIR"

    # Install Playwright browsers
    echo "Installing Playwright Chromium..."
    PLAYWRIGHT_BROWSERS_PATH="$APPDIR/usr/browsers" playwright install chromium

    # Copy core module
    echo "Copying core module..."
    cp -r "$REPO_ROOT/core" "$APPDIR/usr/share/ms-sso-openconnect/"
    mkdir -p "$APPDIR/usr/share/ms-sso-openconnect"
    cp -r "$REPO_ROOT/core" "$APPDIR/usr/share/ms-sso-openconnect/"

    deactivate

    # Create launcher script
    cat > "$APPDIR/usr/bin/ms-sso-openconnect-ui" << 'LAUNCHER'
#!/bin/bash
APPDIR="$(dirname "$(dirname "$(readlink -f "$0")")")"

export PLAYWRIGHT_BROWSERS_PATH="$APPDIR/browsers"
export PYTHONPATH="$APPDIR/share/ms-sso-openconnect:$PYTHONPATH"
export PATH="$APPDIR/venv/bin:$PATH"

# Qt plugin path
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
export QT_PLUGIN_PATH="$APPDIR/venv/lib/python${PYTHON_VERSION}/site-packages/PyQt6/Qt6/plugins"

exec "$APPDIR/venv/bin/python" -m vpn_ui "$@"
LAUNCHER
    chmod +x "$APPDIR/usr/bin/ms-sso-openconnect-ui"

    # Create AppRun
    cat > "$APPDIR/AppRun" << 'APPRUN'
#!/bin/bash
APPDIR="$(dirname "$(readlink -f "$0")")"
exec "$APPDIR/usr/bin/ms-sso-openconnect-ui" "$@"
APPRUN
    chmod +x "$APPDIR/AppRun"

    # Copy desktop file and icon
    cp "$UI_DIR/packaging/linux/desktop/ms-sso-openconnect-ui.desktop" "$APPDIR/usr/share/applications/"
    cp "$UI_DIR/packaging/linux/desktop/ms-sso-openconnect-ui.desktop" "$APPDIR/"
    cp "$UI_DIR/src/vpn_ui/resources/icons/app-icon.svg" "$APPDIR/usr/share/icons/hicolor/256x256/apps/ms-sso-openconnect-ui.svg"
    cp "$UI_DIR/src/vpn_ui/resources/icons/app-icon.svg" "$APPDIR/ms-sso-openconnect-ui.svg"

    # Download appimagetool if needed
    APPIMAGETOOL="$UI_DIR/build/appimagetool"
    if [[ ! -f "$APPIMAGETOOL" ]]; then
        echo "Downloading appimagetool..."
        curl -Lo "$APPIMAGETOOL" "https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage"
        chmod +x "$APPIMAGETOOL"
    fi

    # Build AppImage
    echo "Building AppImage..."
    ARCH=x86_64 "$APPIMAGETOOL" "$APPDIR" "$UI_DIR/dist/MS-SSO-OpenConnect-UI-${VERSION}-x86_64.AppImage"

    echo "AppImage created: $UI_DIR/dist/MS-SSO-OpenConnect-UI-${VERSION}-x86_64.AppImage"
}

# ===========================================================================
# Build Debian Package
# ===========================================================================
build_deb() {
    echo ""
    echo "=== Building Debian Package ==="

    # Check for required tools
    if ! command -v dpkg-buildpackage &> /dev/null; then
        echo "Error: dpkg-buildpackage not found. Install with: sudo apt install devscripts debhelper"
        return 1
    fi

    BUILD_DIR="$UI_DIR/build/deb"
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"

    # Copy source
    cp -r "$UI_DIR/src" "$BUILD_DIR/"
    cp -r "$UI_DIR/packaging/linux/debian" "$BUILD_DIR/"
    cp -r "$UI_DIR/packaging" "$BUILD_DIR/"
    cp "$UI_DIR/pyproject.toml" "$BUILD_DIR/"

    # Copy core module
    mkdir -p "$BUILD_DIR/core"
    cp -r "$REPO_ROOT/core/"*.py "$BUILD_DIR/core/"

    # Build
    cd "$BUILD_DIR"
    dpkg-buildpackage -us -uc -b

    # Move result
    mv "$UI_DIR/build/"*.deb "$UI_DIR/dist/"

    echo "Debian package created in $UI_DIR/dist/"
}

# ===========================================================================
# Main
# ===========================================================================
case "${2:-all}" in
    appimage)
        build_appimage
        ;;
    deb)
        build_deb
        ;;
    all)
        build_appimage
        build_deb
        ;;
    *)
        echo "Usage: $0 [version] [appimage|deb|all]"
        exit 1
        ;;
esac

echo ""
echo "=== Build Complete ==="
ls -la "$UI_DIR/dist/"
