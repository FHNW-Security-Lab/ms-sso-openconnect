#!/usr/bin/env bash
# Build script for Linux (Debian package and AppImage)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRONTEND_DIR="$SCRIPT_DIR/.."
REPO_ROOT="$FRONTEND_DIR/../.."
CODEBASE_UI_DIR="$REPO_ROOT/codebase/ui"
CORE_DIR="$REPO_ROOT/codebase/core"
PACKAGING_DIR="$FRONTEND_DIR/packaging"
VERSION="${1:-2.0.0}"

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    echo "Usage: $0 [version] [appimage|deb|all]"
    exit 0
fi

echo "=== Building Linux Package v${VERSION} ==="

# Ensure we're on Linux
if [[ "$(uname)" != "Linux" ]]; then
    echo "Error: This script must be run on Linux"
    exit 1
fi

# Create dist directory
mkdir -p "$FRONTEND_DIR/dist"

# ===========================================================================
# Build AppImage
# ===========================================================================
build_appimage() {
    echo ""
    echo "=== Building AppImage ==="

    APPDIR="$FRONTEND_DIR/build/AppDir"
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
    pip install -q "$CODEBASE_UI_DIR"

    # Install Playwright browsers
    echo "Installing Playwright Chromium..."
    PLAYWRIGHT_BROWSERS_PATH="$APPDIR/usr/browsers" playwright install chromium

    # Copy core module
    echo "Copying core module..."
    mkdir -p "$APPDIR/usr/share/ms-sso-openconnect"
    cp -r "$CORE_DIR" "$APPDIR/usr/share/ms-sso-openconnect/"

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
    cp "$PACKAGING_DIR/desktop/ms-sso-openconnect-ui.desktop" "$APPDIR/usr/share/applications/"
    cp "$PACKAGING_DIR/desktop/ms-sso-openconnect-ui.desktop" "$APPDIR/"
    cp "$CODEBASE_UI_DIR/src/vpn_ui/resources/icons/app-icon.svg" "$APPDIR/usr/share/icons/hicolor/256x256/apps/ms-sso-openconnect-ui.svg"
    cp "$CODEBASE_UI_DIR/src/vpn_ui/resources/icons/app-icon.svg" "$APPDIR/ms-sso-openconnect-ui.svg"

    # Download appimagetool if needed
    APPIMAGETOOL="$FRONTEND_DIR/build/appimagetool"
    if [[ ! -f "$APPIMAGETOOL" ]]; then
        echo "Downloading appimagetool..."
        curl -Lo "$APPIMAGETOOL" "https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage"
        chmod +x "$APPIMAGETOOL"
    fi

    # Build AppImage
    echo "Building AppImage..."
    ARCH=x86_64 "$APPIMAGETOOL" "$APPDIR" "$FRONTEND_DIR/dist/MS-SSO-OpenConnect-UI-${VERSION}-x86_64.AppImage"

    echo "AppImage created: $FRONTEND_DIR/dist/MS-SSO-OpenConnect-UI-${VERSION}-x86_64.AppImage"
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

    BUILD_DIR="$FRONTEND_DIR/build/deb"
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"

    # Copy source
    cp -r "$CODEBASE_UI_DIR/src" "$BUILD_DIR/"
    cp -r "$PACKAGING_DIR/debian" "$BUILD_DIR/"
    mkdir -p "$BUILD_DIR/packaging/linux"
    cp -r "$PACKAGING_DIR/desktop" "$BUILD_DIR/packaging/linux/"
    cp -r "$PACKAGING_DIR/polkit" "$BUILD_DIR/packaging/linux/"
    cp "$CODEBASE_UI_DIR/pyproject.toml" "$BUILD_DIR/"

    # Copy core module
    mkdir -p "$BUILD_DIR/core"
    cp -r "$CORE_DIR/"*.py "$BUILD_DIR/core/"

    # Build
    cd "$BUILD_DIR"
    dpkg-buildpackage -us -uc -b

    # Move result
    mv "$FRONTEND_DIR/build/"*.deb "$FRONTEND_DIR/dist/"

    echo "Debian package created in $FRONTEND_DIR/dist/"
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
ls -la "$FRONTEND_DIR/dist/"
