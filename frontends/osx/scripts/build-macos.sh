#!/usr/bin/env bash
# Build script for macOS (pkg with daemon) using PyInstaller
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRONTEND_DIR="$SCRIPT_DIR/.."
REPO_ROOT="$FRONTEND_DIR/../.."
CODEBASE_UI_DIR="$REPO_ROOT/codebase/ui"
CORE_DIR="$REPO_ROOT/codebase/core"
DAEMON_SRC_DIR="$REPO_ROOT/frontends/osx/daemon"
VERSION="${1:-2.0.0}"

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    echo "Usage: $0 [version]"
    exit 0
fi

echo "=== Building macOS Package v${VERSION} ==="

# Ensure we're on macOS
if [[ "$(uname)" != "Darwin" ]]; then
    echo "Error: This script must be run on macOS"
    exit 1
fi

# Create directories
BUILD_DIR="$FRONTEND_DIR/build/macos"
PKG_ROOT="$BUILD_DIR/pkg-root"
SCRIPTS_DIR="$BUILD_DIR/scripts"
DIST_DIR="$FRONTEND_DIR/dist"

rm -rf "$BUILD_DIR"
mkdir -p "$PKG_ROOT" "$SCRIPTS_DIR" "$DIST_DIR"

# ===========================================================================
# Build the .app bundle using PyInstaller
# ===========================================================================
echo ""
echo "=== Building .app Bundle with PyInstaller ==="

# Create/activate virtual environment for building
VENV_DIR="$BUILD_DIR/build-venv"
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

# Install build dependencies
echo "Installing build dependencies..."
pip install -q --upgrade pip wheel
pip install -q pyinstaller PyQt6 keyring pyotp playwright

# Install the UI package in development mode
pip install -q -e "$CODEBASE_UI_DIR"

# Create PyInstaller spec file
echo "Creating PyInstaller spec..."
cat > "$BUILD_DIR/ms-sso-openconnect.spec" << 'SPEC'
# -*- mode: python ; coding: utf-8 -*-
import sys
from pathlib import Path

# Paths
ui_dir = Path("UI_DIR_PLACEHOLDER")
core_dir = Path("CORE_DIR_PLACEHOLDER")
src_dir = ui_dir / "src"
resources_dir = src_dir / "vpn_ui" / "resources"

block_cipher = None

a = Analysis(
    [str(src_dir / "vpn_ui" / "__main__.py")],
    pathex=[str(src_dir), str(core_dir.parent)],
    binaries=[],
    datas=[
        # Include icons
        (str(resources_dir / "icons"), "vpn_ui/resources/icons"),
        # Include core module
        (str(core_dir), "core"),
    ],
    hiddenimports=[
        "PyQt6.QtCore",
        "PyQt6.QtGui",
        "PyQt6.QtWidgets",
        "PyQt6.sip",
        "keyring.backends",
        "keyring.backends.macOS",
        "playwright",
        "playwright.sync_api",
        "playwright.async_api",
        "pyotp",
        "core",
        "core.auth",
        "core.config",
        "core.connect",
        "core.cookies",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="ms-sso-openconnect-ui",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="ms-sso-openconnect-ui",
)

app = BUNDLE(
    coll,
    name="MS SSO OpenConnect.app",
    icon=None,
    bundle_identifier="com.github.ms-sso-openconnect-ui",
    info_plist={
        "CFBundleName": "MS SSO OpenConnect",
        "CFBundleDisplayName": "MS SSO OpenConnect",
        "CFBundleVersion": "VERSION_PLACEHOLDER",
        "CFBundleShortVersionString": "VERSION_PLACEHOLDER",
        "LSMinimumSystemVersion": "11.0",
        "LSUIElement": True,
        "NSHighResolutionCapable": True,
        "NSAppleEventsUsageDescription": "This app needs to send Apple Events for notifications.",
    },
)
SPEC

# Replace version placeholder
sed -i '' "s/VERSION_PLACEHOLDER/${VERSION}/g" "$BUILD_DIR/ms-sso-openconnect.spec"
sed -i '' "s#UI_DIR_PLACEHOLDER#${CODEBASE_UI_DIR}#g" "$BUILD_DIR/ms-sso-openconnect.spec"
sed -i '' "s#CORE_DIR_PLACEHOLDER#${CORE_DIR}#g" "$BUILD_DIR/ms-sso-openconnect.spec"

# Run PyInstaller
echo "Running PyInstaller..."
cd "$BUILD_DIR"
pyinstaller --clean --noconfirm ms-sso-openconnect.spec

# Move the app to pkg root
echo "Moving app to package root..."
mkdir -p "$PKG_ROOT/Applications"
mv "$BUILD_DIR/dist/MS SSO OpenConnect.app" "$PKG_ROOT/Applications/"

# Install Playwright browsers into the app bundle
echo "Installing Playwright Chromium..."
BROWSERS_DIR="$PKG_ROOT/Applications/MS SSO OpenConnect.app/Contents/Resources/browsers"
mkdir -p "$BROWSERS_DIR"
PLAYWRIGHT_BROWSERS_PATH="$BROWSERS_DIR" playwright install chromium

deactivate

# ===========================================================================
# Build the daemon
# ===========================================================================
echo ""
echo "=== Building Daemon ==="

DAEMON_DIR="$PKG_ROOT/Library/PrivilegedHelperTools"
LAUNCHDAEMON_DIR="$PKG_ROOT/Library/LaunchDaemons"

mkdir -p "$DAEMON_DIR" "$LAUNCHDAEMON_DIR"

# Install the real daemon. Source of truth lives in
# frontends/osx/daemon/vpn_daemon.py so it cannot drift from the dev copy.
cp "$DAEMON_SRC_DIR/vpn_daemon.py" "$DAEMON_DIR/ms-sso-openconnect-daemon"
chmod +x "$DAEMON_DIR/ms-sso-openconnect-daemon"

# Copy LaunchDaemon plist
cp "$DAEMON_SRC_DIR/com.github.ms-sso-openconnect.daemon.plist" "$LAUNCHDAEMON_DIR/"

# ===========================================================================
# Create install scripts
# ===========================================================================
echo ""
echo "=== Creating Install Scripts ==="

# Postinstall script
cat > "$SCRIPTS_DIR/postinstall" << 'POSTINSTALL'
#!/bin/bash
# Create socket directory
mkdir -p /var/run/ms-sso-openconnect
chmod 755 /var/run/ms-sso-openconnect

# Use modern launchctl commands (bootstrap/bootout instead of deprecated load/unload)
# Try to stop any existing daemon first
launchctl bootout system/com.github.ms-sso-openconnect.daemon 2>/dev/null || true

# Give it a moment to fully stop
sleep 1

# Start the daemon using bootstrap (modern macOS 10.10+)
launchctl bootstrap system /Library/LaunchDaemons/com.github.ms-sso-openconnect.daemon.plist 2>/dev/null || \
    launchctl load /Library/LaunchDaemons/com.github.ms-sso-openconnect.daemon.plist 2>/dev/null || true

# Verify daemon is running
sleep 2
if launchctl list com.github.ms-sso-openconnect.daemon &>/dev/null; then
    echo "MS SSO OpenConnect installed successfully."
    echo "The VPN daemon is now running."
else
    echo "Warning: VPN daemon may not have started. Try rebooting or run:"
    echo "  sudo launchctl bootstrap system /Library/LaunchDaemons/com.github.ms-sso-openconnect.daemon.plist"
fi
exit 0
POSTINSTALL
chmod +x "$SCRIPTS_DIR/postinstall"

# Preinstall script (stop existing daemon)
cat > "$SCRIPTS_DIR/preinstall" << 'PREINSTALL'
#!/bin/bash
# Stop existing daemon if running (using modern bootout, fallback to legacy unload)
launchctl bootout system/com.github.ms-sso-openconnect.daemon 2>/dev/null || \
    launchctl unload /Library/LaunchDaemons/com.github.ms-sso-openconnect.daemon.plist 2>/dev/null || true

# Also kill any orphaned daemon process
pkill -9 -f "ms-sso-openconnect-daemon" 2>/dev/null || true

# Clean up stale socket
rm -f /var/run/ms-sso-openconnect/daemon.sock 2>/dev/null || true
exit 0
PREINSTALL
chmod +x "$SCRIPTS_DIR/preinstall"

# ===========================================================================
# Build the pkg
# ===========================================================================
echo ""
echo "=== Building Package ==="

# Build component package
pkgbuild \
    --root "$PKG_ROOT" \
    --scripts "$SCRIPTS_DIR" \
    --identifier "com.github.ms-sso-openconnect" \
    --version "$VERSION" \
    --install-location "/" \
    "$BUILD_DIR/ms-sso-openconnect-component.pkg"

# Create distribution XML for better installer UI
cat > "$BUILD_DIR/Distribution.xml" << DISTRIBUTION
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>MS SSO OpenConnect</title>
    <welcome file="welcome.txt"/>
    <conclusion file="conclusion.txt"/>
    <options customize="never" require-scripts="false"/>
    <domains enable_anywhere="false" enable_currentUserHome="false" enable_localSystem="true"/>
    <choices-outline>
        <line choice="default"/>
    </choices-outline>
    <choice id="default" title="MS SSO OpenConnect">
        <pkg-ref id="com.github.ms-sso-openconnect"/>
    </choice>
    <pkg-ref id="com.github.ms-sso-openconnect" version="${VERSION}">ms-sso-openconnect-component.pkg</pkg-ref>
</installer-gui-script>
DISTRIBUTION

# Create welcome and conclusion texts
cat > "$BUILD_DIR/welcome.txt" << 'WELCOME'
Welcome to MS SSO OpenConnect

This package installs:
- MS SSO OpenConnect UI application
- VPN daemon (runs as root for passwordless connections)

After installation, launch the app from Applications.
WELCOME

cat > "$BUILD_DIR/conclusion.txt" << 'CONCLUSION'
Installation Complete!

You can now launch MS SSO OpenConnect from your Applications folder.

The VPN daemon is running and will start automatically at boot.
You won't need to enter your password for VPN connections.
CONCLUSION

# Build final distribution package
productbuild \
    --distribution "$BUILD_DIR/Distribution.xml" \
    --package-path "$BUILD_DIR" \
    --resources "$BUILD_DIR" \
    "$DIST_DIR/MS-SSO-OpenConnect-${VERSION}.pkg"

echo ""
echo "=== Build Complete ==="
echo "Package: $DIST_DIR/MS-SSO-OpenConnect-${VERSION}.pkg"
ls -la "$DIST_DIR/"
