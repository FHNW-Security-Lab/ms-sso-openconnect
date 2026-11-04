#!/usr/bin/env bash
# Build script for macOS (pkg with daemon) using PyInstaller
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRONTEND_DIR="$SCRIPT_DIR/.."
REPO_ROOT="$FRONTEND_DIR/../.."
CODEBASE_UI_DIR="$REPO_ROOT/codebase/ui"
CORE_DIR="$REPO_ROOT/codebase/core"
DAEMON_SRC_DIR="$REPO_ROOT/frontends/osx/daemon"
VERSION="${1:-2.1.6}"

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
"${PYTHON_BIN:-python3}" -m venv "$VENV_DIR"
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

# The privileged helper has its own root-owned runtime. Do not depend on
# launchd finding Homebrew or the developer-tools Python installation.
source "$VENV_DIR/bin/activate"
pyinstaller --clean --noconfirm --onedir \
    --name ms-sso-openconnect-daemon \
    --paths "$DAEMON_SRC_DIR" \
    --distpath "$BUILD_DIR/daemon-dist" \
    --workpath "$BUILD_DIR/daemon-work" \
    --specpath "$BUILD_DIR" \
    "$DAEMON_SRC_DIR/vpn_daemon.py"
mv "$BUILD_DIR/daemon-dist/ms-sso-openconnect-daemon" "$DAEMON_DIR/ms-sso-openconnect"

# OpenConnect invokes this without a shell command string or system Python.
cat > "$DAEMON_DIR/ms-sso-openconnect/ms-sso-hip-report" << 'HIP_WRAPPER'
#!/bin/sh
exec /Library/PrivilegedHelperTools/ms-sso-openconnect/ms-sso-openconnect-daemon --hip-report "$@"
HIP_WRAPPER
chmod +x "$DAEMON_DIR/ms-sso-openconnect/ms-sso-hip-report"

cat > "$DAEMON_DIR/ms-sso-openconnect/ms-sso-vpnc-script" << 'NETWORK_WRAPPER'
#!/bin/sh
exec /Library/PrivilegedHelperTools/ms-sso-openconnect/ms-sso-openconnect-daemon --network-script
NETWORK_WRAPPER
chmod +x "$DAEMON_DIR/ms-sso-openconnect/ms-sso-vpnc-script"

# Declare the actual minimum supported OS from all bundled native binaries.
MIN_MACOS=$(python "$SCRIPT_DIR/macos-minimum.py" "$PKG_ROOT")
/usr/libexec/PlistBuddy -c "Set :LSMinimumSystemVersion $MIN_MACOS" \
    "$PKG_ROOT/Applications/MS SSO OpenConnect.app/Contents/Info.plist"
# Chromium is installed after PyInstaller creates the app. Re-seal the outer
# bundle now, preserving vendor signatures in its nested browser components.
codesign --force --sign - "$PKG_ROOT/Applications/MS SSO OpenConnect.app"
codesign --verify --deep --strict "$PKG_ROOT/Applications/MS SSO OpenConnect.app"
deactivate

# Copy LaunchDaemon plist
cp "$DAEMON_SRC_DIR/com.github.ms-sso-openconnect.daemon.plist" "$LAUNCHDAEMON_DIR/"

# ===========================================================================
# Create install scripts
# ===========================================================================
echo ""
echo "=== Creating Install Scripts ==="

# Postinstall runs inside the already-authorized installer. Runtime connections
# use only the helper socket and never request administrator privileges.
cat > "$SCRIPTS_DIR/postinstall" << 'POSTINSTALL'
#!/bin/bash
set -euo pipefail
LABEL=com.github.ms-sso-openconnect.daemon
HELPER=/Library/PrivilegedHelperTools/ms-sso-openconnect/ms-sso-openconnect-daemon
mkdir -p /var/run/ms-sso-openconnect
chmod 755 /var/run/ms-sso-openconnect
launchctl bootout "system/$LABEL" 2>/dev/null || true
if ! launchctl bootstrap system "/Library/LaunchDaemons/$LABEL.plist"; then
    echo "Unable to start the VPN helper. Re-run this installer to repair it." >&2
    exit 1
fi
for attempt in {1..15}; do
    if "$HELPER" --check; then
        echo "MS SSO OpenConnect installed. VPN connections do not require administrator approval."
        exit 0
    fi
    sleep 1
done
echo "The VPN helper did not become ready. Re-run this installer to repair it." >&2
exit 1
POSTINSTALL
chmod +x "$SCRIPTS_DIR/postinstall"

cat > "$SCRIPTS_DIR/preinstall" << 'PREINSTALL'
#!/bin/bash
set -euo pipefail
LABEL=com.github.ms-sso-openconnect.daemon
# launchd stops its owned helper gracefully; do not kill unrelated VPNs.
launchctl bootout "system/$LABEL" 2>/dev/null || true
# bootout can return before shutdown finishes. Allow the plist's 30-second
# ExitTimeOut plus a small margin before replacing the helper or its socket.
for attempt in {0..35}; do
    if ! launchctl print "system/$LABEL" >/dev/null 2>&1; then
        break
    fi
    if (( attempt == 35 )); then
        echo "The previous VPN helper could not be stopped." >&2
        exit 1
    fi
    sleep 1
done
rm -f /var/run/ms-sso-openconnect/daemon.sock
# Remove the legacy script only; new packages install a self-contained directory.
rm -f /Library/PrivilegedHelperTools/ms-sso-openconnect-daemon
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
    <options customize="never" require-scripts="false" hostArchitectures="$(uname -m)"/>
    <volume-check script="true">
        <allowed-os-versions><os-version min="${MIN_MACOS}"/></allowed-os-versions>
    </volume-check>
    <domains enable_anywhere="false" enable_currentUserHome="false" enable_localSystem="true"/>
    <choices-outline>
        <line choice="default"/>
    </choices-outline>
    <choice id="default" title="MS SSO OpenConnect">
        <pkg-ref id="com.github.ms-sso-openconnect"/>
    </choice>
    <pkg-ref id="com.github.ms-sso-openconnect" version="${VERSION}">ms-sso-openconnect-component.pkg</pkg-ref>
    <pkg-ref id="com.github.ms-sso-openconnect">
        <must-close>
            <app id="com.github.ms-sso-openconnect-ui"/>
        </must-close>
    </pkg-ref>
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
OpenConnect must be installed separately (brew install openconnect).

The VPN daemon is running and will start automatically at boot.
You won't need to enter your password for VPN connections.
CONCLUSION

# Only the installer text belongs in the resources archive.
mkdir -p "$BUILD_DIR/installer-resources"
cp "$BUILD_DIR/welcome.txt" "$BUILD_DIR/conclusion.txt" "$BUILD_DIR/installer-resources/"

# Build final distribution package
productbuild \
    --distribution "$BUILD_DIR/Distribution.xml" \
    --package-path "$BUILD_DIR" \
    --resources "$BUILD_DIR/installer-resources" \
    "$DIST_DIR/MS-SSO-OpenConnect-${VERSION}-macos-$(uname -m).pkg"

echo ""
echo "=== Build Complete ==="
echo "Package: $DIST_DIR/MS-SSO-OpenConnect-${VERSION}-macos-$(uname -m).pkg"
ls -la "$DIST_DIR/"
