#!/bin/bash
# Build script for macOS (pkg with daemon) using PyInstaller
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UI_DIR="$SCRIPT_DIR/.."
REPO_ROOT="$UI_DIR/.."
VERSION="${1:-2.0.0}"

echo "=== Building macOS Package v${VERSION} ==="

# Ensure we're on macOS
if [[ "$(uname)" != "Darwin" ]]; then
    echo "Error: This script must be run on macOS"
    exit 1
fi

# Create directories
BUILD_DIR="$UI_DIR/build/macos"
PKG_ROOT="$BUILD_DIR/pkg-root"
SCRIPTS_DIR="$BUILD_DIR/scripts"
DIST_DIR="$UI_DIR/dist"

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
pip install -q -e "$UI_DIR"

# Create PyInstaller spec file
echo "Creating PyInstaller spec..."
cat > "$BUILD_DIR/ms-sso-openconnect.spec" << 'SPEC'
# -*- mode: python ; coding: utf-8 -*-
import sys
from pathlib import Path

# Paths
ui_dir = Path(SPECPATH).parent.parent
repo_root = ui_dir.parent
src_dir = ui_dir / "src"
resources_dir = src_dir / "vpn_ui" / "resources"
core_dir = repo_root / "core"

block_cipher = None

a = Analysis(
    [str(src_dir / "vpn_ui" / "__main__.py")],
    pathex=[str(src_dir), str(repo_root)],
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

# Create the daemon executable (standalone Python script - uses system Python)
cat > "$DAEMON_DIR/ms-sso-openconnect-daemon" << 'DAEMON_SCRIPT'
#!/usr/bin/env python3
"""VPN Daemon - runs as root via LaunchDaemon."""

import asyncio
import json
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import Optional

DAEMON_VERSION = "1.0.0"
SOCKET_PATH = "/var/run/ms-sso-openconnect/daemon.sock"
PID_FILE = "/var/run/ms-sso-openconnect/daemon.pid"

# Search paths for openconnect binary
OPENCONNECT_PATHS = [
    "/opt/homebrew/bin/openconnect",
    "/usr/local/bin/openconnect",
    "/usr/bin/openconnect",
]


def find_openconnect():
    for path in OPENCONNECT_PATHS:
        if os.path.exists(path):
            return path
    return None


class VPNDaemon:
    def __init__(self):
        self._openconnect_proc: Optional[subprocess.Popen] = None
        self._current_connection: Optional[str] = None
        self._server = None
        self._running = True

    async def handle_client(self, reader, writer):
        try:
            data = await asyncio.wait_for(reader.readline(), timeout=30)
            if not data:
                return

            request = json.loads(data.decode().strip())
            method = request.get("method", "")
            params = request.get("params", {})
            req_id = request.get("id", 0)

            if method == "ping":
                result = {"pong": True, "version": DAEMON_VERSION}
            elif method == "connect":
                result = await self._handle_connect(params)
            elif method == "disconnect":
                result = await self._handle_disconnect(params)
            elif method == "status":
                result = self._handle_status()
            else:
                result = {"error": f"Unknown method: {method}"}

            response = {"jsonrpc": "2.0", "result": result, "id": req_id}
            writer.write(json.dumps(response).encode() + b"\n")
            await writer.drain()
        except Exception as e:
            print(f"[Daemon] Error: {e}", file=sys.stderr)
        finally:
            writer.close()
            await writer.wait_closed()

    async def _handle_connect(self, params):
        if self._openconnect_proc and self._openconnect_proc.poll() is None:
            return {"success": False, "message": "Already connected"}

        address = params.get("address")
        protocol = params.get("protocol", "anyconnect")
        cookies = params.get("cookies", {})
        no_dtls = params.get("no_dtls", False)
        username = params.get("username")
        cached_usergroup = params.get("cached_usergroup")

        openconnect_bin = find_openconnect()
        if not openconnect_bin:
            return {"success": False, "message": "openconnect not found"}

        cmd = [openconnect_bin]
        cmd.extend([f"--protocol={protocol}"])
        if username:
            cmd.extend(["--user", username])
        if no_dtls:
            cmd.append("--no-dtls")

        # Handle cookies based on protocol
        cookie_value = None
        if protocol == "gp":
            if "portal-userauthcookie" in cookies:
                cookie_value = cookies["portal-userauthcookie"]
                cmd.extend(["--usergroup", "portal:portal-userauthcookie"])
            elif "portal_userauthcookie" in cookies:
                cookie_value = cookies["portal_userauthcookie"]
                cmd.extend(["--usergroup", "portal:portal-userauthcookie"])
            elif "prelogin-cookie" in cookies:
                cmd.extend(["--usergroup", f"portal:{cached_usergroup or 'prelogin-cookie'}"])
                cookie_value = cookies["prelogin-cookie"]
        else:
            # AnyConnect - check various cookie names
            for key in ["webvpn", "SVPNCOOKIE", "session_token"]:
                if key in cookies:
                    cookie_value = cookies[key]
                    break
            if not cookie_value and cookies:
                cookie_value = "; ".join([f"{k}={v}" for k, v in cookies.items()])

        cmd.append(address)

        try:
            if cookie_value and protocol != "gp":
                self._openconnect_proc = subprocess.Popen(
                    cmd + ["--cookie-on-stdin"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )
                self._openconnect_proc.stdin.write((cookie_value + "\n").encode())
                self._openconnect_proc.stdin.close()
            elif cookie_value and protocol == "gp":
                self._openconnect_proc = subprocess.Popen(
                    cmd + ["--passwd-on-stdin"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )
                self._openconnect_proc.stdin.write((cookie_value + "\n").encode())
                self._openconnect_proc.stdin.close()
            else:
                self._openconnect_proc = subprocess.Popen(
                    cmd, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                )

            await asyncio.sleep(2)
            if self._openconnect_proc.poll() is not None:
                output = self._openconnect_proc.stdout.read().decode()[:500]
                return {"success": False, "message": f"Failed: {output}"}

            self._current_connection = params.get("connection_name", address)
            return {"success": True, "message": "Connected"}
        except Exception as e:
            return {"success": False, "message": str(e)}

    async def _handle_disconnect(self, params):
        if not self._openconnect_proc or self._openconnect_proc.poll() is not None:
            self._openconnect_proc = None
            self._current_connection = None
            return {"success": True, "message": "Not connected"}

        try:
            # ALWAYS SIGTERM for graceful shutdown on macOS
            self._openconnect_proc.send_signal(signal.SIGTERM)
            try:
                self._openconnect_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._openconnect_proc.kill()
                self._openconnect_proc.wait()

            self._openconnect_proc = None
            self._current_connection = None
            return {"success": True, "message": "Disconnected"}
        except Exception as e:
            return {"success": False, "message": str(e)}

    def _handle_status(self):
        if self._openconnect_proc and self._openconnect_proc.poll() is None:
            return {"connected": True, "connection_name": self._current_connection,
                    "pid": self._openconnect_proc.pid}
        return {"connected": False, "connection_name": None, "pid": None}

    def _signal_handler(self, signum, frame):
        print(f"[Daemon] Signal {signum}, shutting down...", file=sys.stderr)
        self._running = False
        if self._openconnect_proc and self._openconnect_proc.poll() is None:
            self._openconnect_proc.send_signal(signal.SIGTERM)
            try:
                self._openconnect_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._openconnect_proc.kill()

    async def run(self):
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        socket_dir = Path(SOCKET_PATH).parent
        socket_dir.mkdir(parents=True, exist_ok=True)

        socket_path = Path(SOCKET_PATH)
        if socket_path.exists():
            socket_path.unlink()

        Path(PID_FILE).write_text(str(os.getpid()))

        self._server = await asyncio.start_unix_server(
            self.handle_client, path=SOCKET_PATH
        )
        os.chmod(SOCKET_PATH, 0o666)

        openconnect_bin = find_openconnect()
        print(f"[Daemon] Started v{DAEMON_VERSION}")
        print(f"[Daemon] Listening on {SOCKET_PATH}")
        print(f"[Daemon] openconnect: {openconnect_bin or 'NOT FOUND'}")

        try:
            while self._running:
                await asyncio.sleep(1)
                if self._openconnect_proc and self._openconnect_proc.poll() is not None:
                    self._openconnect_proc = None
                    self._current_connection = None
        finally:
            self._server.close()
            await self._server.wait_closed()
            if socket_path.exists():
                socket_path.unlink()
            if Path(PID_FILE).exists():
                Path(PID_FILE).unlink()
            print("[Daemon] Shutdown complete")


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Error: Must run as root", file=sys.stderr)
        sys.exit(1)
    asyncio.run(VPNDaemon().run())
DAEMON_SCRIPT
chmod +x "$DAEMON_DIR/ms-sso-openconnect-daemon"

# Copy LaunchDaemon plist
cp "$UI_DIR/macos/daemon/com.github.ms-sso-openconnect.daemon.plist" "$LAUNCHDAEMON_DIR/"

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

# Load the daemon
launchctl load /Library/LaunchDaemons/com.github.ms-sso-openconnect.daemon.plist 2>/dev/null || true

echo "MS SSO OpenConnect installed successfully."
echo "The VPN daemon is now running."
exit 0
POSTINSTALL
chmod +x "$SCRIPTS_DIR/postinstall"

# Preinstall script (stop existing daemon)
cat > "$SCRIPTS_DIR/preinstall" << 'PREINSTALL'
#!/bin/bash
# Stop existing daemon if running
launchctl unload /Library/LaunchDaemons/com.github.ms-sso-openconnect.daemon.plist 2>/dev/null || true
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
