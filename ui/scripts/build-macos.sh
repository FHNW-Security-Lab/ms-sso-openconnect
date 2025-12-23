#!/bin/bash
# Build script for macOS (pkg with daemon)
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
# Build the .app bundle (UI application)
# ===========================================================================
echo ""
echo "=== Building .app Bundle ==="

APP_DIR="$PKG_ROOT/Applications/MS SSO OpenConnect.app"
CONTENTS="$APP_DIR/Contents"
MACOS_DIR="$CONTENTS/MacOS"
RESOURCES="$CONTENTS/Resources"

mkdir -p "$MACOS_DIR" "$RESOURCES"

# Detect Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "Using Python $PYTHON_VERSION"

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv "$RESOURCES/venv"
source "$RESOURCES/venv/bin/activate"

# Install dependencies
echo "Installing dependencies..."
pip install -q --upgrade pip wheel
pip install -q PyQt6 keyring pyotp playwright

# Install the UI package
pip install -q "$UI_DIR"

# Install Playwright browsers
echo "Installing Playwright Chromium..."
PLAYWRIGHT_BROWSERS_PATH="$RESOURCES/browsers" playwright install chromium

deactivate

# Copy core module
echo "Copying core module..."
cp -r "$REPO_ROOT/core" "$RESOURCES/"

# Copy icons
mkdir -p "$RESOURCES/icons"
cp "$UI_DIR/src/vpn_ui/resources/icons/"*.svg "$RESOURCES/icons/"

# Create launcher script
cat > "$MACOS_DIR/ms-sso-openconnect-ui" << LAUNCHER
#!/bin/bash
DIR="\$(dirname "\$0")"
RESOURCES="\$DIR/../Resources"

export PLAYWRIGHT_BROWSERS_PATH="\$RESOURCES/browsers"
export PYTHONPATH="\$RESOURCES:\$PYTHONPATH"
export PATH="\$RESOURCES/venv/bin:\$PATH"
export QT_PLUGIN_PATH="\$RESOURCES/venv/lib/python${PYTHON_VERSION}/site-packages/PyQt6/Qt6/plugins"

exec "\$RESOURCES/venv/bin/python" -m vpn_ui "\$@"
LAUNCHER
chmod +x "$MACOS_DIR/ms-sso-openconnect-ui"

# Create Info.plist
cat > "$CONTENTS/Info.plist" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>MS SSO OpenConnect</string>
    <key>CFBundleDisplayName</key>
    <string>MS SSO OpenConnect</string>
    <key>CFBundleIdentifier</key>
    <string>com.github.ms-sso-openconnect-ui</string>
    <key>CFBundleVersion</key>
    <string>${VERSION}</string>
    <key>CFBundleShortVersionString</key>
    <string>${VERSION}</string>
    <key>CFBundleExecutable</key>
    <string>ms-sso-openconnect-ui</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSAppleEventsUsageDescription</key>
    <string>This app needs to send Apple Events for notifications.</string>
</dict>
</plist>
PLIST

# ===========================================================================
# Build the daemon
# ===========================================================================
echo ""
echo "=== Building Daemon ==="

DAEMON_DIR="$PKG_ROOT/Library/PrivilegedHelperTools"
LAUNCHDAEMON_DIR="$PKG_ROOT/Library/LaunchDaemons"

mkdir -p "$DAEMON_DIR" "$LAUNCHDAEMON_DIR"

# Create the daemon executable (standalone Python script with bundled deps)
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

        # Find openconnect binary
        openconnect_bin = None
        for path in ["/opt/homebrew/bin/openconnect", "/usr/local/bin/openconnect", "/usr/bin/openconnect"]:
            if os.path.exists(path):
                openconnect_bin = path
                break
        if not openconnect_bin:
            return {"success": False, "message": "openconnect not found"}

        cmd = [openconnect_bin]
        cmd.extend([f"--protocol={protocol}"])
        if username:
            cmd.extend(["--user", username])
        if no_dtls:
            cmd.append("--no-dtls")

        cookie_value = None
        if protocol == "gp":
            if "portal_userauthcookie" in cookies:
                cookie_value = cookies["portal_userauthcookie"]
                cmd.extend(["--cookie", cookie_value])
        else:
            cookie_value = cookies.get("webvpn") or cookies.get("session_token")

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
            else:
                self._openconnect_proc = subprocess.Popen(
                    cmd, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                )

            await asyncio.sleep(1)
            if self._openconnect_proc.poll() is not None:
                output = self._openconnect_proc.stdout.read().decode()[:200]
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

        print(f"[Daemon] Started v{DAEMON_VERSION}, listening on {SOCKET_PATH}")

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
