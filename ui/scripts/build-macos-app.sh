#!/bin/bash
#
# Build macOS .app bundle for MS SSO OpenConnect UI
#
# This script creates a self-contained .app bundle that includes:
# - Python virtual environment with all dependencies
# - Playwright with Chromium browser
# - The VPN UI application and core module
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR/.."
REPO_ROOT="$PROJECT_DIR/.."
APP_NAME="MS SSO OpenConnect"
VERSION="${1:-1.0.1}"
DIST_DIR="$PROJECT_DIR/dist"
APP_DIR="$DIST_DIR/${APP_NAME}.app"
CONTENTS="$APP_DIR/Contents"

echo "=== Building ${APP_NAME} v${VERSION} for macOS ==="
echo ""

# Check for required tools
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo "Error: $1 is not installed"
        echo "Install with: $2"
        exit 1
    fi
}

check_tool python3 "brew install python3"

# Clean previous build
echo "Cleaning previous build..."
rm -rf "$APP_DIR"
mkdir -p "$CONTENTS"/{MacOS,Resources}

# Create venv
echo "Creating Python virtual environment..."
python3 -m venv "$CONTENTS/Resources/venv"
"$CONTENTS/Resources/venv/bin/pip" install -q --upgrade pip

# Install dependencies
echo "Installing dependencies..."
"$CONTENTS/Resources/venv/bin/pip" install -q PyQt6 keyring pyotp playwright

# Install vpn_ui package
echo "Installing vpn_ui..."
"$CONTENTS/Resources/venv/bin/pip" install -q -e "$PROJECT_DIR"

# Install Playwright Chromium
echo "Installing Playwright Chromium..."
PLAYWRIGHT_PATH="$CONTENTS/Resources/playwright-browsers"
mkdir -p "$PLAYWRIGHT_PATH"
PLAYWRIGHT_BROWSERS_PATH="$PLAYWRIGHT_PATH" "$CONTENTS/Resources/venv/bin/playwright" install chromium

# Copy core module
echo "Copying core module..."
cp -r "$REPO_ROOT/core" "$CONTENTS/Resources/"

# Copy icons
echo "Copying resources..."
mkdir -p "$CONTENTS/Resources/icons"
cp "$PROJECT_DIR/src/vpn_ui/resources/icons/"*.svg "$CONTENTS/Resources/icons/"

# Convert SVG to ICNS for macOS app icon (if possible)
if command -v rsvg-convert &> /dev/null && command -v iconutil &> /dev/null; then
    echo "Creating app icon..."
    ICONSET_DIR="$CONTENTS/Resources/app.iconset"
    mkdir -p "$ICONSET_DIR"

    # Generate different sizes
    for size in 16 32 64 128 256 512; do
        rsvg-convert -w $size -h $size "$PROJECT_DIR/src/vpn_ui/resources/icons/app-icon.svg" \
            -o "$ICONSET_DIR/icon_${size}x${size}.png" 2>/dev/null || true
        # Retina versions
        double=$((size * 2))
        rsvg-convert -w $double -h $double "$PROJECT_DIR/src/vpn_ui/resources/icons/app-icon.svg" \
            -o "$ICONSET_DIR/icon_${size}x${size}@2x.png" 2>/dev/null || true
    done

    # Create ICNS
    iconutil -c icns "$ICONSET_DIR" -o "$CONTENTS/Resources/app.icns" 2>/dev/null || true
    rm -rf "$ICONSET_DIR"
fi

# Detect Python version for paths
PYTHON_VERSION=$("$CONTENTS/Resources/venv/bin/python" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")

# Create launcher script
echo "Creating launcher script..."
cat > "$CONTENTS/MacOS/ms-sso-openconnect-ui" << 'LAUNCHER'
#!/bin/bash
DIR="$(dirname "$0")"
RESOURCES="$DIR/../Resources"

# Set environment variables
export PLAYWRIGHT_BROWSERS_PATH="$RESOURCES/playwright-browsers"
export QT_PLUGIN_PATH="$RESOURCES/venv/lib/python${PYTHON_VERSION}/site-packages/PyQt6/Qt6/plugins"
export PYTHONPATH="$RESOURCES:$PYTHONPATH"
export PATH="$RESOURCES/venv/bin:$PATH"

# Run the application
exec "$RESOURCES/venv/bin/python" -m vpn_ui "$@"
LAUNCHER

# Replace PYTHON_VERSION placeholder
sed -i '' "s/\${PYTHON_VERSION}/$PYTHON_VERSION/g" "$CONTENTS/MacOS/ms-sso-openconnect-ui"
chmod +x "$CONTENTS/MacOS/ms-sso-openconnect-ui"

# Create Info.plist
echo "Creating Info.plist..."
cat > "$CONTENTS/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>MS SSO OpenConnect</string>
    <key>CFBundleDisplayName</key>
    <string>MS SSO OpenConnect</string>
    <key>CFBundleExecutable</key>
    <string>ms-sso-openconnect-ui</string>
    <key>CFBundleIdentifier</key>
    <string>com.github.ms-sso-openconnect-ui</string>
    <key>CFBundleVersion</key>
    <string>${VERSION}</string>
    <key>CFBundleShortVersionString</key>
    <string>${VERSION}</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleIconFile</key>
    <string>app</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSRequiresAquaSystemAppearance</key>
    <false/>
    <key>NSAppleEventsUsageDescription</key>
    <string>MS SSO OpenConnect needs to run administrative commands to manage VPN connections.</string>
    <key>NSSystemAdministrationUsageDescription</key>
    <string>MS SSO OpenConnect requires administrator privileges to manage VPN connections via openconnect.</string>
</dict>
</plist>
EOF

# Copy LaunchAgent plist to Resources for easy installation
cp "$PROJECT_DIR/packaging/launchd/com.github.ms-sso-openconnect-ui.plist" "$CONTENTS/Resources/"

# Create install-launchagent helper script
cat > "$CONTENTS/Resources/install-launchagent.sh" << 'INSTALL_SCRIPT'
#!/bin/bash
# Install LaunchAgent for autostart at login

PLIST_NAME="com.github.ms-sso-openconnect-ui.plist"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_PLIST="$SCRIPT_DIR/$PLIST_NAME"
DEST_DIR="$HOME/Library/LaunchAgents"
DEST_PLIST="$DEST_DIR/$PLIST_NAME"

mkdir -p "$DEST_DIR"

# Unload if already loaded
launchctl unload "$DEST_PLIST" 2>/dev/null || true

# Copy and load
cp "$SOURCE_PLIST" "$DEST_PLIST"
launchctl load "$DEST_PLIST"

echo "LaunchAgent installed. MS SSO OpenConnect will start automatically at login."
INSTALL_SCRIPT
chmod +x "$CONTENTS/Resources/install-launchagent.sh"

# Create uninstall-launchagent helper script
cat > "$CONTENTS/Resources/uninstall-launchagent.sh" << 'UNINSTALL_SCRIPT'
#!/bin/bash
# Uninstall LaunchAgent

PLIST_NAME="com.github.ms-sso-openconnect-ui.plist"
DEST_PLIST="$HOME/Library/LaunchAgents/$PLIST_NAME"

launchctl unload "$DEST_PLIST" 2>/dev/null || true
rm -f "$DEST_PLIST"

echo "LaunchAgent uninstalled."
UNINSTALL_SCRIPT
chmod +x "$CONTENTS/Resources/uninstall-launchagent.sh"

echo ""
echo "=== Build complete ==="
echo ""
echo "App bundle created: $APP_DIR"
echo ""
echo "To install:"
echo "  cp -r \"$APP_DIR\" /Applications/"
echo ""
echo "To enable autostart at login:"
echo "  /Applications/MS\\ SSO\\ OpenConnect.app/Contents/Resources/install-launchagent.sh"
echo ""
echo "To run:"
echo "  open \"/Applications/MS SSO OpenConnect.app\""
