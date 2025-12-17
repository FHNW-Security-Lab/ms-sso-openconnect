#!/bin/bash
#
# Build macOS .app bundle for MS SSO OpenConnect UI
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR/.."
REPO_ROOT="$PROJECT_DIR/.."
APP_NAME="MS SSO OpenConnect"
VERSION="${1:-1.0.0}"
DIST_DIR="$PROJECT_DIR/dist"
APP_DIR="$DIST_DIR/${APP_NAME}.app"
CONTENTS="$APP_DIR/Contents"

echo "=== Building ${APP_NAME} v${VERSION} for macOS ==="

# Clean previous build
rm -rf "$APP_DIR"
mkdir -p "$CONTENTS"/{MacOS,Resources}

# Create venv
echo "Creating Python virtual environment..."
python3 -m venv "$CONTENTS/Resources/venv"
"$CONTENTS/Resources/venv/bin/pip" install -q --upgrade pip

# Install dependencies
echo "Installing dependencies..."
"$CONTENTS/Resources/venv/bin/pip" install -q PyQt6 keyring pyotp playwright

# Install Playwright Chromium
echo "Installing Playwright Chromium..."
"$CONTENTS/Resources/venv/bin/playwright" install chromium

# Copy app code
echo "Copying application files..."
cp -r "$PROJECT_DIR/src/vpn_ui" "$CONTENTS/Resources/"
cp "$REPO_ROOT/ms-sso-openconnect.py" "$CONTENTS/Resources/"

# Copy icons
mkdir -p "$CONTENTS/Resources/icons"
cp "$PROJECT_DIR/src/vpn_ui/resources/icons/"*.svg "$CONTENTS/Resources/icons/"

# Create launcher script
cat > "$CONTENTS/MacOS/ms-sso-openconnect-ui" << 'EOF'
#!/bin/bash
DIR="$(dirname "$0")"
RESOURCES="$DIR/../Resources"
export PLAYWRIGHT_BROWSERS_PATH="$HOME/Library/Caches/ms-playwright"
export PYTHONPATH="$RESOURCES"
exec "$RESOURCES/venv/bin/python" -m vpn_ui "$@"
EOF
chmod +x "$CONTENTS/MacOS/ms-sso-openconnect-ui"

# Create Info.plist
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
    <string>com.github.ms-sso-openconnect</string>
    <key>CFBundleVersion</key>
    <string>${VERSION}</string>
    <key>CFBundleShortVersionString</key>
    <string>${VERSION}</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
EOF

echo ""
echo "=== Build complete ==="
echo "App bundle: $APP_DIR"
echo ""
echo "To run: open \"$APP_DIR\""
echo "To install: cp -r \"$APP_DIR\" /Applications/"
