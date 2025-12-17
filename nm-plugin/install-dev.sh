#!/bin/bash
#
# Development installation script for nm-plugin
# This links files for testing without full installation
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== MS SSO OpenConnect NetworkManager Plugin - Dev Install ==="
echo ""

# Check for required build dependencies
echo "Checking build dependencies..."
for pkg in meson ninja-build pkg-config libnm-dev libgtk-4-dev libglib2.0-dev libsecret-1-dev; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        echo "Missing: $pkg"
        MISSING=1
    fi
done

if [ -n "$MISSING" ]; then
    echo ""
    echo "Install missing dependencies with:"
    echo "  sudo apt install meson ninja-build pkg-config libnm-dev libgtk-4-dev libglib2.0-dev libsecret-1-dev"
    exit 1
fi

echo "All build dependencies present."
echo ""

# Build the editor library
echo "Building editor library..."
cd "$SCRIPT_DIR"

if [ -d build ]; then
    rm -rf build
fi

meson setup build
meson compile -C build

echo ""
echo "Build complete."
echo ""

# Install files
echo "Installing files (requires sudo)..."

# Create directories if needed
sudo mkdir -p /usr/lib/NetworkManager/VPN
sudo mkdir -p /usr/libexec
sudo mkdir -p /usr/share/dbus-1/system.d
sudo mkdir -p /usr/share/ms-sso-openconnect

# Detect library directory
if [ -d /usr/lib/x86_64-linux-gnu/NetworkManager ]; then
    LIBDIR=/usr/lib/x86_64-linux-gnu/NetworkManager
elif [ -d /usr/lib/aarch64-linux-gnu/NetworkManager ]; then
    LIBDIR=/usr/lib/aarch64-linux-gnu/NetworkManager
else
    LIBDIR=/usr/lib/NetworkManager
fi
sudo mkdir -p "$LIBDIR"

# Install Python scripts
sudo cp "$SCRIPT_DIR/src/nm-ms-sso-service.py" /usr/libexec/nm-ms-sso-service
sudo chmod +x /usr/libexec/nm-ms-sso-service

sudo cp "$SCRIPT_DIR/src/nm-ms-sso-auth-dialog.py" /usr/libexec/nm-ms-sso-auth-dialog
sudo chmod +x /usr/libexec/nm-ms-sso-auth-dialog

# Install configuration files
sudo cp "$SCRIPT_DIR/data/nm-ms-sso-service.name" /usr/lib/NetworkManager/VPN/
sudo cp "$SCRIPT_DIR/data/nm-ms-sso-service.conf" /usr/share/dbus-1/system.d/

# Install editor library
sudo cp "$SCRIPT_DIR/build/src/editor/libnm-vpn-plugin-ms-sso-editor.so" "$LIBDIR/"

# Install core Python module
sudo cp "$PROJECT_ROOT/ms-sso-openconnect.py" /usr/share/ms-sso-openconnect/

echo ""
echo "Files installed:"
echo "  /usr/libexec/nm-ms-sso-service"
echo "  /usr/libexec/nm-ms-sso-auth-dialog"
echo "  /usr/lib/NetworkManager/VPN/nm-ms-sso-service.name"
echo "  /usr/share/dbus-1/system.d/nm-ms-sso-service.conf"
echo "  $LIBDIR/libnm-vpn-plugin-ms-sso-editor.so"
echo "  /usr/share/ms-sso-openconnect/ms-sso-openconnect.py"
echo ""

# Restart NetworkManager
echo "Restarting NetworkManager..."
sudo systemctl restart NetworkManager

echo ""
echo "=== Installation complete! ==="
echo ""
echo "Open GNOME Settings -> Network -> VPN to add a new 'MS SSO OpenConnect' connection."
echo ""
