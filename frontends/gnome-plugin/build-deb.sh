#!/usr/bin/env bash
#
# Build Debian package for network-manager-ms-sso
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PACKAGE_NAME="network-manager-ms-sso"
VERSION="2.0.0"

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    echo "Usage: $0"
    echo "Builds Debian package for the GNOME NetworkManager plugin."
    exit 0
fi

echo "=== Building Debian Package for $PACKAGE_NAME ==="
echo ""

# Check for required build tools
echo "Checking build dependencies..."
MISSING=""
for pkg in dpkg-dev debhelper meson ninja-build pkg-config libnm-dev libgtk-4-dev libglib2.0-dev libsecret-1-dev; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        echo "  Missing: $pkg"
        MISSING="$MISSING $pkg"
    fi
done

if [ -n "$MISSING" ]; then
    echo ""
    echo "Install missing dependencies with:"
    echo "  sudo apt install$MISSING"
    exit 1
fi
echo "All build dependencies present."
echo ""

# Create build directory
BUILD_DIR="$SCRIPT_DIR/deb-build"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Create source directory with version
SRC_DIR="$BUILD_DIR/${PACKAGE_NAME}-${VERSION}"
mkdir -p "$SRC_DIR"

# Copy source files
echo "Copying source files..."
cp -r "$SCRIPT_DIR/src" "$SRC_DIR/"
cp -r "$SCRIPT_DIR/data" "$SRC_DIR/"
cp "$SCRIPT_DIR/meson.build" "$SRC_DIR/"
cp -r "$REPO_ROOT/codebase/core" "$SRC_DIR/"

# Copy and setup debian directory
cp -r "$SCRIPT_DIR/packaging/debian" "$SRC_DIR/"

# Update debian/rules to not use parent directory reference
cat > "$SRC_DIR/debian/rules" << 'RULES_EOF'
#!/usr/bin/make -f

export DEB_BUILD_MAINT_OPTIONS = hardening=+all

%:
	dh $@ --buildsystem=meson

override_dh_auto_configure:
	dh_auto_configure -- \
		--prefix=/usr \
		--libexecdir=/usr/libexec \
		--sysconfdir=/etc

override_dh_auto_install:
	dh_auto_install
	# Install the core Python module directory
	mkdir -p debian/network-manager-ms-sso/usr/share/ms-sso-openconnect/
	cp -r core debian/network-manager-ms-sso/usr/share/ms-sso-openconnect/
RULES_EOF
chmod +x "$SRC_DIR/debian/rules"

# Add source format
mkdir -p "$SRC_DIR/debian/source"
echo "3.0 (native)" > "$SRC_DIR/debian/source/format"

# Build the package
echo ""
echo "Building package..."
cd "$SRC_DIR"
dpkg-buildpackage -us -uc -b

# Move the built packages to output directory
echo ""
echo "Moving packages to output directory..."
mkdir -p "$SCRIPT_DIR/dist"
mv "$BUILD_DIR"/*.deb "$SCRIPT_DIR/dist/" 2>/dev/null || true
mv "$BUILD_DIR"/*.changes "$SCRIPT_DIR/dist/" 2>/dev/null || true
mv "$BUILD_DIR"/*.buildinfo "$SCRIPT_DIR/dist/" 2>/dev/null || true

# Cleanup
rm -rf "$BUILD_DIR"

echo ""
echo "=== Build Complete ==="
echo ""
echo "Package(s) created in: $SCRIPT_DIR/dist/"
ls -la "$SCRIPT_DIR/dist/"
echo ""
echo "Install with:"
echo "  sudo dpkg -i $SCRIPT_DIR/dist/${PACKAGE_NAME}_*.deb"
echo "  sudo apt-get install -f  # to fix any missing dependencies"
echo ""
