#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET="${1:-help}"
VERSION="${2:-2.0.0}"

case "$TARGET" in
    appimage)
        "$SCRIPT_DIR/build-linux.sh" "$VERSION" appimage
        ;;
    deb)
        "$SCRIPT_DIR/build-linux.sh" "$VERSION" deb
        ;;
    linux-all)
        "$SCRIPT_DIR/build-linux.sh" "$VERSION" all
        ;;
    pkg|osx-pkg)
        "$SCRIPT_DIR/build-macos.sh" "$VERSION"
        ;;
    nix)
        "$SCRIPT_DIR/build-nix.sh" "${2:-all}"
        ;;
    help|-h|--help)
        cat <<'EOF'
Unified build entrypoint

Usage:
  ./build/build.sh appimage [version]
  ./build/build.sh deb [version]
  ./build/build.sh linux-all [version]
  ./build/build.sh pkg [version]
  ./build/build.sh nix [core|ui|all]
EOF
        ;;
    *)
        echo "Unknown target: $TARGET"
        "$REPO_ROOT/build/build.sh" help
        exit 1
        ;;
esac
