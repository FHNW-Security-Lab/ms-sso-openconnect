#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET="${1:-all}"

build_one() {
    local attr="$1"
    echo "Building nix attribute: $attr"
    nix-build "$REPO_ROOT/nix/default.nix" -A "$attr"
}

case "$TARGET" in
    core)
        build_one ms-sso-openconnect-core
        ;;
    ui)
        build_one ms-sso-openconnect-ui
        ;;
    plugin|gnome-plugin)
        build_one networkmanager-ms-sso
        ;;
    all)
        build_one ms-sso-openconnect-core
        build_one ms-sso-openconnect-ui
        build_one networkmanager-ms-sso
        ;;
    *)
        echo "Usage: $0 [core|ui|plugin|all]"
        exit 1
        ;;
esac
