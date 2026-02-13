#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET="${1:-all}"

build_one() {
    local attr="$1"
    echo "Building nix package: $attr"
    nix build "$REPO_ROOT#$attr"
}

case "$TARGET" in
    core)
        build_one ms-sso-openconnect-core
        ;;
    ui)
        build_one ms-sso-openconnect-ui
        ;;
    all)
        build_one ms-sso-openconnect-core
        build_one ms-sso-openconnect-ui
        ;;
    *)
        echo "Usage: $0 [core|ui|all]"
        exit 1
        ;;
esac
