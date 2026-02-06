#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION="${1:-2.0.0}"
TARGET="${2:-all}"

"$REPO_ROOT/frontends/linux/build.sh" "$VERSION" "$TARGET"
