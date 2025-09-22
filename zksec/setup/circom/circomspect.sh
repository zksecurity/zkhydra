#!/usr/bin/env bash
set -euo pipefail

echo "[info] Installing circomspect..."

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
TOOLS_DIR="$ROOT_DIR/tools"
UTILS_DIR="$ROOT_DIR/setup/utils"

# Install Rust toolchain (if present)
[[ -f "$UTILS_DIR/rust.sh" ]] && bash "$UTILS_DIR/rust.sh" || true

# Install circomspect
cd "$TOOLS_DIR/circomspect"
echo "[info] In $(pwd)"
if cargo install --path cli > /dev/null 2>&1; then
    echo "[info] circomspect installed successfully."
else
    echo "[error] circomspect installation failed."
    exit 1
fi
