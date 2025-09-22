#!/usr/bin/env bash
set -euo pipefail

echo "[info] Installing zkFuzz..."

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
TOOLS_DIR="$ROOT_DIR/tools"

# zkFuzz Installation
cd "$TOOLS_DIR/zkFuzz"
if cargo build --release > /dev/null 2>&1; then
    echo "[info] zkFuzz installed successfully."
else
    echo "[error] zkFuzz installation failed."
    exit 1
fi
