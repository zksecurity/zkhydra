#!/usr/bin/env bash
set -euo pipefail

echo "[info] Installing pilspector..."

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
TOOLS_DIR="$ROOT_DIR/tools"

cd "$TOOLS_DIR/pilspector"
echo "[info] In $(pwd)"
cargo build --release

echo "[info] pilspector installed successfully."
