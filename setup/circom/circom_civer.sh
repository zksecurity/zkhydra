#!/usr/bin/env bash
set -euo pipefail

echo "[info] Installing circom_civer..."

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
TOOLS_DIR="$ROOT_DIR/tools"

cd "$TOOLS_DIR/circom_civer"
echo "[info] In $(pwd)"
cargo build --release

echo "[info] circom_civer installed successfully."
