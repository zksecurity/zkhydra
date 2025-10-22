#!/usr/bin/env bash
set -euo pipefail

echo "[info] Installing circom..."

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
UTILS_DIR="$ROOT_DIR/setup/utils"

# Install Rust
[[ -f "$UTILS_DIR/rust.sh" ]] && bash "$UTILS_DIR/rust.sh" || true

# Install Node.js & npm
if ! command -v node &> /dev/null || ! command -v npm &> /dev/null; then
    echo "[info] Installing Node.js and npm..."
    sudo apt update
    sudo apt install -y nodejs npm
fi

# Install snarkjs globally via npm
if ! npm list -g snarkjs &> /dev/null; then
    echo "[info] Installing snarkjs globally..."
    sudo npm install -g snarkjs
fi

# Install circom
bash "$ROOT_DIR/bugs/zkbugs/scripts/install_circom.sh"

echo "[info] circom installation completed successfully."
