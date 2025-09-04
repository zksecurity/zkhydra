#!/usr/bin/env bash
set -euo pipefail

echo "[info] Installing circom..."

# Ensure we’re running from the script’s directory
cd "$(dirname "$0")"

# Install Rust
./rust.sh

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
./zksec/bugs/zkbugs/scripts/install_circom.sh

echo "[info] circom installation completed successfully."
