#!/usr/bin/env bash
set -euo pipefail

echo "[info] Installing circomspect..."

# Ensure we’re running from the script’s directory
cd "$(dirname "$0")"

# Install Rust
./rust.sh

# Install circomspect
cd ../zksec/tools/circomspect
if cargo install --path cli > /dev/null 2>&1; then
    echo "[info] circomspect installed successfully."
else
    echo "[error] circomspect installation failed."
    exit 1
fi
