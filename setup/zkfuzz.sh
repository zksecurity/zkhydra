#!/usr/bin/env bash
set -euo pipefail

echo "[info] Installing zkFuzz..."

# Ensure we’re running from the script’s directory
cd "$(dirname "$0")"

# zkFuzz Installation
cd ../zksec/tools/zkFuzz
if cargo build --release > /dev/null 2>&1; then
    echo "[info] zkFuzz installed successfully."
else
    echo "[error] zkFuzz installation failed."
    exit 1
fi
