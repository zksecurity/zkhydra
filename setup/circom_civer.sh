#!/usr/bin/env bash
set -euo pipefail

echo "[info] Installing circom_civer..."

# Ensure we’re running from the script’s directory
cd "$(dirname "$0")"

cargo build --release

echo "[info] circom_civer installed successfully."
