#!/usr/bin/env bash
set -euo pipefail

# Install Rust only if rustup is not found
if ! command -v rustup &> /dev/null; then
    echo "Rust not found. Installing..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi

# Always source env (in case script is run in a fresh shell)
if [ -f "$HOME/.cargo/env" ]; then
    . "$HOME/.cargo/env"
fi
