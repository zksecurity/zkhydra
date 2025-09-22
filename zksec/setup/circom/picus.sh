#!/usr/bin/env bash
set -euo pipefail

echo "[info] Installing Picus..."

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
TOOLS_DIR="$ROOT_DIR/tools"
HELPERS_DIR="$ROOT_DIR/helpers"

# Install Racket
if ! command -v racket &> /dev/null; then
    echo "[info] Installing Racket..."
    sudo apt update
    sudo apt install -y racket
fi

if ! dpkg -s libgmp-dev &> /dev/null; then
    echo "[info] Installing libgmp-dev..."
    sudo apt install -y libgmp-dev
fi

# Setup CVC5 environment
cd "$HELPERS_DIR/cvc5"

if [ ! -d "venv" ]; then
    uv venv
fi

uv pip install tomli scikit-build Cython

if [ ! -f "build/Makefile" ]; then
    uv run ./configure.sh --cocoa --auto-download --python-bindings --gpl
fi

cd build
make -j4 install > /dev/null 2>&1

# Install Picus
cd "$TOOLS_DIR/Picus"

raco pkg install || true

# Install Rosette and CSV-reading if not installed
for pkg in rosette csv-reading; do
    if ! raco pkg show "$pkg" &> /dev/null; then
        raco pkg install --auto "$pkg"
    fi
done

echo "[info] Picus installed successfully."
