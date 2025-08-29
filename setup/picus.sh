#!/usr/bin/env bash
set -euo pipefail

echo "[info] Installing Picus..."

# Ensure we’re running from the script’s directory
cd "$(dirname "$0")"

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

# Steup CVC5 environment
cd ../zksec/helpers/cvc5

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
cd ../zksec/tools/Picus

raco pkg install || true

# Install Rosette and CSV-reading if not installed
for pkg in rosette csv-reading; do
    if ! raco pkg show "$pkg" &> /dev/null; then
        raco pkg install --auto "$pkg"
done

echo "[info] Picus installed successfully."
