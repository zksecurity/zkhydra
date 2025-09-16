#!/usr/bin/env bash
echo "===Running setup script...==="
set -e
sudo -v

# Ensure we’re running from the script’s directory
cd "$(dirname "$0")"

# Initialize and update git submodules
echo "[info] Initializing and updating Git submodules..."
git submodule update --init --recursive
echo "[info] Git submodules initialized and updated successfully."

# Install uv for Python package management
if ! command -v uv &> /dev/null; then
    echo "[info] Installing uv for Python package management..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
fi

# Install Circom
./circom.sh

# Install tools
./circom_civer.sh
./circomspect.sh
./ecneproject.sh
./picus.sh
./zkfuzz.sh

echo "===Setup script completed successfully.==="
