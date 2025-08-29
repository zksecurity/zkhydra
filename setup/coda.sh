#!/usr/bin/env bash
set -euo pipefail

echo "[info] Installing Coda..."

# Ensure we’re running from the script’s directory
cd "$(dirname "$0")"

# Coda Installation
cd ../zksec/tools/Coda

# Install OPAM
if ! command -v opam &> /dev/null; then
    echo "[info] Installing OPAM..."
    sudo apt update
    sudo apt install -y opam
fi

if ! command -v coqtop &> /dev/null; then
    echo "[info] Installing Coq Platform 2022.04.1..."
    sudo snap install coq-prover --channel=2022.04/stable
fi

# Build Rewriter
cd ../zksec/helpers/rewriter
make

# TODO: Fix Coda installation
