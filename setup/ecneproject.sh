#!/usr/bin/env bash
set -euo pipefail

echo "[info] Installing EcneProject..."
# Ensure we’re running from the script’s directory
cd "$(dirname "$0")"


# Install EcneProject
cd ../zksec/tools/EcneProject/Circom_Functions
git clone https://github.com/iden3/circomlib
cd ..

# Install Julia
curl -fsSL https://install.julialang.org | sh -s -- -y

# Install Just
sudo apt install just

# Resolving dependencies
julia --project=.

# In the Julia REPL
# Resolve Julia dependencies
julia --project=. -e '
using Pkg
Pkg.resolve()
Pkg.update()
Pkg.instantiate()
'

# Instantiate the Julia package environment
just install
