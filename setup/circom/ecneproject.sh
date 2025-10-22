#!/usr/bin/env bash
set -euo pipefail

echo "[info] Installing EcneProject..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
TOOLS_DIR="$ROOT_DIR/tools"


# Install EcneProject
cd "$TOOLS_DIR/ecneproject/Circom_Functions"
git clone https://github.com/iden3/circomlib
cd ..

# Install Julia
curl -fsSL https://install.julialang.org | sh -s -- -y

# Install Just
sudo apt install just

# Resolving dependencies
# julia --project=.

# In the Julia REPL
# Resolve Julia dependencies
julia --project=. -e '
using Pkg
Pkg.update()
Pkg.resolve()
Pkg.update()
Pkg.instantiate()
'

# Instantiate the Julia package environment
just install
