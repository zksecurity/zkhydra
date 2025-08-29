#!/usr/bin/env bash
set -euo pipefail

echo "[info] Installing garden..."

# Ensure we’re running from the script’s directory
cd "$(dirname "$0")"

# Install Rust
./rust.sh

cd ../zksec/tools/garden

# Install OPAM if not present
if ! command -v opam &> /dev/null; then
    echo "Installing OPAM..."
    sudo apt update
    sudo apt install -y opam
fi

# Initialize OPAM if needed
if [ ! -d "$HOME/.opam" ]; then
    opam init -y
fi

# Create Garden switch if it doesn't exist
if ! opam switch list --short | grep -q "^garden$"; then
    opam switch create garden --packages=ocaml-variants.4.14.0+options,ocaml-option-flambda 
fi

# Load switch environment
eval "$(opam env --switch=garden)"

# Add Coq repo if not already added
if ! opam repo list | grep -q "coq-released"; then
    opam repo add coq-released https://coq.inria.fr/opam/released
fi

# Install Garden dependencies
opam install --deps-only -y ./Garden/coq-garden.opam

cd third-party/circom

# Install Circom via Cargo if needed
if ! cargo install --list | grep -q '^circom'; then
    cargo install --path circom > /dev/null 2>&1
fi

cd ../circomlib

# Compile all .circom files
find . -name '*.circom' -execdir circom {} \;

cd ../..

# Symlink needed due to given script
sudo ln -s $(which python3) /usr/bin/python
python scripts/coq_of_circom_ci.py
# Remove symlink again
sudo rm /usr/bin/python

cd Garden
make > /dev/null 2>&1
cd ..

# Pin VSCoq language server if not already pinned
if ! opam list --installed | grep -q 'vscoq-language-server'; then
    opam pin add -y vscoq-language-server.2.2.3 https://github.com/rocq-prover/vscoq/releases/download/v2.2.3/vscoq-language-server-2.2.3.tar.gz
fi


if [ $? -eq 0 ]; then
    echo "[info] Garden installed successfully."
else
    echo "[error] Garden installation failed."
    exit 1
fi
