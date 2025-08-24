#!/bin/bash

# Initialize and update git submodules
git submodule init
git submodule update

# Install uv for python package management
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install circom
## Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && source $HOME/.cargo/env
## Install npm
sudo apt install nodejs npm -y
sudo npm -g install snarkjs
## Install circom
./zksec/bugs/zkbugs/scripts/install_circom.sh

# Picus Installation
cd zksec/tools/Picus
## Install Racket
sudo apt install racket -y
## Install cvc5-ff
cd ../../helpers/cvc5
sudo apt install libgmp-dev
uv venv
uv pip install tomli scikit-build Cython
uv run ./configure.sh --cocoa --auto-download --python-bindings
cd build/
make -j4 install
## Install Picus
raco pkg install
