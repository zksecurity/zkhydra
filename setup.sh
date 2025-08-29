#!/bin/bash

### This script hasn't been tested yet and is currenlty just a note to remember the commands that should be needed.

# Initialize and update git submodules
# git submodule init
git submodule update --init --recursive
git submodule update

# Install uv for python package management
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install circom
## Install Rust (rather use commands from circomspect installation)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && source $HOME/.cargo/env
## Install npm
sudo apt install nodejs npm -y
sudo npm -g install snarkjs
## Install circom
./zksec/bugs/zkbugs/scripts/install_circom.sh


# circomspect Installation
cd zksec/tools/circomspect
# Install Rust (https://www.rust-lang.org/tools/install)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
cargo install --path cli



# Coda Installation
cd zksec/tools/Coda
## Install OPAM
sudo apt install opam
## Install Coq Platform 2022.04.1
sudo snap install coq-prover --channel=2022.04/stable
##
cd zksec/helpers/rewriter
make


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
raco pkg install --auto rosette
raco pkg install --auto csv-reading


# zkFuzz Installation
cd zksec/tools/zkFuzz
cargo build --release


# Install Garden -- needs rust installed
## Install OPAM
sudo apt install opam
opam init
opam switch create garden --packages=ocaml-variants.4.14.0+options,ocaml-option-flambda
eval $(opam env --switch=garden)
opam repo add coq-released https://coq.inria.fr/opam/released
opam install -y --deps-only Garden/coq-garden.opam
cd third-party/circom
cargo install --path circom
cd ../circomlib
find . -name '*.circom' -execdir circom {} \;
cd ../..
## Alias needed due to script itself as well
sudo ln -s $(which python3) /usr/bin/python
python scripts/coq_of_circom_ci.py
cd Garden
make
cd ..
opam pin add -y vscoq-language-server.2.2.3 https://github.com/rocq-prover/vscoq/releases/download/v2.2.3/vscoq-language-server-2.2.3.tar.gz
