#!/usr/bin/env bash
set -euo pipefail

echo "Setting up test bug..."
cd "$(dirname "$0")"

# Compile the circuit
circom circuits/circuit.circom --r1cs --wasm --sym --output .

echo "Test bug setup complete."
