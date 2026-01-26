#!/usr/bin/env bash
set -euo pipefail

echo "Setting up test_bug_3 (bug-free IsZero circuit)..."
cd "$(dirname "$0")"

# Compile the circuit
circom circuits/circuit.circom --r1cs --wasm --sym --output .

echo "test_bug_3 setup complete."
