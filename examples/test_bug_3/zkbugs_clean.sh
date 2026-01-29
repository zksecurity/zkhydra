#!/usr/bin/env bash
set -euo pipefail

echo "Cleaning test_bug_3..."
cd "$(dirname "$0")"

# Remove compiled artifacts
rm -rf circuit.r1cs circuit.sym circuit_js/

echo "Cleanup complete."
