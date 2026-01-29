#!/usr/bin/env bash
set -euo pipefail

echo "Cleaning up test bug..."
cd "$(dirname "$0")"

# Remove compiled artifacts
rm -rf circuit_js/
rm -f circuit.r1cs circuit.sym

echo "Test bug cleanup complete."
