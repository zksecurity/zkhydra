import logging
from pathlib import Path
import subprocess, shlex


def execute(bug_path: str):
    # Verify the circuit file exists
    circuit_file = Path(bug_path) / "circuits" / "circuit.circom"
    if circuit_file.is_file():
        logging.debug(f"Found circuit file: {circuit_file}")
    else:
        logging.warning(f"Circuit file not found: {circuit_file}")

    # Run circomspect
    cmd = ["circomspect", str(circuit_file)]
    logging.debug(f"Running: {shlex.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)

    return result.stdout
