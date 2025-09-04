import logging
from pathlib import Path
import os
import subprocess, shlex


CIRCOM_CIVER_DIR = Path(__file__).resolve().parent / "circom_civer"


def execute(bug_path: str):
    logging.debug(f"CIRCOM_CIVER_DIR='{CIRCOM_CIVER_DIR}'")
    logging.debug(f"bug_path='{bug_path}'")
    
    # Verify the circuit file exists
    circuit_file = Path(bug_path) / "circuits" / "circuit.circom"
    if circuit_file.is_file():
        logging.debug(f"Found circuit file: {circuit_file}")
    else:
        logging.warning(f"Circuit file not found: {circuit_file}")

    # Change to the Circom Civer directory
    os.chdir(CIRCOM_CIVER_DIR)
    logging.debug(f"Changed directory to: {Path.cwd()}")
    # Run Circom Civer
    # cmd = ["./run-circom-civer", str(circuit_file)]
    # logging.debug(f"Running: {shlex.join(cmd)}")
    # result = subprocess.run(cmd, capture_output=False, text=True, check=True)
    result = 'not implemented'

    # Change back to the original directory
    base_dir = Path.cwd().parent.parent
    logging.debug(f"Changing back to base directory: {base_dir}")
    os.chdir(base_dir)

    return result.stdout
