import logging
from pathlib import Path
import os
import subprocess, shlex


GARDEN_DIR = Path(__file__).resolve().parent / "garden"


def execute(bug_path: str):
    logging.debug(f"GARDEN_DIR='{GARDEN_DIR}'")
    logging.debug(f"bug_path='{bug_path}'")
    
    # Verify the circuit file exists
    circuit_file = Path(bug_path) / "circuits" / "circuit.circom"
    if circuit_file.is_file():
        logging.info(f"Found circuit file: {circuit_file}")
    else:
        logging.warning(f"Circuit file not found: {circuit_file}")

    # Change to the garden directory
    # os.chdir(GARDEN_DIR)
    # logging.debug(f"Changed directory to: {Path.cwd()}")
    # # Run garden
    # cmd = ["./run-garden", str(circuit_file)]
    # logging.debug(f"Running: {shlex.join(cmd)}")
    # result = subprocess.run(cmd, capture_output=True, text=True, check=True)

    # Change back to the original directory
    base_dir = Path.cwd().parent.parent
    logging.debug(f"Changing back to base directory: {base_dir}")
    os.chdir(base_dir)

    return result.stdout
