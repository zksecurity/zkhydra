import logging
from pathlib import Path
import os
import subprocess, shlex


PICUS_DIR = Path(__file__).resolve().parent / "Picus"


def execute(bug_path: str):
    logging.debug(f"PICUS_DIR='{PICUS_DIR}'")
    logging.debug(f"bug_path='{bug_path}'")
    
    # Verify the circuit file exists
    circuit_file = Path(bug_path) / "circuits" / "circuit.circom"
    if circuit_file.is_file():
        logging.info(f"Found circuit file: {circuit_file}")
    else:
        logging.warning(f"Circuit file not found: {circuit_file}")

    # Change to the Picus directory
    os.chdir(PICUS_DIR)
    logging.debug(f"Changed directory to: {Path.cwd()}")
    # Run Picus
    cmd = ["./run-picus", str(circuit_file)]
    logging.debug(f"Running: {shlex.join(cmd)}")
    subprocess.run(cmd, check=True)
    
    # Change back to the original directory
    base_dir = Path.cwd().parent.parent
    logging.debug(f"Changing back to base directory: {base_dir}")
    os.chdir(base_dir)
