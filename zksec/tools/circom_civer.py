import logging
from pathlib import Path
import os
import re
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
    cmd = ["./target/release/civer_circom", str(circuit_file), "--check_safety"]
    logging.debug(f"Running: {shlex.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    last_line = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""

    # Remove ANSI escape sequences from last line only
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    last_line_clean = ansi_escape.sub('', last_line)

    # Change back to the original directory
    base_dir = Path.cwd().parent.parent
    logging.debug(f"Changing back to base directory: {base_dir}")
    os.chdir(base_dir)

    # TODO: See what to return
    return last_line_clean
