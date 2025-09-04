import logging
from pathlib import Path
import os
import subprocess, shlex


ZKFUZZ_DIR = Path(__file__).resolve().parent / "zkFuzz"


def execute(bug_path: str):
    logging.debug(f"ZKFUZZ_DIR='{ZKFUZZ_DIR}'")
    logging.debug(f"bug_path='{bug_path}'")
    
    # Verify the circuit file exists
    circuit_file = Path(bug_path) / "circuits" / "circuit.circom"
    if circuit_file.is_file():
        logging.debug(f"Found circuit file: {circuit_file}")
    else:
        logging.warning(f"Circuit file not found: {circuit_file}")

    # Change to the zkFuzz directory
    os.chdir(ZKFUZZ_DIR)
    logging.debug(f"Changed directory to: {Path.cwd()}")
    # Run zkFuzz
    cmd = ["./target/release/zkfuzz", str(circuit_file)]
    logging.debug(f"Running: {shlex.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)

    output =  result.stderr

    # TODO: Parse report
    zkfuzz_report = output

    # Change back to the original directory
    base_dir = Path.cwd().parent.parent
    logging.debug(f"Changing back to base directory: {base_dir}")
    os.chdir(base_dir)

    return zkfuzz_report
