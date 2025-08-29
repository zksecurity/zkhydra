import logging
import sys
import os
import subprocess, shlex
from pathlib import Path


BASE_DIR = Path.cwd()
ZKBUGS_DIR = Path(__file__).resolve().parent / "zkbugs"
SCRIPT_DIR = Path(ZKBUGS_DIR) / "scripts"


def setup(bug_dir: str):
    logging.info(f"Setting up bug environment.")

    # Check if PTAU file exists
    ptau_file = Path(ZKBUGS_DIR) / "misc" / "circom" / "bn128_pot12_0001.ptau"
    if ptau_file.is_file():
        logging.debug(f"Found PTAU file: {ptau_file}")
    else:
        logging.debug(f"PTAU file not found: {ptau_file}")
        # Generate PTAU file
        generate_ptau()

    # Verify the setup script exists
    setup_script = Path(bug_dir) / "zkbugs_setup.sh"
    if setup_script.is_file():
        logging.debug(f"Found setup script: {setup_script}")
    else:
        logging.error(f"Setup script not found: {setup_script}")
        sys.exit(f"Error. Setup script not found for {bug_dir}.")

    # Change to the bug directory
    os.chdir(bug_dir)
    # Run setup script
    cmd = ["./zkbugs_setup.sh"]
    logging.debug(f"Running Command: ${shlex.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    # Log each line separately
    for line in result.stdout.splitlines():
        logging.debug(f"${shlex.join(cmd)}:\t{line}")

    # Change back to the base directory
    os.chdir(BASE_DIR)


def generate_ptau():
    # TODO: Test this function
    logging.debug(f"Generating PTAU file.")
    os.chdir(SCRIPT_DIR)

    # Run setup script
    cmd = ["bash", "./generate_ptau_snarkjs.sh", "bn128", "12"]
    logging.debug(f"Running Command: ${shlex.join(cmd)}")
    subprocess.run(cmd, check=True)

    # Change back to the base directory
    os.chdir(BASE_DIR)


def cleanup(bug_dir: str):
    logging.debug(f"Cleaning up bug environment. bug_dir='{bug_dir}'")
    
    # Verify the cleanup script exists
    cleanup_script = Path(bug_dir) / "zkbugs_clean.sh"
    if cleanup_script.is_file():
        logging.debug(f"Found cleanup script: {cleanup_script}")
    else:
        logging.error(f"Cleanup script not found: {cleanup_script}")
        sys.exit(f"Error. Cleanup script not found for {bug_dir}.")

    # Change to the bug directory
    os.chdir(bug_dir)
    # Run cleanup script
    cmd = ["./zkbugs_clean.sh"]
    logging.debug(f"Running Command: ${shlex.join(cmd)}")
    subprocess.run(cmd, check=True)
    
    # Change back to the base directory
    os.chdir(BASE_DIR)
