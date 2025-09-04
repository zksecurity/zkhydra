import logging
import sys
import os
import random
import string
import subprocess, shlex
from pathlib import Path


BASE_DIR = Path.cwd()
ZKBUGS_DIR = Path(__file__).resolve().parent / "zkbugs"
SCRIPT_DIR = Path(ZKBUGS_DIR) / "scripts"


def setup(bug_dir: str):
    logging.info(f"Setting up bug environment for '{bug_dir}'.")

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
    cmd = ["./zkbugs_compile_setup.sh"]
    random_text = generate_random_text()
    logging.info(f"Running Command: '${shlex.join(cmd)}', with random text (entropy): '{random_text}'")

    # Run the command and provide random text as input
    with subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as proc:
        stdout, stderr = proc.communicate(input=random_text + "\n")

        if proc.returncode != 0:
            logging.error(f"Command '${shlex.join(cmd)}' failed with return code {proc.returncode}")
            logging.error(stderr)
        else:
            logging.debug(f"Command '${shlex.join(cmd)}' completed successfully.")
            logging.debug(stdout)

    # Change back to the base directory
    os.chdir(BASE_DIR)


def generate_random_text(min_len=8, max_len=25) -> str:
    """Generate a random string of random length."""
    length = random.randint(min_len, max_len)
    characters = string.ascii_letters + string.digits + string.punctuation
    random_text = ''.join(random.choice(characters) for _ in range(length))
    return random_text


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
