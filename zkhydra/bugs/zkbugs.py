import json
import logging
import os
import random
import re
import shlex
import string
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path.cwd()
ZKBUGS_DIR = Path(__file__).resolve().parent / "zkbugs"
SCRIPT_DIR = Path(ZKBUGS_DIR) / "scripts"


def setup_circom(bug_dir: str):
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
    logging.info(
        f"Running Command: '${shlex.join(cmd)}', with random text (entropy): '{random_text}'"
    )

    # Run the command and provide random text as input
    with subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ) as proc:
        stdout, stderr = proc.communicate(input=random_text + "\n")

        if proc.returncode != 0:
            logging.error(
                f"Command '${shlex.join(cmd)}' failed with return code {proc.returncode}"
            )
            logging.error(stderr)
        else:
            logging.debug(
                f"Command '${shlex.join(cmd)}' completed successfully."
            )
            logging.debug(stdout)

    # Change back to the base directory
    os.chdir(BASE_DIR)


def setup_pil_cairo(bug_dir: str):
    logging.info(f"Setting up bug environment for '{bug_dir}'.")
    repo_url, commit_hash = get_repo_url_and_commit_hash(bug_dir)
    logging.debug(f"Repo URL: {repo_url}, Commit Hash: {commit_hash}")
    commit_hash = commit_hash.replace("0x", "")
    repo_path = bug_dir / "repo"
    clone_repo_and_checkout_commit(repo_url, commit_hash, repo_path)


def get_repo_url_and_commit_hash(bug_path: Path) -> tuple[str, str]:
    """Get the repository URL and commit hash from a bug path."""
    logging.info(
        f"Getting repository URL and commit hash for bug '{bug_path}'."
    )

    bug_config = bug_path / "zkbugs_config.json"

    with open(bug_config, "r", encoding="utf-8") as f:
        config = json.load(f)

    value = next(iter(config.values()))
    repo_url = value.get("Project")
    commit_hash = value.get("Commit")
    logging.debug(
        f"Got repository URL and commit hash for bug '{bug_path}': {repo_url}, {commit_hash}"
    )
    return repo_url, commit_hash


def clone_repo_and_checkout_commit(
    repo_url: str, commit_hash: str, repo_path: Path
) -> tuple[str, str]:
    """Clone a repository and checkout a commit."""
    clone_repo(repo_url, repo_path)
    checkout_commit(commit_hash, repo_path)


def clone_repo(repo_url: str, repo_path: Path) -> None:
    """Clone a repository."""
    logging.info(f"Cloning repository: {repo_url}")
    subprocess.run(["git", "clone", repo_url, repo_path])
    logging.info(f"Cloned repository: {repo_url}")


def checkout_commit(commit_hash: str, repo_path: Path) -> None:
    """Checkout a commit."""
    logging.info(f"Checking out commit: {commit_hash}")
    subprocess.run(["git", "checkout", commit_hash], cwd=repo_path)
    logging.info(f"Checked out commit: {commit_hash}")


def setup(dsl: str, bug_dir: str):
    if dsl == "circom":
        setup_circom(bug_dir)
    elif dsl == "pil" or dsl == "cairo":
        setup_pil_cairo(bug_dir)


def generate_random_text(min_len=8, max_len=25) -> str:
    """Generate a random string of random length."""
    length = random.randint(min_len, max_len)
    characters = string.ascii_letters + string.digits + string.punctuation
    random_text = "".join(random.choice(characters) for _ in range(length))
    return random_text


def generate_ptau():
    logging.debug(f"Generating PTAU file.")
    os.chdir(SCRIPT_DIR)

    # Run setup script
    cmd = ["bash", "./generate_ptau_snarkjs.sh", "bn128", "12"]
    logging.debug(f"Running Command: ${shlex.join(cmd)}")
    subprocess.run(cmd, check=True)

    # Change back to the base directory
    os.chdir(BASE_DIR)


def cleanup(dsl: str, bug_dir: str):
    if dsl == "circom":
        cleanup_circom(bug_dir)
    elif dsl == "pil" or dsl == "cairo":
        cleanup_pil_cairo(bug_dir)


def cleanup_circom(bug_dir: str):
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


def cleanup_pil_cairo(bug_dir: str):
    logging.debug(f"Cleaning up bug environment. bug_dir='{bug_dir}'")
    # Remove the repo directory
    repo_path = bug_dir / "repo"
    if repo_path.exists():
        logging.debug(f"Removing repo directory: {repo_path}")
        subprocess.run(["rm", "-rf", repo_path], check=True)
    else:
        logging.error(f"Repo directory not found: {repo_path}")
    # Change back to the base directory
    os.chdir(BASE_DIR)


def generate_ground_truth(
    bug_name: str, bug_path: str, dsl: str, output_file: Path
) -> None:
    logging.info(
        f"Generating ground truth for bug '{bug_name}' into '{output_file}'."
    )

    bug_config = bug_path / "zkbugs_config.json"

    with open(bug_config, "r", encoding="utf-8") as f:
        config = json.load(f)

    value = next(iter(config.values()))
    vulnerability = value.get("Vulnerability")
    impact = value.get("Impact")
    root_cause = value.get("Root Cause")
    location = value.get("Location")

    bug_data = {
        "Vulnerability": vulnerability,
        "Impact": impact,
        "Root Cause": root_cause,
        "Location": location,
    }

    output_file.parent.mkdir(parents=True, exist_ok=True)
    # Write back to JSON
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(bug_data, f, indent=2)

    logging.debug(
        f"Written ground truth for bug '{bug_name}' under DSL '{dsl}' in {output_file}"
    )
    return
