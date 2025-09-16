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
            logging.debug(f"Command '${shlex.join(cmd)}' completed successfully.")
            logging.debug(stdout)

    # Change back to the base directory
    os.chdir(BASE_DIR)


def generate_random_text(min_len=8, max_len=25) -> str:
    """Generate a random string of random length."""
    length = random.randint(min_len, max_len)
    characters = string.ascii_letters + string.digits + string.punctuation
    random_text = "".join(random.choice(characters) for _ in range(length))
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


def generate_ground_truth(
    bug_name: str, bug_path: str, dsl: str, output_file: Path
) -> None:
    logging.info(f"Generating ground truth for bug '{bug_name}' into '{output_file}'.")

    readme_file = bug_path / "README.md"
    logging.info(f"Reading README file: '{readme_file}'")

    update_bug_info_json(bug_name, dsl, readme_file, output_file)
    return


# TODO: Clean up sbug_path
def update_bug_info_json(sbug_path, dsl: str, file_path, output_json_path) -> None:
    """Update or add a single bug entry in the JSON file."""
    # Extract data
    bug_data = extract_vulnerability_info_from_file(file_path)
    bug_key = sbug_path

    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_json_path), exist_ok=True)

    # Load existing JSON if it exists
    if os.path.exists(output_json_path):
        with open(output_json_path, "r", encoding="utf-8") as f:
            bug_info = json.load(f)
    else:
        bug_info = {}

    # Ensure the DSL key exists
    if dsl not in bug_info:
        bug_info[dsl] = {}

    # Determine if created or updated
    action = "updated" if bug_key in bug_info[dsl] else "created"
    bug_info[dsl][bug_key] = bug_data

    # Write back to JSON
    with open(output_json_path, "w", encoding="utf-8") as f:
        json.dump(bug_info, f, indent=2)

    logging.error(
        f"Bug entry '{bug_key}' {action} under DSL '{dsl}' in {output_json_path}"
    )


def extract_vulnerability_info_from_file(file_path):
    """Extract vulnerability info from a single Markdown file."""
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Patterns
    vuln_pattern = r"\* Vulnerability:\s*(.*)"
    impact_pattern = r"\* Impact:\s*(.*)"
    root_cause_pattern = r"\* Root Cause:\s*(.*)"
    location_pattern = (
        r"\* Location\s*\n"
        r"\s*- Path:\s*(.*)\n"
        r"\s*- Function:\s*(.*)\n"
        r"\s*- Line:\s*(.*)"
    )

    vulnerability = re.search(vuln_pattern, content)
    impact = re.search(impact_pattern, content)
    root_cause = re.search(root_cause_pattern, content)
    location_match = re.search(location_pattern, content)

    if not (vulnerability and impact and root_cause and location_match):
        raise ValueError(f"Required fields not found in {file_path}")

    return {
        "Vulnerability": vulnerability.group(1).strip(),
        "Impact": impact.group(1).strip(),
        "Root Cause": root_cause.group(1).strip(),
        "Location": {
            "Path": location_match.group(1).strip(),
            "Function": location_match.group(2).strip(),
            "Line": location_match.group(3).strip(),
        },
    }
