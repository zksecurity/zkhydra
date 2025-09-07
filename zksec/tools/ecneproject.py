import logging
from pathlib import Path
import os
import subprocess, shlex


ECNEPROJECT_DIR = Path(__file__).resolve().parent / "EcneProject"


def execute(bug_path: str):
    logging.debug(f"ECNEPROJECT_DIR='{ECNEPROJECT_DIR}'")
    logging.debug(f"bug_path='{bug_path}'")
    
    circuit_file = Path(bug_path) / "circuits" / "circuit.circom"
    r1cs_file    = Path(bug_path) / "circuit.r1cs"
    sym_file     = Path(bug_path) / "circuit.sym"

    # Verify files exist
    for name, path in [("circuit_file", circuit_file),
                    ("r1cs_file", r1cs_file),
                    ("sym_file", sym_file)]:
        if path.is_file():
            logging.debug(f"Found {name}: {path}")
        else:
            logging.warning(f"{name} not found: {path}")

    # Change to the EcneProject directory
    os.chdir(ECNEPROJECT_DIR)
    logging.debug(f"Changed directory to: {Path.cwd()}")
    
    # Run EcneProject
    cmd = ["julia", "--project=.", "src/Ecne.jl", "--r1cs", str(r1cs_file), "--name", "circuit", "--sym", str(sym_file)]
    logging.debug(f"Running: {shlex.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    last_line = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""

    # Change back to the original directory
    base_dir = Path.cwd().parent.parent
    logging.debug(f"Changing back to base directory: {base_dir}")
    os.chdir(base_dir)

    # TODO: See what to return
    return last_line
