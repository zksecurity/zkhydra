import logging
from pathlib import Path
import os
from .utils import run_command, change_directory, check_files_exist


TOOL_DIR = Path(__file__).resolve().parent / "Picus"


def execute(bug_path: str, timeout: int) -> str:
    logging.debug(f"PICUS_DIR='{TOOL_DIR}'")
    logging.debug(f"bug_path='{bug_path}'")
    
    circuit_file = Path(bug_path) / "circuits" / "circuit.circom"
    if not check_files_exist(circuit_file):
        return "[Circuit file not found]"

    change_directory(TOOL_DIR)
    
    cmd = ["./run-picus", str(circuit_file)]
    result = run_command(cmd, timeout, tool="picus", bug=bug_path)

    change_directory(TOOL_DIR.parent.parent.parent)

    return result

def parse_output(file: str) -> str:
    logging.warning("Not implemented.")
