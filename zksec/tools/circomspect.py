import logging
from pathlib import Path
from .utils import run_command, check_files_exist


def execute(bug_path: str, timeout: int) -> str:
    logging.debug(f"bug_path='{bug_path}'")

    circuit_file = Path(bug_path) / "circuits" / "circuit.circom"
    if not check_files_exist(circuit_file):
        return "[Circuit file not found]"

    cmd = ["circomspect", str(circuit_file)]
    result = run_command(cmd, timeout, tool="circomspect", bug=bug_path)

    return result

def parse_output(file: str) -> str:
    logging.warning("Not implemented.")
