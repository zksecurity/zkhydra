import logging
from pathlib import Path
from ..utils import run_command, change_directory, check_files_exist


TOOL_DIR = Path(__file__).resolve().parent / "circom_civer"


def execute(bug_path: str, timeout: int) -> str:
    logging.debug(f"CIRCOM_CIVER_DIR='{TOOL_DIR}'")
    logging.debug(f"bug_path='{bug_path}'")
    
    # Verify the circuit file exists
    circuit_file = Path(bug_path) / "circuits" / "circuit.circom"
    if not check_files_exist(circuit_file):
        return "[Circuit file not found]"

    change_directory(TOOL_DIR)
    
    cmd = ["./target/release/civer_circom", str(circuit_file), "--check_safety"]
    result = run_command(cmd, timeout, tool="circom_civer", bug=bug_path)

    change_directory(TOOL_DIR.parent.parent.parent)

    return result


def parse_output(file: str) -> str:
    logging.warning("Not implemented.")