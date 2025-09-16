import logging
from pathlib import Path

from ..utils import change_directory, check_files_exist, run_command

TOOL_DIR = Path(__file__).resolve().parent / "zkfuzz"


def execute(bug_path: str, timeout: int) -> str:
    logging.debug(f"ZKFUZZ_DIR='{TOOL_DIR}'")
    logging.debug(f"bug_path='{bug_path}'")

    circuit_file = Path(bug_path) / "circuits" / "circuit.circom"
    if not check_files_exist(circuit_file):
        return "[Circuit file not found]"

    change_directory(TOOL_DIR)

    cmd = ["./target/release/zkfuzz", str(circuit_file)]
    result = run_command(cmd, timeout, tool="zkfuzz", bug=bug_path)

    return result


def parse_output(tool_result_raw: Path, output_file: Path) -> None:
    logging.warning("Not implemented.")
    return


def compare_zkbugs_ground_truth(
    tool: str,
    dsl: str,
    bug_name: str,
    ground_truth: Path,
    tool_result_parsed: Path,
    output_file: Path,
) -> None:
    logging.warning("Not implemented.")
    return
