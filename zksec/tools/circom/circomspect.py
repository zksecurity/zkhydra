import logging
from pathlib import Path

from ..utils import check_files_exist, run_command


def execute(bug_path: str, timeout: int):
    logging.debug(f"bug_path='{bug_path}'")

    circuit_file = Path(bug_path) / "circuits" / "circuit.circom"
    if not check_files_exist(circuit_file):
        return "[Circuit file not found]"

    cmd = ["circomspect", str(circuit_file), "-l", "INFO", "-v"]
    result = run_command(cmd, timeout, tool="circomspect", bug=bug_path)

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
