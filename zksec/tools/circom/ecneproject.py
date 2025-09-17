import json
import logging
from pathlib import Path

from ..utils import change_directory, check_files_exist, run_command

TOOL_DIR = Path(__file__).resolve().parent / "ecneproject"


def execute(bug_path: str, timeout: int) -> str:
    logging.debug(f"ECNEPROJECT_DIR='{TOOL_DIR}'")
    logging.debug(f"bug_path='{bug_path}'")

    circuit_file = Path(bug_path) / "circuits" / "circuit.circom"
    r1cs_file = Path(bug_path) / "circuit.r1cs"
    sym_file = Path(bug_path) / "circuit.sym"
    if not check_files_exist(circuit_file, r1cs_file, sym_file):
        return "[Circuit file not found]"

    change_directory(TOOL_DIR)

    cmd = [
        "julia",
        "--project=.",
        "src/Ecne.jl",
        "--r1cs",
        str(r1cs_file),
        "--name",
        "circuit",
        "--sym",
        str(sym_file),
    ]
    result = run_command(cmd, timeout, tool="ecneproject", bug=bug_path)

    return result


def parse_output(
    tool_result_raw: Path, tool: str, bug_name: str, dsl: str, _: Path
) -> None:
    with open(tool_result_raw, "r", encoding="utf-8") as f:
        bug_info = json.load(f).get(dsl, {}).get(tool, {}).get(bug_name, [])

    result = ""
    for i, line in enumerate(bug_info):
        if line == "[Timed out]":
            result = "Timed out"
            break
        # TODO: Verify: when setup script doesn't work, r1cs and sym files are not created
        if line == "[Circuit file not found]":
            result = "Circuit file not found"
            break
        if line == "stderr:":
            info = bug_info[i - 2]
            result = info
            break

    structured_info = {}
    if dsl not in structured_info:
        structured_info[dsl] = {}
    if tool not in structured_info[dsl]:
        structured_info[dsl][tool] = {}

    structured_info[dsl][tool][bug_name] = {
        "result": result,
    }

    return structured_info


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
