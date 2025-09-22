import json
import logging
import os
import shutil
from pathlib import Path
from typing import Any, Dict

from ..utils import (
    change_directory,
    check_files_exist,
    get_tool_result_parsed,
    load_output_dict,
    remove_bug_entry,
    run_command,
    update_result_counts,
)

TOOL_DIR = Path(__file__).resolve().parent / "ecneproject"


def execute(bug_path: str, timeout: int) -> str:
    """Run EcneProject (Julia) against the bug's R1CS and sym files.

    Args:
        bug_path: Absolute path to the bug directory containing artifacts.
        timeout: Maximum execution time in seconds.

    Returns:
        Raw tool output, or a bracketed error marker string.
    """
    logging.debug(f"ECNEPROJECT_DIR='{TOOL_DIR}'")
    logging.debug(f"bug_path='{bug_path}'")

    circuit_file = Path(bug_path) / "circuits" / "circuit.circom"
    r1cs_file = Path(bug_path) / "circuit.r1cs"
    sym_file = Path(bug_path) / "circuit.sym"
    if not check_files_exist(circuit_file, r1cs_file, sym_file):
        return "[Circuit file not found]"

    if shutil.which("julia") is None:
        logging.error("'julia' binary not found in PATH")
        return "[Binary not found: install Julia]"

    # Ensure project and entrypoint exist
    ecne_entry = TOOL_DIR / "src" / "Ecne.jl"
    if not ecne_entry.is_file():
        logging.error(f"Ecne.jl not found at {ecne_entry}")
        return "[Binary not found: Ecne.jl entrypoint missing]"

    change_directory(TOOL_DIR)

    cmd = [
        "julia",
        f"--project={TOOL_DIR}",
        str(ecne_entry),
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
) -> Dict[str, Dict[str, Dict[str, Dict[str, Any]]]]:
    """Parse EcneProject output into a small structured summary.

    Returns nested structure: { dsl: { tool: { bug_name: { "result": str } } } }
    Possible results:
      - "Timed out"
      - "Circuit file not found"
      - "R1CS function circuit has potentially unsound constraints"
      - "No result"
      - Or a best-effort fallback line extracted from near 'stderr:'
    """
    with open(tool_result_raw, "r", encoding="utf-8") as f:
        bug_info = json.load(f).get(dsl, {}).get(tool, {}).get(bug_name, [])

    # Default to an explicit value so downstream comparison can categorize it
    result = "No result"

    # Fast checks for common sentinel lines
    for line in bug_info:
        if line == "[Timed out]":
            result = "Timed out"
            break
        # When setup script doesn't work, r1cs and sym files are not created
        if line == "[Circuit file not found]":
            result = "Circuit file not found"
            break

    # If still undecided, try to detect the EcneProject success message anywhere
    if result == "No result":
        for line in bug_info:
            if "R1CS function" in line and "potentially unsound constraints" in line:
                result = "R1CS function circuit has potentially unsound constraints"
                break

    # Legacy heuristic: sometimes the interesting line appears two lines before 'stderr:'
    if result == "No result":
        for i, line in enumerate(bug_info):
            if line == "stderr:" and i >= 2:
                result = bug_info[i - 2]
                break

    structured_info: Dict[str, Dict[str, Dict[str, Dict[str, Any]]]] = {}
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
) -> Dict[str, Any]:
    """Compare EcneProject result to expectations and update aggregate output.

    EcneProject is heuristic; we treat its positive message as a correct detection
    and handle timeouts/missing files explicitly. Otherwise it's a false/unknown.
    """
    output = load_output_dict(output_file, dsl, tool)
    output = remove_bug_entry(output, dsl, tool, bug_name)

    tool_result: str = get_tool_result_parsed(
        tool_result_parsed, dsl, tool, bug_name
    ).get("result", "No result")

    if tool_result == "R1CS function circuit has potentially unsound constraints":
        output[dsl][tool]["correct"].append(bug_name)
    elif tool_result == "Timed out":
        output[dsl][tool]["timeout"].append(
            {"bug": bug_name, "reason": "Reached zksec threshold."}
        )
    elif tool_result == "Circuit file not found":
        output[dsl][tool]["error"].append(
            {
                "bug": bug_name,
                "reason": "Circuit file not found. Might be missing in bug environment setup script.",
            }
        )
    else:
        output[dsl][tool]["false"].append(
            {
                "bug_name": bug_name,
                "reason": "Missing or inconclusive result from parsing.",
            }
        )

    output = update_result_counts(output, dsl, tool)

    return output
