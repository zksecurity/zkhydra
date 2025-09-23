import json
import logging
import os
from pathlib import Path
from typing import Any, Dict

from ..utils import (
    change_directory,
    check_files_exist,
    get_tool_result_parsed,
    run_command,
)

TOOL_DIR = Path(__file__).resolve().parent / "picus"


def execute(bug_path: str, timeout: int) -> str:
    """Run Picus on the given circuit.

    Args:
        bug_path: Absolute path to the bug directory containing `circuits/circuit.circom`.
        timeout: Maximum execution time in seconds.

    Returns:
        Raw tool output, or a bracketed error marker string.
    """
    logging.debug(f"PICUS_DIR='{TOOL_DIR}'")
    logging.debug(f"bug_path='{bug_path}'")

    circuit_file = Path(bug_path) / "circuits" / "circuit.circom"
    if not check_files_exist(circuit_file):
        return "[Circuit file not found]"

    run_script = TOOL_DIR / "run-picus"
    if not run_script.is_file():
        logging.error(f"run-picus not found at {run_script}")
        return "[Binary not found: run-picus missing]"
    if not os.access(run_script, os.X_OK):
        logging.error(f"run-picus is not executable: {run_script}")
        return "[Binary not executable: fix permissions for run-picus]"

    change_directory(TOOL_DIR)

    cmd = [str(run_script), str(circuit_file)]
    result = run_command(cmd, timeout, tool="picus", bug=bug_path)

    return result


def parse_output(
    tool_result_raw: Path, _: Path
) -> Dict[str, Dict[str, Dict[str, Dict[str, Any]]]]:
    """Parse Picus output and classify the result."""
    with open(tool_result_raw, "r", encoding="utf-8") as f:
        bug_info: list[str] = [line.strip() for line in f if line.strip()]

    status: str
    if not bug_info:
        status = "No result"
    elif any(line == "[Timed out]" for line in bug_info):
        status = "Timed out"
    elif any(line == "[Circuit file not found]" for line in bug_info):
        status = "Circuit file not found"
    elif any(line == "The circuit is underconstrained" for line in bug_info):
        status = "Underconstrained"
    elif any(line == "The circuit is properly constrained" for line in bug_info):
        status = "Properly Constrained"
    elif any(
        line == "Cannot determine whether the circuit is properly constrained"
        for line in bug_info
    ):
        status = "Unknown"
    else:
        status = "Tool Error"

    structured_info: Dict[str, Any] = {}

    structured_info = {
        "result": status,
    }

    return structured_info


def compare_zkbugs_ground_truth(
    tool: str, dsl: str, bug_name: str, ground_truth: Path, tool_result_parsed: Path
) -> Dict[str, Any]:
    """Compare Picus classification to ground truth and update aggregate output."""
    logging.debug(
        "When picus finds a bug, we assume it found the correct one. We can check if the bug is supposed to be underconstrained."
    )
    output = {}

    with open(ground_truth, "r", encoding="utf-8") as f:
        gt_data = json.load(f).get(dsl, {}).get(bug_name, {})

    tool_result: str = get_tool_result_parsed(
        tool_result_parsed, dsl, tool, bug_name
    ).get("result", "No result")

    is_correct = False
    reason = ""

    if (
        tool_result == "Underconstrained"
        and gt_data.get("Vulnerability") == "Under-Constrained"
    ):
        is_correct = True
    elif tool_result == "Timed out":
        reason = "Reached zksec threshold."
    elif tool_result == "Unknown":
        reason = "Unknown result"
    elif tool_result == "Tool Error":
        reason = "Picus Tool Error"
    elif tool_result == "Properly Constrained":
        reason = "Tool says circuit is properly constrained."
    elif tool_result == "Circuit file not found":
        reason = "Circuit file not found"
    elif tool_result == "No result":
        reason = "No result"

    if is_correct:
        output = {"result": "correct"}
    elif reason == "Reached zksec threshold.":
        output = {"result": "timeout", "reason": reason}
    elif reason == "Picus Tool Error":
        output = {"result": "error", "reason": reason}
    elif reason == "Circuit file not found":
        output = {"result": "error", "reason": reason}
    else:
        output = {"result": "false", "reason": reason}

    return output
