import json
import logging
import os
from pathlib import Path

from ..utils import change_directory, check_files_exist, run_command

TOOL_DIR = Path(__file__).resolve().parent / "picus"


def execute(bug_path: str, timeout: int) -> str:
    logging.debug(f"PICUS_DIR='{TOOL_DIR}'")
    logging.debug(f"bug_path='{bug_path}'")

    circuit_file = Path(bug_path) / "circuits" / "circuit.circom"
    if not check_files_exist(circuit_file):
        return "[Circuit file not found]"

    change_directory(TOOL_DIR)

    cmd = ["./run-picus", str(circuit_file)]
    result = run_command(cmd, timeout, tool="picus", bug=bug_path)

    return result


def parse_output(
    tool_result_raw: Path, tool: str, bug_name: str, dsl: str, _: Path
) -> None:
    with open(tool_result_raw, "r", encoding="utf-8") as f:
        bug_info = json.load(f).get(dsl, {}).get(tool, {}).get(bug_name, [])

    status = ""

    if bug_info[0] == "[Timed out]":
        status = "Timed out"
    elif len(bug_info) > 1 and bug_info[1] == "The circuit is underconstrained":
        status = "Underconstrained"
    elif len(bug_info) > 1 and bug_info[1] == "The circuit is properly constrained":
        status = "Properly Constrained"
    elif (
        len(bug_info) > 2
        and bug_info[2]
        == "Cannot determine whether the circuit is properly constrained"
    ):
        status = "Unknown"
    else:
        status = "Tool Error"

    structured_info = {}
    if dsl not in structured_info:
        structured_info[dsl] = {}
    if tool not in structured_info[dsl]:
        structured_info[dsl][tool] = {}

    structured_info[dsl][tool][bug_name] = {
        "result": status,
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
    logging.debug(
        "When picus finds a bug, we assume it found the correct one. We can check if the bug is supposed to be underconstrained."
    )

    # Load existing output or initialize
    if os.path.exists(output_file):
        with open(output_file, "r", encoding="utf-8") as f:
            output = json.load(f)
    else:
        output = {dsl: {}}

    # Ensure tool entry exists
    output.setdefault(dsl, {}).setdefault(tool, {}).setdefault("correct", [])
    output.setdefault(dsl, {}).setdefault(tool, {}).setdefault("false", [])
    output.setdefault(dsl, {}).setdefault(tool, {}).setdefault("error", [])
    output.setdefault(dsl, {}).setdefault(tool, {}).setdefault("timeout", [])

    with open(ground_truth, "r", encoding="utf-8") as f:
        gt_data = json.load(f).get(dsl, {}).get(bug_name, {})

    with open(tool_result_parsed, "r", encoding="utf-8") as f:
        tool_output_data = (
            json.load(f)
            .get(dsl, {})
            .get(tool, {})
            .get(bug_name, {})
            .get("result", "No result")
        )

    is_correct = False
    reason = ""

    if (
        tool_output_data == "Underconstrained"
        and gt_data.get("Vulnerability") == "Under-Constrained"
    ):
        is_correct = True
    elif tool_output_data == "Timed out":
        reason = "Reached zksec threshold."
    elif tool_output_data == "Unknown":
        reason = "Unknown result"
    elif tool_output_data == "Tool Error":
        reason = "Picus Tool Error"
    elif tool_output_data == "Properly Constrained":
        reason = "Tool says circuit is properly constrained."

    if is_correct:
        if bug_name not in output[dsl][tool]["correct"]:
            output[dsl][tool]["correct"].append(bug_name)
    elif reason == "Reached zksec threshold.":
        if bug_name not in output[dsl][tool]["timeout"]:
            output[dsl][tool]["timeout"].append({"bug": bug_name, "reason": reason})
    elif reason == "Picus Tool Error":
        if bug_name not in output[dsl][tool]["error"]:
            output[dsl][tool]["error"].append({"bug": bug_name, "reason": reason})
    elif reason == "Tool says circuit is properly constrained.":
        if bug_name not in output[dsl][tool]["false"]:
            output[dsl][tool]["false"].append({"bug": bug_name, "reason": reason})
    else:
        if bug_name not in output[dsl][tool]["false"]:
            output[dsl][tool]["false"].append({"bug": bug_name, "reason": reason})

    # Update counts dynamically
    output[dsl][tool]["count"] = {
        "correct": len(output[dsl][tool]["correct"]),
        "false": len(output[dsl][tool]["false"]),
        "error": len(output[dsl][tool]["error"]),
        "timeout": len(output[dsl][tool]["timeout"]),
    }

    return output
