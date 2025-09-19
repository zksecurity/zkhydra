import json
import logging
import os
import re
from pathlib import Path

from ..utils import (
    change_directory,
    check_files_exist,
    get_tool_result_parsed,
    load_output_dict,
    run_command,
    update_result_counts,
)

TOOL_DIR = Path(__file__).resolve().parent / "circom_civer"


def execute(bug_path: str, timeout: int) -> str:
    logging.debug(f"CIRCOM_CIVER_DIR='{TOOL_DIR}'")
    logging.debug(f"bug_path='{bug_path}'")

    # Verify the circuit file exists
    circuit_file = Path(bug_path) / "circuits" / "circuit.circom"
    if not check_files_exist(circuit_file):
        return "[Circuit file not found]"

    change_directory(TOOL_DIR)

    cmd = [
        "./target/release/civer_circom",
        str(circuit_file),
        "--check_safety",
        "--verbose",
        "--O0",
    ]
    result = run_command(cmd, timeout, tool="circom_civer", bug=bug_path)

    return result


def parse_output(
    tool_result_raw: Path, tool: str, bug_name: str, dsl: str, _: Path
) -> None:
    with open(tool_result_raw, "r", encoding="utf-8") as f:
        bug_info = json.load(f).get(dsl, {}).get(tool, {}).get(bug_name, [])
    structured_info = {}

    stats = {"verified": None, "failed": None, "timeout": None}
    buggy_components = []

    context = None  # track section

    for line in bug_info:
        if line == "[Timed out]":
            context = "Reached zksec threshold."
            buggy_components = ["Reached zksec threshold."]
            continue
        # --- Track context (which section we are in) ---
        if line.startswith("Components that do not satisfy weak safety"):
            context = "buggy"
            continue
        elif line.startswith("Components timeout when checking weak-safety"):
            context = "timeout"
            continue
        # TODO: verify string
        elif line.startswith("Components that failed verification"):
            context = "failed"
            continue
        elif line == "":
            context = None  # reset only on empty line

        # --- Match component lines only if inside "buggy" context ---
        if context == "buggy" and line.strip().startswith("-"):

            comp_match = re.match(r"-\s*([A-Za-z0-9_]+)\(([\d,\s]*)\)", line.strip())
            if comp_match:
                comp_name, numbers = comp_match.groups()
                nums = [int(n.strip()) for n in numbers.split(",") if n.strip()]
                buggy_components.append({"name": comp_name, "params": nums})

        # --- Stats parsing ---
        if "Number of verified components" in line:
            stats["verified"] = int(re.search(r"(\d+)$", line).group(1))
        elif "Number of failed components" in line:
            stats["failed"] = int(re.search(r"(\d+)$", line).group(1))
        elif "Number of timeout components" in line:
            stats["timeout"] = int(re.search(r"(\d+)$", line).group(1))

    if dsl not in structured_info:
        structured_info[dsl] = {}
    if tool not in structured_info[dsl]:
        structured_info[dsl][tool] = {}

    structured_info[dsl][tool][bug_name] = {
        "stats": stats,
        "buggy_components": buggy_components,
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
    output = load_output_dict(output_file, dsl, tool)

    # Get ground truth data
    with open(ground_truth, "r", encoding="utf-8") as f:
        ground_truth_data = json.load(f).get(dsl, {}).get(bug_name, {})

    bug_location = ground_truth_data.get("Location", {})
    if not bug_location:
        logging.error(f"Location data for bug '{bug_name}' not found in ground truth.")
        return

    buggy_function = bug_location.get("Function")
    buggy_line = bug_location.get("Line")
    if "-" in buggy_line:
        startline, endline = map(int, buggy_line.split("-", 1))
    elif not buggy_line:
        startline = endline = 0
        logging.warning(f"Line data for bug '{bug_name}' not found in ground truth.")
    else:
        startline = endline = int(buggy_line)
    logging.debug(
        f"Buggy function: {buggy_function}, startline: {startline}, endline: {endline}"
    )

    tool_output_data = get_tool_result_parsed(tool_result_parsed, dsl, tool, bug_name)

    buggy_components = tool_output_data.get("buggy_components", [])

    is_correct = False
    reason = ""
    for component in buggy_components:
        if component == "Reached zksec threshold.":
            reason = "Reached zksec threshold."
            break
        comp_name = component.get("name")
        comp_params = component.get("params", [])
        logging.debug(
            f"Found buggy component in '{bug_name}': {comp_name} with params {comp_params}"
        )

        params = component.get("params", [])
        if not params:
            startline_tool = endline_tool = 0
        elif len(params) == 1:
            startline_tool = endline_tool = params[0]
        elif len(params) == 2:
            startline_tool = params[0]
            endline_tool = params[1]
        else:
            raise ValueError("params should have at most 2 values")
        logging.debug(
            f"Component lines: startline={startline_tool}, endline={endline_tool}"
        )

        # Compare with ground truth
        if comp_name == buggy_function:
            logging.debug(f"Component name matches buggy function: {comp_name}")

            # Check lines
            if startline_tool == endline_tool == 0:
                logging.debug(f"Component lines not provided by tool")
                is_correct = True
            if startline_tool <= startline and endline_tool >= endline:
                logging.debug(
                    f"Component lines match ground truth: startline={startline_tool}, endline={endline_tool}"
                )
                is_correct = True
            else:
                logging.debug(
                    f"Component lines do not match ground truth: startline={startline_tool}, endline={endline_tool}"
                )

        logging.debug(f"Component '{comp_name}' correctness: {is_correct}")

    if is_correct:
        if bug_name not in output[dsl][tool]["correct"]:
            output[dsl][tool]["correct"].append(bug_name)
    else:
        if reason == "Reached zksec threshold.":
            if bug_name not in output[dsl][tool]["timeout"]:
                output[dsl][tool]["timeout"].append({"bug": bug_name, "reason": reason})
            return output
        if not buggy_components:
            reason = "tool found no module"
        elif comp_name != buggy_function:
            reason = f"tool found wrong module (tool found: '{comp_name}'; buggy module: '{buggy_function}')"
        else:
            reason = f"tool found correct module, but lines didn't match (tool found lines: '{startline_tool}-{endline_tool}'; buggy lines: '{startline}-{endline}')"

        # Append dictionary with reason if not already recorded
        existing_false = output[dsl][tool]["false"]
        if not any(entry["bug_name"] == bug_name for entry in existing_false):
            output[dsl][tool]["false"].append({"bug_name": bug_name, "reason": reason})

    output = update_result_counts(output, dsl, tool)

    return output
