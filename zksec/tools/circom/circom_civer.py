import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..utils import (
    change_directory,
    check_files_exist,
    get_tool_result_parsed,
    load_output_dict,
    remove_bug_entry,
    run_command,
    update_result_counts,
)

TOOL_DIR = Path(__file__).resolve().parent / "circom_civer"


def execute(bug_path: str, timeout: int) -> str:
    """Run circom-civer on a given bug's circuit.

    Args:
        bug_path: Absolute path to the bug directory containing `circuits/circuit.circom`.
        timeout: Maximum execution time in seconds.

    Returns:
        The raw string output from the tool, or a bracketed error marker string.
    """
    logging.debug(f"CIRCOM_CIVER_DIR='{TOOL_DIR}'")
    logging.debug(f"bug_path='{bug_path}'")

    # Verify the circuit file exists
    circuit_file = Path(bug_path) / "circuits" / "circuit.circom"
    if not check_files_exist(circuit_file):
        return "[Circuit file not found]"

    # Ensure the binary exists before attempting to run
    binary_path = TOOL_DIR / "target" / "release" / "civer_circom"
    if not binary_path.is_file():
        logging.error(f"circom-civer binary not found at {binary_path}")
        return "[Binary not found: build circom_civer first]"

    change_directory(TOOL_DIR)

    cmd = [
        str(binary_path),
        str(circuit_file),
        "--check_safety",
        "--verbose",
        "--O0",
    ]
    result = run_command(cmd, timeout, tool="circom_civer", bug=bug_path)

    return result


def parse_output(
    tool_result_raw: Path, tool: str, bug_name: str, dsl: str, _: Path
) -> Dict[str, Dict[str, Dict[str, Dict[str, Any]]]]:
    """Parse circom-civer raw output into a structured dictionary.

    The input file is expected to contain a JSON mapping shaped like:
        { dsl: { tool: { bug_name: [lines...] } } }

    Returns a nested dict in the form:
        { dsl: { tool: { bug_name: { stats, buggy_components } } } }
    """
    with open(tool_result_raw, "r", encoding="utf-8") as f:
        bug_info: List[str] = json.load(f).get(dsl, {}).get(tool, {}).get(bug_name, [])
    structured_info: Dict[str, Dict[str, Dict[str, Dict[str, Any]]]] = {}

    stats: Dict[str, Optional[int]] = {
        "verified": None,
        "failed": None,
        "timeout": None,
    }
    buggy_components: List[Any] = []

    context: Optional[str] = None  # track section

    for raw_line in bug_info:
        line = (raw_line or "").strip()
        if line == "[Timed out]":
            context = "timeout"
            buggy_components = ["Reached zksec threshold."]
            continue
        # --- Track context (which section we are in) ---
        if line.startswith("Components that do not satisfy weak safety"):
            context = "buggy"
            continue
        elif line.startswith("Components timeout when checking weak-safety"):
            context = "timeout"
            continue
        elif line.startswith("Components that failed verification"):
            context = "failed"
            continue
        elif line == "":
            context = None  # reset only on empty line
            continue

        # --- Match component lines only if inside "buggy" context ---
        if context == "buggy" and line.startswith("-"):
            comp_match = re.match(r"-\s*([A-Za-z0-9_]+)\(([\d,\s]*)\)", line)
            if comp_match:
                comp_name, numbers = comp_match.groups()
                nums = [int(n.strip()) for n in numbers.split(",") if n.strip()]
                buggy_components.append({"name": comp_name, "params": nums})

        # --- Stats parsing ---
        def _safe_int_from_line(pattern: str, text: str) -> Optional[int]:
            m = re.search(pattern, text)
            if m:
                try:
                    return int(m.group(1))
                except (ValueError, TypeError):
                    return None
            return None

        if "Number of verified components" in line:
            stats["verified"] = _safe_int_from_line(r"(\d+)$", line)
        elif "Number of failed components" in line:
            stats["failed"] = _safe_int_from_line(r"(\d+)$", line)
        elif "Number of timeout components" in line:
            stats["timeout"] = _safe_int_from_line(r"(\d+)$", line)

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
) -> Dict[str, Any]:
    """Compare parsed tool output against ground-truth for a single bug.

    Returns the updated aggregated `output` dictionary.
    """
    output = load_output_dict(output_file, dsl, tool)
    output = remove_bug_entry(output, dsl, tool, bug_name)

    # Get ground truth data
    with open(ground_truth, "r", encoding="utf-8") as f:
        ground_truth_data = json.load(f).get(dsl, {}).get(bug_name, {})

    bug_location = ground_truth_data.get("Location", {})
    if not bug_location:
        logging.error(f"Location data for bug '{bug_name}' not found in ground truth.")
        return output

    buggy_function: Optional[str] = bug_location.get("Function")
    buggy_line: Optional[str] = bug_location.get("Line")
    startline: int
    endline: int
    if buggy_line and "-" in buggy_line:
        start_str, end_str = buggy_line.split("-", 1)
        startline, endline = int(start_str), int(end_str)
    elif not buggy_line:
        startline = endline = 0
        logging.warning(f"Line data for bug '{bug_name}' not found in ground truth.")
    else:
        startline = endline = int(buggy_line)
    logging.debug(
        f"Buggy function: {buggy_function}, startline: {startline}, endline: {endline}"
    )

    tool_output_data = get_tool_result_parsed(tool_result_parsed, dsl, tool, bug_name)

    buggy_components: List[Any] = tool_output_data.get("buggy_components", [])

    is_correct = False
    timed_out = False
    last_comp_name: Optional[str] = None
    last_lines: Optional[str] = None

    for component in buggy_components:
        if component == "Reached zksec threshold.":
            timed_out = True
            break
        comp_name = component.get("name")
        comp_params = component.get("params", [])
        logging.debug(
            f"Found buggy component in '{bug_name}': {comp_name} with params {comp_params}"
        )

        params = comp_params
        if not params:
            startline_tool = endline_tool = 0
        elif len(params) == 1:
            startline_tool = endline_tool = params[0]
        elif len(params) == 2:
            startline_tool, endline_tool = params[0], params[1]
        else:
            logging.warning(f"params should have at most 2 values; got {params}")
            continue
        last_comp_name = comp_name
        last_lines = f"{startline_tool}-{endline_tool}"
        logging.debug(
            f"Component lines: startline={startline_tool}, endline={endline_tool}"
        )

        # Compare with ground truth
        if comp_name == buggy_function:
            logging.debug(f"Component name matches buggy function: {comp_name}")

            # Check lines
            if startline_tool == endline_tool == 0:
                logging.debug("Component lines not provided by tool")
                is_correct = True
            elif startline_tool <= startline and endline_tool >= endline:
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
        output[dsl][tool]["correct"].append(bug_name)
    else:
        if timed_out:
            output[dsl][tool]["timeout"].append(
                {"bug": bug_name, "reason": "Reached zksec threshold."}
            )
        else:
            if not buggy_components:
                reason = "tool found no module"
            elif last_comp_name != buggy_function:
                reason = (
                    f"tool found wrong module (tool found: '{last_comp_name}'; "
                    f"buggy module: '{buggy_function}')"
                )
            else:
                reason = (
                    f"tool found correct module, but lines didn't match (tool found lines: "
                    f"'{last_lines}'; buggy lines: '{startline}-{endline}')"
                )

            output[dsl][tool]["false"].append({"bug_name": bug_name, "reason": reason})

    output = update_result_counts(output, dsl, tool)

    return output
