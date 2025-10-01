import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List

from ..utils import (
    change_directory,
    check_files_exist,
    get_tool_result_parsed,
    run_command,
)

TOOL_DIR = Path(__file__).resolve().parent / "zkfuzz"


def execute(bug_path: str, timeout: int) -> str:
    """Run zkfuzz on the given circuit.

    Args:
        bug_path: Absolute path to the bug directory containing `circuits/circuit.circom`.
        timeout: Maximum execution time in seconds.

    Returns:
        Raw tool output, or a bracketed error marker string.
    """
    logging.debug(f"ZKFUZZ_DIR='{TOOL_DIR}'")
    logging.debug(f"bug_path='{bug_path}'")

    circuit_file = Path(bug_path) / "circuits" / "circuit.circom"
    if not check_files_exist(circuit_file):
        return "[Circuit file not found]"

    binary_path = TOOL_DIR / "target" / "release" / "zkfuzz"
    if not binary_path.is_file():
        logging.error(f"zkfuzz binary not found at {binary_path}")
        return "[Binary not found: build zkfuzz first]"
    if not os.access(binary_path, os.X_OK):
        logging.error(f"zkfuzz binary is not executable: {binary_path}")
        return "[Binary not executable: fix permissions for zkfuzz]"

    change_directory(TOOL_DIR)

    cmd = [str(binary_path), str(circuit_file)]
    result = run_command(cmd, timeout, tool="zkfuzz", bug=bug_path)

    return result


def parse_output(
    tool_result_raw: Path, _: Path
) -> Dict[str, Dict[str, Dict[str, Dict[str, Any]]]]:
    """Parse zkfuzz output and extract status and vulnerability string."""
    with open(tool_result_raw, "r", encoding="utf-8") as f:
        bug_info: list[str] = [line.strip() for line in f if line.strip()]

    status = ""
    vulnerability = ""

    if not bug_info:
        status = "tool error"
        vulnerability = "tool error (no output)"
    elif any(line == "[Timed out]" for line in bug_info):
        status = "Timed out"
        vulnerability = "Not found"
    elif any(line == "previous errors were found" for line in bug_info):
        status = "previous errors were found"
        vulnerability = "previous errors were found"
    elif bug_info[-1] != "Everything went okay":
        status = "tool error"
        vulnerability = "tool error"
    else:
        for i, line in enumerate(bug_info):
            if "No Counter Example Found" in line:
                status = "found_no_bug"
                vulnerability = "No Counter Example Found"
                break
            if "Counter Example" in line and i + 1 < len(bug_info):
                status = "found_bug"
                vulnerability = bug_info[i + 1]
                vulnerability = re.sub(r"^[^A-Za-z()]*", "", vulnerability)
                vulnerability = re.sub(r"[^A-Za-z()]*$", "", vulnerability)
                break

    structured_info: Dict[str, Any] = {}

    structured_info = {
        "result": status,
        "vulnerability": vulnerability,
    }

    return structured_info


def compare_zkbugs_ground_truth(
    tool: str, dsl: str, bug_name: str, ground_truth: Path, tool_result_parsed: Path
) -> Dict[str, Any]:
    """Compare zkfuzz findings against ground truth and update aggregates."""
    output = {}

    tool_output_data = get_tool_result_parsed(tool_result_parsed)

    status: str = tool_output_data.get("result", "tool error")
    vulnerability: str = tool_output_data.get("vulnerability", "")

    # Load ground truth correctly (file path -> JSON)
    with open(ground_truth, "r", encoding="utf-8") as f:
        gt_data = json.load(f)
    # gt_data = gt_data_all.get(dsl, {}).get(bug_name, {})
    gt_vulnerability = gt_data.get("Vulnerability")

    is_correct = False
    reason = ""

    if status == "Timed out":
        reason = "Reached zksec threshold."
    elif status == "tool error":
        reason = vulnerability or "tool error"
    elif status == "found_bug":
        reason = "found_bug"
    elif status == "found_no_bug":
        reason = "Tool found no counter example"
    elif status == "previous errors were found":
        reason = "Tool found previous errors"
    else:
        reason = status or "unknown"

    # Normalize strings for comparison
    vulnerability_str = (vulnerability or "").replace("-", "").replace(" ", "").lower()
    gt_vulnerability_str = (
        (gt_vulnerability or "").replace("-", "").replace(" ", "").lower()
    )

    if (
        reason == "found_bug"
        and gt_vulnerability_str
        and gt_vulnerability_str in vulnerability_str
    ):
        is_correct = True
        reason = gt_vulnerability or "found_bug"

    if is_correct:
        output = {"result": "correct"}
    elif reason == "Reached zksec threshold.":
        output = {"result": "timeout", "reason": reason}
    elif reason in ("tool error", "Tool Error"):
        output = {"result": "error", "reason": reason}
    elif reason == "Tool found previous errors":
        output = {"result": "error", "reason": reason}
    else:
        output = {"result": "false", "reason": reason}

    return output
