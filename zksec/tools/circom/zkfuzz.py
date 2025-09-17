import json
import logging
import os
import re
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


def parse_output(
    tool_result_raw: Path, tool: str, bug_name: str, dsl: str, _: Path
) -> None:
    with open(tool_result_raw, "r", encoding="utf-8") as f:
        bug_info = json.load(f).get(dsl, {}).get(tool, {}).get(bug_name, [])

    status = ""
    vulnerability = ""
    logging.debug(f"{bug_name=}")
    if bug_info == []:
        status = "tool error"
        vulnerability = "tool error (no output)"
    elif bug_info[0] == "[Timed out]":
        status = "Timed out"
        vulnerability = "Not found"
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
                vulnerability = re.sub(
                    r"^[^A-Za-z()]*", "", vulnerability
                )  # remove leading junk
                vulnerability = re.sub(
                    r"[^A-Za-z()]*$", "", vulnerability
                )  # remove trailing junk
                break

    structured_info = {}
    if dsl not in structured_info:
        structured_info[dsl] = {}
    if tool not in structured_info[dsl]:
        structured_info[dsl][tool] = {}

    structured_info[dsl][tool][bug_name] = {
        "result": status,
        "vulnerability": vulnerability,
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

    with open(tool_result_parsed, "r", encoding="utf-8") as f:
        tool_output_data = json.load(f).get(dsl, {}).get(tool, {}).get(bug_name, {})

    status = tool_output_data.get("result")
    vulnerability = tool_output_data.get("vulnerability")

    is_correct = False

    reason = ""
    if status == "tool error":
        reason = vulnerability
    if status == "Timed out":
        reason = "Timed out"
    elif status == "found_bug":
        reason = "found_bug"
    else:
        reason = "Tool Error"

    with open(ground_truth, "r", encoding="utf-8") as f:
        gt_data = json.load(f).get(dsl, {}).get(bug_name, {})

    gt_vulnerability = gt_data.get("Vulnerability")

    if (
        reason == "found_bug"
        and gt_vulnerability.replace("-", "") in vulnerability.strip()
    ):
        is_correct = True
        reason = gt_vulnerability
    elif reason == "Timed out":
        pass
    else:
        reason = (
            f"Tool found '{vulnerability}', but ground truth is '{gt_vulnerability}'."
        )

    if is_correct:
        if bug_name not in output[dsl][tool]["correct"]:
            output[dsl][tool]["correct"].append(bug_name)
    elif reason == "Tool Error":
        if bug_name not in output[dsl][tool]["error"]:
            output[dsl][tool]["error"].append(bug_name)
    else:
        if bug_name not in output[dsl][tool]["false"]:
            output[dsl][tool]["false"].append({"bug": bug_name, "reason": reason})

    # Update counts dynamically
    output[dsl][tool]["count"] = {
        "correct": len(output[dsl][tool]["correct"]),
        "false": len(output[dsl][tool]["false"]),
        "error": len(output[dsl][tool]["error"]),
    }

    return output
