import json
import logging
import os
import re
from pathlib import Path

from ..utils import (
    check_files_exist,
    get_tool_result_parsed,
    load_output_dict,
    run_command,
    update_result_counts,
)

# From circomspect: https://github.com/trailofbits/circomspect/blob/ece9efe0a21e6c422a43ab6f2e1c0ce99678013b/program_structure/src/program_library/report_code.rs#L164C13-L182C44
CS_MAPPING = {
    "CS0001": "shadowing-variable",  # ShadowingVariable
    "CS0002": "parameter-name-collision",  # ParameterNameCollision
    "CS0003": "field-element-comparison",  # FieldElementComparison
    "CS0004": "field-element-arithmetic",  # FieldElementArithmetic
    "CS0005": "under-constrained",  # SignalAssignmentStatement
    "CS0006": "under-constrained",  # UnusedVariableValue
    "CS0007": "unused-parameter-value",  # UnusedParameterValue
    "CS0008": "variable-without-side-effect",  # VariableWithoutSideEffect
    "CS0009": "constant-branch-condition",  # ConstantBranchCondition
    "CS0010": "under-constrained",  # NonStrictBinaryConversion
    "CS0011": "cyclomatic-complexity",  # CyclomaticComplexity
    "CS0012": "too-many-arguments",  # TooManyArguments
    "CS0013": "under-constrained",  # UnnecessarySignalAssignment
    "CS0014": "under-constrained",  # UnconstrainedLessThan
    "CS0015": "unconstrained-division",  # UnconstrainedDivision
    "CS0016": "bn254-specific-circuit",  # Bn254SpecificCircuit
    "CS0017": "under-constrained-signal",  # UnderConstrainedSignal
    "CS0018": "unused-output-signal",  # UnusedOutputSignal
}


def execute(bug_path: str, timeout: int):
    logging.debug(f"bug_path='{bug_path}'")

    circuit_file = Path(bug_path) / "circuits" / "circuit.circom"
    if not check_files_exist(circuit_file):
        return "[Circuit file not found]"

    cmd = ["circomspect", str(circuit_file), "-l", "INFO", "-v"]
    result = run_command(cmd, timeout, tool="circomspect", bug=bug_path)

    return result


def parse_output(
    tool_result_raw: Path, tool: str, bug_name: str, dsl: str, ground_truth: Path
) -> None:
    # Get ground truth to reverse search
    with open(ground_truth, "r", encoding="utf-8") as f:
        gt_data = json.load(f).get(dsl, {}).get(bug_name, {})
    vuln_function = gt_data.get("Location", {}).get("Function")

    # Get tool output
    with open(tool_result_raw, "r", encoding="utf-8") as f:
        bug_info = json.load(f).get(dsl, {}).get(tool, {}).get(bug_name, [])

    # Get block that is analyzing the vulnerable function or template
    start_marker_function = f"circomspect: analyzing function '{vuln_function}'"
    start_marker_template = f"circomspect: analyzing template '{vuln_function}'"
    block = []
    inside_block = False

    warnings = []

    for line in bug_info:
        if line == "[Timed out]":
            warnings = ["Reached zksec threshold."]
            break
        if line.startswith("circomspect: analyzing function") or line.startswith(
            "circomspect: analyzing template"
        ):
            # If we were inside the desired block, stop when a new function begins
            if inside_block:
                break
            # If this is the function we want, start recording
            if (
                line.strip() == start_marker_function
                or line.strip() == start_marker_template
            ):
                inside_block = True
                block.append(line)
        elif inside_block:
            block.append(line)

    # Extarct Warnings from block
    current_code = None
    for line in block:
        # Detect a warning line and extract the code (e.g. CS0005)
        match_warn = re.match(r"\s*warning\[(CS\d+)\]:", line)
        if match_warn:
            current_code = match_warn.group(1)

        # Detect the line number from the code snippet (e.g. "373")
        match_line = re.match(r"\s*(\d+)\s*│", line)
        if current_code and match_line:
            line_number = int(match_line.group(1))
            warnings.append((current_code, line_number))
            current_code = None  # reset after recording

    structured_info = {}
    if dsl not in structured_info:
        structured_info[dsl] = {}
    if tool not in structured_info[dsl]:
        structured_info[dsl][tool] = {}

    result_value = warnings if warnings else "No Warnings Found"
    structured_info[dsl][tool][bug_name] = {
        "warnings": result_value,
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

    warnings = get_tool_result_parsed(tool_result_parsed, dsl, tool, bug_name).get(
        "warnings", "No Warnings Found"
    )

    if warnings == "No Warnings Found":
        if bug_name not in output[dsl][tool]["false"]:
            output[dsl][tool]["false"].append(
                {"bug_name": bug_name, "reason": warnings}
            )
        return output
    if warnings == ["Reached zksec threshold."]:
        if bug_name not in output[dsl][tool]["timeout"]:
            output[dsl][tool]["timeout"].append(
                {"bug_name": bug_name, "reason": warnings}
            )
        return output

    # Get ground truth data
    with open(ground_truth, "r", encoding="utf-8") as f:
        gt_data = json.load(f).get(dsl, {}).get(bug_name, {})

    gt_vulnerability = gt_data.get("Vulnerability")
    gt_lines = gt_data.get("Location", {}).get("Line")
    if "-" in gt_lines:
        gt_startline, gt_endline = gt_lines.split("-")
    else:
        gt_startline = gt_endline = gt_lines

    is_correct = False
    reason = []

    for warning in warnings:
        tool_code = warning[0]
        tool_line = warning[1]
        tool_vulnerability = CS_MAPPING.get(tool_code)

        if tool_vulnerability.lower() == gt_vulnerability.lower():
            if int(tool_line) >= int(gt_startline) and int(tool_line) <= int(
                gt_endline
            ):
                is_correct = True
            else:
                reason.append(
                    f"tool found correct vulnerability ('{tool_vulnerability}'), but wrong line: tool found: '{tool_line}'; ground truth line: '{gt_startline}'-'{gt_endline}'"
                )
        else:
            reason.append(
                f"tool found wrong vulnerability ('{tool_vulnerability}'); ground truth vulnerability: '{gt_vulnerability}'"
            )

    if is_correct:
        if bug_name not in output[dsl][tool]["correct"]:
            output[dsl][tool]["correct"].append(bug_name)
    else:
        if bug_name not in output[dsl][tool]["false"]:
            if reason == []:
                reason = "circomspect found no warnings."
            output[dsl][tool]["false"].append({"bug_name": bug_name, "reason": reason})

    output = update_result_counts(output, dsl, tool)

    return output
