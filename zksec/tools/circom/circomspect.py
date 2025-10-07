import json
import logging
import re
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..utils import (
    check_files_exist,
    get_tool_result_parsed,
    run_command,
)

# TODO: Verify what really is under-constrained
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


def execute(bug_path: str, timeout: int) -> str:
    """Run circomspect on a given bug's circuit.

    Args:
        bug_path: Absolute path to the bug directory containing `circuits/circuit.circom`.
        timeout: Maximum execution time in seconds.

    Returns:
        Raw tool output, or a bracketed error marker string.
    """
    logging.debug(f"bug_path='{bug_path}'")

    circuit_file = Path(bug_path) / "circuits" / "circuit.circom"
    if not check_files_exist(circuit_file):
        return "[Circuit file not found]"

    if shutil.which("circomspect") is None:
        logging.error("'circomspect' CLI not found in PATH")
        return "[Binary not found: install circomspect]"

    cmd = ["circomspect", str(circuit_file), "-l", "INFO", "-v"]
    result = run_command(cmd, timeout, tool="circomspect", bug=bug_path)

    return result


def parse_output(
    tool_result_raw: Path, ground_truth: Path
) -> Dict[str, Dict[str, Dict[str, Dict[str, Any]]]]:
    """Parse circomspect output and extract warnings for the vulnerable function."""
    # Get ground truth to reverse search
    with open(ground_truth, "r", encoding="utf-8") as f:
        gt_data = json.load(f)
    vuln_function: Optional[str] = gt_data.get("Location", {}).get("Function")

    # Get tool output
    with open(tool_result_raw, "r", encoding="utf-8") as f:
        bug_info: List[str] = [line.strip() for line in f if line.strip()]

    # If we don't know the function, we cannot find the specific block
    if not vuln_function:
        logging.warning(f"Ground truth missing vulnerable function.")
        return {"warnings": "No Warnings Found"}

    # Get block that is analyzing the vulnerable function or template
    start_marker_function = f"circomspect: analyzing function '{vuln_function}'"
    start_marker_template = f"circomspect: analyzing template '{vuln_function}'"

    block: List[str] = []
    inside_block = False

    warnings: List[Any] = []

    for raw_line in bug_info:
        line = (raw_line or "").rstrip("\n")
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
            if line.strip() in (start_marker_function, start_marker_template):
                inside_block = True
                block.append(line)
        elif inside_block:
            block.append(line)

    # Extract warnings from block
    current_code: Optional[str] = None
    for i, line in enumerate(block):
        # Detect a warning line and extract the code (e.g. CS0005)
        match_warn = re.match(r"\s*warning\[(CS\d+)\]:", line)
        if match_warn:
            current_code = match_warn.group(1)
        try:
            match_line = re.search(r":(\d+):", block[i + 1])
        except Exception:
            match_line = None
        if match_line:
            line_number = match_line.group(1)
        if current_code and match_line:
            try:
                line_number = int(line_number)
                warnings.append((current_code, line_number))
            except ValueError:
                logging.error(f"Failed to parse line number from '{line}'")
            finally:
                current_code = None  # reset after recording

    structured_info: Dict[str, Any] = {}

    result_value: Any = warnings if warnings else []
    structured_info = {
        "warnings": result_value,
    }

    return structured_info


def compare_zkbugs_ground_truth(
    tool: str, dsl: str, bug_name: str, ground_truth: Path, tool_result_parsed: Path
) -> Dict[str, Any]:
    """Compare circomspect warnings to ground truth and update aggregate output."""
    output = {}

    warnings: List[Any] = get_tool_result_parsed(tool_result_parsed).get(
        "warnings", "No Warnings Found"
    )

    # Handle trivial outcomes first
    if warnings == "No Warnings Found":
        output = {"result": "false", "reason": warnings}
        return output
    elif warnings == ["Reached zksec threshold."]:
        output = {"result": "timeout", "reason": warnings}
        return output
    elif warnings == "No Warnings Found for vulnerable function":
        output = {"result": "false", "reason": warnings}
        return output

    # Get ground truth data
    with open(ground_truth, "r", encoding="utf-8") as f:
        gt_data = json.load(f)

    gt_vulnerability: Optional[str] = gt_data.get("Vulnerability")
    gt_lines: Optional[str] = gt_data.get("Location", {}).get("Line")

    if not gt_vulnerability or not gt_lines:
        logging.error(
            f"Ground truth missing fields for '{bug_name}' ({dsl}): vulnerability={gt_vulnerability}, lines={gt_lines}"
        )
        output = {"result": "false", "reason": "incomplete ground truth"}
        return output

    if "-" in gt_lines:
        gt_startline_str, gt_endline_str = gt_lines.split("-", 1)
    else:
        gt_startline_str = gt_endline_str = gt_lines
    gt_startline, gt_endline = int(gt_startline_str), int(gt_endline_str)

    is_correct = False
    reason: List[str] = []
    manual_evaluation = False

    for warning in warnings:
        try:
            tool_code, tool_line_raw = warning
            tool_line = int(tool_line_raw)
        except Exception:
            logging.error(f"Unexpected warning format: {warning}")
            continue
        tool_vulnerability = CS_MAPPING.get(tool_code)

        if not tool_vulnerability:
            reason.append(
                f"unrecognized warning code '{tool_code}' by circomspect for '{bug_name}'"
            )
            continue

        if tool_vulnerability.lower() == gt_vulnerability.lower():
            if gt_startline <= tool_line <= gt_endline:
                is_correct = True
            else:
                reason.append(
                    f"Tool found correct vulnerability ('{tool_vulnerability}'), but wrong line: "
                    f"tool found: '{tool_line}'; ground truth line: '{gt_startline}'-'{gt_endline}'"
                )
                manual_evaluation = True
        else:
            reason.append(
                f"Tool found wrong vulnerability ('{tool_vulnerability}'); ground truth vulnerability: '{gt_vulnerability}'"
            )
            manual_evaluation = True
    if is_correct:
        output = {"result": "correct"}
    else:
        if reason == []:
            reason = ["circomspect found no warnings for vulnerable function."]
        if manual_evaluation:
            output = {
                "result": "false",
                "reason": reason,
                "need_manual_evaluation": True,
            }
        else:
            output = {"result": "false", "reason": reason}

    return output
