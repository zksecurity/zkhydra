import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import (
    EXIT_CODES,
    AbstractTool,
    Finding,
    Input,
    OutputStatus,
    ToolOutput,
    get_tool_result_parsed,
)

# From circomspect: https://github.com/trailofbits/circomspect/blob/ece9efe0a21e6c422a43ab6f2e1c0ce99678013b/program_structure/src/program_library/report_code.rs#L164C13-L182C44
CS_MAPPING = {
    "CS0001": "ShadowingVariable",
    "CS0002": "ParameterNameCollision",
    "CS0003": "FieldElementComparison",
    "CS0004": "FieldElementArithmetic",
    "CS0005": "SignalAssignmentStatement",
    "CS0006": "UnusedVariableValue",
    "CS0007": "UnusedParameterValue",
    "CS0008": "VariableWithoutSideEffect",
    "CS0009": "ConstantBranchCondition",
    "CS0010": "NonStrictBinaryConversion",
    "CS0011": "CyclomaticComplexity",
    "CS0012": "TooManyArguments",
    "CS0013": "UnnecessarySignalAssignment",
    "CS0014": "Under-Constrained",  # "UnconstrainedLessThan"
    "CS0015": "Under-Constrained",  # "UnconstrainedDivision"
    "CS0016": "Bn254SpecificCircuit",
    "CS0017": "Under-Constrained",  # "UnderConstrainedSignal"
    "CS0018": "UnusedOutputSignal",
    "CA01": "Under-Constrained",  # Unconstrained signal
}


class Circomspect(AbstractTool):
    """Circomspect static analyzer for Circom circuits."""

    def __init__(self):
        super().__init__("circomspect")
        self.exit_codes = EXIT_CODES - {1}

    def execute(self, input_paths: Input, timeout: int) -> ToolOutput:
        """Run circomspect on a given circuit.

        Args:
            input_paths: Input object containing circuit_dir and circuit_file paths
            timeout: Maximum execution time in seconds

        Returns:
            ToolOutput object with execution results
        """
        logging.debug(f"circuit_dir='{input_paths.circuit_dir}'")
        logging.debug(f"circuit_file='{input_paths.circuit_file}'")

        circuit_file_path = Path(input_paths.circuit_file)

        if not self.check_binary_exists("circomspect"):
            return ToolOutput(
                status=OutputStatus.FAIL,
                stdout="",
                stderr="",
                return_code=-1,
                msg="[Binary not found: install circomspect]",
            )

        cmd = ["circomspect", str(circuit_file_path), "-l", "INFO", "-v"]
        return self.run_command(cmd, timeout, input_paths.circuit_dir)

    def parse_findings(self, raw_output: str) -> List[Finding]:
        """Parse circomspect warnings into findings list.

        Args:
            raw_output: Raw circomspect output

        Returns:
            List of Finding objects
        """
        findings = []
        lines = raw_output.split("\n")

        for i, line in enumerate(lines):
            if "warning[" in line:
                # Extract warning code and description
                try:
                    code = line.split("[")[1].split("]")[0]
                    description = line.strip()

                    # Next line usually has file:line info
                    location_line = None
                    line_number = None
                    if i + 1 < len(lines):
                        location_line = lines[i + 1].strip()
                        # Try to extract line number from location (format: "file:line:col")
                        match = re.search(r":(\d+):", location_line)
                        if match:
                            line_number = match.group(1)

                    # Determine severity from code prefix
                    if code.startswith("CS"):
                        severity = "warning"
                    else:
                        severity = "note"

                    # Get actual bug type from CS_MAPPING, default to code itself
                    bug_type = CS_MAPPING.get(code, code)

                    findings.append(
                        Finding(
                            description=description,
                            bug_type=bug_type,
                            code=code,
                            severity=severity,
                            location=location_line if location_line else None,
                            line=line_number,
                            raw_message=line,
                        )
                    )
                except:
                    pass

        return findings

    def parse_output(
        self, tool_result_raw: Path, ground_truth: Path
    ) -> Dict[str, Any]:
        """Parse circomspect output and extract warnings for the vulnerable function.

        Args:
            tool_result_raw: Path to raw tool output file
            ground_truth: Path to ground truth JSON file

        Returns:
            Dictionary with parsed warnings
        """
        # Get ground truth to reverse search
        gt_data = self.load_json_file(ground_truth)
        vuln_function: Optional[str] = gt_data.get("Location", {}).get(
            "Function"
        )

        # Get tool output
        with open(tool_result_raw, "r", encoding="utf-8") as f:
            bug_info: List[str] = [line.strip() for line in f if line.strip()]

        # If we don't know the function, we cannot find the specific block
        if not vuln_function:
            logging.warning(f"Ground truth missing vulnerable function.")
            return {"warnings": "No Warnings Found"}

        # Get block that is analyzing the vulnerable function or template
        start_marker_function = (
            f"circomspect: analyzing function '{vuln_function}'"
        )
        start_marker_template = (
            f"circomspect: analyzing template '{vuln_function}'"
        )

        block: List[str] = []
        inside_block = False

        warnings: List[Any] = []

        for raw_line in bug_info:
            line = (raw_line or "").rstrip("\n")
            if line == "[Timed out]":
                warnings = ["Reached zkhydra threshold."]
                break
            if line.startswith(
                "circomspect: analyzing function"
            ) or line.startswith("circomspect: analyzing template"):
                # If we were inside the desired block, stop when a new function begins
                if inside_block:
                    break
                # If this is the function we want, start recording
                if line.strip() in (
                    start_marker_function,
                    start_marker_template,
                ):
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

        result_value: Any = warnings if warnings else []
        return {"warnings": result_value}

    def compare_zkbugs_ground_truth(
        self,
        tool: str,
        dsl: str,
        bug_name: str,
        ground_truth: Path,
        tool_result_parsed: Path,
    ) -> Dict[str, Any]:
        """Compare circomspect warnings to ground truth.

        Args:
            tool: Tool name
            dsl: Domain-specific language
            bug_name: Bug name
            ground_truth: Path to ground truth JSON
            tool_result_parsed: Path to parsed tool results

        Returns:
            Comparison result dictionary
        """
        output = {}

        warnings: List[Any] = get_tool_result_parsed(tool_result_parsed).get(
            "warnings", "No Warnings Found"
        )

        # Handle trivial outcomes first
        if warnings == "No Warnings Found":
            output = {"result": "false", "reason": warnings}
            return output
        elif warnings == ["Reached zkhydra threshold."]:
            output = {"result": "timeout", "reason": warnings}
            return output
        elif warnings == "No Warnings Found for vulnerable function":
            output = {"result": "false", "reason": warnings}
            return output

        # Get ground truth data
        gt_data = self.load_json_file(ground_truth)

        gt_vulnerability: Optional[str] = gt_data.get("Vulnerability")
        gt_lines: Optional[str] = gt_data.get("Location", {}).get("Line")

        if not gt_vulnerability or not gt_lines:
            logging.error(
                f"Ground truth missing fields for '{bug_name}' ({dsl}): "
                f"vulnerability={gt_vulnerability}, lines={gt_lines}"
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
                    f"Tool found wrong vulnerability ('{tool_vulnerability}'); "
                    f"ground truth vulnerability: '{gt_vulnerability}'"
                )

        if is_correct:
            output = {"result": "correct"}
        else:
            if reason == []:
                reason = [
                    "circomspect found no warnings for vulnerable function."
                ]
            if manual_evaluation:
                output = {
                    "result": "false",
                    "reason": reason,
                    "need_manual_evaluation": True,
                }
            else:
                output = {"result": "false", "reason": reason}

        return output


# Create a singleton instance for the registry
_circomspect_instance = Circomspect()
