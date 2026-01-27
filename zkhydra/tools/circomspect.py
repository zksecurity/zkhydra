import json
import logging
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import (
    EXIT_CODES,
    AbstractTool,
    Finding,
    Input,
    OutputStatus,
    ToolOutput,
    UniformFinding,
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


@dataclass
class CircomspectIssue:
    """Represents a single issue found by circomspect."""

    severity: str  # "warning", "note", "error"
    code: str  # e.g., "CS0013", "CA01"
    name: str  # e.g., "UnnecessarySignalAssignment"
    message: str  # Short description
    file: str  # File path
    line: int  # Line number
    column: int  # Column number
    template: Optional[str] = None  # Template being analyzed

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            "severity": self.severity,
            "code": self.code,
            "name": self.name,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "column": self.column,
        }
        if self.template:
            result["template"] = self.template
        return result


@dataclass
class CircomspectParsed:
    """Structured parsed output from circomspect tool.

    Contains detailed tool-specific information.
    """

    # Execution status
    status: str = "success"  # "success", "timeout", "error"
    # All issues found with full details
    issues: List[CircomspectIssue] = field(default_factory=list)
    # Statistics
    total_issues: int = 0
    warnings_count: int = 0
    notes_count: int = 0
    errors_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "status": self.status,
            "issues": [issue.to_dict() for issue in self.issues],
            "statistics": {
                "total_issues": self.total_issues,
                "warnings": self.warnings_count,
                "notes": self.notes_count,
                "errors": self.errors_count,
            },
        }


class Circomspect(AbstractTool):
    """Circomspect static analyzer for Circom circuits."""

    def __init__(self):
        super().__init__("circomspect")
        self.exit_codes = EXIT_CODES - {1}
        if not self.check_binary_exists("circomspect"):
            logging.error("[Binary not found: install circomspect]")
            sys.exit(1)

    def _internal_execute(self, input_paths: Input, timeout: int) -> ToolOutput:
        """Run circomspect on a given circuit.

        Args:
            input_paths: Input object containing circuit_dir and circuit_file paths
            timeout: Maximum execution time in seconds

        Returns:
            ToolOutput object with execution results
        """
        circuit_file_path = Path(input_paths.circuit_file)
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
                            line=line_number,
                            raw_message=line,
                        )
                    )
                except:
                    pass

        return findings

    def _helper_parse_output(self, tool_result_raw: Path) -> CircomspectParsed:
        """Parse circomspect output and extract all issues.

        Args:
            tool_result_raw: Path to raw tool output file

        Returns:
            CircomspectParsed object with detailed structured data
        """
        # Get tool output
        with open(tool_result_raw, "r", encoding="utf-8") as f:
            bug_info: List[str] = [line.strip() for line in f if line.strip()]

        # Check for timeout
        for raw_line in bug_info:
            line = (raw_line or "").rstrip("\n")
            if line == "[Timed out]":
                return CircomspectParsed(status="timeout")

        issues: List[CircomspectIssue] = []
        current_template: Optional[str] = None

        # Extract all warnings/notes/errors from the output
        current_code: Optional[str] = None
        current_message: Optional[str] = None
        current_file: Optional[str] = None
        current_line: Optional[int] = None
        current_column: Optional[int] = None
        current_severity: Optional[str] = None

        for i, line in enumerate(bug_info):
            # Track current template
            if "template:" in line.lower():
                match = re.search(r"template:\s*(\w+)", line, re.IGNORECASE)
                if match:
                    current_template = match.group(1)

            # Detect a warning/note/error line and extract the code
            match_issue = re.match(
                r"\s*(warning|note|error)\[([A-Z0-9]+)\]:\s*(.+)", line
            )
            if match_issue:
                current_severity = match_issue.group(1)
                current_code = match_issue.group(2)
                current_message = match_issue.group(3)

            # Try to get file location from next line (format: "file:line:col")
            if current_code and i + 1 < len(bug_info):
                try:
                    location_line = bug_info[i + 1]
                    match_location = re.search(
                        r"(.+):(\d+):(\d+)", location_line
                    )
                    if match_location:
                        # Remove box-drawing characters from file path
                        current_file = re.sub(
                            r"[\u2500-\u257F\u250C-\u254B]",
                            "",
                            match_location.group(1),
                        ).strip()
                        current_line = int(match_location.group(2))
                        current_column = int(match_location.group(3))

                        # Get bug name from mapping
                        bug_name = CS_MAPPING.get(current_code, current_code)

                        # Create issue
                        issue = CircomspectIssue(
                            severity=current_severity or "warning",
                            code=current_code,
                            name=bug_name,
                            message=current_message or "",
                            file=current_file,
                            line=current_line,
                            column=current_column,
                            template=current_template,
                        )
                        issues.append(issue)

                        # Reset
                        current_code = None
                        current_message = None
                        current_file = None
                        current_line = None
                        current_column = None
                        current_severity = None
                except (ValueError, IndexError) as e:
                    logging.debug(
                        f"Failed to parse location from '{bug_info[i+1]}': {e}"
                    )
                    current_code = None

        # Calculate statistics
        warnings_count = sum(
            1 for issue in issues if issue.severity == "warning"
        )
        notes_count = sum(1 for issue in issues if issue.severity == "note")
        errors_count = sum(1 for issue in issues if issue.severity == "error")

        return CircomspectParsed(
            status="success",
            issues=issues,
            total_issues=len(issues),
            warnings_count=warnings_count,
            notes_count=notes_count,
            errors_count=errors_count,
        )

    def generate_uniform_results(
        self,
        parsed_output: CircomspectParsed,
        tool_output: ToolOutput,
        output_file: Path,
    ) -> None:
        """Generate uniform results.json file.

        Args:
            parsed_output: Parsed tool output
            tool_output: Tool execution output with timing info
            output_file: Path to write results.json
        """
        findings = []

        for issue in parsed_output.issues:
            finding = UniformFinding(
                bug_type=issue.name,
                severity=issue.severity,
                message=issue.message,
                file=issue.file,
                line=issue.line,
                column=issue.column,
                code=issue.code,
                template=issue.template,
            )
            findings.append(finding.to_dict())

        results = {
            "status": parsed_output.status,
            "execution_time": round(tool_output.execution_time, 2),
            "findings": findings,
        }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

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
