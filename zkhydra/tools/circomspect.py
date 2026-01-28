import json
import logging
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .base import (
    EXIT_CODES,
    AbstractTool,
    AnalysisStatus,
    Finding,
    Input,
    OutputStatus,
    StandardizedBugCategory,
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
    "CS0014": "UnconstrainedLessThan",
    "CS0015": "UnconstrainedDivision",
    "CS0016": "Bn254SpecificCircuit",
    "CS0017": "UnderConstrainedSignal",
    "CS0018": "UnusedOutputSignal",
    "CA01": "UnconstrainedSignal",
}

# Mapping from circomspect bug names to standardized categories
CIRCOMSPECT_TO_STANDARD = {
    "ShadowingVariable": StandardizedBugCategory.WARNING,
    "ParameterNameCollision": StandardizedBugCategory.WARNING,
    "FieldElementComparison": StandardizedBugCategory.WARNING,
    "FieldElementArithmetic": StandardizedBugCategory.WARNING,
    "SignalAssignmentStatement": StandardizedBugCategory.WARNING,
    "UnusedVariableValue": StandardizedBugCategory.WARNING,
    "UnusedParameterValue": StandardizedBugCategory.WARNING,
    "VariableWithoutSideEffect": StandardizedBugCategory.WARNING,
    "ConstantBranchCondition": StandardizedBugCategory.WARNING,
    "NonStrictBinaryConversion": StandardizedBugCategory.WARNING,
    "CyclomaticComplexity": StandardizedBugCategory.WARNING,
    "TooManyArguments": StandardizedBugCategory.WARNING,
    "UnnecessarySignalAssignment": StandardizedBugCategory.WARNING,
    "UnconstrainedLessThan": StandardizedBugCategory.UNDER_CONSTRAINED,
    "UnconstrainedDivision": StandardizedBugCategory.UNDER_CONSTRAINED,
    "Bn254SpecificCircuit": StandardizedBugCategory.WARNING,
    "UnderConstrainedSignal": StandardizedBugCategory.UNDER_CONSTRAINED,
    "UnusedOutputSignal": StandardizedBugCategory.UNDER_CONSTRAINED,
    "UnconstrainedSignal": StandardizedBugCategory.UNDER_CONSTRAINED,
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

    def _helper_generate_uniform_results(
        self,
        parsed_output: CircomspectParsed,
        tool_output: ToolOutput,
    ) -> Tuple[AnalysisStatus, List[Finding]]:
        """Generate uniform findings from parsed output.

        Args:
            parsed_output: Parsed tool output
            tool_output: Tool execution output with timing info

        Returns:
            Tuple of (AnalysisStatus, List[Finding])
        """
        findings = []

        # Determine analysis status
        if parsed_output.status == "timeout":
            analysis_status = AnalysisStatus.TIMEOUT
        elif parsed_output.issues:
            analysis_status = AnalysisStatus.BUGS_FOUND
        else:
            analysis_status = AnalysisStatus.NO_BUGS

        for issue in parsed_output.issues:
            # Map to standardized bug category
            unified_title = CIRCOMSPECT_TO_STANDARD.get(
                issue.name, StandardizedBugCategory.COMPUTATIONAL_ISSUE
            )

            finding = Finding(
                bug_title=issue.name,  # Tool-specific name
                unified_bug_title=unified_title,  # Standardized category
                description=issue.message,
                file=issue.file,
                position={
                    "line": issue.line,
                    "column": issue.column,
                    "template": issue.template,
                },
                metadata={
                    "severity": issue.severity,
                    "code": issue.code,
                },
            )
            findings.append(finding)

        return analysis_status, findings

    def evaluate_zkbugs_ground_truth(
        self,
        tool: str,
        dsl: str,
        bug_name: str,
        ground_truth: Path,
        tool_result_path: Path,
    ) -> Dict[str, Any]:
        """Evaluate circomspect results against ground truth.

        Args:
            tool: Tool name
            dsl: Domain-specific language
            bug_name: Bug name
            ground_truth: Path to ground truth JSON
            tool_result_path: Path to results.json

        Returns:
            Evaluation result dictionary
        """
        # Load ground truth
        gt_data = self.load_json_file(ground_truth)
        gt_vulnerability = gt_data.get("vulnerability")
        gt_location = gt_data.get("location", {})
        gt_function = gt_location.get("Function")
        gt_lines = gt_location.get("Line")

        # Load tool results
        tool_results = self.load_json_file(tool_result_path)
        findings = tool_results.get("findings", [])

        # If no findings, it's definitely a FalseNegative
        if not findings:
            return {
                "status": "FalseNegative",
                "reason": "Tool found no issues",
                "need_manual_analysis": False,
                "manual_analysis": "N/A",
                "manual_analysis_reasoning": "N/A",
            }

        # Parse ground truth line range
        if gt_lines:
            if "-" in gt_lines:
                gt_start, gt_end = gt_lines.split("-", 1)
                gt_startline, gt_endline = int(gt_start), int(gt_end)
            else:
                gt_startline = gt_endline = int(gt_lines)
        else:
            gt_startline = gt_endline = None

        # Check if any finding matches the ground truth
        exact_match = False
        partial_matches = []

        for finding in findings:
            unified_title = finding.get("unified_bug_title", "")
            position = finding.get("position", {})
            finding_line = position.get("line")

            # Check if vulnerability type matches
            vuln_match = (
                gt_vulnerability
                and unified_title.lower() == gt_vulnerability.lower()
            )

            # Check if line matches (if we have line info)
            if finding_line and gt_startline is not None:
                line_match = gt_startline <= finding_line <= gt_endline
            else:
                line_match = None  # Can't determine without line info

            if vuln_match and line_match:
                exact_match = True
            elif vuln_match:
                partial_matches.append(
                    f"Found {unified_title} but at different line ({finding_line} vs {gt_lines})"
                )

        # Conservative evaluation
        if exact_match:
            # 100% certain: exact vulnerability type and line match
            return {
                "status": "TruePositive",
                "reason": f"Found {gt_vulnerability} at lines {gt_lines}",
                "need_manual_analysis": False,
                "manual_analysis": "N/A",
                "manual_analysis_reasoning": "N/A",
            }
        elif partial_matches:
            # Uncertain: right vulnerability but wrong line
            return {
                "status": "Undecided",
                "reason": "; ".join(partial_matches),
                "need_manual_analysis": True,
                "manual_analysis": "Pending",
                "manual_analysis_reasoning": "TODO",
            }
        else:
            # Found issues but not the expected vulnerability
            return {
                "status": "Undecided",
                "reason": f"Tool found {len(findings)} issues but none match {gt_vulnerability}",
                "need_manual_analysis": True,
                "manual_analysis": "Pending",
                "manual_analysis_reasoning": "TODO",
            }
