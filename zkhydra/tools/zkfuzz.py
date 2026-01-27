import logging
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .base import (
    AbstractTool,
    AnalysisStatus,
    Finding,
    Input,
    OutputStatus,
    StandardizedBugCategory,
    ToolOutput,
    get_tool_result_parsed,
)

# Mapping from zkfuzz bug names to standardized categories
ZKFUZZ_TO_STANDARD = {
    "Under-Constrained": StandardizedBugCategory.UNDER_CONSTRAINED,
    "Over-Constrained": StandardizedBugCategory.OVER_CONSTRAINED,
}


@dataclass
class ZkFuzzParsed:
    """Structured parsed output from zkFuzz tool.

    Contains detailed execution result and vulnerability type.
    """

    # Tool-specific fields
    result: str  # "found_bug", "found_no_bug", "Timed out", etc.
    vulnerability: str  # Vulnerability type or status message
    signal: str = ""  # Underconstrained signal (e.g., "main.c")
    expected_value: str = ""  # Expected value for the signal
    assignments: Dict[str, str] = field(
        default_factory=dict
    )  # Signal assignments

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = {
            "result": self.result,
            "vulnerability": self.vulnerability,
        }
        if self.signal:
            data["signal"] = self.signal
        if self.expected_value:
            data["expected_value"] = self.expected_value
        if self.assignments:
            data["assignments"] = self.assignments
        return data


class ZkFuzz(AbstractTool):
    """zkFuzz fuzzing tool for Circom circuits."""

    def __init__(self):
        super().__init__("zkfuzz")
        if not self.check_binary_exists("zkfuzz"):
            logging.error("[Binary not found: install zkfuzz]")
            sys.exit(1)

    def _internal_execute(self, input_paths: Input, timeout: int) -> ToolOutput:
        """Run zkfuzz on the given circuit.

        Args:
            input_paths: Input object containing circuit_dir and circuit_file paths
            timeout: Maximum execution time in seconds

        Returns:
            ToolOutput object with execution results
        """
        circuit_file_path = Path(input_paths.circuit_file)

        cmd = ["zkfuzz", str(circuit_file_path)]
        return self.run_command(cmd, timeout, input_paths.circuit_dir)

    def _helper_parse_output(self, tool_result_raw: Path) -> ZkFuzzParsed:
        """Parse zkfuzz output and extract status and vulnerability string.

        Args:
            tool_result_raw: Path to raw tool output file

        Returns:
            ZkFuzzParsed object with detailed structured data
        """
        with open(tool_result_raw, "r", encoding="utf-8") as f:
            bug_info: list[str] = [line.strip() for line in f if line.strip()]

        status = ""
        vulnerability = ""
        signal = ""
        expected_value = ""
        assignments = {}

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

                    # Extract signal and expected value from "is expected to be" line
                    # Format: ➡️ `main.c` is expected to be `21888...`
                    for j in range(i, min(i + 10, len(bug_info))):
                        if "is expected to be" in bug_info[j]:
                            match = re.search(
                                r"`([^`]+)`\s+is expected to be\s+`([^`]+)`",
                                bug_info[j],
                            )
                            if match:
                                signal = match.group(1)
                                expected_value = match.group(2)
                            break

                    # Extract assignments from "Assignment Details" section
                    # Format: ➡️ main.a = 21888...
                    in_assignments = False
                    for j in range(i, min(i + 20, len(bug_info))):
                        if "Assignment Details" in bug_info[j]:
                            in_assignments = True
                            continue
                        if in_assignments:
                            # Stop at box border or new section
                            if bug_info[j].startswith("╚") or bug_info[
                                j
                            ].startswith("╔"):
                                break
                            # Parse assignment line: ➡️ main.a = 21888...
                            assign_match = re.search(
                                r"➡️\s*([^\s=]+)\s*=\s*(\S+)", bug_info[j]
                            )
                            if assign_match:
                                var_name = assign_match.group(1)
                                var_value = assign_match.group(2)
                                assignments[var_name] = var_value

                    break

        return ZkFuzzParsed(
            result=status,
            vulnerability=vulnerability,
            signal=signal,
            expected_value=expected_value,
            assignments=assignments,
        )

    def _helper_generate_uniform_results(
        self,
        parsed_output: ZkFuzzParsed,
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
        if parsed_output.result == "Timed out":
            analysis_status = AnalysisStatus.TIMEOUT
        elif parsed_output.result == "found_bug":
            analysis_status = AnalysisStatus.BUGS_FOUND
        elif parsed_output.result == "found_no_bug":
            analysis_status = AnalysisStatus.NO_BUGS
        else:
            analysis_status = AnalysisStatus.ERROR

        # Only add finding if bug found
        if parsed_output.result == "found_bug":
            # Determine bug type from vulnerability string
            if "under" in parsed_output.vulnerability.lower():
                bug_title = "Under-Constrained"
            elif "over" in parsed_output.vulnerability.lower():
                bug_title = "Over-Constrained"
            else:
                # Default to under-constrained for unknown types
                bug_title = "Under-Constrained"

            # Build description
            description = (
                f"Counter example found: {parsed_output.vulnerability}"
            )
            if parsed_output.signal and parsed_output.expected_value:
                description = f"Signal `{parsed_output.signal}` is expected to be `{parsed_output.expected_value}`"

            # Build metadata
            metadata = {"severity": "error"}
            if parsed_output.expected_value:
                metadata["expected_value"] = parsed_output.expected_value
            if parsed_output.assignments:
                metadata["assignments"] = parsed_output.assignments

            # Build position
            position = {}
            if parsed_output.signal:
                position["signal"] = parsed_output.signal

            finding = Finding(
                bug_title=bug_title,
                unified_bug_title=ZKFUZZ_TO_STANDARD.get(
                    bug_title, StandardizedBugCategory.UNDER_CONSTRAINED
                ),
                description=description,
                position=position,
                metadata=metadata,
            )
            findings.append(finding)

        return analysis_status, findings

    def compare_zkbugs_ground_truth(
        self,
        tool: str,
        dsl: str,
        bug_name: str,
        ground_truth: Path,
        tool_result_parsed: Path,
    ) -> Dict[str, Any]:
        """Compare zkfuzz findings against ground truth and update aggregates.

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

        tool_output_data = get_tool_result_parsed(tool_result_parsed)

        status: str = tool_output_data.get("result", "tool error")
        vulnerability: str = tool_output_data.get("vulnerability", "")

        # Load ground truth correctly (file path -> JSON)
        gt_data = self.load_json_file(ground_truth)
        gt_vulnerability = gt_data.get("Vulnerability")

        is_correct = False
        reason = ""

        if status == "Timed out":
            reason = "Reached zkhydra threshold."
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
        vulnerability_str = (
            (vulnerability or "").replace("-", "").replace(" ", "").lower()
        )
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
        elif reason == "Reached zkhydra threshold.":
            output = {"result": "timeout", "reason": reason}
        elif reason in ("tool error", "Tool Error"):
            output = {"result": "error", "reason": reason}
        elif reason == "Tool found previous errors":
            output = {"result": "error", "reason": reason}
        else:
            output = {"result": "false", "reason": reason}

        return output
