import logging
import re
from pathlib import Path
from typing import Any, Dict, List

from .base import (
    AbstractTool,
    Finding,
    Input,
    OutputStatus,
    ToolOutput,
    get_tool_result_parsed,
)


class ZkFuzz(AbstractTool):
    """zkFuzz fuzzing tool for Circom circuits."""

    def __init__(self):
        super().__init__("zkfuzz")

    def execute(self, input_paths: Input, timeout: int) -> ToolOutput:
        """Run zkfuzz on the given circuit.

        Args:
            input_paths: Input object containing circuit_dir and circuit_file paths
            timeout: Maximum execution time in seconds

        Returns:
            ToolOutput object with execution results
        """
        logging.debug(f"circuit_dir='{input_paths.circuit_dir}'")
        logging.debug(f"circuit_file='{input_paths.circuit_file}'")

        circuit_file_path = Path(input_paths.circuit_file)
        if not self.check_files_exist(circuit_file_path):
            return ToolOutput(
                status=OutputStatus.FAIL,
                stdout="",
                stderr="",
                return_code=-1,
                msg="[Circuit file not found]",
            )

        # Check if zkfuzz is in PATH
        if not self.check_binary_exists("zkfuzz"):
            return ToolOutput(
                status=OutputStatus.FAIL,
                stdout="",
                stderr="",
                return_code=-1,
                msg="[Binary not found: install zkfuzz]",
            )

        cmd = ["zkfuzz", str(circuit_file_path)]
        return self.run_command(cmd, timeout, input_paths.circuit_dir)

    def parse_findings(self, raw_output: str) -> List[Finding]:
        """Parse findings from zkfuzz raw output.

        Extracts underconstrained bugs by looking for "NOT SAFE" or "Counter Example Found"
        indicators and extracting signal/component information.

        Args:
            raw_output: Raw string output from zkfuzz

        Returns:
            List of Finding objects with standardized structure
        """
        findings = []

        # Key indicators in "Verification" line:
        # "💥 NOT SAFE 💥" = bug found (actual output)
        # "❌ Counter Example Found" = bug found (from user's examples)
        # "🆗 No Counter Example Found" = no bug
        # Extract signal info from "🚨 Counter Example:" section or "💣 Target" line

        # Check for bugs - must check "No Counter Example" first to avoid false positives
        if "🆗 No Counter Example Found" in raw_output:
            # No bug found - no findings to add
            pass
        elif (
            "💥 NOT SAFE 💥" in raw_output
            or "❌ Counter Example Found" in raw_output
        ):
            # Bug found - try to extract signal/target information
            lines = raw_output.split("\n")
            signal_info = None
            target_info = None

            # First try to extract from "🚨 Counter Example:" section
            # Format: "║           ➡️ `main.c` is expected to be `0`"
            in_counter_example = False
            for line in lines:
                if "🚨 Counter Example:" in line:
                    in_counter_example = True
                    continue

                if in_counter_example:
                    # Stop at the end of the box
                    if "╚═" in line:
                        break

                    # Look for "is expected to be" line to identify the problematic signal
                    if "is expected to be" in line and "➡️" in line:
                        # Extract signal name: "`main.c` is expected to be `0`"
                        match = re.search(
                            r"`([^`]+)`\s+is expected to be", line
                        )
                        if match:
                            signal_info = match.group(1)
                            break

            # Also try to extract from "💣 Target" line (format from user's examples)
            for line in lines:
                if (
                    "💣 Target" in line or "Target" in line
                ) and "signal" in line:
                    if ":" in line:
                        target_info = line.split(":", 1)[1].strip()
                        # Parse signal and template from target_info
                        # Format: "signal `out` in template `Multiplier`"
                        signal_match = re.search(
                            r"signal `([^`]+)`", target_info
                        )
                        template_match = re.search(
                            r"template `([^`]+)`", target_info
                        )

                        if signal_match:
                            signal_name = signal_match.group(1)
                            template_name = (
                                template_match.group(1)
                                if template_match
                                else "unknown"
                            )

                            findings.append(
                                Finding(
                                    description=f"Counter example found for signal `{signal_name}` in template `{template_name}`",
                                    bug_type="Under-Constrained",
                                    signal=signal_name,
                                    template=template_name,
                                )
                            )
                        break

            # If we found signal_info but not target_info, use signal_info
            if signal_info and not target_info:
                findings.append(
                    Finding(
                        description=f"Counter example found for signal `{signal_info}`",
                        bug_type="Under-Constrained",
                        signal=signal_info,
                    )
                )
            elif not signal_info and not target_info:
                # Fallback if we couldn't parse any details
                findings.append(
                    Finding(
                        description="Circuit is not safe",
                        bug_type="Under-Constrained",
                    )
                )

        return findings

    def parse_output(
        self, tool_result_raw: Path, ground_truth: Path
    ) -> Dict[str, Dict[str, Dict[str, Dict[str, Any]]]]:
        """Parse zkfuzz output and extract status and vulnerability string.

        Args:
            tool_result_raw: Path to raw tool output file
            ground_truth: Path to ground truth JSON file

        Returns:
            Dictionary with parsed result and vulnerability
        """
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


# Create a singleton instance for the registry
_zkfuzz_instance = ZkFuzz()
