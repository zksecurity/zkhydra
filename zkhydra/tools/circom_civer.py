import logging
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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

# Mapping from circom_civer bug names to standardized categories
CIVER_TO_STANDARD = {
    "Weak-Safety-Violation": StandardizedBugCategory.UNDER_CONSTRAINED,
}


@dataclass
class CiverComponent:
    """Represents a circuit component analyzed by circom_civer."""

    name: str
    params: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "params": self.params,
        }


@dataclass
class CiverParsed:
    """Structured parsed output from circom-civer tool.

    Contains detailed execution stats and component lists.
    """

    # Execution stats
    stats: Dict[str, Optional[int]] = field(default_factory=dict)
    # Component lists with details
    buggy_components: List[CiverComponent] = field(default_factory=list)
    timed_out_components: List[CiverComponent] = field(default_factory=list)
    verified_components: List[CiverComponent] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "stats": self.stats,
            "buggy_components": [
                comp.to_dict() for comp in self.buggy_components
            ],
            "timed_out_components": [
                comp.to_dict() for comp in self.timed_out_components
            ],
            "verified_components": [
                comp.to_dict() for comp in self.verified_components
            ],
        }


class CircomCiver(AbstractTool):
    """Circom-civer formal verification tool for Circom circuits."""

    def __init__(self):
        super().__init__("circom_civer")
        # Check if civer_circom is in PATH
        if not self.check_binary_exists("civer_circom"):
            logging.error("[Binary not found: install civer_circom]")
            sys.exit(1)

    def _internal_execute(self, input_paths: Input, timeout: int) -> ToolOutput:
        """Run circom-civer on a given circuit.

        Args:
            input_paths: Input object containing circuit_dir and circuit_file paths
            timeout: Maximum execution time in seconds

        Returns:
            ToolOutput object with execution results
        """
        circuit_file_path = Path(input_paths.circuit_file)

        cmd = [
            "civer_circom",
            str(circuit_file_path),
            "--check_safety",
            "--verbose",
            "--verification_timeout",
            "500000",
            "--O0",
        ]
        return self.run_command(cmd, timeout, input_paths.circuit_dir)

    def _helper_parse_output(
        self,
        tool_result_raw: Path,
    ) -> CiverParsed:
        """Parse circom-civer raw output into a structured format.

        Args:
            tool_result_raw: Path to raw tool output file

        Returns:
            CiverParsed object with structured data and uniform findings
        """
        with open(tool_result_raw, "r", encoding="utf-8") as f:
            bug_info: list[str] = [line.strip() for line in f if line.strip()]

        structured_info: Dict[str, Any] = {}

        stats: Dict[str, Optional[int]] = {
            "verified": None,
            "failed": None,
            "timeout": None,
        }
        buggy_components: List[CiverComponent] = []
        timed_out_components: List[CiverComponent] = []
        verified_components: List[CiverComponent] = []

        context: Optional[str] = None

        # Helper function for stats parsing
        def _safe_int_from_line(pattern: str, text: str) -> Optional[int]:
            m = re.search(pattern, text)
            if m:
                try:
                    return int(m.group(1))
                except (ValueError, TypeError):
                    return None
            return None

        for raw_line in bug_info:
            line = (raw_line or "").strip()
            if line == "[Timed out]":
                context = "timeout"
                # Keep empty lists for components
                continue

            # --- Track context (which section we are in) ---
            if line.startswith("Components that do not satisfy weak safety"):
                context = "buggy"
                continue
            elif line.startswith(
                "Components timeout when checking weak-safety"
            ):
                context = "timeout"
                continue
            elif line.startswith("Components that satisfy weak safety"):
                context = "verified"
                continue
            elif line.startswith("Components that failed verification"):
                context = "failed"
                continue
            elif line == "":
                context = None  # reset only on empty line
                continue

            # --- Match component lines ---
            if line.startswith("-"):
                comp_match = re.match(
                    r"-\s*([A-Za-z0-9_]+)\(([\d,\s]*)\)", line
                )
                if comp_match:
                    comp_name, numbers = comp_match.groups()
                    nums = [
                        int(n.strip()) for n in numbers.split(",") if n.strip()
                    ]
                    component = CiverComponent(name=comp_name, params=nums)

                    if context == "buggy":
                        buggy_components.append(component)
                    elif context == "timeout":
                        timed_out_components.append(component)
                    elif context == "verified":
                        verified_components.append(component)

            # --- Stats parsing ---
            if "Number of verified components" in line:
                stats["verified"] = _safe_int_from_line(r"(\d+)$", line)
            elif "Number of failed components" in line:
                stats["failed"] = _safe_int_from_line(r"(\d+)$", line)
            elif "Number of timeout components" in line:
                stats["timeout"] = _safe_int_from_line(r"(\d+)$", line)

        return CiverParsed(
            stats=stats,
            buggy_components=buggy_components,
            timed_out_components=timed_out_components,
            verified_components=verified_components,
        )

    def _helper_generate_uniform_results(
        self, parsed_output: CiverParsed, tool_output: ToolOutput
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
        if parsed_output.buggy_components:
            analysis_status = AnalysisStatus.BUGS_FOUND
        elif parsed_output.stats.get("timeout", 0):
            analysis_status = AnalysisStatus.TIMEOUT
        else:
            analysis_status = AnalysisStatus.NO_BUGS

        for component in parsed_output.buggy_components:
            params_str = (
                f"({', '.join(map(str, component.params))})"
                if component.params
                else ""
            )

            bug_title = "Weak-Safety-Violation"
            finding = Finding(
                bug_title=bug_title,
                unified_bug_title=CIVER_TO_STANDARD[bug_title],
                description=f"Component {component.name}{params_str} does not satisfy weak safety",
                position={
                    "component": component.name,
                },
                metadata={
                    "severity": "error",
                    "params": component.params,
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
        """Evaluate circom_civer results against ground truth.

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
        gt_location = gt_data.get("location", {})
        gt_function = gt_location.get("Function")

        # Load tool results
        tool_results = self.load_json_file(tool_result_path)
        findings = tool_results.get("findings", [])

        # If no findings, it's FalseNegative
        if not findings:
            return {
                "status": "FalseNegative",
                "reason": "Tool found no components with weak safety violations",
                "need_manual_analysis": False,
                "manual_analysis": "N/A",
                "manual_analysis_reasoning": "N/A",
            }

        # Check if any finding matches the ground truth function/component
        for finding in findings:
            position = finding.get("position", {})
            component = position.get("component")

            if component and gt_function and component == gt_function:
                # Exact match: component name matches
                return {
                    "status": "TruePositive",
                    "reason": f"Found weak safety violation in component {gt_function}",
                    "need_manual_analysis": False,
                    "manual_analysis": "N/A",
                    "manual_analysis_reasoning": "N/A",
                }

        # Found violations but not in the expected component
        return {
            "status": "Undecided",
            "reason": f"Tool found {len(findings)} weak safety violations but not in {gt_function}",
            "need_manual_analysis": True,
            "manual_analysis": "Pending",
            "manual_analysis_reasoning": "TODO",
        }
