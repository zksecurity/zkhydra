import logging
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import (
    AbstractTool,
    Finding,
    Input,
    OutputStatus,
    ToolOutput,
    UniformFinding,
    get_tool_result_parsed,
)


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

    def parse_findings(self, raw_output: str) -> List[Finding]:
        """Parse findings from circom_civer raw output.

        Extracts underconstrained bugs by looking for "could not verify weak safety"
        and extracting component names from the failed components list.

        Args:
            raw_output: Raw string output from circom_civer

        Returns:
            List of Finding objects with standardized structure
        """
        findings = []

        # Key indicator: "CIVER could not verify weak safety" means underconstrained bugs found
        # Also check for "Number of failed components (weak-safety): X" where X > 0

        if "could not verify weak safety" in raw_output:
            # Extract failed components
            lines = raw_output.split("\n")
            failed_components = []

            # Look for components that failed verification
            in_failed_section = False
            for line in lines:
                if "Components that do not satisfy weak safety:" in line:
                    in_failed_section = True
                    continue

                if in_failed_section:
                    # Stop when we hit the statistics or another section
                    if line.strip().startswith("*") or "----" in line:
                        break

                    # Extract component name (format: "    - ComponentName(), ")
                    stripped = line.strip()
                    if stripped.startswith("-") and "(" in stripped:
                        component = stripped[1:].strip().rstrip(",").strip()
                        failed_components.append(component)

            # Extract number of failed components from statistics
            match = re.search(
                r"Number of failed components.*:\s*(\d+)", raw_output
            )
            num_failed = (
                int(match.group(1)) if match else len(failed_components)
            )

            if failed_components:
                for component in failed_components:
                    findings.append(
                        Finding(
                            description=f"Component {component} does not satisfy weak safety",
                            bug_type="Weak-Safety-Violation",
                            raw_message=raw_output,
                            component=component,
                        )
                    )
            else:
                # Fallback if we couldn't parse component names
                findings.append(
                    Finding(
                        description=f"{num_failed} component(s) failed weak safety verification",
                        bug_type="Weak-Safety-Violation",
                        raw_message=raw_output,
                    )
                )

        elif (
            "verified weak safety" in raw_output
            or "verified components (weak-safety):" in raw_output
        ):
            # Check if all components were verified (no bugs)
            match_failed = re.search(
                r"Number of failed components.*:\s*(\d+)", raw_output
            )
            if match_failed and int(match_failed.group(1)) == 0:
                # All components verified = no findings (no bugs)
                pass
            else:
                # Some failed, extract them
                match = re.search(
                    r"Number of failed components.*:\s*(\d+)", raw_output
                )
                if match and int(match.group(1)) > 0:
                    findings.append(
                        Finding(
                            description=f"{match.group(1)} component(s) failed weak safety verification",
                            bug_type="underconstrained",
                            raw_message=raw_output,
                        )
                    )

        return findings

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
    ) -> None:
        """Generate uniform results.json file.

        Args:
            parsed_output: Parsed tool output
            tool_output: Tool execution output with timing info
            output_file: Path to write results.json
        """
        import json

        findings = []

        for component in parsed_output.buggy_components:
            params_str = (
                f"({', '.join(map(str, component.params))})"
                if component.params
                else ""
            )

            finding = UniformFinding(
                bug_type="Weak-Safety-Violation",
                severity="error",
                message=f"Component {component.name}{params_str} does not satisfy weak safety",
                component=component.name,
            )
            findings.append(finding.to_dict())

        # Determine overall status
        if parsed_output.buggy_components:
            status = "bugs_found"
        elif parsed_output.stats.get("timeout", 0):
            status = "timeout"
        else:
            status = "success"

        results = {
            "status": status,
            "execution_time": round(tool_output.execution_time, 2),
            "findings": findings,
        }

        return results

    def compare_zkbugs_ground_truth(
        self,
        tool: str,
        dsl: str,
        bug_name: str,
        ground_truth: Path,
        tool_result_parsed: Path,
    ) -> Dict[str, Any]:
        """Compare parsed tool output against ground-truth for a single bug.

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

        # Get ground truth data
        ground_truth_data = self.load_json_file(ground_truth)

        bug_location = ground_truth_data.get("Location", {})
        if not bug_location:
            logging.error(
                f"Location data for bug '{bug_name}' not found in ground truth."
            )
            output = {
                "result": "error",
                "reason": "Location data not found in ground truth.",
            }
            return output

        buggy_function: Optional[str] = bug_location.get("Function")
        # buggy_line: Optional[str] = bug_location.get("Line")
        # startline: int
        # endline: int
        # if buggy_line and "-" in buggy_line:
        #     start_str, end_str = buggy_line.split("-", 1)
        #     startline, endline = int(start_str), int(end_str)
        # elif not buggy_line:
        #     startline = endline = 0
        #     logging.warning(f"Line data for bug '{bug_name}' not found in ground truth.")
        # else:
        #     startline = endline = int(buggy_line)
        # logging.debug(
        #     f"Buggy function: {buggy_function}, startline: {startline}, endline: {endline}"
        # )

        tool_output_data = get_tool_result_parsed(tool_result_parsed)

        buggy_components: List[Any] = tool_output_data.get(
            "buggy_components", []
        )
        timed_out_components: List[Any] = tool_output_data.get(
            "timed_out_components", []
        )
        logging.debug(f"Buggy components: {buggy_components}")
        logging.debug(f"Timed out components: {timed_out_components}")

        is_correct = False
        timed_out = False
        last_comp_name: Optional[str] = None
        # last_lines: Optional[str] = None

        for component in buggy_components:
            if component == "Reached zkhydra threshold.":
                timed_out = True
                break
            comp_name = component.get("name")
            # comp_params = component.get("params", [])
            # logging.debug(
            #     f"Found buggy component in '{bug_name}': {comp_name} with params {comp_params}"
            # )
            logging.debug(
                f"Found buggy component in '{bug_name}': '{comp_name}'"
            )

            # params = comp_params
            # if not params:
            #     startline_tool = endline_tool = 0
            # elif len(params) == 1:
            #     startline_tool = endline_tool = params[0]
            # elif len(params) == 2:
            #     startline_tool, endline_tool = params[0], params[1]
            # else:
            #     logging.warning(f"Params should have at most 2 values; got {params}")
            #     continue
            last_comp_name = comp_name
            # last_lines = f"{startline_tool}-{endline_tool}"
            # logging.debug(
            #     f"Component lines: startline={startline_tool}, endline={endline_tool}"
            # )

            # Compare with ground truth
            if comp_name == buggy_function:
                logging.debug(
                    f"Component name matches buggy function: {comp_name}"
                )
                is_correct = True

                # # Check lines
                # if startline_tool == endline_tool == 0:
                #     logging.debug("Component lines not provided by tool")
                #     is_correct = True
                # elif startline_tool <= startline and endline_tool >= endline:
                #     logging.debug(
                #         f"Component lines match ground truth: startline={startline_tool}, endline={endline_tool}"
                #     )
                #     is_correct = True
                # else:
                #     logging.debug(
                #         f"Component lines do not match ground truth: startline={startline_tool}, endline={endline_tool}"
                #     )

            logging.debug(f"Component '{comp_name}' correctness: {is_correct}")

        if is_correct:
            output = {"result": "correct"}
        else:
            if timed_out:
                output = {
                    "result": "timeout",
                    "reason": "Reached zkhydra threshold.",
                }
            else:
                if not buggy_components:
                    reason = (
                        "Tool found no module that do not satisfy weak safety."
                    )
                    output = {
                        "result": "false",
                        "reason": reason,
                        "buggy_components": buggy_components,
                        "timed_out_components": timed_out_components,
                        "need_manual_evaluation": True,
                    }
                elif last_comp_name != buggy_function:
                    reason = f"Tool found wrong module; buggy module: '{buggy_function}'."
                    # reason = f"Tool found wrong module; buggy module: '{buggy_function}' ({buggy_line}))."
                    output = {
                        "result": "false",
                        "reason": reason,
                        "buggy_components": buggy_components,
                        "timed_out_components": timed_out_components,
                        "need_manual_evaluation": True,
                    }
                else:
                    reason = f"xxxxxxxxTool found correct module, but lines didn't match (tool found lines: "
                    # f"'{last_lines}'; buggy lines: '{startline}-{endline}')"
                    output = {
                        "result": "false",
                        "reason": reason,
                        "buggy_components": buggy_components,
                        "timed_out_components": timed_out_components,
                        "need_manual_evaluation": True,
                    }

        return output
