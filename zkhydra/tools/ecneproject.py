import logging
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

# Navigate from zkhydra/tools/ecneproject.py to project root, then to tools/ecneproject/
TOOL_DIR = (
    Path(__file__).resolve().parent.parent.parent / "tools" / "ecneproject"
)

# Mapping from ecneproject bug names to standardized categories
ECNEPROJECT_TO_STANDARD = {
    "Unsound-Constraint": StandardizedBugCategory.UNDER_CONSTRAINED,
}


@dataclass
class EcneProjectParsed:
    """Structured parsed output from EcneProject tool.

    Contains detailed execution result.
    """

    # Tool-specific result message
    result: (
        str  # "R1CS function circuit has potentially unsound constraints", etc.
    )
    # Additional context
    constraint_status: Optional[str] = None  # "sound", "unsound", None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = {"result": self.result}
        if self.constraint_status:
            data["constraint_status"] = self.constraint_status
        return data


class EcneProject(AbstractTool):
    """EcneProject constraint analysis tool for Circom circuits."""

    def __init__(self):
        super().__init__("ecneproject")
        if not self.check_binary_exists("circom"):
            logging.error("[Circom not found: install Circom]")
            sys.exit(1)
        if not self.check_binary_exists("julia"):
            logging.error("[Julia not found: install Julia]")
            sys.exit(1)
        ecne_entry = TOOL_DIR / "src" / "Ecne.jl"
        if not ecne_entry.is_file():
            logging.error(f"Ecne.jl not found at {ecne_entry}")
            sys.exit(1)

    def _internal_execute(self, input_paths: Input, timeout: int) -> ToolOutput:
        """Run EcneProject (Julia) against the circuit's R1CS and sym files.

        Args:
            input_paths: Input object containing circuit_dir and circuit_file paths
            timeout: Maximum execution time in seconds

        Returns:
            ToolOutput object with execution results
        """
        # EcneProject needs R1CS and sym files from the circuit directory
        circuit_file_path = Path(input_paths.circuit_file)
        cmd = [
            "circom",
            str(circuit_file_path),
            "--r1cs",
            "--sym",
            "--output",
            input_paths.circuit_dir,
        ]
        circom_output = self.run_command(cmd, timeout, input_paths.circuit_dir)
        if circom_output.status != OutputStatus.SUCCESS:
            return ToolOutput(
                status=OutputStatus.FAIL,
                stdout=circom_output.stdout,
                stderr=circom_output.stderr,
                return_code=circom_output.return_code,
                msg=f"[Circom failed: {circom_output.msg}]",
            )

        # Now we need to find the R1CS and sym files
        # The r1cs should end with .r1cs and the sym should end with .sym
        r1cs_file = next(
            (f for f in Path(input_paths.circuit_dir).glob("*.r1cs")), None
        )
        sym_file = next(
            (f for f in Path(input_paths.circuit_dir).glob("*.sym")), None
        )
        if not r1cs_file or not sym_file:
            return ToolOutput(
                status=OutputStatus.FAIL,
                stdout=circom_output.stdout,
                stderr=circom_output.stderr,
                return_code=circom_output.return_code,
                msg=f"[R1CS or sym file not found: {circom_output.msg}]",
            )

        # Ensure project and entrypoint exist
        ecne_entry = TOOL_DIR / "src" / "Ecne.jl"

        current_dir = Path.cwd()
        self.change_directory(TOOL_DIR)

        cmd = [
            "julia",
            f"--project={TOOL_DIR}",
            str(ecne_entry),
            "--r1cs",
            str(r1cs_file),
            "--name",
            "circuit",
            "--sym",
            str(sym_file),
        ]
        result = self.run_command(cmd, timeout, input_paths.circuit_dir)
        self.change_directory(current_dir)

        # remove the R1CS and sym files
        r1cs_file.unlink()
        sym_file.unlink()

        return result

    def _helper_parse_output(self, tool_result_raw: Path) -> EcneProjectParsed:
        """Parse EcneProject output into a structured format.

        Args:
            tool_result_raw: Path to raw tool output file

        Returns:
            EcneProjectParsed object with detailed structured data
        """
        with open(tool_result_raw, "r", encoding="utf-8") as f:
            bug_info = [line.strip() for line in f if line.strip()]

        # Default to an explicit value so downstream comparison can categorize it
        result = "No result"
        constraint_status = None

        # Fast checks for common sentinel lines
        for line in bug_info:
            if line == "[Timed out]":
                result = "Timed out"
                break
            # When setup script doesn't work, r1cs and sym files are not created
            if line == "[Circuit file not found]":
                result = "Circuit file not found"
                break

        # If still undecided, try to detect the EcneProject success message anywhere
        if result == "No result":
            for line in bug_info:
                if (
                    "R1CS function" in line
                    and "potentially unsound constraints" in line
                ):
                    result = "R1CS function circuit has potentially unsound constraints"
                    constraint_status = "unsound"
                    break

                if (
                    "R1CS function circuit has sound constraints (No trusted functions needed!)"
                    in line
                ):
                    result = "R1CS function circuit has sound constraints (No trusted functions needed!)"
                    constraint_status = "sound"
                    break

        # Legacy heuristic: sometimes the interesting line appears two lines before 'stderr:'
        if result == "No result":
            for i, line in enumerate(bug_info):
                if line == "stderr:" and i >= 2:
                    result = bug_info[i - 2]
                    break

        return EcneProjectParsed(
            result=result,
            constraint_status=constraint_status,
        )

    def _helper_generate_uniform_results(
        self,
        parsed_output: EcneProjectParsed,
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
        elif parsed_output.constraint_status == "unsound":
            analysis_status = AnalysisStatus.BUGS_FOUND
        elif parsed_output.constraint_status == "sound":
            analysis_status = AnalysisStatus.NO_BUGS
        else:
            analysis_status = AnalysisStatus.ERROR

        # Only add finding if unsound constraints detected
        if parsed_output.constraint_status == "unsound":
            bug_title = "Unsound-Constraint"
            finding = Finding(
                bug_title=bug_title,
                unified_bug_title=ECNEPROJECT_TO_STANDARD[bug_title],
                description="R1CS function circuit has potentially unsound constraints",
                metadata={"severity": "error"},
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
        """Evaluate EcneProject results against ground truth.

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

        # Load tool results
        tool_results = self.load_json_file(tool_result_path)
        findings = tool_results.get("findings", [])

        # If no findings and ground truth is Under-Constrained, it's FalseNegative
        if not findings:
            if gt_vulnerability == "Under-Constrained":
                return {
                    "status": "FalseNegative",
                    "reason": "Tool found no unsound constraints",
                    "need_manual_analysis": False,
                    "manual_analysis": "N/A",
                    "manual_analysis_reasoning": "N/A",
                }
            else:
                # Tool correctly found nothing (not an under-constrained bug)
                return {
                    "status": "Undecided",
                    "reason": f"Tool found nothing, ground truth is {gt_vulnerability}",
                    "need_manual_analysis": True,
                    "manual_analysis": "Pending",
                    "manual_analysis_reasoning": "TODO",
                }

        # Tool found unsound constraints
        # EcneProject is circuit-level, doesn't provide precise location
        # So we can only verify the vulnerability type matches
        for finding in findings:
            unified_title = finding.get("unified_bug_title", "")
            if (
                unified_title == "Under-Constrained"
                and gt_vulnerability == "Under-Constrained"
            ):
                # Conservative: needs manual analysis because EcneProject is circuit-level
                return {
                    "status": "Undecided",
                    "reason": "EcneProject found unsound constraints but cannot verify exact location",
                    "need_manual_analysis": True,
                    "manual_analysis": "Pending",
                    "manual_analysis_reasoning": "TODO",
                }

        # Found something but doesn't match ground truth
        return {
            "status": "Undecided",
            "reason": f"Tool found {len(findings)} issues but ground truth is {gt_vulnerability}",
            "need_manual_analysis": True,
            "manual_analysis": "Pending",
            "manual_analysis_reasoning": "TODO",
        }
