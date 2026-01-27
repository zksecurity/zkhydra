import logging
from pathlib import Path
from typing import Any, Dict, List

from .base import AbstractTool, Finding, get_tool_result_parsed

# Navigate from zkhydra/tools/ecneproject.py to project root, then to tools/ecneproject/
TOOL_DIR = Path(__file__).resolve().parent.parent.parent / "tools" / "ecneproject"


class EcneProject(AbstractTool):
    """EcneProject constraint analysis tool for Circom circuits."""

    def __init__(self):
        super().__init__("ecneproject")

    def execute(self, bug_path: str, timeout: int) -> str:
        """Run EcneProject (Julia) against the bug's R1CS and sym files.

        Args:
            bug_path: Absolute path to the bug directory containing artifacts.
            timeout: Maximum execution time in seconds.

        Returns:
            Raw tool output, or a bracketed error marker string.
        """
        logging.debug(f"ECNEPROJECT_DIR='{TOOL_DIR}'")
        logging.debug(f"bug_path='{bug_path}'")

        circuit_file = Path(bug_path) / "circuits" / "circuit.circom"
        r1cs_file = Path(bug_path) / "circuit.r1cs"
        sym_file = Path(bug_path) / "circuit.sym"
        if not self.check_files_exist(circuit_file, r1cs_file, sym_file):
            return "[Circuit file not found]"

        if not self.check_binary_exists("julia"):
            return "[Binary not found: install Julia]"

        # Ensure project and entrypoint exist
        ecne_entry = TOOL_DIR / "src" / "Ecne.jl"
        if not ecne_entry.is_file():
            logging.error(f"Ecne.jl not found at {ecne_entry}")
            return "[Binary not found: Ecne.jl entrypoint missing]"

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
        result = self.run_command(cmd, timeout, bug_path)

        return result

    def parse_findings(self, raw_output: str) -> List[Finding]:
        """Parse EcneProject findings from raw output.

        Args:
            raw_output: Raw EcneProject output

        Returns:
            List of Finding objects
        """
        findings = []
        # TODO: Implement EcneProject-specific parsing logic
        # For now, return empty list - parsing will be done by parse_output for evaluate mode
        return findings

    def parse_output(
        self, tool_result_raw: Path, ground_truth: Path
    ) -> Dict[str, Dict[str, Dict[str, Dict[str, Any]]]]:
        """Parse EcneProject output into a small structured summary.

        Args:
            tool_result_raw: Path to raw tool output file
            ground_truth: Path to ground truth JSON file

        Returns:
            Dictionary with parsed result
        """
        with open(tool_result_raw, "r", encoding="utf-8") as f:
            bug_info = [line.strip() for line in f if line.strip()]

        # Default to an explicit value so downstream comparison can categorize it
        result = "No result"

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
                    break

                if (
                    "R1CS function circuit has sound constraints (No trusted functions needed!)"
                    in line
                ):
                    result = "R1CS function circuit has sound constraints (No trusted functions needed!)"
                    break

        # Legacy heuristic: sometimes the interesting line appears two lines before 'stderr:'
        if result == "No result":
            for i, line in enumerate(bug_info):
                if line == "stderr:" and i >= 2:
                    result = bug_info[i - 2]
                    break

        structured_info: Dict[str, Any] = {}

        structured_info = {
            "result": result,
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
        """Compare EcneProject result to expectations and update aggregate output.

        EcneProject is heuristic; we treat its positive message as a correct detection
        and handle timeouts/missing files explicitly. Otherwise it's a false/unknown.

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

        tool_result: str = get_tool_result_parsed(tool_result_parsed).get(
            "result", "No result"
        )

        if tool_result == "R1CS function circuit has potentially unsound constraints":
            output = {"result": "correct"}
        elif (
            tool_result
            == "R1CS function circuit has sound constraints (No trusted functions needed!)"
        ):
            output = {
                "result": "false",
                "reason": "Tool found sound constraints but the circuit is unsound.",
            }
        elif tool_result == "Timed out":
            output = {"result": "timeout", "reason": "Reached zkhydra threshold."}
        elif tool_result == "Circuit file not found":
            output = {
                "result": "error",
                "reason": "Circuit file not found. Might be missing in bug environment setup script.",
            }
        else:
            output = {
                "result": "false",
                "reason": "Missing or inconclusive result from parsing.",
            }

        return output


# Create a singleton instance for the registry
_ecneproject_instance = EcneProject()
