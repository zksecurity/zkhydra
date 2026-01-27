import logging
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

# Navigate from zkhydra/tools/ecneproject.py to project root, then to tools/ecneproject/
TOOL_DIR = (
    Path(__file__).resolve().parent.parent.parent / "tools" / "ecneproject"
)


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

    def parse_findings(self, raw_output: str) -> List[Finding]:
        """Parse EcneProject findings from raw output.

        Args:
            raw_output: Raw EcneProject output

        Returns:
            List of Finding objects
        """
        findings = []

        # Check for tool errors - these are not findings, just return empty
        if "Error while running" in raw_output:
            return findings

        # Check if circuit has potentially unsound constraints
        if (
            "R1CS function circuit has potentially unsound constraints"
            not in raw_output
        ):
            return findings

        # Parse the "Bad Constraints" section to extract details
        lines = raw_output.split("\n")
        in_bad_constraints = False
        current_constraint_num = None
        current_constraint_expr = None
        undetermined_variables = []

        for i, line in enumerate(lines):
            stripped = line.strip()

            # Detect sections
            if stripped == "------ Bad Constraints ------":
                in_bad_constraints = True
                continue
            elif stripped == "------ All Variables ------":
                in_bad_constraints = False
                break

            if in_bad_constraints:
                # Detect constraint number (e.g., "constraint #1")
                if stripped.startswith("constraint #"):
                    current_constraint_num = stripped
                    # Next line is the constraint expression
                    if i + 1 < len(lines):
                        current_constraint_expr = lines[i + 1].strip()
                    continue

                # Look for "Uniquely Determined: false" to identify problematic variables
                if stripped.startswith("Uniquely Determined: false"):
                    # Previous line should be the variable name
                    if i > 0:
                        var_name = lines[i - 1].strip()
                        if (
                            var_name
                            and not var_name.startswith("Uniquely")
                            and not var_name.startswith("Bounds")
                        ):
                            undetermined_variables.append(
                                {
                                    "variable": var_name,
                                    "constraint": current_constraint_num,
                                    "constraint_expr": current_constraint_expr,
                                }
                            )

        # Group variables by template/component and create ONE finding per component
        if undetermined_variables:
            # Remove duplicates and group by template
            seen_vars = {}
            for var_info in undetermined_variables:
                var_name = var_info["variable"]
                if var_name not in seen_vars:
                    seen_vars[var_name] = var_info

            # Group by template name
            templates = {}
            for var_name, var_info in seen_vars.items():
                template_name = "unknown"
                if "." in var_name:
                    template_name = var_name.split(".", 1)[0]

                if template_name not in templates:
                    templates[template_name] = []
                templates[template_name].append(var_info)

            # Create one finding per template/component
            for template_name, vars_list in templates.items():
                var_names = [v["variable"] for v in vars_list]
                var_count = len(var_names)

                # Create description
                if var_count == 1:
                    description = f"Component `{template_name}` has under-constrained variable: {var_names[0]}"
                else:
                    var_list_str = ", ".join(var_names[:3])
                    if var_count > 3:
                        var_list_str += f", ... ({var_count} total)"
                    description = f"Component `{template_name}` has {var_count} under-constrained variables: {var_list_str}"

                findings.append(
                    Finding(
                        description=description,
                        bug_type="Under-Constrained",
                        raw_message=raw_output,
                        template=template_name,
                        severity="warning",
                        metadata={
                            "undetermined_variables": var_names,
                            "variable_count": var_count,
                            "constraints": [
                                {
                                    "variable": v["variable"],
                                    "constraint": v["constraint"],
                                    "constraint_expr": v["constraint_expr"],
                                }
                                for v in vars_list
                            ],
                        },
                    )
                )

        # If we found the unsound message but no specific variables, create a generic finding
        if (
            not findings
            and "R1CS function circuit has potentially unsound constraints"
            in raw_output
        ):
            findings.append(
                Finding(
                    description="Circuit has potentially unsound constraints",
                    bug_type="Under-Constrained",
                    raw_message=raw_output,
                    severity="warning",
                )
            )

        return findings

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

    def generate_uniform_results(
        self,
        parsed_output: EcneProjectParsed,
        tool_output: ToolOutput,
        output_file: Path,
    ) -> None:
        """Generate uniform results.json file.

        Args:
            parsed_output: Parsed tool output
            tool_output: Tool execution output with timing info
            output_file: Path to write results.json
        """
        import json

        findings = []

        # Only add finding if unsound constraints detected
        if parsed_output.constraint_status == "unsound":
            finding = UniformFinding(
                bug_type="Unsound-Constraint",
                severity="error",
                message="R1CS function circuit has potentially unsound constraints",
            )
            findings.append(finding.to_dict())

        # Determine status
        if parsed_output.result == "Timed out":
            status = "timeout"
        elif parsed_output.constraint_status == "unsound":
            status = "bugs_found"
        elif parsed_output.constraint_status == "sound":
            status = "success"
        else:
            status = "error"

        results = {
            "status": status,
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

        if (
            tool_result
            == "R1CS function circuit has potentially unsound constraints"
        ):
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
            output = {
                "result": "timeout",
                "reason": "Reached zkhydra threshold.",
            }
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
