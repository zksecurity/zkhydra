import logging
import os
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

# Navigate from zkhydra/tools/picus.py to project root, then to tools/picus/
TOOL_DIR = Path(__file__).resolve().parent.parent.parent / "tools" / "picus"

# Mapping from picus bug names to standardized categories
PICUS_TO_STANDARD = {
    "Under-Constrained Signal": StandardizedBugCategory.UNDER_CONSTRAINED,
}


@dataclass
class PicusSignal:
    """Signal that can take multiple values (underconstrained)."""

    name: str
    first_value: str
    second_value: str
    template: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            "name": self.name,
            "first_value": self.first_value,
            "second_value": self.second_value,
        }
        if self.template:
            result["template"] = self.template
        return result


@dataclass
class PicusParsed:
    """Structured parsed output from Picus tool.

    Contains detailed circuit analysis results.
    """

    # Tool-specific status
    result: str  # "Underconstrained", "Properly Constrained", "Timed out", etc.
    # Detailed signal information
    signals_with_multiple_values: List[PicusSignal] = field(
        default_factory=list
    )
    # Counterexample details
    inputs: Dict[str, str] = field(default_factory=dict)
    first_outputs: Dict[str, str] = field(default_factory=dict)
    second_outputs: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "result": self.result,
            "signals_with_multiple_values": [
                sig.to_dict() for sig in self.signals_with_multiple_values
            ],
            "counterexample": {
                "inputs": self.inputs,
                "first_outputs": self.first_outputs,
                "second_outputs": self.second_outputs,
            },
        }


class Picus(AbstractTool):
    """Picus under-constraint detection tool for Circom circuits."""

    def __init__(self):
        super().__init__("picus")
        run_script = TOOL_DIR / "run-picus"
        if not run_script.is_file():
            logging.error(f"run-picus not found at {run_script}")
            sys.exit(1)
        if not os.access(run_script, os.X_OK):
            logging.error(f"run-picus is not executable: {run_script}")
            sys.exit(1)

    def _internal_execute(self, input_paths: Input, timeout: int) -> ToolOutput:
        """Run Picus on the given circuit.

        Args:
            input_paths: Input object containing circuit_dir and circuit_file paths
            timeout: Maximum execution time in seconds

        Returns:
            ToolOutput object with execution results
        """
        circuit_file_path = Path(input_paths.circuit_file)

        run_script = TOOL_DIR / "run-picus"

        current_dir = Path.cwd()
        self.change_directory(TOOL_DIR)

        cmd = [str(run_script), str(circuit_file_path)]
        result = self.run_command(cmd, timeout, input_paths.circuit_dir)
        self.change_directory(current_dir)
        return result

    def _helper_parse_output(self, tool_result_raw: Path) -> PicusParsed:
        """Parse Picus output and classify the result.

        Args:
            tool_result_raw: Path to raw tool output file

        Returns:
            PicusParsed object with detailed structured data
        """
        with open(tool_result_raw, "r", encoding="utf-8") as f:
            bug_info: list[str] = [line.strip() for line in f if line.strip()]

        # Helper function to remove ANSI color codes
        def strip_ansi(text: str) -> str:
            return re.sub(r"\x1b\[[0-9;]*m", "", text)

        # Clean ANSI codes from all lines
        bug_info = [strip_ansi(line) for line in bug_info]

        status: str
        signals_with_multiple_values: List[PicusSignal] = []
        inputs = {}
        first_outputs = {}
        second_outputs = {}

        if not bug_info:
            status = "No result"
        elif any(line == "[Timed out]" for line in bug_info):
            status = "Timed out"
        elif any(line == "[Circuit file not found]" for line in bug_info):
            status = "Circuit file not found"
        elif any(
            line == "The circuit is underconstrained" for line in bug_info
        ):
            status = "Underconstrained"

            # Parse counterexample to extract signals with multiple values
            in_inputs_section = False
            in_first_outputs = False
            in_second_outputs = False

            for line in bug_info:
                # Detect sections
                if line == "inputs:":
                    in_inputs_section = True
                    in_first_outputs = False
                    in_second_outputs = False
                    continue
                elif line == "first possible outputs:":
                    in_inputs_section = False
                    in_first_outputs = True
                    in_second_outputs = False
                    continue
                elif line == "second possible outputs:":
                    in_inputs_section = False
                    in_first_outputs = False
                    in_second_outputs = True
                    continue
                elif line.startswith(
                    "first internal variables:"
                ) or line.startswith("second internal variables:"):
                    break

                # Parse signal assignments (format: "main.a: 0")
                if ":" in line and not line.endswith(":"):
                    parts = line.rsplit(":", 1)
                    if len(parts) == 2:
                        signal_name = parts[0].strip()
                        signal_value = parts[1].strip()

                        if in_inputs_section:
                            inputs[signal_name] = signal_value
                        elif in_first_outputs:
                            first_outputs[signal_name] = signal_value
                        elif in_second_outputs:
                            second_outputs[signal_name] = signal_value

            # Find signals with different values
            for signal_name in first_outputs:
                if signal_name in second_outputs:
                    first_val = first_outputs[signal_name]
                    second_val = second_outputs[signal_name]

                    if first_val != second_val:
                        # Extract template
                        template = None
                        if "." in signal_name:
                            parts = signal_name.rsplit(".", 1)
                            template = parts[0]

                        signal = PicusSignal(
                            name=signal_name,
                            first_value=first_val,
                            second_value=second_val,
                            template=template,
                        )
                        signals_with_multiple_values.append(signal)

        elif any(
            line == "The circuit is properly constrained" for line in bug_info
        ):
            status = "Properly Constrained"
        elif any(
            line
            == "Cannot determine whether the circuit is properly constrained"
            for line in bug_info
        ):
            status = "Tool cannot determine whether the circuit is properly constrained"
        else:
            status = "Tool Error"

        return PicusParsed(
            result=status,
            signals_with_multiple_values=signals_with_multiple_values,
            inputs=inputs,
            first_outputs=first_outputs,
            second_outputs=second_outputs,
        )

    def _helper_generate_uniform_results(
        self,
        parsed_output: PicusParsed,
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
        elif parsed_output.result == "Underconstrained":
            analysis_status = AnalysisStatus.BUGS_FOUND
        elif parsed_output.result == "Properly Constrained":
            analysis_status = AnalysisStatus.NO_BUGS
        else:
            analysis_status = AnalysisStatus.ERROR

        for signal in parsed_output.signals_with_multiple_values:
            # Build input description
            input_desc = ", ".join(
                [f"{k}={v}" for k, v in parsed_output.inputs.items()]
            )
            message = f"Signal `{signal.name}` can be `{signal.first_value}` or `{signal.second_value}` for inputs ({input_desc})"

            bug_title = "Under-Constrained Signal"
            finding = Finding(
                bug_title=bug_title,
                unified_bug_title=PICUS_TO_STANDARD[bug_title],
                description=message,
                position={
                    "signal": signal.name,  # Full signal name like "main.c"
                },
                metadata={
                    "severity": "error",
                    "inputs": parsed_output.inputs,
                    "first_value": signal.first_value,
                    "second_value": signal.second_value,
                },
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
        """Compare Picus classification to ground truth and update aggregate output.

        Args:
            tool: Tool name
            dsl: Domain-specific language
            bug_name: Bug name
            ground_truth: Path to ground truth JSON
            tool_result_parsed: Path to parsed tool results

        Returns:
            Comparison result dictionary
        """
        logging.debug(
            "When picus finds a bug, we assume it found the correct one. We can check if the bug is supposed to be underconstrained."
        )
        output = {}

        gt_data = self.load_json_file(ground_truth)

        tool_result: str = get_tool_result_parsed(tool_result_parsed).get(
            "result", "No result"
        )

        is_correct = False
        reason = ""

        if (
            tool_result == "Underconstrained"
            and gt_data.get("Vulnerability") == "Under-Constrained"
        ):
            is_correct = True
        elif tool_result == "Timed out":
            reason = "Reached zkhydra threshold."
        elif (
            tool_result
            == "Tool cannot determine whether the circuit is properly constrained"
        ):
            reason = "Tool cannot determine whether the circuit is properly constrained"
        elif tool_result == "Tool Error":
            reason = "Picus Tool Error"
        elif tool_result == "Properly Constrained":
            reason = "Tool says circuit is properly constrained."
        elif tool_result == "Circuit file not found":
            reason = "Circuit file not found"
        elif tool_result == "No result":
            reason = "No result"

        if is_correct:
            output = {"result": "correct"}
        elif reason == "Reached zkhydra threshold.":
            output = {"result": "timeout", "reason": reason}
        elif reason == "Picus Tool Error":
            output = {"result": "error", "reason": reason}
        elif reason == "Circuit file not found":
            output = {"result": "error", "reason": reason}
        else:
            output = {"result": "false", "reason": reason}

        return output
