import logging
import os
import re
import sys
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

# Navigate from zkhydra/tools/picus.py to project root, then to tools/picus/
TOOL_DIR = Path(__file__).resolve().parent.parent.parent / "tools" / "picus"


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

    def parse_findings(self, raw_output: str) -> List[Finding]:
        """Parse Picus findings from raw output.

        Args:
            raw_output: Raw Picus output

        Returns:
            List of Finding objects
        """
        findings = []

        # Check if circuit is underconstrained
        if "The circuit is underconstrained" not in raw_output:
            return findings

        # Helper function to remove ANSI color codes
        def strip_ansi(text: str) -> str:
            return re.sub(r"\x1b\[[0-9;]*m", "", text)

        # Parse counterexample details
        lines = raw_output.split("\n")

        # Extract input signals
        inputs = {}
        in_inputs_section = False

        # Extract outputs (both first and second possible)
        first_outputs = {}
        second_outputs = {}
        in_first_outputs = False
        in_second_outputs = False

        for line in lines:
            # Remove ANSI color codes from the entire line first
            line = strip_ansi(line)
            stripped = line.strip()

            # Detect sections
            if stripped == "inputs:":
                in_inputs_section = True
                in_first_outputs = False
                in_second_outputs = False
                continue
            elif stripped == "first possible outputs:":
                in_inputs_section = False
                in_first_outputs = True
                in_second_outputs = False
                continue
            elif stripped == "second possible outputs:":
                in_inputs_section = False
                in_first_outputs = False
                in_second_outputs = True
                continue
            elif stripped.startswith(
                "first internal variables:"
            ) or stripped.startswith("second internal variables:"):
                # Stop parsing when we reach internal variables
                break

            # Parse signal assignments (format: "main.a: 0")
            if ":" in stripped and not stripped.endswith(":"):
                parts = stripped.rsplit(":", 1)
                if len(parts) == 2:
                    signal_name = parts[0].strip()
                    signal_value = parts[1].strip()

                    if in_inputs_section:
                        inputs[signal_name] = signal_value
                    elif in_first_outputs:
                        first_outputs[signal_name] = signal_value
                    elif in_second_outputs:
                        second_outputs[signal_name] = signal_value

        # Create findings for each output signal that has different values
        for signal_name in first_outputs:
            if signal_name in second_outputs:
                first_val = first_outputs[signal_name]
                second_val = second_outputs[signal_name]

                if first_val != second_val:
                    # Extract template/component name if signal has dot notation (e.g., "main.c")
                    template = None
                    signal_only = signal_name
                    if "." in signal_name:
                        parts = signal_name.rsplit(".", 1)
                        template = parts[0]
                        signal_only = parts[1]

                    # Build description with input context
                    input_desc = ", ".join(
                        [f"{k}={v}" for k, v in inputs.items()]
                    )
                    description = f"Under-constrained signal `{signal_name}` can be `{first_val}` or `{second_val}` for inputs ({input_desc})"

                    findings.append(
                        Finding(
                            description=description,
                            bug_type="Under-Constrained",
                            raw_message=raw_output,
                            signal=signal_only,
                            template=template,
                            metadata={
                                "first_value": first_val,
                                "second_value": second_val,
                                "inputs": inputs,
                            },
                        )
                    )

        # If we found underconstrained but no specific signals, create a generic finding
        if not findings and "The circuit is underconstrained" in raw_output:
            findings.append(
                Finding(
                    description="Circuit is underconstrained",
                    bug_type="Under-Constrained",
                    raw_message=raw_output,
                )
            )

        return findings

    def _helper_parse_output(
        self, tool_result_raw: Path
    ) -> Dict[str, Dict[str, Dict[str, Dict[str, Any]]]]:
        """Parse Picus output and classify the result.

        Args:
            tool_result_raw: Path to raw tool output file

        Returns:
            Dictionary with parsed result status
        """
        with open(tool_result_raw, "r", encoding="utf-8") as f:
            bug_info: list[str] = [line.strip() for line in f if line.strip()]

        status: str
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

        structured_info: Dict[str, Any] = {}

        structured_info = {
            "result": status,
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
