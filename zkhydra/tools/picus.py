import logging
import os
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

# Navigate from zkhydra/tools/picus.py to project root, then to tools/picus/
TOOL_DIR = Path(__file__).resolve().parent.parent.parent / "tools" / "picus"


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

    def generate_uniform_results(
        self,
        parsed_output: PicusParsed,
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

        for signal in parsed_output.signals_with_multiple_values:
            # Extract signal name without template prefix
            signal_only = (
                signal.name.rsplit(".", 1)[-1]
                if "." in signal.name
                else signal.name
            )

            # Build input description
            input_desc = ", ".join(
                [f"{k}={v}" for k, v in parsed_output.inputs.items()]
            )
            message = f"Signal `{signal.name}` can be `{signal.first_value}` or `{signal.second_value}` for inputs ({input_desc})"

            finding = UniformFinding(
                bug_type="Under-Constrained",
                severity="error",
                message=message,
                signal=signal_only,
                template=signal.template,
            )
            findings.append(finding.to_dict())

        results = {
            "status": parsed_output.result,
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
