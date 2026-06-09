import json
import logging
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .base import (
    EXIT_CODES,
    AbstractTool,
    AnalysisStatus,
    Finding,
    Input,
    OutputStatus,
    StandardizedBugCategory,
    ToolOutput,
)


@dataclass
class ConsCSFinding:
    """Represents a single finding from ConsCS."""

    file: str  # e.g., "Edwards2Montgomery@montgomery.circom"
    type: str  # e.g., "UNDER-CONSTRAINED", "CONSTRAINED", "NOT SURE", "TIMEOUT"
    time: Optional[float] = None  # Execution time for this finding
    counter_example: Optional[str] = (
        None  # String representation of counterexample
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            "file": self.file,
            "type": self.type,
        }
        if self.time is not None:
            result["time"] = self.time
        if self.counter_example:
            result["counter-example"] = self.counter_example
        return result


@dataclass
class ConsCsParsed:
    """Structured parsed output from ConsCS tool.

    Contains detailed tool-specific information.
    """

    # Execution status
    status: str = "success"
    # Execution time (in seconds)
    execution_time: float = 0.0
    # All findings found with full details
    findings: List[ConsCSFinding] = field(default_factory=list)
    # Statistics
    total_findings: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "status": self.status,
            "execution_time": self.execution_time,
            "findings": [finding.to_dict() for finding in self.findings],
            "statistics": {
                "total_findings": self.total_findings,
            },
        }


class ConsCS(AbstractTool):
    """ConsCS constraint solver analysis tool for Circom circuits."""

    def __init__(self):
        super().__init__("conscs")
        # Locate ConsCS root directory
        conscs_root = Path(__file__).parent.parent.parent / "tools" / "conscs"
        analyze_script = conscs_root / "analyze_circuit.py"

        if not analyze_script.exists():
            logging.error(
                f"[ConsCS analyze_circuit.py not found at {analyze_script}]"
            )
            sys.exit(1)

        self.conscs_root = conscs_root
        self.analyze_script = analyze_script

        # Verify circom binary is available
        if not self.check_binary_exists("circom"):
            logging.error("[Binary not found: install circom]")
            sys.exit(1)

    def _compile_circom_to_r1cs(
        self,
        circuit_file: Path,
        link_flags: Optional[List[str]] = None,
        timeout: int = 300,
    ) -> Optional[Path]:
        """Compile a Circom circuit to R1CS format.

        Args:
            circuit_file: Path to the .circom file
            timeout: Maximum compilation time in seconds

        Returns:
            Path to generated .r1cs file, or None if compilation failed
        """
        circuit_dir = circuit_file.parent
        r1cs_file = circuit_dir / circuit_file.stem
        r1cs_file = r1cs_file.with_suffix(".r1cs")

        # If r1cs already exists, use it
        if r1cs_file.exists():
            logging.debug(f"Using existing R1CS file: {r1cs_file}")
            return r1cs_file

        # Compile circuit to r1cs
        logging.info(f"Compiling {circuit_file.name} to R1CS format...")
        cmd = [
            "circom",
            str(circuit_file),
            "--r1cs",
            "-o",
            str(circuit_dir),
        ]
        if link_flags:
            cmd.extend(link_flags)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(circuit_dir),
            )

            if result.returncode != 0:
                logging.error(
                    f"Circom compilation failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
                )
                return None

            if not r1cs_file.exists():
                logging.error(f"R1CS file not generated: {r1cs_file}")
                return None

            logging.info(f"Successfully compiled to: {r1cs_file}")
            return r1cs_file

        except subprocess.TimeoutExpired:
            logging.error(
                f"Circom compilation timed out after {timeout} seconds"
            )
            return None
        except Exception as e:
            logging.error(f"Circom compilation failed: {e}")
            return None

    def _internal_execute(self, input_paths: Input, timeout: int) -> ToolOutput:
        """Run ConsCS on a given circuit.

        Args:
            input_paths: Input object containing circuit_dir and circuit_file paths
            timeout: Maximum execution time in seconds

        Returns:
            ToolOutput object with execution results
        """
        circuit_file = Path(input_paths.circuit_file)
        circuit_dir = Path(input_paths.circuit_dir)

        # Compile circuit to R1CS if needed, then deduct elapsed time so the
        # analysis step gets the remaining budget rather than another full timeout.
        if input_paths.r1cs_file:
            r1cs_file = Path(input_paths.r1cs_file)
            compile_elapsed = 0.0
        else:
            t0 = time.monotonic()
            r1cs_file = self._compile_circom_to_r1cs(
                circuit_file, input_paths.link_flags, timeout
            )
            compile_elapsed = time.monotonic() - t0

        if not r1cs_file:
            return ToolOutput(
                status=OutputStatus.FAIL,
                stdout="",
                stderr="Failed to compile circuit to R1CS format",
                return_code=1,
                msg="Failed to compile circuit to R1CS format",
            )

        analysis_timeout = max(1, timeout - int(compile_elapsed))

        # Prepare log file paths in the circuit directory
        base_name = circuit_file.stem
        log_file = circuit_dir / f"{base_name}_conscs.log"
        log_file_contributions = (
            circuit_dir / f"{base_name}_conscs_contributions.log"
        )

        # Clear old log files (ConsCS appends to them, so we need fresh logs)
        for log in [log_file, log_file_contributions]:
            if log.exists():
                log.unlink()
                logging.debug(f"Cleared old log file: {log}")

        # Prepare ConsCS command
        # Flags: "111" = all features enabled (SIMPLIFICATION=1, BPG=1, ASSUMPTION=1)
        # Max depth: "4" (standard value)
        flags = "111"
        max_depth = "4"

        cmd = [
            sys.executable,
            str(self.analyze_script),
            str(r1cs_file),
            str(log_file),
            str(log_file_contributions),
            flags,
            max_depth,
        ]

        # Execute ConsCS with remaining budget after compilation
        result = self.run_command(
            cmd, analysis_timeout, input_paths.circuit_dir
        )

        # ConsCS writes its findings to the log file. Replace msg with log
        # content so _helper_parse_output sees the structured log format.
        # Skip when the process timed out — the TIMEOUT status is the signal;
        # overwriting msg would erase the "[Timed out]" sentinel from raw.txt.
        if result.status != OutputStatus.TIMEOUT and log_file.exists():
            try:
                with open(log_file, "r", encoding="utf-8") as f:
                    result.msg = f.read()
            except Exception as e:
                logging.debug(f"Could not read log file: {e}")

        return result

    def _helper_parse_output(self, tool_result_raw: Path) -> ConsCsParsed:
        """Parse ConsCS output and extract all findings.

        Parses the ConsCS log format:
        ** filename: <name>
        ** result: <CONSTRAINED! | UNDER-CONSTRAINED! | NOT SURE | TIMEOUT>
        ** time: <seconds>
        ** counterexample: <counterexample_dict>

        Args:
            tool_result_raw: Path to raw tool output file (log file)

        Returns:
            ConsCsParsed object with detailed structured data
        """
        if not tool_result_raw.exists():
            logging.debug(f"Log file not found: {tool_result_raw}")
            return ConsCsParsed(
                status="success",
                execution_time=0.0,
                findings=[],
                total_findings=0,
            )

        try:
            with open(tool_result_raw, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            logging.error(f"Failed to read ConsCS output: {e}")
            return ConsCsParsed(
                status="error",
                execution_time=0.0,
                findings=[],
                total_findings=0,
            )

        # Check for timeout
        if "[Timed out]" in content:
            return ConsCsParsed(
                status="timeout",
                execution_time=0.0,
                findings=[],
                total_findings=0,
            )

        # Parse findings from ConsCS log output
        # ConsCS format:
        # ** filename: <circuit_name>
        # ** result: <CONSTRAINED! | UNDER-CONSTRAINED! | NOT SURE | TIMEOUT>
        # ** time: <execution_time>
        # ** counterexample: <dict_representation>
        findings: List[ConsCSFinding] = []
        total_time = 0.0

        lines = content.split("\n")
        i = 0
        while i < len(lines):
            line = lines[i].strip()

            # Look for filename line to start parsing a finding
            if line.startswith("** filename:"):
                filename = line.split("** filename:", 1)[1].strip()

                # Initialize variables for this finding
                result_type = None
                exec_time = None
                counterexample = None

                # Parse the next lines for result, time, and counterexample
                j = i + 1
                while j < len(lines):
                    next_line = lines[j].strip()

                    # Stop if we hit the next filename or end of meaningful data
                    if next_line.startswith("** filename:"):
                        break

                    # Parse result line
                    if next_line.startswith("** result:"):
                        result_text = next_line.split("** result:", 1)[
                            1
                        ].strip()
                        # Remove trailing "!" if present
                        result_type = result_text.rstrip("!")

                    # Parse time line
                    elif next_line.startswith("** time:"):
                        try:
                            exec_time = float(
                                next_line.split("** time:", 1)[1].strip()
                            )
                            total_time += exec_time
                        except ValueError:
                            exec_time = None

                    # Parse counterexample line
                    elif next_line.startswith("** counterexample:"):
                        counterexample = next_line.split(
                            "** counterexample:", 1
                        )[1].strip()

                    # Stop at contribution counts (these are not part of the finding)
                    elif next_line.startswith(
                        "** contribution counts:"
                    ) or next_line.startswith("******"):
                        break

                    j += 1

                # Create finding if we have a result
                if result_type:
                    # Only include findings that are not CONSTRAINED
                    if result_type != "CONSTRAINED":
                        finding = ConsCSFinding(
                            file=filename,
                            type=result_type,
                            time=exec_time,
                            counter_example=counterexample,
                        )
                        findings.append(finding)

                # Move to the next section
                i = j
                continue

            i += 1

        return ConsCsParsed(
            status="success",
            execution_time=total_time,
            findings=findings,
            total_findings=len(findings),
        )

    def _helper_generate_uniform_results(
        self,
        parsed_output: ConsCsParsed,
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

        # Separate per-circuit TIMEOUT results from actual findings so they
        # don't masquerade as BUGS_FOUND when no real bug was detected.
        timeout_findings = [
            f for f in parsed_output.findings if f.type.upper() == "TIMEOUT"
        ]
        real_findings = [
            f for f in parsed_output.findings if f.type.upper() != "TIMEOUT"
        ]

        # Determine analysis status
        if parsed_output.status == "timeout" or (
            timeout_findings and not real_findings
        ):
            analysis_status = AnalysisStatus.TIMEOUT
        elif real_findings:
            analysis_status = AnalysisStatus.BUGS_FOUND
        else:
            analysis_status = AnalysisStatus.NO_BUGS

        # Map ConsCS findings to standardized findings (skip pure-timeout entries)
        for conscs_finding in real_findings:
            # Map ConsCS finding type to standardized category
            finding_type = conscs_finding.type.upper()
            if "UNDER" in finding_type:
                unified_title = StandardizedBugCategory.UNDER_CONSTRAINED
                bug_title = "UnderConstrained"
            elif "OVER" in finding_type:
                unified_title = StandardizedBugCategory.OVER_CONSTRAINED
                bug_title = "OverConstrained"
            elif "NOT SURE" in finding_type:
                unified_title = StandardizedBugCategory.WARNING
                bug_title = "NotSure"
            else:
                unified_title = StandardizedBugCategory.WARNING
                bug_title = "Other"

            # Build description from finding info
            description = f"{conscs_finding.type}: {conscs_finding.file}"

            # ConsCS reports filename as "ComponentName@circuit.circom"; extract
            # the component name so evaluate_zkbugs_ground_truth can match it
            # against the ground-truth location (same as circom_civer does).
            raw_file = conscs_finding.file
            component = raw_file.split("@")[0] if "@" in raw_file else None

            finding = Finding(
                bug_title=bug_title,
                unified_bug_title=unified_title,
                description=description,
                file=raw_file,
                position={"component": component} if component else {},
                metadata={},
            )
            if conscs_finding.time is not None:
                finding.metadata["time"] = conscs_finding.time
            if conscs_finding.counter_example:
                finding.metadata["counter-example"] = (
                    conscs_finding.counter_example
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
        """Evaluate ConsCS results against ground truth.

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
        gt_function = gt_data.get("location", {}).get("Function")

        # Load tool results
        tool_results = self.load_json_file(tool_result_path)
        tool_status = tool_results.get("status", "")
        findings = tool_results.get("findings", [])

        # Timeout or error: cannot draw a verdict
        if tool_status in ("timeout", "error"):
            return {
                "status": "Undecided",
                "reason": f"Tool {tool_status} — analysis did not complete",
                "need_manual_analysis": True,
                "manual_analysis": "Pending",
                "manual_analysis_reasoning": "N/A",
            }

        # No findings → definitive miss
        if not findings:
            return {
                "status": "FalseNegative",
                "reason": "Tool found no issues",
                "need_manual_analysis": False,
                "manual_analysis": "N/A",
                "manual_analysis_reasoning": "N/A",
            }

        # Separate confirmed under-constrained findings from NOT SURE ones
        not_sure_findings = [
            f for f in findings if f.get("bug_title") == "NotSure"
        ]
        confirmed_findings = [
            f for f in findings if f.get("bug_title") != "NotSure"
        ]

        # Check confirmed findings first: match on vulnerability type + component
        for finding in confirmed_findings:
            unified_title = finding.get("unified_bug_title", "")
            component = finding.get("position", {}).get("component")

            type_match = (
                gt_vulnerability
                and unified_title.lower() == gt_vulnerability.lower()
            )
            # Accept if type matches and either no GT component is named or
            # the component name matches exactly (same strategy as circom_civer).
            location_match = not gt_function or component == gt_function

            if type_match and location_match:
                return {
                    "status": "TruePositive",
                    "reason": f"Found {gt_vulnerability}"
                    + (f" in component {component}" if component else ""),
                    "need_manual_analysis": False,
                    "manual_analysis": "N/A",
                    "manual_analysis_reasoning": "N/A",
                }

        # NOT SURE findings on an Under-Constrained target need manual review
        if not_sure_findings and gt_vulnerability == "Under-Constrained":
            return {
                "status": "Undecided",
                "reason": f"ConsCS reported NOT SURE for {len(not_sure_findings)} component(s) — manual review required",
                "need_manual_analysis": True,
                "manual_analysis": "Pending",
                "manual_analysis_reasoning": "N/A",
            }

        # Found issues but none match the expected vulnerability
        return {
            "status": "Undecided",
            "reason": f"Tool found {len(findings)} issues but none match {gt_vulnerability}",
            "need_manual_analysis": True,
            "manual_analysis": "Pending",
            "manual_analysis_reasoning": "TODO",
        }
