import logging
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .base import (
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
    time: float | None = None  # Execution time for this finding
    counter_example: str | None = (
        None  # String representation of counterexample
    )

    def to_dict(self) -> dict[str, Any]:
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
    findings: list[ConsCSFinding] = field(default_factory=list)
    # Statistics
    total_findings: int = 0

    def to_dict(self) -> dict[str, Any]:
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
        link_flags: list[str],
        timeout: int,
        out_dir: Path,
    ) -> tuple[Path | None, ToolOutput | None]:
        """Compile a Circom circuit to R1CS format in a scratch directory.

        Args:
            circuit_file: Path to the .circom file
            link_flags: circom `-l` flags from the bug contract
            timeout: Maximum compilation time in seconds
            out_dir: Directory to write the .r1cs into (never the source dir)

        Returns:
            (r1cs_path, None) on success, (None, failure_output) otherwise.
            A compile timeout keeps its TIMEOUT status so it is not
            misreported as a generic failure.
        """
        logging.info(f"Compiling {circuit_file.name} to R1CS format...")
        cmd = [
            "circom",
            str(circuit_file.resolve()),
            "--r1cs",
            "-o",
            str(out_dir),
            *link_flags,
        ]
        result = self.run_command(cmd, timeout, str(circuit_file))

        if result.status == OutputStatus.TIMEOUT:
            return None, result
        if result.status != OutputStatus.SUCCESS:
            result.msg = f"[Circom compilation failed]\n{result.msg}"
            return None, result

        r1cs_file = next(iter(out_dir.glob("*.r1cs")), None)
        if r1cs_file is None:
            result.status = OutputStatus.FAIL
            result.msg = f"[R1CS file not generated]\n{result.msg}"
            return None, result

        logging.info(f"Successfully compiled to: {r1cs_file}")
        return r1cs_file, None

    def _internal_execute(self, input_paths: Input, timeout: int) -> ToolOutput:
        """Run ConsCS on a given circuit.

        Args:
            input_paths: Input object containing circuit_dir and circuit_file paths
            timeout: Maximum execution time in seconds

        Returns:
            ToolOutput object with execution results
        """
        circuit_file = Path(input_paths.circuit_file)

        # Scratch space for the self-compiled R1CS and ConsCS log files, so
        # the circuit/source directory is never polluted and a stale R1CS
        # from an earlier run can never be picked up.
        with tempfile.TemporaryDirectory(prefix="conscs_") as tmp_dir:
            work_dir = Path(tmp_dir)

            if input_paths.r1cs_file:
                r1cs_file = Path(input_paths.r1cs_file)
                analysis_timeout = timeout
            elif input_paths.mode != "analyze":
                # zkbugs mode always precompiles (conscs is in ARTIFACT_TOOLS);
                # a missing r1cs_file means precompile_circuit already failed,
                # so recompiling here would burn another full timeout on a
                # known failure.
                msg = (
                    "[Precompiled R1CS unavailable: circom failed in the "
                    "precompile step; see scratch/compile.log]"
                )
                return ToolOutput(
                    status=OutputStatus.FAIL,
                    stdout="",
                    stderr=msg,
                    return_code=1,
                    msg=msg,
                )
            else:
                # Compile, then deduct elapsed time so the analysis step gets
                # the remaining budget rather than another full timeout.
                t0 = time.monotonic()
                r1cs_file, compile_failure = self._compile_circom_to_r1cs(
                    circuit_file, input_paths.link_flags, timeout, work_dir
                )
                if compile_failure is not None:
                    return compile_failure
                analysis_timeout = max(1, timeout - int(time.monotonic() - t0))

            base_name = circuit_file.stem
            log_file = work_dir / f"{base_name}_conscs.log"
            log_file_contributions = (
                work_dir / f"{base_name}_conscs_contributions.log"
            )

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
            if result.status != OutputStatus.TIMEOUT:
                if log_file.exists():
                    try:
                        with open(log_file, encoding="utf-8") as f:
                            result.msg = f.read()
                    except Exception as e:
                        logging.debug(f"Could not read log file: {e}")
                elif result.status == OutputStatus.SUCCESS:
                    # ConsCS exited cleanly without writing its log: a tool
                    # failure, which must not parse as a clean NO_BUGS run.
                    result.status = OutputStatus.FAIL
                    result.msg = (
                        f"[ConsCS produced no log output]\n{result.msg}"
                    )

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
            logging.error(f"ConsCS log output not found: {tool_result_raw}")
            return ConsCsParsed(
                status="error",
                execution_time=0.0,
                findings=[],
                total_findings=0,
            )

        try:
            with open(tool_result_raw, encoding="utf-8") as f:
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

        # A valid ConsCS log always contains at least one "** filename:"
        # entry (the main circuit); anything else is a crashed/garbled run
        # and must not parse as a clean NO_BUGS result.
        if "** filename:" not in content:
            logging.error(
                f"ConsCS output has no recognizable entries: {tool_result_raw}"
            )
            return ConsCsParsed(
                status="error",
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
        findings: list[ConsCSFinding] = []
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

                # Create a finding for any result that is not CONSTRAINED
                if result_type and result_type != "CONSTRAINED":
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
    ) -> tuple[AnalysisStatus, list[Finding]]:
        """Generate uniform findings from parsed output.

        Args:
            parsed_output: Parsed tool output
            tool_output: Tool execution output with timing info

        Returns:
            Tuple of (AnalysisStatus, List[Finding])
        """
        findings = []

        # Partition raw results. Only UNDER/OVER-CONSTRAINED verdicts are real
        # findings. Per-circuit TIMEOUT and "canceled" (ConsCS's internal
        # cancellation) mean the analysis was incomplete; NOT SURE means the
        # solver finished without a verdict; anything else (e.g. "maximum
        # recursion depth exceeded") is a crash inside ConsCS. None of those
        # may masquerade as BUGS_FOUND or inflate findings_count — they stay
        # visible in parsed.json only.
        timeout_findings: list[ConsCSFinding] = []
        not_sure_findings: list[ConsCSFinding] = []
        crash_findings: list[ConsCSFinding] = []
        real_findings: list[ConsCSFinding] = []
        for conscs_finding in parsed_output.findings:
            finding_type = conscs_finding.type.upper()
            if finding_type == "TIMEOUT" or "CANCELED" in finding_type:
                timeout_findings.append(conscs_finding)
            elif "NOT SURE" in finding_type:
                not_sure_findings.append(conscs_finding)
            elif "UNDER" in finding_type or "OVER" in finding_type:
                real_findings.append(conscs_finding)
            else:
                crash_findings.append(conscs_finding)

        # Determine analysis status
        if parsed_output.status == "error":
            analysis_status = AnalysisStatus.ERROR
        elif parsed_output.status == "timeout":
            analysis_status = AnalysisStatus.TIMEOUT
        elif real_findings:
            analysis_status = AnalysisStatus.BUGS_FOUND
        elif crash_findings:
            analysis_status = AnalysisStatus.ERROR
        elif timeout_findings:
            analysis_status = AnalysisStatus.TIMEOUT
        else:
            # Includes NOT SURE-only runs: the solver completed but proved
            # nothing, which evaluation counts as a miss.
            analysis_status = AnalysisStatus.NO_BUGS

        # Map confirmed ConsCS findings to standardized findings
        for conscs_finding in real_findings:
            # Map ConsCS finding type to standardized category
            finding_type = conscs_finding.type.upper()
            if "UNDER" in finding_type:
                unified_title = StandardizedBugCategory.UNDER_CONSTRAINED
                bug_title = "UnderConstrained"
            else:
                unified_title = StandardizedBugCategory.OVER_CONSTRAINED
                bug_title = "OverConstrained"

            # Build description from finding info
            description = f"{conscs_finding.type}: {conscs_finding.file}"

            # ConsCS reports "ComponentName@circuit.circom" for sub-components
            # and a bare filename for the entrypoint; keep `file` a plain file
            # name and put the component in position so
            # evaluate_zkbugs_ground_truth can match it against the
            # ground-truth location (same as circom_civer does).
            raw_file = conscs_finding.file
            if "@" in raw_file:
                component, file_name = raw_file.split("@", 1)
            else:
                component, file_name = None, raw_file

            finding = Finding(
                bug_title=bug_title,
                unified_bug_title=unified_title,
                description=description,
                file=file_name,
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
    ) -> dict[str, Any]:
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

        # No findings → definitive miss. Distinguish a clean CONSTRAINED run
        # from NOT SURE results, which results.json omits (they are not
        # findings) but parsed.json records.
        if not findings:
            parsed = self.load_json_file(
                tool_result_path.parent / "parsed.json"
            )
            not_sure_count = sum(
                1
                for f in parsed.get("findings", [])
                if "NOT SURE" in str(f.get("type", "")).upper()
            )
            if not_sure_count:
                # ConsCS finished but could not find a counterexample: the
                # tool failed to detect the bug, which is a FalseNegative.
                reason = (
                    f"ConsCS reported NOT SURE for {not_sure_count} "
                    "component(s), could not find a counterexample"
                )
            else:
                reason = "Tool found no issues"
            return {
                "status": "FalseNegative",
                "reason": reason,
                "need_manual_analysis": False,
                "manual_analysis": "N/A",
                "manual_analysis_reasoning": "N/A",
            }

        # Findings are confirmed under/over-constrained results: match on
        # vulnerability type + component
        for finding in findings:
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

        # Found issues but none match the expected vulnerability
        return {
            "status": "Undecided",
            "reason": f"Tool found {len(findings)} issues but none match {gt_vulnerability}",
            "need_manual_analysis": True,
            "manual_analysis": "Pending",
            "manual_analysis_reasoning": "TODO",
        }
