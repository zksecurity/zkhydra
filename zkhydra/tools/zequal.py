import logging
import os
import re
import shutil
import sys
import tempfile
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

# Navigate from zkhydra/tools/zequal.py to project root, then to tools/zequal/
TOOL_DIR = Path(__file__).resolve().parent.parent.parent / "tools" / "zequal"

# Statuses emitted by zequal.py's VerificationResult enum (the Status column
# of its markdown table). VERIFIED means the constraints encode the same
# computation as the witness generator; NOT_VERIFIED means they diverge.
VALID_STATUSES = {
    "VERIFIED",
    "NOT_VERIFIED",
    "CRASH",
    "TIMEOUT",
    "NOT_FOUND",
}

# Marker the wrapper appends to raw.txt to separate the table from the
# verifier's own stdout/stderr (model / counterexample).
VERIFIER_SECTION = "=== zequal verifier output ==="

# zequal colorizes its verifier output with ANSI escapes; strip them so
# raw.txt and finding metadata stay readable.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# zequal's `verify` prints "Verification Failed: <msg>" for ANY error, including
# circom parse/compile failures (unsupported pragma, unresolved includes) and
# bad input — using the same prefix as a genuine refutation. These markers
# identify a run where zequal never analyzed the circuit, so it must be reported
# as a tool error, never as a detected inconsistency.
_ZEQUAL_ERROR_MARKERS = ("Could not create archive", "Could not read input")


@dataclass
class ZequalParsed:
    """Structured parsed output from the zequal tool."""

    # Wrapper-level status: "success" | "timeout" | "error".
    status: str = "success"
    # zequal's verdict for the circuit (one of VALID_STATUSES, or "").
    result: str = ""
    # Wall-clock time zequal reported for the benchmark, if available.
    execution_time: float | None = None
    # Verifier output lines (model / counterexample) for a failed proof.
    verifier_output: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "status": self.status,
            "result": self.result,
            "execution_time": self.execution_time,
            "verifier_output": self.verifier_output,
        }


class Zequal(AbstractTool):
    """zequal consistency verifier for Circom circuits.

    zequal proves whether a circuit's constraints encode the same computation
    as its witness generator. A failed proof (NOT_VERIFIED) signals an
    inconsistency, which in practice is an under- or over-constrained circuit.

    With ``Input.zequal_static`` set (CLI ``--zequal-static``) the wrapper runs
    zequal in static-analysis-only mode, which skips the SMT phase: fast and
    timeout-free, but a NOT_VERIFIED becomes a candidate rather than a proven
    inconsistency.
    """

    def __init__(self):
        super().__init__("zequal")
        # Whether the most recent run used --only-static-analysis. Set per run
        # in _internal_execute so process_output can describe the verdict
        # accurately (execute -> process_output run on the same instance).
        self._only_static_analysis = False
        zequal_py = TOOL_DIR / "zequal.py"
        verify_bin = TOOL_DIR / "target" / "debug" / "verify"

        if not zequal_py.is_file():
            logging.error(f"[zequal.py not found at {zequal_py}]")
            sys.exit(1)
        if not verify_bin.is_file():
            logging.error(
                f"[zequal verifier not built at {verify_bin}; run "
                "`cargo build` in tools/zequal]"
            )
            sys.exit(1)
        # zequal drives z3 via the SMT-LIB backend.
        if not self.check_binary_exists("z3"):
            logging.error("[Binary not found: install z3]")
            sys.exit(1)

        self.zequal_py = zequal_py

    def _internal_execute(self, input_paths: Input, timeout: int) -> ToolOutput:
        """Run zequal on the given circuit.

        zequal has no library-path flag; its parser resolves ``include``
        directives relative to the circuit's directory. When the wrapper
        circuit's includes point into a separate codebase we mirror the link
        contract into a scratch directory via symlinks (same strategy as
        circomspect). zequal.py is invoked with the current interpreter so we
        don't depend on a separate ``python3`` binary on PATH.
        """
        circuit_file_path = Path(input_paths.circuit_file)
        target_circuit = self._prepare_circuit_for_zequal(
            input_paths, circuit_file_path
        )
        self._only_static_analysis = input_paths.zequal_static

        # Scratch cwd so the verifier's default output_path (".") and zequal's
        # per-benchmark .out file never pollute the circuit/source directory.
        with tempfile.TemporaryDirectory(prefix="zequal_") as tmp_dir:
            work_dir = Path(tmp_dir)
            out_dir = work_dir / "out"

            # Let zequal self-time-out a little before the hard process kill so
            # a slow proof is reported as TIMEOUT rather than a generic failure.
            inner_timeout = max(1, timeout - 10)
            cmd = [
                sys.executable,
                str(self.zequal_py),
                "-t",
                str(inner_timeout),
                "-o",
                str(out_dir),
            ]
            if input_paths.zequal_static:
                cmd.append("--only-static-analysis")
            cmd.append(str(target_circuit.resolve()))

            current_dir = Path.cwd()
            self.change_directory(work_dir)
            try:
                result = self.run_command(cmd, timeout, input_paths.circuit_dir)
            finally:
                self.change_directory(current_dir)

            # On a clean run, fold the verifier's own output (model /
            # counterexample) into raw.txt under a marker so parsing keeps the
            # full detail. Skip on process-level timeout — the "[Timed out]"
            # sentinel from run_command must survive in raw.txt.
            if result.status != OutputStatus.TIMEOUT:
                verifier_out = self._read_verifier_output(
                    out_dir, target_circuit
                )
                if verifier_out:
                    result.msg = (
                        f"{result.msg}\n\n{VERIFIER_SECTION}\n{verifier_out}"
                    )

            return result

    @staticmethod
    def _read_verifier_output(out_dir: Path, circuit: Path) -> str:
        """Read zequal's per-benchmark <base>.out file, if it was written."""
        out_file = out_dir / f"{circuit.stem}.out"
        if not out_file.is_file():
            return ""
        try:
            content = out_file.read_text(encoding="utf-8", errors="replace")
            return _ANSI_RE.sub("", content)
        except OSError as exc:
            logging.debug(
                "Could not read zequal .out file %s: %s", out_file, exc
            )
            return ""

    def _prepare_circuit_for_zequal(
        self, input_paths: Input, circuit_file_path: Path
    ) -> Path:
        """Return a circom entrypoint whose includes zequal can resolve.

        - With no link flags, the circuit is self-contained; run it in place.
        - If the circuit already lives under the codebase, sibling includes
          resolve naturally; run in place.
        - Otherwise mirror each ``-l <path>`` target's children into a fresh
          scratch dir alongside a copy of the wrapper so ``include
          "circuits/..."`` lines resolve without polluting the dataset.
        """
        if not input_paths.link_flags:
            return circuit_file_path

        codebase = Path(input_paths.codebase) if input_paths.codebase else None
        if codebase is not None:
            try:
                circuit_file_path.resolve().relative_to(codebase.resolve())
                return circuit_file_path
            except ValueError:
                pass

        scratch_root = Path(tempfile.mkdtemp(prefix="zkhydra-zequal-"))
        target_wrapper = scratch_root / circuit_file_path.name
        shutil.copy2(circuit_file_path, target_wrapper)

        for link_path in self._extract_link_paths(input_paths.link_flags):
            link_path_obj = Path(link_path)
            if not link_path_obj.is_dir():
                continue
            for child in link_path_obj.iterdir():
                dest = scratch_root / child.name
                if dest.is_symlink() or dest.exists():
                    continue
                try:
                    os.symlink(child.resolve(), dest)
                except OSError as exc:
                    logging.debug(
                        "zequal scratch: cannot symlink %s -> %s: %s",
                        child,
                        dest,
                        exc,
                    )

        return target_wrapper

    @staticmethod
    def _extract_link_paths(link_flags: list[str]) -> list[str]:
        paths: list[str] = []
        it = iter(link_flags)
        for flag in it:
            if flag in ("-l", "-L", "--link-libraries"):
                try:
                    paths.append(next(it))
                except StopIteration:
                    break
        return paths

    def _helper_parse_output(self, tool_result_raw: Path) -> ZequalParsed:
        """Parse zequal output: the markdown table plus verifier section.

        zequal.py prints a markdown table with one data row per circuit:
            | <name> | <STATUS> | <time> |
        We read the STATUS/time cells and, for a failed proof, capture the
        verifier's model lines from the appended verifier section.

        Args:
            tool_result_raw: Path to raw tool output file

        Returns:
            ZequalParsed with the verdict and any counterexample detail
        """
        if not tool_result_raw.is_file():
            logging.error(f"zequal output not found: {tool_result_raw}")
            return ZequalParsed(status="error")

        try:
            content = tool_result_raw.read_text(
                encoding="utf-8", errors="replace"
            )
        except OSError as exc:
            logging.error(f"Failed to read zequal output: {exc}")
            return ZequalParsed(status="error")

        if "[Timed out]" in content:
            return ZequalParsed(status="timeout", result="TIMEOUT")

        # A circom parse/compile failure surfaces as "Verification Failed" too;
        # it is a tool error, not a refutation, so never treat it as a finding.
        if any(marker in content for marker in _ZEQUAL_ERROR_MARKERS):
            return ZequalParsed(status="error", result="ERROR")

        table_part, _, verifier_part = content.partition(VERIFIER_SECTION)

        result, exec_time = self._parse_table(table_part)
        verifier_output = [
            line.rstrip() for line in verifier_part.splitlines() if line.strip()
        ]

        if not result:
            # No recognizable table row — zequal crashed before reporting.
            return ZequalParsed(status="error")

        wrapper_status = "timeout" if result == "TIMEOUT" else "success"
        return ZequalParsed(
            status=wrapper_status,
            result=result,
            execution_time=exec_time,
            verifier_output=verifier_output,
        )

    @staticmethod
    def _parse_table(table_text: str) -> tuple[str, float | None]:
        """Extract (status, time) from zequal's markdown result table."""
        for line in table_text.splitlines():
            if "|" not in line:
                continue
            cells = [c.strip() for c in line.split("|") if c.strip()]
            # Data row: [name, STATUS, time]; STATUS pins it down.
            if len(cells) >= 3 and cells[1] in VALID_STATUSES:
                exec_time: float | None = None
                try:
                    exec_time = float(cells[2])
                except ValueError:
                    exec_time = None
                return cells[1], exec_time
        return "", None

    def _helper_generate_uniform_results(
        self,
        parsed_output: ZequalParsed,
        tool_output: ToolOutput,
    ) -> tuple[AnalysisStatus, list[Finding]]:
        """Generate uniform findings from parsed output.

        Args:
            parsed_output: Parsed tool output
            tool_output: Tool execution output with timing info

        Returns:
            Tuple of (AnalysisStatus, List[Finding])
        """
        if (
            parsed_output.status == "timeout"
            or parsed_output.result == "TIMEOUT"
        ):
            return AnalysisStatus.TIMEOUT, []
        if parsed_output.status == "error":
            return AnalysisStatus.ERROR, []
        if parsed_output.result == "VERIFIED":
            return AnalysisStatus.NO_BUGS, []
        if parsed_output.result != "NOT_VERIFIED":
            # CRASH / NOT_FOUND / anything unexpected: not a clean verdict.
            return AnalysisStatus.ERROR, []

        # NOT_VERIFIED: zequal could not establish that the constraints encode
        # the same computation as the witness generator. In full mode this is a
        # proven inconsistency with a counterexample; in static-analysis-only
        # mode it is a candidate the analysis could not discharge. zequal does
        # not distinguish under- vs over-constrained, so we label the dominant
        # case and record the verdict for the zkbugs evaluator.
        if self._only_static_analysis:
            description = (
                "zequal's static analysis could not prove the constraints "
                "encode the same computation as the witness generator "
                "(candidate constraint/witness inconsistency)"
            )
            analysis_mode = "only-static-analysis"
        else:
            description = (
                "zequal could not verify that the constraints encode the same "
                "computation as the witness generator (constraint/witness "
                "inconsistency)"
            )
            analysis_mode = "full"
        finding = Finding(
            bug_title="ConstraintWitnessMismatch",
            unified_bug_title=StandardizedBugCategory.UNDER_CONSTRAINED,
            description=description,
            metadata={
                "zequal_result": parsed_output.result,
                "analysis_mode": analysis_mode,
            },
        )
        if parsed_output.execution_time is not None:
            finding.metadata["time"] = parsed_output.execution_time
        if parsed_output.verifier_output:
            finding.metadata["counter-example"] = "\n".join(
                parsed_output.verifier_output
            )

        return AnalysisStatus.BUGS_FOUND, [finding]

    def evaluate_zkbugs_ground_truth(
        self,
        tool: str,
        dsl: str,
        bug_name: str,
        ground_truth: Path,
        tool_result_path: Path,
    ) -> dict[str, Any]:
        """Evaluate zequal results against ground truth.

        zequal detects constraint/witness inconsistencies without pinpointing a
        location or distinguishing under- from over-constrained. A detected
        inconsistency is a TruePositive for either consistency category and
        Undecided otherwise; a clean equivalence proof (no findings) means the
        known bug was missed, i.e. a FalseNegative. Parse/compile failures are
        reported as tool errors upstream and never reach this verdict.

        Args:
            tool: Tool name
            dsl: Domain-specific language
            bug_name: Bug name
            ground_truth: Path to ground truth JSON
            tool_result_path: Path to results.json

        Returns:
            Evaluation result dictionary
        """
        gt_data = self.load_json_file(ground_truth)
        gt_vulnerability = gt_data.get("vulnerability") or ""

        tool_results = self.load_json_file(tool_result_path)
        tool_status = tool_results.get("status", "")
        findings = tool_results.get("findings", [])

        # Timeout or error: cannot draw a verdict.
        if tool_status in ("timeout", "error"):
            return {
                "status": "Undecided",
                "reason": f"Tool {tool_status} — analysis did not complete",
                "need_manual_analysis": True,
                "manual_analysis": "Pending",
                "manual_analysis_reasoning": "N/A",
            }

        consistency_categories = {"under-constrained", "over-constrained"}
        gt_is_consistency = gt_vulnerability.lower() in consistency_categories

        # No findings → zequal ran and verified equivalence, so it missed the
        # known bug. Every zkbugs entry is a real bug, so this is a
        # FalseNegative regardless of category (zequal cannot detect a
        # computational bug whose constraints and witness generation are
        # consistently wrong).
        if not findings:
            return {
                "status": "FalseNegative",
                "reason": (
                    "zequal verified equivalence; did not detect the "
                    f"{gt_vulnerability} bug"
                ),
                "need_manual_analysis": False,
                "manual_analysis": "N/A",
                "manual_analysis_reasoning": "N/A",
            }

        # Found an inconsistency. zequal flags both under- and over-constrained
        # circuits, so either category counts as a hit.
        if gt_is_consistency:
            return {
                "status": "TruePositive",
                "reason": (
                    "zequal detected a constraint/witness inconsistency "
                    f"matching the {gt_vulnerability} bug"
                ),
                "need_manual_analysis": False,
                "manual_analysis": "N/A",
                "manual_analysis_reasoning": "N/A",
            }

        return {
            "status": "Undecided",
            "reason": (
                "zequal detected an inconsistency but ground truth is "
                f"{gt_vulnerability}"
            ),
            "need_manual_analysis": True,
            "manual_analysis": "Pending",
            "manual_analysis_reasoning": "TODO",
        }
