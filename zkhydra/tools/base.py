"""
Base classes and utilities for ZK circuit security analysis tools.

This module provides the abstract base class that all analysis tools must implement,
along with common utilities for tool execution and output handling.
"""

import json
import logging
import os
import shlex
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, StrEnum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

EXIT_CODES = {
    1,  # General error: A generic error occurred during execution.
    2,  # Misuse of shell builtins: Incorrect usage of a shell built-in command.
    126,  # Command invoked cannot execute: Permission denied or command not executable.
    127,  # Command not found: The command is not recognized or available in the environment’s PATH.
    128,  # Invalid exit argument: An invalid argument was provided to the exit command.
    130,  # Script terminated by Ctrl+C (SIGINT).
    137,  # Script terminated by SIGKILL (e.g., kill -9 or out-of-memory killer).
    139,  # Segmentation fault: Indicates a segmentation fault occurred in the program.
    143,  # Script terminated by SIGTERM (e.g., kill command without -9).
    255,  # Exit status out of range: Typically, this happens when a script or command exits with a number > 255.
}


class ToolError(Exception):
    """Exception raised when a tool fails and detected when parsing the output
    in parse_findings()."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class StandardizedBugCategory(StrEnum):
    """Standardized bug categories.

    Uses StrEnum for automatic JSON serialization to string values.
    """

    UNDER_CONSTRAINED = "Under-Constrained"
    OVER_CONSTRAINED = "Over-Constrained"
    COMPUTATIONAL_ISSUE = "Computational-Issue"
    WARNING = "Warning (Other -- probably not a bug)"


@dataclass
class Input:
    """Input paths for circuit analysis.

    Encapsulates both the circuit directory and circuit file paths,
    allowing tools to choose which to use based on their requirements.
    """

    circuit_dir: str  # Directory containing the circuit and artifacts
    circuit_file: str  # Path to the circuit file


class OutputStatus(Enum):
    """Status of tool execution output."""

    SUCCESS = "success"
    FAIL = "fail"
    TIMEOUT = "timeout"


class AnalysisStatus(Enum):
    """Status of analysis results."""

    BUGS_FOUND = "bugs_found"
    NO_BUGS = "no_bugs"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class ToolOutput:
    """Output from tool execution.

    Encapsulates all information from running a tool, including
    status, stdout/stderr, return code, and combined message.
    """

    status: OutputStatus  # Execution status
    stdout: str  # Standard output from the tool
    stderr: str  # Standard error from the tool
    return_code: int  # Process return code
    msg: str  # Combined stdout + stderr message (or other costum message)
    execution_time: Optional[float] = None  # Execution time in seconds
    raw_output_file: Optional[str] = None  # Path to raw output file
    parsed_output_file: Optional[str] = None  # Path to parsed output file
    results_file: Optional[str] = None  # Path to results file

    def to_dict(self) -> dict:
        """Convert ToolOutput to dictionary for JSON serialization."""
        return {
            "status": self.status.value,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "return_code": self.return_code,
            "msg": self.msg,
            "execution_time": self.execution_time,
            "raw_output_file": self.raw_output_file,
            "parsed_output_file": self.parsed_output_file,
            "results_file": self.results_file,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ToolOutput":
        """Create ToolOutput from dictionary."""
        return cls(
            status=OutputStatus(data["status"]),
            stdout=data["stdout"],
            stderr=data["stderr"],
            return_code=data["return_code"],
            msg=data["msg"],
            execution_time=data.get("execution_time"),
            raw_output_file=data.get("raw_output_file"),
            parsed_output_file=data.get("parsed_output_file"),
            results_file=data.get("results_file"),
        )


@dataclass
class Finding:
    """Unified finding/vulnerability from a security analysis tool.

    Combines tool-specific and standardized information about a security finding.
    """

    # Required fields
    bug_title: (
        str  # Tool-specific bug name (e.g., "UnnecessarySignalAssignment")
    )
    unified_bug_title: str  # Standardized bug name (e.g., "Under-Constrained")
    description: str  # Human-readable description

    # Location information
    file: Optional[str] = None  # File path

    # Position information (flexible structure)
    position: Dict[str, Any] = field(
        default_factory=dict
    )  # Can include: line, column, template, component, signal

    # Metadata (additional tool-specific information)
    metadata: Dict[str, Any] = field(
        default_factory=dict
    )  # severity, code, raw_message, etc.

    def to_dict(self) -> Dict[str, Any]:
        """Convert Finding to dictionary for JSON serialization.

        Returns:
            Dictionary with all fields
        """
        result = {
            "bug_title": self.bug_title,
            "unified_bug_title": self.unified_bug_title,
            "description": self.description,
        }

        if self.file:
            result["file"] = self.file

        if self.position:
            result["position"] = self.position

        if self.metadata:
            result["metadata"] = self.metadata

        return result

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        """Create Finding from dictionary."""
        return cls(
            bug_title=data["bug_title"],
            unified_bug_title=data["unified_bug_title"],
            description=data["description"],
            file=data.get("file"),
            position=data.get("position", {}),
            metadata=data.get("metadata", {}),
        )


class ToolStatus(Enum):
    """Status of tool execution."""

    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class ToolResult:
    """Result of tool execution."""

    status: ToolStatus
    message: str  # Combined stdout and stderr
    execution_time: float
    findings_count: int = 0
    findings: list[dict] = None
    error: str | None = None
    raw_output_file: str | None = None
    parsed_output_file: str | None = None
    results_file: str | None = None

    def __post_init__(self):
        if self.findings is None:
            self.findings = []

    def to_dict(self) -> dict:
        """Convert ToolResult to dictionary for JSON serialization."""
        return {
            "status": self.status.value,
            "message": self.message,
            "execution_time": self.execution_time,
            "findings_count": self.findings_count,
            "findings": self.findings,
            "error": self.error,
            "raw_output_file": self.raw_output_file,
            "parsed_output_file": self.parsed_output_file,
            "results_file": self.results_file,
        }


@dataclass
class ResultsData:
    """Data for results.json file."""

    status: AnalysisStatus
    execution_time: float
    findings: list[Finding]

    def to_dict(self) -> dict:
        """Convert ResultsData to dictionary for JSON serialization."""
        return {
            "status": self.status.value,
            "execution_time": self.execution_time,
            "findings": [f.to_dict() for f in self.findings],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ResultsData":
        """Create ResultsData from dictionary."""
        return cls(
            status=AnalysisStatus(data["status"]),
            execution_time=data["execution_time"],
            findings=[Finding.from_dict(f) for f in data["findings"]],
        )


class AbstractTool(ABC):
    """Abstract base class for all ZK circuit analysis tools.

    All tool implementations must inherit from this class and implement
    the three required methods: execute, parse_output, and compare_zkbugs_ground_truth.
    """

    def __init__(self, name: str):
        """Initialize the tool with its name.

        Args:
            name: The name of the tool (e.g., "circomspect", "zkfuzz")
        """
        self.name = name
        self.exit_codes = EXIT_CODES

    def execute(
        self, input_paths: Input, timeout: int, raw_output_file: Path
    ) -> ToolOutput:
        """Execute the tool on a circuit and write raw output to a file.

        Args:
            input_paths: Input object containing circuit_dir and circuit_file paths
            timeout: Maximum execution time in seconds
            raw_output_file: Path to file to write raw output to

        Returns:
            ToolOutput object with status, stdout, stderr, return_code, and msg

        Note:
            Tools can choose to use either input_paths.circuit_dir or
            input_paths.circuit_file based on their requirements.
        """
        # Measure execution time
        start_time = time.time()
        tool_output = self._internal_execute(input_paths, timeout)
        execution_time = time.time() - start_time
        # Write raw output (msg field contains combined stdout/stderr)
        with open(raw_output_file, "w", encoding="utf-8") as f:
            f.write(tool_output.msg)
        tool_output = ToolOutput(
            status=tool_output.status,
            stdout=tool_output.stdout,
            stderr=tool_output.stderr,
            return_code=tool_output.return_code,
            msg=tool_output.msg,
            execution_time=execution_time,
            raw_output_file=str(raw_output_file),
        )
        tool_output_file = raw_output_file.parent / "tool_output.json"
        with open(tool_output_file, "w", encoding="utf-8") as f:
            json.dump(tool_output.to_dict(), f, indent=2, ensure_ascii=False)
        return tool_output

    @abstractmethod
    def _internal_execute(self, input_paths: Input, timeout: int) -> ToolOutput:
        """Internal execute method that can be overridden by subclasses.

        Args:
            input_paths: Input object containing circuit_dir and circuit_file paths
            timeout: Maximum execution time in seconds

        Returns:
            ToolOutput object with status, stdout, stderr, return_code, and msg
        """
        pass

    @abstractmethod
    def _helper_parse_output(
        self,
        tool_result_raw: Path,
    ) -> Dict[str, Any]:
        """Helper method to parse the output of the tool into a structured format.

        Args:
            tool_result_raw: Path to raw tool output file

        Returns:
            Dictionary with parsed output
        """

    @abstractmethod
    def _helper_generate_uniform_results(
        self, parsed_output: Any, tool_output: ToolOutput
    ) -> Tuple[AnalysisStatus, List[Finding]]:
        """Generate uniform findings from parsed output.

        Args:
            parsed_output: Parsed tool output
            tool_output: Tool execution output with timing info

        Returns:
            Tuple of (AnalysisStatus, List[Finding])
        """

    def process_output(self, tool_output: ToolOutput) -> ToolResult:
        """Process tool output into structured result.

        This method should generate a parsed.json file in the same directory as the raw output file
        that contains the parsed output of the tool based on its specific output format.
        It will also generate a findings.json file that contains the findings of the tool in the standardized format.

        Args:
            tool_output: ToolOutput object with status, stdout, stderr, return_code, and msg

        Returns:
            ToolResult object with status, message, execution_time, findings_count, findings, error, and raw_output_file
        """
        result = None
        try:
            # Check tool execution status
            if tool_output.status == OutputStatus.TIMEOUT:
                result = ToolResult(
                    status=ToolStatus.TIMEOUT,
                    message=tool_output.msg,
                    execution_time=tool_output.execution_time,
                    findings_count=0,
                    findings=[],
                    raw_output_file=str(tool_output.raw_output_file),
                )
            elif tool_output.status == OutputStatus.FAIL:
                # Tool failed (binary not found, file not found, etc.)
                result = ToolResult(
                    status=ToolStatus.FAILED,
                    message=tool_output.msg,
                    execution_time=tool_output.execution_time,
                    findings_count=0,
                    findings=[],
                    error=tool_output.msg,
                    raw_output_file=str(tool_output.raw_output_file),
                )
                logging.error(f"{self.name}: {tool_output.msg}")
            else:
                # Success - parse findings from output
                try:

                    # Since it succeeded, we can generate the parsed.json file
                    raw_output_path = Path(tool_output.raw_output_file)
                    parsed_output = self._helper_parse_output(raw_output_path)
                    parsed_output_file = raw_output_path.parent / "parsed.json"

                    # Serialize dataclass if it has to_dict method, otherwise use as-is
                    output_data = (
                        parsed_output.to_dict()
                        if hasattr(parsed_output, "to_dict")
                        else parsed_output
                    )

                    with open(parsed_output_file, "w", encoding="utf-8") as f:
                        json.dump(output_data, f, indent=4)

                    # Generate uniform findings
                    analysis_status, findings = (
                        self._helper_generate_uniform_results(
                            parsed_output, tool_output
                        )
                    )

                    # Generate results.json with uniform findings
                    results_file = raw_output_path.parent / "results.json"
                    results_data = ResultsData(
                        status=analysis_status,
                        execution_time=round(tool_output.execution_time, 2),
                        findings=findings,
                    )
                    with open(results_file, "w", encoding="utf-8") as f:
                        json.dump(
                            results_data.to_dict(),
                            f,
                            indent=2,
                            ensure_ascii=False,
                        )

                    # Convert Finding objects to dictionaries for JSON serialization
                    findings_dicts = [f.to_dict() for f in findings]

                    # Map AnalysisStatus to ToolStatus
                    if analysis_status == AnalysisStatus.TIMEOUT:
                        tool_status = ToolStatus.TIMEOUT
                    elif analysis_status == AnalysisStatus.ERROR:
                        tool_status = ToolStatus.FAILED
                    else:
                        tool_status = ToolStatus.SUCCESS

                    logging.info(
                        f"{self.name}: Found {len(findings)} findings in {tool_output.execution_time:.2f}s"
                    )
                    result = ToolResult(
                        status=tool_status,
                        message=tool_output.msg,
                        execution_time=round(tool_output.execution_time, 2),
                        findings_count=len(findings),
                        findings=findings_dicts,
                        raw_output_file=str(tool_output.raw_output_file),
                        parsed_output_file=str(parsed_output_file),
                        results_file=str(results_file),
                    )
                except ToolError as e:
                    result = ToolResult(
                        status=ToolStatus.FAILED,
                        message=tool_output.msg,
                        execution_time=tool_output.execution_time,
                        findings_count=0,
                        findings=[],
                        error=str(e),
                    )
        except Exception as e:
            # Let it crash here because we want to see the full traceback
            # and should never be raised an exception here
            raise Exception(f"Error executing {self.name}: {e}") from e

        return result

    @abstractmethod
    def evaluate_zkbugs_ground_truth(
        self,
        tool: str,
        dsl: str,
        bug_name: str,
        ground_truth: Path,
        tool_result_path: Path,
    ) -> Dict[str, Any]:
        """Evaluate tool results against ground truth.

        Args:
            tool: Tool name
            dsl: Domain-specific language (e.g., "circom", "cairo")
            bug_name: Name of the bug being analyzed
            ground_truth: Path to ground truth JSON file
            tool_result_path: Path to tool results.json file

        Returns:
            Dictionary with evaluation result:
            {
                "status": "TruePositive" | "FalseNegative" | "Undecided",
                "reason": str (explanation of the status),
                "need_manual_analysis": bool (True unless 100% certain),
                "manual_analysis": "Pending" | "Done" | "N/A",
                "manual_analysis_reasoning": str ("TODO" or "N/A" or actual reasoning)
            }

        Be conservative: set need_manual_analysis=True unless 100% certain about the status.
        For example:
        - Tool found nothing → definitely FalseNegative
        - Tool found exact bug at exact component/line → definitely TruePositive
        - Otherwise → Undecided and needs manual analysis
        """
        pass

    # Utility methods that can be used by subclasses

    def check_binary_exists(self, binary_name: str) -> bool:
        """Check if a binary exists in PATH.

        Args:
            binary_name: Name of the binary to check

        Returns:
            True if binary exists in PATH, False otherwise
        """
        if shutil.which(binary_name) is None:
            logging.error(f"'{binary_name}' CLI not found in PATH")
            return False
        return True

    @staticmethod
    def _decode_output(output: str | bytes | None) -> str:
        """Safely decode subprocess output to string.

        Args:
            output: Output that might be str, bytes, or None

        Returns:
            Decoded string, or empty string if None
        """
        if output is None:
            return ""
        if isinstance(output, bytes):
            return output.decode("utf-8", errors="replace")
        return output

    def run_command(
        self, cmd: list[str], timeout: int, bug_path: str
    ) -> ToolOutput:
        """Run a subprocess command and return structured output.

        Args:
            cmd: Command and arguments as list
            timeout: Timeout in seconds
            bug_path: Path being analyzed (for logging)

        Returns:
            ToolOutput object with status, stdout, stderr, return_code, and msg
        """
        logging.info(f"Running: '{shlex.join(cmd)}'")

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, check=True, timeout=timeout
            )
            stdout = result.stdout or ""
            stderr = result.stderr or ""
            msg = f"stdout:\n{stdout}\nstderr:\n{stderr}"

            return ToolOutput(
                status=OutputStatus.SUCCESS,
                stdout=stdout,
                stderr=stderr,
                return_code=result.returncode,
                msg=msg,
            )

        except subprocess.TimeoutExpired as e:
            stdout = self._decode_output(getattr(e, "stdout", None))
            stderr = self._decode_output(getattr(e, "stderr", None))
            logging.warning(
                f"Process for '{self.name}' analysing '{bug_path}' exceeded {timeout} seconds and timed out. "
                f"Partial output: {stdout}"
            )
            msg = "[Timed out]"
            if stdout or stderr:
                msg += f"\nPartial stdout:\n{stdout}\nPartial stderr:\n{stderr}"

            return ToolOutput(
                status=OutputStatus.TIMEOUT,
                stdout=stdout,
                stderr=stderr,
                return_code=-1,
                msg=msg,
            )

        except subprocess.CalledProcessError as e:
            stdout = self._decode_output(e.stdout)
            stderr = self._decode_output(e.stderr)
            # Some tools (e.g., circomspect) return non-zero exit codes by design
            # but still produce valid output. Return SUCCESS status so output can be parsed.
            # Manually handle all standard linux exit codes
            if e.returncode in self.exit_codes:
                logging.warning(
                    f"Process for '{self.name}' analysing '{bug_path}' failed with exit code {e.returncode}. "
                    f"Partial output: {stdout}"
                )
                return ToolOutput(
                    status=OutputStatus.FAIL,
                    stdout=stdout,
                    stderr=stderr,
                    return_code=e.returncode,
                    msg=f"stdout:\n{stdout}\nstderr:\n{stderr}",
                )

            msg = f"stdout:\n{stdout}\nstderr:\n{stderr}"

            return ToolOutput(
                status=OutputStatus.SUCCESS,
                stdout=stdout,
                stderr=stderr,
                return_code=e.returncode,
                msg=msg,
            )

    def check_files_exist(self, *files: Path) -> bool:
        """Check if all provided files exist.

        Args:
            *files: Variable number of Path objects to check

        Returns:
            True if all files exist, False otherwise
        """
        for f in files:
            file_path = Path(f)
            if file_path.is_file():
                logging.debug(f"Found file: {file_path}")
            else:
                logging.error(f"File not found: {file_path}")
                return False
        return True

    def load_json_file(self, file_path: Path) -> Dict[str, Any]:
        """Load and parse a JSON file.

        Args:
            file_path: Path to JSON file

        Returns:
            Parsed JSON as dictionary, or empty dict on error
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Failed to read JSON file '{file_path}': {e}")
            return {}

    def change_directory(self, target_dir: Path) -> None:
        """Change current working directory.

        Args:
            target_dir: Target directory path
        """
        os.chdir(target_dir)
        logging.debug(f"Changed directory to: {Path.cwd()}")


# Utility functions that are used across the codebase


def ensure_dir(path: Path) -> None:
    """Create directory path if it doesn't exist (parents included)."""
    path.mkdir(parents=True, exist_ok=True)


def get_tool_result_parsed(tool_result_parsed: Path) -> dict:
    """Read a parsed tool result file and return the data.

    Args:
        tool_result_parsed: Path to parsed result JSON file

    Returns:
        Parsed JSON data, or empty dict on error
    """
    try:
        with open(tool_result_parsed, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        logging.error(
            f"Failed to read parsed tool result '{tool_result_parsed}': {e}"
        )
        return {}
    return data
