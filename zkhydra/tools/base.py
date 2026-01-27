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
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

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


@dataclass
class Finding:
    """Standardized finding/vulnerability from a security analysis tool.

    This class represents a single security finding discovered by an analysis tool.
    All tools should return findings in this standardized format.
    """

    # Required fields
    description: str  # Human-readable one-line description
    bug_type: (
        str  # Type of bug (e.g., "underconstrained", "weak_safety violation")
    )
    raw_message: str  # Complete raw message from the tool
    # Optional fields - tool-specific details
    circuit: Optional[str] = None  # Circuit file path
    template: Optional[str] = None  # Template/function name where bug was found
    component: Optional[str] = (
        None  # Component name (for tools like circom_civer)
    )
    signal: Optional[str] = None  # Signal name (for tools like zkfuzz)
    line: Optional[str] = (
        None  # Line number(s) as string (can be "10" or "10-15")
    )
    code: Optional[str] = (
        None  # Tool-specific code (e.g., "CS0013" for circomspect)
    )
    severity: Optional[str] = (
        None  # Severity level ("error", "warning", "note")
    )
    metadata: Dict[str, Any] = field(
        default_factory=dict
    )  # Additional tool-specific data

    def to_dict(self) -> Dict[str, Any]:
        """Convert Finding to dictionary for JSON serialization.

        Returns:
            Dictionary with all non-None fields
        """
        # If any field is None set it to empty of its type
        return {
            "description": self.description,
            "bug_type": self.bug_type,
            "raw_message": self.raw_message,
            "circuit": self.circuit if self.circuit else "",
            "template": self.template if self.template else "",
            "component": self.component if self.component else "",
            "signal": self.signal if self.signal else "",
            "line": self.line if self.line else "",
            "code": self.code if self.code else "",
            "severity": self.severity if self.severity else "",
            "metadata": self.metadata if self.metadata else {},
        }


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
        }


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
        return ToolOutput(
            status=tool_output.status,
            stdout=tool_output.stdout,
            stderr=tool_output.stderr,
            return_code=tool_output.return_code,
            msg=tool_output.msg,
            execution_time=execution_time,
            raw_output_file=str(raw_output_file),
        )

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

    def process_output(self, tool_output: ToolOutput) -> ToolResult:
        """Process tool output into structured result.

        Args:
            tool_output: ToolOutput object with status, stdout, stderr, return_code, and msg

        Returns:
            ToolResult object with status, message, execution_time, findings_count, findings, error, and raw_output_file
        """
        try:
            # Check tool execution status
            if tool_output.status == OutputStatus.TIMEOUT:
                return ToolResult(
                    status=ToolStatus.TIMEOUT,
                    message=tool_output.msg,
                    execution_time=tool_output.execution_time,
                    findings_count=0,
                    findings=[],
                    raw_output_file=str(tool_output.raw_output_file),
                )
            if tool_output.status == OutputStatus.FAIL:
                # Tool failed (binary not found, file not found, etc.)
                return ToolResult(
                    status=ToolStatus.FAILED,
                    message=tool_output.msg,
                    execution_time=tool_output.execution_time,
                    findings_count=0,
                    findings=[],
                    error=tool_output.msg,
                    raw_output_file=str(tool_output.raw_output_file),
                )
                logging.error(f"{self.name}: {tool_output.msg}")
            # Success - parse findings from output
            try:
                findings = self.parse_findings(tool_output.msg)
            except ToolError as e:
                return ToolResult(
                    status=ToolStatus.FAILED,
                    message=tool_output.msg,
                    execution_time=tool_output.execution_time,
                    findings_count=0,
                    findings=[],
                    error=str(e),
                )

            # Convert Finding objects to dictionaries for JSON serialization
            findings_dicts = [f.to_dict() for f in findings]

            logging.info(
                f"{self.name}: Found {len(findings)} findings in {tool_output.execution_time:.2f}s"
            )

            return ToolResult(
                status=ToolStatus.SUCCESS,
                message=tool_output.msg,
                execution_time=round(tool_output.execution_time, 2),
                findings_count=len(findings),
                findings=findings_dicts,
                raw_output_file=str(tool_output.raw_output_file),
            )

        except Exception as e:
            # Let it crash here because we want to see the full traceback
            # and should never be raised an exception here
            raise Exception(f"Error executing {self.name}: {e}") from e

    @abstractmethod
    def parse_findings(self, raw_output: str) -> List[Finding]:
        """Parse raw tool output into structured findings.

        This method extracts vulnerability findings from the tool's raw output
        and returns them as Finding objects in a standardized format.

        Args:
            raw_output: Raw output string from tool execution

        Returns:
            List of Finding objects with standardized structure.
            Each Finding must have at minimum description and bug_type set.
            Additional fields (template, signal, line, etc.) should be populated
            when available from the tool output.

        Note:
            This is different from parse_output() which is used for ground truth
            comparison in evaluate mode. This method is for quick analysis display.
        """
        pass

    @abstractmethod
    def compare_zkbugs_ground_truth(
        self,
        tool: str,
        dsl: str,
        bug_name: str,
        ground_truth: Path,
        tool_result_parsed: Path,
    ) -> Dict[str, Any]:
        """Compare parsed tool results against ground truth.

        Args:
            tool: Tool name
            dsl: Domain-specific language (e.g., "circom", "cairo")
            bug_name: Name of the bug being analyzed
            ground_truth: Path to ground truth JSON file
            tool_result_parsed: Path to parsed tool results JSON file

        Returns:
            Dictionary with comparison result:
            {
                "result": "correct" | "false" | "timeout" | "error",
                "reason": str (optional explanation),
                "need_manual_evaluation": bool (optional)
            }
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
            stdout = getattr(e, "stdout", "") or ""
            stderr = getattr(e, "stderr", "") or ""
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
            stdout = e.stdout or ""
            stderr = e.stderr or ""
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
                    stdout=e.stdout or "",
                    stderr=e.stderr or "",
                    return_code=e.returncode,
                    msg=f"stdout:\n{e.stdout}\nstderr:\n{e.stderr}",
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
