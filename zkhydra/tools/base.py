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
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class Finding:
    """Standardized finding/vulnerability from a security analysis tool.

    This class represents a single security finding discovered by an analysis tool.
    All tools should return findings in this standardized format.
    """

    # Required fields
    description: str  # Human-readable one-line description
    bug_type: str  # Type of bug (e.g., "underconstrained", "warning", "error")

    # Optional fields - tool-specific details
    raw_message: Optional[str] = None  # Complete raw message from the tool
    circuit: Optional[str] = None  # Circuit file path
    template: Optional[str] = None  # Template/function name where bug was found
    component: Optional[str] = None  # Component name (for tools like circom_civer)
    signal: Optional[str] = None  # Signal name (for tools like zkfuzz)
    line: Optional[str] = None  # Line number(s) as string (can be "10" or "10-15")
    code: Optional[str] = None  # Tool-specific code (e.g., "CS0013" for circomspect)
    severity: Optional[str] = None  # Severity level ("error", "warning", "note")
    location: Optional[str] = None  # Full location string from tool
    metadata: Dict[str, Any] = field(default_factory=dict)  # Additional tool-specific data

    def to_dict(self) -> Dict[str, Any]:
        """Convert Finding to dictionary for JSON serialization.

        Returns:
            Dictionary with all non-None fields
        """
        result = {
            "description": self.description,
            "bug_type": self.bug_type,
        }

        # Add optional fields only if they have values
        if self.raw_message is not None:
            result["raw_message"] = self.raw_message
        if self.circuit is not None:
            result["circuit"] = self.circuit
        if self.template is not None:
            result["template"] = self.template
        if self.component is not None:
            result["component"] = self.component
        if self.signal is not None:
            result["signal"] = self.signal
        if self.line is not None:
            result["line"] = self.line
        if self.code is not None:
            result["code"] = self.code
        if self.severity is not None:
            result["severity"] = self.severity
        if self.location is not None:
            result["location"] = self.location
        if self.metadata:
            result["metadata"] = self.metadata

        return result


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

    @abstractmethod
    def execute(self, bug_path: str, timeout: int) -> str:
        """Execute the tool on a circuit and return raw output.

        Args:
            bug_path: Path to the circuit file or directory containing the circuit
            timeout: Maximum execution time in seconds

        Returns:
            Raw tool output as string, or an error marker like "[Binary not found]"

        Note:
            The returned string should contain both stdout and stderr,
            formatted as: "stdout:\n<stdout>\nstderr:\n<stderr>"
        """
        pass

    @abstractmethod
    def parse_output(
        self, tool_result_raw: Path, ground_truth: Path
    ) -> Dict[str, Any]:
        """Parse raw tool output into structured format.

        Args:
            tool_result_raw: Path to file containing raw tool output
            ground_truth: Path to ground truth JSON file

        Returns:
            Dictionary containing structured parsing results.
            The structure is tool-specific but should include relevant
            findings, warnings, or vulnerability information.
        """
        pass

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

    def run_command(self, cmd: list[str], timeout: int, bug_path: str) -> str:
        """Run a subprocess command and return combined stdout/stderr.

        Args:
            cmd: Command and arguments as list
            timeout: Timeout in seconds
            bug_path: Path being analyzed (for logging)

        Returns:
            Combined stdout/stderr output, or "[Timed out]" on timeout
        """
        logging.info(f"Running: '{shlex.join(cmd)}'")

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, check=True, timeout=timeout
            )
            return (
                "stdout:\n"
                + (result.stdout or "")
                + "\nstderr:\n"
                + (result.stderr or "")
            )

        except subprocess.TimeoutExpired as e:
            logging.warning(
                f"Process for '{self.name}' analysing '{bug_path}' exceeded {timeout} seconds and timed out. "
                f"Partial output: {getattr(e, 'stdout', '')}"
            )
            return "[Timed out]"

        except subprocess.CalledProcessError as e:
            logging.warning(
                f"Process for '{self.name}' analysing '{bug_path}' failed with exit code {e.returncode}. "
                f"Partial output: {e.stdout}"
            )
            # Some tools (e.g., circomspect) return non-zero exit codes by design
            return "stdout:\n" + e.stdout + "\nstderr:\n" + e.stderr

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
        logging.error(f"Failed to read parsed tool result '{tool_result_parsed}': {e}")
        return {}
    return data


def remove_bug_entry(output: dict, dsl: str, tool: str, bug_name: str) -> dict:
    """Remove a bug from all result buckets for a tool.

    Args:
        output: Output dictionary containing results
        dsl: Domain-specific language
        tool: Tool name
        bug_name: Bug name to remove

    Returns:
        Modified output dictionary
    """
    for bucket_name in ["false", "error", "timeout", "correct"]:
        bucket = output[dsl][tool][bucket_name]
        if isinstance(bucket, list):
            new_bucket = []
            for item in bucket:
                if isinstance(item, dict):
                    if item.get("bug_name") == bug_name:
                        continue
                elif item == bug_name:
                    continue
                new_bucket.append(item)
            bucket[:] = new_bucket

    return output
