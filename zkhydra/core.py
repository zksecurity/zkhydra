#!/usr/bin/env python3
"""
zkHydra - Core execution logic for circuit analysis.

This module contains all the core logic for analyzing circuits with security tools,
including tool execution, result collection, and summary generation.
"""

import argparse
import json
import logging
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path

from zkhydra.printers import print_analyze_summary
from zkhydra.tools.base import Input, OutputStatus, ensure_dir
from zkhydra.utils.tools_resolver import ToolsDict, resolve_tools

BASE_DIR = Path.cwd()


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


@dataclass
class Statistics:
    """Statistics for tool execution results."""

    total_tools: int
    success: int
    failed: int
    timeout: int

    def to_dict(self) -> dict:
        """Convert Statistics to dictionary for JSON serialization."""
        return {
            "total_tools": self.total_tools,
            "success": self.success,
            "failed": self.failed,
            "timeout": self.timeout,
        }


@dataclass
class Summary:
    """Summary of analyze mode execution."""

    mode: str
    input: str
    dsl: str
    timestamp: str
    output_directory: str
    tools: dict[str, dict]
    statistics: Statistics
    total_findings: int
    total_execution_time: float

    def to_dict(self) -> dict:
        """Convert Summary to dictionary for JSON serialization."""
        return {
            "mode": self.mode,
            "input": self.input,
            "dsl": self.dsl,
            "timestamp": self.timestamp,
            "output_directory": self.output_directory,
            "tools": self.tools,
            "statistics": self.statistics.to_dict(),
            "total_findings": self.total_findings,
            "total_execution_time": self.total_execution_time,
        }


# Available tools per DSL
AVAILABLE_TOOLS = {
    "circom": ["circomspect", "circom_civer", "picus", "ecneproject", "zkfuzz"],
    "pil": ["pilspector"],
    "cairo": ["sierra-analyzer"],
}


def setup_output_directory(base_output: Path, mode: str) -> tuple[Path, str]:
    """
    Create timestamped output directory.

    Args:
        base_output: Base output directory
        mode: Mode name (analyze or evaluate)

    Returns:
        Tuple of (output_directory_path, timestamp)
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(base_output) / f"{mode}_{timestamp}"
    ensure_dir(output_dir)
    return output_dir, timestamp


def prepare_circuit_paths(input_path: Path) -> Input:
    """
    Create Input object with circuit directory and file paths for tool execution.

    Args:
        input_path: Input path (file)

    Returns:
        Input object containing absolute circuit_dir and circuit_file paths as strings
    """
    circuit_dir = input_path.parent
    circuit_file = input_path
    full_path_circuit_dir = circuit_dir.resolve()
    full_path_circuit_file = circuit_file.resolve()
    return Input(
        circuit_dir=str(full_path_circuit_dir),
        circuit_file=str(full_path_circuit_file),
    )


def execute_tools(
    tool_registry: ToolsDict,
    input_paths: Input,
    output_dir: Path,
    timeout: int,
) -> dict[str, ToolResult]:
    """
    Execute all tools and collect results.

    Args:
        tool_registry: Loaded tool modules
        input_paths: Input object containing circuit_dir and circuit_file paths
        output_dir: Output directory for results
        timeout: Timeout per tool in seconds

    Returns:
        Dictionary mapping tool names to ToolResult objects
    """
    results = {}

    for tool_name, tool_instance in tool_registry.items():
        logging.info(f"Running {tool_name}...")

        # Create output directory for this tool
        tool_output_dir = output_dir / tool_name
        ensure_dir(tool_output_dir)
        raw_output_file = Path(tool_output_dir) / "raw.txt"

        # Measure execution time
        start_time = time.time()

        try:
            # Execute tool - returns ToolOutput object
            tool_output = tool_instance.execute(input_paths, timeout)

            # Write raw output (msg field contains combined stdout/stderr)
            with open(raw_output_file, "w", encoding="utf-8") as f:
                f.write(tool_output.msg)

            execution_time = time.time() - start_time

            # Check tool execution status
            if tool_output.status == OutputStatus.TIMEOUT:
                results[tool_name] = ToolResult(
                    status=ToolStatus.TIMEOUT,
                    message=tool_output.msg,
                    execution_time=round(execution_time, 2),
                    findings_count=0,
                    findings=[],
                    raw_output_file=str(raw_output_file),
                )
                logging.warning(
                    f"{tool_name}: Timed out after {execution_time:.2f}s"
                )
            elif tool_output.status == OutputStatus.FAIL:
                # Tool failed (binary not found, file not found, etc.)
                results[tool_name] = ToolResult(
                    status=ToolStatus.FAILED,
                    message=tool_output.msg,
                    execution_time=round(execution_time, 2),
                    findings_count=0,
                    findings=[],
                    error=tool_output.msg,
                    raw_output_file=str(raw_output_file),
                )
                logging.error(f"{tool_name}: {tool_output.msg}")
            else:
                # Success - parse findings from output
                findings = tool_instance.parse_findings(tool_output.msg)

                # Convert Finding objects to dictionaries for JSON serialization
                findings_dicts = [f.to_dict() for f in findings]

                results[tool_name] = ToolResult(
                    status=ToolStatus.SUCCESS,
                    message=tool_output.msg,
                    execution_time=round(execution_time, 2),
                    findings_count=len(findings),
                    findings=findings_dicts,
                    raw_output_file=str(raw_output_file),
                )

                logging.info(
                    f"{tool_name}: Found {len(findings)} findings in {execution_time:.2f}s"
                )

        except Exception as e:
            # Let it crash here because we want to see the full traceback
            # and should never be raised an exception here
            raise Exception(f"Error executing {tool_name}: {e}") from e

    return results


def analyze_mode(
    circuit: Path, tools: list[str], dsl: str, timeout: int, output: Path
) -> None:
    """
    Analyze mode: Run tools on a circuit and report findings.
    """
    logging.info("Running in ANALYZE mode")
    logging.info(f"Circuit: {circuit}")
    logging.info(f"Tools: {tools}")
    logging.info(f"Loading tools: {tools}")

    # Resolve tool modules
    tool_registry = resolve_tools(tools)
    if not tool_registry:
        logging.error("No tools loaded successfully")
        sys.exit(1)

    # Setup output directory
    output_dir, timestamp = setup_output_directory(output, "analyze")
    logging.info(f"Output directory: {output_dir}")

    # Determine circuit paths
    input_paths = prepare_circuit_paths(circuit)
    logging.info(f"Circuit directory: {input_paths.circuit_dir}")
    logging.info(f"Circuit file: {input_paths.circuit_file}")

    # Execute all tools
    results = execute_tools(
        tool_registry,
        input_paths,
        output_dir,
        timeout,
    )

    # Generate statistics
    statistics = Statistics(
        total_tools=len(results),
        success=sum(
            1 for r in results.values() if r.status == ToolStatus.SUCCESS
        ),
        failed=sum(
            1 for r in results.values() if r.status == ToolStatus.FAILED
        ),
        timeout=sum(
            1 for r in results.values() if r.status == ToolStatus.TIMEOUT
        ),
    )

    # Generate summary
    summary = Summary(
        mode="analyze",
        input=str(circuit),
        dsl=dsl,
        timestamp=timestamp,
        output_directory=str(output_dir),
        tools={name: result.to_dict() for name, result in results.items()},
        statistics=statistics,
        total_findings=sum(
            r.findings_count
            for r in results.values()
            if r.status == ToolStatus.SUCCESS
        ),
        total_execution_time=sum(r.execution_time for r in results.values()),
    )

    # Write summary JSON
    summary_file = Path(output_dir) / "summary.json"
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(summary.to_dict(), f, indent=2, ensure_ascii=False)

    # Print CLI summary
    print_analyze_summary(summary.to_dict())


def evaluate_mode(args: argparse.Namespace) -> None:
    """
    Evaluate mode: Not implemented.

    Raises:
        NotImplementedError: Evaluate mode is not yet implemented.
    """
    raise NotImplementedError(
        "Evaluate mode is not yet implemented. Use 'analyze' mode instead."
    )
