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
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from zkhydra.printers import print_analyze_summary
from zkhydra.tools.base import Input, ToolResult, ToolStatus, ensure_dir
from zkhydra.utils.tools_resolver import ToolsDict, resolve_tools

BASE_DIR = Path.cwd()


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

        # Execute tool - returns ToolOutput object
        tool_output = tool_instance.execute(
            input_paths, timeout, raw_output_file
        )

        results[tool_name] = tool_instance.process_output(tool_output)

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
