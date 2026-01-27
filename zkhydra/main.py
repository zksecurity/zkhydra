#!/usr/bin/env python3
"""
zkHydra - Zero-Knowledge Circuit Security Analysis Tool Runner

Supports analyze mode:
- analyze: Run tools on a specific circuit file and report findings
"""

import argparse
import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path

from zkhydra.cli import parse_args
from zkhydra.tools.base import Input, OutputStatus, ensure_dir
from zkhydra.utils.logger import setup_logging
from zkhydra.utils.tools_resolver import resolve_tools

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


# Available tools per DSL
AVAILABLE_TOOLS = {
    "circom": ["circomspect", "circom_civer", "picus", "ecneproject", "zkfuzz"],
    "pil": ["pilspector"],
    "cairo": ["sierra-analyzer"],
}


def expand_tools_list(tools_str: str, dsl: str) -> list[str]:
    """
    Expand tools list, handling the special 'all' keyword.

    Args:
        tools_str: Comma-separated tools or 'all'
        dsl: Domain-specific language

    Returns:
        List of tool names
    """
    tools_str = tools_str.strip().lower()

    if tools_str == "all":
        available = AVAILABLE_TOOLS.get(dsl, [])
        if not available:
            logging.warning(f"No tools available for DSL '{dsl}'")
            return []
        logging.info(f"Expanding 'all' to: {', '.join(available)}")
        return available

    # Parse comma-separated list
    return [t.strip().lower() for t in tools_str.split(",") if t.strip()]


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
    output_dir = base_output / f"{mode}_{timestamp}"
    ensure_dir(output_dir)
    return output_dir, timestamp


def prepare_circuit_paths(input_path: Path) -> tuple[Path, Path]:
    """
    Determine circuit file and directory paths from input.

    Args:
        input_path: Input path (file or directory)

    Returns:
        Tuple of (circuit_directory, circuit_file)
    """
    if input_path.is_file():
        # Input is a file - extract parent directory
        circuit_dir = (
            input_path.parent.parent
            if input_path.parent.name == "circuits"
            else input_path.parent
        )
        circuit_file = input_path
    else:
        # Input is a directory
        circuit_dir = input_path
        circuit_file = input_path / "circuits" / "circuit.circom"

    return circuit_dir, circuit_file


def get_tool_input_path(circuit_file: Path, circuit_dir: Path) -> Input:
    """
    Create Input object with circuit directory and file paths for tool execution.

    Args:
        circuit_file: Path to circuit file
        circuit_dir: Path to circuit directory

    Returns:
        Input object containing absolute circuit_dir and circuit_file paths as strings
    """
    full_path_circuit_dir = circuit_dir.resolve()
    full_path_circuit_file = circuit_file.resolve()
    return Input(
        circuit_dir=str(full_path_circuit_dir),
        circuit_file=str(full_path_circuit_file),
    )


def execute_tools(
    tools_list: list[str],
    tool_registry: dict,
    circuit_file: Path,
    circuit_dir: Path,
    output_dir: Path,
    timeout: int,
) -> dict[str, ToolResult]:
    """
    Execute all tools and collect results.

    Args:
        tools_list: List of tool names to run
        tool_registry: Loaded tool modules
        circuit_file: Path to circuit file
        circuit_dir: Path to circuit directory
        output_dir: Output directory for results
        timeout: Timeout per tool in seconds

    Returns:
        Dictionary mapping tool names to ToolResult objects
    """
    results = {}

    for tool_name in tools_list:
        if tool_name not in tool_registry:
            logging.warning(f"Tool '{tool_name}' failed to load, skipping")
            continue

        logging.info(f"Running {tool_name}...")
        tool_module = tool_registry[tool_name]

        # Create output directory for this tool
        tool_output_dir = output_dir / tool_name
        ensure_dir(tool_output_dir)
        raw_output_file = os.path.join(tool_output_dir, "raw.txt")

        # Measure execution time
        start_time = time.time()

        try:
            # Create Input object with circuit directory and file paths
            input_paths = get_tool_input_path(circuit_file, circuit_dir)

            # Execute tool - returns ToolOutput object
            tool_output = tool_module.execute(input_paths, timeout)

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
                tool_instance = tool_registry[tool_name]
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
            execution_time = time.time() - start_time
            logging.error(f"{tool_name} failed: {e}")
            results[tool_name] = ToolResult(
                status=ToolStatus.FAILED,
                message=str(e),
                execution_time=round(execution_time, 2),
                error=str(e),
                findings_count=0,
                findings=[],
                raw_output_file=str(raw_output_file),
            )

    return results


def analyze_mode(args: argparse.Namespace) -> None:
    """
    Analyze mode: Run tools on a circuit and report findings.

    Does NOT use ground truth comparison.
    """
    logging.info("Running in ANALYZE mode")
    logging.info(f"Input: {args.input}")
    logging.info(f"Tools: {args.tools}")

    # Validate input file exists
    if not args.input.exists():
        logging.error(f"Input file not found: {args.input}")
        sys.exit(1)

    # Parse tools list (expand 'all' if needed)
    tools_list = expand_tools_list(args.tools, args.dsl)
    if not tools_list:
        logging.error("No tools specified")
        sys.exit(1)
    logging.info(f"Loading tools: {tools_list}")

    # Resolve tool modules
    tool_registry = resolve_tools(tools_list)
    if not tool_registry:
        logging.error("No tools loaded successfully")
        sys.exit(1)

    # Setup output directory
    output_dir, timestamp = setup_output_directory(args.output, "analyze")
    logging.info(f"Output directory: {output_dir}")

    # Determine circuit paths
    circuit_dir, circuit_file = prepare_circuit_paths(args.input)

    # Execute all tools
    results = execute_tools(
        tools_list,
        tool_registry,
        circuit_file,
        circuit_dir,
        output_dir,
        args.timeout,
    )

    # Generate summary
    summary = {
        "mode": "analyze",
        "input": str(args.input),
        "dsl": args.dsl,
        "timestamp": timestamp,
        "output_directory": str(output_dir),
        "tools": {name: result.to_dict() for name, result in results.items()},
        "statistics": {
            "total_tools": len(results),
            "success": sum(
                1 for r in results.values() if r.status == ToolStatus.SUCCESS
            ),
            "failed": sum(
                1 for r in results.values() if r.status == ToolStatus.FAILED
            ),
            "timeout": sum(
                1 for r in results.values() if r.status == ToolStatus.TIMEOUT
            ),
        },
        "total_findings": sum(
            r.findings_count
            for r in results.values()
            if r.status == ToolStatus.SUCCESS
        ),
        "total_execution_time": sum(r.execution_time for r in results.values()),
    }

    # Write summary JSON
    summary_file = output_dir / "summary.json"
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    # Print CLI summary
    print_analyze_summary(summary)


def evaluate_mode(args: argparse.Namespace) -> None:
    """
    Evaluate mode: Not implemented.

    Raises:
        NotImplementedError: Evaluate mode is not yet implemented.
    """
    raise NotImplementedError(
        "Evaluate mode is not yet implemented. Use 'analyze' mode instead."
    )


def print_analyze_summary(summary: dict) -> None:
    """Print formatted summary for analyze mode."""
    print("\n" + "=" * 80)
    print("ANALYZE MODE - SUMMARY")
    print("=" * 80)
    print(f"Input:          {summary['input']}")
    print(f"Output:         {summary['output_directory']}")
    print(f"Total Time:     {summary['total_execution_time']:.2f}s")
    print(f"Total Findings: {summary['total_findings']}")

    stats = summary.get("statistics", {})
    if stats:
        print("\n" + "-" * 80)
        print("STATISTICS:")
        print("-" * 80)
        print(f"Total Tools:  {stats.get('total_tools', 0)}")
        print(f"Success:      {stats.get('success', 0)}")
        print(f"Failed:       {stats.get('failed', 0)}")
        print(f"Timeout:      {stats.get('timeout', 0)}")

    print("\n" + "-" * 80)
    print("TOOL RESULTS:")
    print("-" * 80)

    for tool_name, result in summary["tools"].items():
        status = result.get("status", "unknown")

        # Status symbols
        status_symbol = {
            "success": "✓",
            "failed": "✗",
            "timeout": "⏱",
        }.get(status, "?")

        status_text = status.upper()

        print(f"\n{tool_name.upper()}: {status_symbol} {status_text}")
        print(f"  Time:     {result['execution_time']}s")
        print(f"  Output:   {result.get('raw_output_file', 'N/A')}")

        if status == "success":
            print(f"  Findings: {result['findings_count']}")

            if result.get("findings"):
                print("\n  Findings List:")
                for idx, finding in enumerate(
                    result["findings"][:10], 1
                ):  # Show first 10
                    desc = finding.get(
                        "description", finding.get("type", "Unknown")
                    )
                    print(f"    {idx}. {desc}")
                if result["findings_count"] > 10:
                    print(f"    ... and {result['findings_count'] - 10} more")

        elif status == "failed":
            print(f"  Error:    {result.get('error', 'Unknown error')}")

        elif status == "timeout":
            print("  Status:   Tool execution timed out")

    print("\n" + "=" * 80)


def main() -> None:
    """Main entry point for zkHydra."""
    args = parse_args()

    # Setup logging
    output_dir = args.output / datetime.now().strftime("%Y%m%d_%H%M%S")
    setup_logging(args.log_level, output_dir, args.log_file)

    logging.info(f"zkHydra starting in {args.mode.upper()} mode")

    if args.dsl != "circom":
        logging.error(f"DSL '{args.dsl}' is not supported yet")
        sys.exit(1)

    try:
        if args.mode == "analyze":
            analyze_mode(args)
        else:
            evaluate_mode(args)
    except KeyboardInterrupt:
        logging.warning("Interrupted by user")
        sys.exit(130)
    except Exception as e:
        logging.exception(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
