#!/usr/bin/env python3
"""
zkHydra - Core execution logic for circuit analysis.

This module contains all the core logic for analyzing circuits with security tools,
including tool execution, result collection, and summary generation.
"""

import argparse
import json
import logging
import os
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from zkhydra.printers import print_analyze_summary
from zkhydra.tools.base import (
    AbstractTool,
    AnalysisStatus,
    Input,
    ResultsData,
    ToolOutput,
    ToolResult,
    ToolStatus,
    ensure_dir,
)
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


def discover_zkbugs(dataset_dir: Path) -> list[dict]:
    """
    Discover all bugs in the dataset by finding zkbugs_config.json files.

    Args:
        dataset_dir: Path to the zkbugs dataset directory

    Returns:
        List of bug information dictionaries containing:
            - config_path: Path to zkbugs_config.json
            - bug_dir: Path to the bug directory
            - bug_name: Name of the bug
            - circuit_path: Path to circuit.circom (if exists)
    """
    bugs = []
    config_files = list(dataset_dir.rglob("zkbugs_config.json"))

    logging.info(f"Found {len(config_files)} zkbugs_config.json files")

    for config_path in config_files:
        bug_dir = config_path.parent
        bug_name = bug_dir.name

        # Check if circuit.circom exists
        circuit_path = bug_dir / "circuits" / "circuit.circom"

        if not circuit_path.exists():
            logging.warning(
                f"Bug '{bug_name}': circuit.circom not found at {circuit_path}"
            )
            circuit_path = None

        bugs.append(
            {
                "config_path": config_path,
                "bug_dir": bug_dir,
                "bug_name": bug_name,
                "circuit_path": circuit_path,
            }
        )

    return bugs


def generate_ground_truth(config_path: Path, output_path: Path) -> None:
    """
    Generate ground_truth.json from zkbugs_config.json.

    Args:
        config_path: Path to zkbugs_config.json
        output_path: Path where ground_truth.json should be written
    """
    with open(config_path, encoding="utf-8") as f:
        config = json.load(f)

    # Extract the bug details (config is dict with single key)
    bug_key = list(config.keys())[0]
    bug_data = config[bug_key]

    ground_truth = {
        "bug_name": bug_key,
        "vulnerability": bug_data.get("Vulnerability"),
        "impact": bug_data.get("Impact"),
        "root_cause": bug_data.get("Root Cause"),
        "location": bug_data.get("Location", {}),
        "dsl": bug_data.get("DSL"),
        "project": bug_data.get("Project"),
        "commit": bug_data.get("Commit"),
        "fix_commit": bug_data.get("Fix Commit"),
        "reproduced": bug_data.get("Reproduced"),
        "short_description": bug_data.get(
            "Short Description of the Vulnerability"
        ),
        "proposed_mitigation": bug_data.get("Proposed Mitigation"),
        "source": bug_data.get("Source"),
    }

    ensure_dir(output_path.parent)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(ground_truth, f, indent=2, ensure_ascii=False)


def _helper_eval(
    tool_result: ToolResult,
    tool_instance: AbstractTool,
    tool_name: str,
    dsl: str,
    bug_name: str,
    ground_truth_path: Path,
    bug_output_dir: Path,
) -> None:
    if tool_result.status != ToolStatus.SUCCESS:
        # Tool failed or timed out, skip evaluation
        return

    # Evaluate findings against ground truth
    evaluation = tool_instance.evaluate_zkbugs_ground_truth(
        tool_name,
        dsl,
        bug_name,
        ground_truth_path,
        bug_output_dir / tool_name / "results.json",
    )

    # Write evaluation results
    eval_path = bug_output_dir / tool_name / "evaluation.json"
    with open(eval_path, "w", encoding="utf-8") as f:
        json.dump(evaluation, f, indent=2, ensure_ascii=False)

    logging.info(
        f"{tool_name} evaluation: {evaluation.get('status', 'Unknown')}"
    )


def zkbugs_mode(
    dataset_dir: Path, tools: list[str], dsl: str, timeout: int, output: Path
) -> None:
    """
    zkbugs mode: Evaluate tools against the zkbugs dataset.

    Args:
        dataset_dir: Path to zkbugs dataset directory
        tools: List of tool names to run
        dsl: Domain-specific language (currently only 'circom')
        timeout: Timeout per tool execution in seconds
        output: Output directory for results
    """
    logging.info("Running in ZKBUGS mode")
    logging.info(f"Dataset: {dataset_dir}")
    logging.info(f"DSL: {dsl}")
    logging.info(f"Tools: {tools}")
    logging.info(f"Timeout: {timeout}s")

    # Discover bugs
    bugs = discover_zkbugs(dataset_dir)
    logging.info(f"Total bugs discovered: {len(bugs)}")

    # Filter bugs that have circuit.circom
    bugs_with_circuits = [b for b in bugs if b["circuit_path"] is not None]
    logging.info(
        f"Bugs with circuit.circom: {len(bugs_with_circuits)}/{len(bugs)}"
    )

    if not bugs_with_circuits:
        logging.error("No bugs with circuit.circom found")
        sys.exit(1)

    # Resolve tool modules
    tool_registry = resolve_tools(tools)
    if not tool_registry:
        logging.error("No tools loaded successfully")
        sys.exit(1)

    # Create output directory
    ensure_dir(output)
    logging.info(f"Output directory: {output}")

    # Process all bugs with circuits
    bugs_to_process = bugs_with_circuits

    # Process each bug
    for idx, bug in enumerate(bugs_to_process, 1):
        logging.info(f"\n{'='*80}")
        logging.info(
            f"Processing bug {idx}/{len(bugs_to_process)}: {bug['bug_name']}"
        )
        logging.info(f"{'='*80}")

        # Create bug-specific output directory
        bug_output_dir = output / bug["bug_name"]
        ensure_dir(bug_output_dir)

        # Generate ground truth
        ground_truth_path = bug_output_dir / "ground_truth.json"
        generate_ground_truth(bug["config_path"], ground_truth_path)
        logging.info(f"Generated ground truth: {ground_truth_path}")

        # Prepare circuit paths
        input_paths = prepare_circuit_paths(bug["circuit_path"])

        # Execute all tools
        results = execute_tools(
            tool_registry,
            input_paths,
            bug_output_dir,
            timeout,
        )

        # Evaluate each tool's results against ground truth
        for tool_name, tool_instance in tool_registry.items():
            if tool_name not in results:
                continue

            tool_result = results[tool_name]
            _helper_eval(
                tool_result,
                tool_instance,
                tool_name,
                dsl,
                bug,
                ground_truth_path,
                bug_output_dir,
            )

    logging.info(f"\n{'='*80}")
    logging.info("zkbugs mode completed")
    logging.info(f"Results written to: {output}")
    logging.info(f"{'='*80}")


def vanilla_mode(output_dir: Path, eval: bool, dsl: str = "circom") -> None:
    """
    Vanilla mode: Process existing .raw files.

    Args:
        output_dir: Output directory
        eval: Whether to evaluate the results
    """
    logging.info("Running in VANILLA mode")
    logging.info(f"Output directory: {output_dir}")
    logging.info(f"Evaluate: {eval}")

    # check if there is a ground truth file or a summary file
    # If there is then we are processing a bug
    # If not then we are processing a dir of many bugs
    ground_truth_path = output_dir / "ground_truth.json"
    summary_path = output_dir / "summary.json"
    bugs_dir = []
    if ground_truth_path.exists() or summary_path.exists():
        logging.info("Processing a bug")
        bugs_dir.append(output_dir)
    else:
        logging.info("Processing a dir of many bugs")
        bugs_dir = list(output_dir.rglob("*"))

    for bug_dir in bugs_dir:
        logging.info(f"Processing bug: {bug_dir}")
        bug_name = bug_dir.name
        # Find all tool directories in the bug directory
        tool_dirs = [
            Path(bug_dir) / d
            for d in os.listdir(bug_dir)
            if (Path(bug_dir) / d).is_dir()
        ]
        for tool_dir in tool_dirs:
            tool_name = tool_dir.name
            logging.info(f"Processing tool: {tool_name}")
            # Load the results.json file
            with open(tool_dir / "results.json", encoding="utf-8") as f:
                results_data = json.load(f)
            results = ResultsData.from_dict(results_data)
            # Load the tool_output.json file
            with open(tool_dir / "tool_output.json", encoding="utf-8") as f:
                tool_output = ToolOutput.from_dict(json.load(f))
            # If the result was TIMEOUT, then we can skip
            if results.status == AnalysisStatus.TIMEOUT:
                logging.info(f"Tool {tool_name} timed out, skipping")
                continue
            # Redo the analysis of the tool result
            tool_instance = resolve_tools([tool_name])[tool_name]
            # Process the tool output
            tool_result = tool_instance.process_output(tool_output)

            # Load the ground truth file
            if eval:
                ground_truth_path = bug_dir / "ground_truth.json"
                _helper_eval(
                    tool_result,
                    tool_instance,
                    tool_name,
                    dsl,
                    bug_name,
                    ground_truth_path,
                    bug_dir,
                )
