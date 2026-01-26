#!/usr/bin/env python3
"""
zkHydra - Zero-Knowledge Circuit Security Analysis Tool Runner

Supports two modes:
- analyze: Run tools on a specific circuit file and report findings
- evaluate: Run tools and compare results against ground truth for evaluation
"""

import argparse
import json
import logging
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from utils.logger import setup_logging
from utils.tools_resolver import resolve_tools
from tools.utils import ensure_dir

BASE_DIR = Path.cwd()

# Available tools per DSL
AVAILABLE_TOOLS = {
    "circom": ["circomspect", "circom_civer", "picus", "ecneproject", "zkfuzz"],
    "pil": ["pilspector"],
    "cairo": ["sierra-analyzer"],
}


def parse_args() -> argparse.Namespace:
    """Parse command line arguments for zkHydra."""
    parser = argparse.ArgumentParser(
        description="zkHydra - Zero-Knowledge Circuit Security Analysis Tool Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a circuit with circomspect
  %(prog)s analyze --input test_bug/circuits/circuit.circom --tools circomspect

  # Analyze with multiple tools
  %(prog)s analyze --input circuit.circom --tools circomspect,circom_civer,picus

  # Evaluate against ground truth
  %(prog)s evaluate --input test_bug/zkbugs_config.json --tools circomspect
        """,
    )

    # Mode selection
    parser.add_argument(
        "mode",
        choices=["analyze", "evaluate"],
        help="Mode: 'analyze' for finding bugs, 'evaluate' for ground truth comparison",
    )

    # Input/Output
    parser.add_argument(
        "--input",
        "-i",
        type=Path,
        required=True,
        help="Input: circuit file (.circom) for analyze mode, or config file (.json) for evaluate mode",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path("output"),
        help="Output directory (default: output/)",
    )

    # Tool selection
    parser.add_argument(
        "--tools",
        "-t",
        type=str,
        required=True,
        help="Comma-separated list of tools or 'all' for all available tools (e.g., circomspect,circom_civer,picus,ecneproject,zkfuzz or all)",
    )

    # DSL (currently only circom, but future-proof)
    parser.add_argument(
        "--dsl",
        type=str,
        default="circom",
        choices=["circom", "pil", "cairo"],
        help="Domain-specific language (default: circom)",
    )

    # Execution settings
    parser.add_argument(
        "--timeout",
        type=int,
        default=1800,
        help="Timeout per tool execution in seconds (default: 1800)",
    )

    # Logging
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Log level (default: INFO)",
    )
    parser.add_argument(
        "--log-file",
        action="store_true",
        help="Enable file logging",
    )

    return parser.parse_args()


def expand_tools_list(tools_str: str, dsl: str) -> List[str]:
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


def setup_output_directory(base_output: Path, mode: str) -> Tuple[Path, str]:
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


def prepare_circuit_paths(input_path: Path) -> Tuple[Path, Path]:
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


def get_tool_input_path(tool_name: str, circuit_file: Path, circuit_dir: Path) -> str:
    """
    Determine what path to pass to a specific tool.

    Args:
        tool_name: Name of the tool
        circuit_file: Path to circuit file
        circuit_dir: Path to circuit directory

    Returns:
        Path string to pass to tool
    """
    # circomspect works with file paths directly, others expect directories
    if tool_name == "circomspect":
        return str(circuit_file)
    else:
        return str(circuit_dir)


def execute_tools(
    tools_list: List[str],
    tool_registry: Dict,
    circuit_file: Path,
    circuit_dir: Path,
    output_dir: Path,
    timeout: int,
) -> Dict:
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
        Dictionary of results per tool
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
        raw_output_file = tool_output_dir / "raw.txt"

        # Measure execution time
        start_time = time.time()

        try:
            # Determine what path to pass to this tool
            tool_input = get_tool_input_path(tool_name, circuit_file, circuit_dir)

            # Execute tool
            raw_output = tool_module.execute(tool_input, timeout)

            # Write raw output
            with open(raw_output_file, "w", encoding="utf-8") as f:
                f.write(raw_output)

            execution_time = time.time() - start_time

            # Check if tool timed out
            if "[Timed out]" in raw_output or "Timeout" in raw_output:
                results[tool_name] = {
                    "status": "timeout",
                    "execution_time": round(execution_time, 2),
                    "findings_count": 0,
                    "findings": [],
                    "raw_output_file": str(raw_output_file),
                }
                logging.warning(f"{tool_name}: Timed out after {execution_time:.2f}s")
            # Check if tool returned an error marker
            elif any(
                marker in raw_output
                for marker in [
                    "[Circuit file not found]",
                    "[Binary not found",
                    "[Error:",
                    "[File not found]",
                ]
            ):
                # Extract error message
                error_msg = raw_output.strip()
                results[tool_name] = {
                    "status": "failed",
                    "execution_time": round(execution_time, 2),
                    "findings_count": 0,
                    "findings": [],
                    "error": error_msg,
                    "raw_output_file": str(raw_output_file),
                }
                logging.error(f"{tool_name}: {error_msg}")
            else:
                # Parse findings (tool-specific)
                findings = parse_findings_from_output(tool_name, raw_output)

                results[tool_name] = {
                    "status": "success",
                    "execution_time": round(execution_time, 2),
                    "findings_count": len(findings),
                    "findings": findings,
                    "raw_output_file": str(raw_output_file),
                }

                logging.info(
                    f"{tool_name}: Found {len(findings)} findings in {execution_time:.2f}s"
                )

        except Exception as e:
            execution_time = time.time() - start_time
            logging.error(f"{tool_name} failed: {e}")
            results[tool_name] = {
                "status": "failed",
                "execution_time": round(execution_time, 2),
                "error": str(e),
                "findings_count": 0,
                "findings": [],
                "raw_output_file": str(raw_output_file),
            }

    return results


def analyze_mode(args: argparse.Namespace) -> None:
    """
    Analyze mode: Run tools on a circuit and report findings.

    Does NOT use ground truth comparison.
    """
    logging.info(f"Running in ANALYZE mode")
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
    tool_registry = resolve_tools(args.dsl, tools_list)
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
        tools_list, tool_registry, circuit_file, circuit_dir, output_dir, args.timeout
    )

    # Generate summary
    summary = {
        "mode": "analyze",
        "input": str(args.input),
        "dsl": args.dsl,
        "timestamp": timestamp,
        "output_directory": str(output_dir),
        "tools": results,
        "statistics": {
            "total_tools": len(results),
            "success": sum(1 for r in results.values() if r.get("status") == "success"),
            "failed": sum(1 for r in results.values() if r.get("status") == "failed"),
            "timeout": sum(1 for r in results.values() if r.get("status") == "timeout"),
        },
        "total_findings": sum(
            r.get("findings_count", 0)
            for r in results.values()
            if r.get("status") == "success"
        ),
        "total_execution_time": sum(r.get("execution_time", 0) for r in results.values()),
    }

    # Write summary JSON
    summary_file = output_dir / "summary.json"
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    # Print CLI summary
    print_analyze_summary(summary)


def evaluate_mode(args: argparse.Namespace) -> None:
    """
    Evaluate mode: Run tools and compare against ground truth.
    """
    logging.info(f"Running in EVALUATE mode")
    logging.info(f"Input config: {args.input}")
    logging.info(f"Tools: {args.tools}")

    # Validate input file
    if not args.input.exists():
        logging.error(f"Config file not found: {args.input}")
        sys.exit(1)

    # Load ground truth config
    with open(args.input, "r", encoding="utf-8") as f:
        config_data = json.load(f)

    # Extract bug info (assume first entry)
    bug_name = next(iter(config_data.keys()))
    bug_info = config_data[bug_name]

    logging.info(f"Evaluating bug: {bug_name}")
    logging.info(f"Vulnerability: {bug_info.get('Vulnerability')}")

    # Get circuit file path
    circuit_file = args.input.parent / bug_info["Location"]["File"]
    if not circuit_file.exists():
        # Try alternative path
        circuit_file = args.input.parent / "circuits" / bug_info["Location"]["File"]

    if not circuit_file.exists():
        logging.error(f"Circuit file not found: {circuit_file}")
        sys.exit(1)

    logging.info(f"Circuit file: {circuit_file}")

    # Parse tools list (expand 'all' if needed)
    tools_list = expand_tools_list(args.tools, args.dsl)
    if not tools_list:
        logging.error("No tools specified")
        sys.exit(1)

    # Resolve tool modules
    tool_registry = resolve_tools(args.dsl, tools_list)
    if not tool_registry:
        logging.error("No tools loaded successfully")
        sys.exit(1)

    # Setup output directory
    output_dir, timestamp = setup_output_directory(args.output, "evaluate")
    logging.info(f"Output directory: {output_dir}")

    # Save ground truth
    ground_truth_file = output_dir / "ground_truth.json"
    ground_truth = {
        "Vulnerability": bug_info.get("Vulnerability"),
        "Impact": bug_info.get("Impact"),
        "Root Cause": bug_info.get("Root Cause"),
        "Location": bug_info.get("Location"),
    }
    with open(ground_truth_file, "w", encoding="utf-8") as f:
        json.dump(ground_truth, f, indent=2)

    # Determine circuit paths
    circuit_dir, _ = prepare_circuit_paths(circuit_file)

    # Execute all tools (same as analyze mode)
    tool_results = execute_tools(
        tools_list, tool_registry, circuit_file, circuit_dir, output_dir, args.timeout
    )

    # Now do evaluation-specific processing (parse & compare)
    evaluation_results = {}
    for tool_name in tools_list:
        if tool_name not in tool_results:
            continue

        tool_result = tool_results[tool_name]

        if tool_result["status"] != "success":
            # Copy status from execution
            evaluation_results[tool_name] = {
                "status": tool_result["status"],
                "execution_time": tool_result["execution_time"],
                "error": tool_result.get("error"),
            }
            continue

        tool_module = tool_registry[tool_name]
        tool_output_dir = output_dir / tool_name
        raw_output_file = tool_output_dir / "raw.txt"
        parsed_output_file = tool_output_dir / "parsed.json"
        results_file = tool_output_dir / "results.json"

        try:
            # Parse output using tool's parser
            if hasattr(tool_module, "parse_output"):
                parsed = tool_module.parse_output(raw_output_file, ground_truth_file)
                with open(parsed_output_file, "w", encoding="utf-8") as f:
                    json.dump(parsed, f, indent=2)
            else:
                parsed = {"raw": "No parser available"}

            # Compare with ground truth
            if hasattr(tool_module, "compare_zkbugs_ground_truth"):
                comparison = tool_module.compare_zkbugs_ground_truth(
                    tool_name, args.dsl, bug_name, ground_truth_file, parsed_output_file
                )
                with open(results_file, "w", encoding="utf-8") as f:
                    json.dump(comparison, f, indent=2)
            else:
                comparison = {"result": "unknown", "reason": "no comparison function"}

            evaluation_results[tool_name] = {
                "status": "success",
                "execution_time": tool_result["execution_time"],
                "result": comparison.get("result"),
                "reason": comparison.get("reason", []),
                "needs_manual_review": comparison.get("need_manual_evaluation", False),
            }

            logging.info(
                f"{tool_name}: {comparison.get('result')} in {tool_result['execution_time']:.2f}s"
            )

        except Exception as e:
            logging.error(f"{tool_name} evaluation failed: {e}")
            evaluation_results[tool_name] = {
                "status": "error",
                "execution_time": tool_result["execution_time"],
                "error": str(e),
            }

    # Generate evaluation summary
    summary = generate_evaluation_summary(
        bug_name, ground_truth, evaluation_results, output_dir, timestamp
    )

    # Write summary
    summary_file = output_dir / "summary.json"
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    # Print CLI summary
    print_evaluate_summary(summary)


def parse_findings_from_output(tool_name: str, raw_output: str) -> List[Dict]:
    """
    Parse findings from raw tool output.
    Returns list of finding dictionaries with one-liner descriptions.
    """
    findings = []

    if tool_name == "circomspect":
        # Parse circomspect warnings
        lines = raw_output.split("\n")
        for i, line in enumerate(lines):
            if "warning[" in line:
                # Extract warning code and description
                try:
                    code = line.split("[")[1].split("]")[0]
                    # Next line usually has file:line info
                    if i + 1 < len(lines):
                        location = lines[i + 1].strip()
                    else:
                        location = "unknown"

                    findings.append(
                        {
                            "code": code,
                            "location": location,
                            "description": line.strip(),
                        }
                    )
                except:
                    pass

    elif tool_name == "circom_civer":
        # Parse circom_civer output
        if "FAIL" in raw_output or "ERROR" in raw_output:
            findings.append(
                {
                    "type": "verification_failure",
                    "description": "Circuit verification failed",
                }
            )
        elif "UNSAT" in raw_output:
            findings.append(
                {
                    "type": "satisfiability",
                    "description": "Unsatisfiable constraints detected",
                }
            )

    # Add more tool-specific parsers as needed

    return findings


def generate_evaluation_summary(
    bug_name: str,
    ground_truth: Dict,
    evaluation_results: Dict,
    output_dir: Path,
    timestamp: str,
) -> Dict:
    """Generate evaluation summary with TP/FP/FN analysis."""

    # Count results
    correct = sum(1 for r in evaluation_results.values() if r.get("result") == "correct")
    false_results = sum(
        1 for r in evaluation_results.values() if r.get("result") == "false"
    )
    timeouts = sum(1 for r in evaluation_results.values() if r.get("result") == "timeout")
    errors = sum(1 for r in evaluation_results.values() if r.get("status") == "error")
    needs_review = [
        tool for tool, r in evaluation_results.items() if r.get("needs_manual_review")
    ]

    summary = {
        "mode": "evaluate",
        "bug": bug_name,
        "ground_truth": ground_truth,
        "timestamp": timestamp,
        "output_directory": str(output_dir),
        "tools": evaluation_results,
        "statistics": {
            "total_tools": len(evaluation_results),
            "true_positives": correct,
            "false_negatives": false_results,
            "timeouts": timeouts,
            "errors": errors,
            "needs_manual_review": len(needs_review),
        },
        "manual_review_items": needs_review,
    }

    # Create evaluation TODO file if needed
    if needs_review:
        todo_file = output_dir / "manual_review_todo.md"
        with open(todo_file, "w") as f:
            f.write(f"# Manual Review TODO - {bug_name}\n\n")
            f.write(f"Generated: {timestamp}\n\n")
            f.write("## Items Requiring Manual Inspection\n\n")
            for tool in needs_review:
                result = evaluation_results[tool]
                f.write(f"### {tool}\n")
                f.write(f"- Status: TODO\n")
                f.write(f"- Reason: {result.get('reason')}\n")
                f.write(f"- Output: {output_dir / tool / 'raw.txt'}\n\n")

    return summary


def print_analyze_summary(summary: Dict) -> None:
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
                print(f"\n  Findings List:")
                for idx, finding in enumerate(result["findings"][:10], 1):  # Show first 10
                    desc = finding.get("description", finding.get("type", "Unknown"))
                    print(f"    {idx}. {desc}")
                if result["findings_count"] > 10:
                    print(f"    ... and {result['findings_count'] - 10} more")

        elif status == "failed":
            print(f"  Error:    {result.get('error', 'Unknown error')}")

        elif status == "timeout":
            print(f"  Status:   Tool execution timed out")

    print("\n" + "=" * 80)


def print_evaluate_summary(summary: Dict) -> None:
    """Print formatted summary for evaluate mode."""
    print("\n" + "=" * 80)
    print("EVALUATE MODE - SUMMARY")
    print("=" * 80)
    print(f"Bug:          {summary['bug']}")
    print(f"Vulnerability: {summary['ground_truth']['Vulnerability']}")
    print(f"Output:       {summary['output_directory']}")
    print("\n" + "-" * 80)
    print("STATISTICS:")
    print("-" * 80)
    stats = summary["statistics"]
    print(f"Total Tools:         {stats['total_tools']}")
    print(f"True Positives:      {stats['true_positives']}")
    print(f"False Negatives:     {stats['false_negatives']}")
    print(f"Timeouts:            {stats['timeouts']}")
    print(f"Errors:              {stats['errors']}")
    print(f"Need Manual Review:  {stats['needs_manual_review']}")

    print("\n" + "-" * 80)
    print("TOOL RESULTS:")
    print("-" * 80)

    for tool_name, result in summary["tools"].items():
        if result["status"] == "success":
            status_symbol = {
                "correct": "✓",
                "false": "✗",
                "timeout": "⏱",
                "unknown": "?",
            }.get(result.get("result"), "?")

            print(
                f"\n{tool_name.upper()}: {status_symbol} {result.get('result', 'unknown').upper()}"
            )
            print(f"  Time: {result['execution_time']}s")
            if result.get("reason"):
                print(f"  Reason: {result['reason']}")
            if result.get("needs_manual_review"):
                print(f"  ⚠ Needs Manual Review")
        else:
            print(f"\n{tool_name.upper()}: ERROR - {result.get('error')}")

    if summary.get("manual_review_items"):
        print("\n" + "-" * 80)
        print("⚠ MANUAL REVIEW REQUIRED:")
        print("-" * 80)
        for tool in summary["manual_review_items"]:
            print(f"  - {tool}")
        print(f"\nSee: {summary['output_directory']}/manual_review_todo.md")

    print("\n" + "=" * 80)


def main() -> None:
    """Main entry point for zkHydra."""
    args = parse_args()

    # Setup logging
    output_dir = args.output / datetime.now().strftime("%Y%m%d_%H%M%S")
    setup_logging(args.log_level, output_dir, args.log_file)

    logging.info(f"zkHydra starting in {args.mode.upper()} mode")

    try:
        if args.mode == "analyze":
            analyze_mode(args)
        elif args.mode == "evaluate":
            evaluate_mode(args)
        else:
            logging.error(f"Unknown mode: {args.mode}")
            sys.exit(1)
    except KeyboardInterrupt:
        logging.warning("Interrupted by user")
        sys.exit(130)
    except Exception as e:
        logging.exception(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
