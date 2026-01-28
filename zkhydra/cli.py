"""
Command-line argument parsing for zkHydra.

This module provides the CLI interface for zkHydra, handling all argument parsing
and validation. The parsed arguments are then passed to the main execution logic.
"""

import argparse
import logging
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    """Parse command line arguments for zkHydra.

    Returns:
        argparse.Namespace: Parsed command line arguments with the following attributes:
            - mode: str - Operation mode ('analyze' or 'evaluate')
            - input: Path - Input circuit file path
            - output: Path - Output directory path
            - tools: str - Comma-separated tool names or 'all'
            - dsl: str - Domain-specific language (default: 'circom')
            - timeout: int - Timeout per tool in seconds (default: 1800)
            - log_level: str - Logging level (default: 'INFO')
            - log_file: bool - Whether to enable file logging
            - vanilla: bool - Whether to just process existing .raw files
    """
    parser = argparse.ArgumentParser(
        description="zkHydra - Zero-Knowledge Circuit Security Analysis Tool Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a circuit with circomspect
  %(prog)s analyze --input test_bug/circuits/circuit.circom --tools circomspect

  # Analyze with multiple tools
  %(prog)s analyze --input circuit.circom --tools circomspect,circom_civer,picus

  # Analyze with all available tools
  %(prog)s analyze --input circuit.circom --tools all

  # Evaluate zkbugs dataset
  %(prog)s zkbugs --dataset zkbugs/dataset/circom/ --dsl circom --tools all --timeout 600 --output zkbugs-run-1
        """,
    )

    # Mode selection
    parser.add_argument(
        "mode",
        choices=["analyze", "evaluate", "zkbugs"],
        help="Mode: 'analyze' for single circuit, 'zkbugs' for dataset evaluation",
    )

    # Input/Output
    parser.add_argument(
        "--input",
        "-i",
        type=Path,
        required=False,
        help="Input: circuit file (.circom) to analyze (required for analyze mode)",
    )
    parser.add_argument(
        "--dataset",
        "-d",
        type=Path,
        required=False,
        help="Dataset directory for zkbugs mode (e.g., zkbugs/dataset/circom/)",
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
        required=False,
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

    # Miscellaneous
    parser.add_argument(
        "--vanilla",
        action="store_true",
        help="Whether to just process existing .raw files",
    )

    args = parser.parse_args()

    # Validation

    if args.vanilla and not args.output.exists():
        logging.error("--output is required and must exist for vanilla mode")
        sys.exit(1)

    if not args.vanilla and not args.tools:
        logging.error("--tools is required when not in vanilla mode")
        sys.exit(1)

    # Mode-specific validation
    if args.mode == "zkbugs":
        # zkbugs mode validation
        if not args.dataset and not args.vanilla:
            logging.error("--dataset is required for zkbugs mode")
            sys.exit(1)
        if not args.vanilla and not args.dataset.exists():
            logging.error(f"Dataset directory not found: {args.dataset}")
            sys.exit(1)
        if args.dsl != "circom":
            logging.error(
                f"DSL '{args.dsl}' is not supported yet for zkbugs mode"
            )
            sys.exit(1)
    else:
        # analyze/evaluate mode validation
        if not args.input and not args.vanilla:
            logging.error(f"--input is required for {args.mode} mode")
            sys.exit(1)
        if not args.input.exists():
            logging.error(f"Input file not found: {args.input}")
            sys.exit(1)
        if args.dsl != "circom":
            logging.error(f"DSL '{args.dsl}' is not supported yet")
            sys.exit(1)

    return args
