"""
Command-line argument parsing for zkHydra.

This module provides the CLI interface for zkHydra, handling all argument parsing
and validation. The parsed arguments are then passed to the main execution logic.
"""

import argparse
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
        """,
    )

    # Mode selection
    parser.add_argument(
        "mode",
        choices=["analyze", "evaluate"],
        help="Mode: 'analyze' for finding bugs (evaluate mode is not implemented)",
    )

    # Input/Output
    parser.add_argument(
        "--input",
        "-i",
        type=Path,
        required=True,
        help="Input: circuit file (.circom) to analyze",
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
