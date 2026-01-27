#!/usr/bin/env python3
"""
zkHydra - Zero-Knowledge Circuit Security Analysis Tool Runner

Main entry point for zkHydra. Parses command-line arguments and dispatches
to the appropriate mode (analyze or evaluate).
"""

import logging
import sys
from datetime import datetime

from zkhydra.cli import parse_args
from zkhydra.core import AVAILABLE_TOOLS, analyze_mode, evaluate_mode
from zkhydra.utils.logger import setup_logging


def main() -> None:
    """Main entry point for zkHydra."""
    args = parse_args()

    # Setup logging
    output_dir = args.output / datetime.now().strftime("%Y%m%d_%H%M%S")
    setup_logging(args.log_level, output_dir, args.log_file)

    logging.info(f"zkHydra starting in {args.mode.upper()} mode")

    # Checks

    if args.dsl != "circom":
        logging.error(f"DSL '{args.dsl}' is not supported yet")
        sys.exit(1)

    # Validate circuit file exists
    if not args.input.exists():
        logging.error(f"Circuit file not found: {args.input}")
        sys.exit(1)

    # Validate tools list
    # NOTE: Core check if tools are available for the DSL
    tools_list = args.tools.split(",")
    if not tools_list:
        logging.error("No tools specified")
        sys.exit(1)
    if "all" in tools_list:
        tools_list = AVAILABLE_TOOLS[args.dsl]

    # Check that input file exists
    if not args.input.exists():
        logging.error(f"Input file not found: {args.input}")
        sys.exit(1)
    # Check if input file is a tolm file
    is_tolm_file = args.input.suffix == ".tolm"
    if is_tolm_file:
        raise NotImplementedError("Tolm files are not supported yet")

    try:
        if args.mode == "analyze":
            if not is_tolm_file and args.input.suffix != ".circom":
                logging.error(f"Input file is not a circuit file: {args.input}")
                sys.exit(1)
            analyze_mode(
                args.input, tools_list, args.dsl, args.timeout, args.output
            )
        else:
            if not is_tolm_file and args.input.suffix == ".json":
                logging.error(f"Input file is not a json file: {args.input}")
                sys.exit(1)
            evaluate_mode(args)
    except KeyboardInterrupt:
        logging.warning("Interrupted by user")
        sys.exit(130)
    except Exception as e:
        logging.exception(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
