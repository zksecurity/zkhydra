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
from zkhydra.core import (
    AVAILABLE_TOOLS,
    analyze_mode,
    evaluate_mode,
    zkbugs_mode,
)
from zkhydra.utils.logger import setup_logging


def main() -> None:
    """Main entry point for zkHydra."""
    args = parse_args()

    # Setup logging based on mode
    if args.mode == "zkbugs":
        # For zkbugs mode, use the output directory name directly (no timestamp)
        output_dir = args.output
    else:
        output_dir = args.output / datetime.now().strftime("%Y%m%d_%H%M%S")

    setup_logging(args.log_level, output_dir, args.log_file)

    logging.info(f"zkHydra starting in {args.mode.upper()} mode")

    # Mode-specific validation
    if args.mode == "zkbugs":
        # zkbugs mode validation
        if not args.dataset:
            logging.error("--dataset is required for zkbugs mode")
            sys.exit(1)
        if not args.dataset.exists():
            logging.error(f"Dataset directory not found: {args.dataset}")
            sys.exit(1)
        if args.dsl != "circom":
            logging.error(
                f"DSL '{args.dsl}' is not supported yet for zkbugs mode"
            )
            sys.exit(1)
    else:
        # analyze/evaluate mode validation
        if not args.input:
            logging.error(f"--input is required for {args.mode} mode")
            sys.exit(1)
        if not args.input.exists():
            logging.error(f"Input file not found: {args.input}")
            sys.exit(1)
        if args.dsl != "circom":
            logging.error(f"DSL '{args.dsl}' is not supported yet")
            sys.exit(1)

    # Validate tools list
    tools_list = args.tools.split(",")
    if not tools_list:
        logging.error("No tools specified")
        sys.exit(1)
    if "all" in tools_list:
        tools_list = AVAILABLE_TOOLS[args.dsl]

    try:
        if args.mode == "zkbugs":
            zkbugs_mode(
                args.dataset, tools_list, args.dsl, args.timeout, args.output
            )
        elif args.mode == "analyze":
            is_tolm_file = args.input.suffix == ".tolm"
            if is_tolm_file:
                raise NotImplementedError("Tolm files are not supported yet")
            if args.input.suffix != ".circom":
                logging.error(f"Input file is not a circuit file: {args.input}")
                sys.exit(1)
            analyze_mode(
                args.input, tools_list, args.dsl, args.timeout, args.output
            )
        else:  # evaluate mode
            is_tolm_file = args.input.suffix == ".tolm"
            if is_tolm_file:
                raise NotImplementedError("Tolm files are not supported yet")
            if args.input.suffix == ".json":
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
