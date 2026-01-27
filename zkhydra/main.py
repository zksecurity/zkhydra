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
from zkhydra.core import analyze_mode, evaluate_mode
from zkhydra.utils.logger import setup_logging


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
