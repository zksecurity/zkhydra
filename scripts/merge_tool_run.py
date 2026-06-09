#!/usr/bin/env python3
"""Merge a single-tool zkbugs run (with direct/ and original/ subdirs) into
an existing multi-tool run directory.

Usage:
    python3 scripts/merge_tool_run.py \
        --source output/conscs-both-run \
        --target output/zkbugs-run-remote \
        --tool conscs

For each mode (direct, original) the script copies
  <source>/<mode>/<bug>/<tool>/
into
  <target>/<mode>/<bug>/<tool>/
skipping bugs that don't exist in the target.
"""

import argparse
import logging
import shutil
import sys
from pathlib import Path


def merge(source: Path, target: Path, tool: str) -> None:
    for mode in ("direct", "original"):
        src_mode = source / mode
        tgt_mode = target / mode
        if not src_mode.is_dir():
            logging.info("No %s/ in source, skipping", mode)
            continue
        if not tgt_mode.is_dir():
            logging.warning("Target has no %s/, skipping", mode)
            continue

        copied = skipped = 0
        for bug_dir in sorted(src_mode.iterdir()):
            if not bug_dir.is_dir():
                continue
            src_tool_dir = bug_dir / tool
            if not src_tool_dir.is_dir():
                continue
            tgt_bug_dir = tgt_mode / bug_dir.name
            if not tgt_bug_dir.is_dir():
                logging.debug("Bug %s not in target %s, skipping", bug_dir.name, mode)
                skipped += 1
                continue
            tgt_tool_dir = tgt_bug_dir / tool
            if tgt_tool_dir.exists():
                shutil.rmtree(tgt_tool_dir)
            shutil.copytree(src_tool_dir, tgt_tool_dir)
            copied += 1

        logging.info("[%s] copied=%d skipped=%d", mode, copied, skipped)


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True, help="Single-tool run dir")
    p.add_argument("--target", type=Path, required=True, help="Multi-tool run dir")
    p.add_argument("--tool", type=str, required=True, help="Tool name (e.g. conscs)")
    args = p.parse_args()

    if not args.source.is_dir():
        logging.error("Source not found: %s", args.source)
        return 1
    if not args.target.is_dir():
        logging.error("Target not found: %s", args.target)
        return 1

    merge(args.source, args.target, args.tool)
    logging.info("Merge complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
