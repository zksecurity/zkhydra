#!/usr/bin/env python3
"""Merge N partial shard run dirs into one combined run directory.

Each shard ran on a non-overlapping subset of the bugs. This script
stitches the individual shard outputs into a single directory that looks
like a full zkhydra zkbugs run.

For --zkbugs-mode both runs (which produce direct/ and original/ subdirs)
each sub-run is merged independently. For flat runs (direct or original
mode only, bug dirs at the top level) the bug dirs are merged directly.

Usage:
    python scripts/merge_shards.py \\
        output/shard_1 output/shard_2 output/shard_3 \\
        --output output/llm_combined

    # Then triage undecideds and merge into the remote run:
    python scripts/triage_zkbugs_run.py output/llm_combined/direct \\
        --auto --update-evaluation --jobs 4
    python scripts/merge_tool_run.py \\
        --source output/llm_combined/direct \\
        --target output/zkbugs-remote/direct \\
        --tool circom_auditor_claude
    python scripts/merge_tool_run.py \\
        --source output/llm_combined/direct \\
        --target output/zkbugs-remote/direct \\
        --tool circom_auditor_codex
"""

import argparse
import json
import logging
import shutil
import sys
from pathlib import Path


def _is_bug_dir(d: Path) -> bool:
    """True if this directory looks like a processed bug output dir."""
    if not d.is_dir():
        return False
    return (d / "ground_truth.json").exists() or any(
        c.is_dir() for c in d.iterdir()
    )


def _merge_summary_list(summaries: list[dict], mode: str) -> dict:
    """Combine multiple shard summary.json files into one aggregate."""
    all_bugs: list[dict] = []
    total = processed = errors = skipped = 0

    for s in summaries:
        all_bugs.extend(s.get("bugs", []))
        total += s.get("total", 0)
        processed += s.get("processed", 0)
        errors += s.get("errors", 0)
        skipped += s.get("skipped", 0)

    base = dict(summaries[0])
    base["bugs"] = all_bugs
    base["total"] = total
    base["processed"] = processed
    base["errors"] = errors
    base["skipped"] = skipped
    base["mode"] = mode
    # evaluation_counts will be stale after merging; remove so it's not misleading
    base.pop("evaluation_counts", None)
    return base


def _merge_dir(
    shards: list[Path],
    src_subdir: str | None,
    dest: Path,
    overwrite: bool,
) -> tuple[int, int]:
    """Copy bug dirs from each shard's src_subdir into dest.

    Returns (copied, skipped_dup) counts.
    """
    dest.mkdir(parents=True, exist_ok=True)
    summaries: list[dict] = []
    copied = skipped_dup = 0

    for shard in shards:
        shard_root = shard / src_subdir if src_subdir else shard

        if not shard_root.is_dir():
            logging.info("Shard %s has no %s, skipping", shard.name, src_subdir or ".")
            continue

        summary_path = shard_root / "summary.json"
        if summary_path.is_file():
            try:
                summaries.append(
                    json.loads(summary_path.read_text(encoding="utf-8"))
                )
            except (json.JSONDecodeError, OSError) as exc:
                logging.warning("Cannot read %s: %s", summary_path, exc)

        for bug_dir in sorted(shard_root.iterdir()):
            if not _is_bug_dir(bug_dir):
                continue
            dest_bug = dest / bug_dir.name
            if dest_bug.exists():
                if overwrite:
                    shutil.rmtree(dest_bug)
                    logging.warning(
                        "Overwriting duplicate bug in %s: %s",
                        src_subdir or ".",
                        bug_dir.name,
                    )
                else:
                    logging.warning(
                        "Duplicate bug %s in %s — skipped (use --overwrite to replace)",
                        bug_dir.name,
                        src_subdir or ".",
                    )
                    skipped_dup += 1
                    continue
            shutil.copytree(bug_dir, dest_bug)
            copied += 1

    if summaries:
        mode = src_subdir or "direct"
        merged = _merge_summary_list(summaries, mode)
        (dest / "summary.json").write_text(
            json.dumps(merged, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    return copied, skipped_dup


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "shards",
        nargs="+",
        type=Path,
        help="Shard run dirs to merge (e.g. output/shard_1 output/shard_2)",
    )
    p.add_argument(
        "--output", "-o",
        type=Path,
        required=True,
        help="Target combined run directory",
    )
    p.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace duplicate bug dirs (default: skip and warn)",
    )
    args = p.parse_args()

    for s in args.shards:
        if not s.is_dir():
            logging.error("Shard not found: %s", s)
            return 1

    args.output.mkdir(parents=True, exist_ok=True)

    # Detect run structure: if any shard has a direct/ subdir it's a both-mode run.
    is_both_mode = any((s / "direct").is_dir() for s in args.shards)

    if is_both_mode:
        logging.info("Detected both-mode structure (direct/ + optional original/)")

        direct_dest = args.output / "direct"
        copied, dups = _merge_dir(args.shards, "direct", direct_dest, args.overwrite)
        logging.info("direct/  copied=%d skipped_dup=%d", copied, dups)

        has_original = any((s / "original").is_dir() for s in args.shards)
        original_dest = args.output / "original"
        if has_original:
            copied, dups = _merge_dir(
                args.shards, "original", original_dest, args.overwrite
            )
            logging.info("original/ copied=%d skipped_dup=%d", copied, dups)

        combined = {
            "mode": "both",
            "merged_from": [str(s) for s in args.shards],
            "output_root": str(args.output),
            "modes": {
                "direct": {
                    "ran": True,
                    "output_dir": str(direct_dest),
                },
                "original": {
                    "ran": has_original,
                    "output_dir": str(original_dest) if has_original else None,
                },
            },
        }
        (args.output / "summary.json").write_text(
            json.dumps(combined, indent=2, ensure_ascii=False), encoding="utf-8"
        )
    else:
        logging.info("Detected flat structure (bug dirs at top level)")
        copied, dups = _merge_dir(args.shards, None, args.output, args.overwrite)
        logging.info("copied=%d skipped_dup=%d", copied, dups)

    logging.info("Merge complete → %s", args.output)

    print(f"\nNext steps:")
    run_dir = args.output / "direct" if is_both_mode else args.output
    print(f"  1. Triage undecided verdicts:")
    print(
        f"     python scripts/triage_zkbugs_run.py {run_dir}"
        f" --auto --update-evaluation --jobs 4"
    )
    print(f"  2. Merge into the remote run:")
    for tool in ("circom_auditor_claude", "circom_auditor_codex"):
        print(
            f"     python scripts/merge_tool_run.py"
            f" --source {run_dir}"
            f" --target output/zkbugs-remote/direct"
            f" --tool {tool}"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
