#!/usr/bin/env python3
"""Split the configured bug list into N shards for rate-limited LLM tools.

Each shard is written as a --bugs-file compatible text file (one bug selector
per line). Bugs are distributed via round-robin so each shard is nearly the
same size and the last shard is never more than N-1 entries smaller than
the first.

Usage:
    # Split config.toml [circom].bugs into 4 shards:
    python scripts/split_bugs.py --shards 4 --output-dir shards/

    # Split an existing bugs file:
    python scripts/split_bugs.py --bugs-file all_bugs.txt --shards 3 --output-dir shards/

After splitting, the script prints ready-to-run commands for each shard and
the merge command to combine them afterwards.
"""

import argparse
import sys
import tomllib
from pathlib import Path


def read_bugs_from_config(config_path: Path) -> list[str]:
    """Read [circom].bugs from config.toml."""
    with open(config_path, "rb") as f:
        data = tomllib.load(f)
    return data.get("circom", {}).get("bugs", [])


def read_bugs_from_file(bugs_file: Path) -> list[str]:
    """Read one bug selector per line, ignoring blank lines and comments."""
    lines = []
    for raw in bugs_file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            lines.append(line)
    return lines


def split_round_robin(bugs: list[str], n: int) -> list[list[str]]:
    """Distribute bugs across n shards by round-robin for even sizing."""
    shards: list[list[str]] = [[] for _ in range(n)]
    for i, bug in enumerate(bugs):
        shards[i % n].append(bug)
    return shards


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--shards", "-n", type=int, required=True,
        help="Number of shards to create",
    )
    p.add_argument(
        "--output-dir", "-o", type=Path, required=True,
        help="Directory where shard_1.txt ... shard_N.txt are written",
    )

    source = p.add_mutually_exclusive_group()
    source.add_argument(
        "--config", type=Path, default=None,
        help="Path to config.toml (default: config.toml in cwd)",
    )
    source.add_argument(
        "--bugs-file", type=Path, default=None,
        help="Existing --bugs-file to split (one selector per line)",
    )

    args = p.parse_args()

    if args.shards < 1:
        print("Error: --shards must be >= 1", file=sys.stderr)
        return 1

    if args.bugs_file:
        if not args.bugs_file.is_file():
            print(f"Error: --bugs-file not found: {args.bugs_file}", file=sys.stderr)
            return 1
        bugs = read_bugs_from_file(args.bugs_file)
    else:
        config_path = args.config or Path("config.toml")
        if not config_path.is_file():
            print(f"Error: config not found: {config_path}", file=sys.stderr)
            return 1
        bugs = read_bugs_from_config(config_path)

    if not bugs:
        print("Error: no bugs found in source", file=sys.stderr)
        return 1

    effective_shards = min(args.shards, len(bugs))
    if effective_shards < args.shards:
        print(
            f"Warning: only {len(bugs)} bug(s) — reducing to {effective_shards} shard(s)",
            file=sys.stderr,
        )

    print(f"Found {len(bugs)} bug(s), splitting into {effective_shards} shard(s)")

    shards = split_round_robin(bugs, effective_shards)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    shard_paths: list[Path] = []
    for i, shard in enumerate(shards, 1):
        shard_path = args.output_dir / f"shard_{i}.txt"
        shard_path.write_text("\n".join(shard) + "\n", encoding="utf-8")
        shard_paths.append(shard_path)
        print(f"  shard_{i}.txt: {len(shard)} bug(s)")

    print("\nReady-to-run commands (run each separately to respect rate limits):")
    for i, path in enumerate(shard_paths, 1):
        print(f"\n  # Shard {i}/{effective_shards}:")
        print(
            f"  uv run python -m zkhydra.main zkbugs"
            f" --dataset bugs/zkbugs/dataset/circom"
            f" --tools circom_auditor_claude,circom_auditor_codex"
            f" --bugs-file {path}"
            f" --zkbugs-mode both"
            f" --output output/shard_{i}"
        )

    shard_dirs = " ".join(f"output/shard_{i}" for i in range(1, effective_shards + 1))
    print(f"\n  # After all shards complete — merge into one combined run:")
    print(
        f"  python scripts/merge_shards.py {shard_dirs}"
        f" --output output/llm_combined"
    )
    print(
        f"\n  # Triage undecided verdicts:"
    )
    print(
        f"  python scripts/triage_zkbugs_run.py output/llm_combined/direct"
        f" --auto --update-evaluation --jobs 4"
    )
    print(
        f"\n  # Merge into the remote run:"
    )
    print(
        f"  python scripts/merge_tool_run.py --source output/llm_combined/direct"
        f" --target output/zkbugs-remote/direct --tool circom_auditor_claude"
    )
    print(
        f"  python scripts/merge_tool_run.py --source output/llm_combined/direct"
        f" --target output/zkbugs-remote/direct --tool circom_auditor_codex"
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
