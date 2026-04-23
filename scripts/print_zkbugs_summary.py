#!/usr/bin/env python3
"""Pretty-print a zkhydra zkbugs run.

Reads `<run>/summary.json` (optionally enriched by the triage
script's `--update-summary`) and prints:

1. Header  — mode, jobs, total/processed/skipped/errors.
2. Evaluation rollup — TruePositive / FalseNegative / Undecided /
   untriaged overall and per-tool (requires --update-summary, else
   falls back to walking per-bug evaluation.json files).
3. Per-bug table — one row per (bug, tool) with the final verdict,
   confidence if triaged, and findings_count.

Usage:
    python3 scripts/print_zkbugs_summary.py output/zkbugs-run
    python3 scripts/print_zkbugs_summary.py output/zkbugs-run --filter FalseNegative
    python3 scripts/print_zkbugs_summary.py output/zkbugs-run --tool picus
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

STATUSES = ("TruePositive", "FalseNegative", "Undecided")


def _load_json(p: Path) -> dict | None:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _collect_evaluations(run_dir: Path) -> list[dict]:
    """Walk per-bug evaluation.json files and build a flat row list."""
    rows = []
    for eval_path in sorted(run_dir.glob("*/*/evaluation.json")):
        tool = eval_path.parent.name
        bug = eval_path.parent.parent.name
        ev = _load_json(eval_path) or {}
        res = _load_json(eval_path.parent / "results.json") or {}
        findings = res.get("findings") or []
        rows.append(
            {
                "bug_name": bug,
                "tool": tool,
                "status": ev.get("status", "Undecided"),
                "confidence": ev.get("confidence"),
                "triaged": bool(ev.get("triaged_by")),
                "findings_count": len(findings),
                "reason": ev.get("reason", "")[:60],
            }
        )
    return rows


def _rollup(rows: list[dict]) -> dict:
    overall = {s: 0 for s in STATUSES}
    overall["untriaged"] = 0
    per_tool: dict[str, dict] = {}
    for r in rows:
        s = r["status"] if r["status"] in STATUSES else "Undecided"
        overall[s] = overall.get(s, 0) + 1
        if s == "Undecided" and not r["triaged"]:
            overall["untriaged"] += 1
        t = per_tool.setdefault(
            r["tool"], {s: 0 for s in STATUSES} | {"untriaged": 0}
        )
        t[s] += 1
        if s == "Undecided" and not r["triaged"]:
            t["untriaged"] += 1
    return {"overall": overall, "per_tool": per_tool}


def _fmt_table(rows: list[list[str]], headers: list[str]) -> str:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    sep = "  "
    lines = [sep.join(h.ljust(w) for h, w in zip(headers, widths))]
    lines.append(sep.join("-" * w for w in widths))
    for row in rows:
        lines.append(sep.join(c.ljust(w) for c, w in zip(row, widths)))
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("run_dir", type=Path)
    p.add_argument(
        "--tool",
        type=str,
        default=None,
        help="Only print rows for this tool.",
    )
    p.add_argument(
        "--filter",
        type=str,
        choices=[*STATUSES, "Errored", "Skipped"],
        default=None,
        help="Only show rows matching this final verdict.",
    )
    p.add_argument(
        "--no-rows",
        action="store_true",
        help="Print headers + rollup only; skip the per-bug table.",
    )
    args = p.parse_args()

    run_dir = args.run_dir.resolve()
    summary = _load_json(run_dir / "summary.json")
    if summary is None:
        print(f"error: summary.json not found in {run_dir}", file=sys.stderr)
        return 1

    print("=" * 72)
    print(f"run        : {run_dir}")
    print(f"dataset    : {summary.get('dataset')}")
    print(f"mode       : {summary.get('mode')}")
    print(
        f"jobs       : {summary.get('jobs')}    "
        f"total: {summary.get('total')}    "
        f"processed: {summary.get('processed')}    "
        f"errors: {summary.get('errors', 0)}    "
        f"skipped: {summary.get('skipped')}"
    )
    print("=" * 72)

    rows = _collect_evaluations(run_dir)
    if args.tool:
        rows = [r for r in rows if r["tool"] == args.tool]

    rollup = _rollup(rows)
    overall = rollup["overall"]
    print()
    print("Evaluation rollup (per (bug, tool) evaluation.json)")
    print(
        f"  TruePositive : {overall.get('TruePositive', 0)}    "
        f"FalseNegative : {overall.get('FalseNegative', 0)}    "
        f"Undecided : {overall.get('Undecided', 0)}    "
        f"(untriaged : {overall.get('untriaged', 0)})"
    )
    print()
    print("Per-tool:")
    tool_headers = ["tool", "TP", "FN", "Und", "untriaged"]
    tool_rows = []
    for tool, counts in sorted(rollup["per_tool"].items()):
        tool_rows.append(
            [
                tool,
                str(counts["TruePositive"]),
                str(counts["FalseNegative"]),
                str(counts["Undecided"]),
                str(counts["untriaged"]),
            ]
        )
    if tool_rows:
        print(_fmt_table(tool_rows, tool_headers))

    # Include skipped + errored bugs from summary.json.
    bug_entries = summary.get("bugs", []) or []
    skipped_errored = [
        b for b in bug_entries if b.get("status") in {"skipped", "error"}
    ]
    if skipped_errored:
        print()
        print(f"Non-processed bugs: {len(skipped_errored)}")
        for b in skipped_errored:
            print(
                f"  [{b.get('status', '?')}] {b['bug_name']}: "
                f"{b.get('reason') or b.get('error') or ''}"
            )

    if args.no_rows:
        return 0

    # Per-row table
    if args.filter in STATUSES:
        rows = [r for r in rows if r["status"] == args.filter]
    elif args.filter in {"Errored", "Skipped"}:
        # Only skipped/errored meta-rows; handled above — print nothing more.
        return 0

    if not rows:
        print()
        print("(no evaluation rows to show)")
        return 0

    print()
    print(f"Per (bug, tool) — {len(rows)} row(s):")
    headers = ["status", "conf", "t?", "tool", "n", "bug"]
    table_rows = []
    for r in rows:
        table_rows.append(
            [
                r["status"],
                r["confidence"] or "-",
                "T" if r["triaged"] else "-",
                r["tool"],
                str(r["findings_count"]),
                r["bug_name"],
            ]
        )
    # Sort by status then tool then bug
    status_rank = {"TruePositive": 0, "FalseNegative": 1, "Undecided": 2}
    table_rows.sort(key=lambda x: (status_rank.get(x[0], 99), x[3], x[5]))
    print(_fmt_table(table_rows, headers))

    return 0


if __name__ == "__main__":
    sys.exit(main())
