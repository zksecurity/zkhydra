#!/usr/bin/env python3
"""Summarize a zkhydra `fp` (false-positive) run.

Reads a run's `summary.json` (after `triage_fp_run.py --update-summary`) and
reports, per tool:

- **FP headline** — soundness-class candidates and their triaged verdicts
  (FalsePositive / RealIssue / Undecided), the per-unit FP rate
  (units with >=1 FalsePositive / units run) and per-alert precision
  (RealIssue / (RealIssue + FalsePositive)).
- **Review burden** — total alerts incl. warnings, warnings (circomspect lint),
  and alerts per unit (median).
- **Triage effort** — soundness candidates triaged + aggregate auto-triage time.
- **Paired buggy -> fixed** (optional, `--rq2-run <dir>`) — for fixed-commit
  units, whether the tool flagged the bug at the buggy commit (RQ2) yet went
  silent at the fixed commit (correct) vs still flags it (false positive).

Outputs a text report to stdout; `--json <path>` also writes machine-readable
metrics, and `--latex <path.tex>` writes LaTeX tables (compiled with pdflatex
when available).

Examples:
    python3 scripts/process_fp_results.py output/fp-run
    python3 scripts/process_fp_results.py output/fp-run --rq2-run output/zkbugs-run
    python3 scripts/process_fp_results.py output/fp-run --json output/fp-metrics.json
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
from pathlib import Path

TOOLS = ["circomspect", "circom_civer", "picus", "ecneproject", "zkfuzz", "conscs"]
WARNING_CATEGORY = "Warning (Other -- probably not a bug)"


def _read_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _processed_units(summary: dict) -> list[dict]:
    return [
        u
        for u in summary.get("units", [])
        if u.get("status") == "processed"
    ]


def compute_metrics(summary: dict) -> dict:
    """Per-tool FP + review-burden metrics from a (triaged) fp summary.json."""
    units = _processed_units(summary)
    tools: dict[str, dict] = {}

    for u in units:
        for tool, entry in (u.get("tools") or {}).items():
            t = tools.setdefault(
                tool,
                {
                    "units_run": 0,
                    "units_with_soundness": 0,
                    "units_with_fp": 0,
                    "soundness_alerts": 0,
                    "warning_alerts": 0,
                    "alerts_per_unit": [],
                    "FalsePositive": 0,
                    "RealIssue": 0,
                    "Undecided": 0,
                    "WarningStyle": 0,
                },
            )
            t["units_run"] += 1
            snd = int(entry.get("soundness_count") or 0)
            warn = int(entry.get("warning_count") or 0)
            t["soundness_alerts"] += snd
            t["warning_alerts"] += warn
            t["alerts_per_unit"].append(snd + warn)
            if snd > 0:
                t["units_with_soundness"] += 1
            fp = entry.get("fp") or {}
            t["FalsePositive"] += int(fp.get("FalsePositive") or 0)
            t["RealIssue"] += int(fp.get("RealIssue") or 0)
            t["Undecided"] += int(fp.get("Undecided") or 0)
            t["WarningStyle"] += int(fp.get("Warning/Style") or 0)
            if int(fp.get("FalsePositive") or 0) > 0:
                t["units_with_fp"] += 1

    for t in tools.values():
        n = t["units_run"] or 1
        t["per_unit_fp_rate"] = round(t["units_with_fp"] / n, 3)
        denom = t["RealIssue"] + t["FalsePositive"]
        t["per_alert_precision"] = (
            round(t["RealIssue"] / denom, 3) if denom else None
        )
        apu = t.pop("alerts_per_unit")
        t["median_alerts_per_unit"] = (
            round(statistics.median(apu), 2) if apu else 0
        )

    return {
        "n_units": len(units),
        "tools": tools,
        "triage_effort": summary.get("triage_effort"),
        "fp_counts": summary.get("fp_counts"),
    }


def paired_buggy_fixed(run_dir: Path, rq2_run: Path) -> list[dict]:
    """For fixed-commit units, cross-tab flagged@buggy (RQ2) vs flagged@fixed.

    A unit is a fixed-commit unit when its fp_candidates.json provenance has
    Origin containing "fixed" and a SourceBug. "flagged@fixed" = the tool had
    >=1 soundness alert on the fixed circuit. "flagged@buggy" = the RQ2
    evaluation for that bug+tool is TruePositive (or any soundness finding).
    """
    rows: list[dict] = []
    for cand_path in sorted(run_dir.glob("*/fp_candidates.json")):
        data = _read_json(cand_path) or {}
        prov = data.get("provenance") or {}
        origin = str(prov.get("Origin") or "")
        source_bug = prov.get("SourceBug")
        if "fixed" not in origin.lower() or not source_bug:
            continue
        for tool, entry in (data.get("tools") or {}).items():
            flagged_fixed = int(entry.get("soundness_count") or 0) > 0
            ev = _read_json(rq2_run / source_bug / tool / "evaluation.json")
            flagged_buggy = bool(ev and ev.get("status") == "TruePositive")
            rows.append(
                {
                    "unit": cand_path.parent.name,
                    "source_bug": source_bug,
                    "tool": tool,
                    "flagged_buggy": flagged_buggy,
                    "flagged_fixed": flagged_fixed,
                    # ideal tool: flagged the bug, silent once fixed
                    "false_positive_on_fixed": flagged_fixed,
                    "clean_resolution": flagged_buggy and not flagged_fixed,
                }
            )
    return rows


def _ordered_tools(present) -> list[str]:
    """Canonical tools first (those present), then any extras."""
    return [t for t in TOOLS if t in present] + [
        t for t in present if t not in TOOLS
    ]


def print_report(metrics: dict, paired: list[dict]) -> None:
    print("=" * 78)
    print(f"FP experiment — {metrics['n_units']} clean/fixed units")
    print("=" * 78)
    hdr = (
        f"{'tool':<14}{'N':>4}{'snd':>5}{'FP':>4}{'Real':>5}{'Und':>4}"
        f"{'FP/unit':>9}{'prec':>7}{'warn':>6}{'med/u':>7}"
    )
    print(hdr)
    print("-" * len(hdr))
    for tool in _ordered_tools(metrics["tools"]):
        t = metrics["tools"].get(tool)
        if not t:
            continue
        prec = "-" if t["per_alert_precision"] is None else f"{t['per_alert_precision']:.2f}"
        print(
            f"{tool:<14}{t['units_run']:>4}{t['soundness_alerts']:>5}"
            f"{t['FalsePositive']:>4}{t['RealIssue']:>5}{t['Undecided']:>4}"
            f"{t['per_unit_fp_rate']:>9.2f}{prec:>7}"
            f"{t['warning_alerts']:>6}{t['median_alerts_per_unit']:>7}"
        )
    print()
    print("Legend: N=units run, snd=soundness alerts, FP/Real/Und=triaged "
          "verdicts,")
    print("        FP/unit=units with >=1 FP / N, prec=Real/(Real+FP), "
          "warn=lint burden,")
    print("        med/u=median alerts (incl. warnings) per unit.")
    if metrics.get("triage_effort"):
        print()
        print("Triage effort:", metrics["triage_effort"])

    if paired:
        print()
        print("-" * 78)
        print("Paired buggy -> fixed (fixed-commit units):")
        res = (
            f"{'tool':<14}{'cells':>6}{'clean_resolve':>15}"
            f"{'FP_on_fixed':>13}"
        )
        print(res)
        print("-" * len(res))
        by_tool: dict[str, list[dict]] = {}
        for r in paired:
            by_tool.setdefault(r["tool"], []).append(r)
        for tool in _ordered_tools(by_tool):
            rows = by_tool.get(tool)
            if not rows:
                continue
            clean = sum(1 for r in rows if r["clean_resolution"])
            fp = sum(1 for r in rows if r["false_positive_on_fixed"])
            print(f"{tool:<14}{len(rows):>6}{clean:>15}{fp:>13}")
        print("clean_resolve = flagged the bug, silent once fixed (ideal).")
        print("FP_on_fixed   = still flags the patched circuit "
              "(false positive).")


def _latex(metrics: dict) -> str:
    rows = []
    for tool in TOOLS:
        t = metrics["tools"].get(tool)
        if not t:
            continue
        prec = "--" if t["per_alert_precision"] is None else f"{t['per_alert_precision']:.2f}"
        rows.append(
            f"{tool.replace('_', '\\_')} & {t['units_run']} & "
            f"{t['soundness_alerts']} & {t['FalsePositive']} & "
            f"{t['RealIssue']} & {t['Undecided']} & "
            f"{t['per_unit_fp_rate']:.2f} & {prec} & {t['warning_alerts']} \\\\"
        )
    body = "\n".join(rows)
    return (
        "\\documentclass{article}\n\\usepackage{booktabs}\n"
        "\\begin{document}\n\\begin{table}[h]\\centering\n"
        "\\caption{False positives on %d clean/fixed circuits (indicative).}\n"
        "\\begin{tabular}{lrrrrrrrr}\n\\toprule\n"
        "Tool & N & Snd & FP & Real & Und & FP/unit & Prec & Warn \\\\\n"
        "\\midrule\n%s\n\\bottomrule\n\\end{tabular}\n\\end{table}\n"
        "\\end{document}\n"
    ) % (metrics["n_units"], body)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("run_dir", type=Path, help="zkhydra fp output dir")
    p.add_argument(
        "--rq2-run",
        type=Path,
        default=None,
        help="RQ2 zkbugs run dir, for the paired buggy->fixed analysis.",
    )
    p.add_argument("--json", type=Path, default=None, help="Write metrics JSON.")
    p.add_argument(
        "--latex", type=Path, default=None, help="Write LaTeX table (.tex)."
    )
    args = p.parse_args()

    run_dir = args.run_dir.resolve()
    summary = _read_json(run_dir / "summary.json")
    if summary is None:
        print(f"error: no summary.json under {run_dir}", file=sys.stderr)
        return 1

    metrics = compute_metrics(summary)
    paired = (
        paired_buggy_fixed(run_dir, args.rq2_run.resolve())
        if args.rq2_run
        else []
    )
    print_report(metrics, paired)

    if args.json:
        out = {"metrics": metrics, "paired": paired}
        args.json.write_text(
            json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"\nWrote metrics: {args.json}")

    if args.latex:
        args.latex.write_text(_latex(metrics), encoding="utf-8")
        print(f"Wrote LaTeX: {args.latex}")
        try:
            subprocess.run(
                ["pdflatex", "-interaction=nonstopmode", args.latex.name],
                cwd=args.latex.parent,
                capture_output=True,
                timeout=120,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            print("(pdflatex unavailable; left .tex only)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
