#!/usr/bin/env python3
"""Report the FP experiment: per-tool false positives on audited projects.

Inputs (all under the `zkhydra fp` run dir):
- `summary.json` and `<unit>/fp_candidates.json` — per tool: run status,
  soundness alerts, lint warnings;
- `<unit>/<tool>/fp_triage.json` — per soundness alert: the author's verdict
  (from `review_fp_triage.py`).

A verdict belongs to one finding, matched by fingerprint, so re-runs cannot
re-attach it to another alert. Alerts without a verdict are reported as
`pending`, and the report is marked PRELIMINARY until none are left.

Per tool:
- coverage: units where the tool completed vs timed out / failed. Only
  completed runs enter the denominators (a timeout is not "no alert");
- alerts: units with >=1 soundness alert, soundness alerts, lint warnings
  (review burden, never counted as FPs);
- verdicts: FalsePositive / RealIssue / Undecided, FP rate per unit (units with
  >=1 FP / completed units), precision (Real / (Real + FP)).
Also a per-project breakdown (alerts/FP per tool).

Examples:
    python3 scripts/process_fp_results.py output/fp-run
    python3 scripts/process_fp_results.py output/fp-run --json output/fp-metrics.json --latex output/fp-table.tex
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from review_fp_triage import finding_fingerprint, is_reviewed  # noqa: E402

TOOLS = ["circomspect", "circom_civer", "picus", "ecneproject", "zkfuzz", "conscs"]
TOOL_LABEL = {
    "circomspect": "Circomspect",
    "circom_civer": "CIVER",
    "picus": "Picus",
    "ecneproject": "Ecne",
    "zkfuzz": "zkFuzz",
    "conscs": "ConsCS",
}
VERDICTS = ["FalsePositive", "RealIssue", "Undecided"]


def _read_json(path: Path):
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _ordered(present) -> list[str]:
    return [t for t in TOOLS if t in present] + sorted(t for t in present if t not in TOOLS)


def load_units(run_dir: Path) -> list[dict]:
    units = []
    for cand_path in sorted(run_dir.glob("*/fp_candidates.json")):
        data = _read_json(cand_path) or {}
        name = cand_path.parent.name
        prov = data.get("provenance") or {}
        rec = {
            "unit": name,
            "project": prov.get("ProjectName") or prov.get("Project") or "?",
            "constraints": prov.get("Constraints"),
            "tools": {},
        }
        for tool, entry in (data.get("tools") or {}).items():
            cases = {
                c.get("finding_index"): c
                for c in (_read_json(run_dir / name / tool / "fp_triage.json") or [])
                if isinstance(c, dict)
            }
            findings = entry.get("soundness") or []
            snd = int(entry.get("soundness_count") or len(findings))
            final = {v: 0 for v in VERDICTS}
            pending = 0
            for idx, finding in enumerate(findings):
                c = cases.get(idx)
                if is_reviewed(c, finding_fingerprint(finding)):
                    final[c["status"]] += 1
                else:
                    pending += 1
            rec["tools"][tool] = {
                "status": entry.get("status"),
                "soundness": snd,
                "warnings": int(entry.get("warning_count") or 0),
                "tool_errors": len(entry.get("tool_errors") or []),
                **final,
                "pending": pending,
            }
        units.append(rec)
    return units


def tool_metrics(units: list[dict]) -> dict:
    out = {}
    for tool in _ordered({t for u in units for t in u["tools"]}):
        cells = [u["tools"][tool] for u in units if tool in u["tools"]]
        ok = [c for c in cells if c["status"] == "success"]
        m = {
            "units": len(cells),
            "completed": len(ok),
            "timeout": sum(1 for c in cells if c["status"] == "timeout"),
            "failed": sum(1 for c in cells if c["status"] not in ("success", "timeout")),
            "units_with_alert": sum(1 for c in ok if c["soundness"] > 0),
            "alerts": sum(c["soundness"] for c in ok),
            "warnings": sum(c["warnings"] for c in ok),
            **{v: sum(c[v] for c in ok) for v in VERDICTS},
            "pending": sum(c["pending"] for c in ok),
            "units_with_fp": sum(1 for c in ok if c["FalsePositive"] > 0),
        }
        n = m["completed"]
        m["fp_rate_per_unit"] = round(m["units_with_fp"] / n, 3) if n else None
        denom = m["RealIssue"] + m["FalsePositive"]
        m["precision"] = round(m["RealIssue"] / denom, 3) if denom else None
        out[tool] = m
    return out


def compute(units: list[dict]) -> dict:
    tools = tool_metrics(units)
    projects = {}
    for proj in sorted({u["project"] for u in units}):
        pu = [u for u in units if u["project"] == proj]
        projects[proj] = {
            "units": len(pu),
            "tools": {
                t: {k: m[k] for k in ("completed", "units", "alerts", "FalsePositive", "RealIssue", "Undecided", "pending", "warnings")}
                for t, m in tool_metrics(pu).items()
            },
        }
    return {
        "n_units": len(units),
        "n_projects": len(projects),
        "preliminary": any(m["pending"] for m in tools.values()),
        "tools": tools,
        "projects": projects,
    }


def _f(x, fmt="{:.2f}", dash="-"):
    return dash if x is None else fmt.format(x)


def print_report(metrics: dict, not_processed: list[dict]) -> None:
    flag = "  [PRELIMINARY: unreviewed alerts remain]" if metrics["preliminary"] else ""
    print("=" * 100)
    print(f"FP experiment — {metrics['n_projects']} projects, {metrics['n_units']} units{flag}")
    print("=" * 100)
    hdr = (f"{'tool':<13}{'N':>4}{'ok':>4}{'TO':>4}{'err':>4}{'u+':>4}{'alerts':>7}{'FP':>5}{'Real':>5}"
           f"{'Und':>5}{'pend':>5}{'FP/u':>6}{'prec':>6}{'warn':>6}")
    print(hdr)
    print("-" * len(hdr))
    for tool, t in metrics["tools"].items():
        print(f"{tool:<13}{t['units']:>4}{t['completed']:>4}{t['timeout']:>4}{t['failed']:>4}"
              f"{t['units_with_alert']:>4}{t['alerts']:>7}{t['FalsePositive']:>5}{t['RealIssue']:>5}"
              f"{t['Undecided']:>5}{t['pending']:>5}{_f(t['fp_rate_per_unit']):>6}{_f(t['precision']):>6}"
              f"{t['warnings']:>6}")
    print("\nN units · ok/TO/err completed/timeout/failed · u+ completed units with >=1 soundness alert ·\n"
          "FP/Real/Und author verdicts · pend not yet reviewed · FP/u units with >=1 FP / ok ·\n"
          "prec Real/(Real+FP) · warn lint warnings (review burden)")
    print("\nPer project (alerts/FP per tool; '-' = did not complete):")
    tools = list(metrics["tools"])
    print(f"{'project':<26}{'units':>6}" + "".join(f"{TOOL_LABEL.get(t, t)[:10]:>12}" for t in tools))
    for proj, pd in metrics["projects"].items():
        cells = []
        for t in tools:
            c = pd["tools"].get(t)
            cells.append("-" if not c or not c["completed"] else f"{c['alerts']}/{c['FalsePositive']}")
        print(f"{proj:<26}{pd['units']:>6}" + "".join(f"{x:>12}" for x in cells))
    if not_processed:
        print(f"\nNot processed ({len(not_processed)}):")
        for s in not_processed:
            print(f"  {s['status']:<8} {s['unit']}: {s['reason']}")


def latex_table(metrics: dict) -> str:
    rows = [
        "% Generated by scripts/process_fp_results.py -- do not edit by hand.",
        f"% {metrics['n_projects']} projects, {metrics['n_units']} entrypoints"
        + (" -- PRELIMINARY (unreviewed alerts remain)" if metrics["preliminary"] else ""),
        "\\begin{tabular}{lrrrrrrrr}",
        "\\toprule",
        "Tool & Ran & Units w/ alert & Alerts & FP & Real & Und. & FP/unit & Warnings \\\\",
        "\\midrule",
    ]
    for tool, t in metrics["tools"].items():
        rows.append(
            f"{TOOL_LABEL.get(tool, tool.replace('_', chr(92) + '_'))} & {t['completed']}/{t['units']} & "
            f"{t['units_with_alert']} & {t['alerts']} & {t['FalsePositive']} & {t['RealIssue']} & "
            f"{t['Undecided']} & {_f(t['fp_rate_per_unit'], dash='--')} & {t['warnings']} \\\\"
        )
    rows += [
        "\\bottomrule",
        "\\end{tabular}",
        "",
    ]
    return "\n".join(rows)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("run_dir", type=Path, help="zkhydra fp output dir")
    p.add_argument("--json", type=Path, default=None, help="write all metrics as JSON")
    p.add_argument("--latex", type=Path, default=None, help="write the per-tool LaTeX table fragment")
    args = p.parse_args()

    run_dir = args.run_dir.resolve()
    summary = _read_json(run_dir / "summary.json")
    if summary is None:
        print(f"error: no summary.json under {run_dir}", file=sys.stderr)
        return 1
    not_processed = [
        {"unit": r["bug_name"], "status": r["status"], "reason": r.get("reason") or r.get("error")}
        for r in summary.get("units", [])
        if r.get("status") != "processed"
    ]
    units = load_units(run_dir)
    metrics = compute(units)
    print_report(metrics, not_processed)
    if args.json:
        args.json.write_text(json.dumps({"metrics": metrics, "not_processed": not_processed, "units": units},
                                        indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nWrote metrics: {args.json}")
    if args.latex:
        args.latex.write_text(latex_table(metrics), encoding="utf-8")
        print(f"Wrote LaTeX table: {args.latex}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
