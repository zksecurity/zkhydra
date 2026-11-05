#!/usr/bin/env python3
"""Author verification of FP triage verdicts (the step that makes them final).

Triage of the FP experiment is two-stage: ``triage_fp_run.py --auto`` writes an
AI-proposed verdict per soundness alert; an author then verifies EVERY case
here. For each alert the script shows the finding, the source around it, any
known-unfixed audit findings for the project, and the AI proposal; the author
accepts or overrides it. The final verdict, reviewer, and the measured review
time are stored in the case's ``review`` field in
``<run>/<unit>/<tool>/fp_triage.json`` — ``process_fp_results.py`` reports the
reviewed verdicts and sums review time as the triage effort.

Cases with no AI proposal (``--auto`` not run) can be reviewed too; the author
then decides from scratch.

Keys at the prompt:
    a = accept the AI verdict     f = FalsePositive     r = RealIssue
    u = Undecided                 s = skip for now      q = save and quit

Examples:
    python3 scripts/review_fp_triage.py output/fp-run --dataset output/fp-corpus/dataset/circom --reviewer TS
    python3 scripts/review_fp_triage.py output/fp-run --status
    python3 scripts/review_fp_triage.py output/fp-run --reviewer TS --tool picus --redo
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from triage_fp_run import (  # noqa: E402
    FINAL_VERDICTS,
    _collect_candidates,
    _fp_corpus_root,
    build_bundle,
    finding_fingerprint,
    is_reviewed,
)

VERDICT_KEYS = {"f": "FalsePositive", "r": "RealIssue", "u": "Undecided"}


def _load(path: Path) -> list[dict]:
    if path.is_file():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    return []


def _case(records: list[dict], unit: str, tool: str, idx: int, fp: str) -> dict:
    """Record for this finding; an AI row for a different (stale) finding at
    the same index is replaced so its proposal is not shown."""
    for i, r in enumerate(records):
        if r.get("finding_index") == idx:
            if r.get("finding_fp") == fp:
                return r
            records.pop(i)
            break
    rec = {"unit": unit, "tool": tool, "finding_index": idx, "finding_fp": fp,
           "triage": None, "elapsed_s": None}
    records.append(rec)
    return rec


def _ai_status(rec: dict) -> str | None:
    """AI proposal usable as a final verdict (Warning/Style is not one for a
    soundness alert)."""
    st = (rec.get("triage") or {}).get("status")
    return st if st in FINAL_VERDICTS else None


def _show(bundle: dict, rec: dict, n: int, total: int) -> None:
    f = bundle["finding"]
    prov = bundle["provenance"] or {}
    pos = f.get("position") or {}
    print("\n" + "=" * 100)
    print(f"[{n}/{total}] {bundle['unit']}  ·  tool={bundle['tool']}  ·  finding #{bundle['finding_index']}")
    print(f"project: {prov.get('ProjectName')} {prov.get('Project')} @ {str(prov.get('Commit'))[:10]}")
    print(f"finding: {f.get('bug_title')}  [{f.get('unified_bug_title')}]")
    if f.get("description"):
        print(f"  {str(f['description'])[:600]}")
    loc = ", ".join(f"{k}={v}" for k, v in pos.items() if v not in (None, ""))
    if loc or f.get("file"):
        print(f"  at {f.get('file') or ''} {loc}")
    if bundle.get("source_snippet"):
        print(f"--- {bundle['source_file']}")
        print(bundle["source_snippet"])
    known = prov.get("KnownUnfixed") or []
    if known:
        print("--- known unfixed audit findings in this project:")
        for k in known:
            print(f"  - {k.get('id')}: {k.get('title')} ({k.get('location')}, {k.get('status')})")
    ai = rec.get("triage")
    if ai:
        print(f"--- AI proposal: {ai.get('status')} ({ai.get('confidence')}) — {ai.get('reason')}")
        if ai.get("manual_analysis_reasoning"):
            print(f"    {str(ai['manual_analysis_reasoning'])[:800]}")
    else:
        print("--- AI proposal: none (decide from scratch)")
    print(f"--- tool output: {bundle['tool_dir']}")


def _ask(has_ai: bool) -> str:
    opts = "[a]ccept AI / " if has_ai else ""
    while True:
        ans = input(f"verdict? {opts}[f]alsePositive / [r]ealIssue / [u]ndecided / [s]kip / [q]uit: ").strip().lower()
        if ans in VERDICT_KEYS or ans in ("s", "q") or (ans == "a" and has_ai):
            return ans


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("run_dir", type=Path)
    p.add_argument("--dataset", type=Path, default=None, help="corpus dataset dir (for source snippets)")
    p.add_argument("--reviewer", default=None, help="reviewer initials (required unless --status)")
    p.add_argument("--tool", default=None, help="only this tool")
    p.add_argument("--redo", action="store_true", help="also show already reviewed cases")
    p.add_argument("--status", action="store_true", help="print review progress and exit")
    args = p.parse_args()

    run_dir = args.run_dir.resolve()
    candidates, _ = _collect_candidates(run_dir, args.tool)
    cells: dict[tuple[str, str], list[dict]] = {}
    for unit_dir, tool, idx, _f, _p in candidates:
        key = (unit_dir.name, tool)
        if key not in cells:
            cells[key] = _load(run_dir / unit_dir.name / tool / "fp_triage.json")

    def reviewed(unit, tool, idx, finding):
        fp = finding_fingerprint(finding)
        return any(r.get("finding_index") == idx and is_reviewed(r, fp) for r in cells[(unit, tool)])

    if args.status:
        by_tool: dict[str, list[int]] = {}
        for unit_dir, tool, idx, finding, _p in candidates:
            t = by_tool.setdefault(tool, [0, 0])
            t[0] += 1
            t[1] += reviewed(unit_dir.name, tool, idx, finding)
        for tool, (n, done) in sorted(by_tool.items()):
            print(f"{tool:<14} {done:>5}/{n:<5} reviewed")
        print(f"{'total':<14} {sum(v[1] for v in by_tool.values()):>5}/{len(candidates):<5}")
        return 0
    if not args.reviewer:
        p.error("--reviewer is required")

    dataset = args.dataset.resolve() if args.dataset else None
    corpus_root = _fp_corpus_root(dataset) if dataset else None
    todo = [c for c in candidates if args.redo or not reviewed(c[0].name, c[1], c[2], c[3])]
    print(f"{len(todo)} case(s) to review ({len(candidates)} soundness alerts in total)")

    def save(unit, tool):
        path = run_dir / unit / tool / "fp_triage.json"
        path.write_text(json.dumps(sorted(cells[(unit, tool)], key=lambda r: r["finding_index"]),
                                   indent=2, ensure_ascii=False), encoding="utf-8")

    for n, (unit_dir, tool, idx, finding, prov) in enumerate(todo, 1):
        unit = unit_dir.name
        fp = finding_fingerprint(finding)
        rec = _case(cells[(unit, tool)], unit, tool, idx, fp)
        bundle = build_bundle(unit_dir, tool, idx, finding, prov, corpus_root, dataset)
        _show(bundle, rec, n, len(todo))
        ai_status = _ai_status(rec)
        if rec.get("triage") and not ai_status:
            print("    (the AI proposal is not a final soundness verdict; choose f/r/u)")
        t0 = time.monotonic()
        ans = _ask(bool(ai_status))
        if ans == "q":
            break
        if ans == "s":
            continue
        status = ai_status if ans == "a" else VERDICT_KEYS[ans]
        note = input("note (optional, enter to skip): ").strip()
        seconds = round(time.monotonic() - t0, 1)
        rec["review"] = {
            "status": status,
            "note": note,
            "reviewer": args.reviewer,
            "seconds": seconds,
            "finding_fp": fp,
            "ai_status_seen": (rec.get("triage") or {}).get("status"),
            "agrees_with_ai": (status == ai_status) if ai_status else None,
            "reviewed_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        save(unit, tool)
    return 0


if __name__ == "__main__":
    sys.exit(main())
