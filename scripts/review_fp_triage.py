#!/usr/bin/env python3
"""Manual triage of the soundness alerts from an `fp` run.

An author reviews every soundness alert in `<run>/<unit>/fp_candidates.json`.
For each alert the script shows the finding, the source around it, and the
project's known-unfixed audit findings; the author labels it FalsePositive,
RealIssue or Undecided. Verdicts are stored per (unit, tool) in
`<run>/<unit>/<tool>/fp_triage.json` as `{unit, tool, finding_index,
finding_fp, status}`; `finding_fp` ties a verdict to exactly one finding, so a
re-run cannot re-attach it to a different alert. `process_fp_results.py`
reports the verdicts. Warnings (circomspect lint) are not triaged: they count
toward review burden, not soundness FPs.

Keys at the prompt:
    f = FalsePositive   r = RealIssue   u = Undecided   s = skip   q = quit

Examples:
    python3 scripts/review_fp_triage.py output/fp-run --dataset output/fp-corpus/dataset/circom
    python3 scripts/review_fp_triage.py output/fp-run --status
    python3 scripts/review_fp_triage.py output/fp-run --tool picus --redo
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

SOURCE_CONTEXT_BEFORE = 8
SOURCE_CONTEXT_AFTER = 20
FINAL_VERDICTS = ("FalsePositive", "RealIssue", "Undecided")
VERDICT_KEYS = {"f": "FalsePositive", "r": "RealIssue", "u": "Undecided"}


def _read_json(path: Path):
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def finding_fingerprint(finding: dict) -> str:
    """Stable id of a finding, so verdicts stay attached to the same finding
    even if a re-run reorders or changes a tool's findings."""
    blob = json.dumps(finding, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def is_reviewed(rec: dict | None, fingerprint: str) -> bool:
    """A verdict counts iff it is final and belongs to exactly this finding.
    Shared by review and reporting."""
    rec = rec or {}
    return rec.get("status") in FINAL_VERDICTS and rec.get("finding_fp") == fingerprint


def _fp_corpus_root(dataset_dir: Path) -> Path:
    """Map ``<root>/dataset/circom`` -> ``<root>`` (mirrors fp_loader)."""
    cur = dataset_dir.resolve()
    for anc in [cur, *cur.parents]:
        if anc.name == "dataset":
            return anc.parent
    return cur.parent


def _corpus_unit_dirs(dataset_dir: Path | None) -> dict[str, Path]:
    """Corpus unit dirs (holding fp_config.json) by unit name."""
    if dataset_dir is None:
        return {}
    return {p.parent.name: p.parent for p in dataset_dir.rglob("fp_config.json")}


def _finding_source(
    provenance: dict,
    finding: dict,
    corpus_root: Path | None,
    unit_corpus_dir: Path | None,
) -> tuple[str | None, str]:
    """Best-effort: locate the flagged file (absolute, unit wrapper, codebase,
    then link paths) and return a numbered snippet around the finding's line.
    A basename search is used only when it is unambiguous."""
    file_field = finding.get("file")
    if corpus_root is None or not file_field:
        return None, ""
    roots: list[Path] = []
    if unit_corpus_dir is not None:
        roots.append(unit_corpus_dir)
    if provenance.get("Codebase"):
        roots.append((corpus_root / provenance["Codebase"]).resolve())
    for lp in provenance.get("LinkPaths") or []:
        roots.append((corpus_root / lp).resolve())

    candidate: Path | None = None
    if Path(file_field).is_absolute() and Path(file_field).is_file():
        candidate = Path(file_field)
    for root in roots:
        if candidate is None and (root / file_field).is_file():
            candidate = root / file_field
    if candidate is None and provenance.get("Codebase"):
        codebase = (corpus_root / provenance["Codebase"]).resolve()
        if codebase.is_dir():
            matches = [m for m in codebase.rglob(Path(file_field).name) if "node_modules" not in m.parts]
            if len(matches) == 1:
                candidate = matches[0]
    if candidate is None:
        return None, ""

    line = (finding.get("position") or {}).get("line")
    if not isinstance(line, int):
        return str(candidate), ""
    lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(1, line - SOURCE_CONTEXT_BEFORE)
    snippet = lines[start - 1 : line + SOURCE_CONTEXT_AFTER]
    return str(candidate), "\n".join(f"{i:>5}: {s}" for i, s in enumerate(snippet, start))


def _collect_candidates(run_dir: Path, tool_filter: str | None) -> list[tuple]:
    """[(unit_dir, tool, finding_index, finding, provenance)] for every soundness finding."""
    candidates = []
    for cand_path in sorted(run_dir.glob("*/fp_candidates.json")):
        data = _read_json(cand_path) or {}
        provenance = data.get("provenance") or {}
        for tool, entry in (data.get("tools") or {}).items():
            if tool_filter and tool_filter != tool:
                continue
            for idx, finding in enumerate(entry.get("soundness") or []):
                candidates.append((cand_path.parent, tool, idx, finding, provenance))
    return candidates


def _show(unit: str, tool: str, idx: int, finding: dict, prov: dict, source: tuple, n: int, total: int) -> None:
    pos = finding.get("position") or {}
    print("\n" + "=" * 100)
    print(f"[{n}/{total}] {unit}  ·  tool={tool}  ·  finding #{idx}")
    print(f"project: {prov.get('ProjectName')} {prov.get('Project')} @ {str(prov.get('Commit'))[:10]}")
    print(f"finding: {finding.get('bug_title')}  [{finding.get('unified_bug_title')}]")
    if finding.get("description"):
        print(f"  {str(finding['description'])[:600]}")
    loc = ", ".join(f"{k}={v}" for k, v in pos.items() if v not in (None, ""))
    if loc or finding.get("file"):
        print(f"  at {finding.get('file') or ''} {loc}")
    source_file, snippet = source
    if snippet:
        print(f"--- {source_file}")
        print(snippet)
    known = prov.get("KnownUnfixed") or []
    if known:
        print("--- known unfixed audit findings in this project:")
        for k in known:
            print(f"  - {k.get('id')}: {k.get('title')} ({k.get('location')}, {k.get('status')})")


def _ask() -> str:
    while True:
        ans = input("verdict? [f]alsePositive / [r]ealIssue / [u]ndecided / [s]kip / [q]uit: ").strip().lower()
        if ans in VERDICT_KEYS or ans in ("s", "q"):
            return ans


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("run_dir", type=Path)
    p.add_argument("--dataset", type=Path, default=None, help="corpus dataset dir (for source snippets)")
    p.add_argument("--tool", default=None, help="only this tool")
    p.add_argument("--redo", action="store_true", help="also show already reviewed alerts")
    p.add_argument("--status", action="store_true", help="print review progress and exit")
    args = p.parse_args()

    run_dir = args.run_dir.resolve()
    candidates = _collect_candidates(run_dir, args.tool)
    cells: dict[tuple[str, str], list[dict]] = {}
    for unit_dir, tool, *_ in candidates:
        cells.setdefault((unit_dir.name, tool), _read_json(unit_dir / tool / "fp_triage.json") or [])

    def reviewed(unit: str, tool: str, idx: int, finding: dict) -> bool:
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

    dataset = args.dataset.resolve() if args.dataset else None
    corpus_root = _fp_corpus_root(dataset) if dataset else None
    unit_dirs = _corpus_unit_dirs(dataset)
    todo = [c for c in candidates if args.redo or not reviewed(c[0].name, c[1], c[2], c[3])]
    print(f"{len(todo)} alert(s) to review ({len(candidates)} soundness alerts in total)")

    for n, (unit_dir, tool, idx, finding, prov) in enumerate(todo, 1):
        unit = unit_dir.name
        source = _finding_source(prov, finding, corpus_root, unit_dirs.get(unit))
        _show(unit, tool, idx, finding, prov, source, n, len(todo))
        ans = _ask()
        if ans == "q":
            break
        if ans == "s":
            continue
        records = [r for r in cells[(unit, tool)] if r.get("finding_index") != idx]
        records.append({"unit": unit, "tool": tool, "finding_index": idx,
                        "finding_fp": finding_fingerprint(finding), "status": VERDICT_KEYS[ans]})
        cells[(unit, tool)] = sorted(records, key=lambda r: r["finding_index"])
        (unit_dir / tool / "fp_triage.json").write_text(
            json.dumps(cells[(unit, tool)], indent=2, ensure_ascii=False), encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
