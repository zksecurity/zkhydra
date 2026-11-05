#!/usr/bin/env python3
"""First-pass (AI-proposed) triage of candidate false positives from an `fp` run.

Walks `<run>/<unit>/fp_candidates.json`. Every soundness-class finding is a
candidate false positive; each is bundled with the tool's results/parsed/raw
output, the unit provenance (incl. the project's known-unfixed audit
findings), and — when reachable — the circuit source at the finding's
location, then either:

- dry run (default): writes `<run>/fp_triage_queue.json` with all bundles.
- `--auto`: shells out to `claude -p` per candidate with the triage prompt and
  writes per-(unit,tool) `fp_triage.json` plus `<run>/fp_triage_summary.json`.
  Per-case wall time is recorded.

These verdicts are PROPOSALS. An author verifies every case with
`review_fp_triage.py`, which stores the final verdict next to the proposal;
re-running `--auto` keeps those reviews. Warnings (circomspect lint) are never
sent for triage: they count toward review burden, not soundness FPs.

Examples:
    python3 scripts/triage_fp_run.py output/fp-run --dataset output/fp-corpus/dataset/circom
    python3 scripts/triage_fp_run.py output/fp-run --dataset output/fp-corpus/dataset/circom --auto --jobs 4
    python3 scripts/triage_fp_run.py output/fp-run --auto --tool picus
"""

from __future__ import annotations

import argparse
import concurrent.futures as _cf
import hashlib
import json
import logging
import shutil
import subprocess
import sys
import time
from pathlib import Path

RAW_HEAD_LINES = 200
SOURCE_CONTEXT_BEFORE = 8
SOURCE_CONTEXT_AFTER = 20
WARNING_CATEGORY = "Warning (Other -- probably not a bug)"
VALID_STATUSES = {"FalsePositive", "RealIssue", "Warning/Style", "Undecided"}


def _read_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        logging.warning("malformed JSON at %s: %s", path, exc)
        return None


def _head_text(path: Path, n: int = RAW_HEAD_LINES) -> str:
    if not path.is_file():
        return ""
    try:
        with path.open(encoding="utf-8", errors="replace") as f:
            lines = [next(f, "") for _ in range(n)]
        return "".join(lines)
    except Exception as exc:  # noqa: BLE001
        logging.warning("cannot read %s: %s", path, exc)
        return ""


def _fp_corpus_root(dataset_dir: Path) -> Path:
    """Map ``<root>/dataset/circom`` -> ``<root>`` (mirrors fp_loader)."""
    cur = dataset_dir.resolve()
    for anc in [cur, *cur.parents]:
        if anc.name == "dataset":
            return anc.parent
    return cur.parent


FINAL_VERDICTS = ("FalsePositive", "RealIssue", "Undecided")


def finding_fingerprint(finding: dict) -> str:
    """Stable id of a finding, so verdicts stay attached to the same finding
    even if a re-run reorders or changes a tool's findings."""
    blob = json.dumps(finding, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def is_reviewed(rec: dict | None, fingerprint: str) -> bool:
    """A case counts as reviewed iff the author recorded a final soundness
    verdict for exactly this finding. Shared by review and reporting."""
    rv = (rec or {}).get("review") or {}
    return rv.get("status") in FINAL_VERDICTS and rv.get("finding_fp") == fingerprint


_UNIT_DIRS: dict[Path, dict[str, Path]] = {}


def _corpus_unit_dir(dataset_dir: Path | None, unit: str) -> Path | None:
    """Locate the corpus unit dir (holding fp_config.json) for a run unit.
    The dataset is scanned once and cached."""
    if dataset_dir is None:
        return None
    if dataset_dir not in _UNIT_DIRS:
        _UNIT_DIRS[dataset_dir] = {
            p.parent.name: p.parent for p in dataset_dir.rglob("fp_config.json")
        }
    return _UNIT_DIRS[dataset_dir].get(unit)


def _resolve_finding_source(
    provenance: dict | None,
    finding: dict,
    corpus_root: Path | None,
    unit_corpus_dir: Path | None = None,
) -> tuple[str | None, str]:
    """Best-effort: locate the flagged file (absolute, unit wrapper, codebase,
    then link paths) and return a numbered snippet around the finding's line.
    There is no ground truth here, so we key off the finding's own
    file/position. A basename search is used only when it is unambiguous."""
    if corpus_root is None or not finding:
        return None, ""
    file_field = finding.get("file")
    if not file_field:
        return None, ""
    prov = provenance or {}
    roots: list[Path] = []
    if unit_corpus_dir is not None:
        roots.append(unit_corpus_dir)
    if prov.get("Codebase"):
        roots.append((corpus_root / prov["Codebase"]).resolve())
    for lp in prov.get("LinkPaths") or []:
        roots.append((corpus_root / lp).resolve())

    candidate: Path | None = None
    if Path(file_field).is_absolute() and Path(file_field).is_file():
        candidate = Path(file_field)
    for root in roots:
        if candidate is not None:
            break
        if (root / file_field).is_file():
            candidate = root / file_field
    if candidate is None and prov.get("Codebase"):
        codebase_abs = (corpus_root / prov["Codebase"]).resolve()
        if codebase_abs.is_dir():
            matches = [
                m
                for m in codebase_abs.rglob(Path(file_field).name)
                if "node_modules" not in m.parts
            ]
            if len(matches) == 1:
                candidate = matches[0]
    if candidate is None:
        return None, ""

    line = (finding.get("position") or {}).get("line")
    try:
        lines = candidate.read_text(encoding="utf-8").splitlines()
    except Exception as exc:  # noqa: BLE001
        logging.warning("cannot read source %s: %s", candidate, exc)
        return str(candidate), ""
    if not isinstance(line, int):
        return str(candidate), ""
    start = max(1, line - SOURCE_CONTEXT_BEFORE)
    end = line + SOURCE_CONTEXT_AFTER
    slice_ = lines[start - 1 : end]
    numbered = "\n".join(f"{i:>5}: {s}" for i, s in enumerate(slice_, start))
    return str(candidate), numbered


def _collect_candidates(
    run_dir: Path, tool_filter: str | None
) -> tuple[list[tuple], dict[tuple[str, str], int]]:
    """Return ([(unit_dir, tool, idx, finding, provenance)], warning_counts).

    Every soundness finding is a candidate. Warnings are tallied for EVERY
    (unit, tool) cell, including cells with no soundness finding.
    """
    candidates: list[tuple] = []
    warning_counts: dict[tuple[str, str], int] = {}
    for cand_path in sorted(run_dir.glob("*/fp_candidates.json")):
        unit_dir = cand_path.parent
        data = _read_json(cand_path)
        if not data:
            continue
        provenance = data.get("provenance") or {}
        for tool_name, tool_entry in (data.get("tools") or {}).items():
            if tool_filter and tool_filter != tool_name:
                continue
            soundness = tool_entry.get("soundness") or []
            warnings = tool_entry.get("warnings") or []
            if warnings:
                warning_counts[(unit_dir.name, tool_name)] = len(warnings)
            for idx, finding in enumerate(soundness):
                candidates.append(
                    (unit_dir, tool_name, idx, finding, provenance)
                )
    return candidates, warning_counts


def build_bundle(
    unit_dir: Path,
    tool_name: str,
    finding_index: int,
    finding: dict,
    provenance: dict,
    corpus_root: Path | None,
    dataset_dir: Path | None = None,
) -> dict:
    tool_dir = unit_dir / tool_name
    source_path, source_snippet = _resolve_finding_source(
        provenance,
        finding,
        corpus_root,
        _corpus_unit_dir(dataset_dir, unit_dir.name),
    )
    return {
        "unit": unit_dir.name,
        "tool": tool_name,
        "finding_index": finding_index,
        "unit_dir": str(unit_dir.resolve()),
        "tool_dir": str(tool_dir.resolve()),
        "provenance": provenance,
        "finding": finding,
        "results": _read_json(tool_dir / "results.json"),
        "parsed": _read_json(tool_dir / "parsed.json"),
        "raw_head": _head_text(tool_dir / "raw.txt"),
        "source_file": source_path,
        "source_snippet": source_snippet,
    }


PROMPT_TEMPLATE = """Use the `triage-fp-finding` skill to triage this candidate \
false positive raised on an audited, battle-tested circuit.

Return ONLY a JSON object matching the skill's output schema (no prose, no code
fences). Here is the full case bundle:

```json
{bundle}
```
"""


def _strip_code_fence(s: str) -> str:
    s = s.strip()
    if s.startswith("```"):
        lines = s.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        return "\n".join(lines).strip()
    return s


def _extract_json(text: str) -> dict | None:
    text = _strip_code_fence(text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return None
    return None


def run_skill(bundle: dict, claude_bin: str, timeout: int) -> dict:
    prompt = PROMPT_TEMPLATE.format(bundle=json.dumps(bundle, indent=2))
    try:
        proc = subprocess.run(
            [claude_bin, "-p", prompt],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return {
            "status": "Undecided",
            "reason": f"claude CLI not found: {claude_bin}",
            "manual_analysis": "Pending",
            "manual_analysis_reasoning": "claude -p invocation failed",
            "confidence": "low",
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "Undecided",
            "reason": f"claude -p timed out after {timeout}s",
            "manual_analysis": "Pending",
            "manual_analysis_reasoning": "timeout",
            "confidence": "low",
        }
    output = proc.stdout.strip() or proc.stderr.strip()
    verdict = _extract_json(output)
    if not verdict or verdict.get("status") not in VALID_STATUSES:
        return {
            "status": "Undecided",
            "reason": "skill response did not parse",
            "manual_analysis": "Pending",
            "manual_analysis_reasoning": output[:500],
            "confidence": "low",
        }
    return verdict


def _process_case(args_tuple):
    bundle, claude_bin, timeout = args_tuple
    t0 = time.monotonic()
    verdict = run_skill(bundle, claude_bin, timeout)
    elapsed = round(time.monotonic() - t0, 2)
    return {
        "unit": bundle["unit"],
        "tool": bundle["tool"],
        "finding_index": bundle["finding_index"],
        "finding_fp": finding_fingerprint(bundle["finding"]),
        "triage": verdict,
        "elapsed_s": elapsed,
    }


def _write_per_tool_triage(run_dir: Path, verdicts: list[dict]) -> None:
    """Merge AI verdicts into <unit>/<tool>/fp_triage.json. An author `review`
    is carried over only when it belongs to the same finding (fingerprint);
    reviews of findings that changed are dropped so they cannot attach to a
    different alert. The review keeps the AI status the author actually saw,
    so agreement is not rewritten by a later AI pass."""
    by_tool: dict[tuple[str, str], list[dict]] = {}
    for v in verdicts:
        by_tool.setdefault((v["unit"], v["tool"]), []).append(v)
    for (unit, tool), rows in by_tool.items():
        out = run_dir / unit / tool / "fp_triage.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        existing = {
            r.get("finding_index"): r for r in (_read_json(out) or []) if isinstance(r, dict)
        }
        for row in rows:
            old = existing.get(row["finding_index"]) or {}
            if is_reviewed(old, row["finding_fp"]):
                row["review"] = old["review"]
            elif old.get("review"):
                logging.warning(
                    "%s/%s #%d: finding changed since it was reviewed; review dropped",
                    unit, tool, row["finding_index"],
                )
            existing[row["finding_index"]] = row
        out.write_text(
            json.dumps(
                sorted(existing.values(), key=lambda r: r["finding_index"]),
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("run_dir", type=Path, help="zkhydra fp output dir")
    p.add_argument(
        "--dataset",
        type=Path,
        default=None,
        help="The --dataset (corpus) arg used for the fp run, to resolve "
        "circuit source. If omitted, source_snippet in bundles is empty.",
    )
    p.add_argument("--tool", type=str, default=None, help="Only this tool.")
    p.add_argument(
        "--auto",
        action="store_true",
        help="Invoke claude -p per candidate and write fp_triage.json files.",
    )
    p.add_argument("--jobs", "-j", type=int, default=1)
    p.add_argument(
        "--claude-bin",
        default=shutil.which("claude") or "claude",
    )
    p.add_argument("--timeout", type=int, default=180)
    p.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    args = p.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    run_dir = args.run_dir.resolve()
    if not run_dir.is_dir():
        logging.error("run_dir not found: %s", run_dir)
        return 1

    corpus_root = _fp_corpus_root(args.dataset) if args.dataset else None

    candidates, warning_counts = _collect_candidates(run_dir, args.tool)
    dataset_dir = args.dataset.resolve() if args.dataset else None
    bundles: list[dict] = [
        build_bundle(
            unit_dir, tool_name, idx, finding, provenance, corpus_root, dataset_dir
        )
        for unit_dir, tool_name, idx, finding, provenance in candidates
    ]

    if not bundles and not warning_counts:
        logging.info("No candidate findings under %s", run_dir)
        return 0

    logging.info(
        "Found %d soundness candidate(s), %d (unit,tool) cells with warnings",
        len(bundles),
        sum(1 for n in warning_counts.values() if n),
    )

    queue_path = run_dir / "fp_triage_queue.json"
    queue_path.write_text(
        json.dumps(bundles, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    logging.info("Wrote %d bundle(s) to %s", len(bundles), queue_path)

    if not args.auto:
        logging.info("dry run (default); pass --auto to request AI proposals")
        return 0

    if (
        not shutil.which(args.claude_bin)
        and not Path(args.claude_bin).is_file()
    ):
        logging.error(
            "claude CLI not found at %s — cannot use --auto", args.claude_bin
        )
        return 2

    work = [(b, args.claude_bin, args.timeout) for b in bundles]
    verdicts: list[dict] = []
    if args.jobs == 1:
        for idx, wt in enumerate(work, 1):
            logging.info(
                "[%d/%d] %s / %s #%d",
                idx,
                len(work),
                wt[0]["unit"],
                wt[0]["tool"],
                wt[0]["finding_index"],
            )
            verdicts.append(_process_case(wt))
    else:
        logging.info(
            "Dispatching %d candidates across %d workers", len(work), args.jobs
        )
        with _cf.ThreadPoolExecutor(max_workers=args.jobs) as ex:
            futures = {ex.submit(_process_case, wt): wt for wt in work}
            for idx, fut in enumerate(_cf.as_completed(futures), 1):
                wt = futures[fut]
                try:
                    verdicts.append(fut.result())
                    logging.info(
                        "[%d/%d] ✓ %s / %s #%d",
                        idx,
                        len(work),
                        wt[0]["unit"],
                        wt[0]["tool"],
                        wt[0]["finding_index"],
                    )
                except Exception as exc:  # noqa: BLE001
                    logging.error(
                        "[%d/%d] ✗ %s / %s: %s",
                        idx,
                        len(work),
                        wt[0]["unit"],
                        wt[0]["tool"],
                        exc,
                    )

    _write_per_tool_triage(run_dir, verdicts)

    counts = {s: 0 for s in VALID_STATUSES}
    total_elapsed = 0.0
    for v in verdicts:
        counts[v["triage"].get("status", "Undecided")] += 1
        total_elapsed += float(v.get("elapsed_s") or 0.0)
    counts["Warning/Style"] += sum(warning_counts.values())

    summary = {
        "run_dir": str(run_dir),
        "soundness_candidates": len(bundles),
        "warnings_counted": sum(warning_counts.values()),
        "auto": True,
        "counts": counts,
        "auto_triage_seconds": round(total_elapsed, 2),
        "cases": verdicts,
    }
    summary_path = run_dir / "fp_triage_summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    logging.info("FP triage summary (AI proposals): %s — %s", counts, summary_path)
    logging.info("Next: verify every case with scripts/review_fp_triage.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
