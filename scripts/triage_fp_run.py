#!/usr/bin/env python3
"""Triage candidate false positives from a zkhydra `fp` run.

Walks `<run>/<unit>/fp_candidates.json`. Every soundness-class finding is a
candidate false positive; each is bundled with the tool's results/parsed/raw
output, the unit provenance, and — when reachable — the circuit source at the
finding's location, then either:

- `--dry-run` (default): writes `<run>/fp_triage_queue.json` with all bundles.
- `--auto`: shells out to `claude -p` per candidate, instructing Claude to use
  the `triage-fp-finding` skill, and writes per-(unit,tool) `fp_triage.json`
  plus a rolled-up `<run>/fp_triage_summary.json`. Per-case wall-time is
  recorded so the report can show indicative triage effort.

Warning/Style findings (circomspect lint) are counted toward review burden
without an LLM call — they are never soundness false positives.

Mutating flag (opt-in, implies --auto):

- `--update-summary`: patch the run's `summary.json` with an `fp_counts` rollup
  {FalsePositive, RealIssue, Warning/Style, Undecided}, a `triage_effort`
  object, and a per-(unit,tool) `fp` verdict breakdown.

Examples:
    python3 scripts/triage_fp_run.py output/fp-run
    python3 scripts/triage_fp_run.py output/fp-run --dataset path/to/corpus/dataset/circom
    python3 scripts/triage_fp_run.py output/fp-run --auto --jobs 4 --update-summary
    python3 scripts/triage_fp_run.py output/fp-run --tool picus
"""

from __future__ import annotations

import argparse
import concurrent.futures as _cf
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


def _resolve_finding_source(
    provenance: dict | None, finding: dict, corpus_root: Path | None
) -> tuple[str | None, str]:
    """Best-effort: locate the flagged file under the unit's codebase and
    return a numbered snippet around the finding's line. There is no ground
    truth here, so we key off the finding's own file/position."""
    if corpus_root is None or not finding:
        return None, ""
    codebase_rel = (provenance or {}).get("Codebase")
    if not codebase_rel:
        return None, ""
    codebase_abs = (corpus_root / codebase_rel).resolve()
    if not codebase_abs.is_dir():
        return None, ""

    file_field = finding.get("file")
    if not file_field:
        return None, ""
    candidate = codebase_abs / file_field
    if not candidate.is_file():
        # fall back to matching by basename anywhere under the codebase
        matches = list(codebase_abs.rglob(Path(file_field).name))
        if not matches:
            return None, ""
        candidate = matches[0]

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


def _iter_candidates(run_dir: Path, tool_filter: str | None):
    """Yield (unit_dir, tool_name, finding_index, finding, provenance) for
    every soundness candidate, plus warning tallies per (unit, tool)."""
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
            for idx, finding in enumerate(soundness):
                yield unit_dir, tool_name, idx, finding, provenance, len(
                    warnings
                )


def build_bundle(
    unit_dir: Path,
    tool_name: str,
    finding_index: int,
    finding: dict,
    provenance: dict,
    corpus_root: Path | None,
) -> dict:
    tool_dir = unit_dir / tool_name
    source_path, source_snippet = _resolve_finding_source(
        provenance, finding, corpus_root
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
false positive raised on a clean/fixed circuit.

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
        "triage": verdict,
        "elapsed_s": elapsed,
    }


def _write_per_tool_triage(run_dir: Path, verdicts: list[dict]) -> None:
    """Group verdicts by (unit, tool) and write <unit>/<tool>/fp_triage.json."""
    by_tool: dict[tuple[str, str], list[dict]] = {}
    for v in verdicts:
        by_tool.setdefault((v["unit"], v["tool"]), []).append(v)
    for (unit, tool), rows in by_tool.items():
        out = run_dir / unit / tool / "fp_triage.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(
                sorted(rows, key=lambda r: r["finding_index"]),
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )


def _update_run_summary(
    run_dir: Path,
    verdicts: list[dict],
    warning_counts: dict[tuple[str, str], int],
) -> None:
    """Patch summary.json with fp_counts, triage_effort, and per-(unit,tool) fp."""
    summary_path = run_dir / "summary.json"
    data = _read_json(summary_path)
    if data is None:
        logging.warning("summary.json missing; cannot update")
        return

    counts = {s: 0 for s in VALID_STATUSES}
    total_elapsed = 0.0
    per_cell: dict[tuple[str, str], dict] = {}
    for v in verdicts:
        status = v["triage"].get("status", "Undecided")
        counts[status] = counts.get(status, 0) + 1
        total_elapsed += float(v.get("elapsed_s") or 0.0)
        cell = per_cell.setdefault(
            (v["unit"], v["tool"]),
            {s: 0 for s in VALID_STATUSES},
        )
        cell[status] += 1
    # warnings tallied without an LLM call
    for (unit, tool), n in warning_counts.items():
        counts["Warning/Style"] = counts.get("Warning/Style", 0) + n
        cell = per_cell.setdefault((unit, tool), {s: 0 for s in VALID_STATUSES})
        cell["Warning/Style"] += n

    for row in data.get("units", []):
        unit = row.get("bug_name")
        for tool_name, tool_entry in (row.get("tools") or {}).items():
            cell = per_cell.get((unit, tool_name))
            if cell is not None:
                tool_entry["fp"] = cell

    data["fp_counts"] = counts
    data["triage_effort"] = {
        "soundness_candidates_triaged": len(verdicts),
        "auto_triage_seconds": round(total_elapsed, 2),
        "warnings_counted": sum(warning_counts.values()),
    }
    summary_path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    logging.info("Updated summary.json fp_counts: %s", counts)


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
        "--update-summary",
        action="store_true",
        help="Patch summary.json with fp_counts, triage_effort, and per-cell fp.",
    )
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

    bundles: list[dict] = []
    warning_counts: dict[tuple[str, str], int] = {}
    for (
        unit_dir,
        tool_name,
        idx,
        finding,
        provenance,
        n_warn,
    ) in _iter_candidates(run_dir, args.tool):
        bundles.append(
            build_bundle(
                unit_dir, tool_name, idx, finding, provenance, corpus_root
            )
        )
        warning_counts[(unit_dir.name, tool_name)] = n_warn

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
        logging.info("--dry-run (default); skipping skill invocation")
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
    logging.info("FP triage summary: %s — %s", counts, summary_path)

    if args.update_summary:
        _update_run_summary(run_dir, verdicts, warning_counts)

    return 0


if __name__ == "__main__":
    sys.exit(main())
