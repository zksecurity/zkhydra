#!/usr/bin/env python3
"""Triage Undecided verdicts from a zkhydra zkbugs run.

Walks `<run>/<bug>/<tool>/evaluation.json`, collects every
`Undecided`, bundles the per-case context (ground_truth, results,
parsed, a head of raw.txt, and — when reachable — the circuit
source at the bug's Location), and either:

- `--dry-run` (default): writes `<run>/triage_queue.json` with all
  bundles ready for inspection or manual routing.
- `--auto`: shells out to `claude -p` in headless mode per case,
  instructing Claude to use the `triage-zkbugs-finding` skill.
  Writes the structured verdict to
  `<run>/<bug>/<tool>/triage.json` and a rolled-up
  `<run>/triage_summary.json`.

Examples:
    python3 scripts/triage_zkbugs_run.py output/zkbugs-run
    python3 scripts/triage_zkbugs_run.py output/zkbugs-run --auto --jobs 4
    python3 scripts/triage_zkbugs_run.py output/zkbugs-run --tool picus
"""

from __future__ import annotations

import argparse
import concurrent.futures as _cf
import json
import logging
import shutil
import subprocess
import sys
from pathlib import Path

RAW_HEAD_LINES = 200
SOURCE_CONTEXT_BEFORE = 5
SOURCE_CONTEXT_AFTER = 20
VALID_STATUSES = {"TruePositive", "FalseNegative", "Undecided"}


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
    except Exception as exc:
        logging.warning("cannot read %s: %s", path, exc)
        return ""


def _parse_line_range(line_field: str | None) -> tuple[int, int] | None:
    """GT's Line field is "39-45" or "45" or empty."""
    if not line_field:
        return None
    s = str(line_field).strip()
    if not s:
        return None
    if "-" in s:
        lo, hi = s.split("-", 1)
        try:
            return int(lo), int(hi)
        except ValueError:
            return None
    try:
        n = int(s)
        return n, n
    except ValueError:
        return None


def _resolve_source(
    ground_truth: dict, dataset_root: Path | None
) -> tuple[Path | None, str]:
    """Return the absolute path of the vulnerable source file and a
    small snippet around the GT line range. `dataset_root` is the
    directory passed to `--dataset` when zkhydra ran; the codebase
    field is stored relative to that.
    """
    location = (ground_truth or {}).get("location") or {}
    rel_path = location.get("Path")
    codebase = (ground_truth or {}).get("codebase")
    if not rel_path or not codebase or dataset_root is None:
        return None, ""

    codebase_abs = (dataset_root.parent.parent / codebase).resolve()
    if not codebase_abs.is_dir():
        return None, ""

    candidate = codebase_abs / rel_path
    if not candidate.is_file():
        return None, ""

    rng = _parse_line_range(location.get("Line"))
    if rng is None:
        return candidate, ""
    lo, hi = rng
    start = max(1, lo - SOURCE_CONTEXT_BEFORE)
    end = hi + SOURCE_CONTEXT_AFTER
    try:
        lines = candidate.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        logging.warning("cannot read source %s: %s", candidate, exc)
        return candidate, ""
    slice_ = lines[start - 1 : end]
    numbered = "\n".join(f"{i:>5}: {s}" for i, s in enumerate(slice_, start))
    return candidate, numbered


def _iter_undecided(run_dir: Path, tool_filter: str | None):
    for eval_path in sorted(run_dir.glob("*/*/evaluation.json")):
        bug_dir = eval_path.parent.parent
        tool_dir = eval_path.parent
        tool_name = tool_dir.name
        if tool_filter and tool_filter != tool_name:
            continue
        data = _read_json(eval_path)
        if not data or data.get("status") != "Undecided":
            continue
        yield bug_dir, tool_dir, data


def build_bundle(
    bug_dir: Path,
    tool_dir: Path,
    existing_eval: dict,
    dataset_root: Path | None,
) -> dict:
    tool_name = tool_dir.name
    bug_name = bug_dir.name
    gt = _read_json(bug_dir / "ground_truth.json") or {}
    source_path, source_snippet = _resolve_source(gt, dataset_root)
    return {
        "bug_name": bug_name,
        "tool": tool_name,
        "bug_dir": str(bug_dir.resolve()),
        "tool_dir": str(tool_dir.resolve()),
        "existing_evaluation": existing_eval,
        "ground_truth": gt,
        "results": _read_json(tool_dir / "results.json"),
        "parsed": _read_json(tool_dir / "parsed.json"),
        "raw_head": _head_text(tool_dir / "raw.txt"),
        "source_file": str(source_path) if source_path else None,
        "source_snippet": source_snippet,
    }


PROMPT_TEMPLATE = """Use the `triage-zkbugs-finding` skill to triage this case.

Return ONLY a JSON object matching the skill's output schema (no
prose, no code fences). Here is the full case bundle:

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
    # Best-effort: find first {...} block.
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
    bundle, claude_bin, timeout, tool_dir_str = args_tuple
    verdict = run_skill(bundle, claude_bin, timeout)
    triage_path = Path(tool_dir_str) / "triage.json"
    triage_path.write_text(
        json.dumps(verdict, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return {
        "bug_name": bundle["bug_name"],
        "tool": bundle["tool"],
        "triage": verdict,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("run_dir", type=Path, help="zkhydra zkbugs output dir")
    p.add_argument(
        "--dataset",
        type=Path,
        default=None,
        help="Original --dataset arg, for resolving codebase sources. "
        "If omitted, source_snippet in bundles will be empty.",
    )
    p.add_argument(
        "--tool",
        type=str,
        default=None,
        help="Only triage verdicts from this tool (e.g. circomspect).",
    )
    p.add_argument(
        "--auto",
        action="store_true",
        help="Invoke claude -p per case and write triage.json files.",
    )
    p.add_argument(
        "--jobs",
        "-j",
        type=int,
        default=1,
        help="Parallel claude invocations under --auto (default 1).",
    )
    p.add_argument(
        "--claude-bin",
        default=shutil.which("claude") or "claude",
        help="Path to the claude CLI (default: $(which claude)).",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="Timeout per claude -p invocation in seconds (default 180).",
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

    cases = []
    for bug_dir, tool_dir, existing_eval in _iter_undecided(run_dir, args.tool):
        cases.append((bug_dir, tool_dir, existing_eval))

    if not cases:
        logging.info("No Undecided verdicts under %s", run_dir)
        return 0

    logging.info("Found %d Undecided case(s)", len(cases))

    dataset_root = args.dataset.resolve() if args.dataset else None
    bundles = [
        build_bundle(bd, td, ev, dataset_root) for bd, td, ev in cases
    ]

    queue_path = run_dir / "triage_queue.json"
    queue_path.write_text(
        json.dumps(bundles, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    logging.info("Wrote %d bundle(s) to %s", len(bundles), queue_path)

    if not args.auto:
        logging.info("--dry-run (default); skipping skill invocation")
        return 0

    if not shutil.which(args.claude_bin) and not Path(args.claude_bin).is_file():
        logging.error(
            "claude CLI not found at %s — cannot use --auto", args.claude_bin
        )
        return 2

    work = [
        (b, args.claude_bin, args.timeout, b["tool_dir"]) for b in bundles
    ]
    verdicts = []
    if args.jobs == 1:
        for idx, wt in enumerate(work, 1):
            logging.info(
                "[%d/%d] %s / %s",
                idx,
                len(work),
                wt[0]["bug_name"],
                wt[0]["tool"],
            )
            verdicts.append(_process_case(wt))
    else:
        logging.info("Dispatching %d cases across %d workers", len(work), args.jobs)
        with _cf.ThreadPoolExecutor(max_workers=args.jobs) as ex:
            futures = {ex.submit(_process_case, wt): wt for wt in work}
            for idx, fut in enumerate(_cf.as_completed(futures), 1):
                wt = futures[fut]
                try:
                    verdicts.append(fut.result())
                    logging.info(
                        "[%d/%d] ✓ %s / %s",
                        idx,
                        len(work),
                        wt[0]["bug_name"],
                        wt[0]["tool"],
                    )
                except Exception as exc:  # noqa: BLE001
                    logging.error(
                        "[%d/%d] ✗ %s / %s: %s",
                        idx,
                        len(work),
                        wt[0]["bug_name"],
                        wt[0]["tool"],
                        exc,
                    )

    counts = {s: 0 for s in VALID_STATUSES}
    for v in verdicts:
        counts[v["triage"].get("status", "Undecided")] = (
            counts.get(v["triage"].get("status", "Undecided"), 0) + 1
        )

    summary = {
        "run_dir": str(run_dir),
        "total_undecided": len(cases),
        "auto": True,
        "counts": counts,
        "cases": verdicts,
    }
    summary_path = run_dir / "triage_summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    logging.info("Triage summary: %s — %s", counts, summary_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
