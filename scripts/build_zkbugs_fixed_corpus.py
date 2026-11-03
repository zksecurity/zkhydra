#!/usr/bin/env python3
"""Build a FIXED-commit FP corpus from the zkbugs dataset.

For every zkbugs bug that has a non-empty ``Fix Commit``, an ``Original
Entrypoint`` and a locally-available codebase, this creates one clean unit: the
project checked out at the fix commit (via ``git worktree``), with an
``fp_config.json`` pointing at the original entrypoint on the patched code. Any
finding a tool raises on that patched circuit is a candidate false positive, and
the report pairs it against the RQ2 result on the buggy commit (``SourceBug``).

Layout produced (so ``--dataset <out>/dataset/circom`` feeds ``zkhydra fp``):

    <out>/dataset/circom/fixed/<org>/<project>/<bug>/
        ├── _src/                 # git worktree at Fix Commit (--build only)
        ├── input.json            # copied from the bug's Input
        └── fp_config.json        # Origin=fixed-commit, SourceBug=<bug>

Default is a DRY RUN that writes ``<out>/fixed_corpus_plan.json`` describing the
eligible units without touching git. Pass ``--build`` to create the worktrees
and configs (requires the zkbugs codebases populated, i.e. run on the machine
where ``scripts/download_sources.sh`` has been run — typically Ubuntu).

Examples:
    python3 scripts/build_zkbugs_fixed_corpus.py --dataset ../zkbugs/dataset/circom --out output/fp-corpus
    python3 scripts/build_zkbugs_fixed_corpus.py --dataset ../zkbugs/dataset/circom --out output/fp-corpus --build
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path

SKIP_PATH_PARTS = {"codebases", "dependencies"}


def _read_bug(config_path: Path) -> dict | None:
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not data:
        return None
    return data[next(iter(data))]


def _zkbugs_root(dataset_dir: Path) -> Path:
    """<repo>/dataset/circom -> <repo> (codebase paths are relative to it)."""
    cur = dataset_dir.resolve()
    for anc in [cur, *cur.parents]:
        if anc.name == "dataset":
            return anc.parent
    return cur.parent


def discover_eligible(dataset_dir: Path) -> list[dict]:
    """Bugs with a Fix Commit + Original Entrypoint + Codebase present."""
    root = _zkbugs_root(dataset_dir)
    out: list[dict] = []
    for cfg in sorted(dataset_dir.rglob("zkbugs_config.json")):
        if set(cfg.parts) & SKIP_PATH_PARTS:
            continue
        bug = _read_bug(cfg)
        if not bug:
            continue
        fix = (bug.get("Fix Commit") or "").strip()
        entry = bug.get("Original Entrypoint") or []
        codebase_rel = bug.get("Codebase")
        reason = None
        if not fix:
            reason = "no Fix Commit"
        elif not entry:
            reason = "no Original Entrypoint"
        elif not codebase_rel:
            reason = "no Codebase"
        codebase_abs = (root / codebase_rel).resolve() if codebase_rel else None
        if reason is None and (
            codebase_abs is None or not codebase_abs.is_dir()
        ):
            reason = "codebase not available locally"
        out.append(
            {
                "bug_dir": cfg.parent,
                "bug_name": cfg.parent.name,
                "rel": str(cfg.parent.resolve().relative_to(dataset_dir.resolve())),
                "fix_commit": fix,
                "entrypoint": entry[0] if entry else None,
                "codebase_rel": codebase_rel,
                "codebase_abs": str(codebase_abs) if codebase_abs else None,
                "input_direct": (bug.get("Input") or {}).get("Direct"),
                "input_original": (bug.get("Input") or {}).get("Original"),
                "project": bug.get("Project"),
                "skip_reason": reason,
            }
        )
    return out


def build_unit(cand: dict, out_root: Path) -> dict:
    """Create the worktree + input.json + fp_config.json for one unit."""
    unit_dir = out_root / "dataset" / "circom" / "fixed" / cand["rel"]
    unit_dir.mkdir(parents=True, exist_ok=True)
    src = unit_dir / "_src"

    # git worktree at the fix commit (codebase dir is the git repo).
    codebase = Path(cand["codebase_abs"])
    if not src.exists():
        subprocess.run(
            ["git", "-C", str(codebase), "fetch", "--all", "--quiet"],
            capture_output=True,
            timeout=600,
        )
        res = subprocess.run(
            [
                "git",
                "-C",
                str(codebase),
                "worktree",
                "add",
                "--detach",
                str(src.resolve()),
                cand["fix_commit"],
            ],
            capture_output=True,
            text=True,
            timeout=600,
        )
        if res.returncode != 0:
            return {"unit": cand["bug_name"], "error": res.stderr.strip()}

    # copy the bug's original input next to the config.
    input_name = cand["input_original"] or cand["input_direct"] or "input.json"
    bug_input = cand["bug_dir"] / input_name
    if bug_input.is_file():
        shutil.copy2(bug_input, unit_dir / "input.json")

    # fp_config.json — entrypoint/codebase both live under the unit's _src.
    codebase_rel = os.path.relpath(src.resolve(), out_root.resolve())
    entry_rel = f"_src/{cand['entrypoint']}"
    config = {
        f"{cand['bug_name']} (fixed)": {
            "Project": cand["project"],
            "Commit": cand["fix_commit"],
            "DSL": "Circom",
            "Clean": True,
            "Origin": "fixed-commit",
            "SourceBug": cand["bug_name"],
            "Source": {
                "FixedCommitOf": cand["bug_name"],
                "FixCommit": cand["fix_commit"],
            },
            "Codebase": codebase_rel,
            "Entrypoint": entry_rel,
            "Input": "input.json",
            "Compiled": True,
        }
    }
    (unit_dir / "fp_config.json").write_text(
        json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return {"unit": cand["bug_name"], "unit_dir": str(unit_dir)}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dataset", type=Path, required=True, help="zkbugs/dataset/circom")
    p.add_argument("--out", type=Path, required=True, help="FP corpus output root")
    p.add_argument(
        "--build",
        action="store_true",
        help="Actually create git worktrees + configs (needs codebases).",
    )
    p.add_argument(
        "--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING"]
    )
    args = p.parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    dataset = args.dataset.resolve()
    if not dataset.is_dir():
        logging.error("dataset not found: %s", dataset)
        return 1

    cands = discover_eligible(dataset)
    eligible = [c for c in cands if c["skip_reason"] is None]
    skipped = [c for c in cands if c["skip_reason"] is not None]
    logging.info(
        "Scanned %d bugs: %d eligible, %d skipped",
        len(cands),
        len(eligible),
        len(skipped),
    )
    for c in skipped:
        logging.debug("  skip %s: %s", c["bug_name"], c["skip_reason"])

    args.out.mkdir(parents=True, exist_ok=True)

    if not args.build:
        plan = {
            "dataset": str(dataset),
            "eligible": [
                {k: v for k, v in c.items() if k != "bug_dir"}
                for c in eligible
            ],
            "skipped": [
                {"bug_name": c["bug_name"], "reason": c["skip_reason"]}
                for c in skipped
            ],
        }
        plan_path = args.out / "fixed_corpus_plan.json"
        plan_path.write_text(
            json.dumps(plan, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        logging.info(
            "DRY RUN — wrote plan for %d eligible unit(s) to %s "
            "(pass --build to create them)",
            len(eligible),
            plan_path,
        )
        return 0

    built, errors = [], []
    for c in eligible:
        res = build_unit(c, args.out)
        (errors if res.get("error") else built).append(res)
        if res.get("error"):
            logging.error("  ✗ %s: %s", res["unit"], res["error"])
        else:
            logging.info("  ✓ %s", res["unit"])

    logging.info(
        "Built %d unit(s), %d error(s) under %s/dataset/circom/fixed",
        len(built),
        len(errors),
        args.out,
    )
    return 0 if not errors else 2


if __name__ == "__main__":
    sys.exit(main())
