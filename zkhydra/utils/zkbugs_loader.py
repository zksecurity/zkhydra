"""Load a zkbugs bug description into an Input via print_bug_vars.sh.

print_bug_vars.sh lives in the zkbugs repo (branch: circom-link-flags-contract
and onward). It sources each bug's zkbugs_vars.sh under the chosen ZKBUGS_MODE
and emits absolute paths plus a flat link_flags list. Using the script as the
single source of truth avoids re-implementing the mode/path logic in Python.
"""

import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Any

from zkhydra.tools.base import Input


class ZkbugsLoaderError(Exception):
    """Raised when the zkbugs loader cannot populate an Input."""


def find_print_bug_vars(dataset_dir: Path) -> Path:
    """Locate scripts/print_bug_vars.sh by walking up from dataset_dir.

    The expected layout is <repo>/scripts/print_bug_vars.sh with
    <repo>/dataset/... underneath.
    """
    current = dataset_dir.resolve()
    for candidate in [current, *current.parents]:
        script = candidate / "scripts" / "print_bug_vars.sh"
        if script.is_file():
            return script
    raise ZkbugsLoaderError(
        f"print_bug_vars.sh not found when walking up from {dataset_dir}. "
        "Expected <zkbugs_repo>/scripts/print_bug_vars.sh. Point --dataset "
        "at a zkbugs checkout that includes the runner contract (branch "
        "circom-link-flags-contract or later)."
    )


def load_bug_config(bug_dir: Path) -> dict[str, Any]:
    """Return the single-bug value from zkbugs_config.json."""
    config_path = bug_dir / "zkbugs_config.json"
    with open(config_path, encoding="utf-8") as f:
        config = json.load(f)
    if not config:
        raise ZkbugsLoaderError(f"Empty zkbugs_config.json: {config_path}")
    bug_key = next(iter(config))
    return config[bug_key]


def load_bug_input(bug_dir: Path, mode: str, script_path: Path) -> Input:
    """Shell out to print_bug_vars.sh and convert its JSON into an Input."""
    if mode not in ("direct", "original"):
        raise ZkbugsLoaderError(f"invalid zkbugs mode: {mode!r}")

    cmd = [str(script_path), str(bug_dir), "--mode", mode]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=True, timeout=60
        )
    except subprocess.CalledProcessError as exc:
        raise ZkbugsLoaderError(
            f"print_bug_vars.sh failed for {bug_dir} (mode={mode}): "
            f"{exc.stderr.strip() or exc.stdout.strip()}"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise ZkbugsLoaderError(
            f"print_bug_vars.sh timed out for {bug_dir} (mode={mode})"
        ) from exc

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ZkbugsLoaderError(
            f"print_bug_vars.sh produced non-JSON output for {bug_dir}: "
            f"{exc}"
        ) from exc

    circuit = data.get("circuit")
    if not circuit:
        raise ZkbugsLoaderError(
            f"print_bug_vars.sh JSON missing 'circuit' for {bug_dir}"
        )

    return Input(
        circuit_dir=os.path.dirname(circuit),
        circuit_file=circuit,
        link_flags=list(data.get("link_flags", [])),
        input_json=data.get("input"),
        ptau=data.get("ptau"),
        codebase=data.get("codebase"),
        codebase_exists=bool(data.get("codebase_exists", True)),
        mode=data.get("mode", mode),
        target=data.get("target"),
        bug_dir=str(bug_dir.resolve()),
    )


def log_loader_warning(bug_dir: Path, exc: Exception) -> None:
    logging.warning("zkbugs loader: %s (%s)", bug_dir, exc)
