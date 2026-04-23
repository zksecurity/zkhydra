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
    """Shell out to print_bug_vars.sh and convert its JSON into an Input.

    Falls back to a direct config parse when the bug's zkbugs_vars.sh
    predates the CIRCOM_LINK_FLAGS contract (typically an older
    snapshot that's since been regenerated upstream).
    """
    if mode not in ("direct", "original"):
        raise ZkbugsLoaderError(f"invalid zkbugs mode: {mode!r}")

    cmd = [str(script_path), str(bug_dir), "--mode", mode]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=True, timeout=60
        )
    except subprocess.CalledProcessError as exc:
        msg = (exc.stderr or "").strip() or (exc.stdout or "").strip()
        if "CIRCOM_LINK_FLAGS not defined" in msg:
            logging.info(
                "zkbugs_vars.sh predates CIRCOM_LINK_FLAGS contract in %s; "
                "using config-based fallback",
                bug_dir,
            )
            return _load_bug_input_fallback(bug_dir, mode, script_path)
        raise ZkbugsLoaderError(
            f"print_bug_vars.sh failed for {bug_dir} (mode={mode}): {msg}"
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


def _dataset_root_from_script(script_path: Path) -> Path:
    """`<repo>/scripts/print_bug_vars.sh` → `<repo>`."""
    return script_path.resolve().parent.parent


def _load_bug_input_fallback(
    bug_dir: Path, mode: str, script_path: Path
) -> Input:
    """Build an Input from zkbugs_config.json when the runner contract is
    unavailable in zkbugs_vars.sh. Mirrors the semantics of print_bug_vars.sh
    for circom bugs: direct mode → bug_dir/circuit.circom + direct_input.json;
    original mode → <codebase>/<Original Entrypoint[0]> + input.json.
    link_flags come from `Codebase` + the dataset's dependency circomlib.
    """
    config = load_bug_config(bug_dir)
    repo_root = _dataset_root_from_script(script_path)

    codebase_rel = config.get("Codebase")
    if not codebase_rel:
        raise ZkbugsLoaderError(
            f"fallback: zkbugs_config.json for {bug_dir} has no 'Codebase'"
        )
    codebase_abs = (repo_root / codebase_rel).resolve()
    circomlib_abs = (
        repo_root / "dataset" / "circom" / "dependencies" / "circomlib"
    ).resolve()

    bug_dir_abs = bug_dir.resolve()
    if mode == "direct":
        entry = config.get("Direct Entrypoint") or "circuit.circom"
        circuit_abs = (bug_dir_abs / entry).resolve()
        input_name = (
            config.get("Input", {}).get("Direct") or "direct_input.json"
        )
    else:
        original_list = config.get("Original Entrypoint") or []
        if not original_list:
            circuit_abs = (
                bug_dir_abs
                / (config.get("Direct Entrypoint") or "circuit.circom")
            ).resolve()
        else:
            circuit_abs = (codebase_abs / original_list[0]).resolve()
        input_name = config.get("Input", {}).get("Original") or "input.json"

    input_json_abs = str((bug_dir_abs / input_name).resolve())

    link_flags = ["-l", str(codebase_abs), "-l", str(circomlib_abs)]
    target = circuit_abs.stem
    ptau_abs = str(repo_root / "misc" / "circom" / "bn128_pot12_0001.ptau")

    return Input(
        circuit_dir=str(circuit_abs.parent),
        circuit_file=str(circuit_abs),
        link_flags=link_flags,
        input_json=input_json_abs,
        ptau=ptau_abs,
        codebase=str(codebase_abs),
        codebase_exists=codebase_abs.is_dir(),
        mode=mode,
        target=target,
        bug_dir=str(bug_dir_abs),
    )


def log_loader_warning(bug_dir: Path, exc: Exception) -> None:
    logging.warning("zkbugs loader: %s (%s)", bug_dir, exc)
