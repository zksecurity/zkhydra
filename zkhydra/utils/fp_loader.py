"""Load a false-positive (FP) corpus unit into an Input.

The FP corpus mirrors the zkbugs new-format layout (a wrapper circuit that
``include``s a separate codebase, resolved with ``-l`` link flags) but every
unit is a CLEAN or FIXED circuit described by an ``fp_config.json`` instead of a
``zkbugs_config.json``. Unlike the zkbugs loader this builds the Input directly
in Python with no ``print_bug_vars.sh`` runner contract, so corpus builders only
have to emit a small JSON manifest + a wrapper circuit.

An ``fp_config.json`` has a single top-level key (the unit's human name) mapping
to a dict with:
    - ``Entrypoint``  wrapper circuit, relative to the unit dir (default
      ``circuit.circom``)
    - ``Input``       input json, relative to the unit dir (default
      ``input.json``)
    - ``Codebase``    project source dir, relative to the corpus root
    - ``Ptau``        ptau file, relative to the corpus root
    - ``Compiled``    bool; false units are skipped by discovery
    - ``Source`` / ``Origin`` / ``Project`` / ``Commit``  free-form provenance
      (audit link, or ``"fixed-commit of <bug>"``) carried into reports.
"""

import json
from pathlib import Path
from typing import Any

from zkhydra.tools.base import Input


class FpLoaderError(Exception):
    """Raised when the FP loader cannot populate an Input."""


def load_fp_config(unit_dir: Path) -> dict[str, Any]:
    """Return the single-unit value from fp_config.json."""
    config_path = unit_dir / "fp_config.json"
    with open(config_path, encoding="utf-8") as f:
        config = json.load(f)
    if not config:
        raise FpLoaderError(f"Empty fp_config.json: {config_path}")
    key = next(iter(config))
    return config[key]


def fp_corpus_root(dataset_dir: Path) -> Path:
    """Map ``<root>/dataset/circom`` -> ``<root>``.

    Codebase/ptau paths in fp_config.json are relative to this root, matching
    the zkbugs convention where ``--dataset`` points at ``<repo>/dataset/circom``
    and shared assets live under ``<repo>/``.
    """
    cur = dataset_dir.resolve()
    for anc in [cur, *cur.parents]:
        if anc.name == "dataset":
            return anc.parent
    return cur.parent


def load_fp_input(unit_dir: Path, dataset_dir: Path) -> Input:
    """Build an Input for a clean/fixed unit from its fp_config.json."""
    config = load_fp_config(unit_dir)
    root = fp_corpus_root(dataset_dir)
    unit_dir_abs = unit_dir.resolve()

    entry = config.get("Entrypoint") or "circuit.circom"
    circuit_abs = (unit_dir_abs / entry).resolve()

    input_name = config.get("Input") or "input.json"
    input_json_abs = str((unit_dir_abs / input_name).resolve())

    link_flags: list[str] = []
    codebase_abs_str: str | None = None
    codebase_exists = True
    codebase_rel = config.get("Codebase")
    if codebase_rel:
        codebase_abs = (root / codebase_rel).resolve()
        codebase_abs_str = str(codebase_abs)
        codebase_exists = codebase_abs.is_dir()
        link_flags += ["-l", str(codebase_abs)]

    # Optional shared circomlib dependency, mirroring the zkbugs dataset layout.
    circomlib_abs = (
        root / "dataset" / "circom" / "dependencies" / "circomlib"
    ).resolve()
    if circomlib_abs.is_dir():
        link_flags += ["-l", str(circomlib_abs)]

    ptau_rel = config.get("Ptau")
    ptau_abs = str((root / ptau_rel).resolve()) if ptau_rel else None

    return Input(
        circuit_dir=str(circuit_abs.parent),
        circuit_file=str(circuit_abs),
        link_flags=link_flags,
        input_json=input_json_abs,
        ptau=ptau_abs,
        codebase=codebase_abs_str,
        codebase_exists=codebase_exists,
        mode="fp",
        target=circuit_abs.stem,
        bug_dir=str(unit_dir_abs),
    )
