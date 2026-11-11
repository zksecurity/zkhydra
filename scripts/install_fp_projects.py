#!/usr/bin/env python3
"""Install the FP-experiment corpus from fp_experiment/projects.json.

For every project in the manifest:
1. clone it and check out the pinned post-audit commit into
   ``<out>/dataset/codebases/audited/<name>``;
2. replay its dependency steps (npm installs, circomlib symlinks, patches from
   ``fp_experiment/patches``);
3. write one zkhydra ``fp`` unit per entrypoint under
   ``<out>/dataset/circom/audited/<name>/<name>__<entry>/``;
4. compile every unit with circom and record ``Compiled`` (failed units are
   skipped by ``zkhydra fp``).

A shared circomlib (pinned in the manifest) is installed at
``<out>/dataset/circom/dependencies/circomlib``; manifest link paths refer to it
as ``@circomlib``. Outcomes are summarised in ``<out>/corpus.json``.

Run it inside the zkhydra Docker image so the circom version matches the tool
run. Installed projects are reused unless ``--force``.

Examples:
    scripts/fp_docker.sh python3 scripts/install_fp_projects.py
    scripts/fp_docker.sh python3 scripts/install_fp_projects.py --projects circomlib,semaphore
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "fp_experiment" / "projects.json"
PATCHES = REPO_ROOT / "fp_experiment" / "patches"
MARKER = ".zkhydra_install.json"
COMPILE_TIMEOUT = 900
# npm git dependencies default to SSH; force HTTPS for this process only.
GIT_HTTPS_ENV = {
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_CONFIG_COUNT": "2",
    "GIT_CONFIG_KEY_0": "url.https://github.com/.insteadOf",
    "GIT_CONFIG_VALUE_0": "ssh://git@github.com/",
    "GIT_CONFIG_KEY_1": "url.https://github.com/.insteadOf",
    "GIT_CONFIG_VALUE_1": "git@github.com:",
}
CONSTRAINTS_RE = re.compile(r"(non-linear|linear) constraints:\s*(\d+)")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


class InstallError(Exception):
    pass


def _run(cmd, cwd: Path | None = None, timeout: int = 3600, shell: bool = False):
    res = subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, shell=shell,
        env={**os.environ, **GIT_HTTPS_ENV},
    )
    if res.returncode != 0:
        shown = cmd if isinstance(cmd, str) else " ".join(cmd)
        tail = (res.stderr or res.stdout).strip().splitlines()[-15:]
        raise InstallError(f"`{shown}` failed (rc={res.returncode}):\n" + "\n".join(tail))


def _rel(target: Path, start: Path) -> str:
    return os.path.relpath(target.resolve(), start.resolve())


def _resolve(path: str, codebase: Path, circomlib: Path) -> Path:
    if path == "@circomlib" or path.startswith("@circomlib/"):
        return circomlib / path[len("@circomlib"):].lstrip("/")
    return codebase / path


def clone_at(repo: str, commit: str, dest: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    _run(["git", "clone", "--quiet", "--filter=blob:none", "--no-checkout", repo, str(dest)])
    if subprocess.run(["git", "-C", str(dest), "cat-file", "-e", f"{commit}^{{commit}}"],
                      capture_output=True).returncode != 0:
        _run(["git", "-C", str(dest), "fetch", "--quiet", "--filter=blob:none", "origin", commit])
    _run(["git", "-C", str(dest), "-c", "advice.detachedHead=false", "checkout", "--quiet", "--detach", commit])


def apply_deps(project: dict, codebase: Path, circomlib: Path) -> None:
    for step in project["deps"]:
        kind = step["kind"]
        if kind in ("npm", "shell"):
            _run(step["cmd"], cwd=codebase / step.get("cwd", "."), shell=True)
        elif kind == "symlink":
            link = codebase / step["path"]
            target = _resolve(step["target"], codebase, circomlib)
            if link.is_symlink():
                link.unlink()
            if not link.exists():
                link.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(os.path.relpath(target.resolve(), link.parent.resolve()), link)
        elif kind == "patch":
            _run(["git", "-C", str(codebase), "apply", "--whitespace=nowarn", str(PATCHES / step["file"])])
        else:
            raise InstallError(f"unknown deps step kind: {kind!r}")


def install_project(project: dict, out: Path, circomlib: Path, force: bool) -> Path:
    codebase = out / "dataset" / "codebases" / "audited" / project["name"]
    marker = codebase / MARKER
    if not force and marker.is_file() and json.loads(marker.read_text()).get("commit") == project["commit"]:
        return codebase
    clone_at(project["repo"], project["commit"], codebase)
    apply_deps(project, codebase, circomlib)
    marker.write_text(json.dumps({"commit": project["commit"]}))
    return codebase


def compile_unit(entry: Path, link_paths: list[Path]) -> dict:
    flags = [arg for lp in link_paths for arg in ("-l", str(lp))]
    with tempfile.TemporaryDirectory(prefix="fp-check-") as tmp:
        try:
            res = subprocess.run(["circom", str(entry), "--r1cs", "--O0", "-o", tmp, *flags],
                                 capture_output=True, text=True, timeout=COMPILE_TIMEOUT)
            ok, text = res.returncode == 0, ANSI_RE.sub("", res.stdout + res.stderr)
        except subprocess.TimeoutExpired:
            ok, text = False, f"compile timed out after {COMPILE_TIMEOUT}s"
    if ok:
        counts = {k: int(v) for k, v in CONSTRAINTS_RE.findall(text)}
        return {"Compiled": True, "Constraints": sum(counts.values())}
    errs = [ln for ln in text.splitlines() if "error" in ln.lower()] or text.splitlines()
    return {"Compiled": False, "CompileError": "\n".join(errs[:8]) or "circom failed with no output"}


def write_units(project: dict, out: Path, codebase: Path, circomlib: Path) -> list[dict]:
    proj_dir = out / "dataset" / "circom" / "audited" / project["name"]
    if proj_dir.exists():
        shutil.rmtree(proj_dir)
    link_abs = [_resolve(lp, codebase, circomlib) for lp in project["link_paths"] or [""]]
    rows = []
    for ep in project["entrypoints"]:
        unit = f"{project['name']}__{ep['name']}"
        unit_dir = proj_dir / unit
        unit_dir.mkdir(parents=True)
        if ep.get("wrapper"):
            (unit_dir / "circuit.circom").write_text(ep["wrapper"], encoding="utf-8")
            entry = unit_dir / "circuit.circom"
        else:
            entry = codebase / ep["path"]
        (unit_dir / "input.json").write_text("{}\n")
        result = compile_unit(entry, link_abs) if entry.is_file() else {
            "Compiled": False, "CompileError": f"entrypoint missing: {ep.get('path')}"}
        config = {
            "Project": project["repo"],
            "ProjectName": project["name"],
            "Commit": project["commit"],
            "DSL": "Circom",
            "Origin": "audited",
            "Source": {"Audits": project["audits"], "BattleTested": project["battle_tested"],
                       "CommitNote": project["commit_note"]},
            "KnownUnfixed": project["known_unfixed"],
            "Codebase": _rel(codebase, out),
            "LinkPaths": [_rel(p, out) for p in link_abs],
            "Entrypoint": _rel(entry, unit_dir),
            "Input": "input.json",
            **result,
        }
        (unit_dir / "fp_config.json").write_text(
            json.dumps({unit: config}, indent=2, ensure_ascii=False), encoding="utf-8")
        logging.info("    %s %s %s", "✓" if result["Compiled"] else "✗", unit,
                     f"{result['Constraints']:,} constraints" if result["Compiled"]
                     else result["CompileError"].splitlines()[0][:120])
        rows.append({"unit": unit, **result})
    return rows


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", type=Path, default=Path("output/fp-corpus"), help="corpus root")
    p.add_argument("--projects", default=None, help="comma-separated subset (default: all)")
    p.add_argument("--force", action="store_true", help="re-clone even if already installed")
    args = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")

    if shutil.which("circom") is None:
        logging.error("circom not on PATH — run via scripts/fp_docker.sh (see fp_experiment/README.md)")
        return 1
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    projects = manifest["projects"]
    out = args.out.resolve()
    if args.projects:
        wanted = {s.strip() for s in args.projects.split(",") if s.strip()}
        projects = [pr for pr in projects if pr["name"] in wanted]
    else:
        shutil.rmtree(out / "dataset" / "circom" / "audited", ignore_errors=True)

    lib = manifest["circomlib"]
    circomlib = out / "dataset" / "circom" / "dependencies" / "circomlib"
    marker = circomlib / MARKER
    if args.force or not marker.is_file() or json.loads(marker.read_text()).get("commit") != lib["commit"]:
        clone_at(lib["repo"], lib["commit"], circomlib)
        marker.write_text(json.dumps({"commit": lib["commit"]}))

    summary, failed = [], False
    for pr in projects:
        logging.info("== %s @ %s", pr["name"], pr["commit"][:10])
        try:
            codebase = install_project(pr, out, circomlib, args.force)
            summary.append({"project": pr["name"], "units": write_units(pr, out, codebase, circomlib)})
        except (InstallError, subprocess.TimeoutExpired) as exc:
            failed = True
            logging.error("  ✗ %s: %s", pr["name"], exc)
            summary.append({"project": pr["name"], "error": str(exc)})

    (out / "corpus.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    units = [u for s in summary for u in s.get("units", [])]
    logging.info("done: %d project(s), %d/%d unit(s) compiled — %s", len(summary),
                 sum(u["Compiled"] for u in units), len(units), out / "corpus.json")
    return 2 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
