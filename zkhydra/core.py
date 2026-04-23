#!/usr/bin/env python3
"""
zkHydra - Core execution logic for circuit analysis.

This module contains all the core logic for analyzing circuits with security tools,
including tool execution, result collection, and summary generation.
"""

import argparse
import json
import logging
import multiprocessing as mp
import os
import random
import re
import shlex
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path

from zkhydra.printers import print_analyze_summary
from zkhydra.tools.base import (
    AbstractTool,
    Input,
    ToolOutput,
    ToolResult,
    ToolStatus,
    ensure_dir,
)
from zkhydra.utils.logger import setup_logging
from zkhydra.utils.tools_resolver import ToolsDict, resolve_tools
from zkhydra.utils.zkbugs_loader import (
    ZkbugsLoaderError,
    find_print_bug_vars,
    load_bug_config,
    load_bug_input,
)

# Tools that consume R1CS (the shared pre-compile feeds these).
ARTIFACT_TOOLS = frozenset({"ecneproject", "picus"})

BASE_DIR = Path.cwd()


@dataclass
class Statistics:
    """Statistics for tool execution results."""

    total_tools: int
    success: int
    failed: int
    timeout: int

    def to_dict(self) -> dict:
        """Convert Statistics to dictionary for JSON serialization."""
        return {
            "total_tools": self.total_tools,
            "success": self.success,
            "failed": self.failed,
            "timeout": self.timeout,
        }


@dataclass
class Summary:
    """Summary of analyze mode execution."""

    mode: str
    input: str
    dsl: str
    timestamp: str
    output_directory: str
    tools: dict[str, dict]
    statistics: Statistics
    total_findings: int
    total_execution_time: float

    def to_dict(self) -> dict:
        """Convert Summary to dictionary for JSON serialization."""
        return {
            "mode": self.mode,
            "input": self.input,
            "dsl": self.dsl,
            "timestamp": self.timestamp,
            "output_directory": self.output_directory,
            "tools": self.tools,
            "statistics": self.statistics.to_dict(),
            "total_findings": self.total_findings,
            "total_execution_time": self.total_execution_time,
        }


# Available tools per DSL
AVAILABLE_TOOLS = {
    "circom": ["circomspect", "circom_civer", "picus", "ecneproject", "zkfuzz"],
    "pil": ["pilspector"],
    "cairo": ["sierra-analyzer"],
}


def setup_output_directory(base_output: Path, mode: str) -> tuple[Path, str]:
    """
    Create timestamped output directory.

    Args:
        base_output: Base output directory
        mode: Mode name (analyze or evaluate)

    Returns:
        Tuple of (output_directory_path, timestamp)
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(base_output) / f"{mode}_{timestamp}"
    ensure_dir(output_dir)
    return output_dir, timestamp


def prepare_circuit_paths(input_path: Path) -> Input:
    """
    Create Input object with circuit directory and file paths for tool execution.

    Args:
        input_path: Input path (file)

    Returns:
        Input object containing absolute circuit_dir and circuit_file paths as strings
    """
    circuit_dir = input_path.parent
    circuit_file = input_path
    full_path_circuit_dir = circuit_dir.resolve()
    full_path_circuit_file = circuit_file.resolve()
    return Input(
        circuit_dir=str(full_path_circuit_dir),
        circuit_file=str(full_path_circuit_file),
    )


def execute_tools(
    tool_registry: ToolsDict,
    input_paths: Input,
    output_dir: Path,
    timeout: int,
) -> dict[str, ToolResult]:
    """
    Execute all tools and collect results.

    Args:
        tool_registry: Loaded tool modules
        input_paths: Input object containing circuit_dir and circuit_file paths
        output_dir: Output directory for results
        timeout: Timeout per tool in seconds

    Returns:
        Dictionary mapping tool names to ToolResult objects
    """
    results = {}

    for tool_name, tool_instance in tool_registry.items():
        logging.info(f"Running {tool_name}...")

        # Create output directory for this tool
        tool_output_dir = output_dir / tool_name
        ensure_dir(tool_output_dir)
        raw_output_file = Path(tool_output_dir) / "raw.txt"

        # Execute tool - returns ToolOutput object
        tool_output = tool_instance.execute(
            input_paths, timeout, raw_output_file
        )

        results[tool_name] = tool_instance.process_output(tool_output)

    return results


def analyze_mode(
    circuit: Path, tools: list[str], dsl: str, timeout: int, output: Path
) -> None:
    """
    Analyze mode: Run tools on a circuit and report findings.
    """
    logging.info("Running in ANALYZE mode")
    logging.info(f"Circuit: {circuit}")
    logging.info(f"Tools: {tools}")
    logging.info(f"Loading tools: {tools}")

    # Resolve tool modules
    tool_registry = resolve_tools(tools)
    if not tool_registry:
        logging.error("No tools loaded successfully")
        sys.exit(1)

    # Setup output directory
    output_dir, timestamp = setup_output_directory(output, "analyze")
    logging.info(f"Output directory: {output_dir}")

    # Determine circuit paths
    input_paths = prepare_circuit_paths(circuit)
    logging.info(f"Circuit directory: {input_paths.circuit_dir}")
    logging.info(f"Circuit file: {input_paths.circuit_file}")

    # Execute all tools
    results = execute_tools(
        tool_registry,
        input_paths,
        output_dir,
        timeout,
    )

    # Generate statistics
    statistics = Statistics(
        total_tools=len(results),
        success=sum(
            1 for r in results.values() if r.status == ToolStatus.SUCCESS
        ),
        failed=sum(
            1 for r in results.values() if r.status == ToolStatus.FAILED
        ),
        timeout=sum(
            1 for r in results.values() if r.status == ToolStatus.TIMEOUT
        ),
    )

    # Generate summary
    summary = Summary(
        mode="analyze",
        input=str(circuit),
        dsl=dsl,
        timestamp=timestamp,
        output_directory=str(output_dir),
        tools={name: result.to_dict() for name, result in results.items()},
        statistics=statistics,
        total_findings=sum(
            r.findings_count
            for r in results.values()
            if r.status == ToolStatus.SUCCESS
        ),
        total_execution_time=sum(r.execution_time for r in results.values()),
    )

    # Write summary JSON
    summary_file = Path(output_dir) / "summary.json"
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(summary.to_dict(), f, indent=2, ensure_ascii=False)

    # Print CLI summary
    print_analyze_summary(summary.to_dict())


def evaluate_mode(args: argparse.Namespace) -> None:
    """
    Evaluate mode: Not implemented.

    Raises:
        NotImplementedError: Evaluate mode is not yet implemented.
    """
    raise NotImplementedError(
        "Evaluate mode is not yet implemented. Use 'analyze' mode instead."
    )


SKIP_PATH_PARTS = {"codebases", "dependencies"}

# Matches: include "path"; or include 'path'; (ignoring // line comments).
_INCLUDE_RE = re.compile(r'^\s*include\s+["\']([^"\']+)["\']\s*;', re.MULTILINE)


def _is_excluded_config(config_path: Path) -> bool:
    """Skip configs that are not actual bugs (shared codebases, deps)."""
    parts = set(config_path.parts)
    return bool(parts & SKIP_PATH_PARTS)


def _wrapper_needs_codebase(circuit_file: str | None, bug_dir: Path) -> bool:
    """True if the wrapper has an include that can't be resolved locally.

    An include path is considered locally-resolvable when it's either an
    absolute path that exists, or relative to the bug dir and the target
    file exists there. Everything else (e.g. ``include "circuits/foo.circom"``)
    requires the project codebase, so the bug should be skipped when that
    codebase is missing.
    """
    if not circuit_file:
        return False
    try:
        src = Path(circuit_file).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    for inc in _INCLUDE_RE.findall(src):
        candidate = Path(inc)
        if candidate.is_absolute():
            if candidate.is_file():
                continue
            return True
        if (bug_dir / candidate).is_file():
            continue
        return True
    return False


def load_bug_selectors(
    selectors: str | None, selectors_file: Path | None
) -> list[str]:
    """Collect bug selectors from --bugs (comma-separated) and --bugs-file."""
    result: list[str] = []
    if selectors:
        result.extend(s.strip() for s in selectors.split(",") if s.strip())
    if selectors_file is not None:
        for raw in selectors_file.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line and not line.startswith("#"):
                result.append(line)
    return result


def _bug_matches_selectors(
    bug_dir: Path, dataset_dir: Path, selectors: list[str]
) -> bool:
    """True if any selector is a substring of the bug name or relative path."""
    if not selectors:
        return True
    name = bug_dir.name
    try:
        rel = str(bug_dir.resolve().relative_to(dataset_dir.resolve()))
    except ValueError:
        rel = str(bug_dir)
    return any(sel in name or sel in rel for sel in selectors)


def discover_zkbugs(
    dataset_dir: Path,
    mode: str,
    script_path: Path,
    selectors: list[str] | None = None,
) -> list[dict]:
    """Discover bugs by walking zkbugs_config.json files and loading an Input.

    Each bug entry carries:
        - config_path: Path to zkbugs_config.json
        - bug_dir: Path to the bug directory
        - bug_name: Name of the bug
        - config: parsed single-bug section of zkbugs_config.json
        - input: populated Input (None if loading failed or bug is skipped)
        - skip_reason: str | None, set when the bug must be skipped

    If `selectors` is non-empty, bugs whose directory name and
    dataset-relative path both lack every selector substring are dropped
    entirely (not listed in summary; they are not real candidates).
    """
    selectors = selectors or []
    bugs: list[dict] = []
    config_files = [
        p
        for p in dataset_dir.rglob("zkbugs_config.json")
        if not _is_excluded_config(p)
        and _bug_matches_selectors(p.parent, dataset_dir, selectors)
    ]

    if selectors:
        logging.info(
            "Selectors %s matched %d bug(s)", selectors, len(config_files)
        )
    logging.info("Found %d zkbugs_config.json files", len(config_files))

    compile_flag = (
        "Compiled Direct" if mode == "direct" else "Compiled Original"
    )

    for config_path in config_files:
        bug_dir = config_path.parent
        bug_name = bug_dir.name
        entry: dict = {
            "config_path": config_path,
            "bug_dir": bug_dir,
            "bug_name": bug_name,
            "config": None,
            "input": None,
            "skip_reason": None,
        }

        try:
            config = load_bug_config(bug_dir)
        except (OSError, ZkbugsLoaderError) as exc:
            entry["skip_reason"] = f"failed to read zkbugs_config.json: {exc}"
            bugs.append(entry)
            continue
        entry["config"] = config

        # Skip only on compile flags, never on Executed=false.
        if config.get(compile_flag) is False:
            entry["skip_reason"] = f"{compile_flag}=false"
            bugs.append(entry)
            continue

        try:
            inp = load_bug_input(bug_dir, mode, script_path)
        except ZkbugsLoaderError as exc:
            entry["skip_reason"] = f"loader error: {exc}"
            bugs.append(entry)
            continue

        if (
            inp.codebase
            and not inp.codebase_exists
            and any(flag == inp.codebase for flag in inp.link_flags)
            and _wrapper_needs_codebase(inp.circuit_file, bug_dir)
        ):
            entry["skip_reason"] = (
                "codebase not available locally and wrapper needs it "
                "(run scripts/download_sources.sh, or source is private)"
            )
            bugs.append(entry)
            continue

        entry["input"] = inp
        bugs.append(entry)

    return bugs


def generate_ground_truth(
    config_path: Path, output_path: Path, mode: str
) -> None:
    """Write ground_truth.json from zkbugs_config.json + active mode."""
    with open(config_path, encoding="utf-8") as f:
        config = json.load(f)

    bug_key = list(config.keys())[0]
    bug_data = config[bug_key]

    ground_truth = {
        "bug_name": bug_key,
        "vulnerability": bug_data.get("Vulnerability"),
        "impact": bug_data.get("Impact"),
        "root_cause": bug_data.get("Root Cause"),
        "location": bug_data.get("Location", {}),
        "dsl": bug_data.get("DSL"),
        "project": bug_data.get("Project"),
        "commit": bug_data.get("Commit"),
        "fix_commit": bug_data.get("Fix Commit"),
        "reproduced": bug_data.get("Reproduced"),
        "short_description": bug_data.get(
            "Short Description of the Vulnerability"
        ),
        "proposed_mitigation": bug_data.get("Proposed Mitigation"),
        "source": bug_data.get("Source"),
        "codebase": bug_data.get("Codebase"),
        "direct_entrypoint": bug_data.get("Direct Entrypoint"),
        "original_entrypoint": bug_data.get("Original Entrypoint", []),
        "input": bug_data.get("Input", {}),
        "executed": bug_data.get("Executed"),
        "compiled_direct": bug_data.get("Compiled Direct"),
        "compiled_original": bug_data.get("Compiled Original"),
        "similar_bugs": bug_data.get("Similar Bugs", []),
        "mode": mode,
    }

    ensure_dir(output_path.parent)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(ground_truth, f, indent=2, ensure_ascii=False)


def precompile_circuit(
    input_paths: Input, scratch_dir: Path, timeout: int
) -> Input | None:
    """Compile circom once so ecneproject / picus can reuse the artifacts.

    Returns a new Input with r1cs_file/sym_file populated, or None if
    compilation failed. Writes compile.log to scratch_dir.
    """
    ensure_dir(scratch_dir)
    cmd = [
        "circom",
        input_paths.circuit_file,
        "--r1cs",
        "--sym",
        "--wasm",
        "--O0",
        "-o",
        str(scratch_dir),
        *input_paths.link_flags,
    ]
    log_path = scratch_dir / "compile.log"
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        log_path.write_text("[circom compile timed out]\n", encoding="utf-8")
        logging.warning(
            "precompile_circuit: timed out for %s", input_paths.circuit_file
        )
        return None

    combined = f"cmd: {shlex.join(cmd)}\n\nstdout:\n{result.stdout}\n\nstderr:\n{result.stderr}\n"
    log_path.write_text(combined, encoding="utf-8")
    if result.returncode != 0:
        logging.warning(
            "precompile_circuit: circom failed for %s (rc=%s)",
            input_paths.circuit_file,
            result.returncode,
        )
        return None

    r1cs = next(iter(scratch_dir.glob("*.r1cs")), None)
    sym = next(iter(scratch_dir.glob("*.sym")), None)
    if r1cs is None or sym is None:
        logging.warning(
            "precompile_circuit: r1cs/sym missing in %s", scratch_dir
        )
        return None

    return replace(
        input_paths,
        r1cs_file=str(r1cs.resolve()),
        sym_file=str(sym.resolve()),
    )


def _helper_eval(
    tool_result: ToolResult,
    tool_instance: AbstractTool,
    tool_name: str,
    dsl: str,
    bug_name: str,
    ground_truth_path: Path,
    bug_output_dir: Path,
) -> None:
    if tool_result.status != ToolStatus.SUCCESS:
        # Tool failed or timed out, skip evaluation
        return

    # Evaluate findings against ground truth
    evaluation = tool_instance.evaluate_zkbugs_ground_truth(
        tool_name,
        dsl,
        bug_name,
        ground_truth_path,
        bug_output_dir / tool_name / "results.json",
    )

    # Write evaluation results
    eval_path = bug_output_dir / tool_name / "evaluation.json"
    with open(eval_path, "w", encoding="utf-8") as f:
        json.dump(evaluation, f, indent=2, ensure_ascii=False)

    logging.info(
        f"{tool_name} evaluation: {evaluation.get('status', 'Unknown')}"
    )


def _process_one_bug(
    bug: dict,
    tools: list[str],
    dsl: str,
    timeout: int,
    output: Path,
    mode: str,
    needs_artifacts: bool,
    in_worker: bool,
    log_level: str,
) -> dict:
    """Run all tools against a single bug and return its summary row.

    Top-level (picklable) so it can be dispatched via ProcessPoolExecutor.
    When `in_worker` is True (jobs > 1), reroute logging to a per-bug
    run.log so parallel workers don't race on the main log.
    """
    bug_output_dir = output / bug["bug_name"]
    ensure_dir(bug_output_dir)

    if in_worker:
        setup_logging(
            log_level,
            bug_output_dir,
            file_logging=True,
            log_filename="run.log",
            console=False,
        )

    logging.info("=" * 80)
    logging.info("Processing bug: %s", bug["bug_name"])
    logging.info("=" * 80)

    ground_truth_path = bug_output_dir / "ground_truth.json"
    generate_ground_truth(bug["config_path"], ground_truth_path, mode)
    logging.info("Generated ground truth: %s", ground_truth_path)

    input_paths: Input = bug["input"]

    if needs_artifacts:
        scratch_dir = bug_output_dir / "scratch"
        compiled = precompile_circuit(input_paths, scratch_dir, timeout)
        if compiled is not None:
            input_paths = compiled
        else:
            logging.warning(
                "Precompile failed for %s; ecneproject/picus will report errors",
                bug["bug_name"],
            )

    tool_registry = resolve_tools(tools)
    results = execute_tools(tool_registry, input_paths, bug_output_dir, timeout)

    for tool_name, tool_instance in tool_registry.items():
        if tool_name not in results:
            continue
        tool_result = results[tool_name]
        _helper_eval(
            tool_result,
            tool_instance,
            tool_name,
            dsl,
            bug["bug_name"],
            ground_truth_path,
            bug_output_dir,
        )

    return {
        "bug_name": bug["bug_name"],
        "status": "processed",
        "mode": mode,
        "tools": {
            name: {
                "status": r.status.value,
                "findings_count": r.findings_count,
            }
            for name, r in results.items()
        },
    }


_STATUS_RANK = {"processed": 0, "error": 1, "skipped": 2}


def _sort_summary_rows(rows: list[dict]) -> list[dict]:
    """Order rows by (status, bug_name) so serial/parallel runs diff cleanly."""
    return sorted(
        rows, key=lambda r: (_STATUS_RANK.get(r["status"], 99), r["bug_name"])
    )


def _zkbugs_both(
    dataset_dir: Path,
    tools: list[str],
    dsl: str,
    timeout: int,
    output: Path,
    selectors: list[str] | None,
    jobs: int,
    random_bugs: int | None,
    random_seed: int | None,
    log_level: str,
) -> None:
    """Run direct for every bug, then original only for bugs with a
    distinct Original Entrypoint. Emits <output>/{direct,original}/
    sub-runs and a combined top-level summary.json.
    """
    logging.info("Running in ZKBUGS mode (both)")
    logging.info("Output root: %s", output)

    ensure_dir(output)
    direct_out = output / "direct"
    original_out = output / "original"

    # Pass 1: direct.
    zkbugs_mode(
        dataset_dir,
        tools,
        dsl,
        timeout,
        direct_out,
        mode="direct",
        selectors=selectors,
        jobs=jobs,
        random_bugs=random_bugs,
        random_seed=random_seed,
        log_level=log_level,
    )

    # Determine which of the processed bugs have a distinct original
    # entrypoint — reading the direct summary avoids re-discovering bugs.
    direct_summary_path = direct_out / "summary.json"
    direct_summary: dict = {}
    try:
        direct_summary = json.loads(
            direct_summary_path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        logging.error(
            "both-mode: cannot read %s (%s); skipping original pass",
            direct_summary_path,
            exc,
        )

    processed_bug_names = [
        b["bug_name"]
        for b in direct_summary.get("bugs", [])
        if b.get("status") == "processed"
    ]

    distinct_names: list[str] = []
    for bug_name in processed_bug_names:
        # Locate the bug dir under the dataset to read its config.
        matches = list(dataset_dir.rglob(f"{bug_name}/zkbugs_config.json"))
        matches = [m for m in matches if not _is_excluded_config(m)]
        if not matches:
            continue
        try:
            config = load_bug_config(matches[0].parent)
        except (OSError, ZkbugsLoaderError):
            continue
        if config.get("Original Entrypoint"):
            distinct_names.append(bug_name)

    logging.info(
        "both-mode: %d/%d processed bugs have a distinct Original Entrypoint",
        len(distinct_names),
        len(processed_bug_names),
    )

    # Pass 2: original, narrowed to the distinct set. Skip entirely if
    # nothing qualifies — keeps the empty original/ subdir off disk.
    original_summary: dict = {}
    if distinct_names:
        zkbugs_mode(
            dataset_dir,
            tools,
            dsl,
            timeout,
            original_out,
            mode="original",
            selectors=distinct_names,
            jobs=jobs,
            random_bugs=None,
            random_seed=random_seed,
            log_level=log_level,
        )
        original_summary_path = original_out / "summary.json"
        try:
            original_summary = json.loads(
                original_summary_path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            logging.error(
                "both-mode: cannot read %s (%s)",
                original_summary_path,
                exc,
            )
    else:
        logging.info("both-mode: no distinct originals; original pass skipped")

    combined = {
        "mode": "both",
        "dataset": str(dataset_dir),
        "output_root": str(output),
        "modes": {
            "direct": _extract_mode_rollup(direct_summary, direct_out),
            "original": (
                _extract_mode_rollup(original_summary, original_out)
                if original_summary
                else {"ran": False, "reason": "no distinct originals"}
            ),
        },
        "bugs_with_distinct_original": distinct_names,
    }
    (output / "summary.json").write_text(
        json.dumps(combined, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    logging.info("\n" + "=" * 80)
    logging.info("zkbugs mode (both) completed")
    logging.info("Combined summary: %s", output / "summary.json")
    logging.info("=" * 80)


def _extract_mode_rollup(summary: dict, output_dir: Path) -> dict:
    """One-line rollup of a sub-run's summary, for the combined top-level."""
    return {
        "ran": True,
        "output_dir": str(output_dir),
        "total": summary.get("total", 0),
        "processed": summary.get("processed", 0),
        "errors": summary.get("errors", 0),
        "skipped": summary.get("skipped", 0),
        "evaluation_counts": summary.get("evaluation_counts"),
    }


def zkbugs_mode(
    dataset_dir: Path,
    tools: list[str],
    dsl: str,
    timeout: int,
    output: Path,
    mode: str = "direct",
    selectors: list[str] | None = None,
    jobs: int = 1,
    random_bugs: int | None = None,
    random_seed: int | None = None,
    log_level: str = "INFO",
) -> None:
    """Evaluate tools against the refactored zkbugs dataset."""
    if mode == "both":
        _zkbugs_both(
            dataset_dir,
            tools,
            dsl,
            timeout,
            output,
            selectors,
            jobs,
            random_bugs,
            random_seed,
            log_level,
        )
        return

    logging.info("Running in ZKBUGS mode")
    logging.info(f"Dataset: {dataset_dir}")
    logging.info(f"DSL: {dsl}")
    logging.info(f"Tools: {tools}")
    logging.info(f"Timeout: {timeout}s")
    logging.info(f"zkbugs-mode: {mode}")
    logging.info(f"Jobs: {jobs}")
    if selectors:
        logging.info("Bug selectors: %s", selectors)

    try:
        script_path = find_print_bug_vars(dataset_dir)
    except ZkbugsLoaderError as exc:
        logging.error(str(exc))
        sys.exit(1)
    logging.info("Using runner contract: %s", script_path)

    bugs = discover_zkbugs(dataset_dir, mode, script_path, selectors)
    logging.info(f"Total bugs discovered: {len(bugs)}")
    if selectors and not bugs:
        logging.error(
            "No bugs matched selectors %s under %s", selectors, dataset_dir
        )
        sys.exit(1)

    runnable = [b for b in bugs if b["input"] is not None]
    skipped = [b for b in bugs if b["input"] is None]
    logging.info(
        "Runnable: %d, skipped: %d/%d",
        len(runnable),
        len(skipped),
        len(bugs),
    )
    for bug in skipped:
        logging.info(
            "  skip %s: %s",
            bug["bug_name"],
            bug.get("skip_reason", "unknown"),
        )

    if not runnable:
        logging.error("No runnable bugs in %s (mode=%s)", dataset_dir, mode)
        sys.exit(1)

    # Fail-fast binary check in the main process before spawning workers.
    tool_registry = resolve_tools(tools)
    if not tool_registry:
        logging.error("No tools loaded successfully")
        sys.exit(1)
    needs_artifacts = bool(set(tool_registry) & ARTIFACT_TOOLS)

    # Optional random sampling after selector filtering.
    if random_bugs is not None and random_bugs < len(runnable):
        rng = random.Random(random_seed)
        runnable = rng.sample(runnable, random_bugs)
        logging.info(
            "Random sampled %d/%d bugs (seed=%s)",
            len(runnable),
            len(bugs),
            random_seed,
        )
    elif random_bugs is not None:
        logging.info(
            "--random-bugs=%d >= runnable=%d; using all runnable bugs",
            random_bugs,
            len(runnable),
        )

    ensure_dir(output)
    logging.info(f"Output directory: {output}")

    summary_rows: list[dict] = []
    error_rows: list[dict] = []

    if jobs == 1:
        # Preserve byte-identical serial behavior: inline, no pickling, no
        # per-bug log redirection. Workers in serial mode == main process.
        for idx, bug in enumerate(runnable, 1):
            logging.info("[%d/%d] %s", idx, len(runnable), bug["bug_name"])
            try:
                summary_rows.append(
                    _process_one_bug(
                        bug,
                        tools,
                        dsl,
                        timeout,
                        output,
                        mode,
                        needs_artifacts,
                        in_worker=False,
                        log_level=log_level,
                    )
                )
            except Exception as exc:  # noqa: BLE001
                logging.exception(
                    "[%d/%d] ✗ %s: %s",
                    idx,
                    len(runnable),
                    bug["bug_name"],
                    exc,
                )
                error_rows.append(
                    {
                        "bug_name": bug["bug_name"],
                        "status": "error",
                        "mode": mode,
                        "error": str(exc),
                    }
                )
    else:
        logging.info(
            "Dispatching %d bugs across %d workers", len(runnable), jobs
        )
        ctx = mp.get_context("spawn")
        with ProcessPoolExecutor(max_workers=jobs, mp_context=ctx) as ex:
            futures = {
                ex.submit(
                    _process_one_bug,
                    bug,
                    tools,
                    dsl,
                    timeout,
                    output,
                    mode,
                    needs_artifacts,
                    True,
                    log_level,
                ): bug
                for bug in runnable
            }
            for done, fut in enumerate(as_completed(futures), 1):
                bug = futures[fut]
                try:
                    summary_rows.append(fut.result())
                    logging.info(
                        "[%d/%d] ✓ %s", done, len(runnable), bug["bug_name"]
                    )
                except Exception as exc:  # noqa: BLE001
                    logging.error(
                        "[%d/%d] ✗ %s: %s",
                        done,
                        len(runnable),
                        bug["bug_name"],
                        exc,
                    )
                    error_rows.append(
                        {
                            "bug_name": bug["bug_name"],
                            "status": "error",
                            "mode": mode,
                            "error": str(exc),
                        }
                    )

    for bug in skipped:
        summary_rows.append(
            {
                "bug_name": bug["bug_name"],
                "status": "skipped",
                "reason": bug.get("skip_reason"),
                "mode": mode,
            }
        )

    summary_rows.extend(error_rows)
    summary_rows = _sort_summary_rows(summary_rows)

    summary_path = output / "summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "mode": mode,
                "dataset": str(dataset_dir),
                "total": len(bugs),
                "processed": len(runnable) - len(error_rows),
                "errors": len(error_rows),
                "skipped": len(skipped),
                "jobs": jobs,
                "bugs": summary_rows,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )

    logging.info("\n" + "=" * 80)
    logging.info(
        "zkbugs mode completed: processed=%d errors=%d skipped=%d",
        len(runnable) - len(error_rows),
        len(error_rows),
        len(skipped),
    )
    logging.info(f"Results written to: {output}")
    logging.info("=" * 80)


def vanilla_mode(output_dir: Path, eval: bool, dsl: str = "circom") -> None:
    """
    Vanilla mode: Process existing .raw files.

    Args:
        output_dir: Output directory
        eval: Whether to evaluate the results
    """
    logging.info("Running in VANILLA mode")
    logging.info(f"Output directory: {output_dir}")
    logging.info(f"Evaluate: {eval}")

    # check if there is a ground truth file or a summary file
    # If there is then we are processing a bug
    # If not then we are processing a dir of many bugs
    ground_truth_path = output_dir / "ground_truth.json"
    summary_path = output_dir / "summary.json"
    bugs_dir = []
    if ground_truth_path.exists() or summary_path.exists():
        logging.info("Processing a bug")
        bugs_dir.append(output_dir)
    else:
        logging.info("Processing a dir of many bugs")
        bugs_dir = list(output_dir.rglob("*"))

    for bug_dir in bugs_dir:
        logging.info(f"Processing bug: {bug_dir}")
        bug_name = bug_dir.name
        # Find all tool directories in the bug directory
        tool_dirs = [
            Path(bug_dir) / d
            for d in os.listdir(bug_dir)
            if (Path(bug_dir) / d).is_dir()
        ]
        for tool_dir in tool_dirs:
            tool_name = tool_dir.name
            logging.info(f"Processing tool: {tool_name}")
            # Load the tool_output.json file
            with open(tool_dir / "tool_output.json", encoding="utf-8") as f:
                tool_output = ToolOutput.from_dict(json.load(f))
            # Redo the analysis of the tool result
            tool_instance = resolve_tools([tool_name])[tool_name]
            # Process the tool output
            tool_result = tool_instance.process_output(tool_output)

            # Load the ground truth file
            if eval:
                ground_truth_path = bug_dir / "ground_truth.json"
                _helper_eval(
                    tool_result,
                    tool_instance,
                    tool_name,
                    dsl,
                    bug_name,
                    ground_truth_path,
                    bug_dir,
                )
