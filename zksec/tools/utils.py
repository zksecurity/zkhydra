import json
import logging
import os
import shlex
import subprocess
from pathlib import Path
from typing import Any, Dict


def run_command(cmd: list[str], timeout: int, tool: str, bug: str) -> str:
    """Run a subprocess command and return combined stdout/stderr text.

    On success (exit code 0), returns a string with stdout and stderr blocks.
    On timeout, returns "[Timed out]". On non-zero exit code, returns stdout
    (some tools intentionally use non-zero codes for non-fatal results).
    """
    logging.info(f"Running: '{shlex.join(cmd)}'")

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=True, timeout=timeout
        )
        return (
            "stdout:\n" + (result.stdout or "") + "\nstderr:\n" + (result.stderr or "")
        )

    except subprocess.TimeoutExpired as e:
        logging.warning(
            f"Process for '{tool}' analysing '{bug}' exceeded {timeout} seconds and timed out. Partial output: {getattr(e, 'stdout', '')}"
        )
        return "[Timed out]"

    except subprocess.CalledProcessError as e:
        # Some tools (e.g., circomspect) return non-zero exit codes by design
        stdout = e.stdout or ""
        stderr = e.stderr or ""
        if stdout:
            return stdout
        # Fallback to combined output if stdout is empty
        return "stdout:\n" + stdout + "\nstderr:\n" + stderr


def change_directory(target_dir: Path) -> None:
    """Change current working directory to target_dir with a debug log."""
    os.chdir(target_dir)
    logging.debug(f"Changed directory to: {Path.cwd()}")


def check_files_exist(*files: Path) -> bool:
    """Return True only if all provided files exist; log missing ones as errors."""
    for f in files:
        file_path = Path(f)
        if file_path.is_file():
            logging.debug(f"Found file: {file_path}")
        else:
            logging.error(f"File not found: {file_path}")
            return False
    return True


def ensure_dir(path: Path) -> None:
    """Create directory path if it doesn't exist (parents included)."""
    path.mkdir(parents=True, exist_ok=True)


def init_output_dict(output: dict, dsl: str, tool: str) -> dict:
    """Ensure output dict has the standard structure for a given dsl/tool."""
    output.setdefault(dsl, {}).setdefault(tool, {}).setdefault("correct", [])
    output.setdefault(dsl, {}).setdefault(tool, {}).setdefault("false", [])
    output.setdefault(dsl, {}).setdefault(tool, {}).setdefault("error", [])
    output.setdefault(dsl, {}).setdefault(tool, {}).setdefault("timeout", [])
    # Do not set count here; updated dynamically by update_result_counts
    return output


def update_result_counts(output: dict, dsl: str, tool: str) -> dict:
    """Recompute and store counts for a given dsl/tool."""
    # Ensure keys exist
    init_output_dict(output, dsl, tool)
    output[dsl][tool]["count"] = {
        "correct": len(output[dsl][tool]["correct"]),
        "false": len(output[dsl][tool]["false"]),
        "error": len(output[dsl][tool]["error"]),
        "timeout": len(output[dsl][tool]["timeout"]),
    }

    return output


def load_output_dict(output_file: Path, dsl: str, tool: str) -> dict:
    """Load the aggregate output JSON file and ensure base structure.

    If the file does not exist or is invalid, initialize a minimal structure.
    """
    output: dict
    if os.path.exists(output_file):
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                output = json.load(f)
            if not isinstance(output, dict):
                logging.error("Output file is not a JSON object; reinitializing")
                output = {dsl: {}}
        except Exception as e:
            logging.error(f"Failed to load output file '{output_file}': {e}")
            output = {dsl: {}}
    else:
        output = {dsl: {}}

    init_output_dict(output, dsl, tool)
    return output


def get_tool_result_parsed(
    tool_result_parsed: Path, dsl: str, tool: str, bug_name: str
) -> dict:
    """Read a parsed tool result file and return the entry for a bug.

    Missing keys return an empty dict; handles invalid files gracefully.
    """
    try:
        with open(tool_result_parsed, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        logging.error(f"Failed to read parsed tool result '{tool_result_parsed}': {e}")
        return {}
    return data.get(dsl, {}).get(tool, {}).get(bug_name, {})


def remove_bug_entry(output: dict, dsl: str, tool: str, bug_name: str) -> dict:
    """Remove a bug from all result buckets for a tool.

    Handles string list bucket ('correct') and dict-list buckets ('false', 'error', 'timeout').
    Robust to buckets containing strings by mistake.
    """
    print(f"\n\n\n")

    for bucket_name in ["false", "error", "timeout", "correct"]:
        bucket = output[dsl][tool][bucket_name]
        if isinstance(bucket, list):
            new_bucket = []
            for item in bucket:
                if isinstance(item, dict):
                    print(f"Checking dict in {bucket_name}: {item}")
                    if item.get("bug_name") == bug_name:
                        print(f"Removing {item}")
                        continue
                elif item == bug_name:
                    print(f"Removing string '{item}' from {bucket_name}")
                    continue
                new_bucket.append(item)
            bucket[:] = new_bucket

    return output
