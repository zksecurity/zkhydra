import json
import logging
import os
import shlex
import subprocess
from pathlib import Path


def run_command(cmd: list[str], timeout: int, tool: str, bug: str) -> str:
    logging.info(f"Running: '{shlex.join(cmd)}'")

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=True, timeout=timeout
        )
        return "stdout:\n" + result.stdout + "\nstderr:\n" + result.stderr

    except subprocess.TimeoutExpired as e:
        logging.warning(
            f"Process for '{tool}' analysing '{bug}' exceeded {timeout} seconds and timed out. Partial output: {e.stdout}"
        )
        return "[Timed out]"

    except subprocess.CalledProcessError as e:
        # Circomspect returns exit code 1
        return e.stdout


def change_directory(target_dir: Path) -> None:
    os.chdir(target_dir)
    logging.debug(f"Changed directory to: {Path.cwd()}")


def check_files_exist(*files: Path) -> bool:
    for f in files:
        file_path = Path(f)
        if file_path.is_file():
            logging.debug(f"Found file: {file_path}")
        else:
            logging.error(f"File not found: {file_path}")
            return False
    return True


def ensure_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)


def init_output_dict(output: dict, dsl: str, tool: str) -> dict:
    # Ensure tool entry exists
    output.setdefault(dsl, {}).setdefault(tool, {}).setdefault("correct", [])
    output.setdefault(dsl, {}).setdefault(tool, {}).setdefault("false", [])
    output.setdefault(dsl, {}).setdefault(tool, {}).setdefault("error", [])
    output.setdefault(dsl, {}).setdefault(tool, {}).setdefault("timeout", [])


def update_result_counts(output: dict, dsl: str, tool: str) -> dict:
    # Update counts dynamically
    output[dsl][tool]["count"] = {
        "correct": len(output[dsl][tool]["correct"]),
        "false": len(output[dsl][tool]["false"]),
        "error": len(output[dsl][tool]["error"]),
        "timeout": len(output[dsl][tool]["timeout"]),
    }

    return output


def load_output_dict(output_file: Path, dsl: str, tool: str) -> dict:
    # Load existing output or initialize
    if os.path.exists(output_file):
        with open(output_file, "r", encoding="utf-8") as f:
            output = json.load(f)
    else:
        output = {dsl: {}}

    init_output_dict(output, dsl, tool)
    return output


def get_tool_result_parsed(
    tool_result_parsed: Path, dsl: str, tool: str, bug_name: str
) -> dict:
    with open(tool_result_parsed, "r", encoding="utf-8") as f:
        tool_output_data = json.load(f).get(dsl, {}).get(tool, {}).get(bug_name, {})
    return tool_output_data
