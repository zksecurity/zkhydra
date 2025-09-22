import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from tools.utils import ensure_dir

from .tools_resolver import ToolInfo


def execute_tool_on_bug(
    tool: str,
    bug_path: Path,
    bug_name: str,
    timeout: int,
    output: Path,
    tool_info: ToolInfo,
) -> None:
    """Execute a tool against a bug and persist raw output lines to JSON."""
    execute_fn = tool_info.execute
    logging.info(f"Running {tool=} on {bug_name=}")
    try:
        result = execute_fn(bug_path, timeout)
    except Exception as e:
        logging.error(f"{tool} failed on {bug_name}: {e}")
        result = f"Error: {e}"
    write_raw_output(output, tool, tool_info.dsl, bug_name, result)


def write_raw_output(
    output_file: Path, tool: str, dsl: str, bug_name: str, content: Any
) -> None:
    """Write raw tool output to a JSON file organized by dsl/tool/bug_name.

    Content is normalized to a list of lines.
    """
    json_file = output_file.with_suffix(".json")
    logging.debug(f"Writing {tool} results for {bug_name} to '{json_file}'")

    # Ensure directory exists
    json_file.parent.mkdir(parents=True, exist_ok=True)

    # Load existing JSON if it exists
    if json_file.exists():
        with open(json_file, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                logging.warning(f"Corrupted JSON at {json_file}, starting fresh")
                data = {}
    else:
        data = {}

    # Ensure content is stored as list of lines (instead of one long string)
    if isinstance(content, str):
        content_lines: List[str] = content.splitlines()
    elif isinstance(content, list):
        content_lines = [str(item) for item in content]
    else:
        content_lines = [str(content)]

    # Navigate into dsl > tool
    if dsl not in data:
        data[dsl] = {}
    if tool not in data[dsl]:
        data[dsl][tool] = {}

    # Update or create entry
    action = "updated" if bug_name in data[dsl][tool] else "created"
    data[dsl][tool][bug_name] = content_lines

    # Write back to JSON
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    logging.info(f"Entry for '{bug_name}' {action} in {json_file}")


def parse_tool_output(
    tool: str,
    tool_info: ToolInfo,
    tool_result_raw: Path,
    output: Path,
    bug_name: str,
    ground_truth: Path,
):
    """Parse a tool's raw output into a structured JSON summary and persist it."""
    parse_output_fn = tool_info.parse_output
    logging.debug(
        f"Parsing output for tool '{tool}' in DSL '{tool_info.dsl}' for bug '{bug_name}'."
    )
    try:
        parsed_result = parse_output_fn(
            tool_result_raw, tool, bug_name, tool_info.dsl, ground_truth
        )
    except Exception as e:
        logging.error(f"Parsing output failed for tool '{tool}': {e}")
        return
    write_parsed_output(output, parsed_result)


def write_output(output_file: Path, content: Dict[str, Any]) -> None:
    """Safely write the full JSON content to output_file.

    - Ensures parent directory exists
    - Writes atomically via a temporary file then rename
    - Uses UTF-8 and pretty formatting
    """
    ensure_dir(output_file.parent)
    temp_file = output_file.with_suffix(output_file.suffix + ".tmp")
    try:
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(content, f, indent=2, ensure_ascii=False)
        temp_file.replace(output_file)
        logging.debug(f"Parsed output written to {output_file}")
    except Exception as e:
        logging.error(f"Failed writing '{output_file}': {e}")
        # Best-effort fallback direct write
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(content, f, indent=2, ensure_ascii=False)


def compare_tool_output_with_zkbugs_ground_truth(
    tool: str,
    tool_info: ToolInfo,
    bug_name: str,
    ground_truth: Path,
    tool_result_parsed: Path,
    output_file: Path,
) -> None:
    """Compare parsed tool output against ground truth and persist aggregate."""
    compare_fn = tool_info.compare_zkbugs_ground_truth
    logging.debug(f"Comparing output for tool '{tool}' in DSL '{tool_info.dsl}'")
    try:
        result = compare_fn(
            tool, tool_info.dsl, bug_name, ground_truth, tool_result_parsed, output_file
        )
    except Exception as e:
        logging.error(f"Comparison with ground truth failed for tool '{tool}': {e}")
        return
    if not isinstance(result, dict):
        logging.error(f"Comparison function for '{tool}' did not return a dict")
        return
    write_output(output_file, result)


def deep_update(original: Any, new_data: Any):
    """
    Recursively update dict `original` with values from `new_data`.
    - Dicts are merged
    - Lists are extended (deduplicated if possible)
    - Other values are overwritten
    """
    if isinstance(original, dict) and isinstance(new_data, dict):
        for key, value in new_data.items():
            if key in original:
                original[key] = deep_update(original[key], value)
            else:
                original[key] = value
        return original

    elif isinstance(original, list) and isinstance(new_data, list):
        # merge lists (append unique items)
        merged = original[:]
        for item in new_data:
            if item not in merged:
                merged.append(item)
        return merged

    else:
        # overwrite scalar or incompatible types
        return new_data


def write_parsed_output(output_file: Path, content: Dict[str, Any]) -> None:
    logging.debug(f"Writing parsed results to '{output_file}'; content={content}")
    ensure_dir(output_file.parent)

    # Load existing JSON or start fresh
    if output_file.exists():
        with open(output_file, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                logging.warning(f"Corrupt JSON in {output_file}, resetting.")
                data = {}
    else:
        data = {}

    # Merge parsed_result into existing JSON
    data = deep_update(data, content)

    # Save back
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    logging.debug(f"Parsed output written to {output_file}")
