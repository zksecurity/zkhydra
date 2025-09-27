import json
import logging
import string
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
    write_raw_output(output, tool, bug_name, result)


def write_raw_output(output_file: Path, tool: str, bug_name: str, content: Any) -> None:
    """Write raw tool output to a JSON file organized by dsl/tool/bug_name.

    Content is normalized to a list of lines.
    """
    # output_file = Path(output / tool / bug_name / "raw.txt")
    logging.info(f"Writing raw output to '{output_file}'")

    # Ensure directory exists
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # Write back to JSON
    with open(output_file, "w", encoding="utf-8") as f:
        clean_text = "".join(c for c in content if c in string.printable)
        f.write(clean_text)

    logging.info(f"Entry for tool '{tool}' on bug '{bug_name}' in {output_file}")


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
        parsed_result = parse_output_fn(tool_result_raw, ground_truth)
    except Exception as e:
        logging.error(f"Parsing output failed for tool '{tool}': {e}")
        return

    write_json(output, tool, bug_name, "parsed", parsed_result)


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
            tool, tool_info.dsl, bug_name, ground_truth, tool_result_parsed
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


def write_parsed_output(output: Path, content: Dict[str, Any]) -> None:
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


def write_json(
    output_file: Path, tool: str, bug_name: str, name: str, content: Any
) -> None:
    """Write JSON content to a file in the output directory."""
    ensure_dir(output_file.parent)

    logging.debug(
        f"Writing {name} results for tool '{tool}' on bug '{bug_name}' to '{output_file}'"
    )
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(content, f, indent=2, ensure_ascii=False)


def summarize_results(
    dsl: str, tool: str, bug_name: str, output_file: Path, output_file_tool: Path
) -> None:
    output = {}
    ensure_dir(output_file.parent)

    inner_output = {}
    inner_output.setdefault(
        "count",
        {
            "correct": 0,
            "false": 0,
            "error": 0,
            "timeout": 0,
        },
    )
    inner_output.setdefault("correct", [])
    inner_output.setdefault("false", [])
    inner_output.setdefault("error", [])
    inner_output.setdefault("timeout", [])

    if output_file.exists():
        with open(output_file, "r", encoding="utf-8") as f:
            output = json.load(f)

    output.setdefault(dsl, {}).setdefault(tool, inner_output)

    with open(output_file_tool, "r", encoding="utf-8") as f:
        output_tool = json.load(f)

    if output_tool["result"] == "correct":
        output[dsl][tool]["correct"].append({"bug_name": bug_name})
        output[dsl][tool]["count"]["correct"] += 1
    elif output_tool["result"] == "false":
        if "need_manual_evaluation" in output_tool:
            output[dsl][tool]["false"].append(
                {
                    "bug_name": bug_name,
                    "reason": output_tool["reason"],
                    "need_manual_evaluation": output_tool["need_manual_evaluation"],
                }
            )
        else:
            output[dsl][tool]["false"].append(
                {"bug_name": bug_name, "reason": output_tool["reason"]}
            )
        output[dsl][tool]["count"]["false"] += 1
    elif output_tool["result"] == "error":
        if "need_manual_evaluation" in output_tool:
            output[dsl][tool]["error"].append(
                {
                    "bug_name": bug_name,
                    "reason": output_tool["reason"],
                    "need_manual_evaluation": output_tool["need_manual_evaluation"],
                }
            )
        else:
            output[dsl][tool]["error"].append(
                {"bug_name": bug_name, "reason": output_tool["reason"]}
            )
        output[dsl][tool]["count"]["error"] += 1
    elif output_tool["result"] == "timeout":
        output[dsl][tool]["timeout"].append(
            {"bug_name": bug_name, "reason": output_tool["reason"]}
        )
        output[dsl][tool]["count"]["timeout"] += 1

    write_json(output_file, "", "", "summary", output)
