import json
import logging
from pathlib import Path

from tools.utils import ensure_dir
from tools_resolver import ToolInfo


def execute_tool_on_bug(
    tool: str,
    bug_path: Path,
    bug_name: str,
    timeout: int,
    base_dir: Path,
    output_dir: Path,
    tool_info: ToolInfo,
    sbug_path,
) -> None:
    dsl = tool_info.dsl
    execute_fn = tool_info.execute
    output = base_dir / output_dir / f"{dsl}" / "raw" / f"{tool}.log"
    logging.info(f"Running {tool=} on {bug_name=}")
    try:
        result = execute_fn(bug_path, timeout)
    except Exception as e:
        logging.error(f"{tool} failed on {bug_name}: {e}")
        result = f"Error: {e}"
    write_output(output, tool, sbug_path, result)


def write_output(output_file: Path, tool: str, bug_name: str, content: str) -> None:
    json_file = output_file.with_suffix(".json")
    logging.info(f"Writing {tool} results for {bug_name} to '{json_file}'")

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
        content_lines = content.splitlines()
    else:
        content_lines = content

    # Update or create entry
    action = "updated" if bug_name in data else "created"
    data[bug_name] = content_lines

    # Write back to JSON
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    logging.info(f"Entry for '{bug_name}' {action} in {json_file}")


def parse_tool_output(
    tool: str,
    tool_info: ToolInfo,
    tool_result_raw: Path,
    output: Path,
):
    parse_output_fn = tool_info.parse_output
    logging.debug(f"Parsing output for tool '{tool}' in DSL '{tool_info.dsl}'")
    try:
        parsed_result = parse_output_fn(tool_result_raw, output)
    except Exception as e:
        logging.error(f"Parsing output failed for tool '{tool}': {e}")
        return
    write_parsed_output(output, tool, parsed_result)


def write_parsed_output(output_file: Path, tool: str, content) -> None:
    logging.info(f"Writing parsed {tool} results to '{output_file}'")

    # Ensure directory exists
    ensure_dir(output_file.parent)

    # Write to JSON
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(content, f, indent=2, ensure_ascii=False)

    logging.info(f"Parsed output written to {output_file}")
