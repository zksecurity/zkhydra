import logging
import json
from pathlib import Path

from tools.utils import ensure_dir
from tools_resolver import ToolInfo


def run_tool_on_bug(
    tool: str,
    bug_path: Path,
    bug_name: str,
    timeout: int,
    base_dir: Path,
    output_dir: Path,
    tool_info: ToolInfo,
    sbug_path
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


# def write_output(output_file: Path, tool: str, bug_name: str, content: str) -> None:
#     logging.info(f"Writing {tool} results for {bug_name} to '{output_file}'")

#     ensure_dir(output_file.parent)

#     # Write the output to the file
#     with open(output_file, "a") as f:
#         f.write(f"========== {bug_name} ==========\n")
#         f.write(str(content))
#         f.write("\n\n")



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

