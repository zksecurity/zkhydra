import logging
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
    write_output(output, tool, bug_name, result)


def write_output(output_file: Path, tool: str, bug_name: str, content: str) -> None:
    logging.info(f"Writing {tool} results for {bug_name} to '{output_file}'")

    ensure_dir(output_file.parent)

    # Write the output to the file
    with open(output_file, "a") as f:
        f.write(f"========== {bug_name} ==========\n")
        f.write(str(content))
        f.write("\n\n")
