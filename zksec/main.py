import argparse
import logging
import os
from pathlib import Path
from typing import Dict, List

from bugs.zkbugs import cleanup as cleanup_zkbug_environment
from bugs.zkbugs import generate_ground_truth as generate_ground_truth_zkbugs
from bugs.zkbugs import setup as setup_zkbug_environment
from utils.config import load_config
from utils.runner import (
    compare_tool_output_with_zkbugs_ground_truth,
    execute_tool_on_bug,
    parse_tool_output,
    summarize_results,
)
from utils.tools_resolver import resolve_tools

BASE_DIR = Path.cwd()
REPO_DIR = BASE_DIR.parent


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Tool runner with config file support")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config.toml"),
        help="Path to the configuration file (default: config.toml)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = load_config(args.config, BASE_DIR)

    for dsl in config.tools:
        logging.info(f"Processing DSL: {dsl}")
        tool_registry = resolve_tools(dsl, config.tools[dsl])

        for bug in config.bugs[dsl]:
            bug_path = REPO_DIR / bug
            bug_name = remove_first_n_dirs(bug, 5)

            if not bug_path.exists():
                logging.error(f"Bug path does not exist: {bug_path}")
                continue

            if config.setup_bug_environment:
                setup_zkbug_environment(bug_path)

            if config.execute_tools:
                execute_bug(config, dsl, bug_path, bug_name, tool_registry)

            if config.cleanup_bug_environment:
                cleanup_zkbug_environment(bug_path)

            if config.generate_ground_truth:
                generate_ground_truth(config, dsl, bug_path, bug_name)

            if config.parse_raw_tool_output:
                parse_raw_tool_output(config, dsl, tool_registry, bug_name)

            if config.analyze_tool_results:
                analyze_tool_results(
                    config,
                    dsl,
                    tool_registry,
                    bug_name,
                )

            if config.summarize_tool_results:
                summarize_tool_results(config, dsl, tool_registry, bug_name)


def get_tool_results_raw(config, dsl: str, tool: str, bug_name: str) -> Path:
    return config.output_dir / dsl / tool / bug_name / "raw.txt"


def get_output_ground_truth(config, dsl: str, bug_name: str) -> Path:
    return config.output_dir / "ground_truth" / dsl / bug_name / "ground_truth.json"


def get_output_structured(config, dsl: str, tool: str, bug_name: str) -> Path:
    return config.output_dir / dsl / tool / bug_name / "parsed.json"


def get_output_result(config, dsl: str, tool: str, bug_name: str) -> Path:
    return config.output_dir / dsl / tool / bug_name / "results.json"


def execute_bug(
    config, dsl: str, bug_path: Path, bug_name: str, tool_registry: Dict[str, any]
) -> None:
    for tool in config.tools[dsl]:
        if tool not in tool_registry:
            logging.warning(f"Skipping {tool} because it failed to load")
            continue

        tool_results_raw = get_tool_results_raw(config, dsl, tool, bug_name)

        execute_tool_on_bug(
            tool,
            bug_path,
            bug_name,
            config.timeout,
            tool_results_raw,
            tool_registry[tool],
        )


def generate_ground_truth(config, dsl: str, bug_path: Path, bug_name: str) -> None:
    output_ground_truth = get_output_ground_truth(config, dsl, bug_name)
    generate_ground_truth_zkbugs(bug_name, bug_path, dsl, output_ground_truth)


def parse_raw_tool_output(
    config, dsl: str, tool_registry: Dict[str, any], bug_name: str
) -> None:
    for tool in config.tools[dsl]:
        if tool not in tool_registry:
            logging.warning(f"Skipping {tool} because it failed to load")
            continue

        output_structured = get_output_structured(config, dsl, tool, bug_name)
        tool_results_raw = get_tool_results_raw(config, dsl, tool, bug_name)
        ground_truth = get_output_ground_truth(config, dsl, bug_name)
        parse_tool_output(
            tool,
            tool_registry[tool],
            tool_results_raw,
            output_structured,
            bug_name,
            ground_truth,
        )


def analyze_tool_results(
    config, dsl: str, tool_registry: Dict[str, any], bug_name: str
) -> None:
    for tool in config.tools[dsl]:
        if tool not in tool_registry:
            logging.warning(f"Skipping {tool} because it failed to load")
            continue

        output_result = get_output_result(config, dsl, tool, bug_name)
        compare_tool_output_with_zkbugs_ground_truth(
            tool,
            tool_registry[tool],
            bug_name,
            get_output_ground_truth(config, dsl, bug_name),
            get_output_structured(config, dsl, tool, bug_name),
            output_result,
        )


def summarize_tool_results(
    config, dsl: str, tool_registry: Dict[str, any], bug_name: str
) -> None:
    output_result = config.output_dir / "summary.json"

    for tool in config.tools[dsl]:
        if tool not in tool_registry:
            logging.warning(f"Skipping {tool} because it failed to load")
            continue
        output_result_tool = get_output_result(config, dsl, tool, bug_name)
        summarize_results(dsl, tool, bug_name, output_result, output_result_tool)


def remove_first_n_dirs(path: str, n: int = 5) -> str:
    """Drop the first n path components from a string path safely.

    If n >= number of components, returns the last component or empty string.
    """
    path_parts: List[str] = os.path.normpath(path).split(os.sep)
    new_path_parts = path_parts[n:] if n < len(path_parts) else path_parts[-1:]
    return os.path.join(*new_path_parts) if new_path_parts else ""


if __name__ == "__main__":
    main()
