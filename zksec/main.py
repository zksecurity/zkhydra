import argparse
import logging
import os
from pathlib import Path

from bugs.zkbugs import cleanup as cleanup_zkbug_environment
from bugs.zkbugs import generate_ground_truth
from bugs.zkbugs import setup as setup_zkbug_environment
from config import load_config
from runner import (
    compare_tool_output_with_zkbugs_ground_truth,
    execute_tool_on_bug,
    parse_tool_output,
)
from tools_resolver import resolve_tools

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


def main():
    args = parse_args()

    config = load_config(args.config)

    for dsl in config.tools:
        logging.info(f"Processing DSL: {dsl}")
        tool_registry = resolve_tools(dsl, config.tools[dsl])

        for bug in config.bugs[dsl]:
            bug_path = REPO_DIR / bug
            bug_name = remove_first_n_dirs(bug, 5)

            setup_zkbug_environment(bug_path)

            for tool in config.tools[dsl]:
                if tool not in tool_registry:
                    logging.warning(f"Skipping {tool} because it failed to load")
                    continue
            # TODO: use this in function below
            tool_results_raw = (
                BASE_DIR / config.output_dir / f"{dsl}" / "raw" / f"{tool}.json"
            )
            execute_tool_on_bug(
                tool,
                bug_path,
                bug_name,
                config.timeout,
                tool_results_raw,
                tool_registry[tool],
            )

            cleanup_zkbug_environment(bug_path)

            ################################################################
            # Generate ground truth
            ################################################################
            output_ground_truth = (
                BASE_DIR / config.output_dir / "bug_info_ground_truth.json"
            )
            generate_ground_truth(bug_name, bug_path, dsl, output_ground_truth)

            ################################################################
            # Parse raw tool outputs
            ################################################################
            for tool in config.tools[dsl]:
                if tool not in tool_registry:
                    logging.warning(f"Skipping {tool} because it failed to load")
                    continue

                output_structured = (
                    BASE_DIR / config.output_dir / "tool_output_parsed.json"
                )
                parse_tool_output(
                    tool, tool_registry[tool], tool_results_raw, output_structured
                )

                ################################################################
                # Analyze tool results against ground truth
                ################################################################
                output_result = BASE_DIR / config.output_dir / "results.json"
                compare_tool_output_with_zkbugs_ground_truth(
                    tool,
                    tool_registry[tool],
                    bug_name,
                    output_ground_truth,
                    output_structured,
                    output_result,
                )


def remove_first_n_dirs(path, n=5):
    # Normalize path separators
    path_parts = os.path.normpath(path).split(os.sep)
    # Remove the first n parts
    new_path_parts = path_parts[n:]
    # Join the remaining parts back
    return os.path.join(*new_path_parts)


if __name__ == "__main__":
    main()
