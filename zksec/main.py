import argparse
import json
import logging
import os
import re
from multiprocessing import context
from pathlib import Path

import config
from bugs.zkbugs import cleanup as cleanup_zkbug_environment
from bugs.zkbugs import generate_ground_truth
from bugs.zkbugs import setup as setup_zkbug_environment
from config import load_config
from runner import run_tool_on_bug
from tools.circom.circom_civer import compare_zkbugs_ground_truth, parse_output
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
            # TODO: bugname should be sbug_path
            # TODO: Clean up sbug_path
            sbug_path = remove_first_n_dirs(bug, 5)
            bug_name = bug_path.name

            # setup_zkbug_environment(bug_path)

            # for tool in config.tools[dsl]:
            #     if tool not in tool_registry:
            #         logging.warning(f"Skipping {tool} because it failed to load")
            #         continue
            #     run_tool_on_bug(
            #         tool,
            #         bug_path,
            #         bug_name,
            #         config.timeout,
            #         BASE_DIR,
            #         config.output_dir,
            #         tool_registry[tool],
            #         sbug_path
            #     )

            # cleanup_zkbug_environment(bug_path)

            ################################################################
            output_ground_truth = (
                BASE_DIR / config.output_dir / "bug_info_ground_truth.json"
            )
            generate_ground_truth(sbug_path, bug_path, dsl, output_ground_truth)
            #################################################################

            ################################################################
            # Analyze tool results against ground truth
            ################################################################
            # 1. Parse tool results/output to extract buggy components
            for tool in config.tools[dsl]:
                # TODO: This will chaneg when all is written to one file for raw output
                input = BASE_DIR / config.output_dir / f"{dsl}" / "raw" / f"{tool}.json"
                output_structured = (
                    BASE_DIR / config.output_dir / f"{dsl}" / "tool_output_parsed.json"
                )
                # TODO: Make call generic like `run_tool_on_bug`
                if tool == "circom_civer":
                    parse_output(input, output_structured)
                else:
                    logging.error(
                        f"Tool '{tool}' not yet supported for result analysis"
                    )

                # TODO: Make call generic like `run_tool_on_bug`
                # 2. Compare extracted buggy components with ground truth
                result_json = BASE_DIR / config.output_dir / f"{dsl}" / "results.json"
                compare_zkbugs_ground_truth(
                    tool,
                    dsl,
                    ground_truth=output_ground_truth,
                    tool_output=output_structured,
                    output_file=result_json,
                    bug_name=sbug_path,
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
