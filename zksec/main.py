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
            output = BASE_DIR / config.output_dir / "bug_info_ground_truth.json"
            generate_ground_truth(sbug_path, bug_path, dsl, output)
            #################################################################

            # ################################################################
            # # Analyze tool results against ground truth
            # ################################################################
            # TODO: 1. Parse tool results/output to extract buggy components
            # for tool in config.tools[dsl]:
            #     input = BASE_DIR / config.output_dir / f"{dsl}" / "raw" / f"{tool}.json"
            #     output_structured = BASE_DIR / config.output_dir / f"{dsl}" / "tool_output_parsed.json"
            #     # if tool == 'circom_civer': get_buggy_component_circom_civer(input, output_structured)
            #     # else:
            #     #     logging.error(f"Tool '{tool}' not yet supported for result analysis")

            #     # TODO: 2. Compare extracted buggy components with ground truth
            #     result_json = BASE_DIR / config.output_dir / f"{dsl}" / "results.json"
            #     compare_tool_output_with_ground_truth(tool, ground_truth=output, tool_output=output_structured, output_file=result_json, bug_name=sbug_path)


def remove_first_n_dirs(path, n=5):
    # Normalize path separators
    path_parts = os.path.normpath(path).split(os.sep)
    # Remove the first n parts
    new_path_parts = path_parts[n:]
    # Join the remaining parts back
    return os.path.join(*new_path_parts)


def get_buggy_component_circom_civer(input_json: Path, output_json: Path) -> None:
    with open(input_json, "r", encoding="utf-8") as f:
        bug_info = json.load(f)

    structured_info = {}

    for bug_name, lines in bug_info.items():
        stats = {"verified": None, "failed": None, "timeout": None}
        buggy_components = []

        context = None  # track section

        for raw_line in lines:
            line = raw_line.strip().rstrip(",")

            # --- Track context (which section we are in) ---
            if line.startswith("Components that do not satisfy weak safety"):
                context = "buggy"
                continue
            elif line.startswith("Components timeout when checking weak-safety"):
                context = "timeout"
                continue
            # TODO: verify string
            elif line.startswith("Components that failed verification"):
                context = "failed"
                continue
            elif line == "":
                context = None  # reset only on empty line

            # --- Match component lines only if inside "buggy" context ---
            if context == "buggy" and line.startswith("-"):
                comp_match = re.match(r"-\s*([A-Za-z0-9_]+)\(([\d,\s]*)\)", line)
                if comp_match:
                    comp_name, numbers = comp_match.groups()
                    nums = [int(n.strip()) for n in numbers.split(",") if n.strip()]
                    buggy_components.append({"name": comp_name, "params": nums})

            # --- Stats parsing ---
            if "Number of verified components" in line:
                stats["verified"] = int(re.search(r"(\d+)$", line).group(1))
            elif "Number of failed components" in line:
                stats["failed"] = int(re.search(r"(\d+)$", line).group(1))
            elif "Number of timeout components" in line:
                stats["timeout"] = int(re.search(r"(\d+)$", line).group(1))

        # TODO: make generic in a different method
        if "circom" not in structured_info:
            structured_info["circom"] = {}
        if "circom_civer" not in structured_info["circom"]:
            structured_info["circom"]["circom_civer"] = {}

        structured_info["circom"]["circom_civer"][bug_name] = {
            "stats": stats,
            "buggy_components": buggy_components,
        }

    os.makedirs(os.path.dirname(output_json), exist_ok=True)

    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(structured_info, f, indent=2, ensure_ascii=False)

    print(f"Structured bug info written to {output_json}")


def compare_tool_output_with_ground_truth(
    tool: str, ground_truth: Path, tool_output: Path, output_file: Path, bug_name: str
) -> None:
    # Load existing output or initialize
    if os.path.exists(output_file):
        with open(output_file, "r", encoding="utf-8") as f:
            output = json.load(f)
    else:
        output = {"circom": {}}

    # Ensure tool entry exists
    output.setdefault("circom", {}).setdefault(tool, {}).setdefault("correct", [])
    output.setdefault("circom", {}).setdefault(tool, {}).setdefault("false", [])

    # Get ground truth data
    with open(ground_truth, "r", encoding="utf-8") as f:
        ground_truth_data = json.load(f)

    bug_location = ground_truth_data.get(bug_name, {}).get("Location", {})
    if not bug_location:
        logging.error(f"Location data for bug '{bug_name}' not found in ground truth.")
        return

    buggy_function = bug_location.get("Function")
    buggy_line = bug_location.get("Line")
    if "-" in buggy_line:
        startline, endline = map(int, buggy_line.split("-", 1))
    else:
        startline = endline = int(buggy_line)
    logging.error(
        f"Buggy function: {buggy_function}, startline: {startline}, endline: {endline}"
    )

    # Get tool output data
    with open(tool_output, "r", encoding="utf-8") as f:
        tool_output_data = json.load(f)

    buggy_components = (
        tool_output_data.get("circom", {})
        .get(tool, {})
        .get(bug_name, {})
        .get("buggy_components", [])
    )

    is_correct = False
    for component in buggy_components:
        comp_name = component.get("name")
        comp_params = component.get("params", [])
        logging.error(
            f"Found buggy component in '{bug_name}': {comp_name} with params {comp_params}"
        )

        params = component.get("params", [])
        if not params:
            startline_tool = endline_tool = 0
        elif len(params) == 1:
            startline_tool = endline_tool = params[0]
        elif len(params) == 2:
            startline_tool = params[0]
            endline_tool = params[1]
        else:
            raise ValueError("params should have at most 2 values")
        logging.error(
            f"Component lines: startline={startline_tool}, endline={endline_tool}"
        )

        # Compare with ground truth
        if comp_name == buggy_function:
            logging.error(f"Component name matches buggy function: {comp_name}")

            # Check lines
            if startline_tool == endline_tool == 0:
                logging.error(f"Component lines not provided by tool")
                is_correct = True
            if startline_tool <= startline and endline_tool >= endline:
                logging.error(
                    f"Component lines match ground truth: startline={startline_tool}, endline={endline_tool}"
                )
                is_correct = True
            else:
                logging.error(
                    f"Component lines do not match ground truth: startline={startline_tool}, endline={endline_tool}"
                )

        logging.warning(f"Component '{comp_name}' correctness: {is_correct}")

    if is_correct:
        if bug_name not in output["circom"][tool]["correct"]:
            output["circom"][tool]["correct"].append(bug_name)
    else:
        reason = ""
        if not buggy_components:
            reason = "tool found no module"
        elif comp_name != buggy_function:
            reason = f"tool found wrong module (tool found: {comp_name}; buggy module: {buggy_function})"
        else:
            reason = f"tool found correct module, but lines didn't match (tool found lines: {startline_tool}-{endline_tool}; buggy lines: {startline}-{endline})"

        # Append dictionary with reason
        output["circom"][tool]["false"].append({"bug_name": bug_name, "reason": reason})

    # Update counts dynamically
    output["circom"][tool]["count"] = {
        "correct": len(output["circom"][tool]["correct"]),
        "false": len(output["circom"][tool]["false"]),
    }

    # Write back to file
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4)


if __name__ == "__main__":
    main()
