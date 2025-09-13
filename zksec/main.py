import argparse
import logging
import os
from pathlib import Path
import re
import json

from bugs.zkbugs import cleanup as cleanup_zkbug_environment
from bugs.zkbugs import setup as setup_zkbug_environment
from config import load_config
import config
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
            bug_name = bug_path.name

            # setup_zkbug_environment(bug_path)

            # # TODO: Clean up sbug_path
            # sbug_path = remove_first_n_dirs(bug, 5)

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

            # # TODO: Separate in a different method
            # ################################################################
            # # Generate ground truth JSON
            # ################################################################
            # sbug_path = remove_first_n_dirs(bug, 5)

            # output = BASE_DIR / config.output_dir / f"{dsl}" / "bug_info_raw.json"
            # logging.error(output)

            # readme_file = bug_path / "README.md"
            # logging.error(readme_file)

            # update_bug_info_json(sbug_path, readme_file, output)

            # ################################################################
            # # Analyze tool results against ground truth
            # ################################################################
            # # TODO
            for tool in config.tools[dsl]:
                input = BASE_DIR / config.output_dir / f"{dsl}" / "raw" / f"{tool}.json"
                output_structured = BASE_DIR / config.output_dir / f"{dsl}" / "bug_info_structured.json"
                get_buggy_component_circom_civer(input, output_structured)


def extract_vulnerability_info_from_file(file_path):
    """Extract vulnerability info from a single Markdown file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Patterns
    vuln_pattern = r"\* Vulnerability:\s*(.*)"
    impact_pattern = r"\* Impact:\s*(.*)"
    root_cause_pattern = r"\* Root Cause:\s*(.*)"
    location_pattern = (
        r"\* Location\s*\n"
        r"\s*- Path:\s*(.*)\n"
        r"\s*- Function:\s*(.*)\n"
        r"\s*- Line:\s*(.*)"
    )

    vulnerability = re.search(vuln_pattern, content)
    impact = re.search(impact_pattern, content)
    root_cause = re.search(root_cause_pattern, content)
    location_match = re.search(location_pattern, content)

    if not (vulnerability and impact and root_cause and location_match):
        raise ValueError(f"Required fields not found in {file_path}")

    return {
        "Vulnerability": vulnerability.group(1).strip(),
        "Impact": impact.group(1).strip(),
        "Root Cause": root_cause.group(1).strip(),
        "Location": {
            "Path": location_match.group(1).strip(),
            "Function": location_match.group(2).strip(),
            "Line": location_match.group(3).strip()
        }
    }


# TODO: Clean up sbug_path
def update_bug_info_json(sbug_path, file_path, output_json_path, ) -> None:
    """Update or add a single bug entry in the JSON file."""
    # Extract data
    bug_data = extract_vulnerability_info_from_file(file_path)
    bug_key = sbug_path

    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_json_path), exist_ok=True)

    # Load existing JSON if it exists
    if os.path.exists(output_json_path):
        with open(output_json_path, 'r', encoding='utf-8') as f:
            bug_info = json.load(f)
    else:
        bug_info = {}

    # Determine if created or updated
    action = "updated" if bug_key in bug_info else "created"
    bug_info[bug_key] = bug_data

    # Write back to JSON
    with open(output_json_path, 'w', encoding='utf-8') as f:
        json.dump(bug_info, f, indent=2)

    logging.error(f"Bug entry '{bug_key}' {action} in {output_json_path}")

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
            elif line.startswith("Components with timeout"):
                context = "timeout"
                continue
            elif line.startswith("Components that failed verification"):
                context = "failed"
                continue
            elif line == "" or not line.startswith("-"):
                context = None  # reset context if line irrelevant

            # --- Match component lines only if inside "buggy" context ---
            if context == "buggy" and line.startswith("- "):
                comp_match = re.match(r"-\s*([A-Za-z0-9_]+)\(([\d,\s]+)\)", line)
                if comp_match:
                    comp_name, numbers = comp_match.groups()
                    nums = [int(n.strip()) for n in numbers.split(",")]
                    buggy_components.append({
                        "name": comp_name,
                        "params": nums
                    })

            # --- Stats parsing ---
            if "Number of verified components" in line:
                stats["verified"] = int(re.search(r"(\d+)$", line).group(1))
            elif "Number of failed components" in line:
                stats["failed"] = int(re.search(r"(\d+)$", line).group(1))
            elif "Number of timeout components" in line:
                stats["timeout"] = int(re.search(r"(\d+)$", line).group(1))

        structured_info[bug_name] = {
            "stats": stats,
            "buggy_components": buggy_components
        }

    os.makedirs(os.path.dirname(output_json), exist_ok=True)

    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(structured_info, f, indent=2, ensure_ascii=False)

    print(f"Structured bug info written to {output_json}")






if __name__ == "__main__":
    main()







