import argparse
import logging
from pathlib import Path

from bugs.zkbugs import cleanup as cleanup_zkbug_environment
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
            bug_name = bug_path.name

            setup_zkbug_environment(bug_path)

            for tool in config.tools[dsl]:
                if tool not in tool_registry:
                    logging.warning(f"Skipping {tool} because it failed to load")
                    continue
                run_tool_on_bug(
                    tool,
                    bug_path,
                    bug_name,
                    config.timeout,
                    BASE_DIR,
                    config.output_dir,
                    tool_registry[tool],
                )

            cleanup_zkbug_environment(bug_path)


if __name__ == "__main__":
    main()
