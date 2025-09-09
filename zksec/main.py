import argparse
import logging
import os
import tomllib
import importlib
from pathlib import Path
from bugs.zkbugs import setup as setup_zkbug
from bugs.zkbugs import cleanup as cleanup_zkbug


BASE_DIR = Path.cwd()
REPO_DIR = BASE_DIR.parent
VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
TOOL_LIST = {
    ("circom", "circom_civer"),
    ("circom", "circomspect",),
    ("circom", "ecneproject",),
    ("circom", "picus",),
    ("circom", "zkfuzz",),
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Tool runner with config file support"
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config.toml"),
        help="Path to the configuration file (default: config.toml)"
    )
    return parser.parse_args()


def read_lines(file_path: Path):
    with file_path.open("r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]


def configuration(path: Path = Path("config.toml")) -> tuple[list[str], list[str], Path]:
    # Verify config file exists
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    # Load config file
    with open(path, "rb") as f:
        config = tomllib.load(f)

    # Validate log level
    log_level = config.get("log_level", "WARNING").upper()
    if log_level not in VALID_LOG_LEVELS:
        raise ValueError(
            f"Config error: Invalid log_level '{log_level}'. "
            f"Must be one of {', '.join(VALID_LOG_LEVELS)}."
        )

    # Setup logging
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s: [%(filename)s:%(lineno)d]: \t[%(levelname)s]: \t%(message)s",
        datefmt="%H:%M:%S"
    )

    # Validate tools & bugs
    tools = config.get("tools", [])
    bugs = config.get("bugs", [])
    if not tools:
        raise ValueError("Config error: 'tools' list must not be empty.")
    if not bugs:
        raise ValueError("Config error: 'bugs' list must not be empty.")

    # Ensure output directory exists
    output_dir = Path(config.get("output", "./output"))
    output_dir.mkdir(parents=True, exist_ok=True)

    timeout = config.get("timeout", 300)

    return tools, bugs, output_dir, timeout


def main():
    args = parse_args()
    tools, bugs, output_dir, timeout = configuration(args.config)

    # Dynamically import execute functions and store in a dict
    tool_functions = {}
    for tool_name in TOOL_LIST:
        module = importlib.import_module(f"tools.{tool_name}")
        tool_functions[tool_name] = getattr(module, "execute")

    for bug in bugs:
        bug_path = REPO_DIR / bug
        bug_name = bug_path.name

        # Setup bug environment
        setup_zkbug(bug_path)

        for tool in tools:
            tool_key = tool.lower()
            output = Path(BASE_DIR) / output_dir / f"{tool_key}.log"

            if tool_key in tool_functions:
                logging.info(f"Running {tool=} on {bug_name=}")
                result = tool_functions[tool_key](bug_path, timeout)
                write_output(output, tool_key, bug_name, result)
        
        # Cleanup bug environment
        cleanup_zkbug(bug_path)


def write_output(output_file: Path, tool: str, bug_name: str, content: str):
    logging.info(f"Writing {tool} results for {bug_name} to '{output_file}'")
    # Check if file exists
    if not os.path.exists(output_file):
        logging.debug(f"Output file does not exist. Creating: {output_file}")
        # Create the file
        with open(output_file, 'w') as f:
            pass  # Create an empty file
            
    # Write the output to the file
    with open(output_file, 'a') as f:
        f.write(f"========== {bug_name} ==========\n")
        f.write(str(content))
        f.write("\n\n")


if __name__ == "__main__":
    main()
