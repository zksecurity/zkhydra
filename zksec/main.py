import argparse
import logging
import tomllib
import importlib
from pathlib import Path
from bugs.zkbugs import setup as setup_zkbug_environment
from bugs.zkbugs import cleanup as cleanup_zkbug_environment


BASE_DIR = Path.cwd()
REPO_DIR = BASE_DIR.parent
VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}

CAIRO = "cairo"
CIRCOM = "circom"
GNARK = "gnark"
HALO2 = "halo2"
PIL = "pil"

TOOL_LIST = [
    (CIRCOM, "circom_civer"),
    (CIRCOM, "circomspect"),
    (CIRCOM, "ecneproject"),
    (CIRCOM, "picus"),
    (CIRCOM, "zkfuzz"),
]


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
    log_level = config["app"].get("log_level", "WARNING").upper()
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

    tools, bugs = parse_dsl_sections(config)

    # Ensure output directory exists
    output_dir = Path(config["app"].get("output", "./output"))
    output_dir.mkdir(parents=True, exist_ok=True)

    timeout = config["app"].get("timeout", 300)

    # make: bugs or tools::dsl::name as two vars
    # return dsl_tools_bugs, output_dir, timeout
    return tools, bugs, output_dir, timeout


def parse_dsl_sections(config: dict) -> dict[str, dict]:
    # dsl_sections = {}
    tools = {}
    bugs = {}
    for dsl, section in config.items():
        if dsl == "app":
            continue
        tools[dsl] = [t.lower() for t in section.get("tools", [])]
        bugs[dsl] = section.get("bugs", [])
        
        if not tools[dsl]:
            raise ValueError("Config error: 'tools' list must not be empty.")
        if not bugs[dsl]:
            raise ValueError("Config error: 'bugs' list must not be empty.")
    return tools, bugs


def resolve_tools(tools: list[str]) -> dict[str, dict]:
    loaded = {}
    for dsl, tool in TOOL_LIST:
        if tool not in tools: continue
        try:
            module = importlib.import_module(f"tools.{dsl}.{tool}")
            loaded[tool] = {
                "dsl": dsl,
                "execute": getattr(module, "execute")
            }
        except ImportError as e:
            logging.error(f"Failed to import {tool}: {e}")
    return loaded


def run_tool_on_bug(tool: str,
                    bug_path: Path,
                    bug_name: str,
                    timeout: int,
                    output_dir: Path,
                    tool_registry: dict[str, dict]
                    ) -> None:
    dsl = tool_registry[tool]["dsl"]
    execute_fn = tool_registry[tool]["execute"]
    output = Path(BASE_DIR) / output_dir / f"{dsl}" / "raw" / f"{tool}.log"
    logging.info(f"Running {tool=} on {bug_name=}")
    result = execute_fn(bug_path, timeout)
    write_output(output, tool, bug_name, result)


def write_output(output_file: Path, tool: str, bug_name: str, content: str):
    logging.info(f"Writing {tool} results for {bug_name} to '{output_file}'")

    # Ensure the parent directory exists
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # Write the output to the file
    with open(output_file, 'a') as f:
        f.write(f"========== {bug_name} ==========\n")
        f.write(str(content))
        f.write("\n\n")


def main():
    args = parse_args()

    tools, bugs, output_dir, timeout = configuration(args.config)

    for dsl in tools:
        tool_registry = resolve_tools(tools[dsl])

        for bug in bugs[dsl]:
            bug_path = REPO_DIR / bug
            bug_name = bug_path.name

            setup_zkbug_environment(bug_path)

            for tool in tools[dsl]:
                run_tool_on_bug(tool, bug_path, bug_name, timeout, output_dir, tool_registry)

            cleanup_zkbug_environment(bug_path)


if __name__ == "__main__":
    main()
