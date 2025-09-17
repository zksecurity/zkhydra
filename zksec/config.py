import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

from logger import setup_logging
from tools.utils import ensure_dir


@dataclass
class AppConfig:
    tools: Dict[str, List[str]]
    bugs: Dict[str, List[str]]
    output_dir: Path
    timeout: int
    log_level: str
    setup_bug_environment: bool
    execute_tools: bool
    cleanup_bug_environment: bool
    generate_ground_truth: bool
    parse_raw_tool_output: bool
    analyze_tool_results: bool


def load_config(
    path: Path = Path("config.toml"),
) -> AppConfig:
    # Verify config file exists
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    # Load config file
    with open(path, "rb") as f:
        config = tomllib.load(f)

    log_level = config["app"].get("log_level", "WARNING").upper()

    output_dir = Path(config["app"].get("output", "./output"))
    ensure_dir(output_dir)

    file_logging = config["app"].get("file_logging", False)
    setup_logging(log_level, output_dir, file_logging)

    tools, bugs = parse_dsl_sections(config)

    output_dir = Path(config["app"].get("output", "./output"))
    ensure_dir(output_dir)

    timeout = int(config["app"].get("timeout", 300))

    setup_bug_environment = config["app"].get("setup_bug_environment", True)
    execute_tools = config["app"].get("execute_tools", True)
    cleanup_bug_environment = config["app"].get("cleanup_bug_environment", True)
    generate_ground_truth = config["app"].get("generate_ground_truth", True)
    parse_raw_tool_output = config["app"].get("parse_raw_tool_output", True)
    analyze_tool_results = config["app"].get("analyze_tool_results", True)

    return AppConfig(
        tools=tools,
        bugs=bugs,
        output_dir=output_dir,
        timeout=timeout,
        log_level=log_level,
        setup_bug_environment=setup_bug_environment,
        execute_tools=execute_tools,
        cleanup_bug_environment=cleanup_bug_environment,
        generate_ground_truth=generate_ground_truth,
        parse_raw_tool_output=parse_raw_tool_output,
        analyze_tool_results=analyze_tool_results,
    )


def parse_dsl_sections(config: dict) -> dict[str, dict]:
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
