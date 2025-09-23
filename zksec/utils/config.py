import tomllib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

from tools.utils import ensure_dir

from .logger import setup_logging


@dataclass
class AppConfig:
    tools: Dict[str, List[str]]
    bugs: Dict[str, List[str]]
    output_dir: Path
    timeout: int
    log_level: str
    log_level_file: str
    dynamic_name: bool
    static_name: str
    setup_bug_environment: bool
    execute_tools: bool
    cleanup_bug_environment: bool
    generate_ground_truth: bool
    parse_raw_tool_output: bool
    analyze_tool_results: bool
    summarize_tool_results: bool


def load_config(
    path: Path = Path("config.toml"),
    base_dir: Path = Path.cwd(),
) -> AppConfig:
    """Load the TOML configuration and return an AppConfig instance.

    Validates presence of the `app` section, creates the output directory,
    and configures logging according to settings.
    """
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path, "rb") as f:
        config: Dict[str, Any] = tomllib.load(f)

    app_section = config.get("app")
    if not isinstance(app_section, dict):
        raise ValueError("Config error: missing or invalid 'app' section")

    log_level = str(app_section.get("log_level", "WARNING")).upper()
    log_level_file = str(app_section.get("log_level_file", "WARNING")).upper()

    output_dir = Path(app_section.get("output", "./output"))
    dynamic_name = bool(app_section.get("dynamic_name", False))

    if dynamic_name:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        output_dir = base_dir / output_dir / f"zksec_{timestamp}"
    else:
        static_name = app_section.get("static_name", "zksec")
        output_dir = base_dir / output_dir / static_name

    ensure_dir(output_dir)

    file_logging = bool(app_section.get("file_logging", False))
    setup_logging(log_level, log_level_file, output_dir, file_logging)

    tools, bugs = parse_dsl_sections(config)

    # Timeout must be a positive integer
    timeout = int(app_section.get("timeout", 300))
    if timeout <= 0:
        raise ValueError("Config error: 'timeout' must be a positive integer")

    setup_bug_environment = bool(app_section.get("setup_bug_environment", True))
    execute_tools = bool(app_section.get("execute_tools", True))
    cleanup_bug_environment = bool(app_section.get("cleanup_bug_environment", True))
    generate_ground_truth = bool(app_section.get("generate_ground_truth", True))
    parse_raw_tool_output = bool(app_section.get("parse_raw_tool_output", True))
    analyze_tool_results = bool(app_section.get("analyze_tool_results", True))
    summarize_tool_results = bool(app_section.get("summarize_tool_results", True))

    return AppConfig(
        tools=tools,
        bugs=bugs,
        output_dir=output_dir,
        timeout=timeout,
        log_level=log_level,
        log_level_file=log_level_file,
        dynamic_name=dynamic_name,
        static_name=static_name,
        setup_bug_environment=setup_bug_environment,
        execute_tools=execute_tools,
        cleanup_bug_environment=cleanup_bug_environment,
        generate_ground_truth=generate_ground_truth,
        parse_raw_tool_output=parse_raw_tool_output,
        analyze_tool_results=analyze_tool_results,
        summarize_tool_results=summarize_tool_results,
    )


def parse_dsl_sections(
    config: dict,
) -> Tuple[Dict[str, List[str]], Dict[str, List[str]]]:
    """Extract DSL sections from config to build tools and bugs maps.

    Returns a tuple: (tools, bugs)
      - tools[dsl] -> list of tool names (lowercased)
      - bugs[dsl] -> list of bug names
    """
    tools: Dict[str, List[str]] = {}
    bugs: Dict[str, List[str]] = {}
    for dsl, section in config.items():
        if dsl == "app":
            continue
        if not isinstance(section, dict):
            raise ValueError(f"Config error: section for '{dsl}' must be a table")

        tools_list = section.get("tools", [])
        bugs_list = section.get("bugs", [])

        tools[dsl] = [str(t).lower() for t in tools_list]
        bugs[dsl] = [str(b) for b in bugs_list]

        if not tools[dsl]:
            raise ValueError("Config error: 'tools' list must not be empty.")
        if not bugs[dsl]:
            raise ValueError("Config error: 'bugs' list must not be empty.")
    return tools, bugs
