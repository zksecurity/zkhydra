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
    setup_logging(log_level)

    tools, bugs = parse_dsl_sections(config)

    output_dir = Path(config["app"].get("output", "./output"))
    ensure_dir(output_dir)

    timeout = int(config["app"].get("timeout", 300))

    return AppConfig(
        tools=tools,
        bugs=bugs,
        output_dir=output_dir,
        timeout=timeout,
        log_level=log_level,
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
