import importlib
import logging
from dataclasses import dataclass
from typing import Any, Callable, Dict, List


@dataclass
class ToolInfo:
    dsl: str
    execute: Callable[..., Any]
    parse_output: Callable[..., Any]
    compare_zkbugs_ground_truth: Callable[..., Any]


def resolve_tools(dsl: str, tools: List[str]) -> Dict[str, ToolInfo]:
    """Dynamically import tool modules for a DSL and return callables metadata."""
    loaded: Dict[str, ToolInfo] = {}
    for tool in tools:
        module_path = f"tools.{dsl}.{tool}"
        try:
            module = importlib.import_module(module_path)
        except ImportError as e:
            logging.error(f"Failed to import module '{module_path}': {e}")
            continue

        try:
            execute = getattr(module, "execute")
            parse_output = getattr(module, "parse_output")
            compare = getattr(module, "compare_zkbugs_ground_truth")
        except AttributeError as e:
            logging.error(f"Missing required functions in '{module_path}': {e}")
            continue

        if not callable(execute):
            logging.error(f"{module_path}: 'execute' is not callable")
            continue
        if not callable(parse_output):
            logging.error(f"{module_path}: 'parse_output' is not callable")
            continue
        if not callable(compare):
            logging.error(
                f"{module_path}: 'compare_zkbugs_ground_truth' is not callable"
            )
            continue

        loaded[tool] = ToolInfo(
            dsl=dsl,
            execute=execute,
            parse_output=parse_output,
            compare_zkbugs_ground_truth=compare,
        )

    return loaded
