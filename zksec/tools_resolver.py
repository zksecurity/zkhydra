import importlib
import logging
from dataclasses import dataclass


@dataclass
class ToolInfo:
    dsl: str
    execute: callable


def resolve_tools(dsl: str, tools: list[str]) -> dict[str, ToolInfo]:
    loaded = {}
    for tool in tools:
        try:
            module = importlib.import_module(f"tools.{dsl}.{tool}")
            execute = getattr(module, "execute")
            if execute is None:
                logging.error(f"{tool} in DSL {dsl} does not have 'execute' function")
                continue
            loaded[tool] = ToolInfo(dsl=dsl, execute=execute)
        except ImportError as e:
            logging.error(f"Failed to import {tool}: {e}")
    return loaded
