import importlib
import logging
from dataclasses import dataclass


@dataclass
class ToolInfo:
    dsl: str
    execute: callable
    parse_output: callable
    compare_zkbugs_ground_truth: callable


def resolve_tools(dsl: str, tools: list[str]) -> dict[str, ToolInfo]:
    loaded = {}
    for tool in tools:
        try:
            module = importlib.import_module(f"tools.{dsl}.{tool}")
            execute = getattr(module, "execute")
            parse_output = getattr(module, "parse_output")
            compare_zkbugs_ground_truth = getattr(module, "compare_zkbugs_ground_truth")
            if execute is None:
                logging.error(f"{tool} in DSL {dsl} does not have 'execute' function")
                continue
            if parse_output is None:
                logging.error(
                    f"{tool} in DSL {dsl} does not have 'parse_output' function"
                )
                continue
            if compare_zkbugs_ground_truth is None:
                logging.error(
                    f"{tool} in DSL {dsl} does not have 'compare_zkbugs_ground_truth' function"
                )
                continue
            loaded[tool] = ToolInfo(
                dsl=dsl,
                execute=execute,
                parse_output=parse_output,
                compare_zkbugs_ground_truth=compare_zkbugs_ground_truth,
            )
        except ImportError as e:
            logging.error(f"Failed to import {tool}: {e}")
    return loaded
