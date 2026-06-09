"""
Tool resolution system for zkHydra.

This module provides a simple registry-based system for resolving tools by name.
All tools are registered in a central TOOL_REGISTRY lookup table.
"""

import logging

from zkhydra.tools.base import AbstractTool

# Import all tool instances
from zkhydra.tools.circom_civer import CircomCiver
from zkhydra.tools.circomspect import Circomspect
from zkhydra.tools.conscs import ConsCS
from zkhydra.tools.ecneproject import EcneProject
from zkhydra.tools.picus import Picus
from zkhydra.tools.zkfuzz import ZkFuzz

# Type alias for tools dictionary (for clarity in type hints)
type ToolsDict = dict[str, AbstractTool]


TOOL_REGISTRY: ToolsDict = {
    "circomspect": Circomspect,
    "circom_civer": CircomCiver,
    "conscs": ConsCS,
    "zkfuzz": ZkFuzz,
    "picus": Picus,
    "ecneproject": EcneProject,
    # Add other tools here as they are refactored
}


def resolve_tools(tools: list[str]) -> ToolsDict:
    """Resolve tool names to their singleton instances.

    Args:
        tools: List of tool names to resolve

    Returns:
        Dictionary mapping tool names to their AbstractTool instances

    Note:
        Tools that are not found in the registry will be logged as errors
        and skipped from the returned dictionary.
    """
    loaded: dict[str, AbstractTool] = {}

    for tool_name in tools:
        logging.debug(f"Resolving tool: {tool_name}")

        if tool_name not in TOOL_REGISTRY:
            logging.error(
                f"Tool '{tool_name}' not found in registry. "
                f"Available tools: {list(TOOL_REGISTRY.keys())}"
            )
            continue

        loaded[tool_name] = TOOL_REGISTRY[tool_name]()
        logging.debug(
            f"Resolved {tool_name} -> {loaded[tool_name].__class__.__name__}"
        )

    return loaded


def get_available_tools() -> list[str]:
    """Get list of all available tool names.

    Returns:
        Sorted list of tool names registered in the system
    """
    return sorted(TOOL_REGISTRY.keys())
