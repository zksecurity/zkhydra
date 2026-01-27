"""
Tool resolution system for zkHydra.

This module provides a simple registry-based system for resolving tools by name.
All tools are registered in a central TOOL_REGISTRY lookup table.
"""

import logging

from zkhydra.tools.base import AbstractTool

# Import all tool instances
from zkhydra.tools.circom_civer import _circom_civer_instance
from zkhydra.tools.circomspect import _circomspect_instance
from zkhydra.tools.ecneproject import _ecneproject_instance
from zkhydra.tools.picus import _picus_instance
from zkhydra.tools.zkfuzz import _zkfuzz_instance

# Tool registry: maps tool names to their singleton instances
TOOL_REGISTRY: dict[str, AbstractTool] = {
    "circomspect": _circomspect_instance,
    "circom_civer": _circom_civer_instance,
    "zkfuzz": _zkfuzz_instance,
    "picus": _picus_instance,
    "ecneproject": _ecneproject_instance,
    # Add other tools here as they are refactored
}


def resolve_tools(tools: list[str]) -> dict[str, AbstractTool]:
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

        tool_instance = TOOL_REGISTRY[tool_name]
        loaded[tool_name] = tool_instance
        logging.debug(
            f"Resolved {tool_name} -> {tool_instance.__class__.__name__}"
        )

    return loaded


def get_available_tools() -> list[str]:
    """Get list of all available tool names.

    Returns:
        Sorted list of tool names registered in the system
    """
    return sorted(TOOL_REGISTRY.keys())
