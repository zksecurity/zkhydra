import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..utils import (
    change_directory,
    check_files_exist,
    get_tool_result_parsed,
    run_command,
)

TOOL_DIR = Path(__file__).resolve().parent / "pilspector"


def execute(bug_path: str, timeout: int) -> str:
    binary_path = "./target/release/pilspector"

    change_directory(TOOL_DIR)

    cmd = [str(binary_path), "analyse", str(bug_path / "repo" / "pil" / "main.pil")]
    logging.debug(" ".join(cmd))
    result = run_command(cmd, timeout, tool="pilspector", bug=bug_path)

    return result


def parse_output(
    tool_result_raw: Path, _: Path
) -> Dict[str, Dict[str, Dict[str, Dict[str, Any]]]]:
    pass


def compare_zkbugs_ground_truth(
    tool: str, dsl: str, bug_name: str, ground_truth: Path, tool_result_parsed: Path
) -> Dict[str, Any]:
    pass
