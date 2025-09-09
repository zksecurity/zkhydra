import logging
from pathlib import Path
from ..utils import run_command, change_directory, check_files_exist


TOOL_DIR = Path(__file__).resolve().parent / "ecneproject"


def execute(bug_path: str, timeout: int) -> str:
    logging.debug(f"ECNEPROJECT_DIR='{TOOL_DIR}'")
    logging.debug(f"bug_path='{bug_path}'")
    
    circuit_file = Path(bug_path) / "circuits" / "circuit.circom"
    r1cs_file    = Path(bug_path) / "circuit.r1cs"
    sym_file     = Path(bug_path) / "circuit.sym"
    if not check_files_exist(circuit_file, r1cs_file, sym_file):
        return "[Circuit file not found]"

    change_directory(TOOL_DIR)
    
    cmd = ["julia", "--project=.", "src/Ecne.jl", "--r1cs", str(r1cs_file), "--name", "circuit", "--sym", str(sym_file)]
    result = run_command(cmd, timeout, tool="ecneproject", bug=bug_path)

    return result


def parse_output(file: str) -> str:
    logging.warning("Not implemented.")
    