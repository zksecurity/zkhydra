import subprocess
import logging
import shlex
from pathlib import Path
import os

def run_command(cmd: list[str], timeout: int, tool: str, bug: str) -> subprocess.CompletedProcess | str:
    logging.debug(f"Running: {shlex.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout
        )
        return result

    except subprocess.TimeoutExpired as e:
        logging.error(
            f"Process for '{tool}' analysing '{bug}' exceeded {timeout} seconds and timed out. Partial output: {e.stdout}"
        )
        return "[Timed out]"

    except subprocess.CalledProcessError as e:
        logging.error(
            f"Process for '{tool}' analysing '{bug}' failed with return code {e.returncode}. Error output: {e.stderr}"
        )
        return "[Failed]"

def change_directory(target_dir: Path) -> None:
    os.chdir(target_dir)
    logging.debug(f"Changed directory to: {Path.cwd()}")

def check_files_exist(*files: Path) -> bool:
    for f in files:
        file_path = Path(f)
        if file_path.is_file():
            logging.debug(f"Found file: {file_path}")
        else:
            logging.error(f"File not found: {file_path}")
            return False
    return True