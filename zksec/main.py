import argparse
from json import tool
import logging
import os

from pathlib import Path

from bugs.zkbugs import setup as setup_zkbug
from bugs.zkbugs import cleanup as cleanup_zkbug

from tools.circomspect import execute as execute_circomspect
# from tools.coda import execute as execute_coda
from tools.picus import execute as execute_picus
from tools.zkfuzz import execute as execute_zkfuzz


BASE_DIR = Path.cwd()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run bugs with specified tools and store outputs."
    )
    parser.add_argument("--bugs", required=True, help="Path to input-bugs.txt")
    parser.add_argument("--tools", required=True, help="Path to input-tools.txt")
    parser.add_argument("--output", required=True, help="Output directory")
    return parser.parse_args()


def read_lines(file_path: Path):
    with file_path.open("r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def main():
    args = parse_args()

    bugs_file = Path(args.bugs)
    tools_file = Path(args.tools)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    bugs = read_lines(bugs_file)
    tools = read_lines(tools_file)

    for bug in bugs:
        bug_path = Path(bug)
        bug_name = bug_path.name
        bug_output = Path(BASE_DIR) / output_dir / f"{bug_name}.log"
        logging.debug(f"{bug_name=}")

        # Setup bug environment
        setup_zkbug(bug_path)

        for tool in tools:
            if tool.lower() == "circomspect":
                logging.info(f"Running {tool=} on {bug_name=}")
                result = execute_circomspect(bug_path)
                write_output(bug_output, tool, result)
            # if tool.lower() == "coda":
            #     logging.info(f"Running {tool=} on {bug_name=}")
            #     result = execute_coda(bug_path)
                write_output(bug_output, tool, result)
            if tool.lower() == "picus":
                logging.info(f"Running {tool=} on {bug_name=}")
                result = execute_picus(bug_path)
                write_output(bug_output, tool, result)
            if tool.lower() == "zkfuzz":
                logging.info(f"Running {tool=} on {bug_name=}")
                result = execute_zkfuzz(bug_path)
                write_output(bug_output, tool, result)

        # Cleanup bug environment
        cleanup_zkbug(bug_path)


def write_output(output_file: Path, tool: str, content: str):
    logging.info(f"Writing {tool} results to '{output_file}'")
    # Check if file exists
    if not os.path.exists(output_file):
        logging.debug(f"Output file does not exist. Creating: {output_file}")
        # Create the file
        with open(output_file, 'w') as f:
            pass  # Create an empty file

    # Write the output to the file
    with open(output_file, 'a') as f:
        f.write(f"=== {tool} ===\n")
        f.write(str(content))
        f.write("\n\n")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s: [%(filename)s:%(lineno)d]: \t[%(levelname)s]: \t%(message)s",
        datefmt="%H:%M:%S"
    )
    main()
