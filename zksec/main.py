import argparse
import logging
from pathlib import Path

from bugs.zkbugs import setup as setup_zkbug
from bugs.zkbugs import cleanup as cleanup_zkbug 
from tools.picus import execute as execute_picus


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
        bug_output = output_dir / f"{bug_name}.log"
        logging.debug(f"{bug_name=}")

        # Setup bug environment
        setup_zkbug(bug_path)

        for tool in tools:
            if tool.lower() == "picus":
                logging.info(f"Running {tool=} on {bug_name=}")
                execute_picus(bug_path)
                logging.info(f"Writing {tool} results to '{bug_output}'")
                # TODO: Write results to file

        # Cleanup bug environment
        cleanup_zkbug(bug_path)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s: [%(filename)s]: \t[%(levelname)s]: \t%(message)s",
        datefmt="%H:%M:%S"
    )
    main()
