import argparse
import subprocess
from pathlib import Path
import os


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


def setup_bug_environment(bug_path: Path):
    """
    Run setup and compile scripts inside the bug directory if they exist.
    """
    base_dir = Path.cwd()
    print(f"[Base Dir] {base_dir}")

    ## Generate PTAU file
    ## TODO: Make this more automatic, and delete file in the end again
    # os.chdir("./bugs/zkbugs/scripts")
    # ptau_script = Path("generate_ptau_snarkjs.sh")
    # if ptau_script.exists():
    #     print(f"[SETUP] Generating PTAU file using script: {ptau_script} bn128 12")
    #     subprocess.run(["bash", str(ptau_script), "bn128", "12"], check=True)
    # else:
    #     print(f"[SETUP] PTAU generation script not found at {ptau_script}, skipping.")


    os.chdir(base_dir)
    os.chdir(bug_path)

    setup_script = Path("zkbugs_setup.sh")
    compile_script = Path("zkbugs_compile_setup.sh")

    if setup_script.exists():
        print(f"[SETUP] Running setup script: {bug_path / setup_script}")
        subprocess.run(["bash", str(setup_script)], check=True)
    else:
        print(f"[SETUP] No setup script found at {setup_script}, skipping.")

    if compile_script.exists():
        print(f"[SETUP] Running compile script: {compile_script}")
        subprocess.run(["bash", str(compile_script)], check=True)
    else:
        print(f"[SETUP] No compile script found at {compile_script}, skipping.")

    os.chdir(base_dir)

def cleanup_bug_environment(bug_path: Path):
    """
    Run cleanup script inside the bug directory if it exists.
    """
    base_dir = Path.cwd()
    os.chdir(bug_path)
    cleanup_script = Path("zkbugs_clean.sh")

    if cleanup_script.exists():
        print(f"[CLEANUP] Running cleanup script: {cleanup_script}")
        subprocess.run(["bash", str(cleanup_script)], check=True)
    else:
        print(f"[CLEANUP] No cleanup script found at {cleanup_script}, skipping.")

    os.chdir(base_dir)

def run_tools_on_bug(bug_path: Path, tools: list[str], output_file: Path):
    """
    Run each tool on the bug's circuit (assume circuit file is bug_path/circuit).
    Write tool outputs to the output file.
    """
    base_dir = Path.cwd()
    os.chdir(bug_path)

    circuit_file = Path("./circuits/circuit.circom")
    if not circuit_file.exists():
        raise FileNotFoundError(f"Circuit file not found: {circuit_file}")

    if "Picus" in tools or "picus" in tools:
        print(f"[TOOL] Running Picus on {circuit_file}")
        subprocess.run(["./tools/Picus/run-picus", str(circuit_file)], check=True)
    elif "Test" in tools or "test" in tools:
        print(f"[TOOL] Running Test on {circuit_file}")


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

        print(f"\n=== Processing bug: {bug_name} ===")

        # Setup bug environment
        setup_bug_environment(bug_path)

        # Run tools and write outputs
        run_tools_on_bug(bug_path, tools, bug_output)
        print(f"[DONE] Results written to {bug_output}")

        # Cleanup
        cleanup_bug_environment(bug_path)


if __name__ == "__main__":
    main()
