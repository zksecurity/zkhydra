# zkHydra

A tool runner framework for zero-knowledge circuit security analysis. zkHydra orchestrates multiple security analysis tools and provides two operational modes:

- **Analyze Mode**: Run security tools on any circuit and get findings
- **Evaluate Mode**: Compare tool results against ground truth for accuracy evaluation

## Supported Tools

- **circomspect** - Static analyzer and linter for Circom circuits
- **circom_civer** - Static analysis using CVC5 SMT solver backend
- **Picus** - Symbolic execution tool using Rosette
- **EcneProject** - Julia-based circuit analysis framework
- **zkFuzz** - Fuzzing tool for Circom circuits

## Installation

### Option 1: Native Installation (Ubuntu 24.04)

```bash
./setup.sh
```

This initializes git submodules, installs uv, sets up Rust toolchain, and builds all tools.

### Option 2: Docker

```bash
# Build the Docker image (takes 30-60 minutes)
docker-compose build

# Run interactively
docker-compose run --rm zkhydra bash
```

## Usage

zkHydra has two modes: **analyze** and **evaluate**.

### Analyze Mode

Analyze a circuit file with one or more tools. Does not require ground truth.

**Synopsis:**
```bash
uv run python -m zkhydra.main analyze --input <circuit.circom> --tools <tool1,tool2,...> [options]
```

**Output:**
- Summary of findings per tool
- Total analysis time per tool
- One-liner list of findings
- Raw tool outputs
- JSON summary file

**Examples:**

```bash
# Analyze with a single tool
uv run python -m zkhydra.main analyze --input test_bug/circuits/circuit.circom --tools circomspect

# Analyze with multiple tools
uv run python -m zkhydra.main analyze \
  --input test_bug/circuits/circuit.circom \
  --tools circomspect,circom_civer,picus

# Specify output directory and timeout
uv run python -m zkhydra.main analyze \
  --input circuit.circom \
  --tools circomspect \
  --output results/ \
  --timeout 3600
```

**Docker:**
```bash
docker-compose run --rm zkhydra uv run python -m zkhydra.main analyze \
  --input test_bug/circuits/circuit.circom \
  --tools circomspect
```

### Evaluate Mode

Run tools and compare results against ground truth from a configuration file.

**Synopsis:**
```bash
uv run python -m zkhydra.main evaluate --input <zkbugs_config.json> --tools <tool1,tool2,...> [options]
```

**Input Format:**
The JSON config file must follow the zkbugs format:
```json
{
  "bug_name": {
    "Project": "https://github.com/project/repo",
    "Commit": "commit_hash",
    "Vulnerability": "Under-Constrained",
    "Impact": "Description of impact",
    "Root Cause": "Description of root cause",
    "Location": {
      "Function": "FunctionName",
      "Line": "10",
      "File": "circuit.circom"
    }
  }
}
```

**Output:**
- Ground truth file
- Tool comparison results (True Positives, False Negatives, etc.)
- Summary statistics
- Evaluation file with TODO items for manual review

**Examples:**

```bash
# Evaluate with ground truth
uv run python -m zkhydra.main evaluate \
  --input test_bug/zkbugs_config.json \
  --tools circomspect

# Evaluate with multiple tools
uv run python -m zkhydra.main evaluate \
  --input test_bug/zkbugs_config.json \
  --tools circomspect,circom_civer,picus
```

**Docker:**
```bash
docker-compose run --rm zkhydra uv run python -m zkhydra.main evaluate \
  --input test_bug/zkbugs_config.json \
  --tools circomspect
```

## CLI Options

### Required Arguments

- `mode` - Operation mode: `analyze` or `evaluate`
- `--input`, `-i` - Input file:
  - Analyze mode: Circuit file (`.circom`)
  - Evaluate mode: Config file (`.json`)
- `--tools`, `-t` - Tools to run:
  - Use `all` to run all available tools for the DSL
  - Or specify comma-separated list: `circomspect,circom_civer,picus`
  - Available tools for Circom: `circomspect`, `circom_civer`, `picus`, `ecneproject`, `zkfuzz`

### Optional Arguments

- `--output`, `-o` - Output directory (default: `output/`)
- `--dsl` - Domain-specific language (default: `circom`, options: `circom`, `pil`, `cairo`)
- `--timeout` - Timeout per tool in seconds (default: `1800`)
- `--log-level` - Logging level (default: `INFO`, options: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`)
- `--log-file` - Enable file logging

### Help

```bash
uv run python -m zkhydra.main --help
uv run python -m zkhydra.main analyze --help
uv run python -m zkhydra.main evaluate --help
```

## Output Structure

### Analyze Mode Output

```
output/analyze_YYYYMMDD_HHMMSS/
├── circomspect/
│   └── raw.txt           # Raw tool output
├── circom_civer/
│   └── raw.txt
├── summary.json          # Complete summary with findings
```

### Evaluate Mode Output

```
output/evaluate_YYYYMMDD_HHMMSS/
├── ground_truth.json              # Extracted ground truth
├── circomspect/
│   ├── raw.txt                    # Raw tool output
│   ├── parsed.json                # Structured output
│   └── results.json               # Comparison result
├── circom_civer/
│   ├── raw.txt
│   ├── parsed.json
│   └── results.json
├── summary.json                   # Evaluation statistics
└── manual_review_todo.md          # Items needing manual review (if any)
```

## Examples

### Quick Start: Analyze a Test Circuit

```bash
# Analyze the example underconstrained circuit
uv run python -m zkhydra.main analyze \
  --input test_bug/circuits/circuit.circom \
  --tools circomspect

# Expected output: 1 finding (underconstrained signal)
```

### Evaluate Against Ground Truth

```bash
# Evaluate tools against known vulnerability
uv run python -m zkhydra.main evaluate \
  --input test_bug/zkbugs_config.json \
  --tools circomspect

# Expected output: True positive detection
```

### Run All Tools

```bash
# Analyze with all available tools (using 'all' keyword)
uv run python -m zkhydra.main analyze \
  --input test_bug/circuits/circuit.circom \
  --tools all \
  --timeout 3600

# Or specify tools explicitly
uv run python -m zkhydra.main analyze \
  --input test_bug/circuits/circuit.circom \
  --tools circomspect,circom_civer,picus,ecneproject,zkfuzz \
  --timeout 3600
```

## Understanding Output

### Analyze Mode Summary

The CLI prints:
- **Input**: Path to analyzed circuit
- **Output**: Where results are saved
- **Total Time**: Combined execution time
- **Total Findings**: Sum of all findings across tools
- **Per-tool Results**: Findings count, execution time, and top findings

Example:
```
================================================================================
ANALYZE MODE - SUMMARY
================================================================================
Input:        test_bug/circuits/circuit.circom
Output:       output/analyze_20260126_153045
Total Time:   2.45s
Total Findings: 1

--------------------------------------------------------------------------------
TOOL RESULTS:
--------------------------------------------------------------------------------

CIRCOMSPECT:
  Time:     2.45s
  Findings: 1
  Output:   output/analyze_20260126_153045/circomspect/raw.txt

  Findings List:
    1. warning[CS0017]: Signal `c` is not constrained
```

### Evaluate Mode Summary

The CLI prints:
- **Bug**: Name from config
- **Vulnerability**: Type from ground truth
- **Statistics**: TP, FN, timeouts, errors, manual review needs
- **Per-tool Results**: Verdict (✓ correct, ✗ false, ⏱ timeout)

Example:
```
================================================================================
EVALUATE MODE - SUMMARY
================================================================================
Bug:          test_bug
Vulnerability: Under-Constrained
Output:       output/evaluate_20260126_153045

--------------------------------------------------------------------------------
STATISTICS:
--------------------------------------------------------------------------------
Total Tools:         1
True Positives:      1
False Negatives:     0
Timeouts:            0
Errors:              0
Need Manual Review:  0

--------------------------------------------------------------------------------
TOOL RESULTS:
--------------------------------------------------------------------------------

CIRCOMSPECT: ✓ CORRECT
  Time: 2.45s
```

## Development

Format the codebase:
```bash
uv run black . && uv run isort . --profile black
```

## Project Structure

```
zkhydra/
├── tools/                      # Tool source code repositories (git submodules)
│   ├── circomspect/           # circomspect source
│   ├── circom_civer/          # circom_civer source
│   ├── picus/                 # picus source
│   ├── ecneproject/           # ecneproject source
│   └── zkfuzz/                # zkfuzz source
├── zkhydra/                    # Python package
│   ├── tools/                 # Tool Python wrappers
│   │   ├── base.py           # AbstractTool base class, Finding dataclass
│   │   ├── circomspect.py    # Circomspect wrapper
│   │   ├── circom_civer.py   # CiVer wrapper
│   │   ├── zkfuzz.py         # zkFuzz wrapper
│   │   ├── picus.py          # Picus wrapper
│   │   └── ecneproject.py    # EcneProject wrapper
│   ├── utils/                 # Utility modules
│   │   ├── logger.py         # Logging setup
│   │   └── tools_resolver.py # Tool registry and resolution
│   ├── bugs/                  # Bug management
│   │   └── zkbugs.py         # zkbugs dataset handling
│   └── main.py                # Main entry point
├── bugs/zkbugs/               # zkbugs dataset (git submodule)
├── output/                    # Analysis results
├── run.py                     # Convenience entry point wrapper
└── pyproject.toml            # Python dependencies
```

## Legacy Config File Mode

The tool previously used TOML config files. This mode will be added back in a future update with:
```bash
uv run python -m zkhydra.main --config config.toml
```

## License

See [LICENSE](LICENSE) file.
