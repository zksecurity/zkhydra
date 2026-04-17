# zkHydra

A unified framework for running zero-knowledge circuit security analysis tools. zkHydra orchestrates multiple analysis tools (circomspect, circom_civer, Picus, EcneProject, zkFuzz) to detect vulnerabilities in Circom circuits.

## Quick Start

### Using Docker (Recommended)

```bash
# Pull the image
docker pull ghcr.io/zksecurity/zkhydra:latest

docker-compose run --rm zkhydra uv run python -m zkhydra.main analyze \
  --input examples/test_bug_2/circuits/circuit.circom \
  --tools circomspect,circom_civer,picus,zkfuzz

# or
docker-compose run --rm zkhydra /bin/bash
```

### Analyze Your First Circuit

```bash
# Inside the container, analyze the example circuit
uv run python -m zkhydra.main analyze \
  --input examples/test_bug/circuits/circuit.circom \
  --tools circomspect
```

### Mount Your Own Circuits

Edit `docker-compose.yml` to mount your circuit directory:

```yaml
volumes:
  - ./output:/zkhydra/output
  - ./examples:/zkhydra/examples
  - ./my-circuits:/zkhydra/my-circuits  # Add this line
```

Then analyze:

```bash
docker-compose run --rm zkhydra uv run python -m zkhydra.main analyze \
  --input my-circuits/circuit.circom \
  --tools circomspect,circom_civer,picus
```

## Running on zkbugs Dataset

The [zkbugs dataset](https://github.com/zksecurity/zkbugs) contains real-world Circom vulnerabilities. zkhydra consumes the refactored dataset format via the runner contract (`scripts/print_bug_vars.sh` inside the zkbugs repo) — each bug's entrypoint, input JSON, ptau, codebase path, and `-l` link flags are resolved from that script.

```bash
# Clone zkbugs dataset
git clone --recurse-submodules https://github.com/zksecurity/zkbugs.git

# (optional) populate project codebases — required for --zkbugs-mode original
# and for every bug whose wrapper includes "circuits/..." resolved via -l
(cd zkbugs && ./scripts/download_sources.sh)

# Update docker-compose.yml to mount it
# volumes:
#   - ./zkbugs:/zkhydra/zkbugs

# Run analysis on the entire dataset
docker-compose run --rm zkhydra uv run python -m zkhydra.main zkbugs \
  --dataset zkbugs/dataset/circom \
  --zkbugs-mode direct \
  --tools all \
  --timeout 600 \
  --log-file
```

This will:
- Walk `--dataset` for `zkbugs_config.json` files (excluding `dataset/codebases/` and `dataset/*/dependencies/`).
- Build each bug's `Input` via `scripts/print_bug_vars.sh` (located by walking up from `--dataset`).
- Skip bugs whose `Compiled Direct=false` (or `Compiled Original=false` in original mode), or whose codebase wasn't downloaded. Skipped rows show up in `summary.json` with a reason.
- Run all available tools (circomspect, circom_civer, picus, ecneproject, zkfuzz) with 10-minute timeout per tool per bug.
- Output per-bug results and a dataset-level `summary.json` under `output/zkbugs_.../`.

### zkbugs modes

- `--zkbugs-mode direct` (default) — run against each bug's isolated wrapper `circuit.circom`. Every bug supports this mode and it's the fastest path. circom link flags are still needed because the wrapper typically `include`s files from the codebase (e.g. `include "circuits/..."`).
- `--zkbugs-mode original` — run against the project's real entrypoint (`Original Entrypoint` in `zkbugs_config.json`). Requires `dataset/codebases/` to be populated.

### Selecting a subset of bugs

- `--bugs <sel1>,<sel2>,...` — comma-separated substrings matched against each bug's directory name or its `--dataset`-relative path.
- `--bugs-file <path>` — one selector per line (lines starting with `#` are ignored).

Both flags combine as a union. Missing-match exits with an error.

```bash
# Single bug
uv run python -m zkhydra.main zkbugs \
  --dataset zkbugs/dataset/circom --tools circomspect \
  --bugs veridise_decoder_accepting_bogus_output_signal

# Path fragment (matches all bugs under darkforest-v0.3/)
uv run python -m zkhydra.main zkbugs \
  --dataset zkbugs/dataset/circom --tools all \
  --bugs darkforest-eth/darkforest-v0.3

# From a file
uv run python -m zkhydra.main zkbugs \
  --dataset zkbugs/dataset/circom --tools all \
  --bugs-file my-selectors.txt
```

## Supported Tools

- **circomspect** - Static analyzer and linter
- **circom_civer** - SMT-based verification with CVC5
- **Picus** - Symbolic execution via Rosette
- **EcneProject** - Julia-based circuit analysis
- **zkFuzz** - Fuzzing-based bug detection

## Usage Modes

### 1. Analyze Mode

Run tools on a single circuit without ground truth.

```bash
uv run python -m zkhydra.main analyze \
  --input circuit.circom \
  --tools circomspect,circom_civer \
  --timeout 600 \
  --output results/
```

**Output**: Raw findings from each tool in `results/`

### 2. Evaluate Mode

Compare tool results against known vulnerabilities (requires zkbugs format config).

```bash
uv run python -m zkhydra.main evaluate \
  --input bug/zkbugs_config.json \
  --tools all
```

**Output**: Ground truth comparison, True Positives, False Negatives

### 3. zkbugs Mode

Run tools against the refactored zkbugs dataset.

```bash
uv run python -m zkhydra.main zkbugs \
  --dataset zkbugs/dataset/circom \
  --zkbugs-mode direct \
  --tools all \
  --timeout 600
```

**Output**: Per-bug analysis results, per-bug `ground_truth.json` (with the full refactored config: `codebase`, `direct_entrypoint`, `original_entrypoint`, `input`, `executed`, `compiled_direct`, `compiled_original`), and a dataset-level `summary.json` that records processed and skipped bugs with reasons.

## CLI Options

```bash
# analyze / evaluate
--input, -i        Circuit file (.circom) for analyze mode

# zkbugs
--dataset, -d      Path to <zkbugs>/dataset/circom
--zkbugs-mode      direct (default) | original
--bugs             Comma-separated bug selectors (substring match)
--bugs-file        File with one bug selector per line (# comments allowed)

# shared
--tools, -t        Tools to run (comma-separated or 'all')
--output, -o       Output directory (default: output/)
--timeout          Timeout per tool in seconds (default: 1800)
--log-file         Enable file logging
--log-level        Logging verbosity (default: INFO)
--vanilla          Re-process existing raw output instead of running tools
```

## Examples

### Single Tool Analysis

```bash
docker-compose run --rm zkhydra uv run python -m zkhydra.main analyze \
  --input examples/test_bug/circuits/circuit.circom \
  --tools circomspect
```

### New-format smoke test (no zkbugs checkout required)

`examples/zkbugs_new_format/` ships a self-contained toy bug that mirrors the refactored layout:

```bash
uv run python -m zkhydra.main zkbugs \
  --dataset examples/zkbugs_new_format/dataset/circom \
  --zkbugs-mode direct \
  --tools circomspect \
  --timeout 30 \
  --output output/zkbugs-new-format-smoke
```

### Multiple Tools with Timeout

```bash
docker-compose run --rm zkhydra uv run python -m zkhydra.main analyze \
  --input examples/test_bug/circuits/circuit.circom \
  --tools circomspect,circom_civer,zkfuzz \
  --timeout 300
```

### Full zkbugs Evaluation

```bash
# From host machine with zkbugs cloned locally
docker-compose run --rm zkhydra uv run python -m zkhydra.main zkbugs \
  --dataset zkbugs/dataset/circom \
  --zkbugs-mode direct \
  --tools all \
  --timeout 600 \
  --log-file \
  --output output/zkbugs-run
```

### Single bug (fast feedback loop)

```bash
docker-compose run --rm zkhydra uv run python -m zkhydra.main zkbugs \
  --dataset zkbugs/dataset/circom \
  --tools circomspect,circom_civer \
  --bugs veridise_decoder_accepting_bogus_output_signal \
  --timeout 120
```

## Output Structure

```
output/
└── analyze_YYYYMMDD_HHMMSS/
    ├── circomspect/
    │   ├── raw.txt          # Raw tool output
    │   ├── tool_output.json # Execution metadata
    │   ├── parsed.json      # Structured findings
    │   └── results.json     # Standardized format
    ├── circom_civer/
    │   └── ...
    └── summary.json         # Aggregated results
```

For zkbugs mode:
```
output/zkbugs-run/
├── <bug_name>/
│   ├── ground_truth.json        # includes new keys (codebase, entrypoints, compile flags, mode)
│   ├── scratch/                 # precompile artifacts (.r1cs / .sym / compile.log)
│   ├── circomspect/
│   │   ├── raw.txt
│   │   ├── results.json
│   │   └── evaluation.json      # TP/FN/Undecided
│   └── ...
└── summary.json                 # processed + skipped rows with reasons, per-mode totals
```

## Existing zkbugs analysis

You can find a report of the zkbugs analysis in `output/zkbugs-report.pdf` and you can download a tar with all the results here: https://drive.google.com/file/d/1zTIrrVqy0MXMxC4tRiPoFMEfXv-2TLYY/view?usp=sharing.

## Installation (Local Development)

### Prerequisites
- Ubuntu 24.04
- Python 3.12+
- Rust toolchain
- Julia, Node.js, Racket

### Build from Source

```bash
# Clone repository with submodules
git clone --recurse-submodules https://github.com/zksecurity/zkhydra.git
cd zkhydra

# Run setup script (installs all dependencies and builds tools)
./setup.sh

# Run zkHydra
uv run python -m zkhydra.main --help
```

### Docker Build

```bash
# Build image locally (takes 30-60 minutes)
docker build -t zkhydra:latest .

# Or use docker-compose
docker-compose build
```

## Development

### Code Quality

```bash
# Format and lint (requires uv)
make all

# Or manually
uv run black zkhydra/
uv run isort zkhydra/ --profile black
uv run ruff check zkhydra/ --fix
```

### Project Structure

```
zkhydra/
├── zkhydra/              # Python package
│   ├── tools/           # Tool wrappers (circomspect.py, etc.)
│   ├── cli.py           # CLI argument parsing
│   ├── core.py          # Execution orchestration
│   └── main.py          # Entry point
├── tools/               # Tool source repos (git submodules)
├── examples/            # Example circuits for testing
├── docker-compose.yml   # Docker configuration
└── Dockerfile          # Multi-stage build with all tools
```

## Troubleshooting

### Tools Timeout

Increase timeout for slow tools:
```bash
--timeout 1800  # 30 minutes
```

### Out of Memory

For large circuits, run tools individually:
```bash
--tools circomspect  # Run one at a time
```

### Docker Issues

```bash
# Pull latest image
docker pull ghcr.io/zksecurity/zkhydra:latest

# Rebuild locally if needed
docker-compose build --no-cache
```

## Funding

This project was partially funded by an [Ethereum Foundation](https://esp.ethereum.foundation/) grant.

## License

See [LICENSE](LICENSE) file.

## Resources

- **zkbugs Dataset**: https://github.com/zksecurity/zkbugs
- **Issues**: https://github.com/zksecurity/zkhydra/issues
