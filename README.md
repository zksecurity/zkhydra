# zkHydra

A tool runner framework for executing and evaluating zero-knowledge circuit security analysis tools. zkHydra supports multiple DSLs (Circom, PIL, Cairo) and provides a standardized way to run security tools against a curated dataset of known bugs (zkbugs).

## Implemented Tools

- **circomspect** - Static analyzer and linter for Circom circuits
- **circom_civer** - Static analysis using CVC5 SMT solver backend
- **Picus** - Symbolic execution tool using Rosette
- **EcneProject** - Julia-based circuit analysis framework
- **zkFuzz** - Fuzzing tool for Circom circuits

## Installation

> [!NOTE]
> This project has been tested on Ubuntu 24.04.3 LTS.

### Option 1: Native Installation

```bash
./setup.sh
```

This will initialize git submodules, install uv, set up Rust toolchain, and build all tools.

### Option 2: Docker (Recommended for Quick Start)

```bash
# Build the Docker image (takes 30-60 minutes)
docker-compose build

# Run interactively
docker-compose run --rm zkhydra
```

See [DOCKER.md](DOCKER.md) for detailed Docker instructions.

## Quick Start

### Example 1: Run a Single Tool (Fast)

Test circomspect against the example underconstrained circuit:

```bash
# Native
uv run main.py --config configs/test_simple.toml

# Docker
docker-compose run --rm zkhydra uv run main.py --config configs/test_simple.toml
```

**Check results:**
```bash
cat output/test_simple/circom/circomspect/test_bug/raw.txt
```

### Example 2: Run All Tools (Complete Analysis)

Run all 5 tools against the test circuit:

```bash
# Native
uv run main.py --config configs/test_all_tools.toml

# Docker
docker-compose run --rm zkhydra uv run main.py --config configs/test_all_tools.toml
```

**Check results:**
```bash
# View summary
cat output/test_all_tools/summary.json

# View individual tool outputs
ls -la output/test_all_tools/circom/*/test_bug/
```

### Example 3: Run Full zkbugs Dataset

Use the default config to run tools against all bugs in the zkbugs dataset:

```bash
# Native
uv run main.py

# Docker
docker-compose run --rm zkhydra uv run main.py
```

## Configuration

Create a custom TOML config file to specify:
- Which tools to run
- Which bugs to analyze
- Output directory settings
- Pipeline stages to execute

**Available configs:**
- `config.toml` - Full zkbugs dataset with all bugs
- `configs/test_simple.toml` - Single tool (circomspect) on test circuit
- `configs/test_all_tools.toml` - All 5 tools on test circuit

Example config structure:
```toml
[app]
log_level = "INFO"
timeout = 1800
output = "./output"
file_logging = true
dynamic_name = false
static_name = "my_analysis"

# Pipeline stages
setup_bug_environment = true
execute_tools = true
cleanup_bug_environment = true
generate_ground_truth = true
parse_raw_tool_output = true
analyze_tool_results = true
summarize_tool_results = true

[circom]
tools = ["circomspect", "circom_civer"]
bugs = ["test_bug"]
```

See `config.toml` for the full configuration with all zkbugs.

## Output Structure

```
output/
  {run_name}/
    circom/{tool}/{bug_name}/
      raw.txt          # Raw tool output
      parsed.json      # Structured output
      results.json     # Comparison against ground truth
    ground_truth/circom/{bug_name}/ground_truth.json
    summary.json       # Aggregated results across all tools/bugs
```

## Development

Format the codebase:
```bash
uv run black . && uv run isort . --profile black
```

## Documentation

- [DOCKER.md](DOCKER.md) - Docker setup and usage guide
- [QUICKSTART_DOCKER.md](QUICKSTART_DOCKER.md) - Quick start guide for Docker
- [CLAUDE.md](CLAUDE.md) - Development guide for Claude Code
- [DOCKER_STATUS.md](DOCKER_STATUS.md) - Docker architecture details
