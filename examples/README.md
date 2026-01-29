# zkHydra Examples

This directory contains example Circom circuits for testing zkHydra.

## Available Examples

### test_bug - Underconstrained Circuit
Location: `test_bug/circuits/circuit.circom`

**Description**: A simple Circom circuit with an underconstrained signal. The circuit multiplies two inputs but doesn't properly constrain the output signal `c`.

**Expected Findings**:
- circomspect: Detects underconstrained signal
- Other tools may also detect the vulnerability

**Usage**:
```bash
uv run python -m zkhydra.main analyze \
  --input examples/test_bug/circuits/circuit.circom \
  --tools circomspect
```

**Evaluate Mode** (with ground truth):
```bash
uv run python -m zkhydra.main evaluate \
  --input examples/test_bug/zkbugs_config.json \
  --tools all
```

### test_bug_2
Additional test circuit for validation.

### test_bug_3
Bug-free IsZero circuit for negative testing.

## Using These Examples

### With Docker:
```bash
# The examples directory is automatically mounted in docker-compose.yml
docker-compose run --rm zkhydra uv run python -m zkhydra.main analyze \
  --input examples/test_bug/circuits/circuit.circom \
  --tools circomspect,circom_civer
```

### Native Installation:
```bash
uv run python -m zkhydra.main analyze \
  --input examples/test_bug/circuits/circuit.circom \
  --tools all \
  --timeout 300
```

## Adding Your Own Examples

Place your Circom circuits in this directory and analyze them:

```bash
# Create a directory for your circuit
mkdir -p examples/my-circuit

# Add your circuit.circom file
cp /path/to/your/circuit.circom examples/my-circuit/

# Analyze it
uv run python -m zkhydra.main analyze \
  --input examples/my-circuit/circuit.circom \
  --tools circomspect
```
