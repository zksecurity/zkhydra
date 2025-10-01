# State of ZK Security Tools

## Notes

- **Implemented**
  - circomspect
  - EcneProject
  - Picus
  - zkFuzz
  - circom_civer

## Installation

```Bash
./setup.sh
```

## Execution

Navigate into the source code:

```Bash
cd zksec
```

Execute `main.py`, by default it uses the `config.toml` specifying the bugs, tools, and output:

```Bash
uv run main.py
```

## Development

Format Code:

```Bash
uv run black . && uv run isort . --profile black
```
