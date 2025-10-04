# State of ZK Security Tools

## Notes

> [!NOTE]
> This project has been tested on Ubuntu 24.04.3 LTS.

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

To format the codebase, run:

```Bash
uv run black . && uv run isort . --profile black
```
