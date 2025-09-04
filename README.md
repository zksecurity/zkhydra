# State of ZK Security Tools

> [!WARNING]
> Under development.

## Notes

- **Implemented**
  - circomspect
  - zkFuzz
  - Picus
- **Testing**
  - xxx
- **Issues**  
  - Coda (installation issues)
  - Garden (execution issues)
- **TODO**
  - circom_civer
  - EcneProject
  - r1cs-solver
  - SNARKProbe
  - ZKAP

## Installation

```Bash
./setup/setup.sh
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
