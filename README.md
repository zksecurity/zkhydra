# State of ZK Security Tools

> [!WARNING]
> Under development.

## Notes

- **Implemented**
  - circomspect
  - EcneProject
  - Picus
  - zkFuzz
  - circom_civer
- **Issues**  
  - Coda (installation issues, `make` command doesn't work, working on it)
  - Garden (execution issues, got support from owner; he says for analyzing Circom circuits the project might be buggy/incomplete)
  - ZKAP (Dockerfile doesn't build; working on it, but takes some time)
  - SNARKProbe (repo needed for installation doesn't exist anymore (`git clone https://github.com/fanym919/snarktool.git`); in case that should be the repo/subfolder of the repo: missing package on ubuntu `libprocps`)
- **TODO**
  - r1cs-solver

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
