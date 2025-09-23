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
<!-- - **Issues**  
  - dont care: Coda (installation issues, `make` command doesn't work, working on it), not automated -> write circuit in code
  - dont care: Garden (execution issues, got support from owner; he says for analyzing Circom circuits the project might be buggy/incomplete)
  - Don't care nnow: ZKAP (Dockerfile doesn't build; working on it, but takes some time)
  - Dont care for impl.: SNARKProbe (repo needed for installation doesn't exist anymore (`git clone https://github.com/fanym919/snarktool.git`); in case that should be the repo/subfolder of the repo: missing package on ubuntu `libprocps`) -->
- **TODO**
  - try: r1cs-solver (Haskell library)

<!--
at least 10 bugs
analyse results (get them kinda automated, see if they find the correct bug, FP vs TP (circomspect))
if picus says there is a bug, then it should be there
try to undertsand what happens

then halo2 tools (Korrekt)
then Gnark
then Cairo and PIL
-->


<!-- Upper limit: 10min, maybe one hour later, then time out -->

<!-- for each tool most verbose output (if possible json) -->

<!-- write parser, picus_parser_result that knows how to reead the tool and then gives me a result and that I can then parse to JSON, similar to https://github.com/smartbugs/smartbugs (also templates) -->

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

## Development

```Bash
uv run black . && uv run isort . --profile black
```
