# state-of-zk-security-tools

## Notes

- Picus
  - has issues when running, I think issues due to zkbug again
- Coda
  - issue with `rewriter` installation
- circomspect
  - seems to run
- garden
  - installed, but how do i use it?
- zkFuzz
  - installed, I think issues due to zkbug again

## Questions

In `zksec/bugs/zkbugs/dataset/circom/0xbok/circom-bigint/veridise_missing_range_checks_in_bigmod/zkbugs_vars.sh` it didn't find the PTAU file, so I adjusted the script.
Changed this line:

```sh
ROOT_PATH=$(dirname "$(dirname "$(dirname "$(dirname "$(dirname "$SCRIPT_PATH")")")")")
```

to:

```sh
ROOT_PATH=$(dirname "$(dirname "$(dirname "$(dirname "$(dirname "$(dirname "$SCRIPT_PATH")")")")")")
```

(One dir further up; else it was always looking in the `dataset` dir. Is this an error in the script or how should I use it?)

OR

copy pasted the scripts folder in the development folder; still getting an error that files are not found:

```txt
Compiling the target circuit: circuits/circuit.circom
error[P1014]:  The file ../../../dependencies/circomlib/circuits/comparators.circom to be included has not been found
 = Consider using compilation option -l to indicate include paths
```

## Installation

> [!WARNING]
> Under development.

```Bash
./setup/setup.sh
```

## Execution

> [!WARNING]
> Under development.

Navigate into the source code:

```Bash
cd zksec
```

Execute `main.py` with parameters for the `bugs` and `tools` that should be used, as well as an `output` directory:

```Bash
uv run main.py --bugs ./input-bugs.txt --tools ./input-tools.txt --output ./output
```
