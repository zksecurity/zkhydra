In `zksec/bugs/zkbugs/dataset/circom/0xbok/circom-bigint/veridise_missing_range_checks_in_bigmod/zkbugs_vars.sh`
So it finds the PTAU file:
I changed:
```
ROOT_PATH=$(dirname "$(dirname "$(dirname "$(dirname "$(dirname "$SCRIPT_PATH")")")")")
```

to:

```
ROOT_PATH=$(dirname "$(dirname "$(dirname "$(dirname "$(dirname "$(dirname "$SCRIPT_PATH")")")")")")
```

(One dir further up; else it was always looking in the `dataset` dir. Is this an error in the script or how should I use it?)
