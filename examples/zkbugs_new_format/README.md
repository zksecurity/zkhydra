# zkbugs new-format example

Self-contained fixture used by zkhydra to exercise the refactored zkbugs
layout (wrapper + separate codebase + `-l` link flags) without pulling in
the full zkbugs dataset.

## Layout

```
examples/zkbugs_new_format/
├── scripts/
│   └── print_bug_vars.sh          # runner contract (copy of zkbugs upstream)
├── dataset/
│   ├── circom/example/toy/tiny_bug/
│   │   ├── circuit.circom         # wrapper, includes "circuits/toy.circom"
│   │   ├── direct_input.json
│   │   ├── zkbugs_config.json
│   │   └── zkbugs_vars.sh         # exposes CIRCOM_LINK_FLAGS
│   └── codebases/circom/example/toy/abc/circuits/toy.circom
```

## Run

```bash
uv run python -m zkhydra.main zkbugs \
  --dataset examples/zkbugs_new_format/dataset/circom \
  --zkbugs-mode direct \
  --tools circom_civer,circomspect \
  --timeout 60 \
  --output output/zkbugs-new-format-smoke
```

`zkhydra` walks up from `--dataset` to find `scripts/print_bug_vars.sh`,
loads the bug's contract via that script, and routes link_flags through
to the tool wrappers.
