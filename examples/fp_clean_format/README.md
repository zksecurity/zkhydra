# FP clean-format example

Self-contained fixture that exercises zkhydra's **false-positive (`fp`) mode**
without pulling in the real audited-project corpus or the heavy tool chain. It
mirrors the `zkbugs_new_format` layout (wrapper circuit + separate codebase +
`-l` link flags), but the unit is a **clean** circuit described by an
`fp_config.json` instead of a `zkbugs_config.json`.

`ToyDouble` (`out <== in + in`) is properly constrained, so a correct tool
should report **no soundness alert** on it. Any soundness-class finding here is
a false positive — which is exactly what the experiment measures.

## Layout

```
examples/fp_clean_format/
└── dataset/
    ├── circom/example/toy/clean_unit/
    │   ├── circuit.circom         # wrapper, includes "circuits/toy.circom"
    │   ├── direct_input.json
    │   └── fp_config.json         # provenance + entrypoint/codebase contract
    └── codebases/circom/example/toy/abc/circuits/toy.circom
```

## Run

```bash
uv run python -m zkhydra.main fp \
  --dataset examples/fp_clean_format/dataset/circom \
  --tools circomspect \
  --timeout 30 \
  --output output/fp-smoke
```

Expect per-unit `fp_candidates.json` + a corpus `summary.json`; `soundness_count`
should be 0.
