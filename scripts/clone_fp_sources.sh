#!/usr/bin/env bash
# Clone audited Circom projects into an FP corpus, at a known post-audit commit.
#
# This is the AUDITED tier of the false-positive corpus (the fixed-commit tier
# is built by scripts/build_zkbugs_fixed_corpus.py). Each project is cloned into
#   <out>/dataset/codebases/audited/<name>
# and a unit skeleton is scaffolded at
#   <out>/dataset/circom/audited/<name>/
# with a template fp_config.json + TODO_WIRING.md.
#
# Per-project ENTRYPOINT + INPUT wiring is a manual step (each repo needs a
# circuit with a `component main` and a valid input.json). The seed list below
# is a STARTING POINT — prune it and pin exact post-audit commits with the team
# before running the experiment.
#
# Usage:
#   scripts/clone_fp_sources.sh <out>            # clone + scaffold
#   scripts/clone_fp_sources.sh <out> --list     # print the seed list and exit
#
# Idempotent: existing clones are left untouched (delete a dir to re-clone).

set -euo pipefail

# name|git_url|commit_or_tag   (commit "HEAD" = pin before the real run)
PROJECTS=(
  "circomlib|https://github.com/iden3/circomlib|HEAD"
  "tornado-core|https://github.com/tornadocash/tornado-core|HEAD"
  "semaphore|https://github.com/semaphore-protocol/semaphore|HEAD"
  "maci|https://github.com/privacy-scaling-explorations/maci|HEAD"
  "rln|https://github.com/Rate-Limiting-Nullifier/circom-rln|HEAD"
  "spartan-ecdsa|https://github.com/personaelabs/spartan-ecdsa|HEAD"
  "telepathy|https://github.com/succinctlabs/telepathy-circuits|HEAD"
  "circom-ecdsa|https://github.com/0xPARC/circom-ecdsa|HEAD"
  "hermez|https://github.com/hermeznetwork/circuits|HEAD"
  "darkforest|https://github.com/darkforest-eth/circuits|HEAD"
)

if [[ "${2:-}" == "--list" ]]; then
  printf '%s\n' "${PROJECTS[@]}"
  exit 0
fi

OUT="${1:?usage: clone_fp_sources.sh <out> [--list]}"
CODEBASES="$OUT/dataset/codebases/audited"
UNITS="$OUT/dataset/circom/audited"
mkdir -p "$CODEBASES" "$UNITS"

for entry in "${PROJECTS[@]}"; do
  IFS='|' read -r name url commit <<<"$entry"
  dest="$CODEBASES/$name"
  if [[ -d "$dest" ]]; then
    echo "skip $name (exists)"
  else
    echo "clone $name <- $url @ $commit"
    git clone --quiet "$url" "$dest"
    if [[ "$commit" != "HEAD" ]]; then
      git -C "$dest" checkout --quiet "$commit"
    fi
  fi

  unit="$UNITS/$name"
  mkdir -p "$unit"
  rel_codebase="$(python3 -c "import os,sys;print(os.path.relpath(sys.argv[1],sys.argv[2]))" "$dest" "$OUT")"
  if [[ ! -f "$unit/fp_config.json" ]]; then
    cat >"$unit/fp_config.json" <<JSON
{
    "$name (audited)": {
        "Project": "$url",
        "Commit": "$commit",
        "DSL": "Circom",
        "Clean": true,
        "Origin": "audited",
        "Source": { "Audit Report": { "Source Link": "TODO: audit link" } },
        "Codebase": "$rel_codebase",
        "Entrypoint": "circuit.circom",
        "Input": "input.json",
        "Compiled": false
    }
}
JSON
    cat >"$unit/TODO_WIRING.md" <<'MD'
# Wiring TODO (audited FP unit)

Before this unit can run, do three things in this directory, then flip
`"Compiled": false` to `true` in fp_config.json:

1. Add `circuit.circom` — a wrapper that `include`s a real, audited entrypoint
   from the codebase and declares `component main = <Template>(<params>);`.
   (Or point `Entrypoint` at an existing entrypoint that has `component main`.)
2. Add `input.json` — a valid input for that circuit.
3. Pin `Commit` in fp_config.json to the exact post-audit commit, and fill the
   audit `Source Link`.

Multiple entrypoints per project: make one sibling unit dir per entrypoint
(e.g. `semaphore-16/`, `semaphore-32/`), each with its own fp_config.json.
MD
    echo "  scaffolded $unit (see TODO_WIRING.md)"
  fi
done

echo
echo "Done. Wire each unit per its TODO_WIRING.md, then run:"
echo "  uv run python -m zkhydra.main fp --dataset $OUT/dataset/circom --tools all --jobs 4"
