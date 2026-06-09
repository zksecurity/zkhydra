# LLM Auditor Run Plan — circom zkbugs

Covers both `circom_auditor_claude` and `circom_auditor_codex` across all 70
runnable circom bugs in `config.toml`, using `--zkbugs-mode both` (direct +
original entrypoints). Bugs are split into 6 shards to stay under API rate
limits.

**Why 70 and not 72?** `config.toml` tracks 72 circom bugs total: 70 in
`[circom].bugs` (runnable — these are analyzed here) and 2 in
`[circom].unreproducible_bugs` (not present in the dataset at all:
`ProcessMessages` and `Potentially_Easy_to_Misuse_Interface`).

---

## Prerequisites

Verify each item before starting.

```bash
# 1. Verify the zkbugs dataset is present next to this repo
ls ../zkbugs/dataset/circom   # expected: org directories (0xbok, iden3, ...)

# 2. (Optional) Download original codebases for original-mode runs
bash ../zkbugs/scripts/download_sources.sh

# 3. Claude Code CLI
claude --version
echo $CLAUDE_PLUGIN_DIR         # must be set
ls $CLAUDE_PLUGIN_DIR/skills/circom-auditor/SKILL.md   # must exist

# 4. OpenAI Codex CLI
codex --version
echo $OPENAI_API_KEY            # must be set
# CODEX_PLUGIN_DIR defaults to CLAUDE_PLUGIN_DIR if unset (same skill dir works)

# 5. Optional: increase include-closure cap for large circuits (default 5000)
# export CIRCOM_AUDITOR_MAX_LINES=8000
```

---

## Step 1 — Split bugs into shards

Run once. Produces `shards/shard_{1..6}.txt`, each with ~11 bugs.

```bash
python scripts/split_bugs.py --shards 6 --output-dir shards/
```

---

## Step 2 — Run each shard

Run shards **sequentially** to respect rate limits (each shard takes ~2-3 h).
Adjacent shards (1+4, 2+5, 3+6) can run concurrently in separate terminals —
they have no shared state.

Each command runs both tools on both modes (direct + original) and writes
results under `output/shard_N/`.

```bash
# Shard 1
uv run python -m zkhydra.main zkbugs \
  --dataset ../zkbugs/dataset/circom \
  --tools circom_auditor_claude,circom_auditor_codex \
  --bugs-file shards/shard_1.txt \
  --zkbugs-mode both \
  --output output/shard_1

# Shard 2
uv run python -m zkhydra.main zkbugs \
  --dataset ../zkbugs/dataset/circom \
  --tools circom_auditor_claude,circom_auditor_codex \
  --bugs-file shards/shard_2.txt \
  --zkbugs-mode both \
  --output output/shard_2

# Shard 3
uv run python -m zkhydra.main zkbugs \
  --dataset ../zkbugs/dataset/circom \
  --tools circom_auditor_claude,circom_auditor_codex \
  --bugs-file shards/shard_3.txt \
  --zkbugs-mode both \
  --output output/shard_3

# Shard 4
uv run python -m zkhydra.main zkbugs \
  --dataset ../zkbugs/dataset/circom \
  --tools circom_auditor_claude,circom_auditor_codex \
  --bugs-file shards/shard_4.txt \
  --zkbugs-mode both \
  --output output/shard_4

# Shard 5
uv run python -m zkhydra.main zkbugs \
  --dataset ../zkbugs/dataset/circom \
  --tools circom_auditor_claude,circom_auditor_codex \
  --bugs-file shards/shard_5.txt \
  --zkbugs-mode both \
  --output output/shard_5

# Shard 6
uv run python -m zkhydra.main zkbugs \
  --dataset ../zkbugs/dataset/circom \
  --tools circom_auditor_claude,circom_auditor_codex \
  --bugs-file shards/shard_6.txt \
  --zkbugs-mode both \
  --output output/shard_6
```

**Resuming a failed shard**: re-run the same command. Bugs that already have
`results.json` are not re-executed (pass `--vanilla` to just re-parse existing
raw output without re-running tools).

---

## Step 3 — Merge shards into one combined run

Stitches the six shard output dirs into a single `output/llm_combined/` that
mirrors a normal `--zkbugs-mode both` run structure (`direct/` + `original/`).

```bash
python scripts/merge_shards.py \
  output/shard_1 output/shard_2 output/shard_3 \
  output/shard_4 output/shard_5 output/shard_6 \
  --output output/llm_combined
```

Expected layout after merge:

```
output/llm_combined/
  summary.json
  direct/
    summary.json
    <bug_name>/
      ground_truth.json
      circom_auditor_claude/  raw.txt  parsed.json  results.json  evaluation.json
      circom_auditor_codex/   ...
  original/
    summary.json
    <bug_name>/   # only bugs with a distinct Original Entrypoint
      ...
```

---

## Step 4 — Triage Undecided verdicts

Claude automatically resolves verdicts that were marked Undecided by the
auto-evaluator (e.g. class match but different line number). Rewrites
`evaluation.json` in place; preserves the original at `evaluation.original.json`.

Run for both modes:

```bash
python scripts/triage_zkbugs_run.py output/llm_combined/direct \
  --dataset ../zkbugs/dataset/circom \
  --auto --update-evaluation --jobs 4

# Only if output/llm_combined/original/ exists and is non-empty:
python scripts/triage_zkbugs_run.py output/llm_combined/original \
  --dataset ../zkbugs/dataset/circom \
  --auto --update-evaluation --jobs 4
```

Review the triage summary:

```bash
cat output/llm_combined/direct/triage_summary.json
```

---

## Step 5 — Merge into the remote zkbugs run

Copies the two LLM tool result dirs into the existing multi-tool remote run.
Run all four commands (two tools × two modes):

```bash
# direct mode
python scripts/merge_tool_run.py \
  --source output/llm_combined/direct \
  --target output/zkbugs-remote/direct \
  --tool circom_auditor_claude

python scripts/merge_tool_run.py \
  --source output/llm_combined/direct \
  --target output/zkbugs-remote/direct \
  --tool circom_auditor_codex

# original mode (skip if output/llm_combined/original/ is empty)
python scripts/merge_tool_run.py \
  --source output/llm_combined/original \
  --target output/zkbugs-remote/original \
  --tool circom_auditor_claude

python scripts/merge_tool_run.py \
  --source output/llm_combined/original \
  --target output/zkbugs-remote/original \
  --tool circom_auditor_codex
```

---

## Step 6 — Generate summary tables

```bash
# Summary table + bug-tool matrix for the combined LLM run:
python scripts/process_zkbugs_results.py output/llm_combined/direct

# Full remote run (all tools):
python scripts/process_zkbugs_results.py output/zkbugs-remote/direct

# Optional: LaTeX/PDF report:
python scripts/process_zkbugs_results.py output/zkbugs-remote/direct \
  --latex output/zkbugs-remote/report.pdf
```

---

## Summary of output directories

| Path | Contents |
|------|----------|
| `shards/shard_N.txt` | Bug selectors for shard N |
| `output/shard_N/` | Raw shard run (direct/ + original/) |
| `output/llm_combined/` | Merged LLM run (all 70 bugs) |
| `output/zkbugs-remote/` | Full multi-tool run (all tools including LLM) |
