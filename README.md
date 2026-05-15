# zkHydra

A unified framework for running zero-knowledge circuit security analysis tools. zkHydra orchestrates multiple analysis tools (circomspect, circom_civer, Picus, EcneProject, zkFuzz) to detect vulnerabilities in Circom circuits.

## Quick Start

### Using Docker (Recommended)

```bash
# Pull the image
docker pull ghcr.io/zksecurity/zkhydra:latest

docker-compose run --rm zkhydra uv run python -m zkhydra.main analyze \
  --input examples/test_bug_2/circuits/circuit.circom \
  --tools circomspect,circom_civer,picus,zkfuzz

# or
docker-compose run --rm zkhydra /bin/bash
```

### Analyze Your First Circuit

```bash
# Inside the container, analyze the example circuit
uv run python -m zkhydra.main analyze \
  --input examples/test_bug/circuits/circuit.circom \
  --tools circomspect
```

### Mount Your Own Circuits

Edit `docker-compose.yml` to mount your circuit directory:

```yaml
volumes:
  - ./output:/zkhydra/output
  - ./examples:/zkhydra/examples
  - ./my-circuits:/zkhydra/my-circuits  # Add this line
```

Then analyze:

```bash
docker-compose run --rm zkhydra uv run python -m zkhydra.main analyze \
  --input my-circuits/circuit.circom \
  --tools circomspect,circom_civer,picus
```

## Running on zkbugs Dataset

The [zkbugs dataset](https://github.com/zksecurity/zkbugs) contains real-world Circom vulnerabilities. zkhydra does NOT vendor it as a submodule — clone it yourself outside the zkhydra tree and point `--dataset` at it. Each bug's entrypoint, input JSON, ptau, codebase path, and `-l` link flags are resolved from the runner contract (`scripts/print_bug_vars.sh` inside the zkbugs repo).

### End-to-end workflow

The full flow is: **clone → download sources → run tools → triage Undecided → print results**. Commands below assume zkhydra is your cwd and zkbugs is cloned alongside at `../zkbugs`.

#### Step 1 — Clone zkbugs and populate codebases

```bash
git clone https://github.com/zksecurity/zkbugs.git ../zkbugs

# Required for --zkbugs-mode original and for any direct-mode bug whose
# wrapper pulls files from the project codebase via -l. Run once; rerun
# with --force to refresh.
(cd ../zkbugs && ./scripts/download_sources.sh)
```

#### Step 2 — Run zkhydra on the dataset

Pick one of the three patterns below. All of them write per-bug outputs
under `<output>/<bug_name>/` plus a dataset-level `summary.json`.

```bash
# Docker (recommended): mount both your zkhydra source and the zkbugs clone.
docker-compose run --rm \
  -v $(pwd)/zkhydra:/zkhydra/zkhydra \
  -v $(pwd)/../zkbugs:/zkhydra/zkbugs \
  zkhydra uv run python -m zkhydra.main zkbugs \
    --dataset zkbugs/dataset/circom \
    --zkbugs-mode direct \
    --tools all \
    --jobs 4 \
    --timeout 600 \
    --log-file \
    --output output/zkbugs-run

# Local (no Docker, tools installed on the host):
uv run python -m zkhydra.main zkbugs \
  --dataset ../zkbugs/dataset/circom \
  --zkbugs-mode direct \
  --tools all \
  --jobs 4 \
  --timeout 600 \
  --output output/zkbugs-run

# Quick smoke — 6 random bugs, reproducible via --random-seed:
uv run python -m zkhydra.main zkbugs \
  --dataset ../zkbugs/dataset/circom \
  --tools circomspect,circom_civer \
  --jobs 4 --random-bugs 6 --random-seed 42 \
  --timeout 120 --output output/zkbugs-smoke

# Run both direct AND original for every bug (original is skipped when
# it would be identical to direct). Writes output/zkbugs-run/{direct,original}/.
uv run python -m zkhydra.main zkbugs \
  --dataset ../zkbugs/dataset/circom \
  --zkbugs-mode both \
  --tools all \
  --jobs 4 \
  --timeout 600 \
  --output output/zkbugs-run
```

What this does:
- Walks `--dataset` for `zkbugs_config.json` files (excluding `dataset/codebases/` and `dataset/*/dependencies/`).
- Builds each bug's `Input` via `scripts/print_bug_vars.sh` (located by walking up from `--dataset`).
- Skips bugs whose `Compiled Direct=false` (or `Compiled Original=false` in original mode), and bugs whose codebase is missing. Skipped rows land in `summary.json` with a reason.
- Runs the requested tools with per-bug precompilation; per-worker detail logs land at `<output>/<bug>/run.log`.

#### Step 3 — Triage the `Undecided` verdicts

`evaluate_zkbugs_ground_truth` is conservative — anything that isn't a trivial match is reported `Undecided`. The `triage-zkbugs-finding` skill + driver script promote those to `TruePositive` / `FalseNegative` (or keep `Undecided` with a reason when evidence is genuinely thin).

```bash
# Dry-run: collect every Undecided case into triage_queue.json for inspection.
python3 scripts/triage_zkbugs_run.py output/zkbugs-run \
  --dataset ../zkbugs/dataset/circom

# Automated: invoke Claude headlessly per case, write triage.json alongside
# each evaluation.json, rewrite evaluation.json with the triaged verdict
# (preserving the original at evaluation.original.json), and patch
# summary.json with an evaluation_counts rollup.
python3 scripts/triage_zkbugs_run.py output/zkbugs-run \
  --dataset ../zkbugs/dataset/circom \
  --auto --jobs 4 \
  --update-evaluation --update-summary
```

Flags in brief:
- `--auto` — shell out to `claude -p` per case; write `<bug>/<tool>/triage.json` and a top-level `triage_summary.json`.
- `--update-evaluation` — additionally rewrite each `evaluation.json` with the triaged verdict, preserving the original at `evaluation.original.json` (written once; re-runs do not clobber it).
- `--update-summary` — patch the dataset `summary.json` with an `evaluation_counts` rollup and a per-tool `evaluation` subsection. Implies `--update-evaluation`.
- `--tool <name>` — triage only one tool's verdicts (e.g. `--tool picus`).

Prerequisites: the `claude` CLI must be on PATH for `--auto`. Dry-run (default) needs no CLI.

#### Step 4 — Print the final results

```bash
# Tabular summary: header, TP/FN/Undecided rollup, per-tool counts, and
# a per-(bug, tool) table sorted by verdict.
python3 scripts/print_zkbugs_summary.py output/zkbugs-run

# Drill down by verdict or tool:
python3 scripts/print_zkbugs_summary.py output/zkbugs-run --filter FalseNegative
python3 scripts/print_zkbugs_summary.py output/zkbugs-run --tool picus
python3 scripts/print_zkbugs_summary.py output/zkbugs-run --no-rows
```

Raw JSON is always available too:

```bash
jq '.evaluation_counts' output/zkbugs-run/summary.json
jq '.bugs[] | select(.status=="skipped") | {bug_name, reason}' \
  output/zkbugs-run/summary.json
jq '.' output/zkbugs-run/<some_bug>/circomspect/evaluation.json
```

#### Step 5 — Inspect individual cases

Each bug dir has the per-tool detail:

```
output/zkbugs-run/<bug_name>/
├── ground_truth.json           # expected vulnerability, location, refs
├── run.log                     # per-bug worker log (parallel runs only)
├── scratch/                    # precompile artifacts (.r1cs / .sym)
└── <tool>/
    ├── raw.txt                 # tool stdout/stderr
    ├── parsed.json             # tool-specific structured output
    ├── results.json            # unified findings
    ├── evaluation.json         # final verdict (triaged or not)
    ├── evaluation.original.json  # pre-triage verdict (only after --update-evaluation)
    └── triage.json             # skill response (only after --auto)
```

### zkbugs modes

- `--zkbugs-mode direct` (default) — run against each bug's isolated wrapper `circuit.circom`. Every bug supports this mode and it's the fastest path. circom link flags are still needed because the wrapper typically `include`s files from the codebase (e.g. `include "circuits/..."`).
- `--zkbugs-mode original` — run against the project's real entrypoint (`Original Entrypoint` in `zkbugs_config.json`). Requires `dataset/codebases/` to be populated.
- `--zkbugs-mode both` — run direct for every bug, then original **only** for bugs whose `Original Entrypoint` is non-empty (i.e. distinct from direct). Writes `<output>/direct/` + `<output>/original/` with their own per-mode `summary.json`, plus a combined `<output>/summary.json` that aggregates both. Scripts like `triage_zkbugs_run.py` and `print_zkbugs_summary.py` operate on each sub-dir independently.

### Selecting a subset of bugs

- `--bugs <sel1>,<sel2>,...` — comma-separated substrings matched against each bug's directory name or its `--dataset`-relative path.
- `--bugs-file <path>` — one selector per line (lines starting with `#` are ignored).

Both flags combine as a union. Missing-match exits with an error.

```bash
# Single bug
uv run python -m zkhydra.main zkbugs \
  --dataset zkbugs/dataset/circom --tools circomspect \
  --bugs veridise_decoder_accepting_bogus_output_signal

# Path fragment (matches all bugs under darkforest-v0.3/)
uv run python -m zkhydra.main zkbugs \
  --dataset zkbugs/dataset/circom --tools all \
  --bugs darkforest-eth/darkforest-v0.3

# From a file
uv run python -m zkhydra.main zkbugs \
  --dataset zkbugs/dataset/circom --tools all \
  --bugs-file my-selectors.txt
```

### Parallelism and random sampling

- `--jobs N` (default `1`) — dispatch one bug per worker process. Tools within a bug still run sequentially. Each worker writes its detailed log to `<output>/<bug_name>/run.log`; the top-level log stays a concise index.
- `--random-bugs N` — after selector filtering, randomly pick N bugs. Handy for quick parallel smoke tests. Ignored if N exceeds the runnable set.
- `--random-seed <int>` — make `--random-bugs` reproducible.

```bash
# 6 random bugs across 4 workers, reproducible
uv run python -m zkhydra.main zkbugs \
  --dataset zkbugs/dataset/circom --tools all \
  --jobs 4 --random-bugs 6 --random-seed 42 \
  --timeout 600 --output output/parallel-smoke
```

`--jobs 1` is byte-identical to a serial run. `summary.json` adds an `errors` field and a `jobs` field; rows are sorted by `(status, bug_name)` so diffs between serial and parallel runs stay clean.

## Supported Tools

- **circomspect** - Static analyzer and linter
- **circom_civer** - SMT-based verification with CVC5
- **Picus** - Symbolic execution via Rosette
- **EcneProject** - Julia-based circuit analysis
- **zkFuzz** - Fuzzing-based bug detection
- **circom_auditor** - 9-agent parallel LLM audit via [zksecurity/zk-skills](https://github.com/zksecurity/zk-skills) — **native-only, not bundled in Docker**; ~3-5 min per circuit

### circom-auditor — native-only

> ⚠️ **`circom_auditor` only runs in native mode.** It is *not* installed in the zkhydra Docker image. If you try to invoke it inside `docker-compose run`, the tool plugin will exit with an error pointing back here.

`circom_auditor` invokes the [zksecurity/zk-skills](https://github.com/zksecurity/zk-skills) `circom-auditor` Claude Code skill, which spawns 9 specialist sub-agents (vector-scan, signal-flow, range-check, arithmetic-field, selector-mux, invariant, intent-binding, first-principles, free-flow) in parallel and produces a deduplicated, gate-validated security report.

The reason for native-only: Claude Code stores subscription/OAuth credentials in the host OS keychain (macOS Keychain / libsecret on Linux / DPAPI on Windows). Those credentials cannot be mounted into a Linux container, so a containerised version would force everyone onto API-key billing. By keeping this tool native, you can use whatever auth your host's `claude` is set up with — subscription, API key, or both. (The same constraint applies to any other LLM CLI that uses keychain-backed OAuth, e.g. OpenAI's Codex; that's also why `circom-auditor` is Claude-only — it depends on Claude Code's `--plugin-dir` skill system, which Codex doesn't implement.)

#### One-time host setup

```bash
# 1. Install Claude Code CLI
npm install -g @anthropic-ai/claude-code

# 2. Authenticate — pick one
claude login                       # subscription, opens browser, stores in OS keychain
# OR
export ANTHROPIC_API_KEY=sk-ant-... # API key, pay per token

# 3. Install zk-skills (the repo doubles as a plugin dir thanks to its
#    committed `skills/circom-auditor` symlink — no extra scaffolding needed)
git clone https://github.com/zksecurity/zk-skills.git ~/zk-skills

# 4. Tell zkhydra where the plugin dir is (add this to your shell rc)
export CLAUDE_PLUGIN_DIR=~/zk-skills
```

#### Run it

From a checkout of zkhydra, **without Docker**:

```bash
uv run python -m zkhydra.main analyze \
  --input examples/test_bug/circuits/circuit.circom \
  --tools circom_auditor \
  --timeout 600
```

#### Mixed sweep — fast static tools in Docker, LLM auditor natively

```bash
# 1. Static tools in the container (fast, deterministic, no auth)
docker-compose run --rm zkhydra uv run python -m zkhydra.main zkbugs \
  --dataset zkbugs/dataset/circom \
  --tools circomspect,circom_civer,picus,zkfuzz \
  --bugs daira_hopwood_darkforest_v0_3_missing_bit_length_check \
  --output output/static-only

# 2. LLM auditor natively, against the same bug
uv run python -m zkhydra.main zkbugs \
  --dataset zkbugs/dataset/circom \
  --tools circom_auditor \
  --bugs daira_hopwood_darkforest_v0_3_missing_bit_length_check \
  --output output/llm-only

# 3. Merge per-bug findings.json files manually if you want a unified view
```

#### Caveats

- Each `circom_auditor` run spawns 9 parallel Claude sub-agents and takes 3-5 minutes wall-clock on a small bundle (1-5 templates / a few hundred lines). On larger scopes the wall-clock grows non-linearly — the 9 sub-agents each have to ingest the full bundle before producing findings.
- **Use a per-bug timeout of `1800` (30 min), not 24h.** A bug that doesn't finish in 30 min is hung — fail it and move on. The skill is designed for the 2-5 templates a developer is actively touching, not monorepo-sized audits.
- **Bundle-size guard:** the tool plugin refuses to launch on scratch dirs above 30 `.circom` files or 5 000 lines of source (override via `CIRCOM_AUDITOR_MAX_FILES` / `CIRCOM_AUDITOR_MAX_LINES` env vars). zkbugs reproducers from large monorepos like Panther transitively pull in ~200 files / ~50K lines via `-l` link flags; those will be skipped with a clear "bundle too large" failure rather than hanging the run.
- Cost: subscription quota (with `claude login`) or per-token API spend (with `ANTHROPIC_API_KEY`). Pair with `--tools` and `--bugs` filtering to avoid running it on every bug in a large dataset sweep unless that's what you want.
- The skill follows Circom `include` chains (so wrapper-only zkbugs reproducers see the actual buggy template body via the `-l` link flag → scratch-dir trick the tool plugin handles automatically).
- Output is rich markdown — the tool plugin parses the `## Findings` and `## Leads` sections into zkhydra's standardized `Finding` schema.

#### Eval-mode sandboxing (zkbugs honesty guarantees)

When you point `circom_auditor` at a zkbugs reproducer, the bug folder ships sidecar files that contain the literal answer key — `README.md` lists the vulnerability class, root cause, location, and proposed mitigation; `zkbugs_config.json` carries the same structured data. To prevent the LLM from "auditing" by reading the answer, the tool plugin runs every audit inside a fresh tmp dir and keeps the answer key out of it. Three layers of defence:

1. **Filesystem isolation** — the scratch dir contains *only* `.circom` source: the wrapper, any sibling `.circom` files at the top level of the bug dir, and symlinks to the linked codebase's source subdirectories. Excluded by name: `README*`, `zkbugs_config.json`, `zkbugs_*.sh`, `input.json`, `direct_input.json`. Excluded by directory blocklist: `test`, `tests`, `doc`, `docs`, `client`, `examples`, `node_modules`, hidden dirs, and a few other common project-noise names that could leak per-bug hints.
2. **Tool restrictions on the Claude CLI** — `--disallowedTools` blocks `WebSearch`, `WebFetch`, and the common Exa MCP web tools (`mcp__exa__web_search_exa`, `mcp__exa__web_fetch_exa`); `--setting-sources ""` skips the user/project/local Claude settings stack so personal MCP servers (Drive, Gmail, custom search, etc.) don't leak into the run.
3. **Plain-text instruction** — `--append-system-prompt` injects an explicit "sandboxed eval mode: no web, no external context, audit constraint logic only" note that every sub-agent reads.

Layer 1 is the load-bearing one; 2 and 3 are belt-and-suspenders. Net effect: when you run `circom_auditor` on `dataset/circom/.../daira_hopwood_..._missing_bit_length_check`, Claude sees a tmp dir with `circuit.circom` and a `circuits/` symlink — nothing that names the bug, no reference to the audit report, no exploit witness.

## Usage Modes

### 1. Analyze Mode

Run tools on a single circuit without ground truth.

```bash
uv run python -m zkhydra.main analyze \
  --input circuit.circom \
  --tools circomspect,circom_civer \
  --timeout 600 \
  --output results/
```

**Output**: Raw findings from each tool in `results/`

### 2. Evaluate Mode

Compare tool results against known vulnerabilities (requires zkbugs format config).

```bash
uv run python -m zkhydra.main evaluate \
  --input bug/zkbugs_config.json \
  --tools all
```

**Output**: Ground truth comparison, True Positives, False Negatives

### 3. zkbugs Mode

Run tools against the refactored zkbugs dataset.

```bash
uv run python -m zkhydra.main zkbugs \
  --dataset zkbugs/dataset/circom \
  --zkbugs-mode direct \
  --tools all \
  --timeout 600
```

**Output**: Per-bug analysis results, per-bug `ground_truth.json` (with the full refactored config: `codebase`, `direct_entrypoint`, `original_entrypoint`, `input`, `executed`, `compiled_direct`, `compiled_original`), and a dataset-level `summary.json` that records processed and skipped bugs with reasons.

## CLI Options

```bash
# analyze / evaluate
--input, -i        Circuit file (.circom) for analyze mode

# zkbugs
--dataset, -d      Path to <zkbugs>/dataset/circom
--zkbugs-mode      direct (default) | original
--bugs             Comma-separated bug selectors (substring match)
--bugs-file        File with one bug selector per line (# comments allowed)
--jobs, -j         Parallel workers (one bug per worker; default 1)
--random-bugs, -n  Randomly pick N bugs after selector filtering
--random-seed      Seed for --random-bugs

# shared
--tools, -t        Tools to run (comma-separated or 'all')
--output, -o       Output directory (default: output/)
--timeout          Timeout per tool in seconds (default: 1800)
--log-file         Enable file logging
--log-level        Logging verbosity (default: INFO)
--vanilla          Re-process existing raw output instead of running tools
```

### Companion scripts

| Script | Purpose |
|--------|---------|
| `scripts/triage_zkbugs_run.py <run>` | Walk a run dir and collect every `Undecided` verdict; with `--auto` invoke the `triage-zkbugs-finding` skill per case; with `--update-evaluation` / `--update-summary` write verdicts back into `evaluation.json` and `summary.json`. |
| `scripts/print_zkbugs_summary.py <run>` | Pretty-print a run's header, per-tool TP/FN/Undecided rollup, skipped/errored bugs, and the full per-(bug, tool) verdict table. Filters via `--tool` / `--filter`. |

## Examples

### Single Tool Analysis

```bash
docker-compose run --rm zkhydra uv run python -m zkhydra.main analyze \
  --input examples/test_bug/circuits/circuit.circom \
  --tools circomspect
```

### New-format smoke test (no zkbugs checkout required)

`examples/zkbugs_new_format/` ships a self-contained toy bug that mirrors the refactored layout:

```bash
uv run python -m zkhydra.main zkbugs \
  --dataset examples/zkbugs_new_format/dataset/circom \
  --zkbugs-mode direct \
  --tools circomspect \
  --timeout 30 \
  --output output/zkbugs-new-format-smoke
```

### Multiple Tools with Timeout

```bash
docker-compose run --rm zkhydra uv run python -m zkhydra.main analyze \
  --input examples/test_bug/circuits/circuit.circom \
  --tools circomspect,circom_civer,zkfuzz \
  --timeout 300
```

### Full zkbugs Evaluation

```bash
# From host machine with zkbugs cloned locally
docker-compose run --rm zkhydra uv run python -m zkhydra.main zkbugs \
  --dataset zkbugs/dataset/circom \
  --zkbugs-mode direct \
  --tools all \
  --timeout 600 \
  --log-file \
  --output output/zkbugs-run
```

### Single bug (fast feedback loop)

```bash
docker-compose run --rm zkhydra uv run python -m zkhydra.main zkbugs \
  --dataset zkbugs/dataset/circom \
  --tools circomspect,circom_civer \
  --bugs veridise_decoder_accepting_bogus_output_signal \
  --timeout 120
```

### circom-auditor (native only — single circuit)

> See the **circom-auditor — native-only** section above for the one-time host setup. Briefly: install Claude Code, run `claude login` (subscription) or set `ANTHROPIC_API_KEY`, clone zk-skills, and `export CLAUDE_PLUGIN_DIR=~/zk-skills`.

```bash
uv run python -m zkhydra.main analyze \
  --input examples/test_bug/circuits/circuit.circom \
  --tools circom_auditor \
  --timeout 600
```

### circom-auditor on a single zkbugs reproducer (native)

```bash
uv run python -m zkhydra.main zkbugs \
  --dataset zkbugs/dataset/circom \
  --tools circom_auditor \
  --bugs veridise_decoder_accepting_bogus_output_signal \
  --timeout 600
```

## Output Structure

```
output/
└── analyze_YYYYMMDD_HHMMSS/
    ├── circomspect/
    │   ├── raw.txt          # Raw tool output
    │   ├── tool_output.json # Execution metadata
    │   ├── parsed.json      # Structured findings
    │   └── results.json     # Standardized format
    ├── circom_civer/
    │   └── ...
    └── summary.json         # Aggregated results
```

For zkbugs mode:
```
output/zkbugs-run/
├── <bug_name>/
│   ├── ground_truth.json        # includes new keys (codebase, entrypoints, compile flags, mode)
│   ├── scratch/                 # precompile artifacts (.r1cs / .sym / compile.log)
│   ├── circomspect/
│   │   ├── raw.txt
│   │   ├── results.json
│   │   └── evaluation.json      # TP/FN/Undecided
│   └── ...
└── summary.json                 # processed + skipped rows with reasons, per-mode totals
```

## Existing zkbugs analysis

You can find a report of the zkbugs analysis in `output/zkbugs-report.pdf` and you can download a tar with all the results here: https://drive.google.com/file/d/1zTIrrVqy0MXMxC4tRiPoFMEfXv-2TLYY/view?usp=sharing.

## Installation (Local Development)

### Prerequisites
- Ubuntu 24.04
- Python 3.12+
- Rust toolchain
- Julia, Node.js, Racket

### Build from Source

```bash
# Clone repository with submodules
git clone --recurse-submodules https://github.com/zksecurity/zkhydra.git
cd zkhydra

# Run setup script (installs all dependencies and builds tools)
./setup.sh

# Run zkHydra
uv run python -m zkhydra.main --help
```

### Docker Build

```bash
# Build image locally (takes 30-60 minutes)
docker build -t zkhydra:latest .

# Or use docker-compose
docker-compose build
```

## Development

### Code Quality

```bash
# Format and lint (requires uv)
make all

# Or manually
uv run black zkhydra/
uv run isort zkhydra/ --profile black
uv run ruff check zkhydra/ --fix
```

### Project Structure

```
zkhydra/
├── zkhydra/              # Python package
│   ├── tools/           # Tool wrappers (circomspect.py, etc.)
│   ├── cli.py           # CLI argument parsing
│   ├── core.py          # Execution orchestration
│   └── main.py          # Entry point
├── tools/               # Tool source repos (git submodules)
├── examples/            # Example circuits for testing
├── docker-compose.yml   # Docker configuration
└── Dockerfile          # Multi-stage build with all tools
```

## Troubleshooting

### Tools Timeout

Increase timeout for slow tools:
```bash
--timeout 1800  # 30 minutes
```

### Out of Memory

For large circuits, run tools individually:
```bash
--tools circomspect  # Run one at a time
```

### Docker Issues

```bash
# Pull latest image
docker pull ghcr.io/zksecurity/zkhydra:latest

# Rebuild locally if needed
docker-compose build --no-cache
```

## Funding

This project was partially funded by an [Ethereum Foundation](https://esp.ethereum.foundation/) grant.

## License

See [LICENSE](LICENSE) file.

## Resources

- **zkbugs Dataset**: https://github.com/zksecurity/zkbugs
- **Issues**: https://github.com/zksecurity/zkhydra/issues
