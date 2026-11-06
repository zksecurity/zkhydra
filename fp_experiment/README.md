# FP experiment: false positives on audited, battle-tested Circom projects

RQ2 measures whether tools find known bugs. This experiment measures the other
side: how often they raise alarms on correct code, and how much effort it takes
to triage those alarms. We run the six Circom tools from RQ2 (Circomspect,
CIVER, Picus, Ecne, zkFuzz, ConsCS), in the same configuration, on 9 audited,
battle-tested projects (25 circuits). We triage every soundness alert and report
per-tool false positives together with the triage effort. The results are
indicative, not a population estimate.

## Method

**Project selection.** A project is included if it meets all four criteria:
1. It has open-source Circom circuits on GitHub.
2. It has at least one public third-party security audit covering the circuits.
3. It is battle-tested: deployed in production with real users or value, or a
   library reused by deployed circuits.
4. Its circuits compile with circom 2.2.3.

Eligible projects are ranked by GitHub stars (snapshot 2026-11-05). Each project
is pinned to its post-audit commit: the first release, or the fix commit, that
includes the audit fixes.

**Circuits.** We use each project's own production `component main` circuits
with their deployed parameters, or, for libraries, the repo's own test mains of
the audited templates. Circuits above 10M constraints are left out for resource
reasons. Two patches are applied, neither of which changes circuit semantics:
- `tornado-core-circom2-port.patch` is a syntax-only port of the circom-0.x
  code to circom 2.
- `privacy-pools-core-mains.patch` adds the two main files the project
  instantiates in its own `src/index.ts`.

**Known unfixed findings.** Audit findings that are acknowledged but not fixed
at the pinned commit are listed per project (`known_unfixed`). An alert on one
of them is a real issue, not a false positive.

**Tools.** We use the same six tools and configuration as RQ2: 1,800 s timeout
per tool per circuit, circom 2.2.3, and the zkhydra Docker image. Circuits run
one at a time (`--jobs 1`) in a container capped at 24 GB of memory with no
swap, so every tool run gets the same resources. A tool that exceeds the cap is
killed and counted as failed. Each tool gets its own temp directory. When the
tool returns, any process it left running is killed (for example Picus's solver
after a timeout) and its temp files are deleted. Runs that time out or fail are
reported separately and excluded from that tool's FP numbers.

**Alerts.** Soundness alerts (under-constrained, over-constrained,
computational) are the candidate false positives. Circomspect lint warnings are
reported as review burden only. Circomspect parser errors mark the run as
failed.

**Triage.** Triage happens in two passes:
1. Claude proposes a verdict for each soundness alert (`triage_fp_run.py --auto`).
2. An author reviews every alert, accepts or overrides the proposal, and the
   review time is logged (`review_fp_triage.py`).

Only the author's verdict counts. The verdicts are `FalsePositive`, `RealIssue`
and `Undecided`. The triage effort is the authors' review time; the AI-author
agreement is reported alongside it. The paper discloses the AI assistance.

**Metrics per tool:**
- runs completed / attempted
- circuits with ≥1 alert
- soundness alerts
- FP / Real / Undecided
- FP rate per circuit (circuits with ≥1 FP / completed runs)
- lint warnings
- triage time

**Limitations.**
- The sample is small and purposive, and stars measure popularity, not quality.
- Audited code can still contain bugs, which is why every alert is triaged.
- Tools that time out on large circuits have smaller denominators.

## Projects

| Project | ★ | Audit(s) | Commit | Circuits (constraints) |
|---|---|---|---|---|
| [tornado-core](https://github.com/tornadocash/tornado-core) | 1680 | ABDK 2019 | `a533ad9ffb` | withdraw (59,009) |
| [self](https://github.com/selfxyz/self) | 1267 | zkSecurity 2025 | `b50a2892be` | register-sha256-sha256-sha256-rsa-65537-4096 (3,314,606), dsc-sha256-rsa-65537-4096 (6,436,994), vc-and-disclose (225,194) |
| [semaphore](https://github.com/semaphore-protocol/semaphore) | 1095 | Veridise 2023 | `1bb57ca607` | semaphore-v3-20 (17,689) |
| [circomlib](https://github.com/iden3/circomlib) | 751 | Veridise 2022 | `cff5ab6288` | poseidon3 (765), eddsaposeidon (21,246), smtverifier10 (12,582), lessthan (36), pedersen2 (8,127), babypbk (10,114) |
| [maci](https://github.com/privacy-ethereum/maci) | 596 | HashCloak 2022, 2026 | `4d0e3a35f9` | maci-polljoining-10 (23,926), maci-messageprocessorqv-10-20-2 (2,244,412), maci-votetallyqv-10-1-2 (100,082) |
| [zk-email-verify](https://github.com/zkemail/zk-email-verify) | 435 | yAcademy 2023; zkSecurity 2024; Matter Labs 2024 | `9ed3769dc3` | emailverifier (5,993,156), rsaverifier65537-121-17 (208,463), sha256bytes-640 (2,077,273), selectregexreveal-34-8 (1,416) |
| [privacy-pools-core](https://github.com/0xbow-io/privacy-pools-core) | 136 | Oxorio 2025 | `8da36d5e21` | withdraw (54,878), commitment (2,283) |
| [iden3-circuits](https://github.com/iden3/circuits) | 94 | Trail of Bits 2024 | `62b65d3cca` | authv3-40-64 (164,860), credentialatomicqueryv3offchain-40-32-64 (196,801), linkedmultiquery-10-32-64 (644,027) |
| [nocturne](https://github.com/nocturne-xyz/protocol) | 81 | Zellic 2023 | `f66fd0274e` | joinsplit (124,892), canonaddrsigcheck (35,226) |

`projects.json` holds the full record per project: audit report links,
deployment evidence, the pinned commit and why it was chosen, dependency steps,
circuits, and known unfixed findings.

## Running

You need Docker, plus Python 3.10+ and git on the host. Step 3 also needs the
`claude` CLI. The tool run (step 2) needs at least 32 GB of RAM and about 40 GB
of free disk, and takes one to two days. Run everything from the zkhydra repo
root.
`scripts/fp_docker.sh` runs a command inside the zkhydra image, which has all
six tools, with this checkout mounted.

```bash
docker pull ghcr.io/zksecurity/zkhydra:latest

# 1. Install: clone each project at its pinned commit, set up deps, compile-check every circuit
scripts/fp_docker.sh python3 scripts/install_fp_projects.py

# 2. Run the six tools
scripts/fp_docker.sh uv run python -m zkhydra.main fp --dataset output/fp-corpus/dataset/circom \
    --tools all --timeout 1800 --jobs 1 --output output/fp-run

# 3. AI proposals for every soundness alert
python3 scripts/triage_fp_run.py output/fp-run --dataset output/fp-corpus/dataset/circom --auto --jobs 4

# 4. Author review of every alert (interactive, resumable; --status shows progress)
python3 scripts/review_fp_triage.py output/fp-run --dataset output/fp-corpus/dataset/circom --reviewer <initials>

# 5. Report (per tool and per project, triage effort, LaTeX table)
python3 scripts/process_fp_results.py output/fp-run --json output/fp-metrics.json --latex output/fp-table.tex
```

Outputs:
- `output/fp-corpus/` holds the clones, one unit per circuit (`fp_config.json`),
  and `corpus.json` with the install and compile outcome of each circuit.
- `output/fp-run/<unit>/` holds `fp_candidates.json`, with alerts split into
  soundness / warnings / tool errors. Each `<tool>/` subfolder holds the raw and
  parsed tool output plus `fp_triage.json`, which contains the AI proposal and
  the author's verdict.
