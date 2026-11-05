---
name: triage-fp-finding
description: Propose a triage verdict for one candidate false positive from a zkhydra fp run. Given a single tool finding raised on an audited, battle-tested Circom project (plus the circuit source and provenance), classify it as FalsePositive (spurious alarm on correct code), RealIssue (a genuine bug — known-unfixed audit finding or new), Warning/Style (non-soundness lint), or Undecided. Invoked by scripts/triage_fp_run.py; an author verifies every proposal with scripts/review_fp_triage.py.
---

# Triage `fp` candidate false positives

The false-positive experiment runs the six Circom tools over battle-tested,
audited Circom projects at their post-audit commit. There is no ground-truth
vulnerability: **every finding is a candidate false positive**. This skill
inspects one finding against the real circuit source and *proposes* a
verdict; an author verifies every proposal before it is counted. The headline
metric counts soundness-class false alarms, so a wrong classification biases
the paper's FP numbers — **when in doubt, return `Undecided`.**

## Inputs

A single case bundle. Either pass the paths and the skill reads them, or inline
the contents:

- `fp_config` / provenance — keys: `Project`, `ProjectName`, `Commit`
  (post-audit), `Codebase`, `LinkPaths`, `Entrypoint`, `Origin` (`audited`),
  `Source.Audits` (auditor, date, report URL), `KnownUnfixed` (audit findings
  still present at this commit).
- `results.json` — unified findings list (each has `bug_title`,
  `unified_bug_title`, `position`, `file`, `description`, `metadata`).
- `parsed.json` — the tool's structured output (finer signals, e.g. Picus'
  counterexample, civer's component buckets).
- `raw.txt` — first ~200 lines of the tool's stdout/stderr. Read only if
  `results.json` is ambiguous.
- Circuit source at `<codebase>/<file>` (or the unit wrapper), narrowed to the
  finding's `position.line` / `position.template`. Reading the source is the
  core of the job — see `references/fp_walkthroughs.md`.

Always know which tool produced the finding; different tools surface different
evidence (see Per-tool rules).

## Decision rules

### Warning/Style  (decide first, cheaply)

If the finding's `unified_bug_title` is
`"Warning (Other -- probably not a bug)"` (circomspect lint: shadowing, unused
signal, field arithmetic, complexity, …), classify **`Warning/Style`** with
`confidence: high`. These are not soundness claims; they count toward **review
burden**, never toward the soundness false-positive rate. No source reading
needed.

### Known unfixed audit finding → RealIssue  (decide second)

An audited release may still ship findings the auditors marked acknowledged /
won't fix. They are listed in `provenance.KnownUnfixed` (each with `id`,
`title`, `location`, `status`). If the finding plausibly points at one of them
(same template/function or file region, compatible category — a whole-circuit
verdict from picus/ecne/conscs/civer counts when that template is instantiated
by the circuit and is the only soundness issue that could explain it),
classify **`RealIssue`** with reason `"known unfixed <id>"` and cite it. A
correct alert on a known, unfixed issue is not a false positive. If you cannot
tie it to a listed finding, continue with the rules below.

### FalsePositive

Classify **`FalsePositive`** when the finding is soundness-class
(Under-Constrained, Over-Constrained, Computational-Issue) **and** reading the
source shows the flagged signal/component/constraint is in fact **correctly
constrained / safe** — i.e. the tool is wrong on correct code. Typical evidence:

- Every output/intermediate signal the tool names is pinned by a `<==` or `===`
  constraint (not merely `<--`), so it cannot take two values.
- The tool's counterexample (Picus/zkfuzz/ConsCS) does not actually violate any
  constraint when traced through the source.

### RealIssue

Classify **`RealIssue`** (a genuine latent bug the audit or fix missed) only
with **strong, source-backed** evidence that the flagged signal/component is
truly under/over-constrained or computes incorrectly — e.g. an output assigned
with `<--` and never constrained, a missing range check the source confirms. Set
this bar high: an audited project flagged as `RealIssue` is a notable claim.
If you cannot confirm it from the source alone, use `Undecided`, not `RealIssue`.

### Undecided (keep — the safe default)

Keep **`Undecided`** when:

- The soundness of the flagged construct can't be settled without running the
  circuit or a solver (the common case for whole-circuit tools).
- `ecneproject` reports "potentially unsound" with no per-location detail and the
  circuit is too large to hand-verify.
- Tool output is truncated/malformed, or the counterexample signal path can't be
  tied to any constraint in the source.
- The tool is **capability-N/A** for the category it would need (see matrix);
  reason `"tool N/A for <category>"`, `manual_analysis: "N/A"`.

Prefer `Undecided` over a wrong `FalsePositive` (overstates FP rate) or a wrong
`RealIssue` (understates it, and over-claims a missed bug).

## Per-tool rules (what the evidence looks like)

- **circomspect** — soundness codes are CS0013–CS0018 / CA01 (Under-Constrained
  family); everything else (CS0001–CS0012) is `Warning/Style`. Read
  `position.{file,line,template}`; confirm whether the named signal is
  constrained in the template body.
- **circom_civer** — `parsed.buggy_components` lists templates failing weak
  safety. For each, check in source whether that template's outputs are actually
  under-constrained; if they are fully constrained, it's a `FalsePositive`.
  Timeouts → `Undecided`.
- **picus** — carries `position.signal` + a two-witness counterexample. Trace the
  signal: if both witnesses actually satisfy every constraint, it's a real
  non-determinism → lean `RealIssue`; if the counterexample violates a constraint
  the source does enforce, it's a `FalsePositive`/parse artifact. Picus is N/A for
  Over-Constrained / Computational.
- **ecneproject** — single circuit-level verdict, no location. "Potentially
  unsound" on clean code is usually a `FalsePositive`, but **low confidence** and
  often `Undecided` without per-location detail (ecne is known to over-flag).
- **zkfuzz** — reports a counterexample (`signal`, `expected_value`,
  `assignments`). If the assignment it claims is actually blocked by a constraint
  in the source, `FalsePositive`; if it genuinely satisfies all constraints,
  lean `RealIssue`.
- **conscs** — per-component UNDER/OVER verdict with a counterexample; treat like
  picus. `NOT SURE`/timeout never reach triage (not counted as findings).

## Tool capability matrix

| Tool         | Under-Constrained | Over-Constrained | Computational | Warning |
|--------------|-------------------|------------------|---------------|---------|
| circomspect  | some (CS13–18, CA01) | no            | no            | yes     |
| circom_civer | yes               | yes              | no            | no      |
| picus        | yes               | no               | no            | no      |
| ecneproject  | yes               | no               | no            | no      |
| zkfuzz       | yes               | yes              | yes           | no      |
| conscs       | yes               | yes              | no            | no      |

## Output format

Always return a JSON object with these keys, and nothing else:

```json
{
  "status": "FalsePositive | RealIssue | Warning/Style | Undecided",
  "reason": "<one sentence — what in the source/evidence decided it>",
  "manual_analysis": "Done | N/A",
  "manual_analysis_reasoning": "<concise rationale citing finding ids, line numbers, template names, signals, or the constraint that settles it>",
  "confidence": "high | medium | low"
}
```

- `manual_analysis`: `Done` for a firm verdict; `N/A` only when the tool is
  capability-N/A for the category.
- `confidence`: `high` when the source shows the constraint (or its absence)
  unambiguously, or the finding is a lint `Warning/Style`; `medium` when the
  verdict rests on template/component reasoning; `low` for circumstantial
  signal-name or whole-circuit heuristics.

## Reference

For worked FP triage examples and the circuit-reading recipe, see
`references/fp_walkthroughs.md`.
