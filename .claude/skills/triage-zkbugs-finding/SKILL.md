---
name: triage-zkbugs-finding
description: Triage an Undecided verdict from a zkhydra zkbugs run. Given one bug's ground truth plus one tool's findings/raw/parsed output (optionally the circuit source at the bug's location), promote to TruePositive or FalseNegative with a justification, or confirm Undecided when neither is safe. Invoked by scripts/triage_zkbugs_run.py and usable directly on a single case.
---

# Triage zkbugs `Undecided` verdicts

`zkhydra`'s per-tool `evaluate_zkbugs_ground_truth` is intentionally
conservative — anything that isn't a trivial exact match becomes
`Undecided` with `need_manual_analysis=true`. This skill does that
manual step: inspect the tool's real output, cross-reference the
bug's `Location`, and return a firm verdict (or explain why the
case genuinely can't be decided without human review).

## Inputs

A single case bundle. Either pass the paths and the skill reads
them, or inline the contents:

- `ground_truth.json` — keys: `vulnerability`, `location.{Path,Function,Line}`,
  `short_description`, `codebase`, `direct_entrypoint`, `project`, `commit`,
  `similar_bugs`.
- `results.json` — unified findings list (each has `bug_title`,
  `unified_bug_title`, `position`, `file`, `description`, `metadata`).
- `parsed.json` — the tool's structured output (for finer signals
  like Picus' counterexample).
- `raw.txt` — first ~200 lines of the tool's stdout/stderr. Read
  only if `results.json` is ambiguous.
- Optional: circuit source at `<codebase>/<location.Path>` (or
  the direct wrapper), narrowed to `location.Line`.

Always know which tool produced the finding — different tools
surface different evidence (see Per-tool rules below).

## Decision rules

### TruePositive

Promote to **TruePositive** when ALL of the following hold:

1. The tool reported at least one finding whose vulnerability
   category is consistent with `ground_truth.vulnerability`
   (Under-Constrained, Over-Constrained, Computational-Issue).
   A `Warning` finding alone is not enough.
2. The finding's evidence (file, line, template/component, or
   signal) intersects `location.Path` + `location.Function` +
   `location.Line`. "Intersects" means:
   - File: basename of finding's file equals basename of
     `location.Path`, OR the finding's file resolves to the
     same path relative to the codebase.
   - Line: finding's line falls within the inclusive range
     parsed from `location.Line` (`"39-45"` → 39..45, `"45"` → 45).
     If a tool doesn't give lines (e.g. Picus, EcneProject), use
     template/component/signal match instead.
   - Function/template/signal: finding's
     `position.template` / `position.component` / `position.signal`
     contains or is contained in `location.Function` (case-insensitive).

When the tool's reported line is outside the GT range but within
the same function body (template start/end lines reachable from
reading the source), still promote — the audit location may point
at the vulnerable constraint while the tool flags the enclosing
template.

### FalseNegative

Promote to **FalseNegative** when:

- The tool produced no findings matching the GT vulnerability
  category at all (all findings are Warnings, or the tool reported
  "no bugs found"), **and**
- GT's vulnerability is one the tool is designed to detect (see
  tool capability matrix below). If the tool can't detect this
  vulnerability class, keep `Undecided` with reason `"tool N/A for
  <category>"`.

### Undecided (keep)

Keep **Undecided** when:

- Tool findings are in a different file/template entirely and you
  cannot establish any connection from the source.
- The tool output is truncated or malformed.
- Picus returned a counterexample but the signal path doesn't
  match GT's function, and reading the source wouldn't resolve it
  without running the circuit.
- Multiple plausible matches exist; pick the most likely but
  downgrade to `Undecided` when the evidence conflicts.

Always prefer **Undecided** over a wrong promotion — a false
TruePositive corrupts the evaluation more than an honest
"unresolved" row.

## Per-tool rules

### circomspect

- Findings carry `position.line`, `position.column`,
  `position.template`, `file`, `metadata.code` (CS0001…CS0018,
  CA01).
- Promote to TP when a finding's `file` basename matches
  `location.Path` basename AND `position.line` ∈ `location.Line`
  range. Relaxation: if `position.template` equals
  `location.Function`, accept any line within the template body
  (read the source and find the `template Foo()` boundaries).
- Warning-only codes (CS0001..CS0012) don't promote unless GT is
  a Warning-class bug (very rare).
- Promote to FN when no CS0013..CS0018 / CA01 finding exists
  anywhere in the circuit.

### circom_civer

- Parsed output lists `buggy_components`, `timed_out_components`,
  `verified_components` by template name.
- Promote to TP when `location.Function` appears in
  `buggy_components` (or a parent that contains it).
- Promote to FN when `location.Function` appears in
  `verified_components` and GT is Under-Constrained / Over-Constrained.
- Timeouts → Undecided (`"civer timeout on target component"`).

### picus

- Finding carries `position.signal` (e.g. `main.Decoder.out`) and
  a two-witness counterexample.
- Promote to TP when the signal path contains `location.Function`
  (case-insensitive) AND GT vulnerability is Under-Constrained.
- Keep Undecided when the counterexample uses a signal from an
  unrelated template — unless the source clearly chains through
  that template into the target.
- Picus can't detect Over-Constrained or Computational bugs →
  `Undecided` with reason `"tool N/A for <category>"` when GT is
  one of those.

### ecneproject

- Output is essentially a single verdict per circuit (sound vs.
  potentially unsound) with no per-component detail.
- If unsound AND GT is Under-Constrained → `TruePositive` with
  low-confidence reason `"ecne flagged unsound; no per-location
  info available"`.
- If sound AND GT is Under-Constrained → `FalseNegative`.
- Over-Constrained or Computational bugs → `Undecided` with
  `"tool N/A for <category>"`.

### zkfuzz

- Parsed output reports `result`, `vulnerability`, optional
  `signal`, `expected_value`, `assignments`.
- Promote to TP when the reported signal is inside
  `location.Function` and GT category matches
  (Under-Constrained / Over-Constrained / Computational-Issue).
- `result == "found_no_bug"` → FN when GT is a category zkfuzz
  can hit. Otherwise Undecided.

## Tool capability matrix

| Tool         | Under-Constrained | Over-Constrained | Computational | Warning |
|--------------|-------------------|------------------|---------------|---------|
| circomspect  | some (CS13–18, CA01) | no            | no            | yes     |
| circom_civer | yes               | yes              | no            | no      |
| picus        | yes               | no               | no            | no      |
| ecneproject  | yes               | no               | no            | no      |
| zkfuzz       | yes               | yes              | yes           | no      |

When a tool is N/A for a GT category, never promote to FN (the
tool wasn't expected to detect it). Emit `Undecided` with reason
`"tool N/A for <category>"`.

## Output format

Always return a JSON object with these keys, and nothing else:

```json
{
  "status": "TruePositive | FalseNegative | Undecided",
  "reason": "<one sentence — what in the evidence decided the verdict>",
  "manual_analysis": "Done | N/A",
  "manual_analysis_reasoning": "<concise rationale that cites specific finding ids, line numbers, template names, or signals>",
  "confidence": "high | medium | low"
}
```

- `manual_analysis`: `Done` when the skill produced a firm
  verdict; `N/A` only when the tool is capability-N/A for the
  category.
- `confidence`: `high` when a line+file match is exact or the tool
  explicitly asserted the vulnerability; `medium` when match is
  by template/function name only; `low` when verdict rests on
  circumstantial signal names or raw-output heuristics.

## Reference

For example triage walk-throughs and circuit-reading tips, see
`references/triage_walkthroughs.md`.
