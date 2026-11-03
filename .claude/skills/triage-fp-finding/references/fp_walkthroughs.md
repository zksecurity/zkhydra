# FP triage walk-throughs

Concrete examples for the decision rules in `SKILL.md`. Every finding here is
raised on a **clean / fixed** circuit, so the question is always "is the tool
wrong (FalsePositive), right about a missed bug (RealIssue), just lint
(Warning/Style), or undecidable?" Calibrate borderline cases against these.

## Example 1 — circomspect lint on correct code

**Unit:** `audited/circomlib/comparators` (Origin: audited)
**Finding:**
```
{ "bug_title": "ShadowingVariable",
  "unified_bug_title": "Warning (Other -- probably not a bug)",
  "file": "comparators.circom", "position": {"line": 42, "template": "LessThan"} }
```
Decision: **Warning/Style**, confidence `high`.
Reason: WARNING category → review burden only, never a soundness FP. No source
reading needed.

## Example 2 — civer flags a fully-constrained component

**Unit:** `audited/tornado-core/withdraw`
**Finding:** `circom_civer`, `buggy_components: ["CommitmentHasher(...)"]`,
Under-Constrained.
Source check: every output of `CommitmentHasher` (`commitment`, `nullifierHash`)
is pinned with `<==` and the Pedersen/MiMC sub-signals are all constrained.
Decision: **FalsePositive**, confidence `medium`.
Reason: civer named the component, but the source constrains all its outputs;
weak-safety verdict is spurious on this correct template.

## Example 3 — fixed-commit unit, tool still flags the patched line

**Unit:** `fixed/iden3/circomlib/...decoder...` (Origin: fixed-commit of
`veridise_decoder_accepting_bogus_output_signal`)
**Finding:** `circomspect` `UnderConstrainedSignal` at `Decoder:86`.
Source check: the fix added `success * (success - 1) === 0` and
`out[i] * (...) === 0`; signal `success` is now constrained.
Decision: **FalsePositive**, confidence `high`.
Reason: the patch constrains the previously-free signal, yet circomspect still
reports it — a false alarm on fixed code. (If instead the patch were absent or
incomplete and the signal were still free, this would be `RealIssue`.)

## Example 4 — picus counterexample that violates a real constraint

**Unit:** `audited/semaphore/semaphore`
**Finding:** `picus`, `position.signal: "main.Tree.root"`, two witnesses.
Source check: tracing both witnesses, witness B violates
`root === hashes[depth]` — i.e. it is not actually a valid assignment.
Decision: **FalsePositive**, confidence `medium`.
Reason: the "second output" isn't consistent with the constraints; the
counterexample is spurious (often an R1CS-lowering artifact), not real
non-determinism.

## Example 5 — ecne "potentially unsound", no location

**Unit:** `audited/maci/processMessages`
**Finding:** `ecneproject`, `"potentially unsound constraints"`, whole-circuit.
Decision: **Undecided**, confidence `low`.
Reason: ecne gives no per-location detail and the circuit is too large to
hand-verify; ecne is known to over-flag. Don't call it FalsePositive without
confirming the circuit is sound. (Report it as an ecne alert; leave the verdict
to a human spot-check.)

## Example 6 — genuine missed under-constraint (rare)

**Unit:** `audited/<project>/<entrypoint>`
**Finding:** `zkfuzz` counterexample: output `out` takes two values.
Source check: `out <-- in \ 2;` with **no** `===` constraint pinning `out`.
Decision: **RealIssue**, confidence `high`.
Reason: the source confirms `out` is assigned (`<--`) but never constrained, so
two witnesses are genuinely valid — the audit missed it. Only call `RealIssue`
when the source makes the under/over-constraint unambiguous.

## Reading circom source at a finding

1. Open `<Codebase>/<finding.file>` (or the unit wrapper when the finding has no
   codebase-relative file), using the absolute path in the bundle.
2. Grep `template <position.template>` for the header; the body runs to the next
   `template ` declaration.
3. For the named signal, decide: is it pinned by `<==` / `===` (constrained) or
   only assigned by `<--` (computed, possibly free)? A free output that feeds a
   public/intermediate value is the signature of a real under-constraint.
4. For a fixed-commit unit, compare against the original bug (named in
   `Origin`): the fix should have added the missing constraint — confirm it is
   present at the flagged location.

## Anti-patterns

- **Don't call `FalsePositive` just because the project is "audited".** Audits
  miss bugs; confirm the constraint exists before clearing the tool.
- **Don't call `RealIssue` without the source showing a free/over-constrained
  signal.** Over-claiming a missed bug in a deployed project is worse than
  `Undecided`.
- **Don't count `Warning/Style` toward the soundness FP rate.** It is review
  burden, tracked separately.
- **Never invent a constraint you didn't read.** If you can't open the source,
  stay `Undecided`.
