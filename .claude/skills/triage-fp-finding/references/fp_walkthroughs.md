# FP triage walk-throughs

Concrete examples for the decision rules in `SKILL.md`. Every finding here is
raised on an **audited, battle-tested** circuit at its post-audit commit, so the
question is always "is the tool wrong (FalsePositive), right about a real bug
(RealIssue — known-unfixed or new), just lint (Warning/Style), or
undecidable?" The examples are illustrative, not results. Calibrate borderline
cases against them.

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

## Example 3 — alert on a known-unfixed audit finding

**Unit:** `audited/<library>/<entrypoint>`; `provenance.KnownUnfixed` lists
`{id: "V-XYZ-007", title: "Underconstrained outputs in Window4",
location: "circuits/pedersen.circom:Window4", status: "acknowledged"}`.
**Finding:** `picus` reports two witnesses differing in an output of the
`Window4` component instantiated by the circuit.
Decision: **RealIssue**, reason `"known unfixed V-XYZ-007"`, confidence `medium`.
Reason: the auditors documented this under-constraint and it was not fixed at
the pinned commit; the tool is right. Count it as a real issue, not an FP.

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
4. Check `provenance.KnownUnfixed` before deciding: an alert on a documented,
   unfixed audit finding is a `RealIssue`, not a false positive.

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
