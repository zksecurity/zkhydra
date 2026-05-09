# Triage walk-throughs

Concrete examples showing how to apply the decision rules from
`SKILL.md`. Use these to calibrate borderline cases.

## Example 1 — circomspect, line match inside template

**Bug:** `iden3/circomlib/veridise_decoder_accepting_bogus_output_signal`
**GT location:** `circuits/multiplexer.circom:85-86`, function `Decoder`
**GT vulnerability:** Under-Constrained
**circomspect finding:**
```
{ "bug_title": "UnderConstrainedSignal",
  "unified_bug_title": "Under-Constrained",
  "file": "multiplexer.circom",
  "position": {"line": 86, "template": "Decoder", "column": 5} }
```

Decision: **TruePositive**, confidence `high`.
Reason: file basename + line both inside `85-86`, category matches,
template matches `Decoder`.

## Example 2 — circomspect, 8 warnings, none Under-Constrained

**Bug:** `trailofbits_unsafe_use_of_num2bits_in_multiple_circuits`
**GT vulnerability:** Under-Constrained
**circomspect findings:** 8 entries, all `unified_bug_title=Warning`
(ShadowingVariable, FieldElementArithmetic, …). No CS0013..CS0018.

Decision: **FalseNegative**, confidence `high`.
Reason: category mismatch across all findings; circomspect CAN
detect under-constrained (CS0014..CS0017) but didn't here.

## Example 3 — circom_civer, component match in buggy list

**Bug:** `<...>/veridise_private_information_leakage`
**GT function:** `Main`
**civer parsed output:**
```
buggy_components: [ "Main(...)", "HelperA(...)" ]
timed_out_components: []
verified_components: [ "HelperB(...)" ]
```

Decision: **TruePositive**, confidence `medium-to-high`.
Reason: `Main` listed in `buggy_components`; civer is exactly
the tool for Under-Constrained / Over-Constrained bugs.

## Example 4 — picus, signal path outside target function

**GT function:** `RangeProof`
**picus output:**
```
signals_with_multiple_values: [
  { name: "main.LessThan.out", template: "main.LessThan" }
]
```

Decision: **Undecided**, confidence `low`.
Reason: counterexample signal sits in `LessThan`, not `RangeProof`.
`LessThan` IS used by `RangeProof` — but without source confirmation
that the under-constraint flows through, don't promote. Note: if the
source has `RangeProof` instantiating a buggy `LessThan` and the GT
is really about that chain, a human reviewer will promote. Leave
for human.

## Example 5 — ecneproject, unsound verdict

**GT vulnerability:** Under-Constrained
**ecne output:** `"R1CS function circuit has potentially unsound constraints"`.

Decision: **TruePositive**, confidence `low`.
Reason: ecne has no per-location info; "unsound" is consistent
with GT's Under-Constrained category and the circuit under
analysis is the GT circuit. Confidence low because ecne
can over-flag.

## Example 6 — tool N/A for category

**GT vulnerability:** Computational-Issue
**tool:** picus
**picus output:** `"The circuit is properly constrained"`.

Decision: **Undecided**, `"tool N/A for Computational-Issue"`,
`manual_analysis: N/A`.
Reason: picus only detects under-constraint; GT isn't in its scope.
Don't emit FalseNegative because the tool wasn't expected to hit
this category.

## Reading circom source at a location

When you need to disambiguate whether a finding's line sits inside
a template body:

1. Open `<codebase>/<location.Path>` (e.g. the absolute path
   recorded in `ground_truth.codebase + location.Path`).
2. Grep for `template <Function>` — that line marks the template
   header.
3. The template ends at the matching closing brace. A pragmatic
   proxy: the next `template ` declaration in the file.
4. A finding's line is "inside the template" iff
   `template_start_line < finding_line < next_template_start_line`.

Apply this when GT's `Line` range looks narrower than what the
audit actually covers (audits often point at the vulnerable
`<--` line, while tools flag the enclosing constraint block).

## Anti-patterns

- **Don't promote on unified_title alone.** Warning+Under-Constrained
  category mismatch is a signal, not a verdict on its own.
- **Don't promote when only the file basename matches and the line
  is wildly off** (e.g. line 200 with a GT range of 10-15). Keep
  Undecided.
- **Don't rely on the short_description** for ambiguous word matches
  ("signal X is unconstrained" is fine; "constraint is subtle" is not).
- **Never fabricate a line number** if the tool didn't emit one.
  Either match by template/signal or stay Undecided.
