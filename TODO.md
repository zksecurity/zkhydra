# TODO

Follow-ups for the zkbugs new-format migration (branch
`feat/zkbugs-new-format`):

- [ ] **Bump the `zkbugs/` submodule** once upstream PR #65 (and the
  `circom-link-flags-contract` branch) are merged into
  `zksecurity/zkbugs`. The submodule is currently pinned at a
  pre-refactor commit; `print_bug_vars.sh` only exists on the
  runner-contract branch.
- [ ] **Full dataset re-run** once the submodule bump lands: run
  `--zkbugs-mode direct` and `--zkbugs-mode original` across all
  bugs, collect fresh results, and publish the updated evaluation
  alongside `output/zkbugs-report.pdf`.
- [ ] **Helper skills for validating tool findings against ground
  truth**: current `evaluate_zkbugs_ground_truth` implementations
  return `Undecided` for anything that isn't a trivial match. Add
  reusable skills/agents that triage `Undecided` verdicts
  per-tool (inspect raw output, cross-reference the bug's
  Location, promote to TruePositive / FalseNegative with a reason).
