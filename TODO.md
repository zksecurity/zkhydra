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
- [x] **Helper skills for validating tool findings against ground
  truth**: shipped as `.claude/skills/triage-zkbugs-finding/` plus
  `scripts/triage_zkbugs_run.py`. Run the script against a zkbugs
  output dir with `--auto` to invoke Claude per Undecided case.
