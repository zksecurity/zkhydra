# TODO

Follow-ups for the zkbugs new-format migration (branch
`feat/zkbugs-new-format`):

- [ ] **Full dataset re-run** once upstream PR #65 and the
  `circom-link-flags-contract` branch are merged into
  `zksecurity/zkbugs`. `zkbugs` is no longer vendored as a
  submodule — clone it separately and pass `--dataset
  <path>/zkbugs/dataset/circom`. Run `--zkbugs-mode direct` and
  `--zkbugs-mode original` across all bugs, collect fresh results,
  and publish the updated evaluation alongside
  `output/zkbugs-report.pdf`.
