"""
circom-auditor (Codex variant) — wraps the circom-auditor skill instructions
via the OpenAI Codex CLI (`codex --full-auto`).

Unlike the Claude variant, Codex has no plugin system, so the SKILL.md content
is read from disk and injected directly into the initial prompt. Codex then
audits the sandboxed circuit files following the same instructions and produces
a report in the same markdown format, which the shared parser handles.

**Native-only tool.** API credentials (OPENAI_API_KEY) must be available in
the host environment. Does not run inside Docker.

Setup (one-time, on host):

  1. Install Codex CLI: ``npm install -g @openai/codex``
  2. Set API key: ``export OPENAI_API_KEY=sk-...``
  3. Point at the skill directory — either reuse the Claude plugin dir::

         export CODEX_PLUGIN_DIR=$CLAUDE_PLUGIN_DIR

     or clone zk-skills and set up separately::

         git clone https://github.com/zksecurity/zk-skills.git ~/zk-skills
         mkdir -p ~/codex-plugin/skills
         ln -s ~/zk-skills/circom-auditor ~/codex-plugin/skills/circom-auditor
         export CODEX_PLUGIN_DIR=~/codex-plugin

Runtime characteristics:

- Each run takes 3-10 minutes depending on circuit size and model.
- Consumes OpenAI API tokens (model: configurable via CODEX_MODEL env var).
- The skill is injected into the prompt rather than loaded via a plugin.
"""

import logging
import os
import sys
from pathlib import Path

from zkhydra.tools.base import Input, ToolOutput
from zkhydra.tools.circom_auditor_base import CircomAuditorBase

_SANDBOX_NOTE = (
    "Sandboxed evaluation mode. Do NOT perform web searches or external lookups. "
    "Do NOT run shell commands (circom, node, npm, snarkjs, etc.). "
    "Do NOT create or modify any files. "
    "Your only permitted actions are reading .circom files already present in "
    "the working directory. Audit only the constraint system. "
    "Output your complete findings report to stdout following the report format "
    "specified in the skill instructions above. Do NOT write any files."
)


class CircomAuditorCodex(CircomAuditorBase):
    """ZK-Security circom-auditor via OpenAI Codex CLI.

    Reads SKILL.md from CODEX_PLUGIN_DIR (falls back to CLAUDE_PLUGIN_DIR),
    injects it as the leading context in the prompt, then invokes
    `codex --full-auto` from a sandboxed scratch directory.
    """

    def __init__(self) -> None:
        super().__init__("circom_auditor_codex")

        if not self.check_binary_exists("codex"):
            logging.error(
                "circom_auditor_codex: `codex` not found on PATH. Install with "
                "`npm install -g @openai/codex` and set OPENAI_API_KEY."
            )
            sys.exit(1)

        # Accept either CODEX_PLUGIN_DIR or CLAUDE_PLUGIN_DIR so users who
        # already set up the Claude variant can reuse the same skill dir.
        plugin_dir = os.environ.get("CODEX_PLUGIN_DIR") or os.environ.get(
            "CLAUDE_PLUGIN_DIR"
        )
        if not plugin_dir:
            logging.error(
                "circom_auditor_codex: neither CODEX_PLUGIN_DIR nor "
                "CLAUDE_PLUGIN_DIR is set. Clone "
                "https://github.com/zksecurity/zk-skills, symlink "
                "`circom-auditor/` under <plugin-dir>/skills/, and "
                "export CODEX_PLUGIN_DIR=<plugin-dir>."
            )
            sys.exit(1)

        skill_path = Path(plugin_dir) / "skills" / "circom-auditor" / "SKILL.md"
        if not skill_path.is_file():
            logging.error(
                "circom_auditor_codex: SKILL.md not found at %s. The plugin "
                "directory must contain `skills/circom-auditor/SKILL.md`.",
                skill_path,
            )
            sys.exit(1)

        self.skill_content = skill_path.read_text(encoding="utf-8")

        if not os.environ.get("OPENAI_API_KEY"):
            logging.warning(
                "circom_auditor_codex: OPENAI_API_KEY is not set. "
                "The run will likely fail with an authentication error."
            )

    def _internal_execute(self, input_paths: Input, timeout: int) -> ToolOutput:
        """Run `codex --full-auto` on a sandboxed copy of the circuit dir.

        The SKILL.md content is prepended to the prompt so Codex receives the
        same audit instructions as the Claude variant. The shared parser then
        handles the output, which should follow the same markdown report format.
        """
        circuit_file_path = Path(input_paths.circuit_file)
        target_dir, target_file, scope = self._prepare_scratch_dir(
            input_paths, circuit_file_path
        )

        prompt = (
            f"{self.skill_content}\n\n"
            "---\n\n"
            f"Audit target: `{target_file.name}` — {scope.summary_line()}\n\n"
            f"{_SANDBOX_NOTE}"
        )

        # --full-auto: non-interactive, auto-approve all actions.
        # Adjust flags if your Codex CLI version uses a different flag name
        # (e.g. `-a full-auto` or `--approval-mode full-auto`).
        cmd = ["codex", "--full-auto", prompt]

        original_cwd = Path.cwd()
        logging.info(
            "circom_auditor_codex: launching codex in sandbox %s (target=%s)",
            target_dir,
            target_file.name,
        )
        try:
            self.change_directory(target_dir)
            return self.run_command(cmd, timeout, str(target_dir))
        finally:
            self.change_directory(original_cwd)
