"""
circom-auditor (Claude variant) — wraps the Claude Code skill at
https://github.com/zksecurity/zk-skills via `claude --print`.

**Native-only tool.** OAuth credentials live in the host OS keychain
(macOS Keychain / libsecret on Linux / DPAPI on Windows), which cannot
be mounted into a Linux container. Run zkhydra on the host.

Setup (one-time, on host):

  1. Install Claude Code CLI: ``npm install -g @anthropic-ai/claude-code``
  2. Authenticate: ``claude login``  (or ``export ANTHROPIC_API_KEY=...``)
  3. Clone zk-skills + symlink the skill::

         git clone https://github.com/zksecurity/zk-skills.git ~/zk-skills
         mkdir -p ~/audit-plugin/skills
         ln -s ~/zk-skills/circom-auditor ~/audit-plugin/skills/circom-auditor
         export CLAUDE_PLUGIN_DIR=~/audit-plugin

Runtime characteristics:

- Each run takes 3-5 minutes (the skill spawns 9 parallel sub-agents).
- Consumes Claude subscription quota or Anthropic API tokens.
"""

import logging
import os
import sys
from pathlib import Path

from zkhydra.tools.base import Input, ToolOutput
from zkhydra.tools.circom_auditor_base import CircomAuditorBase

# Tools the auditor must never invoke during eval. The first two are
# built-in Claude Code tools; the rest are common MCP web tools.
_DISALLOWED_TOOLS = (
    "WebSearch",
    "WebFetch",
    "mcp__exa__web_search_exa",
    "mcp__exa__web_fetch_exa",
)

_SANDBOX_SYSTEM_NOTE = (
    "Sandboxed evaluation mode. Do not perform web searches, web fetches, "
    "or any external lookups. Audit only the .circom source files in the "
    "current working directory. Reason from the constraint system alone."
)


class CircomAuditorClaude(CircomAuditorBase):
    """ZK-Security circom-auditor Claude skill, packaged as a zkhydra tool.

    Invokes `claude --print --plugin-dir $CLAUDE_PLUGIN_DIR` from a sandboxed
    scratch directory containing only the wrapper's include closure.
    """

    def __init__(self) -> None:
        super().__init__("circom_auditor_claude")

        if not self.check_binary_exists("claude"):
            logging.error(
                "circom_auditor_claude: `claude` not found on PATH. Install with "
                "`npm install -g @anthropic-ai/claude-code` and run "
                "`claude login` (subscription) or export ANTHROPIC_API_KEY."
            )
            sys.exit(1)

        self.plugin_dir = os.environ.get("CLAUDE_PLUGIN_DIR")
        if not self.plugin_dir:
            logging.error(
                "circom_auditor_claude: CLAUDE_PLUGIN_DIR is not set. Clone "
                "https://github.com/zksecurity/zk-skills, symlink "
                "`circom-auditor/` under <plugin-dir>/skills/, and "
                "export CLAUDE_PLUGIN_DIR=<plugin-dir>."
            )
            sys.exit(1)

        skill_path = (
            Path(self.plugin_dir) / "skills" / "circom-auditor" / "SKILL.md"
        )
        if not skill_path.is_file():
            logging.error(
                "circom_auditor_claude: SKILL.md not found at %s. The plugin "
                "directory must contain `skills/circom-auditor/SKILL.md`.",
                skill_path,
            )
            sys.exit(1)

        if not os.environ.get("ANTHROPIC_API_KEY"):
            logging.info(
                "circom_auditor_claude: no ANTHROPIC_API_KEY set — assuming "
                "host-level Claude Code auth (`claude login`). "
                "If the run fails with a 401, set ANTHROPIC_API_KEY."
            )

    def _internal_execute(self, input_paths: Input, timeout: int) -> ToolOutput:
        """Run `claude --print` on a sandboxed copy of the circuit dir."""
        circuit_file_path = Path(input_paths.circuit_file)
        target_dir, target_file, scope = self._prepare_scratch_dir(
            input_paths, circuit_file_path
        )

        prompt = (
            f"run circom auditor on {target_file.name} (sandboxed eval — "
            f"no web, no external context, audit constraint logic only). "
            f"Scope: {scope.summary_line()}"
        )
        cmd = [
            "claude",
            "--print",
            "--plugin-dir",
            self.plugin_dir,
            "--dangerously-skip-permissions",
            "--setting-sources",
            "",
            "--disallowedTools",
            " ".join(_DISALLOWED_TOOLS),
            "--append-system-prompt",
            _SANDBOX_SYSTEM_NOTE,
            "--output-format",
            "text",
            prompt,
        ]

        original_cwd = Path.cwd()
        logging.info(
            "circom_auditor_claude: launching claude in sandbox %s "
            "(target=%s, plugin_dir=%s)",
            target_dir,
            target_file.name,
            self.plugin_dir,
        )
        try:
            self.change_directory(target_dir)
            return self.run_command(cmd, timeout, str(target_dir))
        finally:
            self.change_directory(original_cwd)
