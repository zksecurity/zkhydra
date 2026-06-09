"""
circom-auditor (Codex variant) — wraps the circom-auditor skill instructions
via the OpenAI Codex CLI (`codex exec`) and Codex's native skill discovery.

Unlike the Claude variant, Codex has no `--plugin-dir` flag. It discovers
skills from `.agents/skills`, user, admin, system, and installed plugin
locations. This wrapper locates the circom-auditor skill, exposes it inside the
scratch directory as `.agents/skills/circom-auditor` when needed, and invokes it
explicitly as `$circom-auditor`. The wrapper prebuilds the delegated agent
bundles and forbids Codex's local fallback path; if subagents are unavailable,
the run reports delegated mode as unavailable instead of doing a single-agent
audit.

**Native-only tool.** Codex CLI authentication must be available in the host
environment. Does not run inside Docker.

Setup (one-time, on host):

  1. Install Codex CLI: ``npm install -g @openai/codex``
  2. Authenticate: ``codex login`` or set ``CODEX_API_KEY`` for automation.
  3. Install the skill in a Codex skill location, for example::

         git clone https://github.com/zksecurity/zk-skills.git ~/zk-skills
         mkdir -p ~/.agents/skills
         ln -s ~/zk-skills/skills/circom-auditor ~/.agents/skills/circom-auditor

     A repo-local `.agents/skills/circom-auditor` symlink also works.
     For compatibility, CODEX_PLUGIN_DIR / CLAUDE_PLUGIN_DIR are still accepted
     if they point at a directory containing `skills/circom-auditor/SKILL.md`::

         export CODEX_PLUGIN_DIR=~/zk-skills

Runtime characteristics:

- Each run takes 3-10 minutes depending on circuit size and model.
- Consumes OpenAI API tokens or Codex account quota.
- Model is configurable via CODEX_MODEL env var.
"""

import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path

from zkhydra.tools.base import Input, OutputStatus, ToolOutput
from zkhydra.tools.circom_auditor_base import CircomAuditorBase

_SKILL_NAME = "circom-auditor"
_CONTEXT_DIR_NAME = "_circom_auditor_context"

_SANDBOX_NOTE = (
    "Sandboxed evaluation mode. Do NOT perform web searches or external lookups. "
    "Do NOT run build, compile, package-manager, solver, prover, network, or "
    "test commands (circom, node, npm, snarkjs, git, curl, etc.). Read-only "
    "file inspection commands such as cat, sed, rg, and wc are permitted only "
    "for .circom files already present in the working directory and markdown "
    "bundles under the delegated context directory. "
    "Do NOT rebuild audit context; delegated agent bundles are already present. "
    "Do NOT create or modify any files. "
    "Your only permitted actions are reading .circom files already present in "
    "the working directory and markdown bundles under the delegated context "
    "directory. Audit only the constraint system. "
    "Output your complete findings report to stdout following the report format "
    "specified in the skill instructions above. Do NOT write any files."
)


class CircomAuditorCodex(CircomAuditorBase):
    """ZK-Security circom-auditor via OpenAI Codex CLI.

    Uses Codex native skills (`.agents/skills` / user skills / admin skills),
    then invokes `codex exec` in a sandboxed scratch directory.
    """

    def __init__(self) -> None:
        super().__init__("circom_auditor_codex")

        if not self.check_binary_exists("codex"):
            logging.error(
                "circom_auditor_codex: `codex` not found on PATH. Install with "
                "`npm install -g @openai/codex` and run `codex login` or set "
                "CODEX_API_KEY."
            )
            sys.exit(1)

        self.skill_dir = self._find_skill_dir()
        if self.skill_dir is None:
            logging.error(
                "circom_auditor_codex: `%s` skill not found. Install it at "
                "~/.agents/skills/%s, repo .agents/skills/%s, or set "
                "CODEX_PLUGIN_DIR / CLAUDE_PLUGIN_DIR to a directory containing "
                "skills/%s/SKILL.md.",
                _SKILL_NAME,
                _SKILL_NAME,
                _SKILL_NAME,
                _SKILL_NAME,
            )
            sys.exit(1)

        if not os.environ.get("CODEX_API_KEY") and not os.environ.get(
            "OPENAI_API_KEY"
        ):
            logging.info(
                "circom_auditor_codex: no CODEX_API_KEY / OPENAI_API_KEY set; "
                "assuming saved Codex CLI auth."
            )

    @staticmethod
    def _as_skill_dir(path: Path) -> Path | None:
        """Accept a skill dir, a skills parent, or a legacy plugin root."""
        candidates = (
            path,
            path / _SKILL_NAME,
            path / "skills" / _SKILL_NAME,
            path / ".agents" / "skills" / _SKILL_NAME,
        )
        for candidate in candidates:
            if (candidate / "SKILL.md").is_file():
                return candidate.resolve()
        return None

    @classmethod
    def _find_skill_dir(cls) -> Path | None:
        candidates: list[Path] = []

        explicit = os.environ.get("CIRCOM_AUDITOR_CODEX_SKILL_DIR")
        if explicit:
            candidates.append(Path(explicit).expanduser())

        # Backwards compatibility with the Claude-style setup.
        for env_name in ("CODEX_PLUGIN_DIR", "CLAUDE_PLUGIN_DIR"):
            value = os.environ.get(env_name)
            if value:
                candidates.append(Path(value).expanduser())

        cwd = Path.cwd().resolve()
        for root in (cwd, *cwd.parents):
            candidates.append(root / ".agents" / "skills")
            if (root / ".git").exists():
                break

        home = Path.home()
        candidates.append(home / ".agents" / "skills")
        candidates.append(Path("/etc/codex/skills"))

        seen: set[Path] = set()
        for candidate in candidates:
            skill_dir = cls._as_skill_dir(candidate)
            if skill_dir is None or skill_dir in seen:
                continue
            seen.add(skill_dir)
            return skill_dir
        return None

    def _materialize_skill(self, target_dir: Path) -> None:
        """Make the selected skill visible to Codex from the scratch cwd."""
        scratch_skill_dir = target_dir / ".agents" / "skills" / _SKILL_NAME
        if scratch_skill_dir.exists():
            return

        scratch_skill_dir.parent.mkdir(parents=True, exist_ok=True)
        try:
            scratch_skill_dir.symlink_to(
                self.skill_dir, target_is_directory=True
            )
        except OSError:
            shutil.copytree(self.skill_dir, scratch_skill_dir, symlinks=True)

    def _build_delegated_context(
        self, target_dir: Path, target_file: Path
    ) -> Path:
        """Prebuild delegated agent bundles so Codex can run read-only."""
        context_dir = target_dir / _CONTEXT_DIR_NAME
        script = self.skill_dir / "scripts" / "build_audit_context.py"
        if not script.is_file():
            raise RuntimeError(f"delegated context builder not found: {script}")
        cmd = [
            sys.executable,
            str(script),
            "--repo",
            str(target_dir),
            "--skill-dir",
            str(self.skill_dir),
            "--out",
            str(context_dir),
            "--files",
            target_file.name,
        ]
        logging.info(
            "circom_auditor_codex: building delegated context with %s",
            " ".join(cmd),
        )
        try:
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired as e:
            stdout = e.stdout or ""
            stderr = e.stderr or ""
            raise RuntimeError(
                "delegated context builder timed out\n"
                f"stdout:\n{stdout}\nstderr:\n{stderr}"
            )
        except subprocess.CalledProcessError as e:
            stdout = e.stdout or ""
            stderr = e.stderr or ""
            raise RuntimeError(
                "delegated context builder failed\n"
                f"stdout:\n{stdout}\nstderr:\n{stderr}"
            )

        missing = [
            f"agent-{agent_id}-bundle.md"
            for agent_id in range(1, 18)
            if not (context_dir / f"agent-{agent_id}-bundle.md").is_file()
        ]
        if missing:
            raise RuntimeError(
                "delegated context missing expected bundle(s): "
                + ", ".join(missing)
            )
        return context_dir

    def _internal_execute(self, input_paths: Input, timeout: int) -> ToolOutput:
        """Run `codex exec` on a sandboxed copy of the circuit dir.

        The `$circom-auditor` skill should produce the same markdown report
        format handled by the shared parser.
        """
        circuit_file_path = Path(input_paths.circuit_file)
        target_dir, target_file, scope = self._prepare_scratch_dir(
            input_paths, circuit_file_path
        )
        self._materialize_skill(target_dir)
        try:
            context_dir = self._build_delegated_context(target_dir, target_file)
        except RuntimeError as e:
            msg = f"stdout:\n\nstderr:\n{e}"
            return ToolOutput(
                status=OutputStatus.FAIL,
                stdout="",
                stderr=str(e),
                return_code=1,
                msg=msg,
            )

        prompt = (
            f"Use the ${_SKILL_NAME} skill.\n\n"
            "Run delegated parallel audit mode only. Spawn Codex subagents over "
            f"the prebuilt bundles in `{context_dir.name}/`: "
            "`agent-1-bundle.md` through `agent-17-bundle.md`. Use the Codex "
            "orchestration reference, keep at most 6 agents running at once, "
            "wait for all selected delegated workers, deduplicate their "
            "FINDING/LEAD blocks, then validate and produce the final report.\n\n"
            "Important Codex runtime constraints for this wrapper:\n"
            "- A finished subagent still occupies runtime capacity until it is "
            "closed. Before spawning a queued replacement, close the completed "
            "agent, then spawn the next queued bundle.\n"
            "- If a delegated worker lacks a native file-read tool, it may use "
            "read-only shell inspection commands only to read its assigned "
            f"`{context_dir.name}/agent-N-bundle.md` file and in-scope `.circom` "
            "files. It must not run compilers, package managers, tests, "
            "network commands, or any command that writes files.\n"
            "- Do not stop merely because the worker needs a read-only shell "
            "command to inspect its assigned bundle; that is permitted by this "
            "zkhydra sandbox policy.\n\n"
            "Do not run the local audit workflow and do not use local fallback. "
            "If Codex subagents or delegated spawning are unavailable, stop and "
            "return `## Delegated Audit Unavailable` with the concrete reason; "
            "do not perform a single-agent/local audit.\n\n"
            f"Audit target: `{target_file.name}` — {scope.summary_line()}\n\n"
            f"Delegated context: `{context_dir.name}`.\n\n"
            f"{_SANDBOX_NOTE}"
        )

        # `codex exec` runs non-interactively.
        # --sandbox read-only: the auditor only needs to inspect the scratch dir.
        # -C: set working directory so relative file reads resolve correctly.
        # --skip-git-repo-check: scratch dirs are intentionally not git repos.
        # --ephemeral: don't persist session state to disk.
        cmd = [
            "codex",
            "exec",
            "--enable",
            "multi_agent",
            "-c",
            "agents.max_threads=6",
            "-c",
            "agents.max_depth=1",
            "--sandbox",
            "read-only",
            "-C",
            str(target_dir),
            "--skip-git-repo-check",
            "--ephemeral",
        ]
        model = os.environ.get("CODEX_MODEL")
        if model:
            cmd.extend(["-m", model])
        cmd.append(prompt)

        logging.info(
            "circom_auditor_codex: launching codex in sandbox %s "
            "(target=%s, skill=%s)",
            target_dir,
            target_file.name,
            self.skill_dir,
        )
        return self.run_command(cmd, timeout, str(target_dir))
