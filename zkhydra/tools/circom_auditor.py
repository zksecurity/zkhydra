"""
circom-auditor — wraps the Claude Code skill at https://github.com/zksecurity/zk-skills.

**Native-only tool.** This is the one zkhydra tool that is *not* baked
into the Docker image. Reason: the Claude Code subscription path stores
OAuth credentials in the host OS keychain (macOS Keychain / libsecret
on Linux / DPAPI on Windows), which cannot be mounted into a Linux
container. Rather than restrict users to API-key-only auth, we expose
the tool only when running zkhydra locally on the host (``uv run python
-m zkhydra.main ...``), where ``claude`` is already authenticated with
whatever credentials the user has set up.

Setup (one-time, on host):

  1. Install Claude Code CLI: ``npm install -g @anthropic-ai/claude-code``
  2. Authenticate: ``claude login``  (or ``export ANTHROPIC_API_KEY=...``)
  3. Clone zk-skills + symlink the skill::

         git clone https://github.com/zksecurity/zk-skills.git ~/zk-skills
         mkdir -p ~/audit-plugin/skills
         ln -s ~/zk-skills/circom-auditor ~/audit-plugin/skills/circom-auditor
         export CLAUDE_PLUGIN_DIR=~/audit-plugin

The Claude CLI is then invoked from the circuit directory and produces
a markdown report following
``circom-auditor/references/report-formatting.md``. We parse that
markdown to extract per-finding metadata (template, file:line, signal,
confidence, title, description) and map each finding into the
standardized zkhydra Finding schema.

Runtime characteristics differ from the other tools:

- Each run takes 3-5 minutes (the skill spawns 9 parallel sub-agents).
- Each run consumes either Claude subscription quota or Anthropic API
  tokens, depending on how the host's ``claude`` is authenticated.
- The tool will refuse to run inside a Docker container; use local mode.
"""

import logging
import os
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .base import (
    AbstractTool,
    AnalysisStatus,
    Finding,
    Input,
    OutputStatus,
    StandardizedBugCategory,
    ToolOutput,
)

# Map common bug-class slugs (kebab-case fragments that appear in the skill's
# finding titles or dedup keys) to the standardized zkhydra category.
# The skill's attack-vector library names every vector explicitly; we match on
# the most reliable substring.
BUG_CLASS_TO_STANDARD: List[Tuple[str, StandardizedBugCategory]] = [
    # Under-constrained / soundness (the dominant class)
    (
        "comparator-input-not-range-checked",
        StandardizedBugCategory.UNDER_CONSTRAINED,
    ),
    ("missing-range-check", StandardizedBugCategory.UNDER_CONSTRAINED),
    ("range-check", StandardizedBugCategory.UNDER_CONSTRAINED),
    ("range checked", StandardizedBugCategory.UNDER_CONSTRAINED),
    ("range checks", StandardizedBugCategory.UNDER_CONSTRAINED),
    ("packbytes", StandardizedBugCategory.UNDER_CONSTRAINED),
    ("num2bits", StandardizedBugCategory.UNDER_CONSTRAINED),
    ("aliasing", StandardizedBugCategory.UNDER_CONSTRAINED),
    ("assigned-but-unconstrained", StandardizedBugCategory.UNDER_CONSTRAINED),
    ("assigned but unconstrained", StandardizedBugCategory.UNDER_CONSTRAINED),
    ("unconstrained", StandardizedBugCategory.UNDER_CONSTRAINED),
    ("under-constrained", StandardizedBugCategory.UNDER_CONSTRAINED),
    ("under constrained", StandardizedBugCategory.UNDER_CONSTRAINED),
    ("witness-only", StandardizedBugCategory.UNDER_CONSTRAINED),
    ("decoder", StandardizedBugCategory.UNDER_CONSTRAINED),
    ("one-sided", StandardizedBugCategory.UNDER_CONSTRAINED),
    ("div-by-zero", StandardizedBugCategory.UNDER_CONSTRAINED),
    ("division-by-zero", StandardizedBugCategory.UNDER_CONSTRAINED),
    ("ec-edge-case", StandardizedBugCategory.UNDER_CONSTRAINED),
    ("equal-x", StandardizedBugCategory.UNDER_CONSTRAINED),
    ("intent-binding", StandardizedBugCategory.UNDER_CONSTRAINED),
    ("replay", StandardizedBugCategory.UNDER_CONSTRAINED),
    ("conditional-gate-collapse", StandardizedBugCategory.UNDER_CONSTRAINED),
    ("selector", StandardizedBugCategory.UNDER_CONSTRAINED),
    ("selector-not-boolean", StandardizedBugCategory.UNDER_CONSTRAINED),
    ("limb-out-of-range", StandardizedBugCategory.UNDER_CONSTRAINED),
    ("non-canonical", StandardizedBugCategory.UNDER_CONSTRAINED),
    ("merkle", StandardizedBugCategory.UNDER_CONSTRAINED),
    ("nullifier", StandardizedBugCategory.UNDER_CONSTRAINED),
    # Over-constrained / completeness
    ("over-constrained", StandardizedBugCategory.OVER_CONSTRAINED),
    ("over constrained", StandardizedBugCategory.OVER_CONSTRAINED),
    ("completeness", StandardizedBugCategory.OVER_CONSTRAINED),
    # Computational issues — hash mis-construction, regex compilation, etc.
    ("regex-overlap", StandardizedBugCategory.COMPUTATIONAL_ISSUE),
    ("base64", StandardizedBugCategory.COMPUTATIONAL_ISSUE),
    ("hash-construction", StandardizedBugCategory.COMPUTATIONAL_ISSUE),
    ("non-determinism", StandardizedBugCategory.COMPUTATIONAL_ISSUE),
    ("non-deterministic", StandardizedBugCategory.COMPUTATIONAL_ISSUE),
    ("computational", StandardizedBugCategory.COMPUTATIONAL_ISSUE),
    # Privacy / info-leak (no dedicated standardized category — fall back
    # to COMPUTATIONAL_ISSUE so it stays visible in eval reports)
    ("privacy", StandardizedBugCategory.COMPUTATIONAL_ISSUE),
    ("information-leak", StandardizedBugCategory.COMPUTATIONAL_ISSUE),
    ("information leak", StandardizedBugCategory.COMPUTATIONAL_ISSUE),
    # Language-level footguns (default to WARNING unless they imply
    # under-constraint, which is handled above)
    ("shadowing", StandardizedBugCategory.WARNING),
    ("bitwise-complement", StandardizedBugCategory.WARNING),
    ("assertion-vs-constraint", StandardizedBugCategory.WARNING),
    ("assert-vs-constraint", StandardizedBugCategory.WARNING),
    ("slash-vs-backslash", StandardizedBugCategory.WARNING),
]


@dataclass
class _ScopeInfo:
    """Description of the include closure that ended up in the scratch dir.

    Surfaced both in-prompt (one-line summary) and as `_SCOPE.md` in the
    sandbox so the auditor knows what *is* and *isn't* in scope. Critical
    for large monorepos like Panther where the wrapper's transitive
    include graph would otherwise blow past any reasonable budget.
    """

    wrapper_name: str
    file_count: int
    total_lines: int
    cap_lines: int
    unresolved: List[str] = field(default_factory=list)
    skipped_no_root: List[str] = field(default_factory=list)

    @property
    def truncated(self) -> bool:
        return any("truncated at budget" in u for u in self.unresolved)

    def summary_line(self) -> str:
        truncated = " (truncated at budget)" if self.truncated else ""
        return (
            f"include closure rooted at `{self.wrapper_name}` — "
            f"{self.file_count} file(s) / {self.total_lines} lines"
            f"{truncated}"
        )

    def manifest_markdown(self) -> str:
        lines = [
            "# Audit scope",
            "",
            f"**Wrapper / entrypoint:** `{self.wrapper_name}`",
            f"**Files in scope:** {self.file_count} `.circom` (transitive include closure of the wrapper)",
            f"**Total source lines:** {self.total_lines:,} (cap: {self.cap_lines:,})",
            "",
            "Audit only what's reachable from the wrapper's `include` graph "
            "as materialised in this directory. Do **not** speculate about "
            "code that isn't here — assume out-of-scope templates are "
            "outside the soundness boundary you're being asked to verify.",
        ]
        if self.truncated:
            lines += [
                "",
                "## ⚠️ Closure was truncated at the line budget",
                "",
                "The wrapper's full transitive closure exceeded the configured "
                f"line cap ({self.cap_lines:,}). The bundle in this directory "
                "is the **breadth-first prefix** that fit; deeper / later-in-BFS "
                "deps were dropped. Findings in the included files are still valid; "
                "absence of findings in code below the cut-off is not a clean bill "
                "of health — it just means we didn't show them to you.",
            ]
        if self.unresolved:
            shown = [
                u for u in self.unresolved if "truncated at budget" not in u
            ]
            if shown:
                lines += [
                    "",
                    "## Unresolved includes",
                    "",
                    "These `include` specs could not be resolved against any link root:",
                    "",
                ] + [f"- `{u}`" for u in shown[:32]]
        return "\n".join(lines) + "\n"


@dataclass
class CircomAuditorIssue:
    """One finding parsed out of the skill's markdown report."""

    title: str
    confidence: int
    template: Optional[str]
    file: Optional[str]
    line: Optional[int]
    line_end: Optional[int]
    signal: Optional[str]
    description: str
    severity: str  # "finding" or "lead"
    agents: Optional[int] = (
        None  # the [agents: N] convergence count, when present
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "confidence": self.confidence,
            "template": self.template,
            "file": self.file,
            "line": self.line,
            "line_end": self.line_end,
            "signal": self.signal,
            "description": self.description,
            "severity": self.severity,
            "agents": self.agents,
        }


@dataclass
class CircomAuditorParsed:
    """Structured parsed output from circom-auditor."""

    status: str  # "success" | "timeout" | "error" | "no_findings"
    issues: List[CircomAuditorIssue] = field(default_factory=list)
    raw_report: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "issues": [issue.to_dict() for issue in self.issues],
            "statistics": {
                "total_findings": sum(
                    1 for i in self.issues if i.severity == "finding"
                ),
                "total_leads": sum(
                    1 for i in self.issues if i.severity == "lead"
                ),
            },
        }


# Regex bank for extracting finding metadata from the report's per-finding
# header line (per circom-auditor/references/report-formatting.md):
#   `TemplateName (file.circom:LL-LL) · signal: <signalName>` · Confidence: 95
_HEADER_RE = re.compile(
    r"`(?P<template>[\w\d_]+)\s*"
    r"(?:\((?P<file>[^:)]+)(?::(?P<line>\d+)(?:-(?P<line_end>\d+))?)?\))?"
    r"(?:\s*·\s*signal:\s*(?P<signal>[^`]+?))?\s*`"
    r"\s*·\s*Confidence:\s*(?P<conf>\d+)",
    re.IGNORECASE,
)
_FINDING_NUM_RE = re.compile(
    r"^\[(?P<conf>\d+)\]\s*\*\*\d+\.\s*(?P<title>.+?)\*\*"
)
_AGENTS_RE = re.compile(r"\[agents:\s*(\d+)\]", re.IGNORECASE)
_LEAD_RE = re.compile(
    r"^\s*-\s*\*\*(?P<title>.+?)\*\*\s*—\s*"
    r"`(?P<template>[\w\d_]+)(?:\.(?P<signal>[^`]+))?`"
    r"\s*—\s*Code smells:\s*(?P<smells>.+)$"
)


class CircomAuditor(AbstractTool):
    """ZK-Security circom-auditor Claude skill, packaged as a zkhydra tool.

    The skill is a 9-agent parallel auditor; each invocation runs the full
    orchestration once on the provided circuit directory.
    """

    def __init__(self) -> None:
        super().__init__("circom_auditor")

        # Hard guard: this tool is native-only. Subscription/OAuth
        # credentials live in the host OS keychain and can't be mounted
        # into a Linux container, so we don't ship Claude in the Docker
        # image and refuse to run inside one. Users who want a
        # container-friendly LLM auditor should run zkhydra natively
        # (`uv run python -m zkhydra.main ...`).
        if os.path.exists("/.dockerenv"):
            logging.error(
                "circom_auditor is a native-only tool and cannot run inside "
                "the zkhydra Docker container. Re-run zkhydra on the host "
                "(`uv run python -m zkhydra.main ...`) after installing "
                "the Claude Code CLI and zk-skills locally — see the "
                "circom-auditor section of zkhydra/README.md."
            )
            sys.exit(1)

        if not self.check_binary_exists("claude"):
            logging.error(
                "circom_auditor: `claude` not found on PATH. Install with "
                "`npm install -g @anthropic-ai/claude-code` and run "
                "`claude login` (subscription) or export ANTHROPIC_API_KEY. "
                "See the circom-auditor section of zkhydra/README.md."
            )
            sys.exit(1)

        self.plugin_dir = os.environ.get("CLAUDE_PLUGIN_DIR")
        if not self.plugin_dir:
            logging.error(
                "circom_auditor: CLAUDE_PLUGIN_DIR is not set. Clone "
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
                "circom_auditor: SKILL.md not found at %s. The plugin "
                "directory must contain `skills/circom-auditor/SKILL.md` — "
                "verify CLAUDE_PLUGIN_DIR points at a directory with a "
                "`skills/` subdir holding a symlink or checkout of the "
                "circom-auditor skill from https://github.com/zksecurity/zk-skills.",
                skill_path,
            )
            sys.exit(1)

        if not os.environ.get("ANTHROPIC_API_KEY"):
            logging.info(
                "circom_auditor: no ANTHROPIC_API_KEY set — assuming "
                "host-level Claude Code auth (e.g. `claude login`). "
                "If the run fails with a 401, set ANTHROPIC_API_KEY."
            )

        # Bundle budget for the include-closure builder. The skill spawns
        # 9 parallel sub-agents that each ingest the full source bundle;
        # ~5k lines of Circom is the practical sweet spot before runtime
        # and subscription cost blow up. The closure builder uses this
        # as a hard cap (BFS from wrapper, stop adding files when the
        # next file would push us over) — over-cap projects produce a
        # *focused* bundle anchored at the wrapper, not a fail-fast.
        try:
            self.max_lines = int(
                os.environ.get("CIRCOM_AUDITOR_MAX_LINES", "5000")
            )
        except ValueError:
            self.max_lines = 5000

    # ------------------------------------------------------------------ exec

    # File-name predicates used to keep zkbugs answer-key files out of the
    # sandbox. Anything NOT on the allowlist is excluded — this is critical
    # for zkbugs evaluation, where the bug folder ships a README.md and
    # zkbugs_config.json containing the literal vulnerability class, root
    # cause, location, and proposed mitigation. Witness JSONs (input.json,
    # direct_input.json) are also excluded because static auditing should
    # reason from the constraint system alone, and direct_input.json
    # literally contains the exploit witness for the bug.
    _ALLOWED_SUFFIXES = (".circom",)
    # Directories we never symlink from a linked codebase root. Project
    # READMEs, docs, JS/TS clients, test fixtures, and build outputs can
    # all leak per-bug hints. The .circom source typically lives in one or
    # two well-named subdirs (`circuits/`, `lib/`, `src/`) which still pass.
    _BLOCKED_DIRNAMES = frozenset(
        {
            "test",
            "tests",
            "__tests__",
            "node_modules",
            "doc",
            "docs",
            "documentation",
            "dist",
            "build",
            "out",
            "target",
            "examples",
            "example",
            "static",
            "audit",
            "audits",
            "report",
            "reports",
            "client",
            "frontend",
            "eth",
            "contracts",  # solidity siblings to circom circuits
        }
    )

    # System-prompt appendix injected into every sub-agent. Belt-and-suspenders
    # alongside --disallowedTools / --setting-sources / the filesystem sandbox.
    _SANDBOX_SYSTEM_NOTE = (
        "Sandboxed evaluation mode. Do not perform web searches, web fetches, "
        "or any external lookups. Audit only the .circom source files in the "
        "current working directory and any peripheral files reachable via "
        "Circom `include` resolution from there. Do not reference external "
        "knowledge bases, audit-report archives, or per-bug README files even "
        "if visible. Reason from the constraint system alone."
    )
    # Tool names the auditor must never invoke during eval. The first two are
    # built-in; the rest are common MCP web tools that may be present in the
    # user's personal settings (we already skip user settings via
    # --setting-sources, but listing them here is defense in depth).
    _DISALLOWED_TOOLS = (
        "WebSearch",
        "WebFetch",
        "mcp__exa__web_search_exa",
        "mcp__exa__web_fetch_exa",
    )

    def _internal_execute(self, input_paths: Input, timeout: int) -> ToolOutput:
        """Run `claude --print` on a sandboxed copy of the circuit dir.

        Always materialises a fresh scratch dir under $TMPDIR and copies
        only the in-scope source (.circom files plus link-flag-resolved
        peripheral content). Excludes README.md, zkbugs_config.json,
        zkbugs_*.sh, and direct_input.json so the answer key never reaches
        the model when running on a zkbugs reproducer.

        The Claude CLI inherits the parent process's cwd, so we chdir into
        the scratch dir before launching it (matching the picus pattern in
        base.py). Without this, the skill's `find . -name "*.circom"`
        discovery runs from zkhydra's repo root, sees dozens of unrelated
        circuits, and asks the user for clarification instead of auditing.
        """
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
            # Skip the user/project/local settings stack so personal MCP
            # servers (Exa, Drive, Gmail, etc.) don't leak into a zkbugs run.
            "--setting-sources",
            "",
            # Belt: deny known web tool names by tool-id.
            "--disallowedTools",
            " ".join(self._DISALLOWED_TOOLS),
            # Suspenders: tell every sub-agent in plain text.
            "--append-system-prompt",
            self._SANDBOX_SYSTEM_NOTE,
            "--output-format",
            "text",
            prompt,
        ]

        # chdir into the sandbox so Claude's `find` / `Glob` / Read calls
        # resolve relative to the prepared scratch dir, not zkhydra's repo
        # root. Always restore cwd, even if the run errors / times out.
        original_cwd = Path.cwd()
        logging.info(
            "circom_auditor: launching claude in sandbox %s "
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

    def _is_source_file(self, path: Path) -> bool:
        """Allow .circom files only. Everything else is excluded."""
        return path.suffix.lower() in self._ALLOWED_SUFFIXES

    # ---------------------------------------------- include-closure builder

    # Matches `include "..."` (Circom syntax). Tolerates leading whitespace
    # and an optional trailing semicolon; ignores includes inside line and
    # block comments via a simple strip pass before regex.
    _INCLUDE_RE = re.compile(
        r'^[ \t]*include[ \t]+"([^"]+)"\s*;?', re.MULTILINE
    )
    _LINE_COMMENT_RE = re.compile(r"//[^\n]*")
    _BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)

    @classmethod
    def _strip_comments(cls, source: str) -> str:
        return cls._LINE_COMMENT_RE.sub(
            "", cls._BLOCK_COMMENT_RE.sub("", source)
        )

    @classmethod
    def _extract_includes(cls, source: str) -> List[str]:
        return cls._INCLUDE_RE.findall(cls._strip_comments(source))

    @staticmethod
    def _resolve_include(
        spec: str, from_file: Path, link_paths: List[Path]
    ) -> Optional[Path]:
        """Mirror circom's resolution: relative to including file first,
        then each `-l` root in order. Returns first existing match."""
        candidates = [from_file.parent / spec]
        for lp in link_paths:
            candidates.append(lp / spec)
        for candidate in candidates:
            if candidate.is_file():
                try:
                    return candidate.resolve()
                except OSError:
                    return candidate
        return None

    def _resolve_include_closure(
        self,
        wrapper: Path,
        link_paths: List[Path],
        max_lines: int,
    ) -> Tuple[List[Path], int, List[str]]:
        """BFS the include graph from `wrapper`, capped at `max_lines`.

        Returns:
            included: ordered list of resolved files included in the
                bundle (the wrapper itself comes first, then BFS order).
            total_lines: line count of `included`.
            unresolved: include specs we couldn't resolve via any link
                root — surfaced in the focus manifest so the auditor
                knows what's missing.
        """
        from collections import deque

        included: List[Path] = []
        visited: set = set()
        unresolved: List[str] = []
        wrapper_resolved = wrapper.resolve()
        included.append(wrapper_resolved)
        visited.add(wrapper_resolved)
        try:
            wrapper_lines = wrapper.read_text(errors="replace").count("\n")
        except OSError:
            wrapper_lines = 0
        total_lines = wrapper_lines

        queue: "deque[Path]" = deque([wrapper_resolved])
        while queue:
            current = queue.popleft()
            try:
                content = current.read_text(errors="replace")
            except OSError:
                continue
            for spec in self._extract_includes(content):
                resolved = self._resolve_include(spec, current, link_paths)
                if resolved is None:
                    if spec not in unresolved:
                        unresolved.append(spec)
                    continue
                if resolved in visited:
                    continue
                try:
                    line_count = resolved.read_text(errors="replace").count(
                        "\n"
                    )
                except OSError:
                    continue
                if total_lines + line_count > max_lines:
                    # Adding this would push us over budget; mark as
                    # truncated and stop following further includes from
                    # files we add at-or-after this point. We *don't* skip
                    # tiny files just to fit later in BFS order — the
                    # closure is conservative: BFS gives breadth-first
                    # coverage which mirrors how a human would scope the
                    # audit (start at wrapper, follow direct deps, then
                    # transitive deps).
                    unresolved.append(
                        f"<truncated at budget: would exceed {max_lines} lines "
                        f"after adding {resolved.name} (+{line_count})>"
                    )
                    return included, total_lines, unresolved
                visited.add(resolved)
                included.append(resolved)
                total_lines += line_count
                queue.append(resolved)
        return included, total_lines, unresolved

    @staticmethod
    def _shadow_path_for(
        target: Path, link_paths: List[Path], wrapper_dir: Path
    ) -> Optional[Path]:
        """Compute the relative path the file should occupy in the scratch
        dir. We try wrapper-dir-relative first (so wrapper-local includes
        keep working), then each link root."""
        candidates = [wrapper_dir, *link_paths]
        for root in candidates:
            try:
                return target.resolve().relative_to(root.resolve())
            except (ValueError, OSError):
                continue
        return None

    def _prepare_scratch_dir(
        self, input_paths: Input, circuit_file_path: Path
    ) -> Tuple[Path, Path, "_ScopeInfo"]:
        """Build a sandboxed working dir scoped to the wrapper's include
        closure, capped at `self.max_lines` lines of Circom source.

        Layout produced under $TMPDIR/zkhydra-circom-auditor-XXXXXX/:

          - <wrapper>.circom              (copied from circuit_file)
          - <other top-level .circom>     (copied from circuit_dir siblings)
          - <relpath>/<...>/<dep>.circom  (symlinked, in BFS-include order,
                                           with parent dirs created on demand
                                           to preserve relative include
                                           resolution)
          - _SCOPE.md                     (focus manifest — what's in scope)

        Excluded by construction: anything not reached via the wrapper's
        include graph (so `README.md`, `zkbugs_config.json`,
        `direct_input.json`, irrelevant codebase subdirs etc. don't appear)
        plus everything beyond the line cap.
        """
        scratch_root = Path(tempfile.mkdtemp(prefix="zkhydra-circom-auditor-"))

        # 1. Copy the wrapper itself.
        target_wrapper = scratch_root / circuit_file_path.name
        shutil.copy2(circuit_file_path, target_wrapper)

        # 2. Copy any sibling .circom files at the top level of circuit_dir
        # (so multi-file analyze-mode still works). Top-level only.
        circuit_dir = Path(input_paths.circuit_dir).resolve()
        sibling_files: List[Path] = []
        if circuit_dir.is_dir():
            for child in circuit_dir.iterdir():
                if not child.is_file():
                    continue
                if child.resolve() == circuit_file_path.resolve():
                    continue
                if not self._is_source_file(child):
                    continue
                dest = scratch_root / child.name
                if dest.exists():
                    continue
                shutil.copy2(child, dest)
                sibling_files.append(child)

        # 3. Trace the include closure starting from the wrapper. We trace
        # against the *original* wrapper (not the scratch copy) plus the
        # scratch copy as an alternate root, so includes that look like
        # `include "lib/foo.circom"` resolve correctly via either the
        # original sibling layout or the scratch top level.
        link_paths_str = self._extract_link_paths(input_paths.link_flags)
        link_paths = [Path(p) for p in link_paths_str if Path(p).is_dir()]
        # Preference order for relative-path layout in scratch:
        #   wrapper's own dir, then each -l root.
        wrapper_dir = circuit_file_path.parent

        # Run closure against the *original* wrapper so its `include "..."`
        # paths resolve through the real codebase tree. We then symlink
        # each closure file into the scratch dir at its relative position.
        closure, total_lines, unresolved = self._resolve_include_closure(
            circuit_file_path, link_paths, self.max_lines
        )
        # Drop the wrapper itself from the symlink loop — it's already copied.
        deps = [
            p for p in closure if p.resolve() != circuit_file_path.resolve()
        ]

        symlinked = 0
        skipped_no_root: List[Path] = []
        for dep in deps:
            rel = self._shadow_path_for(dep, link_paths, wrapper_dir)
            if rel is None:
                skipped_no_root.append(dep)
                continue
            dest = scratch_root / rel
            if dest.exists() or dest.is_symlink():
                continue
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(dep, dest)
                symlinked += 1
            except OSError as exc:
                logging.debug(
                    "circom_auditor scratch: cannot symlink %s -> %s: %s",
                    dep,
                    dest,
                    exc,
                )

        # 4. Write a focus manifest describing what's in scope. The auditor
        # picks this up via Read/Glob in cwd; it sets the right mental
        # model so the model doesn't try to audit "the whole project" when
        # only a closure is present.
        scope = _ScopeInfo(
            wrapper_name=target_wrapper.name,
            file_count=len(closure),
            total_lines=total_lines,
            cap_lines=self.max_lines,
            unresolved=unresolved,
            skipped_no_root=[str(p) for p in skipped_no_root],
        )
        try:
            (scratch_root / "_SCOPE.md").write_text(scope.manifest_markdown())
        except OSError:
            pass

        logging.info(
            "circom_auditor: closure=%d files / %d lines (cap=%d), "
            "symlinked=%d, unresolved=%d, no-root=%d",
            scope.file_count,
            scope.total_lines,
            scope.cap_lines,
            symlinked,
            len(unresolved),
            len(skipped_no_root),
        )

        return scratch_root, target_wrapper, scope

    @staticmethod
    def _extract_link_paths(link_flags: List[str]) -> List[str]:
        paths: List[str] = []
        it = iter(link_flags)
        for flag in it:
            if flag in ("-l", "-L", "--link-libraries"):
                try:
                    paths.append(next(it))
                except StopIteration:
                    break
        return paths

    # -------------------------------------------------------------- parsing

    def _helper_parse_output(
        self, tool_result_raw: Path
    ) -> CircomAuditorParsed:
        """Parse the markdown report into structured findings."""
        with open(tool_result_raw, "r", encoding="utf-8") as f:
            raw = f.read()

        if "[Timed out]" in raw and "## Findings" not in raw:
            return CircomAuditorParsed(status="timeout", raw_report=raw)

        if "## Findings" not in raw:
            return CircomAuditorParsed(status="error", raw_report=raw)

        issues: List[CircomAuditorIssue] = []
        issues.extend(self._parse_findings_section(raw))
        issues.extend(self._parse_leads_section(raw))

        status = "success" if issues else "no_findings"
        return CircomAuditorParsed(status=status, issues=issues, raw_report=raw)

    def _parse_findings_section(self, raw: str) -> List[CircomAuditorIssue]:
        """Extract each `[NN] **K. Title**` block from the ## Findings section."""
        # Slice to the Findings section
        start_marker = "## Findings"
        end_markers = ["## Leads", "Findings List", "---\n\n>"]
        start = raw.find(start_marker)
        if start < 0:
            return []
        end = len(raw)
        for marker in end_markers:
            idx = raw.find(marker, start + len(start_marker))
            if 0 <= idx < end:
                end = idx
        section = raw[start:end]

        issues: List[CircomAuditorIssue] = []
        # Each finding starts with a line like: `[95] **1. Title**`
        finding_pattern = re.compile(
            r"^\[(\d+)\]\s*\*\*\d+\.\s*(.+?)\*\*",
            re.MULTILINE,
        )
        matches = list(finding_pattern.finditer(section))
        for i, m in enumerate(matches):
            confidence = int(m.group(1))
            title = m.group(2).strip()
            block_start = m.end()
            block_end = (
                matches[i + 1].start() if i + 1 < len(matches) else len(section)
            )
            block = section[block_start:block_end]

            header = self._extract_header(block)
            description = self._extract_description(block)
            agents_match = _AGENTS_RE.search(block)
            agents = int(agents_match.group(1)) if agents_match else None

            issues.append(
                CircomAuditorIssue(
                    title=title,
                    confidence=confidence,
                    template=header.get("template"),
                    file=header.get("file"),
                    line=header.get("line"),
                    line_end=header.get("line_end"),
                    signal=header.get("signal"),
                    description=description,
                    severity="finding",
                    agents=agents,
                )
            )
        return issues

    @staticmethod
    def _extract_header(block: str) -> Dict[str, Any]:
        """Pull `Template (file:line) · signal: X` · Confidence: N from a block."""
        m = _HEADER_RE.search(block)
        if not m:
            return {}
        return {
            "template": (m.group("template") or None),
            "file": (m.group("file") or "").strip() or None,
            "line": int(m.group("line")) if m.group("line") else None,
            "line_end": (
                int(m.group("line_end")) if m.group("line_end") else None
            ),
            "signal": (m.group("signal") or "").strip() or None,
        }

    @staticmethod
    def _extract_description(block: str) -> str:
        """First paragraph after **Description**, trimmed."""
        m = re.search(
            r"\*\*Description\*\*\s*\n+(.+?)(?:\n\n|\*\*Circuit\s*/\s*Constraint\*\*|\*\*Fix\*\*)",
            block,
            re.DOTALL,
        )
        if not m:
            return ""
        return m.group(1).strip().replace("\n", " ")

    def _parse_leads_section(self, raw: str) -> List[CircomAuditorIssue]:
        start = raw.find("## Leads")
        if start < 0:
            return []
        end_markers = ["---\n\n>", "\n\n> ⚠️"]
        end = len(raw)
        for marker in end_markers:
            idx = raw.find(marker, start)
            if 0 <= idx < end:
                end = idx
        section = raw[start:end]

        issues: List[CircomAuditorIssue] = []
        for line in section.splitlines():
            m = _LEAD_RE.match(line)
            if not m:
                continue
            issues.append(
                CircomAuditorIssue(
                    title=m.group("title").strip(),
                    confidence=0,  # leads aren't scored
                    template=m.group("template"),
                    file=None,
                    line=None,
                    line_end=None,
                    signal=(m.group("signal") or "").strip() or None,
                    description=f"Code smells: {m.group('smells').strip()}",
                    severity="lead",
                )
            )
        return issues

    # ----------------------------------------------------- standardization

    def _helper_generate_uniform_results(
        self,
        parsed_output: CircomAuditorParsed,
        tool_output: ToolOutput,
    ) -> Tuple[AnalysisStatus, List[Finding]]:
        """Convert parsed findings into uniform Finding objects."""
        if parsed_output.status == "timeout":
            return AnalysisStatus.TIMEOUT, []
        if parsed_output.status == "error":
            return AnalysisStatus.ERROR, []
        # Findings (non-leads) drive bug-found vs no-bug; leads are surfaced
        # as additional Finding rows but don't flip the status.
        confirmed = [i for i in parsed_output.issues if i.severity == "finding"]
        analysis_status = (
            AnalysisStatus.BUGS_FOUND if confirmed else AnalysisStatus.NO_BUGS
        )

        findings: List[Finding] = []
        for issue in parsed_output.issues:
            unified = self._classify(issue.title)
            findings.append(
                Finding(
                    bug_title=issue.title,
                    unified_bug_title=unified,
                    description=issue.description,
                    file=issue.file or "",
                    position={
                        "line": issue.line,
                        "column": None,
                        "template": issue.template,
                        "signal": issue.signal,
                        "line_end": issue.line_end,
                    },
                    metadata={
                        "severity": issue.severity,
                        "confidence": issue.confidence,
                        "agents": issue.agents,
                    },
                )
            )
        return analysis_status, findings

    @staticmethod
    def _classify(title: str) -> StandardizedBugCategory:
        haystack = title.lower()
        for slug, category in BUG_CLASS_TO_STANDARD:
            if slug in haystack:
                return category
        # Default for circom-auditor: most findings are soundness issues
        return StandardizedBugCategory.UNDER_CONSTRAINED

    # ------------------------------------------------------ zkbugs eval API

    def evaluate_zkbugs_ground_truth(
        self,
        tool: str,
        dsl: str,
        bug_name: str,
        ground_truth: Path,
        tool_result_path: Path,
    ) -> Dict[str, Any]:
        """Compare circom-auditor results against zkbugs ground truth.

        Matching strategy: same as circomspect — vulnerability-class match
        plus line-range overlap = TruePositive; class-match-only =
        Undecided; everything else = FalseNegative or Undecided.
        """
        gt_data = self.load_json_file(ground_truth)
        gt_vulnerability = (gt_data.get("vulnerability") or "").strip()
        gt_location = gt_data.get("location", {}) or {}
        gt_lines = gt_location.get("Line")

        tool_results = self.load_json_file(tool_result_path)
        findings = tool_results.get("findings", [])
        # Confirmed findings only — leads don't count toward recall (mirrors
        # the eval harness in circom-auditor/evals/compare.md).
        findings = [
            f
            for f in findings
            if f.get("metadata", {}).get("severity") == "finding"
        ]

        if not findings:
            return {
                "status": "FalseNegative",
                "reason": "Tool found no confirmed findings (only leads, if any)",
                "need_manual_analysis": False,
                "manual_analysis": "N/A",
                "manual_analysis_reasoning": "N/A",
            }

        if gt_lines:
            if "-" in gt_lines:
                gt_start, gt_end = gt_lines.split("-", 1)
                gt_startline, gt_endline = int(gt_start), int(gt_end)
            else:
                gt_startline = gt_endline = int(gt_lines)
        else:
            gt_startline = gt_endline = None

        exact_match = False
        partial_matches: List[str] = []
        for finding in findings:
            unified_title = finding.get("unified_bug_title", "")
            position = finding.get("position", {}) or {}
            finding_line = position.get("line")

            vuln_match = (
                gt_vulnerability
                and unified_title.lower() == gt_vulnerability.lower()
            )

            if finding_line is not None and gt_startline is not None:
                line_match = gt_startline <= finding_line <= gt_endline
            else:
                line_match = None

            if vuln_match and line_match:
                exact_match = True
            elif vuln_match:
                partial_matches.append(
                    f"Found {unified_title} but at different line "
                    f"({finding_line} vs {gt_lines})"
                )

        if exact_match:
            return {
                "status": "TruePositive",
                "reason": f"Found {gt_vulnerability} at lines {gt_lines}",
                "need_manual_analysis": False,
                "manual_analysis": "N/A",
                "manual_analysis_reasoning": "N/A",
            }
        if partial_matches:
            return {
                "status": "Undecided",
                "reason": "; ".join(partial_matches),
                "need_manual_analysis": True,
                "manual_analysis": "Pending",
                "manual_analysis_reasoning": "TODO",
            }
        return {
            "status": "Undecided",
            "reason": (
                f"Tool found {len(findings)} confirmed findings but none "
                f"match {gt_vulnerability}"
            ),
            "need_manual_analysis": True,
            "manual_analysis": "Pending",
            "manual_analysis_reasoning": "TODO",
        }
