"""
Shared sandbox-building and markdown-report-parsing logic for LLM-based
Circom auditors (Claude and Codex variants).

Both CircomAuditorClaude and CircomAuditorCodex inherit from CircomAuditorBase.
The base class owns:
  - Include-closure sandbox builder (_prepare_scratch_dir and helpers)
  - Markdown report parser (_helper_parse_output and helpers)
  - Uniform Finding converter (_helper_generate_uniform_results)
  - zkbugs ground-truth evaluator (evaluate_zkbugs_ground_truth)

Each subclass implements only _internal_execute, choosing how to invoke
its respective LLM CLI from the prepared scratch directory, and __init__,
which checks that the required binary and credentials are present.
"""

import logging
import os
import re
import shutil
import tempfile
from abc import abstractmethod
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from zkhydra.tools.base import (
    AbstractTool,
    AnalysisStatus,
    Finding,
    Input,
    StandardizedBugCategory,
    ToolOutput,
)

# Map common bug-class slugs (kebab-case fragments from finding titles or
# dedup keys) to the standardized zkhydra category. Matched on the most
# reliable substring in the finding title.
BUG_CLASS_TO_STANDARD: List[Tuple[str, StandardizedBugCategory]] = [
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
    ("over-constrained", StandardizedBugCategory.OVER_CONSTRAINED),
    ("over constrained", StandardizedBugCategory.OVER_CONSTRAINED),
    ("completeness", StandardizedBugCategory.OVER_CONSTRAINED),
    ("regex-overlap", StandardizedBugCategory.COMPUTATIONAL_ISSUE),
    ("base64", StandardizedBugCategory.COMPUTATIONAL_ISSUE),
    ("hash-construction", StandardizedBugCategory.COMPUTATIONAL_ISSUE),
    ("non-determinism", StandardizedBugCategory.COMPUTATIONAL_ISSUE),
    ("non-deterministic", StandardizedBugCategory.COMPUTATIONAL_ISSUE),
    ("computational", StandardizedBugCategory.COMPUTATIONAL_ISSUE),
    ("privacy", StandardizedBugCategory.COMPUTATIONAL_ISSUE),
    ("information-leak", StandardizedBugCategory.COMPUTATIONAL_ISSUE),
    ("information leak", StandardizedBugCategory.COMPUTATIONAL_ISSUE),
    ("shadowing", StandardizedBugCategory.WARNING),
    ("bitwise-complement", StandardizedBugCategory.WARNING),
    ("assertion-vs-constraint", StandardizedBugCategory.WARNING),
    ("assert-vs-constraint", StandardizedBugCategory.WARNING),
    ("slash-vs-backslash", StandardizedBugCategory.WARNING),
]


@dataclass
class _ScopeInfo:
    """Description of the include closure materialised in the scratch dir."""

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
                "## Warning: Closure was truncated at the line budget",
                "",
                "The wrapper's full transitive closure exceeded the configured "
                f"line cap ({self.cap_lines:,}). The bundle in this directory "
                "is the **breadth-first prefix** that fit; deeper / later-in-BFS "
                "deps were dropped.",
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
    """Structured parsed output from a circom-auditor run."""

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
_AGENTS_RE = re.compile(r"\[agents:\s*(\d+)\]", re.IGNORECASE)
_LEAD_RE = re.compile(
    r"^\s*-\s*\*\*(?P<title>.+?)\*\*\s*—\s*"
    r"`(?P<template>[\w\d_]+)(?:\.(?P<signal>[^`]+))?`"
    r"\s*—\s*Code smells:\s*(?P<smells>.+)$"
)


class CircomAuditorBase(AbstractTool):
    """Abstract base for LLM-powered Circom auditors (Claude and Codex variants).

    Provides the shared include-closure sandbox builder, markdown report parser,
    uniform finding converter, and zkbugs evaluator. Subclasses supply only
    _internal_execute (how to invoke the LLM CLI) and __init__ (credential checks).
    """

    # Only .circom files enter the sandbox.
    _ALLOWED_SUFFIXES = (".circom",)

    # Directories whose contents are never symlinked from a linked codebase root.
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
            "contracts",
        }
    )

    # Matches `include "..."` in Circom source.
    _INCLUDE_RE = re.compile(
        r'^[ \t]*include[ \t]+"([^"]+)"\s*;?', re.MULTILINE
    )
    _LINE_COMMENT_RE = re.compile(r"//[^\n]*")
    _BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)

    def __init__(self, name: str) -> None:
        super().__init__(name)

        # Both LLM tools are native-only: OAuth/API credentials live in the
        # host OS keychain and cannot be mounted into a Docker container.
        if os.path.exists("/.dockerenv"):
            import sys

            logging.error(
                "%s is a native-only tool and cannot run inside the zkhydra "
                "Docker container. Re-run zkhydra on the host "
                "(`uv run python -m zkhydra.main ...`) after installing "
                "the required CLI — see zkhydra/README.md.",
                name,
            )
            sys.exit(1)

        try:
            self.max_lines = int(
                os.environ.get("CIRCOM_AUDITOR_MAX_LINES", "5000")
            )
        except ValueError:
            self.max_lines = 5000

    @abstractmethod
    def _internal_execute(self, input_paths: Input, timeout: int) -> ToolOutput:
        """Invoke the LLM CLI from the prepared scratch directory."""

    # ------------------------------------------------------------------ parsing

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
                    confidence=0,
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
        """Compare findings against zkbugs ground truth.

        Matching strategy: vulnerability-class match plus line-range overlap
        → TruePositive; class-match-only → Undecided; no match → FalseNegative.
        """
        gt_data = self.load_json_file(ground_truth)
        gt_vulnerability = (gt_data.get("vulnerability") or "").strip()
        gt_location = gt_data.get("location", {}) or {}
        gt_lines = gt_location.get("Line")

        tool_results = self.load_json_file(tool_result_path)
        findings = tool_results.get("findings", [])
        # Only confirmed findings count toward recall; leads don't.
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

    # ---------------------------------------------- include-closure builder

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
        then each -l root in order. Returns first existing match."""
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
        """BFS the include graph from `wrapper`, capped at `max_lines`."""
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

        queue: deque = deque([wrapper_resolved])
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
        """Compute the relative path a dep should occupy in the scratch dir."""
        candidates = [wrapper_dir, *link_paths]
        for root in candidates:
            try:
                return target.resolve().relative_to(root.resolve())
            except (ValueError, OSError):
                continue
        return None

    def _is_source_file(self, path: Path) -> bool:
        return path.suffix.lower() in self._ALLOWED_SUFFIXES

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

    def _prepare_scratch_dir(
        self, input_paths: Input, circuit_file_path: Path
    ) -> Tuple[Path, Path, "_ScopeInfo"]:
        """Build a sandboxed working dir scoped to the wrapper's include closure.

        Excluded by construction: READMEs, zkbugs_config.json,
        direct_input.json, and anything beyond the line cap, so the answer
        key never reaches the model during zkbugs evaluation.
        """
        scratch_root = Path(tempfile.mkdtemp(prefix=f"zkhydra-{self.name}-"))

        # 1. Copy the wrapper itself.
        target_wrapper = scratch_root / circuit_file_path.name
        shutil.copy2(circuit_file_path, target_wrapper)

        # 2. Copy sibling .circom files at the top level of circuit_dir.
        circuit_dir = Path(input_paths.circuit_dir).resolve()
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

        # 3. Trace the include closure.
        link_paths_str = self._extract_link_paths(input_paths.link_flags)
        link_paths = [Path(p) for p in link_paths_str if Path(p).is_dir()]
        wrapper_dir = circuit_file_path.parent

        closure, total_lines, unresolved = self._resolve_include_closure(
            circuit_file_path, link_paths, self.max_lines
        )
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
                    "%s scratch: cannot symlink %s -> %s: %s",
                    self.name,
                    dep,
                    dest,
                    exc,
                )

        # 4. Write the focus manifest.
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
            "%s: closure=%d files / %d lines (cap=%d), "
            "symlinked=%d, unresolved=%d, no-root=%d",
            self.name,
            scope.file_count,
            scope.total_lines,
            scope.cap_lines,
            symlinked,
            len(unresolved),
            len(skipped_no_root),
        )

        return scratch_root, target_wrapper, scope
