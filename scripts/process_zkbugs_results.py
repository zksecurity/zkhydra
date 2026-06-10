#!/usr/bin/env python3
"""
Process zkbugs evaluation results and generate summary tables.

Usage:
    python scripts/process_zkbugs_results.py output/zkbugs-final
    python scripts/process_zkbugs_results.py output/zkbugs-final --latex report.pdf

For --zkbugs-mode both runs (output/<run>/{direct,original}/), add --both:
    python scripts/process_zkbugs_results.py output/zkbugs-run --both \\
        --latex output/zkbugs-run/report.pdf

    # produces report.direct.pdf and report.original.pdf next to the given path.
    # Auto-detected when the top-level summary.json has "mode": "both".
"""

import argparse
import json
import statistics
import subprocess
import sys
from collections import defaultdict
from pathlib import Path


def load_json(file_path: Path) -> dict:
    """Load JSON file safely."""
    try:
        with open(file_path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"Warning: Failed to load {file_path}: {e}", file=sys.stderr)
        return {}


def get_tool_status(bug_dir: Path, tool_name: str) -> tuple[str, bool, float]:
    """
    Determine tool status for a bug.

    Returns: (status, was_manually_analyzed, execution_time)
        status: "TP", "FN", "Undecided", "Timeout", "Failure", "N/A", "Unknown"
        was_manually_analyzed: True if manual_analysis="Done"
        execution_time: execution time in seconds, or -1 if not available
    """
    tool_dir = bug_dir / tool_name

    if not tool_dir.exists():
        return "N/A", False, -1

    # Try to get execution time from results.json
    execution_time = -1
    results_file = tool_dir / "results.json"
    if results_file.exists():
        results_data = load_json(results_file)
        execution_time = results_data.get("execution_time", -1)

    # Check if evaluation.json exists
    eval_file = tool_dir / "evaluation.json"
    manually_analyzed = False
    if eval_file.exists():
        eval_data = load_json(eval_file)
        status = eval_data.get("status", "Unknown")
        manually_analyzed = eval_data.get("manual_analysis") == "Done"

        short_status = {
            "TruePositive": "TP",
            "FalseNegative": "FN",
            "Undecided": "Undecided",
        }.get(status, "Unknown")
        return short_status, manually_analyzed, execution_time

    # No evaluation.json, check results.json for execution status
    if results_file.exists():
        results_data = load_json(results_file)
        exec_status = results_data.get("status", "unknown")

        if exec_status == "timeout":
            return "Timeout", False, execution_time
        elif exec_status == "error":
            return "Failure", False, execution_time

    # Check raw.txt to infer status
    raw_file = tool_dir / "raw.txt"
    if raw_file.exists():
        try:
            with open(raw_file, encoding="utf-8") as f:
                raw_content = f.read()
                if "[Timed out]" in raw_content:
                    return "Timeout", False, execution_time
                if (
                    "error" in raw_content.lower()
                    or "failed" in raw_content.lower()
                ):
                    return "Failure", False, execution_time
        except Exception:
            pass

    return "Unknown", False, execution_time


def collect_results(
    results_dir: Path,
) -> tuple[dict[str, dict[str, int]], dict[str, dict[str, str]], dict[str, dict[str, float]], dict[str, list[float]]]:
    """
    Collect all results from the directory.

    Returns:
        - tool_stats: {tool_name: {status: count}}
        - bug_tool_matrix: {bug_name: {tool_name: status_with_asterisk}}
        - bug_time_matrix: {bug_name: {tool_name: execution_time}}
        - tool_times: {tool_name: [execution_times]} (excluding timeouts and errors)
    """
    tool_stats = defaultdict(lambda: defaultdict(int))
    bug_tool_matrix = {}
    bug_time_matrix = {}
    tool_times = defaultdict(list)

    # Get all bug directories
    bug_dirs = sorted([d for d in results_dir.iterdir() if d.is_dir()])

    # Tools to check
    tools = ["circomspect", "circom_civer", "picus", "ecneproject", "zkfuzz", "conscs"]

    for bug_dir in bug_dirs:
        bug_name = bug_dir.name
        bug_tool_matrix[bug_name] = {}
        bug_time_matrix[bug_name] = {}

        for tool_name in tools:
            status, manually_analyzed, execution_time = get_tool_status(bug_dir, tool_name)

            # Add asterisk if manually analyzed
            display_status = status + "*" if manually_analyzed else status
            bug_tool_matrix[bug_name][tool_name] = display_status
            bug_time_matrix[bug_name][tool_name] = execution_time

            # Collect execution times for non-timeout cases
            # For Picus, include failures in time statistics
            if tool_name == "picus":
                if status not in ["Timeout", "N/A", "Unknown"] and execution_time > 0:
                    tool_times[tool_name].append(execution_time)
            else:
                if status not in ["Timeout", "Failure", "N/A", "Unknown"] and execution_time > 0:
                    tool_times[tool_name].append(execution_time)

            # Count stats without asterisk
            if status != "N/A" and status != "Unknown":
                tool_stats[tool_name][status] += 1

    return tool_stats, bug_tool_matrix, bug_time_matrix, tool_times


def print_tool_summary_table(tool_stats: dict[str, dict[str, int]], tool_times: dict[str, list[float]]):
    """Print summary table with tools as rows."""
    print("\n" + "=" * 80)
    print("SUMMARY TABLE: Tool Performance")
    print("=" * 80)

    # Define columns and tools
    columns = ["TP", "FN", "Undecided", "Timeout", "Failure"]
    tools = ["circomspect", "circom_civer", "picus", "ecneproject", "zkfuzz", "conscs"]

    # Calculate column widths
    tool_width = max(len(tool) for tool in tools + ["TOTAL"])
    col_width = 10
    time_width = 12

    # Print header
    header = f"{'Tool':<{tool_width}}"
    for col in columns:
        header += f" | {col:>{col_width}}"
    header += f" | {'Total':>{col_width}} | {'Median Time':>{time_width}}"
    print(header)
    print("-" * len(header))

    # Print tool rows
    totals = defaultdict(int)
    for tool in tools:
        row = f"{tool:<{tool_width}}"
        tool_total = 0
        for col in columns:
            count = tool_stats[tool].get(col, 0)
            row += f" | {count:>{col_width}}"
            totals[col] += count
            tool_total += count
        row += f" | {tool_total:>{col_width}}"

        # Add median time (excluding timeouts)
        if tool in tool_times and len(tool_times[tool]) > 0:
            median_time = statistics.median(tool_times[tool])
            row += f" | {median_time:>{time_width}.2f}s"
        else:
            row += f" | {'-':>{time_width}}"
        print(row)

    # Print totals row
    print("-" * len(header))
    totals_row = f"{'TOTAL':<{tool_width}}"
    grand_total = 0
    for col in columns:
        count = totals[col]
        totals_row += f" | {count:>{col_width}}"
        grand_total += count
    totals_row += f" | {grand_total:>{col_width}}"

    # Calculate overall median time
    all_times = []
    for times in tool_times.values():
        all_times.extend(times)
    if all_times:
        overall_median = statistics.median(all_times)
        totals_row += f" | {overall_median:>{time_width}.2f}s"
    else:
        totals_row += f" | {'-':>{time_width}}"
    print(totals_row)
    print("=" * 80)


def print_bug_tool_matrix(
    bug_tool_matrix: dict[str, dict[str, str]], full_path: bool = False
):
    """Print matrix with bugs as rows and tools as columns.

    Args:
        bug_tool_matrix: Dictionary mapping bug names to tool statuses (with asterisks)
        full_path: If True, print full bug names without truncation
    """
    tools = ["circomspect", "circom_civer", "picus", "ecneproject", "zkfuzz", "conscs"]

    # Calculate column widths
    bug_width = max(len(bug) for bug in bug_tool_matrix)
    if not full_path:
        bug_width = min(bug_width, 60)  # Cap at 60 chars unless full_path
    col_width = 12

    # Calculate total width for separator
    total_width = bug_width + len(tools) * (col_width + 3) - 1

    print("\n" + "=" * total_width)
    print("BUG-TOOL MATRIX (* = manually analyzed)")
    print("=" * total_width)

    # Print header
    header = f"{'Bug Name':<{bug_width}}"
    for tool in tools:
        header += f" | {tool[:col_width]:^{col_width}}"
    print(header)
    print("-" * len(header))

    # Print bug rows
    for bug_name in sorted(bug_tool_matrix.keys()):
        # Truncate bug name if too long and full_path is False
        if full_path or len(bug_name) <= bug_width:
            display_name = bug_name
        else:
            display_name = bug_name[: bug_width - 3] + "..."

        row = f"{display_name:<{bug_width}}"

        for tool in tools:
            status = bug_tool_matrix[bug_name].get(tool, "N/A")
            row += f" | {status:^{col_width}}"
        print(row)

    print("=" * total_width)


def print_execution_time_stats(
    tool_stats: dict[str, dict[str, int]],
    tool_times: dict[str, list[float]],
):
    """Print execution time statistics per tool."""
    print("\n" + "=" * 100)
    print("EXECUTION TIME STATISTICS")
    print("=" * 100)

    tools = ["circomspect", "circom_civer", "picus", "ecneproject", "zkfuzz", "conscs"]

    # Calculate column widths
    tool_width = max(len(tool) for tool in tools)
    col_width = 12

    # Print header
    header = f"{'Tool':<{tool_width}} | {'Total':>{col_width}} | {'Min (s)':>{col_width}} | {'Max (s)':>{col_width}} | {'Median (s)':>{col_width}} | {'Mean (s)':>{col_width}} | {'NR-Timeout':>{col_width}}"
    print(header)
    print("-" * len(header))

    # Print tool rows
    for tool in tools:
        row = f"{tool:<{tool_width}}"

        if tool in tool_times and len(tool_times[tool]) > 0:
            times = tool_times[tool]
            total = len(times)
            min_time = min(times)
            max_time = max(times)
            median_time = statistics.median(times)
            mean_time = statistics.mean(times)
            nr_timeout = tool_stats[tool].get("Timeout", 0)

            row += f" | {total:>{col_width}}"
            row += f" | {min_time:>{col_width}.2f}"
            row += f" | {max_time:>{col_width}.2f}"
            row += f" | {median_time:>{col_width}.2f}"
            row += f" | {mean_time:>{col_width}.2f}"
            row += f" | {nr_timeout:>{col_width}}"
        else:
            # No successful executions
            nr_timeout = tool_stats[tool].get("Timeout", 0)
            row += f" | {0:>{col_width}}"
            row += f" | {'-':>{col_width}}"
            row += f" | {'-':>{col_width}}"
            row += f" | {'-':>{col_width}}"
            row += f" | {'-':>{col_width}}"
            row += f" | {nr_timeout:>{col_width}}"

        print(row)

    print("=" * 100)


def print_statistics(
    tool_stats: dict[str, dict[str, int]],
    bug_tool_matrix: dict[str, dict[str, str]],
    bug_count: int,
):
    """Print additional statistics."""
    print("\n" + "=" * 80)
    print("STATISTICS")
    print("=" * 80)
    print(f"Total bugs processed: {bug_count}")
    print("Total tools evaluated: 5")
    print(f"Total possible evaluations: {bug_count * 5}")

    # Count actual evaluations (excluding N/A and Unknown)
    actual_evals = sum(sum(counts.values()) for counts in tool_stats.values())
    print(f"Actual evaluations completed: {actual_evals}")

    # Overall results breakdown
    total_tp = sum(tool_stats[tool].get("TP", 0) for tool in tool_stats)
    total_fn = sum(tool_stats[tool].get("FN", 0) for tool in tool_stats)
    total_undecided = sum(
        tool_stats[tool].get("Undecided", 0) for tool in tool_stats
    )
    total_timeout = sum(tool_stats[tool].get("Timeout", 0) for tool in tool_stats)
    total_failure = sum(tool_stats[tool].get("Failure", 0) for tool in tool_stats)

    evaluated = total_tp + total_fn + total_undecided + total_timeout + total_failure
    if evaluated > 0:
        print("\nOverall results breakdown:")
        print(f"  True Positives:  {total_tp:3d} ({total_tp/evaluated*100:5.1f}%)")
        print(f"  False Negatives: {total_fn:3d} ({total_fn/evaluated*100:5.1f}%)")
        print(
            f"  Undecided:       {total_undecided:3d} ({total_undecided/evaluated*100:5.1f}%)"
        )
        print(f"  Timeouts:        {total_timeout:3d} ({total_timeout/evaluated*100:5.1f}%)")
        print(f"  Failures:        {total_failure:3d} ({total_failure/evaluated*100:5.1f}%)")

    # Bug-level detection statistics
    tools = ["circomspect", "circom_civer", "picus", "ecneproject", "zkfuzz", "conscs"]
    tools_without_ecne = ["circomspect", "circom_civer", "picus", "zkfuzz"]

    # Count bugs where at least one tool detected the vulnerability
    bugs_detected_all = 0
    bugs_detected_without_ecne = 0

    for tool_results in bug_tool_matrix.values():
        # Check if any tool found it (TP or TP*)
        has_tp_all = any(
            tool_results.get(tool, "").startswith("TP") for tool in tools
        )
        has_tp_without_ecne = any(
            tool_results.get(tool, "").startswith("TP") for tool in tools_without_ecne
        )

        if has_tp_all:
            bugs_detected_all += 1
        if has_tp_without_ecne:
            bugs_detected_without_ecne += 1

    print("\nBug-level detection coverage:")
    print(
        f"  Out of {bug_count} bugs, at least one tool detected the vulnerability in "
        f"{bugs_detected_all} bugs ({bugs_detected_all/bug_count*100:.1f}%)."
    )
    print(
        "  Excluding EcneProject (which does not directly find exploits or pinpoint "
        "issues and has many false positives),"
    )
    print(
        f"  at least one tool detected the vulnerability in {bugs_detected_without_ecne} bugs "
        f"({bugs_detected_without_ecne/bug_count*100:.1f}%)."
    )

    print("=" * 80)


def generate_latex_report(
    tool_stats: dict[str, dict[str, int]],
    bug_tool_matrix: dict[str, dict[str, str]],
    bug_time_matrix: dict[str, dict[str, float]],
    tool_times: dict[str, list[float]],
    output_pdf: Path,
):
    """Generate LaTeX report with four tables."""
    tools = ["circomspect", "circom_civer", "picus", "ecneproject", "zkfuzz", "conscs"]
    columns = ["TP", "FN", "Timeout", "Failure"]

    # Create bug ID mapping
    sorted_bugs = sorted(bug_tool_matrix.keys())
    bug_id_map = {bug: idx + 1 for idx, bug in enumerate(sorted_bugs)}

    # Generate LaTeX content
    latex_content = r"""\documentclass[11pt]{article}
\usepackage[margin=1in]{geometry}
\usepackage{booktabs}
\usepackage{longtable}
\usepackage{pdflscape}

\begin{document}

\section*{zkBugs Evaluation Results}

\subsection*{Table 1: Tool Performance Summary}

\begin{table}[h]
\centering
\begin{tabular}{l|rrrr|r|r}
\toprule
\textbf{Tool} & \textbf{TP} & \textbf{FN} & \textbf{Timeout} & \textbf{Failure} & \textbf{Total} & \textbf{Median Time (s)} \\
\midrule
"""

    # Add tool rows
    totals = defaultdict(int)
    for tool in tools:
        tool_total = 0
        row_values = []
        for col in columns:
            count = tool_stats[tool].get(col, 0)
            row_values.append(str(count))
            totals[col] += count
            tool_total += count
        row_values.append(str(tool_total))

        # Add median time
        if tool in tool_times and len(tool_times[tool]) > 0:
            median_time = statistics.median(tool_times[tool])
            row_values.append(f"{median_time:.2f}")
        else:
            row_values.append("---")

        # Escape underscores in tool name for LaTeX
        latex_tool_name = tool.replace("_", r"\_")
        latex_content += latex_tool_name + " & " + " & ".join(row_values) + r" \\" + "\n"

    # Add totals row
    latex_content += r"\midrule" + "\n"
    grand_total = sum(totals.values())
    totals_row = ["TOTAL"] + [str(totals[col]) for col in columns] + [str(grand_total)]

    # Calculate overall median time
    all_times = []
    for times in tool_times.values():
        all_times.extend(times)
    if all_times:
        overall_median = statistics.median(all_times)
        totals_row.append(f"{overall_median:.2f}")
    else:
        totals_row.append("---")

    latex_content += " & ".join(totals_row) + r" \\" + "\n"

    latex_content += r"""\bottomrule
\end{tabular}
\end{table}

\subsection*{Table 2: Execution Time Statistics}

\begin{table}[h]
\centering
\begin{tabular}{lrrrrrr}
\toprule
\textbf{Tool} & \textbf{Total} & \textbf{Min (s)} & \textbf{Max (s)} & \textbf{Median (s)} & \textbf{Mean (s)} & \textbf{NR-Timeout} \\
\midrule
"""

    # Add tool execution time statistics
    for tool in tools:
        latex_tool_name = tool.replace("_", r"\_")
        if tool in tool_times and len(tool_times[tool]) > 0:
            times = tool_times[tool]
            total = len(times)
            min_time = min(times)
            max_time = max(times)
            median_time = statistics.median(times)
            mean_time = statistics.mean(times)
            nr_timeout = tool_stats[tool].get("Timeout", 0)

            latex_content += (
                f"{latex_tool_name} & {total} & {min_time:.2f} & {max_time:.2f} & "
                f"{median_time:.2f} & {mean_time:.2f} & {nr_timeout} " + r"\\" + "\n"
            )
        else:
            # No successful executions
            nr_timeout = tool_stats[tool].get("Timeout", 0)
            latex_content += (
                f"{latex_tool_name} & 0 & --- & --- & --- & --- & {nr_timeout} " + r"\\" + "\n"
            )

    latex_content += r"""\bottomrule
\end{tabular}
\end{table}

\clearpage

\subsection*{Table 3: Bug-Tool Matrix (by Bug ID)}

\begin{landscape}
\footnotesize
\begin{longtable}{l|ccccc}
\toprule
\textbf{Bug ID} & \textbf{circomspect} & \textbf{circom\_civer} & \textbf{picus} & \textbf{ecneproject} & \textbf{zkfuzz} \\
\midrule
\endfirsthead

\toprule
\textbf{Bug ID} & \textbf{circomspect} & \textbf{circom\_civer} & \textbf{picus} & \textbf{ecneproject} & \textbf{zkfuzz} \\
\midrule
\endhead

\midrule
\multicolumn{6}{r}{\textit{Continued on next page}} \\
\endfoot

\bottomrule
\endlastfoot

"""

    # Add bug rows with IDs
    for bug_name in sorted_bugs:
        bug_id = bug_id_map[bug_name]
        row_values = [str(bug_id)]
        for tool in tools:
            status = bug_tool_matrix[bug_name].get(tool, "N/A")
            # Escape asterisk for LaTeX if present
            latex_status = status.replace("*", "$^*$")
            row_values.append(latex_status)
        latex_content += " & ".join(row_values) + r" \\" + "\n"

    latex_content += r"""\end{longtable}
\end{landscape}

\vspace{1em}
\noindent\textit{$^*$ = manually analyzed}

\clearpage

\subsection*{Table 4: Bug ID to Name Mapping}

\begin{landscape}
\footnotesize
\begin{longtable}{rp{0.8\textwidth}}
\toprule
\textbf{ID} & \textbf{Bug Name} \\
\midrule
\endfirsthead

\toprule
\textbf{ID} & \textbf{Bug Name} \\
\midrule
\endhead

\midrule
\multicolumn{2}{r}{\textit{Continued on next page}} \\
\endfoot

\bottomrule
\endlastfoot

"""

    # Add bug ID to name mapping
    for bug_name in sorted_bugs:
        bug_id = bug_id_map[bug_name]
        # Escape underscores for LaTeX
        latex_bug_name = bug_name.replace("_", r"\_")
        latex_content += f"{bug_id} & {latex_bug_name} " + r"\\" + "\n"

    latex_content += r"""\end{longtable}
\end{landscape}

\clearpage

\subsection*{Table 5: Execution Times per Bug (by Bug ID, in seconds)}

\begin{landscape}
\footnotesize
\begin{longtable}{l|rrrrr}
\toprule
\textbf{Bug ID} & \textbf{circomspect} & \textbf{circom\_civer} & \textbf{picus} & \textbf{ecneproject} & \textbf{zkfuzz} \\
\midrule
\endfirsthead

\toprule
\textbf{Bug ID} & \textbf{circomspect} & \textbf{circom\_civer} & \textbf{picus} & \textbf{ecneproject} & \textbf{zkfuzz} \\
\midrule
\endhead

\midrule
\multicolumn{6}{r}{\textit{Continued on next page}} \\
\endfoot

\bottomrule
\endlastfoot

"""

    # Add bug execution time rows
    for bug_name in sorted_bugs:
        bug_id = bug_id_map[bug_name]
        row_values = [str(bug_id)]
        for tool in tools:
            exec_time = bug_time_matrix[bug_name].get(tool, -1)
            if exec_time > 0:
                row_values.append(f"{exec_time:.2f}")
            else:
                row_values.append("---")
        latex_content += " & ".join(row_values) + r" \\" + "\n"

    latex_content += r"""\end{longtable}
\end{landscape}

\end{document}
"""

    # Write LaTeX file (use absolute paths to avoid path issues)
    output_pdf_abs = output_pdf.resolve()
    output_pdf_abs.parent.mkdir(parents=True, exist_ok=True)
    tex_file = output_pdf_abs.with_suffix(".tex")
    with open(tex_file, "w") as f:
        f.write(latex_content)

    print(f"Generated LaTeX file: {tex_file}")

    # Compile LaTeX to PDF
    try:
        # Run pdflatex twice for proper formatting
        # Note: pdflatex returns exit code 1 for warnings, so we check manually
        for _ in range(2):
            result = subprocess.run(
                ["pdflatex", "-interaction=nonstopmode", tex_file.name],
                cwd=tex_file.parent,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            # Exit codes: 0 = success, 1 = warnings (acceptable), >1 = error
            if result.returncode > 1:
                raise subprocess.CalledProcessError(
                    result.returncode, result.args
                )

        if not output_pdf_abs.exists():
            raise FileNotFoundError(f"PDF was not generated: {output_pdf_abs}")

        print(f"Generated PDF report: {output_pdf_abs}")

        # Clean up LaTeX auxiliary files
        for ext in [".tex", ".aux", ".log", ".out"]:
            aux_file = output_pdf_abs.with_suffix(ext)
            if aux_file.exists():
                aux_file.unlink()
                print(f"Cleaned up: {aux_file}")

    except subprocess.CalledProcessError:
        print(
            "Error: Failed to compile LaTeX. Please ensure pdflatex is installed.",
            file=sys.stderr,
        )
        print(f"LaTeX file saved at: {tex_file}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError as e:
        if "pdflatex" in str(e):
            print(
                "Error: pdflatex not found. Please install a LaTeX distribution.",
                file=sys.stderr,
            )
        else:
            print(f"Error: {e}", file=sys.stderr)
        print(f"LaTeX file saved at: {tex_file}", file=sys.stderr)
        sys.exit(1)


def _process_single_dir(
    results_dir: Path, full_path: bool, latex_out: Path | None, label: str = ""
) -> None:
    """Collect + print + (optionally) render a single run directory."""
    if label:
        print("\n" + "#" * 80)
        print(f"# {label}")
        print("#" * 80)
    print(f"Processing results from: {results_dir}")

    tool_stats, bug_tool_matrix, bug_time_matrix, tool_times = collect_results(
        results_dir
    )

    print_tool_summary_table(tool_stats, tool_times)
    print_bug_tool_matrix(bug_tool_matrix, full_path=full_path)
    print_execution_time_stats(tool_stats, tool_times)
    print_statistics(tool_stats, bug_tool_matrix, len(bug_tool_matrix))

    if latex_out is not None:
        print(f"\nGenerating LaTeX report: {latex_out}")
        generate_latex_report(
            tool_stats, bug_tool_matrix, bug_time_matrix, tool_times, latex_out
        )


def _is_both_run(results_dir: Path) -> bool:
    """True if results_dir is a --zkbugs-mode both run: has direct/ and
    original/ subdirs OR the top-level summary.json declares mode=both."""
    if (results_dir / "direct").is_dir() and (
        results_dir / "original"
    ).is_dir():
        return True
    summary = results_dir / "summary.json"
    if summary.is_file():
        try:
            data = json.loads(summary.read_text(encoding="utf-8"))
            if data.get("mode") == "both":
                return True
        except (OSError, json.JSONDecodeError):
            pass
    return False


def _both_latex_paths(base: Path) -> tuple[Path, Path, Path]:
    """Given report.pdf, return (direct.pdf, original.pdf, both.pdf)."""
    stem, suffix = base.stem, base.suffix or ".pdf"
    parent = base.parent
    return (
        parent / f"{stem}.direct{suffix}",
        parent / f"{stem}.original{suffix}",
        parent / f"{stem}.both{suffix}",
    )


# ---------------------------------------------------------------------------
# Direct-vs-original comparison
# ---------------------------------------------------------------------------

# We collapse the "* = manually analyzed" suffix when comparing verdicts.
def _strip_marker(status: str) -> str:
    return status.rstrip("*")


def compute_mode_comparison(direct_dir: Path, original_dir: Path) -> dict:
    """Compute a side-by-side comparison of two run directories.

    Only bugs present in both passes are compared (i.e. bugs that had a
    distinct Original Entrypoint and therefore actually ran in original
    mode). Per (bug, tool) we record the direct verdict, the original
    verdict, and a 'changed' flag. Per tool we tally TP/FN/Undecided for
    the common bug set under each mode plus a transition matrix
    (direct_status -> original_status).
    """
    d_stats, d_matrix, _, _ = collect_results(direct_dir)
    o_stats, o_matrix, _, _ = collect_results(original_dir)
    tools = ["circomspect", "circom_civer", "picus", "ecneproject", "zkfuzz", "conscs"]

    common = sorted(set(d_matrix) & set(o_matrix))
    tool_compare: dict[str, dict] = {}
    changed_cells: list[dict] = []

    for tool in tools:
        d_counts = {"TP": 0, "FN": 0, "Undecided": 0, "Other": 0}
        o_counts = {"TP": 0, "FN": 0, "Undecided": 0, "Other": 0}
        transitions: dict[str, dict[str, int]] = {}
        for bug in common:
            d_status = _strip_marker(d_matrix[bug].get(tool, "N/A"))
            o_status = _strip_marker(o_matrix[bug].get(tool, "N/A"))

            for bucket, st in ((d_counts, d_status), (o_counts, o_status)):
                if st in bucket:
                    bucket[st] += 1
                else:
                    bucket["Other"] += 1

            transitions.setdefault(d_status, {}).setdefault(o_status, 0)
            transitions[d_status][o_status] += 1

            if d_status != o_status:
                changed_cells.append(
                    {
                        "bug": bug,
                        "tool": tool,
                        "direct": d_status,
                        "original": o_status,
                    }
                )

        delta_tp = o_counts["TP"] - d_counts["TP"]
        delta_fn = o_counts["FN"] - d_counts["FN"]
        tool_compare[tool] = {
            "direct": d_counts,
            "original": o_counts,
            "delta_tp": delta_tp,
            "delta_fn": delta_fn,
            "transitions": transitions,
        }

    fn_to_tp = sum(
        1 for c in changed_cells if c["direct"] == "FN" and c["original"] == "TP"
    )
    tp_to_fn = sum(
        1 for c in changed_cells if c["direct"] == "TP" and c["original"] == "FN"
    )

    return {
        "common_bugs": common,
        "n_common": len(common),
        "tools": tools,
        "per_tool": tool_compare,
        "changed_cells": changed_cells,
        "fn_to_tp": fn_to_tp,
        "tp_to_fn": tp_to_fn,
    }


def print_comparison(comparison: dict) -> None:
    """Print the comparison tables to the terminal."""
    print("\n" + "#" * 80)
    print("# DIRECT vs ORIGINAL")
    print("#" * 80)
    print(f"\nCommon bugs (ran in both modes): {comparison['n_common']}")
    print(
        f"Verdict transitions FN→TP: {comparison['fn_to_tp']}    "
        f"TP→FN: {comparison['tp_to_fn']}"
    )

    print("\nPer-tool TP/FN/Undecided on the common bug set")
    print("-" * 80)
    header = (
        "{:<14}|{:>5}|{:>5}|{:>5}|{:>5}|{:>5}|{:>5}|{:>6}|{:>6}".format(
            "Tool",
            "D-TP",
            "D-FN",
            "D-Un",
            "O-TP",
            "O-FN",
            "O-Un",
            "ΔTP",
            "ΔFN",
        )
    )
    print(header)
    print("-" * 80)
    for tool in comparison["tools"]:
        row = comparison["per_tool"][tool]
        d, o = row["direct"], row["original"]
        print(
            "{:<14}|{:>5}|{:>5}|{:>5}|{:>5}|{:>5}|{:>5}|{:>+6}|{:>+6}".format(
                tool,
                d["TP"],
                d["FN"],
                d["Undecided"],
                o["TP"],
                o["FN"],
                o["Undecided"],
                row["delta_tp"],
                row["delta_fn"],
            )
        )

    if comparison["changed_cells"]:
        print(
            f"\nVerdict-change detail ({len(comparison['changed_cells'])} cells)"
        )
        print("-" * 80)
        print(
            "{:<14} {:<10} {:<10} {}".format(
                "Tool", "Direct", "Original", "Bug"
            )
        )
        print("-" * 80)
        for c in sorted(
            comparison["changed_cells"],
            key=lambda x: (x["tool"], x["direct"], x["original"], x["bug"]),
        ):
            bug = c["bug"]
            if len(bug) > 50:
                bug = bug[:47] + "..."
            print(
                "{:<14} {:<10} {:<10} {}".format(
                    c["tool"], c["direct"], c["original"], bug
                )
            )
    else:
        print("\nNo (bug, tool) cells changed verdict between modes.")


def generate_comparison_latex(comparison: dict, output_pdf: Path) -> None:
    """Render the direct-vs-original comparison as a standalone PDF."""
    output_pdf_abs = output_pdf.resolve()
    output_pdf_abs.parent.mkdir(parents=True, exist_ok=True)
    tex_file = output_pdf_abs.with_suffix(".tex")

    def esc(s: str) -> str:
        return s.replace("_", r"\_").replace("&", r"\&")

    lines = [
        r"\documentclass[11pt]{article}",
        r"\usepackage[margin=1in]{geometry}",
        r"\usepackage{booktabs}",
        r"\usepackage{longtable}",
        r"\usepackage{pdflscape}",
        r"\begin{document}",
        r"\section*{zkBugs Evaluation: Direct vs Original}",
        rf"\noindent Common bugs (ran in both modes): \textbf{{{comparison['n_common']}}}.",
        rf"\par\noindent Verdict transitions FN$\to$TP: \textbf{{{comparison['fn_to_tp']}}},"
        rf" TP$\to$FN: \textbf{{{comparison['tp_to_fn']}}}.",
        r"",
        r"\subsection*{Per-tool comparison on the common bug set}",
        r"\begin{table}[h]\centering",
        r"\begin{tabular}{l|rrr|rrr|rr}",
        r"\toprule",
        r"\textbf{Tool} & \textbf{D-TP} & \textbf{D-FN} & \textbf{D-Un}"
        r" & \textbf{O-TP} & \textbf{O-FN} & \textbf{O-Un}"
        r" & \textbf{$\Delta$TP} & \textbf{$\Delta$FN} \\",
        r"\midrule",
    ]
    for tool in comparison["tools"]:
        row = comparison["per_tool"][tool]
        d, o = row["direct"], row["original"]
        lines.append(
            f"{esc(tool)} & {d['TP']} & {d['FN']} & {d['Undecided']}"
            f" & {o['TP']} & {o['FN']} & {o['Undecided']}"
            f" & {row['delta_tp']:+d} & {row['delta_fn']:+d} \\\\"
        )
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}", r""]

    if comparison["changed_cells"]:
        lines += [
            r"\clearpage",
            r"\subsection*{Cells whose verdict changed between modes}",
            r"\begin{landscape}",
            r"\footnotesize",
            r"\begin{longtable}{llll}",
            r"\toprule",
            r"\textbf{Tool} & \textbf{Direct} & \textbf{Original} & \textbf{Bug} \\",
            r"\midrule",
            r"\endfirsthead",
            r"\toprule",
            r"\textbf{Tool} & \textbf{Direct} & \textbf{Original} & \textbf{Bug} \\",
            r"\midrule",
            r"\endhead",
            r"\bottomrule",
            r"\endlastfoot",
        ]
        for c in sorted(
            comparison["changed_cells"],
            key=lambda x: (x["tool"], x["direct"], x["original"], x["bug"]),
        ):
            lines.append(
                f"{esc(c['tool'])} & {esc(c['direct'])} & {esc(c['original'])} & {esc(c['bug'])} \\\\"
            )
        lines += [r"\end{longtable}", r"\end{landscape}"]

    lines += [r"\end{document}", ""]
    tex_file.write_text("\n".join(lines), encoding="utf-8")

    try:
        for _ in range(2):
            result = subprocess.run(
                ["pdflatex", "-interaction=nonstopmode", tex_file.name],
                cwd=tex_file.parent,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if result.returncode > 1:
                raise subprocess.CalledProcessError(
                    result.returncode, result.args
                )
        if not output_pdf_abs.exists():
            raise FileNotFoundError(
                f"PDF was not generated: {output_pdf_abs}"
            )
        print(f"Generated comparison PDF: {output_pdf_abs}")
        for ext in [".tex", ".aux", ".log", ".out"]:
            aux_file = output_pdf_abs.with_suffix(ext)
            if aux_file.exists():
                aux_file.unlink()
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(
            f"Error compiling comparison LaTeX: {exc}\n"
            f"TeX file kept at: {tex_file}",
            file=sys.stderr,
        )


def main():
    parser = argparse.ArgumentParser(
        description="Process zkbugs evaluation results and generate summary tables"
    )
    parser.add_argument(
        "results_dir",
        type=Path,
        help="Path to results directory (e.g., output/zkbugs-final)",
    )
    parser.add_argument(
        "--full-path",
        action="store_true",
        help="Print full bug names without truncation in the bug-tool matrix",
    )
    parser.add_argument(
        "--latex",
        type=Path,
        metavar="OUTPUT.pdf",
        help="Generate LaTeX report and save as PDF",
    )
    parser.add_argument(
        "--both",
        action="store_true",
        help="Process a --zkbugs-mode both run (direct/ and original/ "
        "subdirs). Auto-detected when summary.json declares mode=both.",
    )

    args = parser.parse_args()

    if not args.results_dir.exists():
        print(
            f"Error: Directory not found: {args.results_dir}", file=sys.stderr
        )
        sys.exit(1)

    if not args.results_dir.is_dir():
        print(f"Error: Not a directory: {args.results_dir}", file=sys.stderr)
        sys.exit(1)

    use_both = args.both or _is_both_run(args.results_dir)
    if use_both:
        direct = args.results_dir / "direct"
        original = args.results_dir / "original"
        if not direct.is_dir():
            print(
                f"Error: --both requires {direct} to exist",
                file=sys.stderr,
            )
            sys.exit(1)

        direct_pdf = original_pdf = both_pdf = None
        if args.latex:
            direct_pdf, original_pdf, both_pdf = _both_latex_paths(args.latex)

        _process_single_dir(direct, args.full_path, direct_pdf, label="DIRECT")
        if original.is_dir():
            _process_single_dir(
                original, args.full_path, original_pdf, label="ORIGINAL"
            )
            comparison = compute_mode_comparison(direct, original)
            print_comparison(comparison)
            if both_pdf is not None:
                print(f"\nGenerating comparison report: {both_pdf}")
                generate_comparison_latex(comparison, both_pdf)
        else:
            print(
                f"\nNote: {original} does not exist — original pass produced "
                "no output (all bugs had Original Entrypoint identical to direct)."
            )
        return

    _process_single_dir(args.results_dir, args.full_path, args.latex)


if __name__ == "__main__":
    main()
