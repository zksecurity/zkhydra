#!/usr/bin/env python3
"""
Process zkbugs evaluation results and generate summary tables.

Usage:
    python scripts/process_zkbugs_results.py output/zkbugs-final
    python scripts/process_zkbugs_results.py output/zkbugs-final --latex report.pdf
"""

import argparse
import json
import os
import statistics
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple


def load_json(file_path: Path) -> dict:
    """Load JSON file safely."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"Warning: Failed to load {file_path}: {e}", file=sys.stderr)
        return {}


def get_tool_status(bug_dir: Path, tool_name: str) -> Tuple[str, bool, float]:
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

        if status == "TruePositive":
            return "TP", manually_analyzed, execution_time
        elif status == "FalseNegative":
            return "FN", manually_analyzed, execution_time
        elif status == "Undecided":
            return "Undecided", manually_analyzed, execution_time
        else:
            return "Unknown", manually_analyzed, execution_time

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
            with open(raw_file, "r", encoding="utf-8") as f:
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
) -> Tuple[Dict[str, Dict[str, int]], Dict[str, Dict[str, str]], Dict[str, Dict[str, float]], Dict[str, List[float]]]:
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
    tools = ["circomspect", "circom_civer", "picus", "ecneproject", "zkfuzz"]

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


def print_tool_summary_table(tool_stats: Dict[str, Dict[str, int]], tool_times: Dict[str, List[float]]):
    """Print summary table with tools as rows."""
    print("\n" + "=" * 80)
    print("SUMMARY TABLE: Tool Performance")
    print("=" * 80)

    # Define columns and tools
    columns = ["TP", "FN", "Undecided", "Timeout", "Failure"]
    tools = ["circomspect", "circom_civer", "picus", "ecneproject", "zkfuzz"]

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
    bug_tool_matrix: Dict[str, Dict[str, str]], full_path: bool = False
):
    """Print matrix with bugs as rows and tools as columns.

    Args:
        bug_tool_matrix: Dictionary mapping bug names to tool statuses (with asterisks)
        full_path: If True, print full bug names without truncation
    """
    tools = ["circomspect", "circom_civer", "picus", "ecneproject", "zkfuzz"]

    # Calculate column widths
    bug_width = max(len(bug) for bug in bug_tool_matrix.keys())
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
    tool_stats: Dict[str, Dict[str, int]],
    tool_times: Dict[str, List[float]],
):
    """Print execution time statistics per tool."""
    print("\n" + "=" * 100)
    print("EXECUTION TIME STATISTICS")
    print("=" * 100)

    tools = ["circomspect", "circom_civer", "picus", "ecneproject", "zkfuzz"]

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
    tool_stats: Dict[str, Dict[str, int]],
    bug_tool_matrix: Dict[str, Dict[str, str]],
    bug_count: int,
):
    """Print additional statistics."""
    print("\n" + "=" * 80)
    print("STATISTICS")
    print("=" * 80)
    print(f"Total bugs processed: {bug_count}")
    print(f"Total tools evaluated: 5")
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
        print(f"\nOverall results breakdown:")
        print(f"  True Positives:  {total_tp:3d} ({total_tp/evaluated*100:5.1f}%)")
        print(f"  False Negatives: {total_fn:3d} ({total_fn/evaluated*100:5.1f}%)")
        print(
            f"  Undecided:       {total_undecided:3d} ({total_undecided/evaluated*100:5.1f}%)"
        )
        print(f"  Timeouts:        {total_timeout:3d} ({total_timeout/evaluated*100:5.1f}%)")
        print(f"  Failures:        {total_failure:3d} ({total_failure/evaluated*100:5.1f}%)")

    # Bug-level detection statistics
    tools = ["circomspect", "circom_civer", "picus", "ecneproject", "zkfuzz"]
    tools_without_ecne = ["circomspect", "circom_civer", "picus", "zkfuzz"]

    # Count bugs where at least one tool detected the vulnerability
    bugs_detected_all = 0
    bugs_detected_without_ecne = 0

    for bug_name, tool_results in bug_tool_matrix.items():
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

    print(f"\nBug-level detection coverage:")
    print(
        f"  Out of {bug_count} bugs, at least one tool detected the vulnerability in "
        f"{bugs_detected_all} bugs ({bugs_detected_all/bug_count*100:.1f}%)."
    )
    print(
        f"  Excluding EcneProject (which does not directly find exploits or pinpoint "
        f"issues and has many false positives),"
    )
    print(
        f"  at least one tool detected the vulnerability in {bugs_detected_without_ecne} bugs "
        f"({bugs_detected_without_ecne/bug_count*100:.1f}%)."
    )

    print("=" * 80)


def generate_latex_report(
    tool_stats: Dict[str, Dict[str, int]],
    bug_tool_matrix: Dict[str, Dict[str, str]],
    bug_time_matrix: Dict[str, Dict[str, float]],
    tool_times: Dict[str, List[float]],
    output_pdf: Path,
):
    """Generate LaTeX report with four tables."""
    tools = ["circomspect", "circom_civer", "picus", "ecneproject", "zkfuzz"]
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

    except subprocess.CalledProcessError as e:
        print(
            f"Error: Failed to compile LaTeX. Please ensure pdflatex is installed.",
            file=sys.stderr,
        )
        print(f"LaTeX file saved at: {tex_file}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError as e:
        if "pdflatex" in str(e):
            print(
                f"Error: pdflatex not found. Please install a LaTeX distribution.",
                file=sys.stderr,
            )
        else:
            print(f"Error: {e}", file=sys.stderr)
        print(f"LaTeX file saved at: {tex_file}", file=sys.stderr)
        sys.exit(1)


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

    args = parser.parse_args()

    if not args.results_dir.exists():
        print(
            f"Error: Directory not found: {args.results_dir}", file=sys.stderr
        )
        sys.exit(1)

    if not args.results_dir.is_dir():
        print(f"Error: Not a directory: {args.results_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"Processing results from: {args.results_dir}")

    # Collect results
    tool_stats, bug_tool_matrix, bug_time_matrix, tool_times = collect_results(args.results_dir)

    # Print tables
    print_tool_summary_table(tool_stats, tool_times)
    print_bug_tool_matrix(bug_tool_matrix, full_path=args.full_path)
    print_execution_time_stats(tool_stats, tool_times)
    print_statistics(tool_stats, bug_tool_matrix, len(bug_tool_matrix))

    # Generate LaTeX report if requested
    if args.latex:
        print(f"\nGenerating LaTeX report...")
        generate_latex_report(tool_stats, bug_tool_matrix, bug_time_matrix, tool_times, args.latex)


if __name__ == "__main__":
    main()
