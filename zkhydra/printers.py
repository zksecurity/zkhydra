"""
Output formatting and display functions for zkHydra.

This module handles all console output formatting and summary printing.
"""


def print_analyze_summary(summary: dict) -> None:
    """Print formatted summary for analyze mode.

    Args:
        summary: Dictionary containing analysis results with keys:
            - input: Input circuit file path
            - output_directory: Output directory path
            - total_execution_time: Total execution time in seconds
            - total_findings: Total number of findings across all tools
            - statistics: Dict with tool execution statistics
            - tools: Dict mapping tool names to their results
    """
    print("\n" + "=" * 80)
    print("ANALYZE MODE - SUMMARY")
    print("=" * 80)
    print(f"Input:          {summary['input']}")
    print(f"Output:         {summary['output_directory']}")
    print(f"Total Time:     {summary['total_execution_time']:.2f}s")
    print(f"Total Findings: {summary['total_findings']}")

    stats = summary.get("statistics", {})
    if stats:
        print("\n" + "-" * 80)
        print("STATISTICS:")
        print("-" * 80)
        print(f"Total Tools:  {stats.get('total_tools', 0)}")
        print(f"Success:      {stats.get('success', 0)}")
        print(f"Failed:       {stats.get('failed', 0)}")
        print(f"Timeout:      {stats.get('timeout', 0)}")

    print("\n" + "-" * 80)
    print("TOOL RESULTS:")
    print("-" * 80)

    for tool_name, result in summary["tools"].items():
        status = result.get("status", "unknown")

        # Status symbols
        status_symbol = {
            "success": "✓",
            "failed": "✗",
            "timeout": "⏱",
        }.get(status, "?")

        status_text = status.upper()

        print(f"\n{tool_name.upper()}: {status_symbol} {status_text}")
        print(f"  Time:     {result['execution_time']}s")
        print(f"  Raw Output:   {result.get('raw_output_file', 'N/A')}")
        print(f"  Parsed Output:   {result.get('parsed_output_file', 'N/A')}")
        if status == "success":
            print(f"  Findings: {result['findings_count']}")

            if result.get("findings"):
                print("\n  Findings List:")
                for idx, finding in enumerate(
                    result["findings"][:10], 1
                ):  # Show first 10
                    desc = finding.get(
                        "description", finding.get("type", "Unknown")
                    )
                    print(f"    {idx}. {desc}")
                if result["findings_count"] > 10:
                    print(f"    ... and {result['findings_count'] - 10} more")

        elif status == "failed":
            print(f"  Error:    {result.get('error', 'Unknown error')}")

        elif status == "timeout":
            print("  Status:   Tool execution timed out")

    print("\n" + "=" * 80)
