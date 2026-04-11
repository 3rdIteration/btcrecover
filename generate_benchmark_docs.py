#!/usr/bin/env python3

# generate_benchmark_docs.py -- Generate benchmark documentation from JSON results
# Copyright (C) 2024 Stephen Rothery
#
# This file is part of btcrecover.
#
# btcrecover is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# btcrecover is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with btcrecover.  If not, see <http://www.gnu.org/licenses/>.

"""Generate the Benchmarks.md documentation page from JSON result files.

Reads all JSON files in benchmark-results/ and generates a formatted
markdown page with tables comparing results across different systems.

Usage:
    python generate_benchmark_docs.py
"""

import glob
import json
import os
import sys


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(SCRIPT_DIR, "benchmark-results")
DOCS_FILE = os.path.join(SCRIPT_DIR, "docs", "Benchmarks.md")

# Markers in the template where generated content is inserted
START_MARKER = "<!-- BENCHMARK_RESULTS_START -->"
END_MARKER = "<!-- BENCHMARK_RESULTS_END -->"


def load_all_results():
    """Load all benchmark result JSON files."""
    results = []
    pattern = os.path.join(RESULTS_DIR, "benchmark_*.json")
    for filepath in sorted(glob.glob(pattern)):
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
                data["_filename"] = os.path.basename(filepath)
                results.append(data)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: Could not load {filepath}: {e}", file=sys.stderr)
    return results


def format_rate(rate):
    """Format a rate value for display in markdown."""
    if rate is None or rate == 0:
        return "—"
    if rate >= 1_000_000:
        return f"{rate / 1_000_000:.2f} Mp/s"
    elif rate >= 1_000:
        return f"{rate / 1_000:.2f} Kp/s"
    else:
        return f"{rate:.2f} p/s"


def get_system_label(result):
    """Create a short label for a system from its info."""
    sys_info = result.get("system_info", {})
    cpu = sys_info.get("cpu_model", "Unknown CPU")
    # Shorten common CPU model strings
    cpu = cpu.replace("Intel(R) Core(TM) ", "").replace("AMD ", "")
    cpu = cpu.replace(" Processor", "").replace(" CPU", "")

    cores = sys_info.get("cpu_cores_logical", "?")
    gpu_info = sys_info.get("gpu", [])
    gpu_name = gpu_info[0].get("name", "") if gpu_info else "No GPU"

    return f"{cpu} ({cores} threads)", gpu_name


def generate_markdown(all_results):
    """Generate the benchmark results markdown content."""
    if not all_results:
        return (
            '!!! note "No benchmark results yet"\n'
            "    No benchmark result files have been found in the `benchmark-results/` directory.\n"
            "    Run `python benchmark.py` to generate your first benchmark, or see the\n"
            "    contributing section above.\n"
        )

    lines = []

    # ── System Overview ──
    lines.append("### Systems Tested\n")
    lines.append("| # | CPU | Cores (Phys/Logical) | GPU | OS | Date |")
    lines.append("|---|-----|----------------------|-----|----|----- |")

    for i, result in enumerate(all_results, 1):
        sys_info = result.get("system_info", {})
        cpu = sys_info.get("cpu_model", "Unknown")
        phys = sys_info.get("cpu_cores_physical", "?")
        logical = sys_info.get("cpu_cores_logical", "?")
        gpu_info = sys_info.get("gpu", [])
        gpu = gpu_info[0].get("name", "None") if gpu_info else "None"
        os_name = f"{sys_info.get('os', '?')} {sys_info.get('os_release', '')}"
        timestamp = result.get("metadata", {}).get("timestamp", "?")
        date = timestamp[:10] if len(timestamp) >= 10 else timestamp
        lines.append(f"| {i} | {cpu} | {phys}/{logical} | {gpu} | {os_name} | {date} |")

    lines.append("")

    # ── Collect all test labels and organize by category ──
    categories = {}
    for result in all_results:
        for bench in result.get("benchmarks", []):
            cat = bench.get("category", "other")
            label = bench.get("label", "Unknown")
            # Strip the mode suffix from label for grouping
            base_label = label
            for suffix in (" (CPU)", " (GPU)", " (OPENCL)"):
                base_label = base_label.replace(suffix, "")
            mode = bench.get("mode", "cpu")
            key = (cat, base_label, mode)
            if cat not in categories:
                categories[cat] = {}
            if (base_label, mode) not in categories[cat]:
                categories[cat][(base_label, mode)] = {}

    # ── Fill in rates per system ──
    for i, result in enumerate(all_results):
        for bench in result.get("benchmarks", []):
            cat = bench.get("category", "other")
            label = bench.get("label", "Unknown")
            base_label = label
            for suffix in (" (CPU)", " (GPU)", " (OPENCL)"):
                base_label = base_label.replace(suffix, "")
            mode = bench.get("mode", "cpu")
            rate = bench.get("passwords_per_second", 0)
            if cat in categories and (base_label, mode) in categories[cat]:
                categories[cat][(base_label, mode)][i] = rate

    # ── Password Recovery Table ──
    if "password" in categories:
        lines.append("### Password Recovery Benchmarks\n")
        _generate_table(lines, categories["password"], all_results)
        lines.append("")

    # ── Seed Recovery Table ──
    if "seed" in categories:
        lines.append("### Seed Recovery Benchmarks\n")
        _generate_table(lines, categories["seed"], all_results)
        lines.append("")

    # ── Other categories ──
    for cat_name, cat_data in categories.items():
        if cat_name not in ("password", "seed"):
            lines.append(f"### {cat_name.title()} Benchmarks\n")
            _generate_table(lines, cat_data, all_results)
            lines.append("")

    return "\n".join(lines)


def _generate_table(lines, category_data, all_results):
    """Generate a markdown table for a category of benchmarks."""
    num_systems = len(all_results)

    # Build header
    header = "| Test | Mode |"
    separator = "|------|------|"
    for i in range(num_systems):
        sys_info = all_results[i].get("system_info", {})
        cpu = sys_info.get("cpu_model", "Unknown")
        # Use a short label
        short_cpu = cpu[:30] + "..." if len(cpu) > 30 else cpu
        header += f" System {i + 1} |"
        separator += "--------|"

    lines.append(header)
    lines.append(separator)

    # Sort by label then mode
    sorted_items = sorted(category_data.items(), key=lambda x: (x[0][0], x[0][1]))

    for (label, mode), system_rates in sorted_items:
        row = f"| {label} | {mode.upper()} |"
        for i in range(num_systems):
            rate = system_rates.get(i, None)
            row += f" {format_rate(rate)} |"
        lines.append(row)


def update_docs_file(content):
    """Update the Benchmarks.md file with generated content."""
    if not os.path.exists(DOCS_FILE):
        print(f"Error: {DOCS_FILE} not found", file=sys.stderr)
        return False

    with open(DOCS_FILE, "r") as f:
        doc = f.read()

    start_idx = doc.find(START_MARKER)
    end_idx = doc.find(END_MARKER)

    if start_idx == -1 or end_idx == -1:
        print(f"Error: Could not find markers in {DOCS_FILE}", file=sys.stderr)
        return False

    new_doc = (
        doc[: start_idx + len(START_MARKER)]
        + "\n\n"
        + content
        + "\n\n"
        + doc[end_idx:]
    )

    with open(DOCS_FILE, "w") as f:
        f.write(new_doc)

    print(f"Updated {DOCS_FILE}")
    return True


def main():
    print("Loading benchmark results...")
    all_results = load_all_results()
    print(f"Found {len(all_results)} result file(s)")

    content = generate_markdown(all_results)
    update_docs_file(content)

    if all_results:
        print("\nBenchmark tables generated successfully.")
        print("Run 'mkdocs serve' to view the documentation.")
    else:
        print("\nNo benchmark results found. Run 'python benchmark.py' first.")


if __name__ == "__main__":
    main()
