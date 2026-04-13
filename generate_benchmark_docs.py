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
TEMPLATE_FILE = os.path.join(SCRIPT_DIR, "docs", "Benchmarks.md.template")
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


def generate_markdown(all_results):
    """Generate the benchmark results markdown content."""
    if not all_results:
        return (
            '!!! note "No benchmark results yet"\n'
            "    No benchmark result files have have been found in the `benchmark-results/` directory.\n"
            "    Run `python benchmark.py` to generate your first benchmark, or see the\n"
            "    contributing section above.\n"
        )

    lines = []

    # ── System Overview ──
    lines.append("### Systems Tested\n")
    lines.append("| # | CPU | Cores (Phys/Logical) | GPU | OpenCL Device | OS | Date |")
    lines.append("|---|-----|----------------------|-----|---------------|----|----- |")

    for i, result in enumerate(all_results, 1):
        sys_info = result.get("system_info", {})
        cpu = sys_info.get("cpu_model", "Unknown")
        cpu = cpu.replace("Intel(R) Core(TM) ", "").replace("AMD ", "")
        cpu = cpu.replace(" Processor", "").replace(" CPU", "")
        phys = sys_info.get("cpu_cores_physical", "?")
        logical = sys_info.get("cpu_cores_logical", "?")
        gpu_info = sys_info.get("gpu", [])
        gpu = gpu_info[0].get("name", "None") if gpu_info else "None"
        opencl_devs = sys_info.get("opencl_devices", [])
        if isinstance(opencl_devs, list) and opencl_devs:
            dev = opencl_devs[0]
            opencl = f"{dev.get('name', '?')} ({dev.get('global_memory_mb', '?')} MB)"
        else:
            opencl = "None"
        os_name = f"{sys_info.get('os', '?')} {sys_info.get('s_release', '')}"
        # Note: using os_release if available, else os
        if not sys_info.get('os_release'):
             os_name = f"{sys_info.get('os', '?')}"
        else:
             os_name = f"{sys_info.get('os', '?')} {sys_info.get('os_release', '')}"

        timestamp = result.get("metadata", {}).get("timestamp", "?")
        date = timestamp[:10] if len(timestamp) >= 10 else timestamp
        lines.append(f"| {i} | {cpu} | {phys}/{logical} | {gpu} | {opencl} | {os_name} | {date} |")

    lines.append("")

    # ── Collect all test labels and organize by category ──
    categories = {}
    difficulties = {}  # (cat, base_label, mode) -> wallet_difficulty string
    rate_lookup = {}   # (system_idx, mode, base_label) -> rate

    for i, result in enumerate(all_results):
        for bench in result.get("benchmarks", []):
            cat = bench.get("category", "other")
            label = bench.get("label", "Unknown")
            mode = bench.get("mode", "cpu")
            
            # Clean label
            base_label = label
            for suffix in (" (CPU)", " (GPU)", " (OPENCL)"):
                base_label = base_label.replace(suffix, "")
            
            if cat not in categories:
                categories[cat] = {}
            
            if (base_label, mode) not in categories[cat]:
                categories[cat][(base_label, mode)] = {}
            
            # Capture rate
            rate = bench.get("passwords_per_second", 0)
            rate_lookup[(i, mode, base_label)] = rate

            # Capture difficulty
            difficulty = bench.get("wallet_difficulty", "")
            if difficulty:
                difficulties[(cat, base_label, mode)] = difficulty

    # ── Build tables for each category ──
    for cat in sorted(categories.keys()):
        lines.append(f"### {cat.title()} Benchmarks\n")
        
        # Prepare data for _generate_table: (label, mode) -> {system_idx: rate}
        category_data = {}
        for (base_label, mode), _ in categories[cat].items():
            category_data[(base_label, mode)] = {}
            for i in range(len(all_results)):
                if (i, mode, base_label) in rate_lookup:
                    category_data[(base_label, mode)][i] = rate_lookup[(i, mode, base_label)]

        # Prepare difficulties for this category
        cat_difficulties = {}
        for (c, label, mode), diff in difficulties.items():
            if c == cat:
                cat_difficulties[(label, mode)] = diff

        _generate_table(lines, category_data, all_results, difficulties=cat_difficulties)
        lines.append("")

    return "\n".join(lines)


def _get_system_hw_label(result, index, mode):
    """Build a short label showing system number and relevant hardware.

    For CPU mode, shows the CPU name.
    For GPU/OpenCL modes, shows the GPU name.
    """
    sys_info = result.get("system_info", {})
    cpu = sys_info.get("cpu_model", "Unknown")
    cpu = cpu.replace("Intel(R) Core(TM) ", "").replace("AMD ", "")
    cpu = cpu.replace(" Processor", "").replace(" CPU", "")
    gpu_info = sys_info.get("gpu", [])
    gpu = gpu_info[0].get("name", "None") if gpu_info else "None"

    if mode in ("gpu", "opencl"):
        if gpu != "None":
            return f"#{index + 1} {gpu}"
        # Fall back to CPU if no GPU info available
        return f"#{index + 1} {cpu}"
    return f"#{index + 1} {cpu}"


def _generate_table(lines, category_data, all_results, difficulties=None):
    """Generate a markdown table for a category of benchmarks."""
    if not category_data:
        return

    # Collect unique base labels (without mode) in sorted order
    base_labels = sorted(set(label for label, mode in category_data.keys()))

    # Collect all (system_idx, mode) row keys that have data
    row_keys = set()
    for (label, mode), system_rates in category_data.items():
        for sys_idx in system_rates:
            row_keys.add((sys_idx, mode))
    # Sort by system index first, then mode
    mode_order = {"cpu": 0, "gpu": 1, "opencl": 2}
    sorted_row_keys = sorted(row_keys, key=lambda x: (x[0], mode_order.get(x[1], 9)))

    # Header — test labels as columns, with difficulty if available
    header = "| System | Mode |"
    separator = "|--------|------|"
    for label in base_labels:
        display_label = label
        if difficulties:
            # Find any difficulty for this label (pick from any mode)
            for mode_key in ("cpu", "gpu", "opencl"):
                diff = difficulties.get((label, mode_key), "")
                if diff:
                    display_label = f"{label} - {diff}"
                    break
        header += f" {display_label} |"
        separator += "--------|"

    lines.append(header)
    lines.append(separator)

    # Rows — one per (system, mode) combination
    for sys_idx, mode in sorted_row_keys:
        sys_label = _get_system_hw_label(all_results[sys_idx], sys_idx, mode)
        row = f"| {sys_label} | {mode.upper()} |"
        for label in base_labels:
            rate = category_data.get((label, mode), {}).get(sys_idx, None)
            row += f" {format_rate(rate)} |"
        lines.append(row)


def update_docs_file(content):
    """Generate Benchmarks.md from the template file with benchmark content inserted."""
    if not os.path.exists(TEMPLATE_FILE):
        print(f"Error: {TEMPLATE_FILE} not found", file=sys.stderr)
        return False

    with open(TEMPLATE_FILE, "r", encoding="utf-8") as f:
        doc = f.read()

    start_idx = doc.find(START_MARKER)
    end_idx = doc.find(END_MARKER)

    if start_idx == -1 or end_idx == -1:
        print(f"Error: Could not find markers in {TEMPLATE_FILE}", file=sys.stderr)
        return False

    new_doc = (
        doc[: start_idx + len(START_MARKER)]
        + "\n\n"
        + content
        + "\n\n"
        + doc[end_idx:]
    )

    with open(DOCS_FILE, "w", encoding="utf-8") as f:
        f.write(new_doc)

    print(f"Generated {DOCS_FILE} from {TEMPLATE_FILE}")
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