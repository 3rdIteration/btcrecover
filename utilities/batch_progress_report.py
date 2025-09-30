#!/usr/bin/env python3
"""Report the processing status of a batch seed run.

This utility inspects a batch seed file (``batch_seeds.txt`` by default)
and its accompanying progress log (``batch_seeds.txt.process`` by default)
to show how far through the batch processing has progressed and highlight
any seeds that appear to have been skipped.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from pathlib import Path
from typing import DefaultDict, List, NamedTuple, Optional, Sequence, Set


class BatchSeedEntry(NamedTuple):
    """Representation of a seed entry from the batch file."""

    seed: str
    position: int
    line_number: int


class ProgressEntry(NamedTuple):
    """Representation of a single progress log entry."""

    status: str
    seed: str
    line_number: int


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Report progress for a batch seed processing run.",
    )
    parser.add_argument(
        "--batch-file",
        type=Path,
        default=Path("batch_seeds.txt"),
        help="Path to the batch seeds file (default: %(default)s)",
    )
    parser.add_argument(
        "--progress-file",
        type=Path,
        default=None,
        help=(
            "Path to the progress log. If omitted, the script looks for "
            "'<batch-file>.process' first and falls back to '<batch-file>.progress'."
        ),
    )
    return parser.parse_args()


def _load_batch_seeds(batch_path: Path) -> Sequence[BatchSeedEntry]:
    """Load batch seeds, ignoring comments and blank lines."""

    entries: List[BatchSeedEntry] = []
    position = 0

    with batch_path.open("r", encoding="utf-8") as batch_file:
        for line_number, line in enumerate(batch_file, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            seed_value = line.split("#", 1)[0].strip()
            if not seed_value:
                continue

            position += 1
            entries.append(BatchSeedEntry(seed_value, position, line_number))

    return entries


def _load_progress(progress_path: Path) -> Sequence[ProgressEntry]:
    """Load progress entries from the progress file."""

    entries: List[ProgressEntry] = []

    with progress_path.open("r", encoding="utf-8") as progress_file:
        for line_number, line in enumerate(progress_file, start=1):
            stripped = line.rstrip("\n")
            if not stripped:
                continue

            parts = stripped.split("\t")
            if len(parts) < 2:
                continue

            status, seed = parts[0].strip(), parts[1].strip()
            if not seed:
                continue

            entries.append(ProgressEntry(status, seed, line_number))

    return entries


def _determine_processed_positions(
    batch_entries: Sequence[BatchSeedEntry],
    progress_entries: Sequence[ProgressEntry],
) -> Set[int]:
    """Identify which batch positions have recorded progress entries.

    The progress log entries may not appear in the same order as the batch
    seeds. Instead of assuming an ordering, we count how many times each seed
    appears in the progress log and mark that many occurrences in the batch as
    processed.
    """

    progress_counts: Counter[str] = Counter(entry.seed for entry in progress_entries)
    processed_positions: Set[int] = set()
    seen_occurrences: DefaultDict[str, int] = defaultdict(int)

    for entry in batch_entries:
        seen_occurrences[entry.seed] += 1
        if progress_counts[entry.seed] >= seen_occurrences[entry.seed]:
            processed_positions.add(entry.position)

    return processed_positions


def _find_progress_file(batch_file: Path, progress_file: Optional[Path]) -> Path:
    if progress_file is not None:
        return progress_file

    process_path = batch_file.with_suffix(batch_file.suffix + ".process")
    if process_path.exists():
        return process_path

    progress_path = batch_file.with_suffix(batch_file.suffix + ".progress")
    return progress_path


def _format_seed(entry: BatchSeedEntry) -> str:
    return f"#{entry.position} (line {entry.line_number}): {entry.seed}"


def main() -> None:
    args = _parse_arguments()
    batch_file: Path = args.batch_file
    progress_file: Path = _find_progress_file(batch_file, args.progress_file)

    if not batch_file.exists():
        raise SystemExit(f"Batch file not found: {batch_file}")

    if not progress_file.exists():
        raise SystemExit(f"Progress file not found: {progress_file}")

    batch_entries = _load_batch_seeds(batch_file)
    if not batch_entries:
        print(f"No seeds found in {batch_file}.")
        return

    progress_entries = _load_progress(progress_file)
    processed_positions = _determine_processed_positions(batch_entries, progress_entries)

    if processed_positions:
        farthest_position = max(processed_positions)
        farthest_entry = next(
            entry for entry in batch_entries if entry.position == farthest_position
        )
    else:
        farthest_position = 0
        farthest_entry = None

    total_seeds = len(batch_entries)
    processed_count = len(processed_positions)

    print(f"Batch file: {batch_file}")
    print(f"Progress file: {progress_file}")
    print(f"Total seeds to process: {total_seeds}")
    print(f"Seeds with progress entries: {processed_count}")

    if farthest_entry is None:
        print("No progress has been recorded yet.")
        return

    percent_complete = (farthest_position / total_seeds) * 100
    print(
        "Farthest processed seed: "
        f"{_format_seed(farthest_entry)} ({percent_complete:.2f}% of batch)"
    )

    skipped_entries = [
        entry
        for entry in batch_entries
        if entry.position < farthest_position and entry.position not in processed_positions
    ]

    if skipped_entries:
        print()
        print("Seeds that appear to have been skipped (up to farthest processed seed):")
        for entry in skipped_entries:
            print(f"  - {_format_seed(entry)}")
    else:
        print("No skipped seeds detected before the farthest processed seed.")


if __name__ == "__main__":
    main()

