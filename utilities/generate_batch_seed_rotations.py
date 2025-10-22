#!/usr/bin/env python3
"""Generate a batch_seeds.txt file with all rotations of a mnemonic."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Iterable

DEFAULT_OUTPUT = Path("batch_seeds.txt")
VALID_LENGTHS = {12, 15, 18, 21, 24}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate a batch_seeds.txt file containing every rotation of the "
            "provided mnemonic."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "mnemonic",
        nargs="*",
        help="Mnemonic words. Provide them directly or leave blank to be prompted.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Path to the output batch_seeds.txt file.",
    )
    return parser.parse_args()


def prompt_mnemonic() -> list[str]:
    seed_input = input("Enter the mnemonic (space-separated words):\n").strip()
    words = seed_input.split()
    if not words:
        raise ValueError("Mnemonic cannot be empty")
    return words


def validate_mnemonic(words: Iterable[str]) -> list[str]:
    mnemonic = [word.strip() for word in words if word.strip()]
    if not mnemonic:
        raise ValueError("Mnemonic cannot be empty")
    if len(mnemonic) not in VALID_LENGTHS:
        allowed = ", ".join(str(length) for length in sorted(VALID_LENGTHS))
        raise ValueError(
            f"Mnemonic must contain one of the following word counts: {allowed}. "
            f"Received {len(mnemonic)} words."
        )
    return mnemonic


def generate_rotations(words: list[str]) -> list[str]:
    rotations = []
    total = len(words)
    for index in range(total):
        rotated = words[index:] + words[:index]
        rotations.append(" ".join(rotated))
    return rotations


def write_batch_file(rotations: Iterable[str], output_path: Path) -> Path:
    with output_path.open("w", encoding="utf-8") as handle:
        for line in rotations:
            handle.write(f"{line}\n")
    return output_path


def main() -> None:
    args = parse_args()
    try:
        raw_words = args.mnemonic or prompt_mnemonic()
        mnemonic = validate_mnemonic(raw_words)
        rotations = generate_rotations(mnemonic)
        output_path = write_batch_file(rotations, args.output)
    except Exception as exc:  # pylint: disable=broad-except
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    else:
        print(
            f"Wrote {len(rotations)} rotation(s) to {output_path.resolve()}"
        )


if __name__ == "__main__":
    main()
