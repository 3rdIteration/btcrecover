#!/usr/bin/env python3
"""Generate a batch_seed.txt file with substitutions from the BIP39 English list."""
from __future__ import annotations

import sys
from pathlib import Path

WORDLIST_PATH = Path(__file__).resolve().parents[1] / "btcrecover" / "wordlists" / "bip39-en.txt"
DEFAULT_OUTPUT = Path("batch_seeds.txt")


def read_bip39_wordlist() -> list[str]:
    words = WORDLIST_PATH.read_text(encoding="utf-8").splitlines()
    if len(words) != 2048:
        raise ValueError(f"Expected 2048 BIP39 words, found {len(words)} in {WORDLIST_PATH}")
    return words


def prompt_seed_phrase() -> list[str]:
    seed_input = input("Enter the 24-word seed phrase (space-separated): \n").strip()
    words = seed_input.split()
    if len(words) != 24:
        raise ValueError(f"Expected 24 words, received {len(words)}")
    return words


def prompt_index() -> int:
    raw = input("Enter the word index (1-24) to substitute: ").strip()
    index = int(raw)
    if not 1 <= index <= 24:
        raise ValueError("Index must be between 1 and 24")
    return index - 1


def write_batch_file(seed_words: list[str], index: int, wordlist: list[str]) -> Path:
    output_path = DEFAULT_OUTPUT
    with output_path.open("w", encoding="utf-8") as fh:
        for candidate in wordlist:
            updated = list(seed_words)
            updated[index] = candidate
            fh.write(" ".join(updated) + "\n")
    return output_path


def main() -> None:
    try:
        wordlist = read_bip39_wordlist()
        seed_words = prompt_seed_phrase()
        index = prompt_index()
        output = write_batch_file(seed_words, index, wordlist)
    except Exception as exc:  # pylint: disable=broad-except
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"Wrote {len(wordlist)} lines to {output.resolve()}")


if __name__ == "__main__":
    main()
