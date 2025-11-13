"""Utility to list BIP39 words matching a user-supplied prefix."""
from __future__ import annotations

import argparse
from pathlib import Path


WORDLIST_PATH = Path(__file__).resolve().parents[1] / "btcrecover" / "wordlists" / "bip39-en.txt"


def load_wordlist() -> list[str]:
    """Return the English BIP39 wordlist as a list of words."""
    with WORDLIST_PATH.open("r", encoding="utf-8") as wordlist_file:
        return [line.strip() for line in wordlist_file if line.strip()]


def prompt_prefix() -> str:
    """Prompt the user for a prefix between one and three characters."""
    prefix = input("Enter between one and three starting characters: ").strip().lower()
    if not (1 <= len(prefix) <= 3):
        raise ValueError("Prefix must contain between one and three characters.")
    return prefix


def validate_prefix(prefix: str) -> str:
    """Ensure *prefix* contains between one and three characters."""
    if not (1 <= len(prefix) <= 3):
        raise argparse.ArgumentTypeError(
            "Prefix must contain between one and three characters."
        )
    return prefix.lower()


def find_matching_words(prefix: str, wordlist: list[str]) -> list[str]:
    """Return all words that start with *prefix* from the supplied *wordlist*."""
    return [word for word in wordlist if word.startswith(prefix)]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="List BIP39 words that start with a provided prefix.",
    )
    parser.add_argument(
        "--prefix",
        type=validate_prefix,
        help="Prefix to match (1-3 characters). If omitted you will be prompted.",
    )
    parser.add_argument(
        "--count",
        action="store_true",
        help="Display the number of matched words on a second line.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    wordlist = load_wordlist()

    if args.prefix is not None:
        prefix = args.prefix
    else:
        try:
            prefix = prompt_prefix()
        except ValueError as exc:
            print(exc)
            return

    matches = find_matching_words(prefix, wordlist)
    print(" ".join(matches))

    if args.count:
        print(len(matches))


if __name__ == "__main__":
    main()
