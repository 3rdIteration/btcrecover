#!/usr/bin/env python3

# walletfinder.py -- Scan directories for supported wallet files and mnemonic phrases
# Copyright (C) 2014-2017 Christopher Gurnee
#
# This program is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version
# 2 of the License, or (at your option) or later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/

import compatibility_check

import argparse
import os
import sys
from pathlib import Path

from btcrecover.btcrpass import load_wallet, MAX_WALLET_FILE_SIZE


EXCLUDED_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', '.mypy_cache', '.pytest_cache'}
MAX_MNEMONIC_FILE_SIZE = 16 * 1024


def get_wallet_type_name(wallet_obj):
    """Extract wallet type name from a loaded wallet object."""
    return type(wallet_obj).__name__


def walk_directory(folder, max_depth, current_depth=0):
    """Walk directory tree with depth limiting and exclusion filtering.

    Yields (filepath,) for each file found.
    """
    folder = Path(folder)
    if not folder.is_dir():
        return

    try:
        entries = sorted(folder.iterdir())
    except PermissionError:
        return

    for entry in entries:
        if entry.is_dir():
            if entry.name.startswith('.') and entry.name != '.':
                continue
            if entry.name in EXCLUDED_DIRS:
                continue
            if max_depth is not None and current_depth >= max_depth:
                continue
            yield from walk_directory(entry, max_depth, current_depth + 1)
        elif entry.is_file():
            yield str(entry)


def scan_wallet_mode(folder, depth):
    """Scan directory for wallet files using btcrecover's load_wallet().

    Returns a list of dicts with keys: path, type, confidence.
    """
    results = []
    files_scanned = 0

    for filepath in walk_directory(Path(folder), depth):
        if os.path.getsize(filepath) > MAX_WALLET_FILE_SIZE:
            continue
        files_scanned += 1

        try:
            wallet_obj = load_wallet(filepath)
            wtype = get_wallet_type_name(wallet_obj)
            results.append({
                'path': filepath,
                'type': wtype,
                'confidence': 'definite',
            })
        except (Exception, SystemExit):
            pass

    return results, files_scanned


def load_mnemonic_wordlists():
    """Load all mnemonic wordlists into named sets.

    Returns a dict mapping wordlist name to set of lowercase words.
    """
    wordlists_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'btcrecover', 'wordlists'
    )
    result = {}

    def load_file(name, filename):
        filepath = os.path.join(wordlists_dir, filename)
        if not os.path.isfile(filepath):
            return set()
        words = set()
        try:
            with open(filepath, encoding='utf-8-sig') as f:
                for line in f:
                    word = line.strip().lower()
                    if word and not word.startswith('#'):
                        words.add(word)
        except Exception:
            pass
        result[name] = words
        return words

    load_file('BIP39 English', 'bip39-en.txt')
    load_file('Electrum Legacy / Blockchain v2', 'electrum1-en.txt')
    load_file('Blockchain v3', 'blockchainpassword_words_v3-en.txt')

    try:
        from shamir_mnemonic import wordlist as sw
        result['SLIP39'] = set(w.lower() for w in sw.WORDLIST)
    except Exception:
        pass

    return result


def check_sequential(tokens, wordset, min_seq):
    """Find consecutive runs of matching words.

    Returns list of (start_index, length, matched_words) tuples.
    """
    matches = []
    run_start = 0
    run_length = 0
    run_words = []

    for i, token in enumerate(tokens):
        clean = token.strip('.,;:!?()[]{}"\'-').lower()
        if clean in wordset:
            if run_length == 0:
                run_start = i
            run_length += 1
            run_words.append(clean)
        else:
            if run_length >= min_seq:
                matches.append((run_start, run_length, list(run_words)))
            run_length = 0
            run_words = []

    if run_length >= min_seq:
        matches.append((run_start, run_length, list(run_words)))

    return matches


def check_scattered(tokens, wordset):
    """Count unique matching words in tokens.

    Returns set of matched words.
    """
    matched = set()
    for token in tokens:
        clean = token.strip('.,;:!?()[]{}"\'-').lower()
        if clean in wordset:
            matched.add(clean)
    return matched


def scan_mnemonic_mode(folder, depth, min_seq, min_scat):
    """Scan directory for files containing mnemonic words.

    Returns a list of dicts with keys: path, size, findings.
    Each finding has: wordlist, sequential (list), scattered_count.
    """
    results = []
    files_scanned = 0
    wordlists = load_mnemonic_wordlists()

    print("Scanning for mnemonic words in: {}".format(folder))
    print("Wordlists loaded:")
    for name, wset in wordlists.items():
        print("  {}: {} words".format(name, len(wset)))
    print()

    for filepath in walk_directory(Path(folder), depth):
        try:
            fsize = os.path.getsize(filepath)
        except OSError:
            continue

        if fsize > MAX_MNEMONIC_FILE_SIZE:
            continue

        try:
            with open(filepath, encoding='utf-8', errors='ignore') as f:
                content = f.read(MAX_MNEMONIC_FILE_SIZE)
        except Exception:
            continue

        files_scanned += 1
        tokens = content.split()
        findings = []

        for wname, wset in wordlists.items():
            seq_matches = check_sequential(tokens, wset, min_seq)
            scattered = check_scattered(tokens, wset)
            scat_count = len(scattered)

            if seq_matches or scat_count >= min_scat:
                findings.append({
                    'wordlist': wname,
                    'sequential': seq_matches,
                    'scattered_count': scat_count,
                })

        if findings:
            results.append({
                'path': filepath,
                'size': fsize,
                'findings': findings,
            })

    return results, files_scanned


def print_wallet_results(results, files_scanned):
    """Print wallet scan results."""
    if not results:
        print("No wallet files found.")
        return

    for r in results:
        print("{}  [{}] {}".format(r['type'], r['confidence'], r['path']))

    print()
    print("Summary:")
    print("  Files scanned: {}".format(files_scanned))
    print("  Wallets found: {}".format(len(results)))

    type_counts = {}
    for r in results:
        wtype = r['type']
        type_counts[wtype] = type_counts.get(wtype, 0) + 1

    if type_counts:
        print("  Breakdown:")
        for wtype, count in sorted(type_counts.items()):
            print("    {}: {}".format(wtype, count))


def print_mnemonic_results(results, files_scanned):
    """Print mnemonic scan results."""
    if not results:
        print("No mnemonic matches found.")
        return

    for r in results:
        print("{} ({} bytes)".format(r['path'], r['size']))
        for f in r['findings']:
            print("  [{}]".format(f['wordlist']))
            if f['sequential']:
                for start, length, words in f['sequential']:
                    print("    Sequential match ({} words): {}".format(
                        length, ' '.join(words)))
            if f['scattered_count'] > 0:
                print("    Scattered unique matches: {}".format(f['scattered_count']))

    print()
    print("Summary:")
    print("  Files scanned: {}".format(files_scanned))
    print("  Matches found: {}".format(len(results)))


def parse_arguments(args=None):
    parser = argparse.ArgumentParser(
        prog='walletfinder',
        description='Scan directories for supported wallet files and mnemonic phrases.',
    )

    parser.add_argument(
        '--folder', metavar='DIR', required=True,
        help='Directory to scan recursively for wallet/mnemonic files.')

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        '--wallet-mode', action='store_true', default=True,
        help='Scan for wallet files using btcrecover auto-detection (default).')
    mode_group.add_argument(
        '--mnemonic-mode', action='store_true',
        help='Scan for files containing mnemonic seed words.')

    parser.add_argument(
        '--depth', type=int, metavar='N', default=None,
        help='Maximum recursion depth (default: unlimited).')

    mnemo_group = parser.add_argument_group('mnemonic mode options')
    mnemo_group.add_argument(
        '--min-sequential', type=int, metavar='N', default=6,
        help='Minimum consecutive wordlist words to report (default: 6).')
    mnemo_group.add_argument(
        '--min-scattered', type=int, metavar='N', default=12,
        help='Minimum unique wordlist words in a file to report (default: 12).')

    return parser.parse_args(args)


def main():
    args = parse_arguments()

    folder = os.path.abspath(args.folder)
    if not os.path.isdir(folder):
        print("Error: '{}' is not a valid directory.".format(folder))
        sys.exit(1)

    depth = args.depth

    if args.mnemonic_mode:
        results, files_scanned = scan_mnemonic_mode(
            folder, depth, args.min_sequential, args.min_scattered)
        print()
        print_mnemonic_results(results, files_scanned)
    else:
        results, files_scanned = scan_wallet_mode(folder, depth)
        print()
        print_wallet_results(results, files_scanned)


if __name__ == "__main__":
    main()
