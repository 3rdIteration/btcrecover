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
import re
import sys
from pathlib import Path

from btcrecover.btcrpass import load_wallet, MAX_WALLET_FILE_SIZE


EXCLUDED_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', '.mypy_cache', '.pytest_cache'}
MAX_MNEMONIC_FILE_SIZE = 16 * 1024

# File extensions that textract can extract text from (without leading dot)
TEXTRACT_SUPPORTED_EXTENSIONS = {
    'csv', 'tsv', 'tab', 'doc', 'docx', 'eml', 'epub', 'gif',
    'jpg', 'jpeg', 'json', 'html', 'htm', 'mp3', 'msg', 'odt',
    'ogg', 'pdf', 'png', 'pptx', 'ps', 'rtf', 'tiff', 'tif', 'txt', 'wav',
    'xls', 'xlsx',
}

# Cache for textract import (only attempt once)
_textract_module = None
TEXTRACT_AVAILABLE = False


def _try_import_textract():
    """Lazily import textract, caching the result."""
    global _textract_module, TEXTRACT_AVAILABLE
    if _textract_module is not None:
        return _textract_module
    try:
        import textract as _t
        _textract_module = _t
        TEXTRACT_AVAILABLE = True
    except ImportError:
        _textract_module = False
    return _textract_module


def read_file_with_textract(filepath, max_size):
    """Read text from a file, using textract for supported document formats.

    For binary documents (docx, pdf, pptx, xlsx, epub, odt, rtf, etc.) uses textract.
    Falls back to direct UTF-8 reading for all other files.
    Returns the extracted text as a string, or None if extraction fails.
    """
    ext = filepath.rsplit('.', 1)[-1].lower() if '.' in os.path.basename(filepath) else ''

    # Try textract first for document formats (it handles all supported types)
    if ext in TEXTRACT_SUPPORTED_EXTENSIONS:
        try:
            textract_mod = _try_import_textract()
            if textract_mod:
                extracted = textract_mod.process(filepath, encoding='utf-8')
                if isinstance(extracted, bytes):
                    extracted = extracted.decode('utf-8', errors='ignore')
                return extracted[:max_size]
        except Exception:
            pass

    # Fallback: try direct UTF-8 reading for all files (plain text and unknown formats)
    try:
        with open(filepath, encoding='utf-8', errors='ignore') as f:
            return f.read(max_size)
    except Exception:
        return None


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


def scan_wallet_mode(folder, depth, debug=False):
    """Scan directory for wallet files using btcrecover's load_wallet().

    Returns a list of dicts with keys: path, type, confidence, (and reason if debug).
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
            result = {
                'path': filepath,
                'type': wtype,
                'confidence': getattr(wallet_obj, 'detection_confidence', 'definite'),
            }
            if debug:
                result['reason'] = getattr(wallet_obj, 'detection_reason', None)
            results.append(result)
        except (Exception, SystemExit):
            pass

    return results, files_scanned


# ---------------------------------------------------------------------------
# Private key detection patterns
# ---------------------------------------------------------------------------

# Base58 alphabet character class (excludes 0, O, I, l to avoid confusion)
B58 = r'[1-9A-HJ-NP-Za-km-z]'

# Raw WIF private keys:
#   Uncompressed: 5 + 50 Base58 chars = 51 total
#   Compressed K/L: K or L + 51 Base58 chars = 52 total
#   Testnet compressed c: c + 51 Base58 chars = 52 total
RAW_WIF_PATTERN = re.compile(
    r'(?<![A-Za-z0-9])'
    r'(?:'
        rf'5{B58}{{50}}'                                # uncompressed 5... (51 total)
        rf'|K{B58}{{51}}'                               # compressed K... (52 total)
        rf'|L{B58}{{51}}'                               # compressed L... (52 total)
        rf'|c{B58}{{51}}'                               # testnet c... (52 total)
    r')'
    r'(?![A-Za-z0-9])',
    re.ASCII
)

# BIP38 encrypted private keys: 6Pn + 54 base58 chars = 58 total
BIP38_PATTERN = re.compile(
    rf'(?<![A-Za-z0-9])6P{B58}{{57}}(?![A-Za-z0-9])',
    re.ASCII
)

# BIP32 extended private keys: prefix (4 chars) + 107 base58 = 111 total
# SLIP-0132 registered prefixes: xprv, yprv, Yprv, zprv, Zprv, tprv, uprv, Uprv, vprv, Vprv
BIP32_XPRV_PATTERN = re.compile(
    rf'(?<![A-Za-z0-9])(?:xprv|yprv|Yprv|zprv|Zprv|tprv|uprv|Uprv|vprv|Vprv){B58}{{107}}(?![A-Za-z0-9])',
    re.ASCII
)

# BIP32 extended public keys: prefix (4 chars) + 106 or 107 base58 = ~110-111 total
# SLIP-0132 registered prefixes: xpub, ypub, Ypub, zpub, Zpub, tpub, upub, Upub, vpub, Vpub
BIP32_XPUB_PATTERN = re.compile(
    rf'(?<![A-Za-z0-9])(?:xpub|ypub|Ypub|zpub|Zpub|tpub|upub|Upub|vpub|Vpub){B58}{{106,107}}(?![A-Za-z0-9])',
    re.ASCII
)


def _classify_wif(key):
    """Return a human-readable label for a raw WIF key."""
    if key.startswith('5'):
        return 'Bitcoin (uncompressed)'
    elif key[0] in ('K', 'L') and len(key) == 52:
        return 'Bitcoin (compressed)'
    elif key[0] == 'c':
        return 'Testnet'
    return 'Unknown network'


def _classify_xprv(key):
    """Return a human-readable label for an extended private key."""
    prefix = key[:4]
    labels = {
        'xprv': 'Bitcoin mainnet (legacy)',
        'yprv': 'Bitcoin mainnet (nested segwit)',
        'Yprv': 'Bitcoin mainnet (multisig nested segwit)',
        'zprv': 'Bitcoin mainnet (native segwit)',
        'tprv': 'Testnet (legacy)',
        'uprv': 'Testnet (nested segwit)',
    }
    return labels.get(prefix, prefix)


def _classify_xpub(key):
    """Return a human-readable label for an extended public key."""
    prefix = key[:4]
    labels = {
        'xpub': 'Bitcoin mainnet (legacy)',
        'ypub': 'Bitcoin mainnet (nested segwit)',
        'zpub': 'Bitcoin mainnet (native segwit)',
        'tpub': 'Testnet (legacy)',
        'upub': 'Testnet (nested segwit)',
    }
    return labels.get(prefix, prefix)


def scan_private_keys(content):
    """Scan extracted text content for private keys.

    Returns a dict with keys: raw_wif, bip38, xprv, xpub.
    Each value is a list of dicts with 'key' and 'network' fields.
    """
    findings = {
        'raw_wif': [],
        'bip38': [],
        'xprv': [],
        'xpub': [],
    }

    for match in RAW_WIF_PATTERN.finditer(content):
        key = match.group(0)
        findings['raw_wif'].append({
            'key': key,
            'network': _classify_wif(key),
        })

    for match in BIP38_PATTERN.finditer(content):
        findings['bip38'].append({
            'key': match.group(0),
            'network': 'BIP38 encrypted',
        })

    for match in BIP32_XPRV_PATTERN.finditer(content):
        key = match.group(0)
        findings['xprv'].append({
            'key': key,
            'network': _classify_xprv(key),
        })

    for match in BIP32_XPUB_PATTERN.finditer(content):
        key = match.group(0)
        findings['xpub'].append({
            'key': key,
            'network': _classify_xpub(key),
        })

    return findings


# ---------------------------------------------------------------------------
# Mnemonic/seed phrase detection (unchanged logic, now part of text mode)
# ---------------------------------------------------------------------------


def load_mnemonic_wordlists():
    """Load all mnemonic wordlists into named sets and ordered lists.

    Returns a tuple (wordlist_sets, wordlist_ordered):
      - wordlist_sets: dict mapping name to set of lowercase words (for fast lookup)
      - wordlist_ordered: dict mapping name to list of lowercase words in canonical order (for checksums)
    """
    wordlists_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'btcrecover', 'wordlists'
    )
    result_sets = {}
    result_ordered = {}

    def load_file(name, filename):
        filepath = os.path.join(wordlists_dir, filename)
        if not os.path.isfile(filepath):
            return set(), []
        words_set = set()
        words_list = []
        try:
            with open(filepath, encoding='utf-8-sig') as f:
                for line in f:
                    word = line.strip().lower()
                    if word and not word.startswith('#'):
                        words_set.add(word)
                        words_list.append(word)
        except Exception:
            pass
        result_sets[name] = words_set
        result_ordered[name] = words_list
        return words_set, words_list

    load_file('BIP39 English', 'bip39-en.txt')
    load_file('Electrum Legacy / Blockchain v2', 'electrum1-en.txt')
    load_file('Blockchain v3', 'blockchainpassword_words_v3-en.txt')

    try:
        from shamir_mnemonic import wordlist as sw
        slip39_set = set(w.lower() for w in sw.WORDLIST)
        result_sets['SLIP39'] = slip39_set
        result_ordered['SLIP39'] = [w.lower() for w in sw.WORDLIST]
    except Exception:
        pass

    return result_sets, result_ordered


# ---------------------------------------------------------------------------
# Checksum validation for mnemonic types
# ---------------------------------------------------------------------------

def _verify_bip39_checksum(words, wordlist):
    """Verify BIP39 checksum for a list of words.

    Valid lengths: 12, 15, 18, 21, 24.
    Returns True if checksum is valid, False otherwise.
    """
    if len(words) not in (12, 15, 18, 21, 24):
        return False
    try:
        import hashlib
        word_to_binary = {w: "{:011b}".format(i) for i, w in enumerate(wordlist)}
        bit_string = "".join(word_to_binary[w] for w in words)
        cksum_len_in_bits = len(words) // 3
        entropy_bytes = bytearray()
        for i in range(0, len(bit_string) - cksum_len_in_bits, 8):
            entropy_bytes.append(int(bit_string[i:i+8], 2))
        cksum_int = int(bit_string[-cksum_len_in_bits:], 2)
        return ord(hashlib.sha256(entropy_bytes).digest()[:1]) >> (8 - cksum_len_in_bits) == cksum_int
    except Exception:
        return False


def _verify_electrum_legacy_checksum(words, wordlist):
    """Verify Electrum Legacy / Blockchain v2 checksum for a list of words.

    Valid lengths: 1-13 and 24.
    Returns True if checksum is valid, False otherwise.
    """
    if len(words) not in list(range(1, 14)) + [24]:
        return False
    try:
        import hashlib
        import hmac
        word_to_id = {w: i for i, w in enumerate(wordlist)}
        ids = [word_to_id[w] for w in words]
        # The last 4 bits of the first word's ID encode the checksum
        test_digest = hmac.new(
            "Seed version".encode(), " ".join(words).encode(), hashlib.sha512
        ).digest()[0]
        return test_digest in (1, 16)
    except Exception:
        return False


def _verify_blockchain_v3_checksum(words):
    """Verify Blockchain v3/v4/v5/v6 checksum for a list of words.

    First 3 words encode version+checksum, remaining words are payload.
    Valid lengths: multiples of 3 (at least 3).
    Returns True if checksum is valid, False otherwise.
    """
    if len(words) < 3 or len(words) % 3 != 0:
        return False
    try:
        import hashlib
        wordlist_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'btcrecover', 'wordlists',
            'blockchainpassword_words_v3-en.txt'
        )
        v3_words = []
        with open(wordlist_path, encoding='utf-8-sig') as f:
            for line in f:
                w = line.strip().lower()
                if w and not w.startswith('#'):
                    v3_words.append(w)

        wordlist_v2_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'btcrecover', 'wordlists',
            'electrum1-en.txt'
        )
        v2_words = []
        with open(wordlist_v2_path, encoding='utf-8-sig') as f:
            for line in f:
                w = line.strip().lower()
                if w and not w.startswith('#'):
                    v2_words.append(w)

        v2_word_to_id = {w: i for i, w in enumerate(v2_words)}

        seedwords = [w for w in words[:3]]
        try:
            v2_ids = [v2_word_to_id[sw] for sw in seedwords]
        except KeyError:
            return False

        checksum = (v2_ids[0] << 16) | (v2_ids[1] << 8) | v2_ids[2]
        version = (checksum >> 24) & 0xFF
        if version not in (3, 4, 5, 6):
            return False

        body_words = words[3:]
        body_v2_ids = []
        for w in body_words:
            try:
                body_v2_ids.append(v2_word_to_id[w])
            except KeyError:
                return False

        str_bytes = bytearray()
        for i in range(0, len(body_v2_ids), 3):
            chunk = (body_v2_ids[i] << 16) | (body_v2_ids[i + 1] << 8) | body_v2_ids[i + 2]
            str_bytes.extend(chunk.to_bytes(4, 'big'))

        str_bytes = bytearray([b for b in str_bytes if b != 0])
        restored_checksum_bytes = version.to_bytes(1, 'big') + hashlib.sha256(str_bytes).digest()[:3]
        restored_checksum = int.from_bytes(restored_checksum_bytes, 'big')
        return checksum == restored_checksum
    except Exception:
        return False


def _verify_slip39_checksum(words):
    """Verify SLIP39 checksum for a list of words.

    Uses the shamir_mnemonic library if available.
    Returns True if checksum is valid, False otherwise.
    """
    try:
        from shamir_mnemonic.share import Share
        Share.from_mnemonic(" ".join(words))
        return True
    except Exception:
        return False


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


def scan_text_mode(folder, depth, min_seq, min_scat, debug=False):
    """Scan directory for files containing mnemonic words or private keys.

    Returns a list of dicts with keys: path, size, findings.
    Each finding has: wordlist/ key_type, sequential/scattered_count/keys, type ('mnemonic' or 'private_key').
    Sequential matches include checksum_valid flag when validated.
    """
    results = []
    files_scanned = 0
    wordlist_sets, wordlist_ordered = load_mnemonic_wordlists()

    print("Scanning for mnemonic words and private keys in: {}".format(folder))
    print("Wordlists loaded:")
    for name, wset in wordlist_sets.items():
        print("  {}: {} words".format(name, len(wset)))
    print()

    if not TEXTRACT_AVAILABLE:
        _try_import_textract()
        if not TEXTRACT_AVAILABLE:
            print("[WARNING] textract is not installed. Document file support (docx, pdf, xlsx, etc.) "
                  "is limited. Plain text files will still be scanned normally.")
            print("         Install textract for full document scanning: pip3 install textract")
            print()

    for filepath in walk_directory(Path(folder), depth):
        try:
            fsize = os.path.getsize(filepath)
        except OSError:
            continue

        if fsize > MAX_MNEMONIC_FILE_SIZE:
            continue

        content = read_file_with_textract(filepath, MAX_MNEMONIC_FILE_SIZE)
        if content is None:
            continue

        files_scanned += 1
        tokens = content.split()
        findings = []

        # Mnemonic word detection with checksum validation
        for wname, wset in wordlist_sets.items():
            seq_matches = check_sequential(tokens, wset, min_seq)
            scattered = check_scattered(tokens, wset)
            scat_count = len(scattered)

            # Validate checksums for sequential matches at valid lengths
            validated_matches = []
            ordered_list = wordlist_ordered.get(wname, [])
            for start, length, words in seq_matches:
                checksum_valid = False
                if 'BIP39' in wname and ordered_list:
                    checksum_valid = _verify_bip39_checksum(words, ordered_list)
                elif ('Electrum' in wname or 'Blockchain v2' in wname) and ordered_list:
                    checksum_valid = _verify_electrum_legacy_checksum(words, ordered_list)
                elif 'Blockchain v3' in wname:
                    checksum_valid = _verify_blockchain_v3_checksum(words)
                elif 'SLIP39' in wname:
                    checksum_valid = _verify_slip39_checksum(words)
                validated_matches.append((start, length, words, checksum_valid))

            if validated_matches or scat_count >= min_scat:
                findings.append({
                    'wordlist': wname,
                    'sequential': validated_matches,
                    'scattered_count': scat_count,
                    'type': 'mnemonic',
                })

        # Private key detection
        key_findings = scan_private_keys(content)
        total_keys_found = (len(key_findings['raw_wif']) + len(key_findings['bip38']) +
                           len(key_findings['xprv']) + len(key_findings['xpub']))

        if total_keys_found > 0:
            key_type_findings = []
            for wif_entry in key_findings['raw_wif']:
                key_type_findings.append({
                    'key': wif_entry['key'],
                    'network': wif_entry['network'],
                    'type': 'private_key',
                })
            for bip38_entry in key_findings['bip38']:
                key_type_findings.append({
                    'key': bip38_entry['key'],
                    'network': bip38_entry['network'],
                    'type': 'private_key',
                })
            for xprv_entry in key_findings['xprv']:
                key_type_findings.append({
                    'key': xprv_entry['key'],
                    'network': xprv_entry['network'],
                    'type': 'private_key',
                })
            for xpub_entry in key_findings['xpub']:
                key_type_findings.append({
                    'key': xpub_entry['key'],
                    'network': xpub_entry['network'],
                    'type': 'private_key',
                })

            findings.append({
                'keys': key_type_findings,
                'total_keys': total_keys_found,
                'type': 'private_key',
            })

        if findings:
            results.append({
                'path': filepath,
                'size': fsize,
                'findings': findings,
            })

    return results, files_scanned


# ---------------------------------------------------------------------------
# Result printing
# ---------------------------------------------------------------------------


def print_wallet_results(results, files_scanned):
    """Print wallet scan results."""
    if not results:
        print("No wallet files found.")
        return

    show_reason = any(r.get('reason') for r in results)

    for r in results:
        line = "{}  [{}] {}".format(r['type'], r['confidence'], r['path'])
        if show_reason and r.get('reason'):
            line += "\n    Detection: {}".format(r['reason'])
        print(line)

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


def _truncate_key(key, max_display=24):
    """Truncate a key string for display purposes."""
    if len(key) <= max_display:
        return key
    return key[:16] + '...' + key[-8:]


def print_text_results(results, files_scanned, debug=False):
    """Print text mode scan results (mnemonics and private keys).

    When debug is False:
      - Sequential matches are not printed.
      - Files with only non-checksum-valid sequential matches are suppressed.
    """
    if not results:
        print("No mnemonic or private key matches found.")
        return

    for r in results:
        # Check if this file has any meaningful results (checksum-valid sequential, keys)
        has_meaningful = False
        for f in r['findings']:
            if f.get('type') == 'mnemonic':
                for match in f['sequential']:
                    checksum_valid = match[3] if len(match) > 3 else False
                    if checksum_valid:
                        has_meaningful = True
                        break
            elif f.get('type') == 'private_key':
                has_meaningful = True

        if not has_meaningful and not debug:
            continue

        print("{} ({} bytes)".format(r['path'], r['size']))
        for f in r['findings']:
            if f.get('type') == 'mnemonic':
                seq_matches = f['sequential']
                # Show sequential matches only in debug mode, or if checksum-valid
                show_seq = []
                for match in seq_matches:
                    length = match[1]
                    words = match[2]
                    checksum_valid = match[3] if len(match) > 3 else False
                    if debug or checksum_valid:
                        show_seq.append((length, words, checksum_valid))

                if not show_seq and f['scattered_count'] == 0:
                    continue

                print("  [Mnemonic: {}]".format(f['wordlist']))
                for length, words, checksum_valid in show_seq:
                    display_words = ' '.join(words[:12])
                    if len(words) > 12:
                        display_words += ' ...'
                    tag = " (checksum valid)" if checksum_valid else ""
                    print("    Sequential match ({} words): {}{}".format(
                        length, display_words, tag))
                if f['scattered_count'] > 0:
                    print("    Scattered unique matches: {}".format(f['scattered_count']))

            elif f.get('type') == 'private_key':
                key_types = {}
                for entry in f['keys']:
                    net = entry['network']
                    if net not in key_types:
                        key_types[net] = []
                    key_types[net].append(entry['key'])

                for network, keys in sorted(key_types.items()):
                    print("  [Private Key: {}]".format(network))
                    for key in keys[:5]:
                        truncated = _truncate_key(key)
                        print("    {}".format(truncated))
                    if len(keys) > 5:
                        print("    ... and {} more".format(len(keys) - 5))

        print()

    print("Summary:")
    print("  Files scanned: {}".format(files_scanned))
    print("  Matches found: {}".format(len(results)))


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------


def parse_arguments(args=None):
    parser = argparse.ArgumentParser(
        prog='walletfinder',
        description='Scan directories for supported wallet files, mnemonic phrases, and private keys.',
    )

    parser.add_argument(
        '--folder', metavar='DIR', required=True,
        help='Directory to scan recursively for wallet/mnemonic/key files.')

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        '--wallet-mode', action='store_true', default=False,
        help='Scan for wallet files using btcrecover auto-detection.')
    mode_group.add_argument(
        '--text-mode', action='store_true',
        help='Scan for mnemonic phrases and private keys (WIF, BIP38, BIP32 extended keys).')
    mode_group.add_argument(
        '--mnemonic-mode', action='store_true', dest='mnemonic_mode_compat',
        help=argparse.SUPPRESS)

    parser.add_argument(
        '--depth', type=int, metavar='N', default=None,
        help='Maximum recursion depth (default: unlimited).')

    parser.add_argument(
        '--debug', action='store_true',
        help='In wallet mode: show detection reasons. In text mode: show all sequential matches '
             '(including checksum-invalid ones) and files with no valid results.')

    text_group = parser.add_argument_group('text mode options')
    text_group.add_argument(
        '--min-sequential', type=int, metavar='N', default=12,
        help='Minimum consecutive wordlist words in a file to report (default: 12).')
    text_group.add_argument(
        '--min-scattered', type=int, metavar='N', default=12,
        help='Minimum unique wordlist words in a file to report (default: 12).')

    args = parser.parse_args(args)
    
    # Set wallet_mode based on whether text mode was explicitly requested
    text_requested = args.text_mode or getattr(args, 'mnemonic_mode_compat', False)
    if not text_requested:
        args.wallet_mode = True
    
    return args


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main():
    args = parse_arguments()

    folder = os.path.abspath(args.folder)
    if not os.path.isdir(folder):
        print("Error: '{}' is not a valid directory.".format(folder))
        sys.exit(1)

    depth = args.depth

    # Determine which mode to use (text-mode is default, mnemonic-mode is backward compat alias)
    text_mode = args.text_mode or getattr(args, 'mnemonic_mode_compat', False)

    if text_mode:
        results, files_scanned = scan_text_mode(
            folder, depth, args.min_sequential, args.min_scattered, debug=args.debug)
        print()
        print_text_results(results, files_scanned, debug=args.debug)
    else:
        results, files_scanned = scan_wallet_mode(folder, depth, debug=args.debug)
        print()
        print_wallet_results(results, files_scanned)


if __name__ == "__main__":
    main()
