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
import hashlib
import os
import re
import signal
import sys
import threading
from pathlib import Path

from btcrecover.btcrpass import load_wallet, MAX_WALLET_FILE_SIZE


# ---------------------------------------------------------------------------
# Graceful shutdown flag
# ---------------------------------------------------------------------------

_should_stop = threading.Event()


def _handle_sigint(signum, frame):
    """Handle Ctrl+C by setting the stop event."""
    _should_stop.set()


signal.signal(signal.SIGINT, _handle_sigint)


EXCLUDED_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', '.mypy_cache', '.pytest_cache'}

# Path-substring exclusion list (bundled with BTCRecover) used to skip the repository's own
# test wallets and example seed/key files when scanning the repo (e.g. `--folder .`). See
# load_exclusions() and update_exclusion_list().
EXCLUSIONLIST_FILENAME = 'walletfinder-exclusionlist.txt'

# Text-mode file-size limits. Plain files are read directly, so a small cap avoids scanning
# large logs/data. Documents (pdf, docx, xlsx, ...) are extracted with textract: the file can be
# far larger than the little text it contains (e.g. a ~190 KB PDF paper wallet), so they get a
# more generous cap. Extracted text is still truncated to MAX_MNEMONIC_FILE_SIZE for scanning.
MAX_MNEMONIC_FILE_SIZE = 16 * 1024
MAX_DOCUMENT_FILE_SIZE = 500 * 1024

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

# Warn at most once when a PDF needs the pypdf fallback but pypdf isn't installed
_pypdf_warning_shown = False


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


def _extract_pdf_text_pypdf(filepath):
    """Extract text from a PDF using pypdf (handles custom font encodings better than pdfminer)."""
    global _pypdf_warning_shown
    try:
        import pypdf
    except ImportError:
        if not _pypdf_warning_shown:
            _pypdf_warning_shown = True
            print("[WARNING] A PDF needed the pypdf fallback (custom font encoding), but pypdf is "
                  "not installed, so its text could not be scanned.")
            print("         Install pypdf to scan these PDFs: pip3 install pypdf")
            print()
        return None
    try:
        reader = pypdf.PdfReader(filepath)
        pages_text = []
        for page in reader.pages:
            txt = page.extract_text()
            if txt:
                pages_text.append(txt)
        return ''.join(pages_text) if pages_text else None
    except Exception:
        return None


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
                # For PDFs specifically, check if extraction produced meaningful text.
                # pdfminer (used by textract) can fail on custom font encodings, producing
                # garbled single characters per line. If so, fall through to pypdf fallback.
                if ext == 'pdf' and extracted:
                    lines = [l.strip() for l in extracted.splitlines() if l.strip()]
                    # If most lines are 1-2 chars (garbled), try pypdf instead
                    short_lines = sum(1 for l in lines if len(l) <= 3)
                    if lines and short_lines > len(lines) * 0.5:
                        pass  # fall through to pypdf below
                    else:
                        return extracted[:max_size]
                elif ext != 'pdf':
                    return extracted[:max_size]
        except Exception:
            pass

        # For PDFs, try pypdf as a fallback (handles custom font encodings better)
        if ext == 'pdf':
            pdf_text = _extract_pdf_text_pypdf(filepath)
            if pdf_text:
                return pdf_text[:max_size]

    # Fallback: try direct UTF-8 reading for all files (plain text and unknown formats)
    try:
        with open(filepath, encoding='utf-8', errors='ignore') as f:
            return f.read(max_size)
    except Exception:
        return None


def _text_size_limit(filepath):
    """Return the max file size to consider for text scanning, based on file type.

    Textract-extractable documents (pdf, docx, xlsx, ...) may be much larger than their text
    content, so they get MAX_DOCUMENT_FILE_SIZE; everything else uses MAX_MNEMONIC_FILE_SIZE.
    """
    ext = filepath.rsplit('.', 1)[-1].lower() if '.' in os.path.basename(filepath) else ''
    return MAX_DOCUMENT_FILE_SIZE if ext in TEXTRACT_SUPPORTED_EXTENSIONS else MAX_MNEMONIC_FILE_SIZE


def get_wallet_type_name(wallet_obj):
    """Extract wallet type name from a loaded wallet object."""
    return type(wallet_obj).__name__


# ---------------------------------------------------------------------------
# Path truncation helpers
# ---------------------------------------------------------------------------

def _truncate_path_component(name, max_len=8, aggressive=False):
    """Truncate a single path component (directory or filename).

    Normal mode: shows first 3 chars + '..' + last 3 chars when longer than max_len.
    Aggressive mode: shows first 1 char + '.' + last 1 char for all components > 1 char.
    Single-char names are returned unchanged in both modes.
    """
    if len(name) <= 1:
        return name
    if aggressive:
        return name[0] + '.' + name[-1]
    if len(name) <= max_len:
        return name
    return name[:3] + '..' + name[-3:]


def _format_path_for_display(path_str, max_length=60):
    """Format a path for display.

    Shows the full absolute path when it fits within max_length characters.
    If longer than max_length, applies per-component truncation (first 3 + '..' + last 3).
    If still longer than 60 chars after normal truncation, uses aggressive truncation
    (first 1 + '.' + last 1) applied uniformly to all path components for consistency.
    """
    # Resolve to absolute path
    abs_path = str(Path(path_str).resolve())

    if len(abs_path) <= max_length:
        return abs_path

    parts = Path(abs_path).parts
    truncated = [_truncate_path_component(p, aggressive=False) for p in parts]
    result = os.sep.join(truncated)

    # If still too long (>60 chars), use aggressive truncation on all components uniformly
    if len(result) > 60:
        truncated = [_truncate_path_component(p, aggressive=True) for p in parts]
        result = os.sep.join(truncated)

    return result


class _TimedResult:
    """Container for timed operation results."""
    def __init__(self):
        self.value = None
        self.exception = None


def _timed_operation(func, args=(), timeout=10):
    """Run a function with a timeout.

    Returns the result on success, raises the original exception if one occurred,
    or returns None if the operation timed out (or Ctrl+C was pressed). Suppresses
    stdout/stderr produced by the operation.

    The work runs in a daemon thread that we simply stop waiting on once the deadline
    passes. We deliberately do NOT join/shutdown-wait on timeout: some OS calls (stat or
    listdir on reparse points/junctions, dead network mounts, pagefile, System Volume
    Information, ...) block uninterruptibly, and waiting for them to finish would defeat
    the timeout and hang the whole scan. The daemon worker is abandoned (it cannot keep
    the process alive) and reaped at interpreter exit.

    Output is redirected on the *calling* thread rather than by having the worker swap the
    global sys.stdout: if the worker hung mid-call, a worker-side swap would leak the
    redirect and silence every subsequent print.
    """
    import io
    import time
    from contextlib import redirect_stdout, redirect_stderr
    tr = _TimedResult()

    def target():
        try:
            tr.value = func(*args)
        except BaseException as e:
            tr.exception = e

    worker = threading.Thread(target=target, daemon=True)
    sink = io.StringIO()
    with redirect_stdout(sink), redirect_stderr(sink):
        worker.start()
        deadline = time.monotonic() + timeout
        while True:
            if _should_stop.is_set():
                return None
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None  # timed out: abandon the daemon worker rather than wait on it
            # Poll in short intervals so Ctrl+C stays responsive.
            worker.join(timeout=min(remaining, 0.5))
            if not worker.is_alive():
                break

    if tr.exception is not None:
        raise tr.exception
    return tr.value


# ---------------------------------------------------------------------------
# Progress indicator
# ---------------------------------------------------------------------------

def _print_progress(current, total=None, filepath=""):
    """Print a single-line progress indicator with a spinning cursor.

    Updates in-place by using carriage return to overwrite the line.
    Uses ASCII-safe characters for Windows console compatibility.
    Displays full absolute path when <= 60 chars, otherwise truncates components.
    """
    spinners = ['|', '/', '-', '\\']
    spinner_idx = current % 4
    spinner = spinners[spinner_idx]

    display_path = _format_path_for_display(filepath)

    if total and total > 0:
        pct = min(int(current / total * 100), 100)
        bar_len = 20
        filled = int(bar_len * current / total)
        bar = '#' * filled + '-' * (bar_len - filled)
        line = "\r[{}] Scanning: {}% [{}] {}/{}  Dir: {}".format(
            spinner, pct, bar, current, total, display_path)
    else:
        line = "\r[{}] Scanning: {} files checked  Dir: {}".format(
            spinner, current, display_path)

    # Pad to clear previous line content
    max_len = 120
    if len(line) < max_len:
        line += ' ' * (max_len - len(line))

    sys.stdout.write(line)
    sys.stdout.flush()


def _clear_progress_line():
    """Clear the progress indicator line."""
    sys.stdout.write("\r" + " " * 120 + "\r")
    sys.stdout.flush()


def _make_discovery_reporter(interval=0.2):
    """Return a progress_cb for _collect_wallet_candidates that shows the directory currently
    being walked, throttled to at most one update per `interval` seconds.

    Because it updates on a time interval (not per-candidate) and prints the current path, the
    discovery phase stays visibly alive even through large directory trees that yield no
    candidates — and it reveals exactly which path a slow or stuck walk is on.
    """
    import time
    spinners = ['|', '/', '-', '\\']
    state = {'last': 0.0, 'count': 0}

    def report(dir_path):
        state['count'] += 1
        now = time.monotonic()
        if now - state['last'] < interval:
            return
        state['last'] = now
        spinner = spinners[state['count'] % 4]
        display_path = _format_path_for_display(dir_path)
        line = "\r[{}] Discovering... {} dirs  Dir: {}".format(spinner, state['count'], display_path)
        max_len = 120
        if len(line) < max_len:
            line += ' ' * (max_len - len(line))
        sys.stdout.write(line[:max_len])
        sys.stdout.flush()

    return report


# ---------------------------------------------------------------------------
# Exclusion list helpers
# ---------------------------------------------------------------------------

def load_exclusions():
    """Load path-substring exclusions from the bundled walletfinder-exclusionlist.txt.

    Returns a list of normalized (forward-slash) substrings. Blank lines and lines starting
    with '#' are ignored. Missing file -> empty list. Each entry is matched against a scanned
    file's path *relative to the scan root* (see _is_excluded), so the entries (repo-relative
    paths like 'btcrecover/test/') only skip the repository's own files when the repo is scanned
    and won't accidentally exclude a user's unrelated folders.
    """
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), EXCLUSIONLIST_FILENAME)
    exclusions = []
    try:
        with open(path, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                exclusions.append(line.replace('\\', '/'))
    except OSError:
        pass
    return exclusions


def _relative_norm(path_str, root):
    """Return path_str relative to root, normalized to forward slashes."""
    try:
        rel = os.path.relpath(str(path_str), str(root))
    except ValueError:  # e.g. different drives on Windows
        rel = str(path_str)
    return rel.replace('\\', '/')


def _is_excluded(path_str, root, exclusions):
    """True if path_str (relative to root) contains any exclusion substring."""
    if not exclusions:
        return False
    rel = _relative_norm(path_str, root)
    return any(ex in rel for ex in exclusions)


def walk_directory(folder, max_depth, current_depth=0, exclusions=None, root=None):
    """Walk directory tree with depth limiting and exclusion filtering.

    Yields each file path (as a string). Entries whose path relative to `root` matches an
    entry in `exclusions` are skipped (directories are not descended into), which is how the
    repository's own test wallets and example files are excluded from a `--folder .` scan.
    """
    folder = Path(folder)
    if root is None:
        root = folder
    if not folder.is_dir():
        return

    try:
        entries = sorted(folder.iterdir())
    except (PermissionError, FileNotFoundError, OSError):
        return

    for entry in entries:
        try:
            is_dir = entry.is_dir()
        except OSError:
            continue
        if _is_excluded(entry, root, exclusions):
            continue
        if is_dir:
            if entry.name.startswith('.') and entry.name != '.':
                continue
            if entry.name in EXCLUDED_DIRS:
                continue
            if max_depth is not None and current_depth >= max_depth:
                continue
            yield from walk_directory(entry, max_depth, current_depth + 1, exclusions, root)
        elif entry.is_file():
            yield str(entry)


# Optional btcrpass modules that certain wallet FILE types need in order to load, mapped to a
# human description and the pip command that provides them. Used by _announce_wallet_scan().
_WALLET_OPTIONAL_MODULES = [
    ('module_eth_keyfile_available', 'Ethereum / imToken keystore wallets', 'pip3 install eth-keyfile'),
    ('sjcl_available', 'BitGo wallets', 'pip3 install sjcl'),
    ('nacl_available', 'Toast wallets', 'pip3 install PyNaCl'),
    ('module_leveldb_available', 'MetaMask LevelDB vault folders',
     'bundled leveldb support unavailable - reinstall BTCRecover'),
]


def _announce_wallet_scan():
    """Print the wallet file types that will be checked and warn about any missing optional
    modules that would stop specific wallet types from loading."""
    import btcrecover.btcrpass as btcrpass
    names = [w.__name__ for w in getattr(btcrpass, 'wallet_types', [])]

    print("Wallet file types checked ({}):".format(len(names)))
    line = "  "
    for i, name in enumerate(names):
        piece = name + (", " if i < len(names) - 1 else "")
        if len(line) + len(piece) > 100:
            print(line)
            line = "  "
        line += piece
    if line.strip():
        print(line)

    warnings = [(desc, hint) for flag, desc, hint in _WALLET_OPTIONAL_MODULES
                if not getattr(btcrpass, flag, True)]
    if warnings:
        print()
        for desc, hint in warnings:
            print("[WARNING] Module missing: {} may not be detected/loaded ({}).".format(desc, hint))
    print()


def _detect_wallet_file(filepath, debug=False):
    """Attempt to load a single file as a wallet using btcrecover's load_wallet().

    Returns a result dict (path/type/confidence, plus reason when debug or unencrypted) if the
    file is a recognised wallet, otherwise None. Runs with a 10-second timeout and swallows
    the load errors raised for non-wallet files.
    """
    try:
        wallet_obj = _timed_operation(load_wallet, (filepath,), timeout=10)
        if wallet_obj is not None:
            result = {
                'path': filepath,
                'type': get_wallet_type_name(wallet_obj),
                'confidence': getattr(wallet_obj, 'detection_confidence', 'definite'),
            }
            if debug:
                result['reason'] = getattr(wallet_obj, 'detection_reason', None)
            return result
    except ValueError as e:
        error_msg = str(e).lower()
        if "not encrypted" in error_msg or "unencrypted" in error_msg:
            return {
                'path': filepath,
                'type': 'Unencrypted',
                'confidence': 'definite',
                'reason': 'Wallet is not encrypted (contains exposed private keys)',
            }
    except (Exception, SystemExit):
        pass
    return None


def _looks_like_wallet_directory(dir_path):
    """Quick pre-filter: does this directory look like it could be a wallet?

    MetaMask LevelDB vaults contain specific marker files (CURRENT, OPTIONS, LOCK, MANIFEST-*,
    *.log). This check is very fast and avoids calling the expensive load_wallet on every
    ordinary directory. Returns True if the directory contains indicators of being a wallet.

    Wrapped with a short timeout so that problematic directories (e.g. Windows system folders)
    do not block the scan indefinitely.
    """
    try:
        result = _timed_operation(_check_wallet_dir_contents, (dir_path,), timeout=5)
        return result if result is not None else False
    except Exception:
        return False


def _check_wallet_dir_contents(dir_path):
    """Inner check for wallet directory markers (called inside a timeout wrapper)."""
    try:
        names = {e.name for e in dir_path.iterdir()}
    except (PermissionError, FileNotFoundError, OSError):
        return False

    # LevelDB marker files indicate a MetaMask vault
    leveldb_markers = {'CURRENT', 'OPTIONS', 'LOCK'}
    has_log = any(n.endswith('.log') or n.startswith('MANIFEST-') for n in names)
    return (names & leveldb_markers) or has_log


def _collect_wallet_candidates(folder, depth, exclusions=None, progress_cb=None):
    """Yield wallet scan candidates as they are discovered: both files and directories.

    This is a generator so callers can display progress and start scanning as the walk
    proceeds, instead of blocking until the entire tree has been enumerated (which, on a
    drive root like ``C:\\``, would otherwise show nothing for a very long time).

    Directories are tested because some wallets (e.g. MetaMask LevelDB vaults) are folders.
    However, only directories that pass a quick pre-filter (_looks_like_wallet_directory) are
    yielded as candidates to avoid wasting time on ordinary directories.
    Files are filtered by MAX_WALLET_FILE_SIZE.
    Yields (path_string, is_directory) tuples.

    ``progress_cb``, if given, is called with the string path of each directory as it is
    entered — including directories that yield no candidates — so callers can show a live
    indicator (and which path a slow/stuck walk is on) during long silent stretches.
    """
    root = Path(folder)
    max_depth = depth

    def walk(dir_path, current_depth):
        if _should_stop.is_set():
            return
        if progress_cb is not None:
            progress_cb(str(dir_path))
        if not dir_path.is_dir():
            return
        try:
            entries = sorted(dir_path.iterdir())
        except (PermissionError, FileNotFoundError, OSError):
            return

        for entry in entries:
            if _should_stop.is_set():
                return
            try:
                is_dir = entry.is_dir()
            except OSError:
                continue
            if _is_excluded(entry, root, exclusions):
                continue
            if is_dir:
                # Only test directories that look like wallets (quick pre-filter)
                if _looks_like_wallet_directory(entry):
                    yield (str(entry), True)
                # Recurse into subdirectories unless depth limit reached
                if not entry.name.startswith('.') and entry.name not in EXCLUDED_DIRS:
                    if max_depth is None or current_depth < max_depth:
                        yield from walk(entry, current_depth + 1)
            else:
                # File candidate - check size
                try:
                    fsize = os.path.getsize(str(entry))
                    if fsize <= MAX_WALLET_FILE_SIZE:
                        yield (str(entry), False)
                except OSError:
                    pass

    yield from walk(root, 0)


def scan_wallet_mode(folder, depth, debug=False, exclusions=None, statusbar=True):
    """Scan directory for wallet files using btcrecover's load_wallet().

    Returns a list of dicts with keys: path, type, confidence, (and reason if debug).

    Scans both files and directories as potential wallets. Directories are tested because
    some wallets (e.g. MetaMask LevelDB vaults) are folders rather than single files.

    When statusbar is True (default), uses a two-pass approach: first counts eligible candidates,
    then scans them with a progress bar. When statusbar is False, scans immediately without
    the initial discovery pass. Each candidate operation has a 10-second timeout.
    """
    results = []
    files_scanned = 0

    _announce_wallet_scan()

    if statusbar:
        # First pass: collect all candidates (files + directories) for progress bar.
        # The reporter shows the directory currently being walked so this phase stays
        # visibly alive even on huge trees (e.g. a drive root) that take a while to enumerate.
        total_candidates = 0
        all_candidates = []
        report = _make_discovery_reporter()
        for candidate_path, is_dir in _collect_wallet_candidates(folder, depth, exclusions,
                                                                  progress_cb=report):
            if _should_stop.is_set():
                break
            all_candidates.append((candidate_path, is_dir))
            total_candidates += 1
        _clear_progress_line()

        # Second pass: scan candidates with progress indicator (with timeout)
        for i, (candidate_path, is_dir) in enumerate(all_candidates):
            if _should_stop.is_set():
                break
            files_scanned += 1

            _print_progress(files_scanned, total_candidates, candidate_path)

            result = _detect_wallet_file(candidate_path, debug=debug)
            if result is not None:
                results.append(result)

        # Clear the progress line and print a newline
        _clear_progress_line()
    else:
        # No statusbar: scan candidates directly without counting first. The reporter keeps
        # the display alive while the walk traverses directories that yield no candidates.
        spinners = ['|', '/', '-', '\\']
        report = _make_discovery_reporter()
        for candidate_path, is_dir in _collect_wallet_candidates(folder, depth, exclusions,
                                                                 progress_cb=report):
            if _should_stop.is_set():
                break

            files_scanned += 1

            # Show current candidate being scanned (single-line updating display with absolute path)
            display_path = _format_path_for_display(candidate_path)
            spinner_idx = files_scanned % 4
            label = "dir" if is_dir else "file"
            line = "\r[{}] Scanning: {} {}s  Path: {}".format(spinners[spinner_idx], files_scanned, label, display_path)
            max_len = 120
            if len(line) < max_len:
                line += ' ' * (max_len - len(line))
            sys.stdout.write(line)
            sys.stdout.flush()

            result = _detect_wallet_file(candidate_path, debug=debug)
            if result is not None:
                results.append(result)

        # Clear the scanning line
        _clear_progress_line()

    if _should_stop.is_set():
        print("\nInterrupted by user.")

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

# BIP38 encrypted private keys: "6P" + 56 base58 chars = 58 total
BIP38_PATTERN = re.compile(
    rf'(?<![A-Za-z0-9])6P{B58}{{56}}(?![A-Za-z0-9])',
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


_B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}


def _b58check_valid(s):
    """Return True if s is a valid Base58Check string (trailing 4-byte double-SHA256 checksum).

    WIF, BIP38, and BIP32 extended keys are all Base58Check-encoded, so this rejects random
    base58-looking strings (e.g. despaced prose) that merely happen to match a key's length and
    alphabet, without which key detection produces frequent false positives.
    """
    num = 0
    for ch in s:
        v = _B58_INDEX.get(ch)
        if v is None:
            return False
        num = num * 58 + v
    decoded = num.to_bytes((num.bit_length() + 7) // 8, 'big') if num else b''
    decoded = b'\x00' * (len(s) - len(s.lstrip('1'))) + decoded  # restore leading zero bytes
    if len(decoded) < 5:
        return False
    data, checksum = decoded[:-4], decoded[-4:]
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4] == checksum


def scan_private_keys(content):
    """Scan extracted text content for private keys.

    Returns a dict with keys: raw_wif, bip38, xprv, xpub.
    Each value is a list of dicts with 'key' and 'network' fields.
    Candidates that match a key pattern but fail Base58Check validation are discarded.
    """
    findings = {
        'raw_wif': [],
        'bip38': [],
        'xprv': [],
        'xpub': [],
    }

    for match in RAW_WIF_PATTERN.finditer(content):
        key = match.group(0)
        if _b58check_valid(key):
            findings['raw_wif'].append({
                'key': key,
                'network': _classify_wif(key),
            })

    for match in BIP38_PATTERN.finditer(content):
        key = match.group(0)
        if _b58check_valid(key):
            findings['bip38'].append({
                'key': key,
                'network': 'BIP38 encrypted',
            })

    for match in BIP32_XPRV_PATTERN.finditer(content):
        key = match.group(0)
        if _b58check_valid(key):
            findings['xprv'].append({
                'key': key,
                'network': _classify_xprv(key),
            })

    for match in BIP32_XPUB_PATTERN.finditer(content):
        key = match.group(0)
        if _b58check_valid(key):
            findings['xpub'].append({
                'key': key,
                'network': _classify_xpub(key),
            })

    return findings


def scan_private_keys_all(content):
    """Scan for private keys, catching keys broken by whitespace (spaces, tabs, or newlines).

    Runs scan_private_keys() on the content as-is and again on transformed copies:
      1. Intra-line whitespace only removed (spaces/tabs) - preserves line boundaries
      2. Newlines replaced with spaces + adjacent base58 tokens joined - recovers keys split
         across PDF lines while Base58Check validation rejects false positives
    Results are unioned (deduplicated per category by key string). The Base58Check validation
    rejects random base58-looking strings, so these transformations are safe for key detection.
    """
    findings = scan_private_keys(content)

    def _merge_extra(extra):
        for category in findings:
            seen = {entry['key'] for entry in findings[category]}
            for entry in extra[category]:
                if entry['key'] not in seen:
                    findings[category].append(entry)
                    seen.add(entry['key'])

    # Remove intra-line whitespace (spaces/tabs) but preserve newlines as boundaries.
    despaced = re.sub(r'[^\S\r\n]+', '', content)
    if despaced != content:
        _merge_extra(scan_private_keys(despaced))

    # Replace all line breaks (CRLF, CR, LF) with spaces to recover keys split across PDF lines.
    newlines_to_spaces = re.sub(r'\r\n|\r|\n', ' ', content)

    # Extract base58 tokens from the newline-replaced text and try joining consecutive pairs.
    # This recovers keys that were split by PDF line-wrapping (e.g. a BIP38 key broken into two
    # lines). We join adjacent base58 tokens in a sliding window so the address on one line
    # doesn't get merged with the key on the next — only consecutive pairs are joined and scanned.
    _b58_long = r'[1-9A-HJ-NP-Za-km-z]{4,}'  # base58 token of at least 4 chars
    tokens = re.findall(_b58_long, newlines_to_spaces)
    if len(tokens) >= 2:
        # Build all consecutive pair/triplet/quadruplet joins (covers keys split into up to 4 parts)
        joined_strings = []
        for window in (2, 3, 4):
            for i in range(len(tokens) - window + 1):
                chunk = ''.join(tokens[i:i+window])
                if len(chunk) >= 50:  # only scan reasonably long strings (keys are ~50-111 chars)
                    joined_strings.append(chunk)
        if joined_strings:
            _merge_extra(scan_private_keys('\n'.join(joined_strings)))

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

    List-marker tokens (pure numbers like "1", "12)" and pure-punctuation bullets that clean
    to an empty string) are treated as non-breaking separators, so a seed recorded as a
    numbered or bulleted list (e.g. "1. drift  2. speed  3. come ...") is still detected as a
    single sequential run. Only the actual wordlist words count toward the run length; a valid
    seed length is still confirmed by checksum validation downstream.

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
        elif clean.isdigit() or clean == '':
            # Numbered/bulleted list markers don't break an otherwise-consecutive run.
            continue
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


def _announce_text_scan(wordlist_sets):
    """Print the loaded-wordlists banner and, when applicable, the textract warning."""
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


def _scan_text_file(filepath, fsize, wordlist_sets, wordlist_ordered, min_seq, min_scat):
    """Scan a single file's text for mnemonic words and private keys.

    Returns {'path', 'size', 'findings'} when the file's text could be read (findings may be an
    empty list), or None when it could not be read. Callers count a readable file as "scanned"
    and only report it when findings is non-empty. Sequential matches include a checksum_valid
    flag when validated.
    """
    content = read_file_with_textract(filepath, MAX_MNEMONIC_FILE_SIZE)
    if content is None:
        return None

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

    # Private key detection (also catches keys split across whitespace/line-wraps)
    key_findings = scan_private_keys_all(content)
    total_keys_found = (len(key_findings['raw_wif']) + len(key_findings['bip38']) +
                       len(key_findings['xprv']) + len(key_findings['xpub']))

    if total_keys_found > 0:
        key_type_findings = []
        for entry in (key_findings['raw_wif'] + key_findings['bip38'] +
                      key_findings['xprv'] + key_findings['xpub']):
            key_type_findings.append({
                'key': entry['key'],
                'network': entry['network'],
                'type': 'private_key',
            })
        findings.append({
            'keys': key_type_findings,
            'total_keys': total_keys_found,
            'type': 'private_key',
        })

    return {'path': filepath, 'size': fsize, 'findings': findings}


def scan_text_mode(folder, depth, min_seq, min_scat, debug=False, exclusions=None):
    """Scan directory for files containing mnemonic words or private keys.

    Returns a list of dicts with keys: path, size, findings.
    Each finding has: wordlist/ key_type, sequential/scattered_count/keys, type ('mnemonic' or 'private_key').
    Sequential matches include checksum_valid flag when validated.
    """
    results = []
    files_scanned = 0
    wordlist_sets, wordlist_ordered = load_mnemonic_wordlists()

    print("Scanning for mnemonic words and private keys in: {}".format(folder))
    _announce_text_scan(wordlist_sets)

    for filepath in walk_directory(Path(folder), depth, exclusions=exclusions):
        try:
            fsize = os.path.getsize(filepath)
        except OSError:
            continue

        if fsize > _text_size_limit(filepath):
            continue

        res = _scan_text_file(filepath, fsize, wordlist_sets, wordlist_ordered, min_seq, min_scat)
        if res is None:
            continue
        files_scanned += 1
        if res['findings']:
            results.append(res)

    return results, files_scanned


def scan_combined(folder, depth, run_wallet, run_text, debug=False,
                  exclusions=None, statusbar=True, min_seq=12, min_scat=12):
    """Scan a directory in a single walk, running wallet-file detection and/or text scanning.

    Walks the tree once; each file is read at most once and dispatched to whichever detectors
    are enabled, so running both modes no longer traverses (or reads) the directory twice.
    A file is scanned for wallets when its size is within MAX_WALLET_FILE_SIZE and for text when
    within MAX_MNEMONIC_FILE_SIZE, so the two modes keep their independent size limits.

    Returns a 4-tuple: (wallet_results, wallet_files_scanned, text_results, text_files_scanned).
    """
    wallet_results = []
    text_results = []
    wallet_files_scanned = 0
    text_files_scanned = 0

    if run_wallet:
        _announce_wallet_scan()

    wordlist_sets = wordlist_ordered = None
    if run_text:
        wordlist_sets, wordlist_ordered = load_mnemonic_wordlists()
        _announce_text_scan(wordlist_sets)

    def process(filepath, size, is_dir=False):
        nonlocal wallet_files_scanned, text_files_scanned
        # Wallet detection: run on files within size limit AND on directories (MetaMask LevelDB vaults)
        if run_wallet:
            if is_dir or (size is not None and size <= MAX_WALLET_FILE_SIZE):
                wallet_files_scanned += 1
                result = _detect_wallet_file(filepath, debug=debug)
                if result is not None:
                    wallet_results.append(result)
        # Text scanning: only on files (can't scan directory text)
        if run_text and not is_dir and size is not None and size <= _text_size_limit(filepath):
            res = _scan_text_file(filepath, size, wordlist_sets, wordlist_ordered, min_seq, min_scat)
            if res is not None:
                text_files_scanned += 1
                if res['findings']:
                    text_results.append(res)

    def candidate_eligible(path_str, size, is_dir):
        """Check if a candidate should be included in the scan."""
        if is_dir:
            return run_wallet  # directories only for wallet detection
        if size is None:
            return False
        if run_wallet and size <= MAX_WALLET_FILE_SIZE:
            return True
        if run_text and size <= _text_size_limit(path_str):
            return True
        return False

    spinners = ['|', '/', '-', '\\']

    # Collect all candidates using _collect_wallet_candidates (files + directories)
    all_candidates = []  # list of (path_string, size_or_None, is_dir)

    if statusbar:
        # Discovery pass: collect files and directories. The reporter shows the directory
        # currently being walked so this phase stays visibly alive on huge trees.
        report = _make_discovery_reporter()
        for cand_path, is_dir in _collect_wallet_candidates(folder, depth, exclusions=exclusions,
                                                            progress_cb=report):
            if _should_stop.is_set():
                break
            if is_dir:
                all_candidates.append((cand_path, None, True))
            else:
                file_size = _timed_operation(os.path.getsize, (cand_path,), timeout=10)
                if candidate_eligible(cand_path, file_size, False):
                    all_candidates.append((cand_path, file_size, False))
        _clear_progress_line()

        total_candidates = len(all_candidates)
        for i, (cand_path, size, is_dir) in enumerate(all_candidates):
            if _should_stop.is_set():
                break
            _print_progress(i + 1, total_candidates, cand_path)
            process(cand_path, size, is_dir)
        _clear_progress_line()
    else:
        # No statusbar: scan directly without the discovery pass. The reporter keeps the
        # display alive while the walk traverses directories that yield no candidates.
        count = 0
        report = _make_discovery_reporter()
        for cand_path, is_dir in _collect_wallet_candidates(folder, depth, exclusions=exclusions,
                                                            progress_cb=report):
            if _should_stop.is_set():
                break
            if is_dir:
                count += 1
                display_path = _format_path_for_display(cand_path)
                spinner_idx = count % 4
                line = "\r[{}] Scanning: {} items  Dir: {}".format(spinners[spinner_idx], count, display_path)
                max_len = 120
                if len(line) < max_len:
                    line += ' ' * (max_len - len(line))
                sys.stdout.write(line)
                sys.stdout.flush()
                process(cand_path, None, True)
            else:
                file_size = _timed_operation(os.path.getsize, (cand_path,), timeout=10)
                if not candidate_eligible(cand_path, file_size, False):
                    continue
                count += 1
                display_path = _format_path_for_display(cand_path)
                spinner_idx = count % 4
                line = "\r[{}] Scanning: {} items  Dir: {}".format(spinners[spinner_idx], count, display_path)
                max_len = 120
                if len(line) < max_len:
                    line += ' ' * (max_len - len(line))
                sys.stdout.write(line)
                sys.stdout.flush()
                process(cand_path, file_size, False)
        _clear_progress_line()

    if _should_stop.is_set():
        print("\nInterrupted by user.")

    return wallet_results, wallet_files_scanned, text_results, text_files_scanned


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

    displayed = 0
    suppressed = 0
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
            # Only a scattered / non-checksum-valid signal: hidden unless --debug.
            suppressed += 1
            continue

        displayed += 1
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
    print("  Matches found: {}".format(displayed))
    if suppressed > 0:
        print("  Suppressed matches (viewable if running with --debug): {}".format(suppressed))


# ---------------------------------------------------------------------------
# Exclusion list maintenance
# ---------------------------------------------------------------------------


def _text_result_is_visible(result):
    """True if a text result would be shown in a normal (non-debug) scan.

    Mirrors the has_meaningful gate in print_text_results: a checksum-valid sequential match or
    any private key. Scattered-only findings do not count (they are suppressed from output).
    """
    for f in result['findings']:
        if f.get('type') == 'private_key':
            return True
        if f.get('type') == 'mnemonic':
            for match in f['sequential']:
                if len(match) > 3 and match[3]:
                    return True
    return False


def update_exclusion_list(statusbar=True):
    """Regenerate walletfinder-exclusionlist.txt from this BTCRecover repository.

    Scans the script's own directory (the repo) with no exclusions applied, collects every file
    a normal scan would surface (wallet matches + checksum-valid/private-key text matches), and
    writes their repo-relative paths so a later `--folder .` scan skips them. Existing entries
    are preserved (union); a file already covered by an existing entry (e.g. a directory prefix
    such as 'btcrecover/test/') is not re-added individually.
    """
    repo_root = os.path.dirname(os.path.abspath(__file__))
    existing = load_exclusions()

    print("Scanning repository to update {} ...".format(EXCLUSIONLIST_FILENAME))
    wallet_results, _, text_results, _ = scan_combined(
        repo_root, None, run_wallet=True, run_text=True, debug=False,
        exclusions=[], statusbar=statusbar)

    matched_paths = [r['path'] for r in wallet_results]
    matched_paths += [r['path'] for r in text_results if _text_result_is_visible(r)]

    new_entries = set()
    for p in matched_paths:
        rel = _relative_norm(p, repo_root)
        if any(ex in rel for ex in existing):  # already covered by an existing entry
            continue
        new_entries.add(rel)

    all_entries = sorted(set(existing) | new_entries)

    header = [
        "# walletfinder-exclusionlist.txt",
        "#",
        "# Path substrings that walletfinder.py skips while scanning. Each non-comment line is",
        "# matched against every scanned file's path *relative to the scan root*, so these",
        "# repo-relative entries only skip BTCRecover's own test wallets and example seed/key",
        "# files when the repository itself is scanned (e.g. `python walletfinder.py --folder .`);",
        "# they do not exclude unrelated folders elsewhere on your system.",
        "#",
        "# Regenerate after adding/removing files in the repo with:",
        "#     python walletfinder.py --update-exclusions",
        "# You may also add your own substrings by hand; they are preserved on regeneration.",
        "",
    ]
    out_path = os.path.join(repo_root, EXCLUSIONLIST_FILENAME)
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(header + all_entries + [""]))

    added = len(set(all_entries) - set(existing))
    print("Wrote {} exclusion entries to {} ({} new).".format(len(all_entries), out_path, added))


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------


def parse_arguments(args=None):
    parser = argparse.ArgumentParser(
        prog='walletfinder',
        description='Scan directories for supported wallet files, mnemonic phrases, and private keys.',
    )

    parser.add_argument(
        '--folder', metavar='DIR', default=None,
        help='Directory to scan recursively for wallet/mnemonic/key files.')

    mode_group = parser.add_argument_group('scan modes')
    mode_group.add_argument(
        '--skip-wallet-mode', action='store_true', default=False,
        help='Skip wallet-file scanning (btcrecover auto-detection). By default both wallet '
             'files and text are scanned.')
    mode_group.add_argument(
        '--skip-text-mode', action='store_true', default=False,
        help='Skip text/document scanning for mnemonic phrases and private keys (WIF, BIP38, '
             'BIP32 extended keys). By default both wallet files and text are scanned.')
    # Hidden backward-compatibility aliases for the previous "only run this mode" flags.
    mode_group.add_argument('--wallet-mode', action='store_true', dest='wallet_mode_compat',
                            default=False, help=argparse.SUPPRESS)
    mode_group.add_argument('--text-mode', action='store_true', dest='text_mode_compat',
                            default=False, help=argparse.SUPPRESS)
    mode_group.add_argument('--mnemonic-mode', action='store_true', dest='mnemonic_mode_compat',
                            default=False, help=argparse.SUPPRESS)

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

    scan_group = parser.add_argument_group('scan options')
    scan_group.add_argument(
        '--no-statusbar', action='store_true', default=False,
        help="Skip the file discovery phase and start scanning immediately without a progress bar.")
    scan_group.add_argument(
        '--update-exclusions', action='store_true', default=False,
        help="Regenerate {} by scanning this BTCRecover repository and recording every file that "
             "currently matches, so a later scan of the repo (e.g. --folder .) skips them. "
             "Ignores --folder.".format(EXCLUSIONLIST_FILENAME))

    args = parser.parse_args(args)

    # --update-exclusions is a maintenance action that scans the repo itself, so --folder
    # is not required in that mode.
    if not args.update_exclusions and not args.folder:
        parser.error("the following argument is required: --folder")

    # Both modes run by default; --skip-wallet-mode / --skip-text-mode turn one off.
    # Hidden compat aliases: --wallet-mode (= wallet only), --text-mode / --mnemonic-mode (= text only).
    skip_wallet = args.skip_wallet_mode or args.text_mode_compat or args.mnemonic_mode_compat
    skip_text = args.skip_text_mode or args.wallet_mode_compat
    args.run_wallet = not skip_wallet
    args.run_text = not skip_text

    if not args.run_wallet and not args.run_text:
        parser.error("nothing to scan: --skip-wallet-mode and --skip-text-mode cannot both be given")

    return args


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main():
    args = parse_arguments()

    if args.update_exclusions:
        update_exclusion_list(statusbar=not args.no_statusbar)
        return

    folder = os.path.abspath(args.folder)
    if not os.path.isdir(folder):
        print("Error: '{}' is not a valid directory.".format(folder))
        sys.exit(1)

    depth = args.depth
    statusbar = not args.no_statusbar
    # Skip the repository's own test wallets and example files when scanning the repo.
    exclusions = load_exclusions()

    # By default both wallet-file and text scanning run; --skip-wallet-mode / --skip-text-mode
    # turn one off (see parse_arguments).
    if args.run_wallet and args.run_text:
        # Single directory walk driving both detectors (each file is read at most once).
        wallet_results, wallet_n, text_results, text_n = scan_combined(
            folder, depth, run_wallet=True, run_text=True, debug=args.debug,
            exclusions=exclusions, statusbar=statusbar,
            min_seq=args.min_sequential, min_scat=args.min_scattered)
        print()
        print("=== Wallet file scan ===")
        print_wallet_results(wallet_results, wallet_n)
        print()
        print("=== Text / seed-phrase & private-key scan ===")
        print_text_results(text_results, text_n, debug=args.debug)
    elif args.run_wallet:
        print("=== Wallet file scan ===")
        results, files_scanned = scan_wallet_mode(folder, depth, debug=args.debug,
                                                  exclusions=exclusions,
                                                  statusbar=statusbar)
        print()
        print_wallet_results(results, files_scanned)
    else:  # args.run_text
        print("=== Text / seed-phrase & private-key scan ===")
        results, files_scanned = scan_text_mode(
            folder, depth, args.min_sequential, args.min_scattered,
            debug=args.debug, exclusions=exclusions)
        print()
        print_text_results(results, files_scanned, debug=args.debug)


if __name__ == "__main__":
    main()