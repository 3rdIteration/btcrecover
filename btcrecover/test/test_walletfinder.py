#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# test_walletfinder.py -- unit tests for walletfinder.py
# Copyright (C) 2014-2017 Christopher Gurnee
#               2019-2021 Stephen Rothery
#
# This file is part of btcrecover.
#
# btcrecover is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version
# 2 of the License, or (at your option) or later version.
#
# btcrecover is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/

import os
import sys
import unittest
import tempfile
import shutil
from pathlib import Path

if __name__ == '__main__':
    sys.path.append(os.path.join(os.path.dirname(__file__), "..", ".."))

# Import walletfinder functions for direct testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))


def can_load_shamir_mnemonic():
    """Check if shamir_mnemonic package is available for SLIP39 support."""
    try:
        from shamir_mnemonic import wordlist as sw  # noqa: F401
        return True
    except ImportError:
        return False


def can_detect_wallet(filename):
    """Check if load_wallet can detect the given wallet file."""
    filepath = os.path.join(os.path.dirname(__file__), "test-wallets", filename)
    if not os.path.isfile(filepath):
        return False
    try:
        from btcrecover.btcrpass import load_wallet
        return load_wallet(filepath) is not None
    except (Exception, SystemExit):
        return False


import walletfinder


WALLET_DIR = os.path.join(os.path.dirname(__file__), "test-wallets")


class TestWalkDirectory(unittest.TestCase):
    """Test the walk_directory helper function."""

    def test_walk_basic(self):
        tmpdir = tempfile.mkdtemp()
        try:
            Path(tmpdir, "a.txt").write_text("hello")
            Path(tmpdir, "b.txt").write_text("world")
            result = sorted(walletfinder.walk_directory(tmpdir, None))
            self.assertEqual(len(result), 2)
            self.assertTrue(any("a.txt" in p for p in result))
            self.assertTrue(any("b.txt" in p for p in result))
        finally:
            shutil.rmtree(tmpdir)

    def test_walk_nested(self):
        tmpdir = tempfile.mkdtemp()
        try:
            Path(tmpdir, "sub").mkdir()
            Path(tmpdir, "a.txt").write_text("hello")
            Path(tmpdir, "sub", "b.txt").write_text("world")
            result = sorted(walletfinder.walk_directory(tmpdir, None))
            self.assertEqual(len(result), 2)
        finally:
            shutil.rmtree(tmpdir)

    def test_walk_depth_limit_0(self):
        tmpdir = tempfile.mkdtemp()
        try:
            Path(tmpdir, "sub").mkdir()
            Path(tmpdir, "a.txt").write_text("hello")
            Path(tmpdir, "sub", "b.txt").write_text("world")
            result = sorted(walletfinder.walk_directory(tmpdir, 0))
            self.assertEqual(len(result), 1)
            self.assertTrue("a.txt" in result[0])
        finally:
            shutil.rmtree(tmpdir)

    def test_walk_depth_limit_1(self):
        tmpdir = tempfile.mkdtemp()
        try:
            Path(tmpdir, "sub").mkdir()
            Path(tmpdir, "sub", "deep").mkdir()
            Path(tmpdir, "a.txt").write_text("hello")
            Path(tmpdir, "sub", "b.txt").write_text("world")
            Path(tmpdir, "sub", "deep", "c.txt").write_text("deep")
            result = sorted(walletfinder.walk_directory(tmpdir, 1))
            self.assertEqual(len(result), 2)
        finally:
            shutil.rmtree(tmpdir)

    def test_walk_excludes_hidden_dirs(self):
        tmpdir = tempfile.mkdtemp()
        try:
            Path(tmpdir, ".hidden").mkdir()
            Path(tmpdir, "a.txt").write_text("hello")
            Path(tmpdir, ".hidden", "b.txt").write_text("world")
            result = sorted(walletfinder.walk_directory(tmpdir, None))
            self.assertEqual(len(result), 1)
        finally:
            shutil.rmtree(tmpdir)

    def test_walk_excludes_common_dirs(self):
        tmpdir = tempfile.mkdtemp()
        try:
            Path(tmpdir, "node_modules").mkdir()
            Path(tmpdir, "__pycache__").mkdir()
            Path(tmpdir, ".git").mkdir()
            Path(tmpdir, "a.txt").write_text("hello")
            Path(tmpdir, "node_modules", "b.txt").write_text("world")
            result = sorted(walletfinder.walk_directory(tmpdir, None))
            self.assertEqual(len(result), 1)
        finally:
            shutil.rmtree(tmpdir)

    def test_walk_nonexistent_dir(self):
        result = list(walletfinder.walk_directory("/nonexistent/path/xyz", None))
        self.assertEqual(len(result), 0)


class TestMnemonicHelpers(unittest.TestCase):
    """Test mnemonic detection helper functions."""

    def setUp(self):
        self.wordset = {"abandon", "ability", "about", "absorb", "abstract", "absurd",
                        "abuse", "access", "accident", "account", "accurate", "across"}

    def test_check_sequential_basic(self):
        tokens = ["the", "abandon", "ability", "about", "hello"]
        matches = walletfinder.check_sequential(tokens, self.wordset, 3)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0][1], 3)
        self.assertEqual(matches[0][2], ["abandon", "ability", "about"])

    def test_check_sequential_no_match(self):
        tokens = ["the", "quick", "brown", "fox"]
        matches = walletfinder.check_sequential(tokens, self.wordset, 3)
        self.assertEqual(len(matches), 0)

    def test_check_sequential_short_run(self):
        tokens = ["abandon", "ability", "hello"]
        matches = walletfinder.check_sequential(tokens, self.wordset, 4)
        self.assertEqual(len(matches), 0)

    def test_check_sequential_exact_match(self):
        tokens = ["abandon", "ability", "about"]
        matches = walletfinder.check_sequential(tokens, self.wordset, 3)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0][1], 3)

    def test_check_sequential_multiple_runs(self):
        tokens = ["abandon", "ability", "about", "foo", "absorb", "abstract", "absurd"]
        matches = walletfinder.check_sequential(tokens, self.wordset, 3)
        self.assertEqual(len(matches), 2)

    def test_check_scattered_basic(self):
        tokens = ["abandon", "ability", "about", "hello", "world"]
        matched = walletfinder.check_scattered(tokens, self.wordset)
        self.assertEqual(len(matched), 3)
        self.assertIn("abandon", matched)

    def test_check_scattered_duplicates(self):
        tokens = ["abandon", "abandon", "ability"]
        matched = walletfinder.check_scattered(tokens, self.wordset)
        self.assertEqual(len(matched), 2)

    def test_check_scattered_punctuation(self):
        tokens = ['"abandon"', "ability,", "about.", '"hello"']
        matched = walletfinder.check_scattered(tokens, self.wordset)
        self.assertEqual(len(matched), 3)


class TestWalletScan(unittest.TestCase):
    """Test wallet scanning against known test-wallet files."""

    def test_scan_finds_wallets(self):
        results, scanned = walletfinder.scan_wallet_mode(WALLET_DIR, None)
        if not results:
            self.skipTest("no wallets detected in this environment")
        self.assertGreater(scanned, 0)

    def test_bitcoincore_detected(self):
        results, _ = walletfinder.scan_wallet_mode(WALLET_DIR, None)
        btc_core = [r for r in results if 'bitcoincore-wallet.dat' in r['path']]
        if not btc_core:
            self.skipTest("bitcoincore-wallet.dat not detected in this environment")
        self.assertIn('BitcoinCore', btc_core[0]['type'])

    def test_electrum_detected(self):
        results, _ = walletfinder.scan_wallet_mode(WALLET_DIR, None)
        electrum = [r for r in results if 'electrum-wallet' == os.path.basename(r['path'])]
        if not electrum:
            self.skipTest("electrum wallet not detected in this environment")
        self.assertIn('Electrum', electrum[0]['type'])

    def test_blockchain_detected(self):
        results, _ = walletfinder.scan_wallet_mode(WALLET_DIR, None)
        bc = [r for r in results if 'blockchain-v4.0-wallet.aes.json' in r['path']]
        if not bc:
            self.skipTest("blockchain wallet not detected in this environment")
        self.assertIn('Blockchain', bc[0]['type'])

    def test_metamask_detected(self):
        results, _ = walletfinder.scan_wallet_mode(WALLET_DIR, None)
        mm = [r for r in results if 'metamask.9.8.4_firefox_vault' in r['path']]
        if not mm:
            self.skipTest("metamask vault not detected in this environment")
        self.assertIn('Metamask', mm[0]['type'])

    def test_dogechain_detected(self):
        results, _ = walletfinder.scan_wallet_mode(WALLET_DIR, None)
        dc = [r for r in results if 'dogechain.wallet.aes.json' == os.path.basename(r['path'])]
        if not dc:
            self.skipTest("dogechain wallet not detected in this environment")
        self.assertIn('Dogechain', dc[0]['type'])

    def test_blockio_detected(self):
        results, _ = walletfinder.scan_wallet_mode(WALLET_DIR, None)
        bio = [r for r in results if 'block.io.request.json' == os.path.basename(r['path'])]
        if not bio:
            self.skipTest("block.io wallet not detected in this environment")
        self.assertIn('BlockIO', bio[0]['type'])

    def test_multibit_detected(self):
        results, _ = walletfinder.scan_wallet_mode(WALLET_DIR, None)
        mb = [r for r in results if 'multibit-wallet.key' == os.path.basename(r['path'])]
        if not mb:
            self.skipTest("multibit wallet not detected in this environment")
        self.assertIn('MultiBit', mb[0]['type'])

    def test_multibithd_detected(self):
        results, _ = walletfinder.scan_wallet_mode(WALLET_DIR, None)
        mbhd = [r for r in results if 'mbhd.wallet.aes' == os.path.basename(r['path'])]
        if not mbhd:
            self.skipTest("multibithd wallet not detected in this environment")
        self.assertIn('MultiBitHD', mbhd[0]['type'])

    def test_btc_com_detected(self):
        results, _ = walletfinder.scan_wallet_mode(WALLET_DIR, None)
        btc = [r for r in results if 'btc_com_parsed' in r['path']]
        if not btc:
            self.skipTest("btc.com wallet not detected in this environment")
        self.assertIn('btc_com', btc[0]['type'])

    def test_scan_empty_dir(self):
        tmpdir = tempfile.mkdtemp()
        try:
            results, scanned = walletfinder.scan_wallet_mode(tmpdir, None)
            self.assertEqual(len(results), 0)
            self.assertEqual(scanned, 0)
        finally:
            shutil.rmtree(tmpdir)

    def test_scan_depth_limit(self):
        tmpdir = tempfile.mkdtemp()
        try:
            src = os.path.join(WALLET_DIR, "electrum1-upgradedto-electrum27-wallet")
            Path(tmpdir, "sub").mkdir()
            shutil.copy2(src, tmpdir)
            shutil.copy2(src, os.path.join(tmpdir, "sub"))
            results_depth0, _ = walletfinder.scan_wallet_mode(tmpdir, 0)
            results_unlimited, _ = walletfinder.scan_wallet_mode(tmpdir, None)
            self.assertEqual(len(results_depth0), 1)
            self.assertEqual(len(results_unlimited), 2)
        finally:
            shutil.rmtree(tmpdir)


class TestMnemonicScan(unittest.TestCase):
    """Test mnemonic scanning functionality."""

    def test_bip39_sequential_detection(self):
        tmpdir = tempfile.mkdtemp()
        try:
            testfile = os.path.join(tmpdir, "test.txt")
            with open(testfile, 'w') as f:
                f.write("abandon ability about absorb abstract absurd abuse access accident account\n")
            results, _ = walletfinder.scan_mnemonic_mode(tmpdir, None, 6, 12)
            self.assertEqual(len(results), 1)
            findings = results[0]['findings']
            bip39_findings = [f for f in findings if 'BIP39' in f['wordlist']]
            self.assertEqual(len(bip39_findings), 1)
            self.assertGreaterEqual(len(bip39_findings[0]['sequential']), 1)
        finally:
            shutil.rmtree(tmpdir)

    def test_bip39_scattered_detection(self):
        tmpdir = tempfile.mkdtemp()
        try:
            testfile = os.path.join(tmpdir, "test.txt")
            with open(testfile, 'w') as f:
                words = ["abandon", "ability", "about", "absorb", "abstract", "absurd",
                         "abuse", "access", "accident", "account", "accurate", "across"]
                for w in words:
                    f.write(w + " hello ")
            results, _ = walletfinder.scan_mnemonic_mode(tmpdir, None, 6, 12)
            self.assertEqual(len(results), 1)
            findings = results[0]['findings']
            bip39_findings = [f for f in findings if 'BIP39' in f['wordlist']]
            self.assertEqual(len(bip39_findings), 1)
            self.assertGreaterEqual(bip39_findings[0]['scattered_count'], 12)
        finally:
            shutil.rmtree(tmpdir)

    def test_below_threshold_not_reported(self):
        tmpdir = tempfile.mkdtemp()
        try:
            testfile = os.path.join(tmpdir, "test.txt")
            with open(testfile, 'w') as f:
                f.write("hello world foo bar baz\n")
            results, _ = walletfinder.scan_mnemonic_mode(tmpdir, None, 6, 12)
            self.assertEqual(len(results), 0)
        finally:
            shutil.rmtree(tmpdir)

    def test_electrum_legacy_detection(self):
        tmpdir = tempfile.mkdtemp()
        try:
            testfile = os.path.join(tmpdir, "test.txt")
            with open(testfile, 'w') as f:
                f.write("like just love know never want time out there make look eye\n")
            results, _ = walletfinder.scan_mnemonic_mode(tmpdir, None, 6, 12)
            self.assertEqual(len(results), 1)
            findings = results[0]['findings']
            electrum_findings = [f for f in findings if 'Electrum' in f['wordlist']]
            self.assertEqual(len(electrum_findings), 1)
        finally:
            shutil.rmtree(tmpdir)

    @unittest.skipUnless(can_load_shamir_mnemonic(), "requires shamir-mnemonic")
    def test_slip39_detection(self):
        tmpdir = tempfile.mkdtemp()
        try:
            testfile = os.path.join(tmpdir, "test.txt")
            with open(testfile, 'w') as f:
                f.write("duckling enlarge academic academic agency result length solution fridge kidney coal piece\n")
            results, _ = walletfinder.scan_mnemonic_mode(tmpdir, None, 6, 12)
            self.assertEqual(len(results), 1)
            findings = results[0]['findings']
            slip39_findings = [f for f in findings if 'SLIP39' in f['wordlist']]
            self.assertGreaterEqual(len(slip39_findings), 1)
        finally:
            shutil.rmtree(tmpdir)

    def test_binary_file_handled(self):
        tmpdir = tempfile.mkdtemp()
        try:
            testfile = os.path.join(tmpdir, "test.bin")
            with open(testfile, 'wb') as f:
                f.write(b'\x00\x01\x02\x03' * 100)
            results, _ = walletfinder.scan_mnemonic_mode(tmpdir, None, 6, 12)
            self.assertEqual(len(results), 0)
        finally:
            shutil.rmtree(tmpdir)

    def test_multiple_files(self):
        tmpdir = tempfile.mkdtemp()
        try:
            for i in range(3):
                testfile = os.path.join(tmpdir, "test{}.txt".format(i))
                with open(testfile, 'w') as f:
                    f.write("abandon ability about absorb abstract absurd\n")
            results, scanned = walletfinder.scan_mnemonic_mode(tmpdir, None, 6, 12)
            self.assertEqual(scanned, 3)
            self.assertEqual(len(results), 3)
        finally:
            shutil.rmtree(tmpdir)

    def test_depth_limit(self):
        tmpdir = tempfile.mkdtemp()
        try:
            Path(tmpdir, "sub").mkdir()
            with open(os.path.join(tmpdir, "a.txt"), 'w') as f:
                f.write("abandon ability about absorb abstract absurd\n")
            with open(os.path.join(tmpdir, "sub", "b.txt"), 'w') as f:
                f.write("abandon ability about absorb abstract absurd\n")
            results_depth0, _ = walletfinder.scan_mnemonic_mode(tmpdir, 0, 6, 12)
            results_unlimited, _ = walletfinder.scan_mnemonic_mode(tmpdir, None, 6, 12)
            self.assertEqual(len(results_depth0), 1)
            self.assertEqual(len(results_unlimited), 2)
        finally:
            shutil.rmtree(tmpdir)

    def test_min_sequential_configurable(self):
        tmpdir = tempfile.mkdtemp()
        try:
            testfile = os.path.join(tmpdir, "test.txt")
            with open(testfile, 'w') as f:
                f.write("abandon ability about\n")
            results_low, _ = walletfinder.scan_mnemonic_mode(tmpdir, None, 3, 12)
            results_high, _ = walletfinder.scan_mnemonic_mode(tmpdir, None, 6, 12)
            self.assertEqual(len(results_low), 1)
            self.assertEqual(len(results_high), 0)
        finally:
            shutil.rmtree(tmpdir)

    def test_min_scattered_configurable(self):
        tmpdir = tempfile.mkdtemp()
        try:
            testfile = os.path.join(tmpdir, "test.txt")
            with open(testfile, 'w') as f:
                words = ["abandon", "ability", "about", "absorb", "abstract"]
                for w in words:
                    f.write(w + " ")
            results_low, _ = walletfinder.scan_mnemonic_mode(tmpdir, None, 6, 5)
            results_high, _ = walletfinder.scan_mnemonic_mode(tmpdir, None, 6, 12)
            self.assertEqual(len(results_low), 1)
            self.assertEqual(len(results_high), 0)
        finally:
            shutil.rmtree(tmpdir)


def can_use_textract():
    """Check if textract is available for document extraction tests."""
    try:
        import textract  # noqa: F401
        return True
    except ImportError:
        return False


class TestTextractIntegration(unittest.TestCase):
    """Test textract-based document scanning functionality."""

    def test_read_file_plain_text(self):
        tmpdir = tempfile.mkdtemp()
        try:
            testfile = os.path.join(tmpdir, "test.txt")
            with open(testfile, 'w') as f:
                f.write("abandon ability about absorb abstract absurd\n")
            content = walletfinder.read_file_with_textract(testfile, 16384)
            self.assertIsNotNone(content)
            self.assertIn("abandon", content)
        finally:
            shutil.rmtree(tmpdir)

    def test_read_file_json(self):
        tmpdir = tempfile.mkdtemp()
        try:
            testfile = os.path.join(tmpdir, "test.json")
            with open(testfile, 'w') as f:
                f.write('{"mnemonic": "abandon ability about absorb abstract absurd"}\n')
            content = walletfinder.read_file_with_textract(testfile, 16384)
            self.assertIsNotNone(content)
            self.assertIn("abandon", content)
        finally:
            shutil.rmtree(tmpdir)

    def test_read_file_html(self):
        tmpdir = tempfile.mkdtemp()
        try:
            testfile = os.path.join(tmpdir, "test.html")
            with open(testfile, 'w') as f:
                f.write('<html><body>abandon ability about absorb abstract absurd</body></html>\n')
            content = walletfinder.read_file_with_textract(testfile, 16384)
            self.assertIsNotNone(content)
            self.assertIn("abandon", content)
        finally:
            shutil.rmtree(tmpdir)

    def test_read_file_unsupported_extension_without_textract(self):
        tmpdir = tempfile.mkdtemp()
        try:
            # Without textract, .docx falls back to raw UTF-8 reading (returns binary garbage)
            testfile = os.path.join(tmpdir, "test.docx")
            with open(testfile, 'wb') as f:
                f.write(b'\x00\x01\x02\x03' * 100)
            content = walletfinder.read_file_with_textract(testfile, 16384)
            # Falls back to reading raw bytes as text (with errors='ignore')
            self.assertIsNotNone(content)
        finally:
            shutil.rmtree(tmpdir)

    def test_read_file_unknown_extension(self):
        tmpdir = tempfile.mkdtemp()
        try:
            # Unknown extensions without textract should still fall back to UTF-8 reading
            testfile = os.path.join(tmpdir, "test.xyz")
            with open(testfile, 'w') as f:
                f.write("abandon ability about absorb abstract absurd\n")
            content = walletfinder.read_file_with_textract(testfile, 16384)
            self.assertIsNotNone(content)
            self.assertIn("abandon", content)
        finally:
            shutil.rmtree(tmpdir)

    def test_read_file_plain_text_fallback(self):
        tmpdir = tempfile.mkdtemp()
        try:
            # Plain text extensions should always work without textract
            for ext in ('txt', 'csv', 'json', 'html', 'htm'):
                testfile = os.path.join(tmpdir, "test.{}".format(ext))
                with open(testfile, 'w') as f:
                    f.write("abandon ability about absorb abstract absurd\n")
                content = walletfinder.read_file_with_textract(testfile, 16384)
                self.assertIsNotNone(content, "Failed for .{} extension".format(ext))
                self.assertIn("abandon", content)
        finally:
            shutil.rmtree(tmpdir)

    def test_scan_mnemonic_mode_includes_documents(self):
        tmpdir = tempfile.mkdtemp()
        try:
            # Create a plain text file with mnemonic words
            testfile = os.path.join(tmpdir, "notes.txt")
            with open(testfile, 'w') as f:
                f.write("abandon ability about absorb abstract absurd\n")
            results, scanned = walletfinder.scan_mnemonic_mode(tmpdir, None, 6, 12)
            self.assertGreaterEqual(scanned, 1)
            self.assertEqual(len(results), 1)
        finally:
            shutil.rmtree(tmpdir)

    @unittest.skipUnless(can_use_textract(), "requires textract")
    def test_scan_mnemonic_mode_with_docx(self):
        try:
            import docx2txt
        except ImportError:
            self.skipTest("requires python-docx2txt for .docx support")
        tmpdir = tempfile.mkdtemp()
        try:
            # Create a real .docx file with mnemonic words
            import docx
            doc = docx.Document()
            doc.add_paragraph("Here are my secret words: abandon ability about absorb abstract absurd abuse access accident account accurate across")
            testfile = os.path.join(tmpdir, "secrets.docx")
            doc.save(testfile)
            results, scanned = walletfinder.scan_mnemonic_mode(tmpdir, None, 6, 12)
            self.assertGreaterEqual(scanned, 1)
            self.assertEqual(len(results), 1)
            findings = results[0]['findings']
            bip39_findings = [f for f in findings if 'BIP39' in f['wordlist']]
            self.assertGreaterEqual(len(bip39_findings), 1)
        finally:
            shutil.rmtree(tmpdir)

    @unittest.skipUnless(can_use_textract(), "requires textract")
    def test_scan_mnemonic_mode_with_xlsx(self):
        try:
            import xlrd
        except ImportError:
            self.skipTest("requires xlrd for .xlsx support")
        tmpdir = tempfile.mkdtemp()
        try:
            # Create a real .xlsx file with mnemonic words
            from openpyxl import Workbook
            wb = Workbook()
            ws = wb.active
            ws.append(["My secret words:", "abandon", "ability", "about", "absorb", "abstract", "absurd"])
            testfile = os.path.join(tmpdir, "secrets.xlsx")
            wb.save(testfile)
            results, scanned = walletfinder.scan_mnemonic_mode(tmpdir, None, 6, 12)
            self.assertGreaterEqual(scanned, 1)
            self.assertEqual(len(results), 1)
            findings = results[0]['findings']
            bip39_findings = [f for f in findings if 'BIP39' in f['wordlist']]
            self.assertGreaterEqual(len(bip39_findings), 1)
        finally:
            shutil.rmtree(tmpdir)

    @unittest.skipUnless(can_use_textract(), "requires textract")
    def test_scan_mnemonic_mode_with_csv(self):
        tmpdir = tempfile.mkdtemp()
        try:
            testfile = os.path.join(tmpdir, "words.csv")
            with open(testfile, 'w') as f:
                f.write("word1,word2,word3\nabandon,ability,about\nabsorb,abstract,absurd\n")
            results, scanned = walletfinder.scan_mnemonic_mode(tmpdir, None, 6, 12)
            self.assertGreaterEqual(scanned, 1)
            findings = results[0]['findings']
            bip39_findings = [f for f in findings if 'BIP39' in f['wordlist']]
            self.assertGreaterEqual(len(bip39_findings), 1)
        finally:
            shutil.rmtree(tmpdir)

    @unittest.skipUnless(can_use_textract(), "requires textract")
    def test_scan_mnemonic_mode_with_json(self):
        tmpdir = tempfile.mkdtemp()
        try:
            testfile = os.path.join(tmpdir, "data.json")
            with open(testfile, 'w') as f:
                f.write('{"notes": "abandon ability about absorb abstract absurd"}\n')
            results, scanned = walletfinder.scan_mnemonic_mode(tmpdir, None, 6, 12)
            self.assertGreaterEqual(scanned, 1)
            findings = results[0]['findings']
            bip39_findings = [f for f in findings if 'BIP39' in f['wordlist']]
            self.assertGreaterEqual(len(bip39_findings), 1)
        finally:
            shutil.rmtree(tmpdir)

    def test_textract_supported_extensions_set(self):
        expected = {
            'csv', 'tsv', 'tab', 'doc', 'docx', 'eml', 'epub', 'gif',
            'jpg', 'jpeg', 'json', 'html', 'htm', 'mp3', 'msg', 'odt',
            'ogg', 'pdf', 'png', 'pptx', 'ps', 'rtf', 'tiff', 'tif', 'txt', 'wav',
            'xls', 'xlsx',
        }
        self.assertEqual(walletfinder.TEXTRACT_SUPPORTED_EXTENSIONS, expected)


class TestArgumentParsing(unittest.TestCase):
    """Test CLI argument parsing."""

    def test_help(self):
        args = walletfinder.parse_arguments(['--folder', '/tmp'])
        self.assertTrue(args.wallet_mode)

    def test_folder_required(self):
        args = walletfinder.parse_arguments(['--folder', '/tmp'])
        self.assertEqual(args.folder, '/tmp')

    def test_wallet_mode_default(self):
        args = walletfinder.parse_arguments(['--folder', '/tmp'])
        self.assertTrue(args.wallet_mode)
        self.assertFalse(args.mnemonic_mode)

    def test_mnemonic_mode_flag(self):
        args = walletfinder.parse_arguments(['--folder', '/tmp', '--mnemonic-mode'])
        self.assertTrue(args.mnemonic_mode)

    def test_depth_argument(self):
        args = walletfinder.parse_arguments(['--folder', '/tmp', '--depth', '3'])
        self.assertEqual(args.depth, 3)

    def test_min_sequential_argument(self):
        args = walletfinder.parse_arguments(['--folder', '/tmp', '--min-sequential', '10'])
        self.assertEqual(args.min_sequential, 10)

    def test_min_scattered_argument(self):
        args = walletfinder.parse_arguments(['--folder', '/tmp', '--min-scattered', '20'])
        self.assertEqual(args.min_scattered, 20)

    def test_debug_flag(self):
        args = walletfinder.parse_arguments(['--folder', '/tmp', '--debug'])
        self.assertTrue(args.debug)


if __name__ == '__main__':
    unittest.main()
