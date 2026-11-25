# cli.py -- command-line argument parser for seedrecover
# Copyright (C) 2014-2017 Christopher Gurnee
#               2019-2021 Stephen Rothery
#
# This file is part of btcrecover.
#
# btcrecover is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version
# 2 of the License, or (at your option) any later version.
#
# btcrecover is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/

"""CLI surface for the seed-recovery engine.

This module owns the :mod:`argparse` parser used by ``seedrecover.py`` /
``btcrseed.main()``. All parsing of the resulting arguments and the recovery
logic itself remain in :mod:`btcrecover.btcrseed._engine`.
"""

import argparse

from . import _engine


def build_parser():
    """Construct and return the fully-configured seedrecover ArgumentParser."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--json",        action="store_true",   help="print the final result as a single JSON object on stdout (human-readable output is redirected to stderr); intended for scripts and AI tools")
    parser.add_argument("--wallet",      metavar="FILE",        help="the wallet file")
    parser.add_argument("--wallet-type", metavar="TYPE",        help="if not using a wallet file, the wallet type")
    parser.add_argument("--mpk",         metavar="XPUB-OR-HEX", help="if not using a wallet file, the master public key (xpub, ypub or zpub)")
    parser.add_argument("--addrs",       metavar="ADDRESS",     nargs="+", help="if not using an mpk, address(es) in the wallet")
    parser.add_argument("--addressdb",   metavar="FILE", nargs="?", help="if not using addrs, use a full address database (default: %(const)s)", const=_engine.ADDRESSDB_DEF_FILENAME)
    parser.add_argument("--addr-limit",  type=int, metavar="COUNT", help="if using addrs or addressdb, the address generation limit")
    parser.add_argument("--addr-start-index",  type=int, metavar="COUNT", help="The index at which the addr-limit starts counting (Useful for wallets like Wasabi that may not start at zero)")
    parser.add_argument("--typos",       type=int, metavar="COUNT", help="the max number of mistakes to try (default: auto)")
    parser.add_argument("--big-typos",   type=int, metavar="COUNT", help="the max number of big (entirely different word) mistakes to try (default: auto or 0)")
    parser.add_argument("--min-typos",   type=int, metavar="COUNT", help="enforce a min # of mistakes per guess")
    parser.add_argument("--close-match",type=float,metavar="CUTOFF",help="try words which are less/more similar for each mistake (0.0 to 1.0, default: 0.65)")
    parser.add_argument("--passphrase",  action="store_true",       help="the mnemonic is augmented with a known passphrase (BIP39 or Electrum 2.x only)")
    parser.add_argument("--passphrase-arg",  metavar="PASSPHRASE", nargs="+", help="the mnemonic is augmented with a known passphrase, entered directly as an argument (BIP39 or Electrum 2.x only)")
    parser.add_argument("--passphrase-list", metavar="FILE", help="Path to a file containing a list of passphrases to test")
    parser.add_argument("--passphrase-prompt", action="store_true", help="prompt for the mnemonic passphrase via the terminal (default: via the GUI)")
    parser.add_argument("--mnemonic",  metavar="MNEMONIC",       help="Your best guess of the mnemonic (if not entered, you will be prompted)")
    parser.add_argument("--mnemonic-prompt",   action="store_true", help="prompt for the mnemonic guess via the terminal (default: via the GUI)")
    parser.add_argument("--mnemonic-length", type=int, metavar="WORD-COUNT", help="the length of the correct mnemonic (default: auto)")
    parser.add_argument("--language",    metavar="LANG-CODE",       help="the wordlist language to use (see wordlists/README.md, default: auto)")
    parser.add_argument("--bip32-path",  metavar="PATH", nargs="+",           help="path (e.g. m/0'/0/) excluding the final index. You can specify multiple derivation paths seperated by a space Eg: m/84'/0'/0'/0 m/84'/0'/1'/0 (default: BIP44,BIP49 & BIP84 account 0)")
    parser.add_argument("--substrate-path",  metavar="PATH", nargs="+",           help="Substrate path (eg: //hard/soft). You can specify multiple derivation paths by a space Eg: //hard /soft //hard/soft (default: No Path)")
    parser.add_argument("--slip39", action="store_true", help="recover a SLIP39 seed share")
    parser.add_argument("--share-length", type=int, metavar="WORD-COUNT", help="the length of the SLIP39 share (default: auto)")
    parser.add_argument("--checksinglexpubaddress", action="store_true", help="Check non-standard single address wallets (Like Atomic, MyBitcoinWallet, PT.BTC")
    parser.add_argument("--force-p2sh",  action="store_true",   help="Force checking of P2SH segwit addresses for all derivation paths (Required for devices like CoolWallet S if if you are using P2SH segwit accounts on a derivation path that doesn't start with m/49')")
    parser.add_argument("--force-p2tr",  action="store_true",   help="Force checking of P2TR (Taproot) addresses for all derivation paths (Required for wallets like Bitkeep/Bitget that put all accounts on  m/44')")
    parser.add_argument("--force-bip44", action="store_true",   help="Force checking of BIP44 legacy (P2PKH) addresses even if they don't match the supplied addresses")
    parser.add_argument("--force-bip84", action="store_true",   help="Force checking of BIP84 native SegWit (P2WPKH) addresses even if they don't match the supplied addresses")
    parser.add_argument("--disable-p2sh", action="store_true",  help="Disable checking of P2SH segwit addresses")
    parser.add_argument("--disable-p2tr", action="store_true",  help="Disable checking of P2TR (Taproot) addresses")
    parser.add_argument("--disable-bip44", action="store_true", help="Disable checking of BIP44 legacy (P2PKH) addresses")
    parser.add_argument("--disable-bip84", action="store_true", help="Disable checking of BIP84 native SegWit (P2WPKH) addresses")
    parser.add_argument("--pathlist",    metavar="FILE",        help="A list of derivation paths to be searched")
    parser.add_argument("--no-check-change-addresses", action="store_true",
                        help="Disable the default behaviour of also checking matching \"change\" (internal, /1) derivation paths alongside \"receive\" (external, /0) paths for UTXO-style wallets (BTC, LTC, BCH, DASH, DGB, DOGE, GRS, MONA, VTC, etc). Has no effect for account-model wallets such as ETH, XRP, SOL, etc.")
    parser.add_argument("--transform-wordswaps",   type=int, metavar="COUNT", help="Test swapping COUNT pairs of words within the mnemonic")
    parser.add_argument(
        "--transform-trezor-common-mistakes",
        type=int,
        metavar="COUNT",
        help=(
            "Test replacing up to COUNT mnemonic words using Trezor's "
            "commonly misspelled word list"
        ),
    )
    parser.add_argument("--skip",        type=int, metavar="COUNT", help="skip this many initial passwords for continuing an interrupted search")
    parser.add_argument("--threads", type=int, metavar="COUNT", help="number of worker threads (default: For CPU Processing, logical CPU cores, for GPU, physical CPU cores)")
    parser.add_argument("--worker",      metavar="ID#(ID#2, ID#3)/TOTAL#",   help="divide the workload between TOTAL# servers, where each has a different ID# between 1 and TOTAL# (You can optionally assign between 1 and TOTAL IDs of work to a server (eg: 1,2/3 will assign both slices 1 and 2 of the 3 to the server...)")
    parser.add_argument("--max-eta",     type=int,              help="max estimated runtime before refusing to even start (default: 168 hours, i.e. 1 week)")
    parser.add_argument("--no-eta",      action="store_true",   help="disable calculating the estimated time to completion")
    parser.add_argument("--no-dupchecks", "-d", action="count", default=0, help="disable duplicate guess checking to save memory; specify up to four times for additional effect")
    parser.add_argument("--no-progress", action="store_true",   help="disable the progress bar")
    parser.add_argument(
        "--pre-start-seconds",
        type=float,
        default=30.0,
        metavar="SECONDS",
        help="limit how long the pre-start benchmark runs for (default: %(default)s seconds); use 0 to skip it",
    )
    parser.add_argument(
        "--skip-pre-start",
        action="store_true",
        help="skip the pre-start benchmark; equivalent to --pre-start-seconds 0",
    )
    parser.add_argument("--no-pause",    action="store_true",   help="never pause before exiting (default: auto)")
    parser.add_argument("--no-gui", action="store_true", help="Force disable the gui elements")
    parser.add_argument(
        "--beep-on-find",
        action="store_true",
        help="play a two-tone alert roughly every ten seconds when a seed is found",
    )
    parser.add_argument(
        "--beep-on-find-pcspeaker",
        action="store_true",
        help="force the alert to use the internal PC speaker when a seed is found",
    )
    parser.add_argument("--performance", action="store_true",   help="run a continuous performance test (Ctrl-C to exit)")
    parser.add_argument("--performance-duration", type=int, default=None, metavar="SECONDS", help="automatically stop a --performance test after this many seconds and report results")
    parser.add_argument("--btcr-args",   action="store_true",   help=argparse.SUPPRESS)
    parser.add_argument("--version","-v",action="store_true",   help="show full version information and exit")
    parser.add_argument("--disablesecuritywarnings", "--dsw", action="store_true", help="Disable Security Warning Messages")
    parser.add_argument("--tokenlist", metavar="FILE", help="The list of BIP39 words to be searched, formatted as a tokenlist")
    parser.add_argument("--keep-tokens-order", action="store_true",
                        help="try tokens in the order in which they are listed in the file, without trying their permutations")
    parser.add_argument("--max-tokens", type=int, help="The max number of tokens use to create potential seeds from the tokenlist")
    parser.add_argument("--min-tokens", type=int, help="The minimum number of tokens use to create potential seeds from the tokenlist")
    parser.add_argument("--seedlist", metavar="FILE", nargs="?", const="-",
                        help="A list of seed phrases to test (exactly one per line) from this file or from stdin, if used in conjunction with --multi-file-seedlist, this is the name of the first file to load")
    parser.add_argument("--multi-file-seedlist",action="store_true",   help="Enables the loading of a seedlist file split over mulitple files with the suffix _XXXX.txt")

    parser.add_argument("--listseeds", action="store_true",
                               help="Just list all seed phrase combinations to test and exit")
    parser.add_argument("--savevalidseeds", metavar="FILE",
                               help="Only list valid seed combinations, then exit. (Similar to --listseeds, but only lists valid BIP39/Electrum seeds)")
    parser.add_argument("--savevalidseeds-filesize", type=int, metavar="COUNT", help="The number of valid seeds to include in each file, multiple output files are automatically incremented when this number is reached")

    parser.add_argument("--skip-worker-checksum", action="store_true",
                        help="Skip the checksum test for BIP39/Electrum seeds (This will force test all seeds, as opposed to 1/10, and will slow things down a lot)")
    opencl_group = parser.add_argument_group("OpenCL acceleration")
    opencl_group.add_argument("--enable-opencl", action="store_true",     help="enable experimental OpenCL-based (GPU) acceleration (only supports BIP39 (for supported coin) and Electrum wallets)")
    opencl_group.add_argument("--opencl-workgroup-size",  type=int, nargs="+", metavar="PASSWORD-COUNT", help="OpenCL global work size (Seeds are tested in batches, this impacts that batch size)")
    opencl_group.add_argument("--opencl-platform",  type=int, nargs="+", metavar="ID", help="Choose the OpenCL platform (GPU) to use (default: auto)")
    opencl_group.add_argument("--opencl-devices", metavar="ID1 ID2 ID3", nargs="+", help="Choose which OpenCL devices for a given to use as a space seperated list eg: 1 2 4 (default: all)")
    opencl_group.add_argument("--opencl-info",  action="store_true",     help="list available GPU names and IDs, then exit")
    opencl_group.add_argument("--force-checksum-in-generator",  action="store_true",     help="GPU processing currently performs seed checksums in the main thread, which works well for 12 word BIP39 seeds, but hurts performance in 12 and 24 word seeds")

    return parser
