# cli.py -- btcrecover command-line argument-parser definitions for btcrpass
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

"""Command-line argument definitions for :mod:`btcrecover.btcrpass`.

This module owns the argparse objects shared by the tokenlist and passwordlist
command lines: ``parser_common`` (plus its ``typo_types_group`` and
``bip39_group`` argument groups), ``init_parser_common()`` which populates it
on first use, and the ``register_simple_typo()`` decorator which adds a
``--typos-NAME`` option *and* registers the generator into the core typo
registry, ``_engine.simple_typos`` (the recovery engine reads that registry;
it deliberately stays in :mod:`btcrecover.btcrpass._engine`).

``_engine`` re-imports the public names defined here, so the long-standing
``btcrpass.register_simple_typo`` / ``btcrpass.parser_common`` surface is
unchanged.
"""

import argparse
import itertools
import sys

from . import _engine

parser_common = argparse.ArgumentParser(add_help=False)
prog          = str(parser_common.prog)
parser_common_initialized = False
def init_parser_common():
    global parser_common, parser_common_initialized, typo_types_group, bip39_group
    if not parser_common_initialized:
        # Build the list of command-line options common to both tokenlist and passwordlist files
        parser_common.add_argument("--wallet",      metavar="FILE", help="the wallet file (this, --data-extract, or --listpass is required)")
        parser_common.add_argument("--typos",       type=int, metavar="COUNT", help="simulate up to this many typos; you must choose one or more typo types from the list below")
        parser_common.add_argument("--min-typos",   type=int, default=0, metavar="COUNT", help="enforce a min # of typos included per guess")
        parser_common.add_argument("--password-repeats-pretypos", action="store_true", help="Also test multiple repititions of each candidate password BEFORE any typos are applied(eg: passwordpassword)")
        parser_common.add_argument("--password-repeats-posttypos", action="store_true", help="Also test multiple repititions of each candidate password AFTER any typos are applied (eg: passwordpassword)")
        parser_common.add_argument("--max-password-repeats", type=int, default=2, metavar="COUNT", help="Max number of additional repetitions of the password to produce (Both the PRE and POST repeats functions use this)")
        typo_types_group = parser_common.add_argument_group("typo types")
        typo_types_group.add_argument("--typos-capslock", action="store_true", help="try the password with caps lock turned on")
        typo_types_group.add_argument("--typos-swap",     action="store_true", help="swap two adjacent characters")
        for typo_name, typo_args in _engine.simple_typo_args.items():
            typo_types_group.add_argument("--typos-"+typo_name, **typo_args)
        typo_types_group.add_argument("--typos-insert",   metavar="WILDCARD-STRING", help="insert a string or wildcard")
        for typo_name in itertools.chain(("swap",), _engine.simple_typo_args.keys(), ("insert",)):
            typo_types_group.add_argument("--max-typos-"+typo_name, type=int, default=sys.maxsize, metavar="#", help="limit the number of --typos-"+typo_name+" typos")
        typo_types_group.add_argument("--max-adjacent-inserts", type=int, default=1, metavar="#", help="max # of --typos-insert strings that can be inserted between a single pair of characters (default: %(default)s)")
        parser_common.add_argument("--custom-wild", metavar="STRING",    help="a custom set of characters for the %%c wildcard")
        parser_common.add_argument("--utf8",        action="store_true", help="enable Unicode mode; all input must be in UTF-8 format")
        parser_common.add_argument("--regex-only",  metavar="STRING",    help="only try passwords which match the given regular expr")
        parser_common.add_argument("--regex-never", metavar="STRING",    help="never try passwords which match the given regular expr")
        parser_common.add_argument("--length-min", 	type=int, default=0, metavar="COUNT",    help="skip passwords shorter than given length")
        parser_common.add_argument("--length-max", 	type=int, default=999999, metavar="COUNT",    help="skip passwords longer than given length")
        parser_common.add_argument("--truncate-length", 	type=int, default=999999, metavar="COUNT",    help="Truncate passwords to be this number of characters long (Useful in situations like Trezor Passprase, etc)")
        parser_common.add_argument("--delimiter",   metavar="STRING",    help="the delimiter between tokens in the tokenlist or columns in the typos-map (default: whitespace)")
        parser_common.add_argument("--skip",        type=int, default=0,    metavar="COUNT", help="skip this many initial passwords for continuing an interrupted search")
        parser_common.add_argument("--threads",     type=int, metavar="COUNT", help="number of worker threads (default: number of logical CPU cores")
        parser_common.add_argument("--worker",      metavar="ID#(ID#2, ID#3)/TOTAL#",   help="divide the workload between TOTAL# servers, where each has a different ID# between 1 and TOTAL# (You can optionally assign between 1 and TOTAL IDs of work to a server (eg: 1,2/3 will assign both slices 1 and 2 of the 3 to the server...)")
        parser_common.add_argument("--max-eta",     type=int, default=168,  metavar="HOURS", help="max estimated runtime before refusing to even start (default: %(default)s hours, i.e. 1 week)")
        parser_common.add_argument("--no-eta",      action="store_true",    help="disable calculating the estimated time to completion")
        parser_common.add_argument("--dynamic-passwords-count", action="store_true", help=argparse.SUPPRESS) #help="start trying the passwords while they are being counted")
        parser_common.add_argument("--no-dupchecks", "-d", action="count", default=0, help="disable duplicate guess checking to save memory; specify up to four times for additional effect")
        parser_common.add_argument("--no-progress", action="store_true",   default=not sys.stdout.isatty(), help="disable the progress bar")
        parser_common.add_argument(
            "--pre-start-seconds",
            type=float,
            default=30.0,
            metavar="SECONDS",
            help="limit how long the pre-start benchmark runs for (default: %(default)s seconds); use 0 to skip it",
        )
        parser_common.add_argument(
            "--skip-pre-start",
            action="store_true",
            help="skip the pre-start benchmark; equivalent to --pre-start-seconds 0",
        )
        parser_common.add_argument("--android-pin", action="store_true", help="search for the spending pin instead of the backup password in a Bitcoin Wallet for Android/BlackBerry")
        parser_common.add_argument("--blockchain-secondpass", action="store_true", help="search for the second password instead of the main password in a Blockchain wallet")
        parser_common.add_argument("--blockchain-correct-mainpass", metavar="STRING", help="The main password for blockchain.com wallets, eithere entered using this argument, or prompted to enter at runtime")
        parser_common.add_argument("--msigna-keychain", metavar="NAME",  help="keychain whose password to search for in an mSIGNA vault")
        parser_common.add_argument("--data-extract",action="store_true", help="prompt for data extracted by one of the extract-* scripts instead of using a wallet file")
        parser_common.add_argument("--data-extract-string", metavar="Data-Extract",help="Directly pass data extracted by one of the extract-* scripts instead of using a wallet file")
        parser_common.add_argument("--mkey",        action="store_true", help=argparse.SUPPRESS)  # deprecated, use --data-extract instead
        parser_common.add_argument("--privkey",     action="store_true", help=argparse.SUPPRESS)  # deprecated, use --data-extract instead
        parser_common.add_argument("--btcrseed", action="store_true",help=argparse.SUPPRESS)  # Internal helper argument
        parser_common.add_argument("--exclude-passwordlist", metavar="FILE", nargs="?", const="-", help="never try passwords read (exactly one per line) from this file or from stdin")
        parser_common.add_argument("--listpass",    action="store_true", help="just list all password combinations to test and exit")
        parser_common.add_argument("--performance", action="store_true", help="run a continuous performance test (Ctrl-C to exit)")
        parser_common.add_argument("--performance-duration", type=int, default=None, metavar="SECONDS", help="automatically stop a --performance test after this many seconds and report results")
        parser_common.add_argument("--pause",       action="store_true", help="pause before exiting")
        parser_common.add_argument(
            "--beep-on-find",
            action="store_true",
            help="play a two-tone alert roughly every ten seconds when a password is found",
        )
        parser_common.add_argument(
            "--beep-on-find-pcspeaker",
            action="store_true",
            help="force the alert to use the internal PC speaker when a password is found",
        )
        parser_common.add_argument("--possible-passwords-file", metavar="FILE", default = "possible_passwords.log", help="Specify the file to save possible close matches to. (Defaults to possible_passwords.log)")
        parser_common.add_argument("--disable-save-possible-passwords",       action="store_true", help="Disable saving possible matches to file")
        parser_common.add_argument("--version","-v",action="store_true", help="show full version information and exit")
        parser_common.add_argument("--disablesecuritywarnings", "--dsw", action="store_true", help="Disable Security Warning Messages")
        dump_group = parser_common.add_argument_group("Wallet Decryption and Key Dumping")
        dump_group.add_argument("--dump-wallet", metavar="FILE",   help="Dump decrypted wallet to a file specified here.")
        dump_group.add_argument("--dump-privkeys", metavar="FILE",   help="Dump a list of private keys (For import in to Electrum) to a file specified here")
        dump_group.add_argument("--correct-wallet-password", metavar="STRING", help="The correct wallet password (This can be used instead of a passwordlist or tokenlist)")
        dump_group.add_argument("--correct-wallet-secondpassword", metavar="STRING", help="The correct wallet second password (This can be used instead of a passwordlist or tokenlist)")
        common_seedkey_group = parser_common.add_argument_group("Brainwallet/BIP39/RawPrivkey Shared Arguments")
        common_seedkey_group.add_argument("--addrs",      metavar="ADDRESS", nargs="+", help="if not using an mpk, address(es) in the wallet")
        common_seedkey_group.add_argument("--skip-compressed",      action="store_true", default=False, help="Skip check using compressed keys")
        common_seedkey_group.add_argument("--skip-uncompressed",      action="store_true", default=False, help="Skip check using uncompressed keys, common in older brainwallets.")
        common_seedkey_group.add_argument("--force-check-p2sh",      action="store_true", default=False, help="For the checking of p2sh segwit addresses (This autodetects for Bitcoin, but will need to be forced for alts like litecoin)")
        common_seedkey_group.add_argument("--addressdb",  metavar="FILE",    nargs="?", help="if not using addrs, use a full address database (default: %(const)s)", const=_engine.ADDRESSDB_DEF_FILENAME)
        common_seedkey_group.add_argument("--wallet-type",     metavar="TYPE",      help="the wallet type, e.g. ethereum (default: bitcoin)")
        brainwallet_group = parser_common.add_argument_group("Brainwallet")
        brainwallet_group.add_argument("--rawprivatekey", action="store_true", help="Search for a Raw Private Key")
        brainwallet_group.add_argument("--brainwallet", action="store_true", help="Search for a brainwallet")
        brainwallet_group.add_argument("--warpwallet",      action="store_true", default=False, help="Treat the brainwallet like a Warpwallet (or Memwallet)")
        brainwallet_group.add_argument("--warpwallet-salt",      metavar="STRING", help="For the checking of p2sh segwit addresses (This autodetects for Bitcoin, but will need to be forced for alts like litecoin)")
        brainwallet_group.add_argument("--memwallet-coin",      metavar="STRING", help="Coin type for memwallet brainwallets. (bitcoin, litecoin)")
        bip38_group = parser_common.add_argument_group("BIP-38 Encrypted Private Keys (eg: From Bitaddress Paper Wallets)")
        bip38_group.add_argument("--bip38-enc-privkey", metavar="ENC-PRIVKEY", help="encrypted private key")
        bip38_group.add_argument("--bip38-currency", metavar="Coin Code", help="Currency name from Bitcoinlib (eg: bitcoin, litecoin, dash)")
        bip39_group = parser_common.add_argument_group("BIP-39/SLIP39 passwords")
        bip39_group.add_argument("--bip39",      action="store_true",   help="search for a BIP-39 passphrase instead of from a wallet")
        bip39_group.add_argument("--slip39",      action="store_true",   help="search for a SLIP-39 passphrase instead of from a wallet")
        bip39_group.add_argument("--slip39-shares",  metavar="SLIP39-MNEMONIC", nargs="+",   help="SLIP39 Share Mnemonics")
        bip39_group.add_argument("--mpk",        metavar="XPUB",        help="the master public key")
        bip39_group.add_argument("--addr-limit", type=int, metavar="COUNT",    help="if using addrs or addressdb, the generation limit")
        bip39_group.add_argument("--language",   metavar="LANG-CODE",   help="the wordlist language to use (see wordlists/README.md, default: auto)")
        bip39_group.add_argument("--bip32-path", metavar="PATH",        nargs="+",           help="path (e.g. m/0'/0/) excluding the final index. You can specify multiple derivation paths seperated by a space Eg: m/84'/0'/0'/0 m/84'/0'/1'/0 (default: BIP44,BIP49 & BIP84 account 0)")
        bip39_group.add_argument("--substrate-path",  metavar="PATH", nargs="+",           help="Substrate path (eg: //hard/soft). You can specify multiple derivation paths by a space Eg: //hard /soft //hard/soft (default: No Path)")
        bip39_group.add_argument("--checksinglexpubaddress", action="store_true", help="Check non-standard single address wallets (Like MyBitcoinWallet and PT.BTC")
        bip39_group.add_argument("--force-p2sh",  action="store_true",   help="Force checking of P2SH segwit addresses for all derivation paths (Required for devices like CoolWallet S if if you are using P2SH segwit accounts on a derivation path that doesn't start with m/49')")
        bip39_group.add_argument("--force-p2tr",  action="store_true",   help="Force checking of P2TR (Taproot) addresses for all derivation paths (Required for wallets like Bitkeep/Bitget that put all accounts on  m/44')")
        bip39_group.add_argument("--force-bip44", action="store_true",   help="Force checking of BIP44 legacy (P2PKH) addresses even if they do not match the supplied addresses")
        bip39_group.add_argument("--force-bip84", action="store_true",   help="Force checking of BIP84 native SegWit (P2WPKH) addresses even if they do not match the supplied addresses")
        bip39_group.add_argument("--disable-p2sh", action="store_true",  help="Disable checking of P2SH segwit addresses")
        bip39_group.add_argument("--disable-p2tr", action="store_true",  help="Disable checking of P2TR (Taproot) addresses")
        bip39_group.add_argument("--disable-bip44", action="store_true", help="Disable checking of BIP44 legacy (P2PKH) addresses")
        bip39_group.add_argument("--disable-bip84", action="store_true", help="Disable checking of BIP84 native SegWit (P2WPKH) addresses")
        bip39_group.add_argument("--mnemonic",  metavar="MNEMONIC",       help="Your best guess of the mnemonic (if not entered, you will be prompted)")
        bip39_group.add_argument("--skip-mnemonic-checksum", action="store_true",
                                 help="skip validating the checksum of the provided mnemonic")
        bip39_group.add_argument("--mnemonic-prompt", action="store_true", help="prompt for the mnemonic guess via the terminal (default: via the GUI)")
        yoroi_group = parser_common.add_argument_group("Yoroi Cadano Wallet")
        yoroi_group.add_argument("--yoroi-master-password", metavar="Master_Password",
                                   help="Search for the password to decrypt a Yoroi wallet master_password provided")
        gpu_group = parser_common.add_argument_group("GPU acceleration")
        gpu_group.add_argument("--enable-gpu", action="store_true",     help="enable experimental OpenCL-based GPU acceleration (only supports Bitcoin Core wallets and extracts)")
        gpu_group.add_argument("--global-ws",  type=int, nargs="+",     default=[4096], metavar="PASSWORD-COUNT", help="OpenCL global work size (default: 4096)")
        gpu_group.add_argument("--local-ws",   type=int, nargs="+",     default=[None], metavar="PASSWORD-COUNT", help="OpenCL local work size; --global-ws must be evenly divisible by --local-ws (default: auto)")
        gpu_group.add_argument("--gpu-names",  nargs="+",               metavar="NAME-OR-ID", help="choose GPU(s) on multi-GPU systems (default: auto)")
        gpu_group.add_argument("--list-gpus",  action="store_true",     help="list available GPU names and IDs, then exit")
        gpu_group.add_argument("--int-rate",   type=int, default=200,   metavar="RATE", help="interrupt rate: raise to improve PC's responsiveness at the expense of search performance (default: %(default)s)")
        opencl_group = parser_common.add_argument_group("OpenCL acceleration")
        opencl_group.add_argument("--enable-opencl", action="store_true",     help="enable experimental OpenCL-based (GPU) acceleration (only supports BIP39 (for supported coin) and Electrum wallets)")
        opencl_group.add_argument("--opencl-workgroup-size",  type=int, nargs="+", metavar="PASSWORD-COUNT", help="OpenCL global work size (Seeds are tested in batches, this impacts that batch size)")
        opencl_group.add_argument("--opencl-platform",  type=int, nargs="+", metavar="ID", help="Choose the OpenCL platform (GPU) to use (default: auto)")
        opencl_group.add_argument("--opencl-devices", metavar="ID1,ID2,ID3", help="Choose which OpenCL devices for a given to use as a comma seperated list eg: 1,2,4 (default: all)")
        opencl_group.add_argument("--opencl-info",  action="store_true",     help="list available GPU names and IDs, then exit")

        parser_common_initialized = True


# A decorator that can be used to register a custom simple typo generator function
# so that it may be passed to parse_arguments() as an option like any other
def register_simple_typo(name, help = None):
    assert name.isalpha() and name.islower(), "simple typo name must have only lowercase letters"
    assert name not in _engine.simple_typos,          "simple typo must not already exist"
    init_parser_common()  # ensure typo_types_group has been initialized
    arg_params = dict(action="store_true")
    if help:
        arg_params["help"] = help
    typo_types_group.add_argument("--typos-"+name, **arg_params)
    typo_types_group.add_argument("--max-typos-"+name, type=int, default=sys.maxsize, metavar="#", help="limit the number of --typos-"+name+" typos")
    def decorator(simple_typo_generator):
        _engine.simple_typos[name] = simple_typo_generator
        return simple_typo_generator  # the decorator returns it unmodified, it just gets registered
    return decorator
