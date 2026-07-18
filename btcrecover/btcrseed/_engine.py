# btcrseed.py -- btcrecover mnemonic sentence library
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

# TODO: finish pythonizing comments/documentation

__version__ = "1.13.0-CryptoGuide"

disable_security_warnings = True

# Import modules included in standard libraries
import sys, os, io, base64, hashlib, hmac, difflib, itertools, \
       unicodedata, collections, struct, glob, atexit, re, random, multiprocessing, binascii, copy, datetime
import bisect
from typing import AnyStr, List, Optional, Sequence, Tuple, TypeVar, Union

# Import modules bundled with BTCRecover
from .. import aezeed, btcrpass
from .. import success_alert
from . import cli
from ..addressset import AddressSet
from lib.bitcoinlib import encoding
from lib.cashaddress import convert, base58
from lib.base58_tools import base58_tools
from lib.eth_hash.auto import keccak
import btcrecover.opencl_helpers
from lib.pyzil.account import Account as zilliqa_account
import lib.bech32 as bech32
import lib.cardano.cardano_utils as cardano
import lib.stacks.c32 as c32
from lib.p2tr_helper import P2TR_tools

# import bundled modules that won't work in some environments
bundled_bitcoinlib_mod_available = False
try:
    from lib.bitcoinlib_mod import encoding as encoding_mod

    bundled_bitcoinlib_mod_available = True
except:
    pass

# Enable functions that may not work for some standard libraries in some environments
hashlib_ripemd160_available = False

try:
    # this will work with micropython and python < 3.10
    # but will raise and exception if ripemd is not supported (python3.10, openssl 3)
    hashlib.new('ripemd160')
    hashlib_ripemd160_available = True
    def ripemd160(msg):
        return hashlib.new('ripemd160', msg).digest()
except:
    # otherwise use pure python implementation
    from lib.embit.py_ripemd160 import ripemd160

# Import modules from requirements.txt
# secp256k1 public-key operations are provided by btcrecover.crypto_backends,
# which prefers coincurve, falls back to wallycore, and finally to a bundled
# pure-Python implementation (emitting a warning when the slow path is used).
from btcrecover.crypto_backends import (
    privkey_to_pubkey,
    pubkey_to_bytes,
    BACKEND_NAME,
)

# Import optional modules
module_opencl_available = False
try:
    from lib.opencl_brute import opencl
    from lib.opencl_brute.opencl_information import opencl_information
    import pyopencl
    module_opencl_available = True
except:
    pass

py_crypto_hd_wallet_available = False
try:
    import py_crypto_hd_wallet

    py_crypto_hd_wallet_available = True
except:
    pass

nacl_available = False
try:
    import nacl.bindings

    nacl_available = True
except:
    pass

bitstring_available = False
try:
    from bitstring import BitArray

    bitstring_available = True
except:
    pass

bip_utils_available = False
try:
    from bip_utils import Bip32Slip10Ed25519, Bip39SeedGenerator

    bip_utils_available = True
except Exception:
    pass

eth2_staking_deposit_available = False
try:
    from staking_deposit.key_handling.key_derivation.path import mnemonic_and_path_to_key
    from py_ecc.bls import G2ProofOfPossession as bls

    eth2_staking_deposit_available = True
except:
    pass

shamir_mnemonic_available = False
slip39_min_words = 20
try:
    import shamir_mnemonic
    from shamir_mnemonic.constants import MIN_MNEMONIC_LENGTH_WORDS as slip39_min_words
    shamir_mnemonic_available = True
except Exception:
    pass


_T = TypeVar("_T")

# Pulled from https://github.com/trezor/python-mnemonic and modified to fix bug in Trezor derivation
# From <https://stackoverflow.com/questions/212358/binary-search-bisection-in-python/2233940#2233940>
def binary_search(
        a: Sequence[_T],
        x: _T,
        lo: int = 0,
        hi: Optional[int] = None,  # can't use a to specify default for hi
) -> int:
    hi = hi if hi is not None else len(a)  # hi defaults to len(a)
    pos = bisect.bisect_left(a, x, lo, hi)  # find insertion position
    return pos if pos != hi and a[pos] == x else -1  # don't walk off the end


# Order of the base point generator, from SEC 2
GENERATOR_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

ADDRESSDB_DEF_FILENAME = "addresses.db"

no_gui = False

def full_version():
    return "seedrecover {}, {}".format(
        __version__,
        btcrpass.full_version()
    )


################################### Utility Functions ###################################


def bytes_to_int(bytes_rep):
    """convert a string of bytes (in big-endian order) to a long integer

    :param bytes_rep: the raw bytes
    :type bytes_rep: str
    :return: the unsigned integer
    :rtype: long
    """
    return int(base64.b16encode(bytes_rep), 16)

def int_to_bytes(int_rep, min_length):
    """convert an unsigned integer to a string of bytes (in big-endian order)

    :param int_rep: a non-negative integer
    :type int_rep: long or int
    :param min_length: the minimum output length
    :type min_length: int
    :return: the raw bytes, zero-padded (at the beginning) if necessary
    :rtype: str
    """
    assert int_rep >= 0
    hex_rep = "{:X}".format(int_rep)
    if len(hex_rep) % 2 == 1:    # The hex decoder below requires
        hex_rep = "0" + hex_rep  # exactly 2 chars per byte.
    return base64.b16decode(hex_rep).rjust(min_length, "\0".encode("utf-8"))


dec_digit_to_base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
base58_digit_to_dec = { b58:dec for dec,b58 in enumerate(dec_digit_to_base58) }


def base58check_to_bytes(base58_rep, expected_size):
    """decode a base58check string to its raw bytes

    :param base58_rep: check-code appended base58-encoded string
    :type base58_rep: str
    :param expected_size: the expected number of decoded bytes (excluding the check code)
    :type expected_size: int
    :return: the base58-decoded bytes
    :rtype: str
    """
    base58_stripped = base58_rep.lstrip("1")

    int_rep = 0
    for base58_digit in base58_stripped:
        int_rep *= 58
        int_rep += base58_digit_to_dec[base58_digit]

    # Convert int to raw bytes
    all_bytes  = int_to_bytes(int_rep, expected_size + 4)

    zero_count = next(zeros for zeros,byte in enumerate(all_bytes) if byte != "\0")
    if len(base58_rep) - len(base58_stripped) != zero_count:
        raise ValueError("prepended zeros mismatch")


    if hashlib.sha256(hashlib.sha256(all_bytes[:-4]).digest()).digest()[:4] != all_bytes[-4:]:
        global groestlcoin_hash
        if groestlcoin_hash.getHash(all_bytes[:-4], len(all_bytes[:-4]))[:4] != all_bytes[-4:]:
            raise ValueError("base58 check code mismatch")

    return all_bytes[:-4]

BIP32ExtendedKey = collections.namedtuple("BIP32ExtendedKey",
    "version depth fingerprint child_number chaincode key")
#
def base58check_to_bip32(base58_rep):
    """decode a bip32-serialized extended key from its base58check form

    :param base58_rep: check-code appended base58-encoded bip32 extended key
    :type base58_rep: str
    :return: a namedtuple containing: version depth fingerprint child_number chaincode key
    :rtype: BIP32ExtendedKey
    """
    decoded_bytes = base58check_to_bytes(base58_rep, 4 + 1 + 4 + 4 + 32 + 33)
    return BIP32ExtendedKey(decoded_bytes[0:4],  ord(decoded_bytes[ 4:5]), decoded_bytes[ 5:9],
        struct.unpack(">I", decoded_bytes[9:13])[0], decoded_bytes[13:45], decoded_bytes[45:])

def compress_pubkey(uncompressed_pubkey):
    """convert an uncompressed public key into a compressed public key

    :param uncompressed_pubkey: the uncompressed public key
    :type uncompressed_pubkey: str
    :return: the compressed public key
    :rtype: str
    """
    assert len(uncompressed_pubkey) == 65 and uncompressed_pubkey[0] == 4
    return chr((uncompressed_pubkey[-1] & 1) + 2).encode() + uncompressed_pubkey[1:33]


def load_pathlist(pathlistFile):
    with open(pathlistFile, "r") as pathlist_file:
        return [line.split("#")[0].strip() for line in pathlist_file
                if line.strip() and line[0] != '#']

def load_passphraselist(passphraselistFile):
    with open(passphraselistFile, "r") as passphraselist_file:
        return passphraselist_file.read().splitlines()

import hmac
import hashlib
from struct import pack

def get_master_key_and_chain_code(seed):
    key = b"ed25519 seed"
    I = hmac.new(key, seed, hashlib.sha512).digest()
    return I[:32], I[32:]

def derive_child_key(parent_key, parent_chain_code, index):
    # Hardened index: index >= 0x80000000
    assert index >= 0x80000000

    data = b'\x00' + parent_key + pack(">L", index)
    I = hmac.new(parent_chain_code, data, hashlib.sha512).digest()
    return I[:32], I[32:]

def derive_path(master_key, master_chain_code, path):
    keys = (master_key, master_chain_code)
    for index_str in path.lstrip("m/").split("/"):
        hardened = index_str.endswith("'")
        index = int(index_str.rstrip("'"))
        if hardened:
            index += 0x80000000
        keys = derive_child_key(keys[0], keys[1], index)
    return keys

################################### Wallets ###################################

# A class decorator which adds a wallet class to a registered
# list that can later be selected by a user in GUI mode
selectable_wallet_classes = []
def register_selectable_wallet_class(description):
    def _register_selectable_wallet_class(cls):
        selectable_wallet_classes.append((cls, description))
        return cls
    return _register_selectable_wallet_class


# Loads a wordlist from a file into a list of Python unicodes. Note that the
# unicodes are normalized in NFC format, which is not what BIP39 requires (NFKD).
# wordlists live in btcrecover/wordlists/; this module is btcrecover/btcrseed/_engine.py,
# so go up two levels to the btcrecover package directory.
wordlists_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "wordlists")
def load_wordlist(name, lang):
    filename = os.path.join(wordlists_dir, "{}-{}.txt".format(name, lang))
    with io.open(filename, encoding="utf_8_sig") as wordlist_file:
        wordlist = []
        for word in wordlist_file:
            word = word.strip()
            if word and not word.startswith(u"#"):
                wordlist.append(unicodedata.normalize("NFC", word))
    return wordlist


def calc_passwords_per_second(checksum_ratio, kdf_overhead, scalar_multiplies):
    """estimate the number of mnemonics that can be checked per second (per CPU core)

    :param checksum_ratio: chances that a random mnemonic has the correct checksum [0.0 - 1.0]
    :type checksum_ratio: float
    :param kdf_overhead: overhead in seconds imposed by the kdf per each guess
    :type kdf_overhead: float
    :param scalar_multiplies: count of EC scalar multiplications required per each guess
    :type scalar_multiplies: int
    :return: estimated mnemonic check rate in hertz (per CPU core)
    :rtype: float
    """
    return 1.0 / (checksum_ratio * (kdf_overhead + scalar_multiplies*0.0001) + 0.00001)


#  Convert any ypub, zpub, etc into an xpub
#  This script uses version bytes as described in SLIP-132
#  https://github.com/satoshilabs/slips/blob/master/slip-0132.md
#  Doesn't attempt any error checking, as this is handled by the callers. Will simply return the input MPK
#  Given that derivation paths are specified elsewhere it's enough to just convert all Master Public Keys to an xpub...

def convert_to_xpub(input_mpk):
    output_mpk = input_mpk

    try:
        input_mpk_b58 = base58.b58decode_check(input_mpk)
        output_mpk_b58 = b'\x04\x88\xb2\x1e' + input_mpk_b58[4:]
        output_mpk = base58.b58encode_check(output_mpk_b58)
    except:
        try:
            input_mpk_b58 = base58.b58grsdecode_check(input_mpk)
            output_mpk_b58 = b'\x04\x88\xb2\x1e' + input_mpk_b58[4:]
            output_mpk = base58.b58grsencode_check(output_mpk_b58)
        except:
            pass

    return output_mpk

################################### Main ###################################

tk_root = None
def init_gui():
    # just return and leave tk_root as none if gui force disabled...
    global no_gui
    if no_gui:
        print("Warning: GUI disabled, you will need to set some recovery arguments manually")
        return

    global disable_security_warnings
    global tk_root, tk, tkFileDialog, tkSimpleDialog, tkMessageBox
    if not tk_root:

        if sys.platform == "win32":
            # Some py2exe .dll's, when registered as Windows shell extensions (e.g. SpiderOak), can interfere
            # with Python scripts which spawn a shell (e.g. a file selection dialog). The code below blocks
            # required modules from loading and prevents any such py2exe .dlls from causing too much trouble.
            sys.modules["win32api"] = None
            sys.modules["win32com"] = None

        try:
            import tkinter as tk
            import tkinter.filedialog
            import tkinter.simpledialog
            import tkinter.messagebox
            tk_root = tk.Tk(className="seedrecover.py")  # initialize library
            tk_root.withdraw()                           # but don't display a window (yet)
            if not disable_security_warnings:
                tkinter.messagebox.showinfo("Security Warning", "Most crypto wallet software and hardware wallets go to great lengths to protect your wallet password, seed phrase and private keys. BTCRecover isn't designed to offer this level of security, so it is possible that malware on your PC could gain access to this sensitive information while it is stored in memory in the use of this tool...\n\nAs a precaution, you should run this tool in a secure, offline environment and not simply use your normal, internet connected desktop environment... At the very least, you should disconnect your PC from the network and only reconnect it after moving your funds to a new seed... (Or if you run the tool on your internet conencted PC, move it to a new seed as soon as practical\n\nYou can disable this message by running this tool with the --dsw argument")
        except:
            print("Warning: Unable to load TK, no gui available, you will need to set some recovery arguments manually")

# seed.py uses routines from password.py to generate guesses, however instead
# of dealing with passwords (immutable sequences of characters), it deals with
# seeds (represented as immutable sequences of mnemonic_ids). More specifically,
# seeds are tuples of mnemonic_ids, and a mnemonic_id is just an int for Electrum1,
# or a UTF-8 bytestring id for most other wallet types.

# These are simple typo generators; see btcrpass.py for additional information.
# Instead of returning iterables of sequences of characters (iterables of strings),
# these return iterables of sequences of mnemonic_ids (iterables of partial seeds).
#
@btcrpass.register_simple_typo("deleteword")
def delete_word(mnemonic_ids, i):
    return (),
#
@btcrpass.register_simple_typo("replaceword")
def replace_word(mnemonic_ids, i):
    if mnemonic_ids[i] is None: return (),      # don't touch invalid words
    return ((new_id,) for new_id in loaded_wallet.word_ids if new_id != mnemonic_ids[i])
#
@btcrpass.register_simple_typo("replacecloseword")
def replace_close_word(mnemonic_ids, i):
    if mnemonic_ids[i] is None: return (),      # don't touch invalid words
    return close_mnemonic_ids[mnemonic_ids[i]]  # the pre-calculated similar words
#
@btcrpass.register_simple_typo("replacewrongword")
def replace_wrong_word(mnemonic_ids, i):
    if mnemonic_ids[i] is not None: return (),  # only replace invalid words
    return ((new_id,) for new_id in loaded_wallet.word_ids)


# Builds a command line and then runs btcrecover with it.
#   typos     - max number of mistakes to apply to each guess
#   big_typos - max number of "big" mistakes to apply to each guess;
#               a big mistake involves replacing or inserting a word using the
#               full word list, and significantly increases the search time
#   min_typos - min number of mistakes to apply to each guess
num_inserts = num_deletes = 0
def run_btcrecover(typos, big_typos = 0, min_typos = 0, is_performance = False, extra_args = [], arg_overrides = None, tokenlist = None, passwordlist = None, listpass = None, min_tokens = None, max_tokens = None, mnemonic_length = None, seed_transform_wordswaps = None, seed_transform_trezor_common_mistakes = None, keep_tokens_order = False):
    if typos < 0:  # typos == 0 is silly, but causes no harm
        raise ValueError("typos must be >= 0")
    if big_typos < 0:
        raise ValueError("big-typos must be >= 0")
    if big_typos > typos:
        raise ValueError("typos includes big_typos, therefore it must be >= big_typos")
    # min_typos < 0 is silly, but causes no harm
    # typos < min_typos is an error; it's checked in btcrpass.parse_arguments()

    # Local copies of globals whose changes should only be visible locally
    l_num_inserts = num_inserts
    l_num_deletes = num_deletes

    # Number of words that were definitely wrong in the guess
    num_wrong = sum(map(lambda id: id is None, mnemonic_ids_guess))

    # Build the configuration passed to btcrpass. Options that must be present as
    # real command-line arguments -- because parse_arguments reads them from files
    # during parsing (tokenlist/passwordlist), affects its early flow, or must keep
    # the argv non-empty -- go into argv. Everything else is passed as already-typed
    # values via arg_overrides, rather than being stringified for argparse to
    # re-parse. extra_args carries the user's own --btcr-args passthrough verbatim.
    argv = ["--typos", str(typos)]
    overrides = dict(arg_overrides or {})

    if tokenlist:
        argv += ["--tokenlist", str(tokenlist)]
        overrides["max_tokens"] = max_tokens if max_tokens else big_typos
        overrides["min_tokens"] = min_tokens if min_tokens else big_typos
        overrides["seedgenerator"] = True
        overrides["mnemonic_length"] = mnemonic_length

    if keep_tokens_order:
        overrides["keep_tokens_order"] = True

    if passwordlist:
        argv += ["--passwordlist", str(passwordlist)]
        overrides["seedgenerator"] = True

    if listpass:
        argv.append("--listpass")

    if is_performance:
        argv.append("--performance")
        # These typos are not supported by seedrecover with --performance testing:
        l_num_inserts = l_num_deletes = num_wrong = 0

    if seed_transform_wordswaps:
        overrides["seed_transform_wordswaps"] = seed_transform_wordswaps
    if seed_transform_trezor_common_mistakes:
        overrides["seed_transform_trezor_common_mistakes"] = seed_transform_trezor_common_mistakes

    # First, check if there are any required typos (if there are missing or extra
    # words in the guess) and adjust the max number of other typos to later apply

    any_typos  = typos  # the max number of typos left after removing required typos
    #big_typos =        # the max number of "big" typos after removing required typos (an arg from above)

    if l_num_deletes:  # if the guess is too long (extra words need to be deleted)
        any_typos -= l_num_deletes
        overrides["typos_deleteword"] = True
        if l_num_deletes < typos:
            overrides["max_typos_deleteword"] = l_num_deletes

    if num_wrong:      # if any of the words were invalid (and need to be replaced)
        any_typos -= num_wrong
        big_typos -= num_wrong
        overrides["typos_replacewrongword"] = True
        if num_wrong < typos:
            overrides["max_typos_replacewrongword"] = num_wrong

    # For (only) Electrum2, num_inserts are not required, so we try several sub-phases with a
    # different number of inserts each time; for all others the total num_inserts are required
    if isinstance(loaded_wallet, WalletElectrum2):
        num_inserts_to_try = range(l_num_inserts + 1)  # try a range
    else:
        num_inserts_to_try = l_num_inserts,             # only try the required max
    for subphase_num, cur_num_inserts in enumerate(num_inserts_to_try, 1):

        # Create local copies of these which are reset at the beginning of each loop
        l_any_typos = any_typos
        l_big_typos = big_typos
        l_overrides = dict(overrides)

        ids_to_try_inserting = None
        if cur_num_inserts:  # if the guess is too short (words need to be inserted)
            l_any_typos -= cur_num_inserts
            l_big_typos -= cur_num_inserts
            # (instead of --typos-insert we'll set inserted_items=ids_to_try_inserting below)
            ids_to_try_inserting = ((id,) for id in loaded_wallet.word_ids)
            l_overrides["max_adjacent_inserts"] = cur_num_inserts
            if cur_num_inserts < typos:
                l_overrides["max_typos_insert"] = cur_num_inserts

        # For >1 subphases, print this out now or just after the skip-this-phase check below
        if len(num_inserts_to_try) > 1:
            subphase_msg = "  - subphase {}/{}: with {} inserted seed word{}".format(
                subphase_num, len(num_inserts_to_try),
                cur_num_inserts, "" if cur_num_inserts == 1 else "s")
        if subphase_num > 1:
            print(subphase_msg)
            maybe_skipping = "the remainder of this phase."
        else:
            maybe_skipping = "this phase."

        if l_any_typos < 0:  # if too many typos are required to generate valid mnemonics
            print("Not enough mistakes permitted to produce a valid seed; skipping", maybe_skipping)
            return False
        if l_big_typos < 0:  # if too many big typos are required to generate valid mnemonics
            print("Not enough entirely different seed words permitted; skipping", maybe_skipping)
            return False
        assert typos >= cur_num_inserts + l_num_deletes + num_wrong

        if subphase_num == 1 and len(num_inserts_to_try) > 1:
            print(subphase_msg)

        # Because btcrecover doesn't support --min-typos-* on a per-typo basis, it ends
        # up generating some invalid guesses. We can use --min-typos to filter out some
        # of them (the remainder is later filtered out by verify_mnemonic_syntax()).
        min_typos = max(min_typos, cur_num_inserts + l_num_deletes + num_wrong)
        if min_typos:
            l_overrides["min_typos"] = min_typos

        # Next, if the required typos above haven't consumed all available typos
        # (as specified by the function's args), add some "optional" typos

        if l_any_typos:
            l_overrides["typos_swap"] = True
            if l_any_typos < typos:
                l_overrides["max_typos_swap"] = l_any_typos

            if l_big_typos:  # if there are any big typos left, add the replaceword typo
                l_overrides["typos_replaceword"] = True
                if l_big_typos < typos:
                    l_overrides["max_typos_replaceword"] = l_big_typos

            # only add replacecloseword typos if they're not already covered by the
            # replaceword typos added above and there exists at least one close word
            num_replacecloseword = l_any_typos - l_big_typos
            if num_replacecloseword > 0 and any(len(ids) > 0 for ids in close_mnemonic_ids.values()):
                l_overrides["typos_replacecloseword"] = True
                if num_replacecloseword < typos:
                    l_overrides["max_typos_replacecloseword"] = num_replacecloseword

        btcrpass.parse_arguments(
            argv + list(extra_args),
            arg_overrides=  l_overrides,
            inserted_items= ids_to_try_inserting,
            wallet=         loaded_wallet,
            base_iterator=  (mnemonic_ids_guess,) if not is_performance else None, # the one guess to modify
            perf_iterator=  lambda: loaded_wallet.performance_iterator(),
            check_only=     loaded_wallet.verify_mnemonic_syntax,
            disable_security_warning_param=True
        )
        (mnemonic_found, not_found_msg) = btcrpass.main()

        if mnemonic_found:
            return mnemonic_found
        elif not_found_msg is None:
            return None  # An error occurred or Ctrl-C was pressed inside btcrpass.main()

    return False  # No error occurred; the mnemonic wasn't found


def register_autodetecting_wallets():
    """Registers wallets which can do file auto-detection with btcrecover's auto-detect mechanism

    :rtype: None
    """
    btcrpass.clear_registered_wallets()
    for wallet_cls, description in selectable_wallet_classes:
        if hasattr(wallet_cls, "is_wallet_file"):
            btcrpass.register_wallet_class(wallet_cls)

def build_search_phases(wallet, phase, phase_transform):
    """Return the run_btcrecover() phase configuration for the current invocation."""

    if phase:
        phases = [phase]
    else:
        passwords_per_seconds = wallet.passwords_per_seconds(1)
        if passwords_per_seconds < 25:
            phases = [dict(typos=1), dict(typos=2, min_typos=2)]
        else:
            phases = [dict(typos=2)]
        phases.extend(
            (
                dict(typos=1, big_typos=1),
                dict(typos=2, big_typos=1, min_typos=2),
            )
        )
        phases.append(
            dict(typos=2, big_typos=2, min_typos=2, extra_args=["--no-dupchecks"])
        )

    if phase_transform:
        for phase_params in phases:
            phase_params.update(phase_transform)

    return phases


def main(argv):
    global loaded_wallet
    loaded_wallet = wallet_type = None
    create_from_params     = {}  # additional args to pass to wallet_type.create_from_params()
    config_mnemonic_params = {}  # additional args to pass to wallet.config_mnemonic()
    phase                  = {}  # if only one phase is requested, the args to pass to run_btcrecover()
    phase_transform        = {}  # args applied to all run_btcrecover() phases without overriding defaults
    extra_args             = []  # verbatim argv passthrough for btcrpass (the user's --btcr-args, plus a
                                 # few options that must stay as real args, e.g. the --no-dupchecks count)
    btcr_overrides         = {}  # already-typed {dest: value} config forwarded to btcrpass.parse_arguments()
                                 # instead of being stringified and re-parsed by argparse
    listseeds = False

    if argv or "_ARGCOMPLETE" in os.environ:
        parser = cli.build_parser()

        # Optional bash tab completion support
        try:
            import argcomplete
            argcomplete.autocomplete(parser)
        except ImportError:
            pass
        assert argv

        # Parse the args; unknown args will be passed to btcrpass.parse_arguments() iff --btcr-args is specified
        args, extra_args = parser.parse_known_args(argv)
        if extra_args and not args.btcr_args:
            parser.parse_args(argv)  # re-parse them just to generate an error for the unknown args
            assert False

        # Assign the no-gui to a global variable...
        global no_gui
        if args.no_gui:
            no_gui = True

        # Tell btcrpass we are running a seed recovery
        btcr_overrides["btcrseed"] = True

        #Disable Security Warnings if parameter set...
        global disable_security_warnings
        if args.disablesecuritywarnings:
            disable_security_warnings = True
        else:
            disable_security_warnings = False

        success_alert.configure_pc_speaker(args.beep_on_find_pcspeaker)
        beep_on_find_enabled = args.beep_on_find or args.beep_on_find_pcspeaker
        success_alert.set_beep_on_find(beep_on_find_enabled)
        if beep_on_find_enabled:
            btcr_overrides["beep_on_find"] = True
        if args.beep_on_find_pcspeaker:
            btcr_overrides["beep_on_find_pcspeaker"] = True

        # Version information is always printed by seedrecover.py, so just exit
        if args.version: sys.exit(0)

        if args.opencl_info:
            info = opencl_information()
            info.printfullinfo()
            exit(0)

        if args.wallet:
            loaded_wallet = btcrpass.load_wallet(args.wallet)

        if args.savevalidseeds:
            if args.enable_opencl: exit("Error: SaveValidSeeds not a valid option when OpenCL is in use...")
            print("WARNING: Seeds aren't actually checked when --savevalidseeds argument is used, only generated, checksummed and saved...")
            args.addrs = ['1QLSbWFtVNnTFUq5vxDRoCpvvsSqTTS88P']
            args.addr_limit = 1
            args.no_eta = True
            args.no_dupchecks = 4
            if args.wallet_type:
                if args.wallet_type.lower() == "ethereum":
                    args.wallet_type = "bip39"

        # Look up the --wallet-type arg in the list of selectable_wallet_classes
        if args.slip39:
            wallet_type = WalletSLIP39Seed
        elif args.wallet_type:
            if args.wallet:
                print("warning: --wallet-type is ignored when a wallet is provided", file=sys.stderr)
            else:
                args.wallet_type  = args.wallet_type.lower()
                wallet_type_names = []
                for cls, desc in selectable_wallet_classes:
                    wallet_type_names.append(cls.__name__.replace("Wallet", "", 1).lower())
                    if wallet_type_names[-1] == args.wallet_type:
                        wallet_type = cls
                        break
                else:
                    wallet_type_names.sort()
                    sys.exit("--wallet-type must be one of: " + ", ".join(wallet_type_names))

        if args.mpk:
            if args.wallet:
                print("warning: --mpk is ignored when a wallet is provided", file=sys.stderr)
            else:
                create_from_params["mpk"] = args.mpk

        if args.addrs:
            if args.wallet:
                print("warning: --addrs is ignored when a wallet is provided", file=sys.stderr)
            else:
                create_from_params["addresses"] = args.addrs

        if args.addr_limit is not None:
            if args.wallet:
                print("warning: --addr-limit is ignored when a wallet is provided", file=sys.stderr)
            else:
                create_from_params["address_limit"] = args.addr_limit

        if args.addr_start_index is not None:
            create_from_params["address_start_index"] = args.addr_start_index

        if args.addressdb and not os.path.isfile(args.addressdb):
            sys.exit("file '{}' does not exist".format(args.addressdb))

        if args.typos is not None:
            phase["typos"] = args.typos

        if args.big_typos is not None:
            phase["big_typos"] = args.big_typos
            if not args.typos:
                phase["typos"] = args.big_typos

        if args.min_typos is not None:
            if not phase.get("typos"):
                sys.exit("--typos must be specified when using --min_typos")
            phase["min_typos"] = args.min_typos

        if args.close_match is not None:
            config_mnemonic_params["closematch_cutoff"] = args.close_match

        if not disable_security_warnings:
            # Print a security warning before giving users the chance to enter ir seed....
            # Also a good idea to keep this warning as late as possible in terms of not needing it to be display for --version --help, or if there are errors in other parameters.
            print("btcrseed")
            print("* * * * * * * * * * * * * * * * * * * *")
            print("*          Security: Warning          *")
            print("* * * * * * * * * * * * * * * * * * * *")
            print()
            print(
                "Most crypto wallet software and hardware wallets go to great lengths to protect your wallet password, seed phrase and private keys. BTCRecover isn't designed to offer this level of security, so it is possible that malware on your PC could gain access to this sensitive information while it is stored in memory in the use of this tool...")
            print()
            print(
                "As a precaution, you should run this tool in a secure, offline environment and not simply use your normal, internet connected desktop environment... At the very least, you should disconnect your PC from the network and only reconnect it after moving your funds to a new seed... (Or if you run the tool on your internet conencted PC, move it to a new seed as soon as practical)")
            print()
            print("You can disable this message by running this tool with the --dsw argument")
            print()
            print("* * * * * * * * * * * * * * * * * * * *")
            print("*          Security: Warning          *")
            print("* * * * * * * * * * * * * * * * * * * *")
            print()

        if args.mnemonic:
            config_mnemonic_params["mnemonic_guess"] = args.mnemonic

        if args.mnemonic_prompt:
            encoding = sys.stdin.encoding or "ASCII"
            if "utf" not in encoding.lower():
                print("terminal does not support UTF; mnemonics with non-ASCII chars might not work", file=sys.stderr)
            mnemonic_guess = input("Please enter your best guess for your mnemonic (seed)\n> ")
            if not mnemonic_guess:
                sys.exit("canceled")
            config_mnemonic_params["mnemonic_guess"] = mnemonic_guess

        if args.passphrase_prompt:
            import getpass
            encoding = sys.stdin.encoding or "ASCII"
            if "utf" not in encoding.lower():
                print("warning: terminal does not support UTF; passwords with non-ASCII chars might not work", file=sys.stderr)
            print("(note your passphrase will not be displayed as you type)")
            while True:
                passphrase = getpass.getpass("Please enter the passphrase you added when the seed was first created: ")
                if not passphrase:
                    sys.exit("canceled")
                if passphrase == getpass.getpass("Please re-enter the passphrase: "):
                    break
                print("The passphrases did not match, try again.")
            config_mnemonic_params["passphrases"] = [passphrase,]
        elif args.passphrase_arg:
            config_mnemonic_params["passphrases"] = args.passphrase_arg
        elif args.passphrase or args.passphrase_list:
            config_mnemonic_params["passphrases"] = True  # config_mnemonic() will prompt for one

        if args.passphrase_list:
            passphrases = load_passphraselist(args.passphrase_list)
            config_mnemonic_params["passphrases"] = passphrases

        if args.seedlist or args.tokenlist:
            if args.mnemonic_length is None:
                exit("Error: Mnemonic length needs to be specificed if using tokenlist or passwordlist")
            if args.language is None:
                if args.wallet_type != 'electrum1':
                    exit("Error: Language needs to be specificed if using tokenlist or passwordlist")
            config_mnemonic_params["mnemonic_guess"] = ("seed_token_placeholder " * args.mnemonic_length)[:-1]
            phase["big_typos"] = args.mnemonic_length
            phase["typos"] = args.mnemonic_length
            phase["max_tokens"] = args.max_tokens
            phase["min_tokens"] = args.min_tokens
            phase["mnemonic_length"] = args.mnemonic_length
            phase["keep_tokens_order"] = args.keep_tokens_order

            if args.tokenlist:
                phase["tokenlist"] = args.tokenlist

            if args.seedlist:
                phase["passwordlist"] = args.seedlist

            if args.wallet_type == "electrum1":
                args.language = None

        if args.language:
            config_mnemonic_params["lang"] = args.language.lower()

        if args.mnemonic_length is not None:
            config_mnemonic_params["expected_len"] = args.mnemonic_length

        if args.share_length is not None:
            config_mnemonic_params["expected_len"] = args.share_length

        if args.bip32_path and not args.pathlist:
            if args.wallet:
                print("warning: --bip32-path is ignored when a wallet is provided", file=sys.stderr)
            else:
                create_from_params["path"] = args.bip32_path

        if args.substrate_path and not args.pathlist:
            if args.wallet:
                print("warning: --bip32-path is ignored when a wallet is provided", file=sys.stderr)
            else:
                create_from_params["path"] = args.substrate_path

        if args.pathlist:
            if args.bip32_path:
                print("warning: Pathlist overrides any --bip32-path or --substrate-path provided", file=sys.stderr)
            create_from_params["path"] = load_pathlist(args.pathlist)

        if args.force_p2sh:
            create_from_params["force_p2sh"] = True

        if args.force_p2tr:
            create_from_params["force_p2tr"] = True

        if args.force_bip44:
            create_from_params["force_bip44"] = True

        if args.force_bip84:
            create_from_params["force_bip84"] = True

        if args.disable_p2sh:
            create_from_params["disable_p2sh"] = True

        if args.disable_p2tr:
            create_from_params["disable_p2tr"] = True

        if args.disable_bip44:
            create_from_params["disable_bip44"] = True

        if args.disable_bip84:
            create_from_params["disable_bip84"] = True

        if args.transform_wordswaps:
            print("SEED-TRANSFORM: Checking", args.transform_wordswaps, "pairs of swapped words for each possible mnemonic")
            phase_transform["seed_transform_wordswaps"] = args.transform_wordswaps
        if args.transform_trezor_common_mistakes:
            print(
                "SEED-TRANSFORM: Checking up to",
                args.transform_trezor_common_mistakes,
                "Trezor common-mistake substitutions for each possible mnemonic",
            )
            phase_transform["seed_transform_trezor_common_mistakes"] = (
                args.transform_trezor_common_mistakes
            )
            
        if args.checksinglexpubaddress:
            create_from_params["checksinglexpubaddress"] = True

        if args.no_check_change_addresses:
            create_from_params["check_change_addresses"] = False

        # These arguments and their values are forwarded to btcrpass as typed overrides
        for argkey in "skip", "threads", "worker", "max_eta", "pre_start_seconds", "performance_duration":
            if args.__dict__[argkey] is not None:
                btcr_overrides[argkey] = args.__dict__[argkey]

        # These (valueless) flags are forwarded to btcrpass as typed overrides
        for argkey in "no_eta", "no_progress", "skip_pre_start":
            if args.__dict__[argkey]:
                btcr_overrides[argkey] = True

        # Special case for --no-dupchecks: it is a repeat-count option, and per-phase
        # config may add more of them, so it stays a real (repeatable) argv flag.
        if args.__dict__["no_dupchecks"] is not None:
            for i in range(0, args.__dict__["no_dupchecks"]):
                extra_args.append("--no-dupchecks")

        if args.performance:
            create_from_params["is_performance"] = phase["is_performance"] = True
            phase.setdefault("typos", 0)
            if not args.mnemonic_prompt:
                # Create a dummy mnemonic; only its language and length are used for anything
                config_mnemonic_params["mnemonic_guess"] = " ".join("act" for i in range(args.mnemonic_length or 12))

        if args.addressdb:
            print("Loading address database ...")
            createdAddressDB = create_from_params["hash160s"] = AddressSet.fromfile(open(args.addressdb, "rb"))
            print("Loaded", len(createdAddressDB), "addresses from database ...")

            # Special Case where we don't know any mnemonic words (Using TokenList or PasswordList)
            # simply configure the menonic to be all invalid words...

        if args.listseeds:
            listseeds = True
            phase["listpass"] = True

    else:  # else if no command-line args are present
        # Print a security warning before giving users the chance to enter ir seed....
        # Also a good idea to keep this warning as late as possible in terms of not needing it to be display for --version --help, or if there are errors in other parameters.
        print("btcrseed")
        print("* * * * * * * * * * * * * * * * * * * *")
        print("*          Security: Warning          *")
        print("* * * * * * * * * * * * * * * * * * * *")
        print()
        print(
            "Most crypto wallet software and hardware wallets go to great lengths to protect your wallet password, seed phrase and private keys. BTCRecover isn't designed to offer this level of security, so it is possible that malware on your PC could gain access to this sensitive information while it is stored in memory in the use of this tool...")
        print()
        print(
            "As a precaution, you should run this tool in a secure, offline environment and not simply use your normal, internet connected desktop environment... At the very least, you should disconnect your PC from the network and only reconnect it after moving your funds to a new seed... (Or if you run the tool on your internet conencted PC, move it to a new seed as soon as practical)")
        print()
        print("You can disable this message by running this tool with the --dsw argument")
        print()
        print("* * * * * * * * * * * * * * * * * * * *")
        print("*          Security: Warning          *")
        print("* * * * * * * * * * * * * * * * * * * *")
        print()

        global pause_at_exit
        pause_at_exit = True
        atexit.register(lambda: pause_at_exit and
                                not multiprocessing.current_process().name.startswith("PoolWorker-") and
                                input("Press Enter to exit ..."))

    if not loaded_wallet and not wallet_type:  # neither --wallet nor --wallet-type were specified

        # Ask for a wallet file
        init_gui()
        if tk_root: # Skip if TK is not available...
            wallet_filename = tk.filedialog.askopenfilename(title="Please select your wallet file if you have one")
        else:
            print("No wallet file or type specified... Exiting...")
            exit()

        if wallet_filename:
            loaded_wallet = btcrpass.load_wallet(wallet_filename)  # raises on failure; no second chance

    if not loaded_wallet:    # if no wallet file was chosen

        if not wallet_type:  # if --wallet-type wasn't specified

            if tk_root:  # Skip if TK is not available...
                # Without a wallet file, we can't automatically determine the wallet type, so prompt the
                # user to select a wallet that's been registered with @register_selectable_wallet_class
                selectable_wallet_classes.sort(key=lambda x: x[1])  # sort by description

                class WalletTypeDialog(tk.simpledialog.Dialog):
                    def body(self, master):
                        self.wallet_type     = None
                        self._index_to_cls   = []
                        self._selected_index = tk.IntVar(value= -1)
                        for i, (cls, desc) in enumerate(selectable_wallet_classes):
                            self._index_to_cls.append(cls)
                            tk.Radiobutton(master, variable=self._selected_index, value=i, text=desc) \
                                .grid(row = i % 20, column = i // 20, sticky = tk.W, pady = 0)
                    def validate(self):
                        if self._selected_index.get() < 0:
                            tk.messagebox.showwarning("Wallet Type", "Please select a wallet type")
                            return False
                        return True
                    def apply(self):
                        self.wallet_type = self._index_to_cls[self._selected_index.get()]
                #
                wallet_type_dialog = WalletTypeDialog(tk_root, "Please select your wallet type")
                wallet_type = wallet_type_dialog.wallet_type
                if not wallet_type:
                    sys.exit("canceled")

            else:
                print("No wallet or wallet type speciiced... Exiting...")
                exit()

        try:
            loaded_wallet = wallet_type.create_from_params(**create_from_params)
        except TypeError as e:
            matched = re.match(r"create_from_params\(\) got an unexpected keyword argument '(.*)'", str(e))
            if matched:
                sys.exit("{} does not support the {} option".format(wallet_type.__name__, matched.group(1)))
            raise
        except ValueError as e:
            sys.exit(e)

    # =====================
    # Set Wallet Parameters
    # =====================

    try:
        loaded_wallet.config_mnemonic(**config_mnemonic_params)
    except TypeError as e:
        matched = re.match(r"config_mnemonic\(\) got an unexpected keyword argument '(.*)'", str(e))
        if matched:
            sys.exit("{} does not support the {} option".format(loaded_wallet.__class__.__name__, matched.group(1)))
        raise
    except ValueError as e:
        sys.exit(e)

    try:
        if args.skip_worker_checksum:
            loaded_wallet._skip_worker_checksum = True
        else:
            loaded_wallet._skip_worker_checksum = False

        loaded_wallet._savevalidseeds = False
        if args.savevalidseeds:
            loaded_wallet._savevalidseeds = args.savevalidseeds
            if args.savevalidseeds_filesize:
                if args.savevalidseeds_filesize <= 0:
                    print("ERROR: --savevalidseed-filesize needs to be a positive whole number")
                    exit()
            else:
                print("NOTICE: No Seed file size specified, Setting Seed Filesize to 10 million seeds per file")
                args.savevalidseeds_filesize = 10000000 # 10 million checksummed seeds will produce files about 1gb each (for 24 word seeds), quite easy to work with...

            loaded_wallet._seedfilecount = args.savevalidseeds_filesize
            if loaded_wallet._skip_worker_checksum:
                print("WARNING: Skipping Worker Checksum is probably not what you want when using --savevalideeds argument")

        if args.multi_file_seedlist:
            loaded_wallet.load_multi_file_seedlist = True
        else:
            loaded_wallet.load_multi_file_seedlist = False


        ##############################
        # OpenCL related arguments
        ##############################

        loaded_wallet.opencl = False
        loaded_wallet.opencl_algo = -1
        loaded_wallet.opencl_context_pbkdf2_sha512 = -1
        # Parse and syntax check all of the GPU related options
        if args.enable_opencl:
            if not module_opencl_available:
                exit("\nERROR: Cannot Load pyOpenCL, see the installation guide at https://btcrecover.readthedocs.io/en/latest/GPU_Acceleration/")

            if not hasattr(loaded_wallet, "_return_verified_password_or_false_opencl"):
                btcrpass.error_exit("Wallet Type: " + loaded_wallet.__class__.__name__ + " does not support OpenCL acceleration")

            loaded_wallet.opencl = True
            # Append GPU related arguments to be sent to BTCrpass
            extra_args.append("--enable-opencl")

            if args.force_checksum_in_generator:
                print()
                print("Note: Performing Seed Checksum in the Generator Step will result in inaccurate speed and password count numbers (Only seeds with valid checksum are included in the count)")
                print()
                loaded_wallet._checksum_in_generator = True

            #
            if args.opencl_platform:
                loaded_wallet.opencl_platform = args.opencl_platform[0]
                loaded_wallet.opencl_device_worksize = 0
                extra_args.append("--opencl-platform")
                extra_args.append(str(args.opencl_platform[0]))
                for device in pyopencl.get_platforms()[args.opencl_platform[0]].get_devices():
                    if device.max_work_group_size > loaded_wallet.opencl_device_worksize:
                        loaded_wallet.opencl_device_worksize = device.max_work_group_size
            #
            # Else if specific devices weren't requested, try to build a good default list
            else:
                btcrecover.opencl_helpers.auto_select_opencl_platform(loaded_wallet)
                #print("OpenCL: Auto Selecting: ", best_device, "on Platform: ", best_platform)

            if args.opencl_devices:
                loaded_wallet.opencl_devices = args.opencl_devices
                loaded_wallet.opencl_devices = [int(x) for x in loaded_wallet.opencl_devices]
                if max(loaded_wallet.opencl_devices) > (len(pyopencl.get_platforms()[loaded_wallet.opencl_platform].get_devices()) - 1):
                    print("Error: Invalid OpenCL device selected")
                    exit()

            loaded_wallet.opencl_algo = 0
            loaded_wallet.opencl_context_pbkdf2_sha512 = 0

            extra_args.append("--opencl-workgroup-size")
            if args.opencl_workgroup_size:
                loaded_wallet.opencl_device_worksize = args.opencl_workgroup_size[0]
                extra_args.append(str(args.opencl_workgroup_size[0]))
                leastbad_worksize = loaded_wallet.opencl_device_worksize
            else:
                if args.force_checksum_in_generator or args.skip_worker_checksum:
                    leastbad_worksize = loaded_wallet.opencl_device_worksize
                else: # If the worksize hasn't be manually specificed, come up with a sensible automatic setting which matches the device worksize with the anticipated checksum error rate
                    leastbad_worksize = loaded_wallet.opencl_device_worksize * 50
                    if args.mnemonic_length:
                        mnemonic_length = args.mnemonic_length
                    else:
                        mnemonic_length = len(mnemonic_ids_guess)
                    if mnemonic_length == 12:
                        if args.wallet_type:
                            if args.wallet_type.lower() == "electrum2":
                                leastbad_worksize = int(loaded_wallet.opencl_device_worksize * 125)
                        else:
                            leastbad_worksize = int(loaded_wallet.opencl_device_worksize * 16)
                    if mnemonic_length == 18:
                        leastbad_worksize = int(loaded_wallet.opencl_device_worksize * 64)
                    if mnemonic_length == 24:
                        leastbad_worksize = int(loaded_wallet.opencl_device_worksize * 256)
                extra_args.append(str(leastbad_worksize))

            #print("OpenCL: Using Work Group Size: ", leastbad_worksize)
            #print()
        #
        # if not --enable-opencl: sanity checks
        else:
            loaded_wallet.opencl = False
            for argkey in "opencl_platform", "opencl_workgroup_size":
                if args.__dict__[argkey] != parser.get_default(argkey):
                    print("Warning: --" + argkey.replace("_", "-"), "is ignored without --enable-opencl",
                          file=sys.stderr)

    except UnboundLocalError: pass


    # Seeds for some wallet types have a checksum which is unlikely to be correct
    # for the initial provided seed guess; if it is correct, let the user know
    try:
        if (  loaded_wallet._initial_words_valid
          and loaded_wallet.verify_mnemonic_syntax(mnemonic_ids_guess)
          and loaded_wallet._verify_checksum(mnemonic_ids_guess) ):
            print(u"Initial seed guess has a valid checksum ({:.2g}% chance).".format(loaded_wallet._checksum_ratio * 100.0))
    except AttributeError: pass

    # Now that most of the GUI code is done, undo any Windows shell extension workarounds from init_gui()
    if sys.platform == "win32" and tk_root:
        del sys.modules["win32api"]
        del sys.modules["win32com"]
        # Some py2exe-compiled .dll shell extensions set sys.frozen, which should only be set
        # for "frozen" py2exe .exe's; this causes problems with multiprocessing, so delete it
        try:
            del sys.frozen
        except AttributeError: pass

    phases = build_search_phases(loaded_wallet, phase, phase_transform)

    for phase_num, phase_params in enumerate(phases, 1):
        # Print Timestamp that this step occured
        print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ": ", end="")

        # Print a friendly message describing this phase's search settings
        print("Phase {}/{}: ".format(phase_num, len(phases)), end="")
        if phase_params["typos"] == 1:
            print("1 mistake", end="")
        else:
            print("up to {} mistakes".format(phase_params["typos"]), end="")
        if phase_params.get("big_typos"):
            if phase_params["big_typos"] == phase_params["typos"] == 1:
                print(" which can be an entirely different seed word.")
            else:
                print(", {} of which can be an entirely different seed word.".format(phase_params["big_typos"]))
        else:
            print(", excluding entirely different seed words.")

        # Perform this phase's search
        phase_params.setdefault("extra_args", []).extend(extra_args)
        phase_params.setdefault("arg_overrides", {}).update(btcr_overrides)

        mnemonic_found = run_btcrecover(**phase_params)

        if not listseeds:
            # Print Timestamp that this step occured
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ": Search Complete")

            if mnemonic_found:
                return " ".join(loaded_wallet.id_to_word(i) for i in mnemonic_found), loaded_wallet.get_path_coin()
            elif mnemonic_found is None:
                return None, loaded_wallet.get_path_coin()  # An error occurred or Ctrl-C was pressed inside btcrpass.main()
            elif loaded_wallet._savevalidseeds: # Don't give a message that seed isn't found, that isn't relevant in this instance
                pass
            else:
                print(" Seed not found" + ( ", sorry..." if phase_num==len(phases) else "" ))

    return False, None  # No error occurred; the mnemonic wasn't found

def show_mnemonic_gui(mnemonic_sentence, path_coin):
    """may be called *after* main() to display the successful result iff the GUI is in use

    :param mnemonic_sentence: the mnemonic sentence that was found
    :type mnemonic_sentence: unicode
    :rtype: None
    """
    assert tk_root
    global pause_at_exit
    padding = 6
    tk.Label(text="WARNING: seed information is sensitive, carefully protect it and do not share", fg="red") \
        .pack(padx=padding, pady=padding)
    tk.Label(text="Seed found:").pack(padx=padding, pady=padding)
    if isinstance(loaded_wallet, WalletSLIP39Seed):
        tk.Label(
            text="NOTE: SLIP39 seed recovery matches checksums, so needs to be manually verified",
            fg="red",
        ).pack(padx=padding, pady=padding)
    elif isinstance(loaded_wallet, WalletAezeed) and getattr(
        loaded_wallet, "_checksum_only_mode", False
    ):
        tk.Label(
            text=(
                "NOTE: aezeed recovery ran without address checks; verify the "
                "seed on your wallet before use."
            ),
            fg="red",
        ).pack(padx=padding, pady=padding)

    entry = tk.Entry(width=120, readonlybackground="white")
    entry.insert(0, mnemonic_sentence)
    entry.config(state="readonly")
    entry.select_range(0, tk.END)
    entry.pack(fill=tk.X, expand=True, padx=padding, pady=padding)

    tk.Label(text="If this tool helped you to recover funds, please consider donating 1% of what you recovered, in your crypto of choice to:") \
        .pack(padx=padding, pady=padding)

    donation = tk.Listbox(tk_root)
    donation.insert(1, "BTC: 37N7B7sdHahCXTcMJgEnHz7YmiR4bEqCrS ")
    donation.insert(2, " ")
    donation.insert(3, "BCH: qpvjee5vwwsv78xc28kwgd3m9mnn5adargxd94kmrt ")
    donation.insert(4, " ")
    donation.insert(5, "LTC: M966MQte7agAzdCZe5ssHo7g9VriwXgyqM ")
    donation.insert(6, " ")
    donation.insert(7, "ETH: 0x72343f2806428dbbc2C11a83A1844912184b4243 ")
    donation.insert(8, " ")

    # Selective Donation Addressess depending on path being recovered... (To avoid spamming the dialogue with shitcoins...)
    # TODO: Implement this better with a dictionary mapping in seperate PY file with BTCRecover specific donation addys... (Seperate from YY Channel)
    if path_coin == 28:
        donation.insert(9, "VTC: vtc1qxauv20r2ux2vttrjmm9eylshl508q04uju936n ")

    if path_coin == 22:
        donation.insert(9, "MONA: mona1q504vpcuyrrgr87l4cjnal74a4qazes2g9qy8mv ")

    if path_coin == 5:
        donation.insert(9, "DASH: Xx2umk6tx25uCWp6XeaD5f7CyARkbemsZG ")

    if path_coin == 121:
        donation.insert(9, "ZEN: znUihTHfwm5UJS1ywo911mdNEzd9WY9vBP7 ")

    if path_coin == 3:
        donation.insert(9, "DOGE: DMQ6uuLAtNoe5y6DCpxk2Hy83nYSPDwb5T ")

    donation.pack(fill=tk.X, expand=True, padx=padding, pady=padding)

    tk.Label(text="Just select the address for your coin of choice and copy the address with ctrl-c") \
        .pack(padx=padding, pady=padding)

    tk.Label(text="Find me on Reddit @ https://www.reddit.com/user/Crypto-Guide") \
        .pack(padx=padding, pady=padding)

    tk.Label(text="You may also consider donating to Gurnec, who created and maintained this tool until late 2017 @ 3Au8ZodNHPei7MQiSVAWb7NB2yqsb48GW4") \
        .pack(padx=padding, pady=padding)

    tk_root.deiconify()
    tk_root.lift()
    entry.focus_set()
    tk_root.mainloop()  # blocks until the user closes the window
    pause_at_exit = False

# Wallet classes live in wallets.py but remain bound in this module's namespace
# (same class objects) for the public surface and for identity checks; the
# import must stay at the end of the module so every helper the wallet classes
# star-import already exists.  Importing wallets also runs the
# @register_selectable_wallet_class decorators in original source order.
from .wallets import *  # noqa: E402,F401,F403
