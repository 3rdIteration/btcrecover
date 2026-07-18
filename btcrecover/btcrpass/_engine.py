# btcrpass.py -- btcrecover main library
# Copyright (C) 2014-2017 Christopher Gurnee
#               2020 Jefferson Nunn and Gaith
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


# TODO: put everything in a class?
# TODO: pythonize comments/documentation

__version__          =  "1.13.0-Cryptoguide"
__ordering_version__ = b"0.6.4"  # must be updated whenever password ordering changes
disable_security_warnings = True

BIP39_OPENCL_MEMORY_PER_THREAD_BYTES = 2 * 1024 ** 3  # ~2 GiB per worker

# On AMD APUs with unified memory the driver reports (a large share of) system
# RAM as "VRAM". Budgeting one ~2 GiB GPU worker per 2 GiB of that would try to
# claim all of system memory at once -- and each worker also needs CPU-side RAM
# for itself -- so only spend this fraction of the reported memory on GPU
# workers and leave the remainder as headroom for the OS and the workers.
OPENCL_UNIFIED_MEMORY_BUDGET_FRACTION = 0.5

# Import modules included in standard libraries
import sys, argparse, itertools, string, re, multiprocessing, signal, os, pickle, gc, \
       time, timeit, hashlib, collections, base64, struct, atexit, zlib, math, json, numbers, datetime, binascii, gzip

# Import modules bundled with BTCRecover
import btcrecover.opencl_helpers
from .. import success_alert
from ..trezor_common_mistakes import TREZOR_COMMON_MISTAKES
import lib.cardano.cardano_utils as cardano
from lib.eth_hash.auto import keccak
from lib.mnemonic_btc_com_tweaked import Mnemonic

module_leveldb_available = False
try:
    from lib.ccl_chrome_indexeddb import ccl_leveldb

    module_leveldb_available = True
except:
    pass

hashlib_ripemd160_available = False
# Enable functions that may not work for some standard libraries in some environments
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

# AES and ChaCha20-Poly1305 are provided by btcrecover.aes_backends,
# which prefers pycryptodome, falls back to bundled pure-Python
# implementations (and prints a warning when the slow path is used).
from btcrecover.aes_backends import AES, chacha20_poly1305_new

# secp256k1 public-key operations are provided by btcrecover.crypto_backends,
# which prefers coincurve, falls back to wallycore, and finally to a bundled
# pure-Python implementation (emitting a warning when the slow path is used).
from btcrecover.crypto_backends import (
    privkey_to_pubkey,
    pubkey_from_bytes,
    pubkey_to_bytes,
    multiply_pubkey,
    bytes_to_int,
    int_to_bytes_padded,
    GROUP_ORDER_INT,
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

# Eth Keystore Libraries
module_eth_keyfile_available = False
try:
    import eth_keyfile

    module_eth_keyfile_available = True
except:
    pass

# PY Crypto HD wallet module
py_crypto_hd_wallet_available = False
try:
    import py_crypto_hd_wallet

    py_crypto_hd_wallet_available = True
except:
    pass

# Shamir-Mnemonic module
shamir_mnemonic_available = False
try:
    import shamir_mnemonic

    from shamir_mnemonic.recovery import RecoveryState
    from shamir_mnemonic.shamir import generate_mnemonics
    from shamir_mnemonic.share import Share
    from shamir_mnemonic.utils import MnemonicError

    import click
    from click import style

    FINISHED = style("\u2713", fg="green", bold=True)
    EMPTY = style("\u2717", fg="red", bold=True)
    INPROGRESS = style("\u25cf", fg="yellow", bold=True)


    def error(s: str) -> None:
        click.echo(style("ERROR: ", fg="red") + s)

    shamir_mnemonic_available = True
except:
    pass

class _BlockIODecryptionError(Exception):
    pass

def _block_io_extract_pubkey(user_key, pin):
    """Decrypt a block.io user_key with pin; return compressed pubkey as hex bytes.

    Replaces lib.block_io.BlockIo.Helper.dynamicExtractKey using only stdlib,
    pycryptodome (already a dependency), and the ecdsa package.
    Raises _BlockIODecryptionError on wrong PIN (GCM auth failure).
    May raise binascii.Error if decrypted data is not valid hex (wrong PIN for ECB/CBC).
    """
    import base64
    from hashlib import pbkdf2_hmac, sha256 as _sha256

    algorithm = {
        "pbkdf2_salt": "",
        "pbkdf2_iterations": 2048,
        "pbkdf2_phase1_key_length": 16,
        "pbkdf2_phase2_key_length": 32,
        "aes_iv": None,
        "aes_cipher": "AES-256-ECB",
        "aes_auth_tag": None,
    }
    if "algorithm" in user_key:
        algorithm = user_key["algorithm"]

    half_iter = int(algorithm["pbkdf2_iterations"]) // 2
    salt = algorithm["pbkdf2_salt"].encode()
    phase1 = pbkdf2_hmac("sha256", pin.encode(), salt, half_iter,
                         int(algorithm["pbkdf2_phase1_key_length"]))
    aes_key = pbkdf2_hmac("sha256", binascii.hexlify(phase1), salt, half_iter,
                          int(algorithm["pbkdf2_phase2_key_length"]))

    data = base64.b64decode(user_key["encrypted_passphrase"])
    cipher_type = algorithm["aes_cipher"]
    try:
        if cipher_type == "AES-256-ECB":
            obj = AES.new(aes_key, AES.MODE_ECB)
            plaintext = obj.decrypt(data)
            plaintext = plaintext[:-plaintext[-1]]  # remove PKCS7 padding
        elif cipher_type == "AES-256-CBC":
            obj = AES.new(aes_key, AES.MODE_CBC, binascii.unhexlify(algorithm["aes_iv"]))
            plaintext = obj.decrypt(data)
            plaintext = plaintext[:-plaintext[-1]]
        elif cipher_type == "AES-256-GCM":
            obj = AES.new(aes_key, AES.MODE_GCM,
                          nonce=binascii.unhexlify(algorithm["aes_iv"]))
            plaintext = obj.decrypt_and_verify(
                data, binascii.unhexlify(algorithm["aes_auth_tag"]))
        else:
            raise Exception("Unsupported cipher: " + cipher_type)
    except (ValueError, KeyError):
        raise _BlockIODecryptionError("Invalid Secret PIN provided.")

    # plaintext is a hex-encoded passphrase; SHA256 of its bytes is the private key
    # binascii.unhexlify may raise binascii.Error for wrong PIN with ECB/CBC (garbage plaintext);
    # the caller handles this exception alongside _BlockIODecryptionError.
    private_key_bytes = _sha256(binascii.unhexlify(plaintext)).digest()

    import ecdsa as _ecdsa
    signing_key = _ecdsa.SigningKey.from_string(private_key_bytes, curve=_ecdsa.SECP256k1)
    vk_bytes = signing_key.get_verifying_key().to_string()  # 64 bytes: x‖y
    # Compressed public key: 0x02 prefix for even y, 0x03 for odd y (secp256k1 convention)
    prefix = b"\x02" if vk_bytes[63] % 2 == 0 else b"\x03"
    return binascii.hexlify(prefix + vk_bytes[:32])

# Modules dependant on SJCL
sjcl_available = False
try:
    from sjcl import SJCL
    sjcl_available = True
except:
    pass

# Nacl
nacl_available = False
try:
    import nacl.pwhash
    import nacl.secret

    nacl_available = True
except:
    pass

# Argument namespace populated by parse_arguments();
# initialized here to allow direct wallet class use in tests
args = argparse.Namespace()

passwordlist_file = None
initial_passwordlist = ()
passwordlist_allcached = False
passwordlist_first_line_num = 1
passwordlist_embedded_arguments = False

# Pre-built set of valid base58 byte values for fast character validation
# Base58 alphabet: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
_base58_bytes = frozenset(b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

searchfailedtext = "\nAll possible passwords (as specified in your tokenlist or passwordlist) have been checked and none are correct for this wallet. You could consider trying again with a different password list or expanded tokenlist..."

def load_customTokenWildcard(customTokenWildcardFile):
    customTokenWildcards = ['']
    if customTokenWildcardFile:
        try:
            customTokenWildcards_File = open(customTokenWildcardFile, "r", encoding="utf-8", errors='ignore')
            customTokenWildcards_Lines = customTokenWildcards_File.readlines()

            for customTokenWildcard in customTokenWildcards_Lines:
                customTokenWildcards.append(customTokenWildcard.strip())
            customTokenWildcards_File.close()
        except Exception as e:
            print(e)
    return customTokenWildcards

# Assemble and output some information about the current system and python environment.
def full_version():
    from struct import calcsize
    return "btcrecover {} on Python {} {}-bit, {}-bit unicodes, {}-bit ints".format(
        __version__,
        ".".join(str(i) for i in sys.version_info[:3]),
        calcsize(b"P") * 8,
        sys.maxunicode.bit_length(),
        sys.maxsize.bit_length() + 1
    )


# One of these two is typically called relatively early by parse_arguments()
def enable_unicode_mode():
    global io, tstr, tstr_from_stdin, tchr
    import locale, io
    tstr              = str
    preferredencoding = locale.getpreferredencoding()
    tstr_from_stdin   = lambda s: s if isinstance(s, str) else str(s, preferredencoding)
    tchr              = chr
#

################################### Configurables/Plugins ###################################
# wildcard sets, simple typo generators, and wallet support functions


# Recognized wildcard (e.g. %d, %a) types mapped to their associated sets
# of characters; used in expand_wildcards_generator()
# warning: these can't be the key for a wildcard set: digits 'i' 'b' '[' ',' ';' '-' '<' '>'
def init_wildcards(wildcard_custom_list_e = None,
                   wildcard_custom_list_f = None,
                   wildcard_custom_list_j = None,
                   wildcard_custom_list_k = None):
    global wildcard_sets, wildcard_keys, wildcard_nocase_sets, wildcard_re, \
           custom_wildcard_cache, backreference_maps, backreference_maps_sha1
    # N.B. that tstr() will not convert string.*case to Unicode correctly if the locale has
    # been set to one with a single-byte code page e.g. ISO-8859-1 (Latin1) or Windows-1252
    wildcard_sets = {
        tstr("H") : tstr(string.hexdigits),
        tstr("B") : tstr("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"),
        tstr("d") : tstr(string.digits),
        tstr("a") : tstr(string.ascii_lowercase),
        tstr("A") : tstr(string.ascii_uppercase),
        tstr("n") : tstr(string.ascii_lowercase + string.digits),
        tstr("N") : tstr(string.ascii_uppercase + string.digits),
        tstr("s") : tstr(" "),        # space
        tstr("l") : tstr("\n"),       # line feed
        tstr("r") : tstr("\r"),       # carriage return
        tstr("R") : tstr("\n\r"),     # newline characters
        tstr("t") : tstr("\t"),       # tab
        tstr("T") : tstr(" \t"),      # space and tab
        tstr("w") : tstr(" \r\n"),    # space and newline characters
        tstr("W") : tstr(" \r\n\t"),  # space, newline, and tab
        tstr("y") : tstr(string.punctuation),
        tstr("Y") : tstr(string.digits + string.punctuation),
        tstr("p") : tstr().join(map(tchr, range(33, 127))),  # all ASCII printable characters except whitespace
        tstr("P") : tstr().join(map(tchr, range(33, 127))) + tstr(" \r\n\t"),  # as above, plus space, newline, and tab
        tstr("q") : tstr().join(map(tchr, range(33, 127))) + tstr(" "),  # all ASCII printable characters plus whitespace (All characters that are easily available for a Trezor Passphrase via keyboard or touchscreen entry)
        tstr("U"): ''.join(chr(i) for i in range(65536)),  # All possible 16 bit unicode characters
        tstr("e"): load_customTokenWildcard(wildcard_custom_list_e), # %e and %f are special types of wildcards which can both be customised AND can occur multiple times, but always have the same value. (And can also include other types of wildcards)
        tstr("f"): load_customTokenWildcard(wildcard_custom_list_f),
        tstr("j"): load_customTokenWildcard(wildcard_custom_list_j), # %j and %k behave mostly like standard wildcards but can be entire words/strings and are loaded from a custom file
        tstr("k"): load_customTokenWildcard(wildcard_custom_list_k),
        # wildcards can be used to escape these special symbols
        tstr("%") : tstr("%"),
        tstr("^") : tstr("^"),
        tstr("S") : tstr("$"),  # the key is intentionally a capital "S", the value is a dollar sign
    }
    wildcard_keys = tstr().join(wildcard_sets)
    #
    # case-insensitive versions (e.g. %ia) of wildcard_sets for those which have them
    wildcard_nocase_sets = {
        tstr("a") : tstr(string.ascii_lowercase + string.ascii_uppercase),
        tstr("A") : tstr(string.ascii_uppercase + string.ascii_lowercase),
        tstr("n") : tstr(string.ascii_lowercase + string.ascii_uppercase + string.digits),
        tstr("N") : tstr(string.ascii_uppercase + string.ascii_lowercase + string.digits)
    }
    #
    wildcard_re = None
    custom_wildcard_cache   = dict()
    backreference_maps      = dict()
    backreference_maps_sha1 = None


# Simple typo generators produce (as an iterable, e.g. a tuple, generator, etc.)
# zero or more alternative typo strings which can replace a single character. If
# more than one string is produced, all combinations are tried. If zero strings are
# produced (e.g. an empty tuple), then the specified input character has no typo
# alternatives that can be tried (e.g. you can't change the case of a caseless char).
# They are called with the full password and an index into that password of the
# character which will be replaced.
#
def typo_repeat(p, i): return 2 * p[i],  # A single replacement of len 2.
def typo_delete(p, i): return tstr(""),  # A single replacement of len 0.
def typo_case(p, i):                     # Returns a single replacement or no
    swapped = p[i].swapcase()            # replacement if it's a caseless char.
    return (swapped,) if swapped != p[i] else ()
#
def typo_closecase(p, i):  #  Returns a swapped case only when case transitions are nearby
    cur_case_id = case_id_of(p[i])  # (case_id functions defined in the Password Generation section)
    if cur_case_id == UNCASED_ID: return ()
    if i==0 or i+1==len(p) or \
            case_id_changed(case_id_of(p[i-1]), cur_case_id) or \
            case_id_changed(case_id_of(p[i+1]), cur_case_id):
        return p[i].swapcase(),
    return ()
#
def typo_replace_wildcard(p, i): return [e for e in typos_replace_expanded if e != p[i]]

def typo_map(p, i):
    returnVal = "".join(list(typos_map.get(p[i], ())))
    return returnVal

# (typos_replace_expanded and typos_map are initialized from args.typos_replace
# and args.typos_map respectively in parse_arguments() )
#
# a dict: command line argument name is: "typos-" + key_name; associated value is
# the generator function from above; this dict MUST BE ORDERED to prevent the
# breakage of --skip and --restore features (the order can be arbitrary, but it
# MUST be repeatable across runs and preferably across implementations)
simple_typos = collections.OrderedDict()
simple_typos["repeat"]    = typo_repeat
simple_typos["delete"]    = typo_delete
simple_typos["case"]      = typo_case
simple_typos["closecase"] = typo_closecase
simple_typos["replace"]   = typo_replace_wildcard
simple_typos["map"]       = typo_map
#
# a dict: typo name (matches typo names in the dict above) mapped to the options
# that are passed to add_argument; this dict is only ordered for cosmetic reasons
simple_typo_args = collections.OrderedDict()
simple_typo_args["repeat"]    = dict( action="store_true",       help="repeat (double) a character" )
simple_typo_args["delete"]    = dict( action="store_true",       help="delete a character" )
simple_typo_args["case"]      = dict( action="store_true",       help="change the case (upper/lower) of a letter" )
simple_typo_args["closecase"] = dict( action="store_true",       help="like --typos-case, but only change letters next to those with a different case")
simple_typo_args["map"]       = dict( metavar="FILE",            help="replace specific characters based on a map file" )
simple_typo_args["replace"]   = dict( metavar="WILDCARD-STRING", help="replace a character with another string or wildcard" )


# A class decorator which adds a wallet class to the registered list
wallet_types       = []
wallet_types_by_id = {}
def register_wallet_class(cls):
    global wallet_types, wallet_types_by_id
    wallet_types.append(cls)
    try:
        assert cls.data_extract_id() not in wallet_types_by_id,\
            "register_wallet_class: registered wallet types must have unique data_extract_id's"
        wallet_types_by_id[cls.data_extract_id()] = cls
    except AttributeError:
        pass

    return cls

# Snapshot of the default (decorator-registered) wallet set, captured lazily the
# first time the registry is cleared so it can be restored later. This matters
# when password wallet loading and seed autodetection (which calls
# clear_registered_wallets() to swap in the seed-detecting wallet classes) run in
# the same process -- e.g. the MCP server or the test suite.
_default_wallet_types = None
_default_wallet_types_by_id = None

# Clears the current set of registered wallets (including those registered by default below)
def clear_registered_wallets():
    global wallet_types, wallet_types_by_id, _default_wallet_types, _default_wallet_types_by_id
    if _default_wallet_types is None:
        _default_wallet_types       = list(wallet_types)
        _default_wallet_types_by_id = dict(wallet_types_by_id)
    wallet_types       = []
    wallet_types_by_id = {}

# Restores the default wallet set captured before the first clear_registered_wallets()
# call (a no-op if the registry was never cleared). Use this before loading a
# password wallet in a process that may have switched to seed autodetection.
def restore_default_registered_wallets():
    global wallet_types, wallet_types_by_id
    if _default_wallet_types is not None:
        wallet_types       = list(_default_wallet_types)
        wallet_types_by_id = dict(_default_wallet_types_by_id)


# The max wallet file size in bytes (prevents trying to load huge files which clearly aren't wallets)
MAX_WALLET_FILE_SIZE = 64 * 2**20  # 64 MiB

# Loads a wallet object and returns it (possibly for external libraries to use)
def load_wallet(wallet_filename):
    # Ask each registered wallet type if the file might be of their type,
    # and if so load the wallet
    uncertain_wallet_types = []
    try:
        with open(wallet_filename, "rb") as wallet_file:
            for wallet_type in wallet_types:
                found = wallet_type.is_wallet_file(wallet_file)
                if found:
                    wallet_file.close()
                    return wallet_type.load_from_filename(wallet_filename)
                elif found is None:  # None means it might still be this type of wallet...
                    uncertain_wallet_types.append(wallet_type)
    except PermissionError: #Metamask wallets can be a folder which may throw a PermissionError or IsADirectoryError
        try:
            return WalletMetamask.load_from_filename(wallet_filename)
        except Exception:
            raise ValueError("not a recognized wallet (directory load failed)")
    except IsADirectoryError:
        try:
            return WalletMetamask.load_from_filename(wallet_filename)
        except Exception:
            raise ValueError("not a recognized wallet (directory load failed)")

    # If the wallet type couldn't be definitively determined, try each
    # questionable type (which must raise ValueError on a load failure)
    uncertain_errors = []
    for wallet_type in uncertain_wallet_types:
        try:
            return wallet_type.load_from_filename(wallet_filename)
        except Exception as e:
            uncertain_errors.append(wallet_type.__name__ + ": " + str(e))

    error_exit("unrecognized wallet format" +
        ("; heuristic parser(s) reported:\n    " + "\n    ".join(uncertain_errors) if uncertain_errors else "") )

# Loads a wallet object into the loaded_wallet global from a filename
def load_global_wallet(wallet_filename):
    global loaded_wallet
    loaded_wallet = load_wallet(wallet_filename)

# Given a base64 string that was produced by one of the extract-* scripts, determines
# the wallet type and sets the loaded_wallet global to a corresponding wallet object
def load_from_base64_key(key_crc_base64):
    global loaded_wallet

    try:   key_crc_data = base64.b64decode(key_crc_base64)
    except TypeError: error_exit("encrypted key data is corrupted (invalid base64)")

    # Check the CRC
    if len(key_crc_data) < 8:
        error_exit("encrypted key data is corrupted (too short)")
    key_data = key_crc_data[:-4]
    (key_crc,) = struct.unpack(b"<I", key_crc_data[-4:])
    if zlib.crc32(key_data) & 0xffffffff != key_crc:
        error_exit("encrypted key data is corrupted (failed CRC check)")

    wallet_type = wallet_types_by_id.get(key_data[:2].decode())

    if not wallet_type:
        print("Wallet Types:", wallet_types_by_id)
        error_exit("unrecognized encrypted key type '" + key_data[:2].decode() + "'")

    loaded_wallet = wallet_type.load_from_data_extract(key_data[3:])
    return key_crc


# Load the OpenCL libraries and return a list of available devices
cl_devices_avail = None
def get_opencl_devices():
    """Return a cached list of available OpenCL devices."""
    global pyopencl, numpy, cl_devices_avail
    if cl_devices_avail is None:
        try:
            import pyopencl, numpy
            platforms = pyopencl.get_platforms()
            devices = []
            for p in platforms:
                for d in p.get_devices():
                    if d.available == 1 and d.profile == "FULL_PROFILE" and d.endian_little == 1:
                        devices.append(d)
            cl_devices_avail = devices
        except ImportError as e:
            print("Warning:", e, file=sys.stderr)
            cl_devices_avail = []
        except pyopencl.LogicError as e:
            if "platform not found" not in str(e):
                raise  # unexpected error
            cl_devices_avail = []  # PyOpenCL loaded OK but didn't find any supported hardware
    return cl_devices_avail


# Estimate the # of bits of entropy per byte in a string using a simple histogram estimator
def est_entropy_bits(data):
    hist_bins = [0] * 256
    for byte in data:
        hist_bins[byte] += 1
    entropy_bits = 0.0
    for frequency in hist_bins:
        if frequency:
            prob = float(frequency) / len(data)
            entropy_bits += prob * math.log(prob, 2)
    return entropy_bits * -1

# Prompt user for a password (possibly containing Unicode characters)
def prompt_unicode_password(prompt, error_msg):
    assert isinstance(prompt, str), "getpass() doesn't support Unicode on all platforms"
    from getpass import getpass
    encoding = sys.stdin.encoding or 'ASCII'
    if 'utf' not in encoding.lower():
        print("Warning: terminal does not support UTF; passwords with non-ASCII chars might not work", file=sys.stderr)
    prompt = "(note your password will not be displayed as you type)\n" + prompt
    password = getpass(prompt)
    if not password:
        error_exit(error_msg)
    return password

# Creates two decryption functions (in global namespace), aes256_cbc_decrypt() and aes256_ofb_decrypt(),
# using either PyCrypto if it's available or a pure python library. The created functions each take
# three bytestring arguments: key, iv, ciphertext. ciphertext must be a multiple of 16 bytes, and any
# padding present is not stripped.
missing_pycrypto_warned = False
def load_aes256_library(force_purepython = False, warnings = True):
    global aes256_cbc_decrypt, aes256_ofb_decrypt, missing_pycrypto_warned
    if not force_purepython:
        try:
            import Crypto.Cipher.AES
            new_aes = Crypto.Cipher.AES.new
            aes256_cbc_decrypt = lambda key, iv, ciphertext: \
                new_aes(key, Crypto.Cipher.AES.MODE_CBC, iv).decrypt(ciphertext)
            aes256_ofb_decrypt = lambda key, iv, ciphertext: \
                new_aes(key, Crypto.Cipher.AES.MODE_OFB, iv).decrypt(ciphertext)
            return Crypto  # just so the caller can check which version was loaded
        except ImportError:
            pass
        # Try bundled pure-python AES backend
        try:
            from btcrecover.aes_backends import AES as _AES_Backend
            new_aes = _AES_Backend.new
            aes256_cbc_decrypt = lambda key, iv, ciphertext: \
                new_aes(key, _AES_Backend.MODE_CBC, iv).decrypt(ciphertext)
            aes256_ofb_decrypt = lambda key, iv, ciphertext: \
                new_aes(key, _AES_Backend.MODE_OFB, iv).decrypt(ciphertext)
            return _AES_Backend
        except ImportError:
            if warnings and not missing_pycrypto_warned:
                print("Warning: Can't find PyCrypto, using aespython instead", file=sys.stderr)
                missing_pycrypto_warned = True

    # This version is attributed to GitHub user serprex; please see the aespython
    # README.txt for more information. It measures over 30x faster than the more
    # common "slowaes" package (although it's still 30x slower than the PyCrypto)
    #

    from lib import aespython
    expandKey = aespython.key_expander.expandKey
    AESCipher = aespython.aes_cipher.AESCipher
    def aes256_decrypt_factory(BlockMode):
        def aes256_decrypt(key, iv, ciphertext):
            block_cipher  = AESCipher( expandKey(bytearray(key)) )
            stream_cipher = BlockMode(block_cipher, 16)
            stream_cipher.set_iv(bytearray(iv))
            plaintext = bytearray()
            for i in range(0, len(ciphertext), 16):
                plaintext.extend( stream_cipher.decrypt_block(bytearray(ciphertext[i:i+16])) )  # input must be a list
            return plaintext

        return aes256_decrypt
    aes256_cbc_decrypt = aes256_decrypt_factory(aespython.CBCMode)
    aes256_ofb_decrypt = aes256_decrypt_factory(aespython.OFBMode)
    return aespython  # just so the caller can check which version was loaded


# Creates a key derivation function (in global namespace) named pbkdf2_hmac() using either the
# hashlib.pbkdf2_hmac from Python if it's available, or a pure python library (passlib).
# The created function takes a hash name, two bytestring arguments and two integer arguments:
# hash_name (e.g. b"sha1"), password, salt, iter_count, key_len (the length of the returned key)
missing_pbkdf2_warned = False
def load_pbkdf2_library(force_purepython = False, warnings = True):
    global pbkdf2_hmac, missing_pbkdf2_warned
    if not force_purepython:
        try:
            pbkdf2_hmac = hashlib.pbkdf2_hmac
            return hashlib  # just so the caller can check which version was loaded
        except AttributeError:
            if warnings and not missing_pbkdf2_warned:
                print("Warning: Can't load hashlib.pbkdf2_hmac, using passlib instead", file=sys.stderr)
                missing_pbkdf2_warned = True
    #
    import lib.passlib.crypto.digest
    pbkdf2_hmac = lib.passlib.crypto.digest.pbkdf2_hmac
    return lib.passlib  # just so the caller can check which version was loaded


################################### Argument Parsing ###################################


# Replace the builtin print with one which won't die when attempts are made to print
# unicode strings which contain characters unsupported by the destination console
#
builtin_print = print
#
def safe_print(*args, **kwargs):
    if kwargs.get("file") in (None, sys.stdout, sys.stderr):
        builtin_print(*_do_safe_print(*args, **kwargs), **kwargs)
    else:
        builtin_print(*args, **kwargs)
#
def _do_safe_print(*args, **kwargs):
    try:
        encoding = kwargs.get("file", sys.stdout).encoding or "ascii"
    except AttributeError:
        encoding = "ascii"
    converted_args = []
    for arg in args:
        #if isinstance(arg, str):
        #    arg = arg.encode(encoding, errors="replace")
        converted_args.append(arg)
    return converted_args
#
#print = safe_print

# Calls sys.exit with an error message, taking unnamed arguments as print() does
def error_exit(*messages):
    sys.exit(" ".join(map(str, _do_safe_print("Error:", *messages))))

# Ensures all chars in the string fall inside the acceptable range for the current mode
def check_chars_range(s, error_msg, no_replacement_chars=False):
    assert isinstance(s, tstr), "check_chars_range: s is of " + str(tstr)
    if tstr != str:
        # For ASCII mode, checks that the input string's chars are all 7-bit US-ASCII
        for c in s:
            if ord(c) > 127:  # 2**7 - 1
                error_exit(error_msg, "has character with code point", ord(c), "(", c , ")", "> max (127 / ASCII)\n"
                                      "(see the Unicode Support section in the Tutorial and the --utf8 option)")
    else:
        # For Unicode mode, a REPLACEMENT CHARACTER indicates a failed conversion from UTF-8
        if no_replacement_chars and "\uFFFD" in s:
            error_exit(error_msg, "contains an invalid UTF-8 byte sequence")
        # For UTF-16 (a.k.a. "narrow" Python Unicode) builds, checks that the input unicode
        # string has no surrogate pairs (all chars fit inside one UTF-16 code unit)
        if sys.maxunicode < 65536:  # 2**16
            for c in s:
                c = ord(c)
                if 0xD800 <= c <= 0xDBFF or 0xDC00 <= c <= 0xDFFF:
                    error_exit(error_msg, "has character with code point > max ("+str(sys.maxunicode)+" / Unicode BMP)")


# Returns an (order preserved) list or string with duplicate elements removed
# (if input is a string, returns a string, otherwise returns a list)
# (N.B. not a generator function, so faster for small inputs, not for large)
def duplicates_removed(iterable):
    if args.no_dupchecks >= 4:
        if isinstance(iterable, str) or isinstance(iterable, list):
            return iterable
        return list(iterable)
    seen = set()
    unique = []
    for x in iterable:
        if x not in seen:
            unique.append(x)
            seen.add(x)
    if len(unique) == len(iterable) and (isinstance(iterable, str) or isinstance(iterable, list)):
        return iterable
    elif isinstance(iterable, str):
        return type(iterable)().join(unique)
    return unique

# Converts a wildcard set into a string, expanding ranges and removing duplicates,
# e.g.: "hexa-fA-F" -> "hexabcdfABCDEF"
def build_wildcard_set(set_string):
    return duplicates_removed(re.sub(r"(.)-(.)", expand_single_range, set_string))
#
def expand_single_range(m):
    char_first, char_last = map(ord, m.groups())
    if char_first > char_last:
        raise ValueError("first character in wildcard range '"+chr(char_first)+"' > last '"+chr(char_last)+"'")
    return tstr().join(map(tchr, range(char_first, char_last+1)))

# Returns an integer count of valid wildcards in the string, or
# a string error message if any invalid wildcards are present
# (see expand_wildcards_generator() for more details on wildcards)
def count_valid_wildcards(str_with_wildcards, permit_contracting_wildcards = False):
    # Remove all valid wildcards, syntax checking the min to max ranges; if any %'s are left they are invalid
    try:
        valid_wildcards_removed, count = \
            re.subn(r"%(?:(?:(\d+),)?(\d+))?(?:i?[{}]|i?\[.+?\]{}|(?:;.+?;(\d+)?|;(\d+))?b)"
                    .format(wildcard_keys, "|[<>-]" if permit_contracting_wildcards else ""),
                    syntax_check_range, str_with_wildcards)
    except ValueError as e: return str(e)
    if tstr("%") in valid_wildcards_removed:
        invalid_wildcard_msg = "invalid wildcard (%) syntax (use %% to escape a %)"
        # If checking with permit_contracting_wildcards==True returns something different,
        # then the string must contain contracting wildcards (which were not permitted)
        if not permit_contracting_wildcards and \
                count_valid_wildcards(str_with_wildcards, True) != invalid_wildcard_msg:
            return "contracting wildcards are not permitted here"
        else:
            return invalid_wildcard_msg
    if count == 0: return 0
    # Expand any custom wildcard sets for the sole purpose of checking for exceptions (e.g. %[z-a])
    # We know all wildcards present have valid syntax, so we don't need to use the full regex, but
    # we do need to capture %% to avoid parsing this as a wildcard set (it isn't one): %%[not-a-set]
    for wildcard_set in re.findall(r"%[\d,i]*\[(.+?)\]|%%", str_with_wildcards):
        if wildcard_set:
            try:   re.sub(r"(.)-(.)", expand_single_range, wildcard_set)
            except ValueError as e: return tstr(e)
    return count
#
def syntax_check_range(m):
    minlen, maxlen, bpos, bpos2 = m.groups()
    if minlen and maxlen and int(minlen) > int(maxlen):
        raise ValueError("max wildcard length ("+maxlen+") must be >= min length ("+minlen+")")
    if maxlen and int(maxlen) == 0:
        print("Warning: %0 or %0,0 wildcards always expand to empty strings", file=sys.stderr)
    if bpos2: bpos = bpos2  # at most one of these is not None
    if bpos and int(bpos) == 0:
        raise ValueError("backreference wildcard position must be > 0")
    return tstr("")


# Loads the savestate from the more recent save slot in an autosave_file (into a global)
SAVESLOT_SIZE = 4096
def load_savestate(autosave_file):
    global savestate, autosave_nextslot
    savestate0 = savestate1 = first_error = None
    # Try to load both save slots, ignoring pickle errors at first
    autosave_file.seek(0)
    try:
        savestate0 = pickle.load(autosave_file)
    except Exception as e:
        first_error = e
    else:  assert autosave_file.tell() <= SAVESLOT_SIZE, "load_savestate: slot 0 data <= "+str(SAVESLOT_SIZE)+" bytes long"
    autosave_file.seek(0, os.SEEK_END)
    autosave_len = autosave_file.tell()
    if autosave_len > SAVESLOT_SIZE:  # if the second save slot is present
        autosave_file.seek(SAVESLOT_SIZE)
        try:
            savestate1 = pickle.load(autosave_file)
        except Exception: pass
        else:  assert autosave_file.tell() <= 2*SAVESLOT_SIZE, "load_savestate: slot 1 data <= "+str(SAVESLOT_SIZE)+" bytes long"
    else:
        # Convert an old format file to a new one by making it at least SAVESLOT_SIZE bytes long
        autosave_file.write((SAVESLOT_SIZE - autosave_len) * b"\0")
    #
    # Determine which slot is more recent, and use it
    if savestate0 and savestate1:
        use_slot = 0 if savestate0["skip"] >= savestate1["skip"] else 1
    elif savestate0:
        if autosave_len > SAVESLOT_SIZE:
            print("Warning: Data in second autosave slot was corrupted, using first slot", file=sys.stderr)
        use_slot = 0
    elif savestate1:
        print("Warning: Data in first autosave slot was corrupted, using second slot", file=sys.stderr)
        use_slot = 1
    else:
        print("Warning: Data in both primary and backup autosave slots is corrupted", file=sys.stderr)
        raise first_error
    if use_slot == 0:
        savestate = savestate0
        autosave_nextslot =  1
    else:
        assert use_slot == 1
        savestate = savestate1
        autosave_nextslot =  0


# Converts a file-like object into a new file-like object with an added peek() method, e.g.:
#   file = open(filename)
#   peekable_file = MakePeekable(file)
#   next_char = peekable_file.peek()
#   assert next_char == peekable_file.read(1)
# Do not take references of the member functions, e.g. don't do this:
#   tell_ref = peekable_file.tell
#   print peekable_file.peek()
#   location = tell_ref(peekable_file)       # will be off by one;
#   assert location == peekable_file.tell()  # will assert
class MakePeekable(object):
    def __new__(cls, file):
        if isinstance(file, MakePeekable):
            return file
        else:
            self         = object.__new__(cls)
            self._file   = file
            self._peeked = b""
            return self
    #
    def peek(self):
        if not self._peeked:
            if hasattr(self._file, "peek"):
                real_peeked = self._file.peek(1)
                if len(real_peeked) >= 1:
                    return real_peeked[0]
            self._peeked = self._file.read(1)
        return self._peeked
    #
    def read(self, size = -1):
        if size == 0: return tstr("")
        peeked = self._peeked
        self._peeked = b""
        return peeked + self._file.read(size - 1) if peeked else self._file.read(size)
    def readline(self, size = -1):
        if size == 0: return tstr("")
        peeked = self._peeked
        self._peeked = b""
        if peeked == b"\n": return peeked # A blank Unix-style line (or OS X)
        if peeked == b"\r":               # A blank Windows or MacOS line
            if size == 1:
                return peeked
            if self.peek() == b"\n":
                peeked = self._peeked
                self._peeked = b""
                return b"\r"+peeked       # A blank Windows-style line
            return peeked                 # A blank MacOS-style line (not OS X)
        return peeked + self._file.readline(size - 1) if peeked else self._file.readline(size)
    def readlines(self, size = -1):
        lines = []
        while self._peeked:
            lines.append(self.readline())
        return lines + self._file.readlines(size)  # (this size is just a hint)
    #
    def __iter__(self):
        return self

    def __next__(self):
        return self.readline() if self._peeked else self._file.__next__()
    #
    reset_before_calling = {"seek", "tell", "truncate", "write", "writelines"}
    def __getattr__(self, name):
        if self._peeked and name in MakePeekable.reset_before_calling:
            self._file.seek(-1, os.SEEK_CUR)
            self._peeked = b""
        return getattr(self._file, name)
    #
    def close(self):
        self._peeked = b""
        self._file.close()


# Opens a new or returns an already-opened file, if it passes the specified constraints.
# * Only examines one file: if filename == "__funccall" and funccall_file is not None,
#   use it. Otherwise if filename is not None, use it. Otherwise if default_filename
#   exists, use it (possibly with its extension duplicated). Otherwise, return None.
# * After deciding which one file to potentially use, check it against the require_data
#   or new_or_empty "no-exception" constraints and just return None if either fails.
#   (These are "soft" fails which don't raise exceptions.)
# * Tries to open (if not already opened) and return the file, letting any exception
#   raised by open (a "hard" fail) to pass up.
# * For Unicode builds (when tstr == unicode), returns an io.TextIOBase which produces
#   unicode strings if and only if mode is text (is not binary / does not contain "b").
# * The results of opening stdin more than once are undefined.
def open_or_use(filename, mode = "r",
        funccall_file    = None,   # already-opened file used if filename == "__funccall"
        permit_stdin     = None,   # when True a filename == "-" opens stdin
        default_filename = None,   # name of file that can be opened if filename == None
        require_data     = None,   # open if file is non-empty, else return None
        new_or_empty     = None,   # open if file is new or empty, else return None
        make_peekable    = None,   # the returned file object is given a peek method
        decoding_errors  = None):  # the Unicode codec error mode (default: strict)
    assert not(permit_stdin and require_data), "open_or_use: stdin cannot require_data"
    assert not(permit_stdin and new_or_empty), "open_or_use: stdin is never new_or_empty"
    assert not(require_data and new_or_empty), "open_or_use: can either require_data or be new_or_empty"
    #
    # If the already-opened file was requested
    if funccall_file and filename == "__funccall":
        if require_data or new_or_empty:
            funccall_file.seek(0, os.SEEK_END)
            if funccall_file.tell() == 0:
                # The file is empty; if it shouldn't be:
                if require_data: return None
            else:
                funccall_file.seek(0)
                # The file has contents; if it shouldn't:
                if new_or_empty: return None
        if tstr == str:
            if "b" in mode:
                assert not isinstance(funccall_file, io.TextIOBase), "already opened file not an io.TextIOBase; produces bytes"
            else:
                assert isinstance(funccall_file, io.TextIOBase), "already opened file isa io.TextIOBase producing unicode"
        return MakePeekable(funccall_file) if make_peekable else funccall_file;
    #
    if permit_stdin and filename == "-":
        if tstr == str and "b" not in mode:
            sys.stdin = io.open(sys.stdin.fileno(), mode,
                                encoding= sys.stdin.encoding or "utf_8_sig", errors= decoding_errors)
        if make_peekable:
            sys.stdin = MakePeekable(sys.stdin)
        return sys.stdin
    #
    # If there was no file specified, but a default exists
    if not filename and default_filename:
        if permit_stdin and default_filename == "-":
            if tstr == str and "b" not in mode:
                sys.stdin = io.open(sys.stdin.fileno(), mode,
                                    encoding= sys.stdin.encoding or "utf_8_sig", errors= decoding_errors)
            if make_peekable:
                sys.stdin = MakePeekable(sys.stdin)
            return sys.stdin
        if os.path.isfile(default_filename):
            filename = default_filename
        else:
            # For default filenames only, try doubling the extension to help users who don't realize
            # their shell is hiding the extension (and thus the actual file has "two" extensions)
            default_filename, default_ext = os.path.splitext(default_filename)
            default_filename += default_ext + default_ext
            if os.path.isfile(default_filename):
                filename = default_filename
    if not filename:
        return None
    #
    filename = tstr_from_stdin(filename)
    if require_data and (not os.path.isfile(filename) or os.path.getsize(filename) == 0):
        return None
    if new_or_empty and os.path.exists(filename) and (os.path.getsize(filename) > 0 or not os.path.isfile(filename)):
        return None
    #
    if tstr == str and "b" not in mode:
        if filename[-3:] == ".gz":
            mode = mode + "t"
            file = gzip.open(filename, mode, encoding="utf_8_sig", errors=decoding_errors)
        else:
            file = io.open(filename, mode, encoding="utf_8_sig", errors=decoding_errors)
    else:
        if filename[-3:] == ".gz":
            file = gzip.open(filename, mode)
        else:
            file = open(filename, mode)
    #
    if "b" not in mode:
        if file.read(5) == br"{\rtf":
            error_exit(filename, "must be a plain text file (.txt), not a Rich Text File (.rtf)")
        file.seek(0)
    #
    return MakePeekable(file) if make_peekable else file


# Enables pause-before-exit (at most once per program run) if stdin is interactive (a tty)
pause_registered = None
def enable_pause():
    global pause_registered
    if pause_registered is None:
        if sys.stdin.isatty():
            atexit.register(lambda: not multiprocessing.current_process().name.startswith("PoolWorker-") and
                                    input("Press Enter to exit ..."))
            pause_registered = True
        else:
            print("Warning: Ignoring --pause since stdin is not interactive (or was redirected)", file=sys.stderr)
            pause_registered = False


ADDRESSDB_DEF_FILENAME = "addresses.db"  # copied from btrseed

# can raise an exception on some platforms
try:                  logical_cpu_cores = multiprocessing.cpu_count()
except Exception: logical_cpu_cores = 1

# The CLI argument-parser definitions (parser_common, init_parser_common,
# register_simple_typo, ...) live in btcrecover.btcrpass.cli; the public names
# are re-imported here so the long-standing btcrpass.* surface is unchanged.
from . import cli
from .cli import init_parser_common, parser_common, prog, register_simple_typo

# A basic function which takes a list of arguments and strips the ones that will change the passwords that will be checked in some way
# This is called twice when trynig to restore an autosave file. (Once with the arguments from autosave file and once with current arguments passed)
def clean_autosave_args(argList, listName):
    # Simple list of parameters and a boolean to indicate whether there is an associated parameter which needs to also be removed from the list
    non_modifying_args = {("--dsw", False),
                          ("--enable-opencl", False),
                          ("--opencl-workgroup-size", True),
                          ("--opencl-platform", True),
                          ("--opencl-devices", True),
                          ("--no-eta", False),
                          ("--no-dupchecks", False),
                          ("--no-progress", False),
                          ("--enable-gpu", False),
                          ("--global-ws", True),
                          ("--local-ws", True),
                          ("--int-rate", True),
                          ("--threads", True),
                          ("--max-eta", True),
                          ("--skip-mnemonic-checksum", False),
                          ("--autosave", True)
                          }

    import copy
    working_arglist = copy.deepcopy(argList) # Make a copy so we don't mess with the original arguments list

    # Strip non-modifying args from argument lists
    for arg, parameter in non_modifying_args:
        try:
            arg_index = working_arglist.index(arg)

            if (parameter):
                print("Restore Autosave: Permitting Non-Modifying Parameter from:", listName, arg,
                      working_arglist[arg_index + 1])
                del working_arglist[arg_index:arg_index + 2]
            else:
                print("Restore Autosave: Permitting Non-Modifying Parameterfrom:", listName, arg)
                del working_arglist[arg_index]

        except ValueError:
            pass

    return working_arglist

# Once parse_arguments() has completed, password_generator_factory() will return an iterator
# (actually a generator object) configured to generate all the passwords requested by the
# command-line options, and loaded_wallet.return_verified_password_or_false() can check
# passwords against the wallet or key that was specified. (Typically called with sys.argv[1:]
# as its only parameter followed by a call to main() to perform the actual password search.)
#
# wallet         - a custom wallet object which must implement
#                  return_verified_password_or_false() and which should be pickleable
#                  (instead of specifying a --wallet or --data-extract)
# base_iterator  - either an iterable or a generator function which produces the base
#                  (without typos) passwords to be checked; unless --no-eta is specified,
#                  it must be possible to iterate over all the passwords more than once
#                  (instead of specifying a --tokenlist or --passwordlist)
# perf_iterator  - a generator function which produces an infinite stream of unique
#                  passwords which is used iff a --performance test is specified
#                  (if omitted, the default perf iterator which generates strings is used)
# inserted_items - instead of specifying "--typos-insert items-to-insert", this can be
#                  an iterable of the items to insert (useful if the wildcard language
#                  is not flexible enough or if the items to insert are not strings)
# check_only     - (similar in concept to --regex-only) a boolean function accepting an
#                  item just before it is passed to return_verified_password_or_false()
#                  which should return False if the the item should not be checked.
#
# TODO: document kwds usage (as used by unit tests)
def parse_arguments(effective_argv, wallet = None, base_iterator = None,
                    perf_iterator = None, inserted_items = None, check_only = None,
                    disable_security_warning_param = False, arg_overrides = None, **kwds):
    # effective_argv is what we are effectively given, either via the command line, via embedded
    # options in the tokenlist file, or as a result of restoring a session, before any argument
    # processing or defaulting is done (unless it's is done by argparse). Each time effective_argv
    # is changed (due to reading a tokenlist or restore file), we redo parser.parse_args() which
    # changes args, so we only do this early on before most args processing takes place.
    #
    # arg_overrides is an optional {dest: value} mapping of already-typed option values applied
    # directly to the parsed namespace. It lets in-process callers (e.g. btcrseed, the API, a GUI)
    # pass structured configuration instead of encoding it as command-line strings for argparse to
    # re-parse. Because it is applied after *every* (re-)parse below, the overrides always win.

    def _finalize_parsed_args(parsed_args):
        # Apply typed overrides first so any logic below (and the processing that
        # follows) sees the final values.
        if arg_overrides:
            for _override_dest, _override_value in arg_overrides.items():
                setattr(parsed_args, _override_dest, _override_value)
        pcspeaker = getattr(parsed_args, "beep_on_find_pcspeaker", False)
        success_alert.configure_pc_speaker(pcspeaker)
        success_alert.set_beep_on_find(getattr(parsed_args, "beep_on_find", False) or pcspeaker)

    # If no args are present on the command line (e.g. user double-clicked the script
    # in the shell), enable --pause by default so user doesn't miss any error messages
    if not effective_argv: enable_pause()

    # Create a parser which can parse any supported option, and run it
    global args, passwordlist_first_line_num, passwordlist_embedded_arguments
    passwordlist_first_line_num = 1
    passwordlist_embedded_arguments = False
    cli.init_parser_common()
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-h", "--help",   action="store_true", help="show this help message and exit")
    parser.add_argument("--json",         action="store_true", help="print the final result as a single JSON object on stdout (human-readable output is redirected to stderr); intended for scripts and AI tools")
    parser.add_argument("--tokenlist",    metavar="FILE",      help="the list of tokens/partial passwords (required)")
    parser.add_argument("--keep-tokens-order", action="store_true",
                        help="try tokens in the order in which they are listed in the file, without trying their permutations")
    parser.add_argument("--seedgenerator", action="store_true",
                               help=argparse.SUPPRESS)  # Flag to be able to indicate to generators that we are doing seed generation, not password generation
    parser.add_argument("--mnemonic-length", type=int,
                               help=argparse.SUPPRESS)  # Argument used for generators in seed generation, not password generation
    parser.add_argument("--seed-transform-wordswaps", type=int,
                               help=argparse.SUPPRESS)  # Flag to be able to indicate to generators that we want to also try swapped words for seed generation
    parser.add_argument("--seed-transform-trezor-common-mistakes", type=int,
                               help=argparse.SUPPRESS)  # Flag to try Trezor common mistake substitutions during seed generation
    parser.add_argument("--max-tokens",   type=int, default=sys.maxsize, metavar="COUNT", help="enforce a max # of tokens included per guess")
    parser.add_argument("--min-tokens",   type=int, default=1,          metavar="COUNT", help="enforce a min # of tokens included per guess")
    parser._add_container_actions(cli.parser_common)
    parser.add_argument("--autosave",     metavar="FILE",      help="autosave (5 min) progress to or restore it from a file")
    parser.add_argument("--restore",      metavar="FILE",      help="restore progress and options from an autosave file (must be the only option on the command line)")
    parser.add_argument("--passwordlist", metavar="FILE", nargs="?", const="-", help="instead of using a tokenlist, read complete passwords (exactly one per line) from this file or from stdin")
    parser.add_argument("--has-wildcards",action="store_true", help="parse and expand wildcards inside passwordlists (default: wildcards are only parsed inside tokenlists)")
    parser.add_argument("--passwordlist-arguments", action="store_true", help="allow the first line of the passwordlist file to start with '#--' and supply additional command line options")
    parser.add_argument("--wildcard-custom-list-e",metavar="FILE", help="Path to a custom list file which will be used fr the %%e expanding wildcard")
    parser.add_argument("--wildcard-custom-list-f",metavar="FILE", help="Path to a custom list file which will be used fr the %%f expanding wildcard")
    parser.add_argument("--wildcard-custom-list-j",metavar="FILE", help="Path to a custom list file which will be used fr the %%j expanding wildcard")
    parser.add_argument("--wildcard-custom-list-k",metavar="FILE", help="Path to a custom list file which will be used fr the %%k expanding wildcard")

    #
    # Optional bash tab completion support
    try:
        import argcomplete
        argcomplete.autocomplete(parser)
    except ImportError:
        pass
    #
    args = parser.parse_args(effective_argv)
    _finalize_parsed_args(args)

    # Do this as early as possible so user doesn't miss any error messages
    if args.pause: enable_pause()

    if args.keep_tokens_order and not args.tokenlist:
        print("The --keep-tokens-order flag will be ignored since --tokenlist is not used")

    # Disable Security Warnings if parameter set...
    global disable_security_warnings
    if args.disablesecuritywarnings or disable_security_warning_param:
        disable_security_warnings = True
    else:
        disable_security_warnings = False

    # Set the character mode early-- it's used by a large portion of the
    # rest of this module (starting with the first call to open_or_use())
    enable_unicode_mode()

    # If a simple passwordlist or base_iterator is being provided, re-parse the command line with fewer options
    # (--help is handled directly by argparse in this case)
    if args.passwordlist or base_iterator:
        parser = argparse.ArgumentParser(add_help=True)
        parser.add_argument("--passwordlist", required=not base_iterator, nargs="?", const="-", metavar="FILE", help="instead of using a tokenlist, read complete passwords (exactly one per line) from this file or from stdin")
        parser.add_argument("--has-wildcards",action="store_true", help="parse and expand wildcards inside passwordlists (default: disabled for passwordlists)")
        parser.add_argument("--passwordlist-arguments", action="store_true", help="allow the first line of the passwordlist file to start with '#--' and supply additional command line options")
        parser.add_argument("--tokenlist", metavar="FILE", help="the list of tokens/partial passwords (required)")
        parser.add_argument("--max-tokens", type=int, default=sys.maxsize, metavar="COUNT",
                            help="enforce a max # of tokens included per guess")
        parser.add_argument("--min-tokens", type=int, default=1, metavar="COUNT",
                            help="enforce a min # of tokens included per guess")
        parser.add_argument("--seedgenerator", action="store_true",
                            help=argparse.SUPPRESS)  # Flag to be able to indicate to generators that we are doing seed generation, not password generation
        parser.add_argument("--keep-tokens-order", action="store_true",
                            help="try tokens in the order in which they are listed in the file, without trying their permutations")
        parser.add_argument("--mnemonic-length", type=int,
                            help=argparse.SUPPRESS)  # Argument used for generators in seed generation, not password generation
        parser.add_argument("--seed-transform-wordswaps", type=int,
                            help=argparse.SUPPRESS)  # Flag to be able to indicate to generators that we want to also try swapped words for seed generation
        parser.add_argument("--seed-transform-trezor-common-mistakes", type=int,
                            help=argparse.SUPPRESS)  # Flag to try Trezor common mistake substitutions during seed generation
        parser.add_argument("--wildcard-custom-list-e", metavar="FILE",
                            help="Path to a custom list file which will be used fr the %%e expanding wildcard")
        parser.add_argument("--wildcard-custom-list-f", metavar="FILE",
                            help="Path to a custom list file which will be used fr the %%f expanding wildcard")
        parser.add_argument("--wildcard-custom-list-j", metavar="FILE",
                            help="Path to a custom list file which will be used fr the %%j expanding wildcard")
        parser.add_argument("--wildcard-custom-list-k", metavar="FILE",
                            help="Path to a custom list file which will be used fr the %%k expanding wildcard")

        parser._add_container_actions(cli.parser_common)
        # Add these in as non-options so that args gets a copy of their values
        parser.set_defaults(autosave=False, restore=False)
        args = parser.parse_args(effective_argv)
        _finalize_parsed_args(args)

    # Manually handle the --help option, now that we know which help (tokenlist, not passwordlist) to print
    elif args.help:
        parser.print_help()
        sys.exit(0)

    # Version information is always printed by btcrecover.py, so just exit
    if args.version: sys.exit(0)

    if args.opencl_info:
        info = opencl_information()
        info.printfullinfo()
        exit(0)

    if args.performance and (base_iterator or args.passwordlist or args.tokenlist):
        error_exit("--performance cannot be used with --tokenlist or --passwordlist")

    if args.list_gpus:
        devices_avail = get_opencl_devices()  # all available OpenCL device objects
        if not devices_avail:
            error_exit("no supported GPUs found")
        for i, dev in enumerate(devices_avail, 1):
            print("#"+str(i), dev.name.strip())
        sys.exit(0)

    # If we're not --restoring nor using a passwordlist, try to open the tokenlist_file now
    # (if we are restoring, we don't know what to open until after the restore data is loaded)
    TOKENS_AUTO_FILENAME = "btcrecover-tokens-auto.txt"

    provided_passwordlist = kwds.get("passwordlist")

    if (not (args.restore or args.passwordlist or args.performance or base_iterator)) or (args.seedgenerator and not args.passwordlist):
        tokenlist_file = open_or_use(args.tokenlist, "r", kwds.get("tokenlist"),
            default_filename=TOKENS_AUTO_FILENAME, permit_stdin=True, make_peekable=True)
        if hasattr(tokenlist_file, "name") and tokenlist_file.name.startswith(TOKENS_AUTO_FILENAME):
            enable_pause()  # enabled by default when using btcrecover-tokens-auto.txt
    else:
        tokenlist_file = None

    if args.passwordlist_arguments and not args.passwordlist:
        error_exit("--passwordlist-arguments requires --passwordlist")

    if args.passwordlist and args.passwordlist_arguments:
        passwordlist_args_file = open_or_use(
            args.passwordlist,
            "r",
            provided_passwordlist,
            permit_stdin=True,
            decoding_errors="replace",
        )
        if passwordlist_args_file == sys.stdin:
            error_exit("--passwordlist-arguments cannot be used with stdin")
        first_line = passwordlist_args_file.readline()
        if not first_line:
            error_exit("--passwordlist-arguments requires a non-empty passwordlist file")
        stripped_first_line = first_line[1:].strip() if first_line.startswith("#") else None
        if not stripped_first_line or not stripped_first_line.startswith("--"):
            error_exit("--passwordlist-arguments requires the first line to begin with '#--'")
        print("Read additional options from passwordlist file: " + stripped_first_line, file=sys.stderr)
        passwordlist_args = stripped_first_line.split()
        effective_argv = passwordlist_args + effective_argv
        args = parser.parse_args(effective_argv)
        _finalize_parsed_args(args)
        if args.pause: enable_pause()
        for arg in passwordlist_args:
            if arg.startswith("--pas"):           # --passwordlist or --passwordlist-arguments
                error_exit("the --passwordlist option is not permitted inside a passwordlist file")
            elif arg.startswith("--to"):          # --tokenlist
                error_exit("the --tokenlist option is not permitted inside a passwordlist file")
            elif arg.startswith("--pe"):          # --performance
                error_exit("the --performance option is not permitted inside a passwordlist file")
            elif arg.startswith("--u"):           # --utf8
                error_exit("the --utf8 option is not permitted inside a passwordlist file")
        try:
            passwordlist_args_file.seek(0)
        except (AttributeError, io.UnsupportedOperation):
            pass
        if passwordlist_args_file not in (provided_passwordlist, None):
            passwordlist_args_file.close()
        passwordlist_first_line_num = 2
        passwordlist_embedded_arguments = True

    # If the first line of the tokenlist file starts with "#\s*--", parse it as additional arguments
    # (note that command line arguments can override arguments in this file)
    tokenlist_first_line_num = 1
    if tokenlist_file and tokenlist_file.peek() == "#": # if it's either a comment or additional args
        first_line = tokenlist_file.readline()[1:].strip()
        tokenlist_first_line_num = 2                     # need to pass this to parse_token_list
        if first_line.startswith("--"):                 # if it's additional args, not just a comment
            print("Read additional options from tokenlist file: "+first_line, file=sys.stderr)
            tokenlist_args = first_line.split()          # TODO: support quoting / escaping?
            effective_argv = tokenlist_args + effective_argv  # prepend them so that real argv takes precedence
            args = parser.parse_args(effective_argv)     # reparse the arguments
            _finalize_parsed_args(args)
            # Check this again as early as possible so user doesn't miss any error messages
            if args.pause: enable_pause()
            for arg in tokenlist_args:
                if arg.startswith("--to"):              # --tokenlist
                    error_exit("the --tokenlist option is not permitted inside a tokenlist file")
                elif arg.startswith("--pas"):           # --passwordlist
                    error_exit("the --passwordlist option is not permitted inside a tokenlist file")
                elif arg.startswith("--pe"):            # --performance
                    error_exit("the --performance option is not permitted inside a tokenlist file")
                elif arg.startswith("--u"):             # --utf8
                    error_exit("the --utf8 option is not permitted inside a tokenlist file")


    # There are two ways to restore from an autosave file: either specify --restore (alone)
    # on the command line in which case the saved arguments completely replace everything else,
    # or specify --autosave along with the exact same arguments as are in the autosave file.
    #
    global savestate, restored, autosave_file
    savestate = None
    restored  = False
    # If args.restore was specified, load and completely replace current arguments
    autosave_file = open_or_use(args.restore, "r+b", kwds.get("restore"))
    if autosave_file:
        if len(effective_argv) > 2 or "=" in effective_argv[0] and len(effective_argv) > 1:
            error_exit("the --restore option must be the only option when used")
        load_savestate(autosave_file)
        effective_argv = savestate["argv"]  # argv is effectively being replaced; it's reparsed below
        print("Restoring session:", " ".join(effective_argv))
        print("Last session ended having finished password #", savestate["skip"])
        restore_filename = args.restore      # save this before it's overwritten below
        args = parser.parse_args(effective_argv)
        _finalize_parsed_args(args)
        # Check this again as early as possible so user doesn't miss any error messages
        if args.pause: enable_pause()
        # If the order of passwords generated has changed since the last version, don't permit a restore
        restored_ordering_version = savestate.get("ordering_version")
        if restored_ordering_version != __ordering_version__:
            if restored_ordering_version == __ordering_version__ + b"-Unicode":
                args.utf8 = True  # backwards compatibility with versions < 0.15.0
            else:
                error_exit("autosave was created with an incompatible version of "+prog)
        assert args.autosave,         "parse_arguments: autosave option enabled in restored autosave file"
        assert not args.passwordlist, "parse_arguments: passwordlist option not specified in restored autosave file"
        # If --utf8 was specified in the autosave file, it's not too late
        # to change the character mode (we haven't yet called open_or_use())
        if args.utf8: enable_unicode_mode()
        #
        # We finally know the tokenlist filename; open it here
        tokenlist_file = open_or_use(args.tokenlist, "r", kwds.get("tokenlist"),
            default_filename=TOKENS_AUTO_FILENAME, permit_stdin=True, make_peekable=True)
        if hasattr(tokenlist_file, "name") and tokenlist_file.name.startswith(TOKENS_AUTO_FILENAME):
            enable_pause()  # enabled by default when using btcrecover-tokens-auto.txt
        # Display a warning if any options (all ignored) were specified in the tokenlist file
        if tokenlist_file and tokenlist_file.peek() == b"#": # if it's either a comment or additional args
            first_line = tokenlist_file.readline()
            tokenlist_first_line_num = 2                     # need to pass this to parse_token_list
            if re.match(r"#\s*--", first_line, re.UNICODE):  # if it's additional args, not just a comment
                print("Warning: all options loaded from restore file; ignoring options in tokenlist file '"+tokenlist_file.name+"'", file=sys.stderr)
        print("Using autosave file '"+restore_filename+"'")
        args.skip = savestate["skip"]  # override this with the most recent value
        restored = True  # a global flag for future reference
    #
    elif args.autosave:
        # If there's anything in the specified file, assume it's autosave data and try to load it
        autosave_file = open_or_use(args.autosave, "r+b", kwds.get("autosave"), require_data=True)
        if autosave_file:
            # Load and compare to current arguments
            load_savestate(autosave_file)
            restored_argv = savestate["argv"]
            print("Restoring session:", " ".join(restored_argv))
            print("Last session ended having finished password #", savestate["skip"])
            if restored_argv != effective_argv: # If the arguments provided are different to the save file, check if the difference actually makes a difference to password generation ordering/etc
                savecheck_restored_argv = clean_autosave_args(restored_argv, "AutoSaveFile")
                savecheck_effective_argv = clean_autosave_args(effective_argv, "CurrentArgs")

                args_difference = list(set(savecheck_effective_argv).symmetric_difference(set(savecheck_restored_argv)))

                if len(args_difference) > 0: # If none of the differences matter, let it go, otherwise exit...
                    print()
                    print("ERROR: Can't restore previous session: the command line options have changed in a way that will impact password generation.")
                    print()
                    print("Non-Changeable Args from Autosave:", " ".join(savecheck_restored_argv))
                    print()
                    print("Non-Changeable Args from Current Command:", " ".join(savecheck_effective_argv))
                    print()
                    error_exit("Disallowed Arguments Difference:", " ".join(args_difference))

            # If the order of passwords generated has changed since the last version, don't permit a restore
            if __ordering_version__ != savestate.get("ordering_version"):
                error_exit("autosave was created with an incompatible version of "+prog)
            print("Using autosave file '"+args.autosave+"'")
            args.skip = savestate["skip"]  # override this with the most recent value
            restored = True  # a global flag for future reference
        #
        # Else if the specified file is empty or doesn't exist:
        else:
            assert not (wallet or base_iterator or inserted_items), \
                        '--autosave is not supported with custom parse_arguments()'
            if args.listpass:
                print("Warning: --autosave is ignored with --listpass", file=sys.stderr)
            elif args.performance:
                print("Warning: --autosave is ignored with --performance", file=sys.stderr)
            else:
                # create an initial savestate that is populated throughout the rest of parse_arguments()
                savestate = dict(argv = effective_argv, ordering_version = __ordering_version__)


    # Do some basic globals initialization; the rest are all done below
    init_wildcards(args.wildcard_custom_list_e, args.wildcard_custom_list_f, args.wildcard_custom_list_j, args.wildcard_custom_list_k)
    init_password_generator()

    # Do a bunch of argument sanity checking

    # Either we're using a passwordlist file (though it's not yet opened),
    # or we're using a tokenlist file which should have been found and opened by now,
    # or we're running a performance test (and neither is open; already checked above).
    if not (args.passwordlist or tokenlist_file or args.performance or base_iterator or
            ((args.correct_wallet_password or args.correct_wallet_password) and (args.dump_wallet or args.dump_privkeys))):
        error_exit("argument --tokenlist or --passwordlist is required (or file "+TOKENS_AUTO_FILENAME+" must be present)")

    if tokenlist_file and args.max_tokens < args.min_tokens:
        error_exit("--max-tokens must be greater than --min-tokens")

    assert not (inserted_items and args.typos_insert), "can't specify inserted_items with --typos-insert"
    if inserted_items:
        args.typos_insert = True

    # Sanity check the --max-typos-* options
    for typo_name in itertools.chain(("swap",), simple_typos.keys(), ("insert",)):
        typo_max = args.__dict__["max_typos_"+typo_name]
        if typo_max < sys.maxsize:
            #
            # Sanity check for when a --max-typos-* is specified, but the corresponding --typos-* is not
            if not args.__dict__["typos_"+typo_name]:
                print("Warning: --max-typos-"+typo_name+" is ignored without --typos-"+typo_name, file=sys.stderr)
            #
            # Sanity check for a a --max-typos-* <= 0
            elif typo_max <= 0:
                print("Warning: --max-typos-"+typo_name, typo_max, "disables --typos-"+typo_name, file=sys.stderr)
                args.__dict__["typos_"+typo_name] = None
            #
            # Sanity check --max-typos-* vs the total number of --typos
            elif args.typos and typo_max > args.typos:
                print("Warning: --max-typos-"+typo_name+" ("+str(typo_max)+") is limited by the number of --typos ("+str(args.typos)+")", file=sys.stderr)

    # Sanity check --typos--closecase
    if args.typos_closecase and args.typos_case:
        print("Warning: specifying --typos-case disables --typos-closecase", file=sys.stderr)
        args.typos_closecase = None

    # Build an ordered list of enabled simple typo generators. This list MUST be in the same relative
    # order as the items in simple_typos to prevent the breakage of --skip and --restore features
    global enabled_simple_typos
    enabled_simple_typos = tuple(
        generator for name,generator in simple_typos.items() if args.__dict__["typos_"+name])

    # Have _any_ (simple or otherwise) typo types been specified?
    any_typo_types_specified = enabled_simple_typos or \
        args.typos_capslock or args.typos_swap or args.typos_insert

    # Sanity check the values of --typos and --min-typos
    if not any_typo_types_specified:
        if args.min_typos > 0:
            error_exit("no passwords are produced when no type of typo is chosen, but --min-typos were required")
        if args.typos:
            print("Warning: --typos has no effect because no type of typo was chosen", file=sys.stderr)
    #
    else:
        if args.typos is None:
            if args.min_typos:
                print("Warning: --typos COUNT not specified; assuming same as --min_typos ("+str(args.min_typos)+")", file=sys.stderr)
                args.typos = args.min_typos
            else:
                print("Warning: --typos COUNT not specified; assuming 1", file=sys.stderr)
                args.typos = 1
        #
        elif args.typos < args.min_typos:
            error_exit("--min_typos must be less than --typos")
        #
        elif args.typos <= 0:
            print("Warning: --typos", args.typos, " disables all typos", file=sys.stderr)
            enabled_simple_typos = args.typos_capslock = args.typos_swap = args.typos_insert = inserted_items = None

    # If any simple typos have been enabled, set max_simple_typos and sum_max_simple_typos appropriately
    global max_simple_typos, sum_max_simple_typos
    if enabled_simple_typos:
        max_simple_typos = \
            [args.__dict__["max_typos_"+name] for name in simple_typos.keys() if args.__dict__["typos_"+name]]
        if min(max_simple_typos) == sys.maxsize:    # if none were specified
            max_simple_typos     = None
            sum_max_simple_typos = sys.maxsize
        elif max(max_simple_typos) == sys.maxsize:  # if one, but not all were specified
            sum_max_simple_typos = sys.maxsize
        else:                                      # else all were specified
            sum_max_simple_typos = sum(max_simple_typos)

    # Sanity check --max-adjacent-inserts (inserts are not a "simple" typo)
    if args.max_adjacent_inserts != 1:
        if not args.typos_insert:
            print("Warning: --max-adjacent-inserts has no effect unless --typos-insert is used", file=sys.stderr)
        elif args.max_adjacent_inserts < 1:
            print("Warning: --max-adjacent-inserts", args.max_adjacent_inserts, " disables --typos-insert", file=sys.stderr)
            args.typos_insert = None
        elif args.max_adjacent_inserts > min(args.typos, args.max_typos_insert):
            if args.max_typos_insert < args.typos:
                print("Warning: --max-adjacent-inserts ("+str(args.max_adjacent_inserts)+") is limited by --max-typos-insert ("+str(args.max_typos_insert)+")", file=sys.stderr)
            else:
                print("Warning: --max-adjacent-inserts ("+str(args.max_adjacent_inserts)+") is limited by the number of --typos ("+str(args.typos)+")", file=sys.stderr)

    # For custom inserted_items, temporarily set this to disable wildcard expansion of --insert
    if inserted_items:
        args.typos_insert = False

    # Parse the custom wildcard set option
    if args.custom_wild:
        global wildcard_keys
        if (args.passwordlist or base_iterator) and not \
                (args.has_wildcards or args.typos_insert or args.typos_replace):
            print("Warning: ignoring unused --custom-wild", file=sys.stderr)
        else:
            args.custom_wild = tstr_from_stdin(args.custom_wild)
            check_chars_range(args.custom_wild, "--custom-wild")
            custom_set_built         = build_wildcard_set(args.custom_wild)
            wildcard_sets[tstr("c")] = custom_set_built  # (duplicates already removed by build_wildcard_set)
            wildcard_sets[tstr("C")] = duplicates_removed(custom_set_built.upper())
            # If there are any case-sensitive letters in the set, build the case-insensitive versions
            custom_set_caseswapped = custom_set_built.swapcase()
            if custom_set_caseswapped != custom_set_built:
                wildcard_nocase_sets[tstr("c")] = duplicates_removed(custom_set_built + custom_set_caseswapped)
                wildcard_nocase_sets[tstr("C")] = wildcard_nocase_sets[tstr("c")].swapcase()
            wildcard_keys += tstr("cC")  # keep track of available wildcard types (this is used in regex's)

    # Syntax check and expand --typos-insert/--typos-replace wildcards
    # N.B. changing the iteration order below will break autosave/restore between btcr versions
    global typos_insert_expanded, typos_replace_expanded
    for arg_name, arg_val in ("--typos-insert", args.typos_insert), ("--typos-replace", args.typos_replace):
        if arg_val:
            arg_val = tstr_from_stdin(arg_val)
            check_chars_range(arg_val, arg_name)
            count_or_error_msg = count_valid_wildcards(arg_val)
            if isinstance(count_or_error_msg, str):
                error_exit(arg_name, arg_val, ":", count_or_error_msg)
            if count_or_error_msg:
                load_backreference_maps_from_token(arg_val)
    if args.typos_insert:
        typos_insert_expanded  = tuple(expand_wildcards_generator(args.typos_insert))
    if args.typos_replace:
        typos_replace_expanded = tuple(expand_wildcards_generator(args.typos_replace))

    if inserted_items:
        args.typos_insert     = True  # undo the temporary change from above
        typos_insert_expanded = tuple(inserted_items)

    if args.delimiter:
        args.delimiter = tstr_from_stdin(args.delimiter)

    # Process any --typos-map file: build a dict (typos_map) mapping replaceable characters to their replacements
    global typos_map
    typos_map = None
    if args.typos_map:
        sha1 = hashlib.sha1() if savestate else None
        typos_map = parse_mapfile(open_or_use(args.typos_map, "r", kwds.get("typos_map")), sha1, "--typos-map")
        #
        # If autosaving, take the hash of the typos_map and either check it
        # during a session restore to make sure we're actually restoring
        # the exact same session, or save it for future such checks
        if savestate:
            typos_map_hash = sha1.digest()
            del sha1
            if restored:
                if typos_map_hash != savestate["typos_map_hash"]:
                    error_exit("can't restore previous session: the typos-map file has changed")
            else:
                savestate["typos_map_hash"] = typos_map_hash
    #
    # Else if not args.typos_map but these were specified:
    elif (args.passwordlist or base_iterator) and args.delimiter:
        # With --passwordlist, --delimiter is only used for a --typos-map
        print("Warning: ignoring unused --delimiter", file=sys.stderr)

    # Compile the regex options
    global regex_only, regex_never
    try:   regex_only  = re.compile(tstr_from_stdin(args.regex_only),  re.U) if args.regex_only  else None
    except re.error as e: error_exit("invalid --regex-only",  args.regex_only, ":", e)
    try:   regex_never = re.compile(tstr_from_stdin(args.regex_never), re.U) if args.regex_never else None
    except re.error as e: error_exit("invalid --regex-never", args.regex_only, ":", e)

    global custom_final_checker
    custom_final_checker = check_only

    if args.length_min < 0:
        print("Warning: length-min must be >= 0, assuming 0", file=sys.stderr)
        args.length_min = 0

    if args.length_max < args.length_min:
        print("Warning: length-max must be >= length-min, assuming length-min", file=sys.stderr)
        args.length_max = args.length_min

    if args.skip < 0:
        print("Warning: --skip must be >= 0, assuming 0", file=sys.stderr)
        args.skip = 0

    threads_specified_by_user = args.threads is not None

    if args.threads:
        if args.threads < 1:
            print("Warning: --threads must be >= 1, assuming 1", file=sys.stderr)
            args.threads = 1

        if args.threads > 60:
            if sys.platform == "win32":
                print("WARNING: Windows doesn't support more than 60 threads")
                args.threads = 60

    if args.worker:  # worker servers
        global worker_id, workers_total
        workers_total = int(args.worker.split("/")[1])

        worker_id = args.worker.split("/")[0].split(",")
        worker_id = [int(x) -1 for x in worker_id] # now it's in the range [0, workers_total)

        if workers_total < 2:
            error_exit("in --worker ID#/TOTAL#, TOTAL# must be >= 2")
        if min(worker_id) < 0:
            error_exit("in --worker ID#/TOTAL#, ID# must be >= 1")
        if max(worker_id) > workers_total:
            error_exit("in --worker ID#/TOTAL#, ID# must be <= TOTAL#")

    global have_progress, progressbar
    if args.no_progress:
        have_progress = False
    else:
        try:
            from lib import progressbar
            have_progress = True
        except ImportError:
            have_progress = False

    ##############################
    # Wallet Loading Related Arguments
    ##############################

    # --bip39 is implied if any bip39 option is used
    for action in cli.bip39_group._group_actions:
        if args.__dict__[action.dest]:
            args.bip39 = True
            break

    # --mkey and --privkey are deprecated synonyms of --data-extract
    if args.mkey or args.privkey:
        args.data_extract = True

    required_args = 0
    if args.wallet:                 required_args += 1
    if args.data_extract:           required_args += 1
    if args.data_extract_string:    required_args += 1
    if args.bip38_enc_privkey:      required_args += 1
    if args.bip39:                  required_args += 1
    if args.yoroi_master_password:  required_args += 1
    if args.brainwallet:            required_args += 1
    if args.rawprivatekey:          required_args += 1
    if args.warpwallet:             required_args += 1
    if args.listpass:               required_args += 1
    if wallet:                      required_args += 1
    if required_args != 1 and (args.seedgenerator == False):
        assert not wallet, 'custom wallet object not permitted with --wallet, --data-extract, --brainwallet, --warpwallet, --bip39, --yoroi-master-password, --bip38_enc_privkey, or --listpass'
        error_exit("argument --wallet (or --data-extract, --bip39, --brainwallet, --warpwallet, --rawprivatekey, --yoroi-master-password, --bip38_enc_privkey, or --listpass, exactly one) is required")

    # If specificed, use a custom wallet object instead of loading a wallet file or data-extract
    global loaded_wallet
    if wallet:
        loaded_wallet = wallet

    # Load the wallet file (this sets the loaded_wallet global)
    if args.wallet:
        if args.android_pin:
            loaded_wallet = WalletAndroidSpendingPIN.load_from_filename(args.wallet)
        elif args.blockchain_secondpass:
            if args.blockchain_correct_mainpass:
                loaded_wallet = WalletBlockchainSecondpass.load_from_filename(args.wallet, args.blockchain_correct_mainpass)
            elif args.correct_wallet_password:
                loaded_wallet = WalletBlockchainSecondpass.load_from_filename(args.wallet, args.correct_wallet_password)
            else:
                loaded_wallet = WalletBlockchainSecondpass.load_from_filename(args.wallet)
        elif args.wallet == "__null":
            loaded_wallet = WalletNull()
        else:
            load_global_wallet(args.wallet)
            if type(loaded_wallet) is WalletBitcoinj:
                print("Notice: for MultiBit, use a .key file instead of a .wallet file if possible")
            if isinstance(loaded_wallet, WalletMultiBit) and not args.android_pin:
                print("Notice: use --android-pin to recover the spending PIN of\n"
                           "    a Bitcoin Wallet for Android/BlackBerry backup (instead of the backup password)")
        if args.msigna_keychain and not isinstance(loaded_wallet, WalletMsigna):
            print("Warning: ignoring --msigna-keychain (wallet file is not an mSIGNA vault)")


    if args.bip38_enc_privkey:
        if args.bip38_currency:
            loaded_wallet = WalletBIP38(args.bip38_enc_privkey, args.bip38_currency)
        else:
            loaded_wallet = WalletBIP38(args.bip38_enc_privkey)

    # Parse --bip39 related options, and create a WalletBIP39 object
    if args.bip39:
        if args.mnemonic:
            mnemonic = args.mnemonic
        elif args.mnemonic_prompt:
            encoding = sys.stdin.encoding or "ASCII"
            if "utf" not in encoding.lower():
                print("terminal does not support UTF; mnemonics with non-ASCII chars might not work", file=sys.stderr)
            mnemonic = input("Please enter your mnemonic (seed)\n> ")
            if not mnemonic:
                sys.exit("canceled")
        else:
            mnemonic = None

        args.wallet_type = args.wallet_type.strip().lower() if args.wallet_type else "bip39"

        if args.wallet_type == "cardano":
            loaded_wallet = WalletCardano(args.addrs, args.addressdb, mnemonic,
                                        args.language, args.bip32_path, args.performance)
        elif args.wallet_type in ['avalanche', 'tron', 'solana', 'cosmos', 'tezos','stellar','multiversx']:
            loaded_wallet = WalletPyCryptoHDWallet(args.mpk, args.addrs, args.addr_limit, args.addressdb, mnemonic,
                                    args.language, args.bip32_path, args.wallet_type, args.performance)
        elif args.wallet_type in ['polkadotsubstrate']:
            loaded_wallet = WalletPyCryptoHDWallet(args.mpk, args.addrs, args.addr_limit, args.addressdb, mnemonic,
                                    args.language, args.substrate_path, args.wallet_type, args.performance)
        elif args.wallet_type == "ethereumvalidator":
            loaded_wallet = WalletEthereumValidator(args.mpk, args.addrs, args.addr_limit, args.addressdb, mnemonic,
                                    args.language, args.bip32_path, args.wallet_type, args.performance)
        elif args.slip39:
            loaded_wallet = WalletSLIP39(args.mpk, args.addrs, args.addr_limit, args.addressdb, args.slip39_shares,
                                    args.language, args.bip32_path, args.wallet_type, args.performance)
        else:
            loaded_wallet = WalletBIP39(args.mpk, args.addrs, args.addr_limit, args.addressdb, mnemonic,
                                    args.language, args.bip32_path, args.wallet_type, args.performance,
                                    force_p2sh = args.force_p2sh,
                                    checksinglexpubaddress =  args.checksinglexpubaddress,
                                    force_p2tr = args.force_p2tr,
                                    force_bip44 = args.force_bip44,
                                    force_bip84 = args.force_bip84,
                                    disable_p2sh = args.disable_p2sh,
                                    disable_p2tr = args.disable_p2tr,
                                    disable_bip44 = args.disable_bip44,
                                    disable_bip84 = args.disable_bip84)


    if args.yoroi_master_password:
        loaded_wallet = WalletYoroi(args.yoroi_master_password, args.performance)

    if args.brainwallet or args.warpwallet:
        loaded_wallet = WalletBrainwallet(addresses = args.addrs,
                                          addressdb = args.addressdb,
                                          check_compressed = not(args.skip_compressed),
                                          check_uncompressed = not(args.skip_uncompressed),
                                          force_check_p2sh = args.force_check_p2sh,
                                          isWarpwallet=args.warpwallet,
                                          salt=args.warpwallet_salt,
                                          crypto=args.memwallet_coin)

    if args.rawprivatekey:
        loaded_wallet = WalletRawPrivateKey(addresses = args.addrs,
                                          addressdb = args.addressdb,
                                          check_compressed = not(args.skip_compressed),
                                          check_uncompressed = not(args.skip_uncompressed),
                                          force_check_p2sh = args.force_check_p2sh,
                                          crypto=args.wallet_type,
                                            correct_wallet_password = args.correct_wallet_password)

    # Set the default number of threads to use. For GPU processing, things like hyperthreading are unhelpful, so use physical cores only...
    if not args.threads:
        if not args.enable_opencl or type(loaded_wallet) is WalletElectrum28 or type(loaded_wallet) is WalletMetamask: # Not (generally) worthwhile having more than 2 threads when using OpenCL due to the relatively simply hash verification (unlike seed recovery)
            args.threads = logical_cpu_cores
        else:
            if args.btcrseed or args.bip39 or args.wallet_type: # BIP39 wallets generally benefit from as much CPU power as possible
                args.threads = logical_cpu_cores
            else:
                args.threads = 2

        if args.threads > 60:
            if sys.platform == "win32":
                print("Note: Windows doesn't support more than 60 threads, setting threads to 60...")
                args.threads = 60

    # Prompt for data extracted by one of the extract-* scripts
    # instead of loading a wallet file
    if args.data_extract or args.data_extract_string:
        key_crc_base64 = kwds.get("data_extract")  # for unittest
        if args.data_extract_string:
            key_crc_base64 = args.data_extract_string
        if not key_crc_base64:
            if tokenlist_file == sys.stdin:
                print("Warning: order of data on stdin is: optional extra command-line arguments, key data, rest of tokenlist", file=sys.stderr)
            elif args.passwordlist == "-" and not sys.stdin.isatty():  # if isatty, friendly prompts are provided instead
                print("Warning: order of data on stdin is: key data, password list", file=sys.stderr)
            #
            key_prompt = "Please enter the data from the extract script\n> "  # the default friendly prompt
            try:
                if not sys.stdin.isatty() or sys.stdin.peeked:
                    key_prompt = "Reading extract data from stdin\n" # message to use if key data has already been entered
            except AttributeError: pass
            key_crc_base64 = input(key_prompt)
        #
        # Emulates load_global_wallet(), but using the base64 key data instead of a wallet
        # file (this sets the loaded_wallet global, and returns the validated CRC)
        key_crc = load_from_base64_key(key_crc_base64)
        #
        if isinstance(loaded_wallet, WalletMsigna):
            if args.msigna_keychain:
                print("Warning: ignoring --msigna-keychain (the extract script has already chosen the keychain)")
        elif args.msigna_keychain:
            print("Warning: ignoring --msigna-keychain (--data-extract is not from an mSIGNA vault)")
        #
        # If autosaving, either check the key_crc during a session restore to make sure we're
        # actually restoring the exact same session, or save it for future such checks
        if savestate:
            if restored:
                if key_crc != savestate["key_crc"]:
                    error_exit("can't restore previous session: the encrypted key entered is not the same")
            else:
                savestate["key_crc"] = key_crc

    #############################################
    #
    # Wallet is certainly loaded by this point...
    #
    #############################################

    if args.dump_wallet:
        try:
            if loaded_wallet._dump_wallet_file:
                pass
        except AttributeError:
            exit("This wallet type does not currently support dumping the decrypted wallet file... (But it might support decrypting private keys (--dump-privkeys), so give that a try)")

        loaded_wallet._dump_wallet_file = args.dump_wallet

    if args.dump_privkeys:
        try:
            if loaded_wallet._dump_privkeys_file:
                pass
        except AttributeError:
            exit("This wallet type does not currently support dumping the decrypted private keys...")

        loaded_wallet._dump_privkeys_file = args.dump_privkeys

    if (args.dump_privkeys or args.dump_wallet) and \
            (args.correct_wallet_password or args.correct_wallet_secondpassword) and \
            (not (args.passwordlist or args.tokenlist or args.performance)):
        print("\nDumping Wallet File or Keys...")
        if args.correct_wallet_secondpassword:
            result, count = loaded_wallet.return_verified_password_or_false([args.correct_wallet_secondpassword])
        elif args.correct_wallet_password:
            result, count = loaded_wallet.return_verified_password_or_false([args.correct_wallet_password])

        if result:
            print("\nWallet successfully dumped...")
        else:
            print("\nUnable to decrypt wallet, likely due to incorrect password..")

        exit()


    if args.disable_save_possible_passwords:
        loaded_wallet._savepossiblematches = False
    else:
        try:
            loaded_wallet._possible_passwords_file = args.possible_passwords_file
            loaded_wallet.init_logfile()
        except AttributeError: # Not all wallet types will automatically prodce a logfile
            pass

    ##############################
    # OpenCL related arguments
    ##############################

    try: #This will fail during some older unit tests if there is no loaded wallet
        loaded_wallet.opencl = False
        loaded_wallet.opencl_algo = -1
        loaded_wallet.opencl_context_pbkdf2_sha1 = -1
    except AttributeError:
        pass

    # Parse and syntax check all of the GPU related options
    if args.enable_opencl:
        try:
            if(len(loaded_wallet.btcrseed_wallet._path_indexes) > 1):
                print("=======================================================================")
                print()
                print("Performance Warning:\n"
                      "OpenCL Acceleration for BIP39 Passphrase (or Electrum extra words"
                      "is very sensitive to extra CPU load, this can dramaticaly slow things down "
                      "You are currently checking multiple derivation paths, (this is the default) "
                      "and if you know which derivation path your wallet used, you should disable "
                      "all unnecessary paths\n"
                      "See https://btcrecover.readthedocs.io/en/latest/bip39-accounts-and-altcoins/")
                print()
                print("=======================================================================")

            if(loaded_wallet.btcrseed_wallet._addrs_to_generate > 1):
                print("=======================================================================")
                print()
                print("Performance Warning:\n"
                      "OpenCL Acceleration for BIP39 Passphrase (or Electrum extra words"
                      "is very sensitive to extra CPU load, this can dramaticaly slow things down"
                      "You have selected an address generation limit greater than 1,"
                      "and this may not be required depending on your wallet type"
                      "See https://btcrecover.readthedocs.io/en/latest/Seedrecover_Quick_Start_Guide/#running-seedrecoverpy")
                print()
                print("=======================================================================")
        except:
            pass
        if args.warpwallet:
            print("=======================================================================")
            print()
            print("Warning: Warpwallet GPU doesn't accelerate the sCrypt portion of hashing, "
                  "so will seem unresponsive for large chunks of time (~15 minutes) "
                  "and isn't any faster than pure CPU processing")
            print()
            print("=======================================================================")
        try:
            if loaded_wallet._iter_count == 0: # V0 blockchain wallets have an iter_count of zero and don't benefit from GPU acceleration...
                print("ERROR: The version of your blockchain.com wallet doesn't support OpenCL acceleration, this cannot changed. Please disable it and try again...")
                exit()
        except AttributeError: #BIP39 wallets don't have an iter_count in the same way as other wallets
            pass
        # Force the multiprocessing mode so that OpenCL will still be happy to run multiple threads. (Otherwise it crashes in Linux)
        try:
            multiprocessing.set_start_method('spawn')
        except RuntimeError: # Catch and ignore error if running multiple phases
            pass
        print()
        print("OpenCL: Available Platforms")
        info = opencl_information()
        info.printplatforms()
        print()
        if not hasattr(loaded_wallet, "_return_verified_password_or_false_opencl"):
            if args.bip39:
                error_exit("Wallet Type: " + loaded_wallet.__class__.__name__ + " does not support OpenCL acceleration for Passphrase Recovery")
            else:
                error_exit("Wallet Type: " + loaded_wallet.__class__.__name__ + " does not support OpenCL acceleration")

        loaded_wallet.opencl = True
        # Append GPU related arguments to be sent to BTCrpass

        #
        if args.opencl_platform:
            loaded_wallet.opencl_platform = args.opencl_platform[0]
            loaded_wallet.opencl_device_worksize = 0
            for device in pyopencl.get_platforms()[args.opencl_platform[0]].get_devices():
                if device.max_work_group_size > loaded_wallet.opencl_device_worksize:
                    loaded_wallet.opencl_device_worksize = device.max_work_group_size
        #
        # Else if specific devices weren't requested, try to build a good default list
        else:
            btcrecover.opencl_helpers.auto_select_opencl_platform(loaded_wallet)

        print("OpenCL: Using Platform:", loaded_wallet.opencl_platform)

        if args.opencl_devices:
            loaded_wallet.opencl_devices = args.opencl_devices.split(",")
            loaded_wallet.opencl_devices = [int(x) for x in loaded_wallet.opencl_devices]
            if max(loaded_wallet.opencl_devices) > (len(pyopencl.get_platforms()[loaded_wallet.opencl_platform].get_devices()) - 1):
                print("Error: Invalid OpenCL device selected")
                exit()

        loaded_wallet.opencl_algo = 0

        if args.opencl_workgroup_size:
            loaded_wallet.opencl_device_worksize = args.opencl_workgroup_size[0]
            loaded_wallet.chunksize = args.opencl_workgroup_size[0]
        else:
            if args.bip38_enc_privkey:
                # Optimal Chunksize Examples
                # NVidia MX250 2GB = 7 (~7 p/s Slower than CPU in the same PC...)
                # NVidia 1660Ti 6GB = 16 (~18.5 p/s Almost identical CPU in the same PC...)
                # NVidia 3090 24GB = 16 (~54 p/s for 2x GPUs, 27 p/s for one, both GPUs make it faster then the 24 core CPU that gets ~31 p/s... Scales nicely with 6x 3090s to ~155 p/s...
                # Seems like chunksize of 16 is basically optimal and needs ~2gb VRAM per thread...Increasing chunksize beyond 16 gives no performance benefit and hits workgroup limits...
                # Probably just worth leaving it at 16 and exiting if less than a 6gb GPU... (As performance won't be worthwhile anyway)
                device_min_vmem = 99999
                for device in pyopencl.get_platforms()[loaded_wallet.opencl_platform].get_devices():
                    if (device.global_mem_size / 1073741824.0) < device_min_vmem:
                        device_min_vmem = device.global_mem_size / 1073741824.0
                print("OpenCL: Minimum GPU Memory Available for platform:", device_min_vmem, "GB")
                if device_min_vmem < 6:
                    print("OpenCL: Insufficient GPU Memory for sCrypt Acceleration... Exiting...")
                    print("You can force OpenCL Acceleration by manually specifying a --opencl-workgroup-size to something like 7 (As opposed to the normal 16) or by using less CPU threads, so try 1 (As opposed to the normal 2)")
                    print("Note: Even if this doesn't hang or crash, it will likely run slower than your CPU...")
                    exit()
                else:
                    print("OpenCL: Sufficient GPU VRAM for sCrypt... Ok to run!")
                    loaded_wallet.chunksize = 16
            else:
                loaded_wallet.chunksize = loaded_wallet.opencl_device_worksize


        print("OpenCL: Using Work Group Size: ", loaded_wallet.chunksize)

        if (
            not threads_specified_by_user
            and (args.btcrseed or args.bip39)
        ):
            try:
                platform_devices = pyopencl.get_platforms()[
                    loaded_wallet.opencl_platform
                ].get_devices()
            except Exception:
                platform_devices = []

            if platform_devices:
                device_indices = getattr(loaded_wallet, "opencl_devices", None)
                if device_indices:
                    unique_indices = []
                    for index in device_indices:
                        if (
                            isinstance(index, int)
                            and 0 <= index < len(platform_devices)
                            and index not in unique_indices
                        ):
                            unique_indices.append(index)
                else:
                    unique_indices = list(range(len(platform_devices)))

                total_vram_bytes = 0
                for index in unique_indices:
                    device = platform_devices[index]
                    if device.type & (
                        pyopencl.device_type.GPU
                        | pyopencl.device_type.ACCELERATOR
                    ):
                        total_vram_bytes += device.global_mem_size

                if total_vram_bytes:
                    # Unified-memory APUs over-report usable memory (it's shared
                    # system RAM), so only budget a fraction of it for GPU workers.
                    is_unified_memory = btcrecover.opencl_helpers._has_amd_unified_memory_gpu(
                        loaded_wallet.opencl_platform
                    )
                    memory_budget_bytes = total_vram_bytes
                    if is_unified_memory:
                        memory_budget_bytes = int(
                            total_vram_bytes * OPENCL_UNIFIED_MEMORY_BUDGET_FRACTION
                        )

                    threads_by_vram = memory_budget_bytes // BIP39_OPENCL_MEMORY_PER_THREAD_BYTES
                    if threads_by_vram == 0:
                        threads_by_vram = 1
                    recommended_threads = min(logical_cpu_cores, threads_by_vram)
                    if recommended_threads < 1:
                        recommended_threads = 1

                    if recommended_threads < args.threads:
                        budget_gb = memory_budget_bytes / (1024 ** 3)
                        per_thread_gb = (
                            BIP39_OPENCL_MEMORY_PER_THREAD_BYTES / (1024 ** 3)
                        )
                        memory_kind = "unified" if is_unified_memory else "GPU"
                        print(
                            "OpenCL: Defaulting to {} worker {} based on {:.2f} GB of usable {} memory (~{:.1f} GB per thread)".format(
                                recommended_threads,
                                "threads"
                                if recommended_threads != 1
                                else "thread",
                                budget_gb,
                                memory_kind,
                                per_thread_gb,
                            )
                        )
                        args.threads = recommended_threads
        print()

    # Parse and syntax check all of the GPU related options
    if args.enable_gpu:
        if not hasattr(loaded_wallet, "init_opencl_kernel"):
            error_exit(loaded_wallet.__class__.__name__ + " does not support GPU acceleration (Though it might support OpenCL acceleration using your GPU, so try --enable-opencl)")
        devices_avail = list(get_opencl_devices())  # all available OpenCL device objects
        if not devices_avail:
            error_exit("no supported GPUs found")
        if args.int_rate <= 0:
            error_exit("--int-rate must be > 0")
        #
        # If specific devices were requested by name, build a list of devices from those available
        if args.gpu_names:
            # Create a list of names of available devices, exactly the same way as --list-gpus except all lower case
            avail_names = []  # will be the *names* of available devices
            for i, dev in enumerate(devices_avail, 1):
                avail_names.append("#"+str(i)+" "+dev.name.strip().lower())
            #
            devices = []  # will be the list of devices to actually use, taken from devices_avail
            for device_name in args.gpu_names:  # for each name specified at the command line
                if device_name == "":
                    error_exit("empty name in --gpus")
                device_name = device_name.lower()
                for i, avail_name in enumerate(avail_names):
                    if device_name in avail_name:  # if the name at the command line matches an available one
                        devices.append(devices_avail[i])
                        avail_names[i] = ""  # this device isn't available a second time
                        break
                else:  # if for loop exits normally, and not via the break above
                    error_exit("can't find GPU whose name contains '"+device_name+"' (use --list-gpus to display available GPUs)")
        #
        # Else if specific devices weren't requested, try to build a good default list
        else:
            best_score_sofar = -1
            for dev in devices_avail:
                cur_score = 0
                if   dev.type & pyopencl.device_type.ACCELERATOR:
                    if "oclgrind" not in device.name.lower():  # Some simulators present as an accelerator...
                        cur_score += 8  # always best
                elif dev.type & pyopencl.device_type.GPU:         cur_score += 4  # better than CPU
                if   "nvidia" in dev.vendor.lower():              cur_score += 2  # is never an IGP: very good
                elif "amd"    in dev.vendor.lower():              cur_score += 1  # sometimes an IGP: good
                if cur_score >= best_score_sofar:                                 # (intel is always an IGP)
                    if cur_score > best_score_sofar:
                        best_score_sofar = cur_score
                        devices = []
                    devices.append(dev)
            #
            # Multiple best devices are only permitted if they seem to be identical
            device_name = devices[0].name
            for dev in devices[1:]:
                if dev.name != device_name:
                    error_exit("can't automatically determine best GPU(s), please use the --gpu-names option")
        #
        # --global-ws and --local-ws lists must be the same length as the number of devices to use, unless
        # they are of length one in which case they are repeated until they are the correct length
        for argname, arglist in ("--global-ws", args.global_ws), ("--local-ws", args.local_ws):
            if len(arglist) == len(devices): continue
            if len(arglist) != 1:
                error_exit("number of", argname, "integers must be either one or be the number of GPUs utilized")
            arglist.extend(arglist * (len(devices) - 1))
        #
        # Check the values of --global-ws and --local-ws
        local_ws_warning = False
        if args.local_ws[0] is not None:  # if one is specified, they're all specified
            for i in range(len(args.local_ws)):
                if args.local_ws[i] < 1:
                    error_exit("each --local-ws must be a postive integer")
                if args.local_ws[i] > devices[i].max_work_group_size:
                    error_exit("--local-ws of", args.local_ws[i], "exceeds max of", devices[i].max_work_group_size, "for GPU '"+devices[i].name.strip()+"'")
                if args.global_ws[i] % args.local_ws[i] != 0:
                    error_exit("each --global-ws ("+str(args.global_ws[i])+") must be evenly divisible by its --local-ws ("+str(args.local_ws[i])+")")
                if args.local_ws[i] % 32 != 0 and not local_ws_warning:
                    print("Warning: each --local-ws should probably be divisible by 32 for good performance", file=sys.stderr)
                    local_ws_warning = True
        for ws in args.global_ws:
            if ws < 1:
                error_exit("each --global-ws must be a postive integer")
            if ws % 32 != 0:
                print("Warning: each --global-ws should probably be divisible by 32 for good performance", file=sys.stderr)
                break

        if args.enable_gpu:
            #If we are dealing with a Bitcoin Core wallet
            if args.threads != parser.get_default("threads"):
                print("Warning: --threads ignored for GPU based Bitcoin Core recovery", file=sys.stderr)
            args.threads = 1
            extra_opencl_args = ()
            loaded_wallet.init_opencl_kernel(devices, args.global_ws, args.local_ws, args.int_rate, *extra_opencl_args)
    #
    # if not --enable-gpu: sanity checks
    else:
        for argkey in "gpu_names", "global_ws", "local_ws", "int_rate":
            if args.__dict__[argkey] != parser.get_default(argkey):
                print("Warning: --"+argkey.replace("_", "-"), "is ignored without --enable-gpu", file=sys.stderr)


    # If specified, use a custom base password generator instead of a tokenlist or passwordlist file
    global base_password_generator, has_any_wildcards
    if base_iterator:
        if args.seedgenerator is False:
            assert not args.passwordlist, "can't specify --passwordlist with base_iterator"
        # (--tokenlist is already excluded by argparse when base_iterator is specified)
        base_password_generator = base_iterator
        has_any_wildcards       = args.has_wildcards  # allowed if requested

    # If specified, usa a custom password generator for performance testing
    global performance_base_password_generator
    performance_base_password_generator = perf_iterator if perf_iterator \
        else default_performance_base_password_generator

    if args.performance:
        base_password_generator = performance_base_password_generator
        has_any_wildcards       = args.has_wildcards  # allowed if requested
        if args.listpass:
            error_exit("--performance tests require a wallet or data-extract")  # or a custom checker

    # ETAs are always disabled with --listpass or --performance
    if args.listpass or args.performance:
        args.no_eta = True


    # If we're using a passwordlist file, open it here. If we're opening stdin, read in at least an
    # initial portion. If we manage to read up until EOF, then we won't need to disable ETA features.
    # TODO: support --autosave with --passwordlist files and short stdin inputs
    global passwordlist_file, initial_passwordlist, passwordlist_allcached
    passwordlist_file = open_or_use(args.passwordlist, "r", provided_passwordlist,
                                    permit_stdin=True, decoding_errors="replace")
    try:
        loaded_wallet.passwordlist_file = args.passwordlist # There are some instance where the generator will be initialised without a loaded wallet, so ignore these
    except AttributeError:
        pass

    if passwordlist_file:
        initial_passwordlist    = []
        passwordlist_allcached  = False
        has_any_wildcards       = False
        base_password_generator = passwordlist_base_password_generator
        if passwordlist_embedded_arguments and passwordlist_file != sys.stdin:
            passwordlist_file.readline()
        #
        if passwordlist_file == sys.stdin:
            passwordlist_isatty = sys.stdin.isatty()
            if passwordlist_isatty:  # be user friendly
                print("Please enter your password guesses, one per line (with no extra spaces)")
                print(exit)  # os-specific version of "Use exit() or Ctrl-D (i.e. EOF) to exit"
            else:
                print("Reading passwordlist from stdin")
            #
            for line_num in range(1, 1000000):
                line = passwordlist_file.readline()
                eof  = not line
                line = line.strip("\r\n")
                if eof or passwordlist_isatty and line == "exit()":
                    passwordlist_allcached = True
                    break
                try:
                    check_chars_range(line, "line", no_replacement_chars=True)
                except SystemExit as e:
                    passwordlist_warn(None if passwordlist_isatty else line_num, e.code)
                    line = None  # add a None to the list so we can count line numbers correctly
                if args.has_wildcards and "%" in line:
                    count_or_error_msg = count_valid_wildcards(line, permit_contracting_wildcards=True)
                    if isinstance(count_or_error_msg, str):
                        passwordlist_warn(None if passwordlist_isatty else line_num, count_or_error_msg)
                        line = None  # add a None to the list so we can count line numbers correctly
                    else:
                        has_any_wildcards = True
                        try:
                            load_backreference_maps_from_token(line)
                        except IOError as e:
                            passwordlist_warn(None if passwordlist_isatty else line_num, e)
                            line = None  # add a None to the list so we can count line numbers correctly
                initial_passwordlist.append(line)
            #
            if not passwordlist_allcached and not args.no_eta:
                # ETA calculations require that the passwordlist file is seekable or all in RAM
                print("Warning: --no-eta has been enabled because --passwordlist is stdin and is large", file=sys.stderr)
                args.no_eta = True
        #
        if not passwordlist_allcached and args.has_wildcards:
            has_any_wildcards = True  # If not all cached, need to assume there are wildcards


    # Some final sanity checking, now that args.no_eta's value is known
    if args.no_eta:  # always true for --listpass and --performance
        if not args.no_dupchecks:
            if args.performance:
                print("Warning: --performance without --no-dupchecks will eventually cause an out-of-memory error", file=sys.stderr)
            elif not args.listpass:
                print("Warning: --no-eta without --no-dupchecks can cause out-of-memory failures while searching", file=sys.stderr)
        if args.max_eta != parser.get_default("max_eta"):
            print("Warning: --max-eta is ignored with --no-eta, --listpass, or --performance", file=sys.stderr)


    # If we're using a tokenlist file, call parse_tokenlist() to parse it.
    if tokenlist_file:
        if tokenlist_file == sys.stdin:
            print("Reading tokenlist from stdin")
        parse_tokenlist(tokenlist_file, tokenlist_first_line_num)
        base_password_generator = tokenlist_base_password_generator


    # Open a new autosave file (if --restore was specified, the restore file
    # is still open and has already been assigned to autosave_file instead)
    if savestate and not restored:
        global autosave_nextslot
        autosave_file = open_or_use(args.autosave, "wb", kwds.get("autosave"), new_or_empty=True)
        if not autosave_file:
            error_exit("--autosave file '"+args.autosave+"' already exists, won't overwrite")
        autosave_nextslot = 0
        print("Using autosave file '"+args.autosave+"'")


    # Process any --exclude-passwordlist file: create the password_dups object earlier than normal and
    # instruct it to always consider passwords found in this file as duplicates (so they'll be skipped).
    # This is done near the end because it may take a while (all the syntax checks are done by now).
    if args.exclude_passwordlist:
        exclude_file = open_or_use(args.exclude_passwordlist, "r", kwds.get("exclude_passwordlist"), permit_stdin=True)
        if exclude_file == tokenlist_file:
            error_exit("can't use stdin for both --tokenlist and --exclude-passwordlist")
        if exclude_file == passwordlist_file:
            error_exit("can't use stdin for both --passwordlist and --exclude-passwordlist")
        #
        global password_dups
        password_dups = DuplicateChecker()
        sha1          = hashlib.sha1() if savestate else None
        try:
            for excluded_pw in exclude_file:
                excluded_pw = excluded_pw.strip("\r\n")
                check_chars_range(excluded_pw, "--exclude-passwordlist file")
                password_dups.exclude(excluded_pw)  # now is_duplicate(excluded_pw) will always return True
                if sha1:
                    sha1.update(excluded_pw.encode("utf_8"))
        except MemoryError:
            error_exit("not enough memory to store entire --exclude-passwordlist file")
        finally:
            if exclude_file != sys.stdin:
                exclude_file.close()
        #
        # If autosaving, take the hash of the excluded passwords and either
        # check it during a session restore to make sure we're actually
        # restoring the exact same session, or save it for future such checks
        if savestate:
            exclude_passwordlist_hash = sha1.digest()
            del sha1
            if restored:
                if exclude_passwordlist_hash != savestate["exclude_passwordlist_hash"]:
                    error_exit("can't restore previous session: the exclude-passwordlist file has changed")
            else:
                savestate["exclude_passwordlist_hash"] = exclude_passwordlist_hash
        #
        # Normally password_dups isn't even created when --no-dupchecks is specified, but it's required
        # for exclude-passwordlist; instruct the password_dups to disable future duplicate checking
        if args.no_dupchecks:
            password_dups.disable_duplicate_tracking()

    if not disable_security_warnings:
        # Print a security warning before giving users the chance to enter ir seed....
        # Also a good idea to keep this warning as late as possible in terms of not needing it to be display for --version --help, or if there are errors in other parameters.
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


    # If something has been redirected to stdin and we've been reading from it, close
    # stdin now so we don't keep the redirected files alive while running, but only
    # if we're done with it (done reading the passwordlist_file and no --pause option)
    if (    not sys.stdin.closed and not sys.stdin.isatty() and (
                args.data_extract                or
                tokenlist_file    == sys.stdin   or
                passwordlist_file == sys.stdin   or
                args.exclude_passwordlist == '-' or
                args.android_pin                 or
                args.blockchain_secondpass       or
                args.mnemonic_prompt
            ) and (
                passwordlist_file != sys.stdin   or
                passwordlist_allcached
            ) and not pause_registered ):
        sys.stdin.close()   # this doesn't really close the fd
        try:   os.close(0)  # but this should, where supported
        except Exception: pass

    if tokenlist_file and not (pause_registered and tokenlist_file == sys.stdin):
        tokenlist_file.close()


# Builds and returns a dict (e.g. typos_map) mapping replaceable characters to their replacements.
#   map_file       -- an open file object (which this function will close)
#   running_hash   -- (opt.) adds the map's data to the hash object
#   feature_name   -- (opt.) used to generate more descriptive error messages
#   same_permitted -- (opt.) if True, the input value may be mapped to the same output value
def parse_mapfile(map_file, running_hash = None, feature_name = "map", same_permitted = False):
    map_data = dict()
    try:
        for line_num, line in enumerate(map_file, 1):
            if line.startswith("#"): continue  # ignore comments
            #
            # Remove the trailing newline, then split the line exactly
            # once on the specified delimiter (default: whitespace)
            if args.delimiter: args.delimiter = args.delimiter.encode().decode('unicode_escape')
            split_line = line.strip("\r\n").split(args.delimiter, 1)
            if split_line in ([], [tstr('')]): continue  # ignore empty lines
            if len(split_line) == 1:
                error_exit(feature_name, "file '"+map_file.name+"' has an empty replacement list on line", line_num)
            if args.delimiter is None: split_line[1] = split_line[1].rstrip()  # ignore trailing whitespace by default

            check_chars_range(tstr().join(split_line), feature_name + " file" + (" '" + map_file.name + "'" if hasattr(map_file, "name") else ""))
            for c in split_line[0]:  # (c is the character to be replaced)
                replacements = duplicates_removed(str(map_data.get(c, tstr())) + split_line[1])
                if not same_permitted and c in replacements:
                    map_data[c] = "".join(list(filter(lambda r: r != c, replacements)))
                else:
                    map_data[c] = replacements
    finally:
        map_file.close()

    # If autosaving, take a hash of the map_data so it can either be checked (later)
    # during a session restore to make sure we're actually restoring the exact same
    # session, or can be saved for future such checks
    if running_hash:
        for k in sorted(map_data.keys()):  # must take the hash in a deterministic order (not in map_data order)
            v = map_data[k]
            running_hash.update(k.encode("utf_8") + v.encode("utf_8"))

    return map_data

################################### Tokenfile Parsing ###################################


# Build up the token_lists structure, a list of lists, reflecting the tokenlist file.
# Each list in the token_lists list is preceded with a None element unless the
# corresponding line in the tokenlist file begins with a "+" (see example below).
# Each token is represented by a string if that token is not anchored, or by an
# AnchoredToken object used to store the begin and end fields
#
# EXAMPLE FILE:
#     #   Lines that begin with # are ignored comments
#     #
#     an_optional_token_exactly_one_per_line...
#     ...may_or_may_not_be_tried_per_guess
#     #
#     mutually_exclusive  token_list  on_one_line  at_most_one_is_tried
#     #
#     +  this_required_token_was_preceded_by_a_plus_in_the_file
#     +  exactly_one_of_these  tokens_are_required  and_were_preceded_by_a_plus
#     #
#     ^if_present_this_is_at_the_beginning  if_present_this_is_at_the_end$
#     #
#     ^2$if_present_this_is_second ^5$if_present_this_is_fifth
#     #
#     ^2,4$if_present_its_second_third_or_fourth_(but_never_last)
#     ^2,$if_present_this_is_second_or_greater_(but_never_last)
#     ^,$exactly_the_same_as_above
#     ^,3$if_present_this_is_third_or_less_(but_never_first_or_last)
#
# RESULTANT token_lists ==
# [
#     [ None,  'an_optional_token_exactly_one_per_line...' ],
#     [ None,  '...may_or_may_not_be_tried_per_guess' ],
#
#     [ None,  'mutually_exclusive',  'token_list',  'on_one_line',  'at_most_one_is_tried' ],
#
#     [ 'this_required_token_was_preceded_by_a_plus_in_the_file' ],
#     [ 'exactly_one_of_these',  'tokens_are_required',  'and_were_preceded_by_a_plus' ],
#
#     [ AnchoredToken(begin=0), AnchoredToken(begin="$") ],
#
#     [ AnchoredToken(begin=1), AnchoredToken(begin=4) ],
#
#     [ AnchoredToken(begin=1, end=3) ],
#     [ AnchoredToken(begin=1, end=sys.maxint) ],
#     [ AnchoredToken(begin=1, end=sys.maxint) ],
#     [ AnchoredToken(begin=1, end=2) ]
# ]

# After creation, AnchoredToken must not be changed: it creates and caches the return
# values for __str__ and __hash__ for speed on the assumption they don't change
class AnchoredToken(object):
    # The possible values for the .type attribute:
    POSITIONAL = 1  # has a .pos attribute
    RELATIVE   = 2  # same as ^
    MIDDLE     = 3  # has .begin and .end attributes

    def __init__(self, token, line_num = "?"):
        if token.startswith("^"):
            # If it is a syntactically correct positional, relative, or middle anchor
            match = re.match(r"\^(?:(?P<begin>\d+)?(?P<middle>,)(?P<end>\d+)?|(?P<rel>[rR])?(?P<pos>\d+))[\^$]", token)
            if match:
                # If it's a middle (ranged) anchor
                if match.group("middle"):
                    begin = match.group("begin")
                    end   = match.group("end")
                    cached_str = tstr("^")  # begin building the cached __str__
                    if begin is None:
                        begin = 2
                    else:
                        begin = int(begin)
                        if begin > 2:
                            cached_str += tstr(begin)
                    cached_str += tstr(",")
                    if end is None:
                        end = sys.maxsize
                    else:
                        end = int(end)
                        cached_str += tstr(end)
                    cached_str += tstr("^")
                    if begin > end:
                        error_exit("anchor range of token on line", line_num, "is invalid (begin > end)")
                    if begin < 2:
                        error_exit("anchor range of token on line", line_num, "must begin with 2 or greater")
                    self.type  = AnchoredToken.MIDDLE
                    self.begin = begin - 1
                    self.end   = end   - 1 if end != sys.maxsize else end
                #
                # If it's a positional or relative anchor
                elif match.group("pos"):
                    pos = int(match.group("pos"))
                    cached_str = tstr("^")  # begin building the cached __str__
                    if match.group("rel"):
                        cached_str += tstr("r") + tstr(pos) + tstr("^")
                        self.type = AnchoredToken.RELATIVE
                        self.pos  = pos
                    else:
                        if pos < 1:
                            error_exit("anchor position of token on line", line_num, "must be 1 or greater")
                        if pos > 1:
                            cached_str += tstr(pos) + tstr("^")
                        self.type = AnchoredToken.POSITIONAL
                        self.pos  = pos - 1
                #
                else:
                    assert False, "AnchoredToken.__init__: determined anchor type"

                self.text = token[match.end():]  # same for positional, relative, and middle anchors
            #
            # Else it's a begin anchor
            else:
                if len(token) > 1 and token[1] in "0123456789,":
                    print("Warning: token on line", line_num, "looks like it might be a positional or middle anchor, " +
                          "but it can't be parsed correctly, so it's assumed to be a simple beginning anchor instead", file=sys.stderr)
                if len(token) > 2 and token[1].lower() == "r" and token[2] in "0123456789":
                    print("Warning: token on line", line_num, "looks like it might be a relative anchor, " +
                          "but it can't be parsed correctly, so it's assumed to be a simple beginning anchor instead", file=sys.stderr)
                cached_str = tstr("^")  # begin building the cached __str__
                self.type  = AnchoredToken.POSITIONAL
                self.pos   = 0
                self.text  = token[1:]
            #
            if self.text.endswith("$"):
                error_exit("token on line", line_num, "is anchored with both ^ at the beginning and $ at the end")
            #
            cached_str += self.text  # finish building the cached __str__
        #
        # Parse end anchor if present
        elif token.endswith("$"):
            cached_str = token
            self.type  = AnchoredToken.POSITIONAL
            self.pos   = b"$"
            self.text  = token[:-1]
        #
        else: raise ValueError("token passed to AnchoredToken constructor is not an anchored token")
        #
        self.cached_str  = sys.intern(cached_str) if type(cached_str) is str else cached_str
        self.cached_hash = hash(self.cached_str)
        if self.text == "":
            print("Warning: token on line", line_num, "contains only an anchor (and zero password characters)", file=sys.stderr)

    # For sets
    def __hash__(self):      return self.cached_hash
    def __eq__(self, other): return     isinstance(other, AnchoredToken) and self.cached_str == other.cached_str
    def __ne__(self, other): return not isinstance(other, AnchoredToken) or  self.cached_str != other.cached_str
    # For sort (so that tstr() can be used as the key function)
    def __str__(self):       return     str(self.cached_str)
    def __unicode__(self):   return str(self.cached_str)
    # For hashlib
    def __repr__(self):      return self.__class__.__name__ + "(" + repr(self.cached_str) + ")"

def parse_tokenlist(tokenlist_file, first_line_num = 1):
    global token_lists
    global has_any_duplicate_tokens, has_any_wildcards, has_any_anchors

    if args.no_dupchecks < 3:
        has_any_duplicate_tokens = False
        token_set_for_dupchecks  = set()
    has_any_wildcards   = False
    has_any_anchors     = False
    token_lists         = []

    for line_num, line in enumerate(tokenlist_file, first_line_num):

        # Ignore comments
        if line.startswith("#"):
            if re.match(r"#\s*--", line, re.UNICODE):
                print("Warning: all options must be on the first line, ignoring options on line", str(line_num), file=sys.stderr)
            continue

        # Start off assuming these tokens are optional (no preceding "+");
        # if it turns out there is a "+", we'll remove this None later
        new_list = [None]

        # Remove the trailing newline, then split the line on the
        # specified delimiter (default: whitespace) to get a list of tokens
        new_list.extend( line.strip("\r\n").split(args.delimiter) )

        # A simple fix to handle the situation where someone has a space in a custom expanding wildcard
        temp_new_list = [None]
        tempToken = None
        for token in new_list:
            if token is None: continue
            if "%" in token[:5] and "[" in token[:5] and "]" not in token:
                tempToken = token
                continue

            if tempToken is not None:
                delimiter = " "
                if args.delimiter is not None:
                    delimiter = args.delimiter
                token = tempToken + delimiter + token
                tempToken = None

            temp_new_list.append(token)

        new_list = temp_new_list

        # Ignore empty lines
        if new_list in ([None], [None, tstr('')]): continue

        # If a "+" is present at the beginning followed by at least one token,
        # then exactly one of the token(s) is required. This is noted in the structure
        # by removing the preceding None we added above (and also delete the "+")
        if new_list[1] == "+" and len(new_list) > 2:
            del new_list[0:2]

        # Check token syntax and convert any anchored tokens to an AnchoredToken object
        for i, token in enumerate(new_list):
            if token is None: continue

            check_chars_range(token, "token on line " + str(line_num))

            # Syntax check any wildcards, and load any wildcard backreference maps
            count_or_error_msg = count_valid_wildcards(token, permit_contracting_wildcards=True)
            if isinstance(count_or_error_msg, str):
                error_exit("on line", str(line_num)+":", count_or_error_msg)
            elif count_or_error_msg:
                has_any_wildcards = True  # (a global)
                load_backreference_maps_from_token(token)

            # Check for tokens which look suspiciously like command line options
            # (using a private ArgumentParser member func is asking for trouble...)
            if token.startswith("--") and cli.parser_common._get_option_tuples(token):
                if line_num == 1:
                    print("Warning: token on line 1 looks like an option, "
                               "but line 1 did not start like this: #--option1 ...", file=sys.stderr)
                else:
                    print("Warning: token on line", str(line_num), "looks like an option, "
                               " but all options must be on the first line", file=sys.stderr)

            # Parse anchor if present and convert to an AnchoredToken object
            if token.startswith("^") or token.endswith("$"):
                token = AnchoredToken(token, line_num)  # (the line_num is just for error messages)
                new_list[i] = token
                has_any_anchors = True

            # Keep track of the existence of any duplicate tokens for future optimization
            if args.no_dupchecks < 3 and not has_any_duplicate_tokens:
                if token in token_set_for_dupchecks:
                    has_any_duplicate_tokens = True
                    del token_set_for_dupchecks
                else:
                    token_set_for_dupchecks.add(token)

        # Add the completed list for this one line to the token_lists list of lists
        token_lists.append(new_list)

    # Tokens at the end of the outer token_lists get tried first below;
    # reverse the list here so that tokens at the beginning of the file
    # appear at the end of the list and consequently get tried first
    token_lists.reverse()

    # If autosaving, take a hash of the token_lists and backreference maps, and
    # either check them during a session restore to make sure we're actually
    # restoring the exact same session, or save them for future such checks
    if savestate:
        global backreference_maps_sha1
        token_lists_hash        = hashlib.sha1(repr(token_lists).encode('utf-8')).digest()
        backreference_maps_hash = backreference_maps_sha1.digest() if backreference_maps_sha1 else None
        if restored:
            if token_lists_hash != savestate["token_lists_hash"]:
                error_exit("can't restore previous session: the tokenlist file has changed")
            if backreference_maps_hash != savestate.get("backreference_maps_hash"):
                error_exit("can't restore previous session: one or more backreference maps have changed")
        else:
            savestate["token_lists_hash"] = token_lists_hash
            if backreference_maps_hash:
                savestate["backreference_maps_hash"] = backreference_maps_hash


# Load any map files referenced in wildcard backreferences in the passed token
def load_backreference_maps_from_token(token):
    global backreference_maps       # initialized to dict() in init_wildcards()
    global backreference_maps_sha1  # initialized to  None  in init_wildcards()
    # We know all wildcards present have valid syntax, so we don't need to use the full regex, but
    # we do need to capture %% to avoid parsing this as a backreference (it isn't one): %%;file;b
    for map_filename in re.findall(r"%[\d,]*;(.+?);\d*b|%%", token):
        if map_filename and map_filename not in backreference_maps:
            if savestate and not backreference_maps_sha1:
                backreference_maps_sha1 = hashlib.sha1()
            backreference_maps[map_filename] = \
                parse_mapfile(open(map_filename, "r"), backreference_maps_sha1, "backreference map", same_permitted=True)


################################### Password Generation ###################################


# Checks for duplicate hashable items in multiple identical runs
# (builds a cache in the first run to be memory efficient in future runs)
class DuplicateChecker(object):

    EXCLUDE = sys.maxsize

    def __init__(self):
        self._seen_once  = dict()  # tracks potential duplicates in run 0 only
        self._duplicates = dict()  # tracks having seen known duplicates in runs 1+
        self._run_number = 0       # incremented at the end of each run
        self._tracking   = True    # is duplicate tracking enabled?
                                   # (even if False, excluded items are still checked)

    # Returns True if x has already been seen in this run. If x has been
    # excluded, always returns True (even if it hasn't been seen yet).
    def is_duplicate(self, x):

        # The duplicates cache is built during the first run
        if self._run_number == 0:
            if x in self._duplicates:  # If it's the third+ time we've seen it (or 2nd+ & excluded):
                return True
            if x in self._seen_once:   # If it's the second time we've seen it, or it's excluded:
                self._duplicates[x] = self._seen_once.pop(x)  # move it to list of known duplicates
                return True
            # Otherwise it's the first time we've seen it
            if self._tracking:
                self._seen_once[x] = 1
            return False

        # The duplicates cache is available for lookup on second+ runs
        duplicate = self._duplicates.get(x)            # ==sys.maxint if it's excluded
        if duplicate:
            if duplicate <= self._run_number:          # First time we've seen it this run:
                self._duplicates[x] = self._run_number + 1  # mark it as having been seen this run
                return False
            else:                                     # Second+ time we've seen it this run, or it's excluded:
                return True
        return False                                  # Else it isn't a recorded duplicate

    # Adds x to the already-seen dict such that is_duplicate(x) will always return True
    def exclude(self, x):
        self._seen_once[x] = self.EXCLUDE

    # Future duplicates will be ignored (and will not consume additional memory), however
    # is_duplicate() will still return True for duplicates and exclusions seen/added so far
    def disable_duplicate_tracking(self):
        self._tracking = False

    # Must be called before the same list of items is revisited
    def run_finished(self):
        if self._run_number == 0:
            del self._seen_once  # No longer need this for second+ runs
        self._run_number += 1


# The main generator function produces all possible requested password permutations with no
# duplicates from the token_lists global as constructed above plus wildcard expansion or from
# the passwordlist file, plus up to a certain number of requested typos. Results are produced
# in lists of length chunksize, which can be changed by calling iterator.send((new_chunksize,
# only_yield_count)) (which does not itself return any passwords). If only_yield_count, then
# instead of producing lists, for each iteration single integers <= chunksize are produced
# (only the last integer might be < than chunksize), useful for counting or skipping passwords.
def init_password_generator():
    global password_dups, token_combination_dups, passwordlist_warnings
    password_dups = token_combination_dups = None
    passwordlist_warnings = 0
    # (re)set the min_typos argument default values to 0
    capslock_typos_generator.__defaults__ = (0,)
    swap_typos_generator    .__defaults__ = (0,)
    simple_typos_generator  .__defaults__ = (0,)
    insert_typos_generator  .__defaults__ = (0,)
#
def password_generator(chunksize = 1, only_yield_count = False):
    assert chunksize > 0, "password_generator: chunksize > 0"

    generatingSeeds = False
    try:
        global loaded_wallet
        if loaded_wallet._checksum_in_generator:
            generatingSeeds = True
    except:
        pass

    # Used to communicate between typo generators the number of typos that have been
    # created so far during each password generated so that later generators know how
    # many additional typos, at most, they are permitted to add, and also if it is
    # the last typo generator that will run, how many, at least, it *must* add
    global typos_sofar
    typos_sofar = 0

    passwords_gathered = []
    passwords_count    = 0  # == len(passwords_gathered)
    worker_count = 0  # Only used if --worker is specified
    new_args = None

    # Initialize this global if not already initialized but only
    # if they should be used; see its usage below for more details
    global password_dups
    if password_dups is None and args.no_dupchecks < 1 and args.seedgenerator == False:
        password_dups = DuplicateChecker()

    print("Duplicate Check Level:", args.no_dupchecks, ", Add --no-dupchecks up to 4 times fully disable duplicate checking")
    print()

    # Copy a few globals into local for a small speed boost
    l_generator_product = generator_product
    l_regex_only        = regex_only
    l_regex_never       = regex_never
    l_password_dups     = password_dups
    l_args_worker       = args.worker
    l_seed_generator = args.seedgenerator
    l_length_min = args.length_min
    l_length_max = args.length_max
    l_truncate_length = args.truncate_length

    if l_args_worker:
        l_workers_total = workers_total
        l_worker_id     = worker_id

    # Build up the modification_generators list; see the inner loop below for more details
    modification_generators = []

    if has_any_wildcards:               modification_generators.append( expand_wildcards_generator )

    if l_seed_generator is False:
        if args.password_repeats_pretypos:  modification_generators.append( password_repeats_generator )
        if args.typos_capslock:             modification_generators.append( capslock_typos_generator   )
        if args.typos_swap:                 modification_generators.append( swap_typos_generator       )
        if enabled_simple_typos:            modification_generators.append( simple_typos_generator     )
        if args.typos_insert:               modification_generators.append( insert_typos_generator     )
        if args.password_repeats_posttypos: modification_generators.append( password_repeats_generator )

    # Only the last typo generator needs to enforce a min-typos requirement
    if args.min_typos and (l_seed_generator is False):
        # Though this isn't applicable to the expand wildcards generator
        if modification_generators[-1] != expand_wildcards_generator:
            # set the min_typos argument default value
            modification_generators[-1].__defaults__ = (args.min_typos,)

    # Modification generators for seed generation
    if args.seed_transform_wordswaps:
        modification_generators.append(swap_tokens_generator)
        modification_generators[-1].__defaults__ = (args.seed_transform_wordswaps,)
    if args.seed_transform_trezor_common_mistakes:
        modification_generators.append(trezor_common_mistakes_generator)
        modification_generators[-1].__defaults__ = (
            args.seed_transform_trezor_common_mistakes,
        )

    modification_generators_len = len(modification_generators)

    # The base password generator is set in parse_arguments(); it's either an iterable
    # or a generator function (which returns an iterator) that produces base passwords
    # usually based on either a tokenlist file (as parsed above) or a passwordlist file.
    for password_base in base_password_generator() if callable(base_password_generator) else base_password_generator:
        # The for loop below takes the password_base and applies zero or more modifications
        # to it to produce a number of different possible variations of password_base (e.g.
        # different wildcard expansions, typos, etc.)

        # modification_generators is a list of function generators each of which takes a
        # string and produces one or more password variations based on that string. It is
        # built just above, and is built differently depending on the token_lists (are any
        # wildcards present?) and the program options (were any typos requested?).
        #
        # If any modifications have been requested, create an iterator that will
        # loop through all combinations of the requested modifications
        if modification_generators_len:
            if modification_generators_len == 1:
                modification_iterator = modification_generators[0](password_base)
            else:
                modification_iterator = l_generator_product(password_base, *modification_generators)
        #
        # Otherwise just produce the unmodified password itself
        else:
            modification_iterator = (password_base,)

        for password in modification_iterator:

            # Check the password against the --regex-only and --regex-never options
            if l_regex_only  and not l_regex_only .search(password): continue
            if l_regex_never and     l_regex_never.search(password): continue

            if l_length_min and (len(password)<l_length_min):
                #print("Skipping ",password," - too short \r", end="", flush=True)
                continue

            if l_length_max and (len(password)>l_length_max):
                #print("Skipping ",password," - too long \r", end="", flush=True)
                continue

            # If it's a seed, split it up into a list
            if l_seed_generator and not isinstance(password,list) and not isinstance(password,tuple):
                password = password.split(" ")

            # This is the check_only argument optionally passed
            # by external libraries to parse_arguments()
            if custom_final_checker and not custom_final_checker(password): continue

            # Truncate password if required
            password = password[0:l_truncate_length]

            # This duplicate check can be disabled via --no-dupchecks
            # because it can take up a lot of memory, sometimes needlessly
            if l_password_dups and l_password_dups.is_duplicate(password):  continue

            # Workers in a server pool ignore passwords not assigned to them
            if l_args_worker:
                skip_current_password = True
                if (worker_count % l_workers_total) in l_worker_id:
                        skip_current_password = False

                worker_count += 1
                if skip_current_password:
                    continue

            if generatingSeeds: #Skip seeds that don't have a valid BIP39 checksum
                if not loaded_wallet._verify_checksum(password):
                    continue

            # Produce the password(s) or the count once enough of them have been accumulated
            passwords_count += 1
            if only_yield_count:
                if passwords_count >= chunksize:
                    new_args = yield passwords_count
                    passwords_count = 0
            else:
                passwords_gathered.append(password)
                if passwords_count >= chunksize:
                    new_args = yield passwords_gathered
                    passwords_gathered = []
                    passwords_count    = 0

            # Process new arguments received from .send(), yielding nothing back to send()
            if new_args:
                chunksize, only_yield_count = new_args
                assert chunksize > 0, "password_generator.send: chunksize > 0"
                new_args = None
                yield

        assert typos_sofar == 0, "password_generator: typos_sofar == 0 after all typo generators have finished"

    if l_password_dups: l_password_dups.run_finished()

    # Produce the remaining passwords that have been accumulated
    if passwords_count > 0:
        yield passwords_count if only_yield_count else passwords_gathered


# This generator utility is a bit like itertools.product. It takes a list of iterators
# and invokes them in (the equivalent of) a nested for loop, except instead of a list
# of simple iterators it takes a list of generators each of which expects to be called
# with a single argument. generator_product calls the first generator with the passed
# initial_value, and then takes each value it produces and calls the second generator
# with each, and then takes each value the second generator produces and calls the
# third generator with each, etc., until there are no generators left, at which point
# it produces all the values generated by the last generator.
#
# This can be useful in the case you have a list of generators, each of which is
# designed to produce a number of variations of an initial value, and you'd like to
# string them together to get all possible (product-wise) variations.
#
# TODO: implement without recursion?
def generator_product(initial_value, generator, *other_generators):
    if other_generators == ():
        for final_value in generator(initial_value):
            yield final_value
    else:
        for intermediate_value in generator(initial_value):
            for final_value in generator_product(intermediate_value, *other_generators):
                yield final_value

# A recursive function that will swap one pair of words in a given mnemonic and then,
# if required, will call itself recursively to handle further possible swaps.

# This implementation prioritises simplicity leaves it to other dup-check functions
# to handle duplicates created through repeated swaps.
# (Though isn't really an issue for small numbers of swaps either way)

# Note: There is a bit of inconsistency in the data type of password_base depending on
# whether tokenlists/seedlists are being used. (Hence why there are a few casts between tuple and list)
def swap_tokens_generator(password_base, numSwaps = 0):
    yield tuple(password_base)
    password_base = list(password_base)
    # If we have reached the end then simply return the base password
    if numSwaps > 0:
        for i, j in itertools.combinations(range(len(password_base)), 2):
            swapped_seed = tuple(password_base[:i] + [password_base[j]] + password_base[i+1:j] + [password_base[i]] + password_base[j+1:])
            yield from swap_tokens_generator(swapped_seed, numSwaps - 1)


def trezor_common_mistakes_generator(password_base, max_mistakes = 0):
    base_seed = tuple(password_base)
    yield base_seed

    if max_mistakes <= 0:
        return

    def recurse(current_seed, start_index, replacements_remaining):
        if replacements_remaining == 0:
            return

        for index in range(start_index, len(current_seed)):
            word = current_seed[index]
            lookup_word = word.lower() if isinstance(word, str) else word
            alternatives = TREZOR_COMMON_MISTAKES.get(lookup_word, ())
            if not alternatives:
                continue

            for alternative in alternatives:
                if alternative == lookup_word:
                    continue

                updated_seed = list(current_seed)
                updated_seed[index] = alternative
                updated_tuple = tuple(updated_seed)
                yield updated_tuple

                if replacements_remaining > 1:
                    yield from recurse(
                        updated_seed,
                        index + 1,
                        replacements_remaining - 1,
                    )

    yield from recurse(list(base_seed), 0, max_mistakes)

# The tokenlist generator function produces all possible password permutations from the
# token_lists global as constructed by parse_tokenlist(). These passwords are then used
# by password_generator() as base passwords that can undergo further modifications.
def tokenlist_base_password_generator():

    # Initialize this global if not already initialized but only
    # if they should be used; see its usage below for more details
    global token_combination_dups

    if token_combination_dups is None and args.no_dupchecks < 2 and has_any_duplicate_tokens:
        token_combination_dups = DuplicateChecker()

    # Copy a few globals into local for a small speed boost
    l_len                    = len
    l_args_min_tokens        = args.min_tokens
    l_args_max_tokens        = args.max_tokens
    l_has_any_anchors        = has_any_anchors
    l_type                   = type
    l_token_combination_dups = token_combination_dups
    l_tuple                  = tuple
    l_sorted                 = sorted
    l_list                   = list
    l_tstr                   = tstr
    l_seed_generator         = args.seedgenerator
    l_mnemonic_length        = args.mnemonic_length

    # Choose between the custom duplicate-checking and the standard itertools permutation
    # functions for the outer loop unless the custom one has been specifically disabled
    # with three (or more) --no-dupcheck options.
    if args.keep_tokens_order:
        permutations_function = lambda x: [tuple(reversed(x))]
    else:
        if args.no_dupchecks < 3 and has_any_duplicate_tokens:
            permutations_function = permutations_nodups
        else:
            permutations_function = itertools.permutations

    # The outer loop iterates through all possible (unordered) combinations of tokens
    # taking into account the at-most-one-token-per-line rule. Note that lines which
    # were not required (no "+") have a None in their corresponding list; if this
    # None item is chosen for a tokens_combination, then this tokens_combination
    # corresponds to one without any token from that line, and we we simply remove
    # the None from this tokens_combination (product_limitedlen does this on its own,
    # itertools.product does not so it's done below).
    #
    # First choose which product generator to use: the custom product_limitedlen
    # might be faster (possibly a lot) if a large --min-tokens or any --max-tokens
    # is specified at the command line, otherwise use the standard itertools version.
    using_product_limitedlen = l_args_min_tokens > 5 or l_args_max_tokens < sys.maxsize
    if using_product_limitedlen:
        product_generator = product_limitedlen(*token_lists, minlen=l_args_min_tokens, maxlen=l_args_max_tokens)
    else:
        product_generator = itertools.product(*token_lists)


    for tokens_combination in product_generator:
        # Remove any None's, then check against token length constraints:
        # (product_limitedlen, if used, has already done all this)
        if not using_product_limitedlen:
            #tokens_combination = filter(lambda t: t is not None, tokens_combination)
            tokens_combination = [x for x in tokens_combination if x is not None]
            if not l_args_min_tokens <= l_len(list(tokens_combination)) <= l_args_max_tokens: continue

        # There are three types of anchors: positional, middle/range, & relative. Positionals
        # only have a single possible position; middle anchors have a range, but are never
        # tried at the beginning or end; relative anchors appear in a certain order with
        # respect to each other. Below, build a tokens_combination_nopos list from
        # tokens_combination with all positional anchors removed. They will be inserted
        # back into the correct position later. Also search for invalid anchors of any
        # type: a positional anchor placed past the end of the current combination (based
        # on its length) or a middle anchor whose begin position is past *or at* the end.
        positional_anchors  = None  # (will contain strings, not AnchoredToken's)
        has_any_mid_anchors = False
        rel_anchors_count   = 0
        if l_has_any_anchors:
            tokens_combination_len   = l_len(list(tokens_combination))
            tokens_combination_nopos = []  # all tokens except positional ones
            invalid_anchors          = False
            for token in tokens_combination:
                if l_type(token) == AnchoredToken:
                    if token.type == AnchoredToken.POSITIONAL:  # a single-position anchor
                        pos = token.pos
                        if pos == b"$":
                            pos = tokens_combination_len - 1
                        elif pos >= tokens_combination_len:
                            invalid_anchors = True  # anchored past the end
                            break
                        if not positional_anchors:  # initialize it to a list of None's
                            positional_anchors = [None for i in range(tokens_combination_len)]
                        elif positional_anchors[pos] is not None:
                            invalid_anchors = True  # two tokens anchored to the same place
                            break
                        positional_anchors[pos] = token.text    # save valid single-position anchor
                    elif token.type == AnchoredToken.MIDDLE:    # a middle/range anchor
                        if token.begin+1 >= tokens_combination_len:
                            invalid_anchors = True  # anchored past *or at* the end
                            break
                        tokens_combination_nopos.append(token)  # add this token (a middle anchor)
                        has_any_mid_anchors = True
                    else:                                       # else it must be a relative anchor,
                        tokens_combination_nopos.append(token)  # add it
                        rel_anchors_count += 1
                else:                                           # else it's not an anchored token,
                    tokens_combination_nopos.append(token)      # add this token (just a string)
            if invalid_anchors: continue
            #
            if tokens_combination_nopos == []:              # if all tokens have positional anchors,
                if not args.seedgenerator:
                    tokens_combination_nopos = ( l_tstr(""), )  # make this non-empty so a password can be created
        else:
            tokens_combination_nopos = tokens_combination

        # Do some duplicate checking early on to avoid running through potentially a
        # lot of passwords all of which end up being duplicates. We check the current
        # combination (of all tokens), sorted because different orderings of token
        # combinations are equivalent at this point. This check can be disabled with two
        # (or more) --no-dupcheck options (one disables only the full duplicate check).
        # TODO:
        #   Be smarter in deciding when to enable this? (currently on if has_any_duplicate_tokens)
        #   Instead of dup checking, write a smarter product (seems hard)?
        # TODO:
        #   Right now, trying to remove duplicates with this method if --keep-tokens-order is passed
        #   will cause some passwords to be skipped, check the following example:
        #
        #   Token file:
        #   -----------
        #   a b
        #   a b
        #   Passwords to try:
        #   -----------------
        #   a
        #   b
        #   aa
        #   ba
        #   ab
        #   bb
        #
        #   Trying to remove duplicates when --keep-tokens-order is passed in the above
        #   example will skip the 5th password "ab". Fix that.
        if not args.keep_tokens_order and l_token_combination_dups and \
           l_token_combination_dups.is_duplicate(l_tuple(l_sorted(tokens_combination, key=l_tstr))): continue

        # The inner loop iterates through all valid permutations (orderings) of one
        # combination of tokens and combines the tokens to create a password string.
        # Because positionally anchored tokens can only appear in one position, they
        # are not passed to the permutations_function.
        for ordered_token_guess in permutations_function(tokens_combination_nopos):
            # If multiple relative anchors are in a guess, they must appear in the correct
            # relative order. If any are out of place, we continue on to the next guess.
            # Otherwise, we remove the anchor information leaving only the string behind.
            if rel_anchors_count:
                invalid_anchors   = False
                last_relative_pos = 0
                for i, token in enumerate(ordered_token_guess):
                    if l_type(token) == AnchoredToken and token.type == AnchoredToken.RELATIVE:
                        if token.pos < last_relative_pos:
                            invalid_anchors = True
                            break
                        if l_type(ordered_token_guess) != l_list:
                            ordered_token_guess = l_list(ordered_token_guess)
                        ordered_token_guess[i] = token.text  # now it's just a string
                        if rel_anchors_count == 1:  # with only one, it's always valid
                            break
                        last_relative_pos = token.pos
                if invalid_anchors: continue

            # Insert the positional anchors we removed above back into the guess
            if positional_anchors:
                ordered_token_guess = l_list(ordered_token_guess)
                for i, token in enumerate(positional_anchors):
                    if token is not None:
                        ordered_token_guess.insert(i, token)  # (token here is just a string)

            # The last type of anchor has a range of possible positions for the anchored
            # token. If any anchored token is outside of its permissible range, we continue
            # on to the next guess. Otherwise, we remove the anchor information leaving
            # only the string behind.
            if has_any_mid_anchors:
                if l_type(ordered_token_guess[0])  == AnchoredToken or \
                   l_type(ordered_token_guess[-1]) == AnchoredToken:
                    continue  # middle anchors are never permitted at the beginning or end
                invalid_anchors = False
                for i, token in enumerate(ordered_token_guess[1:-1], 1):
                    if l_type(token) == AnchoredToken:
                        assert token.type == AnchoredToken.MIDDLE, "only middle/range anchors left"
                        if token.begin <= i <= token.end:
                            if l_type(ordered_token_guess) != l_list:
                                ordered_token_guess = l_list(ordered_token_guess)
                            ordered_token_guess[i] = token.text  # now it's just a string
                        else:
                            invalid_anchors = True
                            break
                if invalid_anchors: continue

            if l_seed_generator:
                expandedGuess = []
                for rawToken in ordered_token_guess:
                    expandedGuess.extend(rawToken.split(","))

                if l_mnemonic_length is None: # If mnemonic_length hasn't been specified then skip this check
                    yield expandedGuess
                else:
                    if len(expandedGuess) == l_mnemonic_length: #Only return mnemonic guesses of the expected length
                        yield expandedGuess
                    else:
                        break

            else:
                yield l_tstr().join(ordered_token_guess)

    if l_token_combination_dups: l_token_combination_dups.run_finished()


# Like itertools.product, but only produces output tuples whose length is between
# minlen and maxlen. Normally, product always produces output of length len(sequences),
# but this version removes elements from each produced product which are == None
# (making their length variable) and only then applies the requested length constraint.
# (Does not accept the itertools "repeat" argument.)
# TODO: implement without recursion?
#
# Check for edge cases that would violate do_product_limitedlen()'s invariants,
# and then call do_product_limitedlen() to do the real work
def product_limitedlen(*sequences, **kwds):
    minlen = max(kwds.get("minlen", 0), 0)  # no less than 0
    maxlen = kwds.get("maxlen", sys.maxsize)

    if minlen > maxlen:  # minlen is already >= 0
        return range(0).__iter__()         # yields nothing at all

    if maxlen == 0:      # implies minlen == 0 because of the check above
        # Produce a length 0 tuple unless there's a seq which doesn't have a None
        # (and therefore would produce output of length >= 1, but maxlen == 0)
        for seq in sequences:
            if None not in seq: break
        else:  # if it didn't break, there was a None in every seq
            return itertools.repeat((), 1)  # a single empty tuple
        # if it did break, there was a seq without a None
        return range(0).__iter__()         # yields nothing at all

    sequences_len = len(sequences)
    if sequences_len == 0:
        if minlen == 0:  # already true: minlen >= 0 and maxlen >= minlen
            return itertools.repeat((), 1)  # a single empty tuple
        else:            # else minlen > 0
            return range(0).__iter__()     # yields nothing at all

    # If there aren't enough sequences to satisfy minlen
    if minlen > sequences_len:
        return range(0).__iter__()         # yields nothing at all

    # Unfortunately, do_product_limitedlen is recursive; the recursion limit
    # must be at least as high as sequences_len plus a small buffer
    if sequences_len + 20 > sys.getrecursionlimit():
        sys.setrecursionlimit(sequences_len + 20)

    # Build a lookup table for do_product_limitedlen() (see below for details)
    requireds_left_sofar = 0
    requireds_left = [None]  # requireds_left[0] is never used
    for seq in reversed(sequences[1:]):
        if None not in seq: requireds_left_sofar += 1
        requireds_left.append(requireds_left_sofar)

    return do_product_limitedlen(minlen, maxlen, requireds_left, sequences_len - 1, *sequences)
#
# assumes: maxlen >= minlen, maxlen >= 1, others_len == len(other_sequences), others_len + 1 >= minlen
def do_product_limitedlen(minlen, maxlen, requireds_left, others_len, sequence, *other_sequences):
    # When there's only one sequence
    if others_len == 0:
        # If minlen == 1, produce everything but empty tuples
        # (since others_len + 1 >= minlen, minlen is 1 or less)
        if minlen == 1:
            for choice in sequence:
                if choice is not None: yield (choice,)
        # Else everything is produced
        else:
            for choice in sequence:
                yield () if choice is None else (choice,)
        return

    # Iterate through elements in the first sequence
    for choice in sequence:

        # Adjust minlen and maxlen if this element affects the length (isn't None)
        # and check that the invariants aren't violated
        if choice is None:
            # If all possible results will end up being shorter than the specified minlen:
            if others_len < minlen:
                continue
            new_minlen = minlen
            new_maxlen = maxlen

            # Expand the other_sequences (the current choice doesn't contribute because it's None)
            for rest in do_product_limitedlen(new_minlen, new_maxlen, requireds_left, others_len - 1, *other_sequences):
                yield rest

        else:
            new_minlen = minlen - 1
            new_maxlen = maxlen - 1
            # requireds_left[others_len] is a count of remaining sequences which do not
            # contain a None: they are "required" and will definitely add to the length
            # of the final result. If all possible results will end up being longer than
            # the specified maxlen:
            if requireds_left[others_len] > new_maxlen:
                continue
            # If new_maxlen == 0, then the only valid result is the one where all of the
            # other_sequences produce a None for their choice. Produce that single result:
            if new_maxlen == 0:
                yield (choice,)
                continue

            # Prepend the choice to the result of expanding the other_sequences
            for rest in do_product_limitedlen(new_minlen, new_maxlen, requireds_left, others_len - 1, *other_sequences):
                yield (choice,) + rest


# Like itertools.permutations, but avoids duplicates even if input contains some.
# Input must be a sequence of hashable elements. (Does not accept the itertools "r" argument.)
# TODO: implement without recursion?
def permutations_nodups(sequence):
    # Copy a global into local for a small speed boost
    l_len = len

    sequence_len = l_len(list(sequence))

    # Special case for speed
    if sequence_len == 2:
        # Only two permutations to try:
        yield sequence if type(sequence) == tuple else tuple(sequence)
        if sequence[0] != sequence[1]:
            yield (sequence[1], sequence[0])
        return

    # If they're all the same, there's only one permutation:
    seen = set(sequence)
    if l_len(seen) == 1:
        yield sequence if type(sequence) == tuple else tuple(sequence)
        return

    # If the sequence contains no duplicates, use the faster itertools version
    if l_len(seen) == sequence_len:
        for permutation in itertools.permutations(sequence):
            yield permutation
        return

    # Else there's at least one duplicate and two+ permutations; use our version
    seen = set()
    for i, choice in enumerate(sequence):
        if i > 0 and choice in seen: continue          # don't need to check the first one
        if i+1 < sequence_len:       seen.add(choice)  # don't need to add the last one
        for rest in permutations_nodups(sequence[:i] + sequence[i+1:]):
            yield (choice,) + rest


MAX_PASSWORDLIST_WARNINGS = 100
def passwordlist_warn(line_num, *args):
    global passwordlist_warnings  # initialized to 0 in init_password_generator()
    if passwordlist_warnings is not None:
        passwordlist_warnings += 1
        if passwordlist_warnings <= MAX_PASSWORDLIST_WARNINGS:
            print("Warning: ignoring",
                  "line "+str(line_num)+":" if line_num else "last line:",
                  *args, file=sys.stderr)
#
# Produces whole passwords from a file, exactly one per line, or from the file's cache
# (which is created by parse_arguments if the file is stdin). These passwords are then
# used by password_generator() as base passwords that can undergo further modifications.
def passwordlist_base_password_generator():
    global initial_passwordlist, passwordlist_warnings
    global passwordlist_file, passwordlist_first_line_num
    global loaded_wallet

    line_num = passwordlist_first_line_num
    for password_base in initial_passwordlist:  # note that these have already been syntax-checked
        if password_base is not None:           # happens if there was a wildcard syntax error
            yield password_base
        line_num += 1                           # count both valid lines and ones with syntax errors

    if not passwordlist_allcached:

        firstRun = True
        try:
            multiFile = loaded_wallet.load_multi_file_seedlist #There are some instances where this will run without a loaded wallet, in these instances, just set multi file to false
        except AttributeError:
            multiFile = False
        file_suffix = ""
        filename = args.passwordlist + file_suffix
        assert not passwordlist_file.closed

        for i in range(9999):
            if multiFile:
                file_suffix = "_" + '{:04d}'.format(i) + ".txt"
                filename = args.passwordlist[:-9] + file_suffix
            if firstRun:
                firstRun = False
                print("Notice: Loading File: ", filename)
            else:
                try:
                    passwordlist_file = open_or_use(filename, "r", decoding_errors="replace")
                    print("Notice: Loading File: ", filename)
                except FileNotFoundError:
                    continue

            for line_num, password_base in enumerate(passwordlist_file, line_num):  # not yet syntax-checked
                password_base = password_base.strip("\r\n")
                try:
                    check_chars_range(password_base, "line", no_replacement_chars=True)
                except SystemExit as e:
                    passwordlist_warn(line_num, e.code)
                    continue
                if args.has_wildcards and "%" in password_base:
                    count_or_error_msg = count_valid_wildcards(password_base, permit_contracting_wildcards=True)
                    if isinstance(count_or_error_msg, str):
                        passwordlist_warn(line_num, count_or_error_msg)
                        continue
                    try:
                        load_backreference_maps_from_token(password_base)
                    except IOError as e:
                        passwordlist_warn(line_num, e)
                        continue

                if args.seedgenerator:
                    yield password_base.replace("'", "").replace(",","").strip('()[]').split(' ') # Gracefully handle seed lists files formatted as tuples, lists or just raw spaced words
                else:
                    yield password_base

            print("Notice: Finished File: ", filename)
            if not multiFile:
                break
            passwordlist_file.close()



    if passwordlist_warnings:
        if passwordlist_warnings > MAX_PASSWORDLIST_WARNINGS:
            print("\n"+"Warning:", passwordlist_warnings-MAX_PASSWORDLIST_WARNINGS,
                  "additional warnings were suppressed", file=sys.stderr)
        passwordlist_warnings = None  # ignore warnings during future runs of the same passwordlist

    try:
        # Prepare for a potential future run of the same passwordlist
        if passwordlist_file != sys.stdin:
            passwordlist_file.seek(0)

        # Data from stdin can't be reused if it hasn't been fully cached
        elif not passwordlist_allcached:
            initial_passwordlist = ()
            passwordlist_file.close()
    except ValueError: #This exception will be thrown if we are reading a multi-file seedlist, as the file was closed earlier
        pass



# Produces an infinite number of base passwords for performance measurements. These passwords
# are then used by password_generator() as base passwords that can undergo further modifications.
def default_performance_base_password_generator():
    for i in itertools.count(0):
        yield tstr("Measure Performance ") + tstr(i)


# This generator function expands (or contracts) all wildcards in the string passed
# to it, or if there are no wildcards it simply produces the string unchanged. The
# prior_prefix argument is only used internally while recursing, and is needed to
# support backreference wildcards. The returned value is:
#   prior_prefix + password_with_all_wildcards_expanded
# TODO: implement without recursion?
def expand_wildcards_generator(password_with_wildcards, prior_prefix = None):
    if isinstance(password_with_wildcards, list):
        password_with_wildcards = " ".join(password_with_wildcards)

    if prior_prefix is None: prior_prefix = tstr()

    # Quick check to see if any wildcards are present
    if tstr("%") not in password_with_wildcards:
        # If none, just produce the string and end
        yield prior_prefix + password_with_wildcards
        return

    # %e and %f are special types of wildcards which can both be customised AND can occur multiple times, but always have the same value
    if "%e" in password_with_wildcards:
        for wildcard in wildcard_sets["e"]:
            loop_password_with_wildcards = password_with_wildcards.replace("%e", wildcard)
            for password_expanded in expand_wildcards_generator(loop_password_with_wildcards):
                yield password_expanded
        return

    if "%f" in password_with_wildcards:
        for wildcard in wildcard_sets["f"]:
            loop_password_with_wildcards = password_with_wildcards.replace("%f", wildcard)
            for password_expanded in expand_wildcards_generator(loop_password_with_wildcards):
                yield password_expanded
        return

    # Copy a few globals into local for a small speed boost
    l_range = range
    l_len    = len
    l_min    = min
    l_max    = max

    # Find the first wildcard parameter in the format %[[min,]max][caseflag]type where
    # caseflag == "i" if present and type is one of: wildcard_keys, "<", ">", or "-"
    # (e.g. "%d", "%-", "%2n", "%1,3ia", etc.), or type is of the form "[custom-wildcard-set]", or
    # for backreferences type is of the form: [ ";file;" ["#"] | ";#" ] "b"  <--brackets denote options
    global wildcard_re
    if not wildcard_re:
        wildcard_re = re.compile(
            r"%(?:(?:(?P<min>\d+),)?(?P<max>\d+))?(?P<nocase>i)?(?:(?P<type>[{}<>-])|\[(?P<custom>.+?)\]|(?:;(?:(?P<bfile>.+?);)?(?P<bpos>\d+)?)?(?P<bref>b))" \
            .format(wildcard_keys))
    match = wildcard_re.search(password_with_wildcards)
    assert match, "expand_wildcards_generator: parsed valid wildcard spec"

    password_prefix      = password_with_wildcards[0:match.start()]          # no wildcards present here,
    full_password_prefix = prior_prefix + password_prefix                    # nor here;
    password_postfix_with_wildcards = password_with_wildcards[match.end():]  # might be other wildcards in here

    m_bref = match.group("bref")
    if m_bref:  # a backreference wildcard, e.g. "%b" or "%;2b" or "%;map.txt;2b"
        m_bfile, m_bpos = match.group("bfile", "bpos")
        m_bpos = int(m_bpos) if m_bpos else 1
        bmap = backreference_maps[m_bfile] if m_bfile else None
    else:
        # For positive (expanding) wildcards, build the set of possible characters based on the wildcard type and caseflag
        m_custom, m_nocase = match.group("custom", "nocase")
        if m_custom:  # a custom set wildcard, e.g. %[abcdef0-9]
            is_expanding = True
            wildcard_set = custom_wildcard_cache.get((m_custom, m_nocase))
            if wildcard_set is None:
                wildcard_set = build_wildcard_set(m_custom)
                if m_nocase:
                    # Build a case-insensitive version
                    wildcard_set_caseswapped = wildcard_set.swapcase()
                    if wildcard_set_caseswapped != wildcard_set:
                        wildcard_set = duplicates_removed(wildcard_set + wildcard_set_caseswapped)
                custom_wildcard_cache[(m_custom, m_nocase)] = wildcard_set
        else:  # either a "normal" or a contracting wildcard
            m_type = match.group("type")
            is_expanding = m_type not in "<>-"
            if is_expanding:
                if m_nocase and m_type in wildcard_nocase_sets:
                    wildcard_set = wildcard_nocase_sets[m_type]
                else:
                    wildcard_set = wildcard_sets[m_type]
        assert not is_expanding or wildcard_set, "expand_wildcards_generator: found expanding wildcard set"

    # Extract or default the wildcard min and max length
    wildcard_maxlen = match.group("max")
    wildcard_maxlen = int(wildcard_maxlen) if wildcard_maxlen else 1
    wildcard_minlen = match.group("min")
    wildcard_minlen = int(wildcard_minlen) if wildcard_minlen else wildcard_maxlen

    # If it's a backreference wildcard
    if m_bref:
        first_pos = len(full_password_prefix) - m_bpos
        if first_pos < 0:  # if the prefix is shorter than the requested bpos
            wildcard_minlen = l_max(wildcard_minlen + first_pos, 0)
            wildcard_maxlen = l_max(wildcard_maxlen + first_pos, 0)
            m_bpos += first_pos  # will always be >= 1
        m_bpos *= -1             # is now <= -1

        if bmap:  # if it's a backreference wildcard with a map file
            # Special case for when the first password has no wildcard characters appended
            if wildcard_minlen == 0:
                # If the wildcard was at the end of the string, we're done
                if password_postfix_with_wildcards == "":
                    yield full_password_prefix
                # Recurse to expand any additional wildcards possibly in password_postfix_with_wildcards
                else:
                    for password_expanded in expand_wildcards_generator(password_postfix_with_wildcards, full_password_prefix):
                        yield password_expanded

            # Expand the mapping backreference wildcard using the helper function (defined below)
            # (this helper function can't handle the special case above)
            for password_prefix_expanded in expand_mapping_backreference_wildcard(full_password_prefix, wildcard_minlen, wildcard_maxlen, m_bpos, bmap):

                # If the wildcard was at the end of the string, we're done
                if password_postfix_with_wildcards == "":
                    yield password_prefix_expanded
                # Recurse to expand any additional wildcards possibly in password_postfix_with_wildcards
                else:
                    for password_expanded in expand_wildcards_generator(password_postfix_with_wildcards, password_prefix_expanded):
                        yield password_expanded

        else:  # else it's a "normal" backreference wildcard (without a map file)
            # Construct the first password to be produced
            for i in range(0, wildcard_minlen):
                full_password_prefix += full_password_prefix[m_bpos]

            # Iterate over the [wildcard_minlen, wildcard_maxlen) range
            i = wildcard_minlen
            while True:

                # If the wildcard was at the end of the string, we're done
                if password_postfix_with_wildcards == "":
                    yield full_password_prefix
                # Recurse to expand any additional wildcards possibly in password_postfix_with_wildcards
                else:
                    for password_expanded in expand_wildcards_generator(password_postfix_with_wildcards, full_password_prefix):
                        yield password_expanded

                i += 1
                if i > wildcard_maxlen: break

                # Construct the next password
                full_password_prefix += full_password_prefix[m_bpos]

    # If it's an expanding wildcard
    elif is_expanding:
        # Iterate through specified wildcard lengths
        for wildcard_len in l_range(wildcard_minlen, wildcard_maxlen+1):

            # Expand the wildcard into a length of characters according to the wildcard type/caseflag
            for wildcard_expanded_list in itertools.product(wildcard_set, repeat=wildcard_len):
                # If the wildcard was at the end of the string, we're done
                if password_postfix_with_wildcards == "":
                    yield full_password_prefix + tstr().join(wildcard_expanded_list)
                    continue
                # Recurse to expand any additional wildcards possibly in password_postfix_with_wildcards
                for password_expanded in expand_wildcards_generator(password_postfix_with_wildcards, full_password_prefix + tstr().join(wildcard_expanded_list)):
                    yield password_expanded

    # Otherwise it's a contracting wildcard
    else:
        # Determine the max # of characters that can be removed from either the left
        # or the right of the wildcard, not yet taking wildcard_maxlen into account
        max_from_left  = l_len(password_prefix) if m_type in "<-" else 0
        if m_type in ">-":
            max_from_right = password_postfix_with_wildcards.find("%")
            if max_from_right == -1: max_from_right = l_len(password_postfix_with_wildcards)
        else:
            max_from_right = 0

        # Iterate over the total number of characters to remove
        for remove_total in l_range(wildcard_minlen, l_min(wildcard_maxlen, max_from_left+max_from_right) + 1):

            # Iterate over the number of characters to remove from the right of the wildcard
            # (this loop runs just once for %#,#< or %#,#> ; or for %#,#- at the beginning or end)
            for remove_right in l_range(l_max(0, remove_total-max_from_left), l_min(remove_total, max_from_right) + 1):
                remove_left = remove_total-remove_right

                password_prefix_contracted = full_password_prefix[:-remove_left] if remove_left else full_password_prefix

                # If the wildcard was at the end or if there's nothing remaining on the right, we're done
                if l_len(password_postfix_with_wildcards) - remove_right == 0:
                    yield password_prefix_contracted
                    continue
                # Recurse to expand any additional wildcards possibly in password_postfix_with_wildcards
                for password_expanded in expand_wildcards_generator(password_postfix_with_wildcards[remove_right:], password_prefix_contracted):
                    yield password_expanded


# Recursive helper generator function for expand_wildcards_generator():
#   password_prefix -- the fully expanded password before a %b wildcard
#   minlen, maxlen  -- the min and max from a %#,#b wildcard
#   bpos            -- from a %;#b wildcard, this is -#
#   bmap            -- the dict associated with the file in a %;file;b wildcard
# This function assumes all range checking has already been performed.
def expand_mapping_backreference_wildcard(password_prefix, minlen, maxlen, bpos, bmap):
    for wildcard_expanded in bmap.get(password_prefix[bpos], (password_prefix[bpos],)):
        password_prefix_expanded = password_prefix + wildcard_expanded
        if minlen <= 1:
            yield password_prefix_expanded
        if maxlen > 1:
            for password_expanded in expand_mapping_backreference_wildcard(password_prefix_expanded, minlen-1, maxlen-1, bpos, bmap):
                yield password_expanded


# capslock_typos_generator() is a generator function which tries swapping the case of
# the entire password (producing just one variation of the password_base in addition
# to the password_base itself)
def capslock_typos_generator(password_base, min_typos = 0):
    global typos_sofar
    min_typos -= typos_sofar
    if min_typos > 1: return  # this generator can't ever generate more than 1 typo

    # Start with the unmodified password itself, and end if there's nothing left to do
    if min_typos   <= 0:          yield password_base
    if typos_sofar >= args.typos: return

    password_swapped = password_base.swapcase()
    if password_swapped != password_base:
        typos_sofar += 1
        yield password_swapped
        typos_sofar -= 1


# swap_typos_generator() is a generator function which produces all possible combinations
# of the password_base where zero or more pairs of adjacent characters are swapped. Even
# when multiple swapping typos are requested, any single character is never swapped more
# than once per generated password.
def swap_typos_generator(password_base, min_typos = 0):
    global typos_sofar
    # Copy a few globals into local for a small speed boost
    l_range                 = range
    l_itertools_combinations = itertools.combinations
    l_args_nodupchecks       = args.no_dupchecks

    # Start with the unmodified password itself
    min_typos -= typos_sofar
    if min_typos <= 0: yield password_base

    # First swap one pair of characters, then all combinations of 2 pairs, then of 3,
    # up to the max requested or up to the max number swappable (whichever's less). The
    # max number swappable is len // 2 because we never swap any single character twice.
    password_base_len = len(password_base)
    max_swaps = min(args.max_typos_swap, args.typos - typos_sofar, password_base_len // 2)
    for swap_count in l_range(max(1, min_typos), max_swaps + 1):
        typos_sofar += swap_count

        # Generate all possible combinations of swapping exactly swap_count characters;
        # swap_indexes is a list of indexes of characters that will be swapped in a
        # single guess (swapped with the character at the next position in the string)
        for swap_indexes in l_itertools_combinations(l_range(password_base_len-1), swap_count):

            # Look for adjacent indexes in swap_indexes (which would cause a single
            # character to be swapped more than once in a single guess), and only
            # continue if no such adjacent indexes are found
            for i in l_range(1, swap_count):
                if swap_indexes[i] - swap_indexes[i-1] == 1:
                    break
            else:  # if we left the loop normally (didn't break)

                # Perform and the actual swaps
                password = password_base
                for i in swap_indexes:
                    if password[i] == password[i+1] and l_args_nodupchecks < 4:  # "swapping" these would result in generating a duplicate guess
                        break
                    password = password[:i] + password[i+1:i+2] + password[i:i+1] + password[i+2:]
                else:  # if we left the loop normally (didn't break)
                    yield password

        typos_sofar -= swap_count


# Convenience functions currently only used by typo_closecase()
#
UNCASED_ID   = 0
LOWERCASE_ID = 1
UPPERCASE_ID = 2
def case_id_of(letter):
    if   letter.islower(): return LOWERCASE_ID
    elif letter.isupper(): return UPPERCASE_ID
    else:                  return UNCASED_ID
#
# Note that  in order for a case to be considered changed, one of the two letters must be
# uppercase (i.e. lowercase to uncased isn't a case change, but uppercase to uncased is a
# case change, and of course lowercase to uppercase is too)
def case_id_changed(case_id1, case_id2):
    if case_id1 != case_id2 and (case_id1 == UPPERCASE_ID or case_id2 == UPPERCASE_ID):
          return True
    else: return False


# simple_typos_generator() is a generator function which, given a password_base, produces
# all possible combinations of typos of that password_base, of a count and of types specified
# at the command line. See the Configurables section for a list and description of the
# available simple typo generator types/functions. (The simple_typos_generator() function
# itself isn't very simple... it's called "simple" because the functions in the Configurables
# section which simple_typos_generator() calls are simple; they are collectively called
# simple typo generators)
def simple_typos_generator(password_base, min_typos = 0):
    global typos_sofar
    # Copy a few globals into local for a small speed boost
    l_range               = range
    l_itertools_product    = itertools.product
    l_product_max_elements = product_max_elements
    l_enabled_simple_typos = enabled_simple_typos
    l_max_simple_typos     = max_simple_typos
    assert len(enabled_simple_typos) > 0, "simple_typos_generator: at least one simple typo enabled"

    # Start with the unmodified password itself
    min_typos -= typos_sofar
    if min_typos <= 0: yield password_base

    # First change all single characters, then all combinations of 2 characters, then of 3, etc.
    password_base_len = len(password_base)
    max_typos         = min(sum_max_simple_typos, args.typos - typos_sofar, password_base_len)
    for typos_count in l_range(max(1, min_typos), max_typos + 1):
        typos_sofar += typos_count

        # Pre-calculate all possible permutations of the chosen simple_typos_choices
        # (possibly limited to individual maximums specified by max_simple_typos)
        if l_max_simple_typos:
            simple_typo_permutations = tuple(l_product_max_elements(l_enabled_simple_typos, typos_count, l_max_simple_typos))
        else:  # use the faster itertools version if possible
            simple_typo_permutations = tuple(l_itertools_product(l_enabled_simple_typos, repeat=typos_count))

        # Select the indexes of exactly typos_count characters from the password_base
        # that will be the target of the typos (out of all possible combinations thereof)
        for typo_indexes in itertools.combinations(l_range(password_base_len), typos_count):
            # typo_indexes_ has an added sentinel at the end; it's the index of
            # one-past-the-end of password_base. This is used in the inner loop.
            typo_indexes_ = typo_indexes + (password_base_len,)

            # Apply each possible permutation of simple typo generators to
            # the typo targets selected above (using the pre-calculated list)
            for typo_generators_per_target in simple_typo_permutations:
                # For each of the selected typo target(s), call the generator(s) selected above
                # to get the replacement(s) of said to-be-replaced typo target(s). Each item in
                # typo_replacements is an iterable (tuple, list, generator, etc.) producing
                # zero or more replacements for a single target. If there are zero replacements
                # for any target, the for loop below intentionally produces no results at all.

                typo_replacements = [ generator(password_base, index) for index, generator in
                    list(zip(typo_indexes, typo_generators_per_target)) ]

                # one_replacement_set is a tuple of exactly typos_count length, with one
                # replacement per selected typo target. If all of the selected generators
                # above each produce only one replacement, this loop will execute once with
                # that one replacement set. If one or more of the generators produce multiple
                # replacements (for a single target), this loop iterates across all possible
                # combinations of those replacements. If any generator produces zero outputs
                # (therefore that the target has no typo), this loop iterates zero times.
                for one_replacement_set in l_itertools_product(*typo_replacements):
                    # Construct a new password, left-to-right, from password_base and the
                    # one_replacement_set. (Note the use of typo_indexes_, not typo_indexes.)
                    password = password_base[0:typo_indexes_[0]]
                    for i, replacement in enumerate(one_replacement_set):
                        password += replacement + password_base[typo_indexes_[i]+1:typo_indexes_[i+1]]

                    yield password

        typos_sofar -= typos_count

# product_max_elements() is a generator function similar to itertools.product() except that
# it takes an extra argument:
#     max_elements  -  a list of length == len(sequence) of positive (non-zero) integers
# When min(max_elements) >= r, these two calls are equivalent:
#     itertools.product(sequence, repeat=r)
#     product_max_elements(sequence, r, max_elements)
# When one of the integers in max_elements < r, then the corresponding element of sequence
# is never repeated in any single generated output more than the requested number of times.
# For example:
#     tuple(product_max_elements(['a', 'b'], 3, [1, 2]))  ==
#     (('a', 'b', 'b'), ('b', 'a', 'b'), ('b', 'b', 'a'))
# Just like itertools.product, each output generated is of length r. Note that if
# sum(max_elements) < r, then zero outputs are (inefficiently) produced.
def product_max_elements(sequence, repeat, max_elements):
    if repeat == 1:
        for choice in sequence:
            yield (choice,)
        return

    # If all of the max_elements are >= repeat, just use the faster itertools version
    if min(max_elements) >= repeat:
        for product in itertools.product(sequence, repeat=repeat):
            yield product
        return

    # Iterate through the elements to choose one for the first position
    for i, choice in enumerate(sequence):

        # If this is the last time this element can be used, remove it from the sequence when recursing
        if max_elements[i] == 1:
            for rest in product_max_elements(sequence[:i] + sequence[i+1:], repeat - 1, max_elements[:i] + max_elements[i+1:]):
                yield (choice,) + rest

        # Otherwise, just reduce it's allowed count before recursing to generate the rest of the result
        else:
            max_elements[i] -= 1
            for rest in product_max_elements(sequence, repeat - 1, max_elements):
                yield (choice,) + rest
            max_elements[i] += 1


# insert_typos_generator() is a generator function which inserts one or more strings
# from the typos_insert_expanded list between every pair of characters in password_base,
# as well as at its beginning and its end.
def insert_typos_generator(password_base, min_typos = 0):
    global typos_sofar
    # Copy a few globals into local for a small speed boost
    l_max_adjacent_inserts = args.max_adjacent_inserts
    l_range               = range
    l_itertools_product    = itertools.product

    # Start with the unmodified password itself
    min_typos -= typos_sofar
    if min_typos <= 0: yield password_base

    password_base_len = len(password_base)
    assert l_max_adjacent_inserts > 0
    if l_max_adjacent_inserts > 1:
        # Can select for insertion the same index more than once in a single guess
        combinations_function = itertools.combinations_with_replacement
        max_inserts = min(args.max_typos_insert, args.typos - typos_sofar)
    else:
        # Will select for insertion an index at most once in a single guess
        combinations_function = itertools.combinations
        max_inserts = min(args.max_typos_insert, args.typos - typos_sofar, password_base_len + 1)

    # First insert a single string, then all combinations of 2 strings, then of 3, etc.
    for inserts_count in l_range(max(1, min_typos), max_inserts + 1):
        typos_sofar += inserts_count

        # Select the indexes (some possibly the same) of exactly inserts_count characters
        # from the password_base before which new string(s) will be inserted
        for insert_indexes in combinations_function(l_range(password_base_len + 1), inserts_count):

            # If multiple inserts are permitted at a single location, make sure they're
            # limited to args.max_adjacent_inserts. (If multiple inserts are not permitted,
            # they are never produced by the combinations_function selected earlier.)
            if l_max_adjacent_inserts > 1 and inserts_count > l_max_adjacent_inserts:
                too_many_adjacent = False
                last_index = -1
                for index in insert_indexes:
                    if index != last_index:
                        adjacent_count = 1
                        last_index = index
                    else:
                        adjacent_count += 1
                        too_many_adjacent = adjacent_count > l_max_adjacent_inserts
                        if too_many_adjacent: break
                if too_many_adjacent: continue

            # insert_indexes_ has an added sentinel at the end; it's the index of
            # one-past-the-end of password_base. This is used in the inner loop.
            insert_indexes_ = insert_indexes + (password_base_len,)

            # For each of the selected insert indexes, select a replacement from
            # typos_insert_expanded (which is created in parse_arguments() )
            for one_insertion_set in l_itertools_product(typos_insert_expanded, repeat = inserts_count):

                # Construct a new password, left-to-right, from password_base and the
                # one_insertion_set. (Note the use of insert_indexes_, not insert_indexes.)
                password = password_base[0:insert_indexes_[0]]
                for i, insertion in enumerate(one_insertion_set):
                    password += insertion + password_base[insert_indexes_[i]:insert_indexes_[i+1]]
                yield password

        typos_sofar -= inserts_count

# password_repeats_generator() is a generator function which creates repetitions of the base password
def password_repeats_generator(password_base, min_typos = 0):
    global typos_sofar

    # Copy a few globals into local for a small speed boost
    l_max_password_repeats = args.max_password_repeats

    for i in range(1,l_max_password_repeats+1):
        yield password_base * (i)

################################### Main ###################################


# Simply forwards calls on to the return_verified_password_or_false()
# member function of the currently loaded global wallet
def return_verified_password_or_false(passwords):
    try:
        return loaded_wallet.return_verified_password_or_false(passwords)
    except Exception as e:
        # pyopencl exceptions contain unpicklable _ErrorRecord objects.
        # Convert to a plain RuntimeError so it can cross process boundaries.
        raise RuntimeError(f"Worker error: {type(e).__name__}: {e}") from None

# Init function for the password verifying worker processes:
#   (re-)loads the wallet & mode (should only be necessary on Windows),
#   tries to set the process priority to minimum, and
#   begins ignoring SIGINTs for a more graceful exit on Ctrl-C
loaded_wallet = None  # initialized once at global scope for Windows
def init_worker(wallet, char_mode, worker_out_queue = None):
    global loaded_wallet
    if not loaded_wallet:
        loaded_wallet = wallet
        if char_mode == str:
            enable_unicode_mode()
        else:
            assert False
        try:
            loaded_wallet._load_wordlist() # Load the wordlist for each worker (Allows word ID lookups in the solver thread, required for Electrum1)
        except:
            pass #don't really care if it doesn't load in terms of performance, this is only called at worker thread creation

    if worker_out_queue:
        loaded_wallet.worker_out_queue = worker_out_queue

    try:
        # If GPU usage is enabled, create the openCL contexts for the workers
        if loaded_wallet.opencl_algo == 0:
            # Split up GPU's over available worker threads
            worker_number = int(multiprocessing.current_process().name.split("-")[1]) - 1
            try:
                openclDevice = loaded_wallet.opencl_devices[worker_number % len(loaded_wallet.opencl_devices)]
            except Exception:
                devices = pyopencl.get_platforms()[loaded_wallet.opencl_platform].get_devices()
                openclDevice = worker_number % len(devices)
            #print("Creating Context for Device :", openclDevice)
            btcrecover.opencl_helpers.init_opencl_contexts(loaded_wallet, openclDevice = openclDevice)

    except Exception as errormessage:
        print(errormessage)
        pass

    set_process_priority_idle()
    signal.signal(signal.SIGINT, signal.SIG_IGN)

#
def set_process_priority_idle():
    try:
        if sys.platform == "win32":
            import ctypes, ctypes.wintypes
            GetCurrentProcess = ctypes.windll.kernel32.GetCurrentProcess
            GetCurrentProcess.argtypes = ()
            GetCurrentProcess.restype  = ctypes.wintypes.HANDLE
            SetPriorityClass = ctypes.windll.kernel32.SetPriorityClass
            SetPriorityClass.argtypes = ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD
            SetPriorityClass.restype  = ctypes.wintypes.BOOL
            SetPriorityClass(GetCurrentProcess(), 0x00000040)  # IDLE_PRIORITY_CLASS
        else:
            os.nice(19)
    except Exception: pass

# If an out-of-memory error occurs which can be handled, free up some memory, display
# an informative error message, and then return True, otherwise return False.
# Generally a call to handle_oom() should be followed by a sys.exit(1)
def handle_oom():
    global password_dups, token_combination_dups  # these are the memory-hogging culprits
    if password_dups and password_dups._run_number == 0:
        del password_dups, token_combination_dups
        gc.collect()
        print()  # move to the next line
        print("Error: out of memory", file=sys.stderr)
        print("Notice: the --no-dupchecks option will reduce memory usage at the possible expense of speed", file=sys.stderr)
        return True
    elif token_combination_dups and token_combination_dups._run_number == 0:
        del token_combination_dups
        gc.collect()
        print()  # move to the next line
        print("Error: out of memory", file=sys.stderr)
        print("Notice: the --no-dupchecks option can be specified twice to further reduce memory usage", file=sys.stderr)
        return True
    return False


# Saves progress by overwriting the older (of two) slots in the autosave file
# (autosave_nextslot is initialized in load_savestate() or parse_arguments() )
def do_autosave(skip, inside_interrupt_handler = False):
    print("SaveState: ", savestate, " Type:", type(savestate))
    global autosave_nextslot
    assert autosave_file and not autosave_file.closed,           "do_autosave: autosave_file is open"
    assert isinstance(savestate, dict) and "argv" in savestate, "do_autosave: savestate is initialized"
    if not inside_interrupt_handler:
        sigint_handler  = signal.signal(signal.SIGINT,  signal.SIG_IGN)    # ignore Ctrl-C,
        sigterm_handler = signal.signal(signal.SIGTERM, signal.SIG_IGN)    # SIGTERM, and
        if sys.platform != "win32":  # (windows has no SIGHUP)
            sighup_handler = signal.signal(signal.SIGHUP, signal.SIG_IGN)  # SIGHUP while saving
    # Erase the target save slot so that a partially written save will be recognized as such
    if autosave_nextslot == 0:
        start_pos = 0
        autosave_file.seek(start_pos)
        autosave_file.write(SAVESLOT_SIZE * b"\0")
        autosave_file.flush()
        try:   os.fsync(autosave_file.fileno())
        except Exception: pass
        autosave_file.seek(start_pos)
    else:
        assert autosave_nextslot == 1
        start_pos = SAVESLOT_SIZE
        autosave_file.seek(start_pos)
        autosave_file.truncate()
        try:   os.fsync(autosave_file.fileno())
        except Exception: pass
    savestate["skip"] = skip  # overwrite the one item which changes for each autosave
    pickle.dump(savestate, autosave_file)
    assert autosave_file.tell() <= start_pos + SAVESLOT_SIZE, "do_autosave: data <= "+str(SAVESLOT_SIZE)+" bytes long"
    autosave_file.flush()
    try:   os.fsync(autosave_file.fileno())
    except Exception: pass
    autosave_nextslot = 1 if autosave_nextslot==0 else 0
    if not inside_interrupt_handler:
        signal.signal(signal.SIGINT,  sigint_handler)
        signal.signal(signal.SIGTERM, sigterm_handler)
        if sys.platform != "win32":
            signal.signal(signal.SIGHUP, sighup_handler)

def count_passwords_async(current_passwords_count):
    try:
        for passwords_count in passwords_count_generator:
            current_passwords_count.value = passwords_count
    except BaseException as e:
        raise Exception(e.code)

def count_and_check_eta_dynamic(est_secs_per_password):
    assert est_secs_per_password > 0.0, "count_and_check_eta_dynamic: est_secs_per_password > 0.0"
    assert args.skip >= 0
    max_seconds = args.max_eta * 3600  # max_eta is in hours
    passwords_count_iterator = password_generator(PASSWORDS_BETWEEN_UPDATES, only_yield_count=True)
    passwords_counted = 0
    # Iterate though the password counts in increments of size PASSWORDS_BETWEEN_UPDATES
    for passwords_counted_last in passwords_count_iterator:
        passwords_counted += passwords_counted_last
        unskipped_passwords_counted = passwords_counted - args.skip

        # If the ETA is past its max permitted limit, exit
        if unskipped_passwords_counted * est_secs_per_password > max_seconds:
            error_exit("\rat least {:,} passwords to try, ETA > --max-eta option ({} hours), exiting" \
                .format(passwords_counted - args.skip, args.max_eta))

        yield passwords_counted

# Given an est_secs_per_password, counts the *total* number of passwords generated by password_generator()
# (including those skipped by args.skip), and returns the result, checking the --max-eta constraint along
# the way (and exiting if it's violated). Displays messages to the user if the process is taking a while.
def count_and_check_eta(est):
    assert est > 0.0, "count_and_check_eta: est_secs_per_password > 0.0"
    return password_generator_factory(est_secs_per_password = est)[1]

# Creates a password iterator from the chosen password_generator() and advances it past skipped passwords (as
# per args.skip), returning a tuple: new_iterator, #_of_passwords_skipped. Displays messages to the user if the
# process is taking a while. (Or does the work of count_and_check_eta() when passed est_secs_per_password.)
SECONDS_BEFORE_DISPLAY    = 5.0
PASSWORDS_BETWEEN_UPDATES = 100000
def password_generator_factory(chunksize = 1, est_secs_per_password = 0):
    # If est_secs_per_password is zero, only skipping is performed;
    # if est_secs_per_password is non-zero, all passwords (including skipped ones) are counted.

    # If not counting all passwords (if only skipping)
    if not est_secs_per_password:
        # The simple case where there's nothing to skip, just return an unmodified password_generator()
        if args.skip <= 0:
            return password_generator(chunksize), 0
        # The still fairly simple case where there's not much to skip, just skip it all at once
        elif args.skip <= PASSWORDS_BETWEEN_UPDATES:
            passwords_count_iterator = password_generator(args.skip, only_yield_count=True)
            passwords_counted = 0
            try:
                # Skip it all in a single iteration (or raise StopIteration if it's empty)
                passwords_counted = passwords_count_iterator.__next__()
                passwords_count_iterator.send( (chunksize, False) )  # change it into a "normal" iterator
            except StopIteration: pass
            return passwords_count_iterator, passwords_counted

    assert args.skip >= 0
    sys_stderr_isatty = sys.stderr.isatty()
    max_seconds = args.max_eta * 3600  # max_eta is in hours
    passwords_count_iterator = password_generator(PASSWORDS_BETWEEN_UPDATES, only_yield_count=True)
    passwords_counted = 0
    is_displayed = False
    start = time.perf_counter() if sys_stderr_isatty else None
    try:
        # Iterate though the password counts in increments of size PASSWORDS_BETWEEN_UPDATES
        for passwords_counted_last in passwords_count_iterator:
            passwords_counted += passwords_counted_last
            unskipped_passwords_counted = passwords_counted - args.skip

            # If it's taking a while, and if we're not almost done, display/update the on-screen message

            if not is_displayed and sys_stderr_isatty and time.perf_counter() - start > SECONDS_BEFORE_DISPLAY and (
                    est_secs_per_password or passwords_counted * 1.5 < args.skip):
                print("Counting passwords ..." if est_secs_per_password else "Skipping passwords ...", file=sys.stderr)
                is_displayed = True

            if is_displayed:
                # If ETAs were requested, calculate and possibly display one
                if est_secs_per_password:
                    # Only display an ETA once unskipped passwords are being counted
                    if unskipped_passwords_counted > 0:
                        eta = unskipped_passwords_counted * est_secs_per_password / 60
                        if eta < 90:     eta = str(int(eta)+1) + " minutes"  # round up
                        else:
                            eta /= 60
                            if eta < 48: eta = str(int(round(eta))) + " hours"
                            else:        eta = str(round(eta / 24, 1)) + " days"
                        msg = "\r  {:,}".format(passwords_counted)
                        if args.skip: msg += " (includes {:,} skipped)".format(args.skip)
                        msg += "  ETA: " + eta + " and counting   "
                        print(msg, end="", file=sys.stderr)
                    # Else just indicate that all the passwords counted so far are skipped
                    else:
                        print("\r  {:,} (all skipped)".format(passwords_counted), end="", file=sys.stderr)
                #
                # Else no ETAs were requested, just display the count ("Skipping passwords ..." was already printed)
                else:
                    print("\r  {:,}".format(passwords_counted), end="", file=sys.stderr)

            # If the ETA is past its max permitted limit, exit
            if unskipped_passwords_counted * est_secs_per_password > max_seconds:
                error_exit("\rat least {:,} passwords to try, ETA > --max-eta option ({} hours), exiting" \
                    .format(passwords_counted - args.skip, args.max_eta))

            # If not counting all the passwords, then break out of this loop before it's gone past args.skip
            # (actually it must leave at least one password left to count before the args.skip limit)
            if not est_secs_per_password and passwords_counted >= args.skip - PASSWORDS_BETWEEN_UPDATES:
                break

        # Erase the on-screen counter if it was being displayed
        if is_displayed:
            print("\rDone" + " "*74, file=sys.stderr)

        # If all passwords were being/have been counted
        if est_secs_per_password:
            return None, passwords_counted

        # Else finish counting the final (probably partial) iteration of skipped passwords
        # (which will be in the range [1, PASSWORDS_BETWEEN_UPDATES] )
        else:
            try:
                passwords_count_iterator.send( (args.skip - passwords_counted, True) )  # the remaining count
                passwords_counted += passwords_count_iterator.__next__()
                passwords_count_iterator.send( (chunksize, False) )  # change it into a "normal" iterator
            except StopIteration: pass
            return passwords_count_iterator, passwords_counted

    except SystemExit: raise  # happens when error_exit is called above
    except BaseException as e:
        handled = handle_oom() if isinstance(e, MemoryError) and passwords_counted > 0 else False
        if not handled: print(file=sys.stderr)  # move to the next line if handle_oom() hasn't already done so

        counting_or_skipping = "counting" if est_secs_per_password else "skipping"
        including_skipped    = "(including skipped ones)" if est_secs_per_password and args.skip else ""
        print("Interrupted after", counting_or_skipping, passwords_counted, "passwords", including_skipped, file=sys.stderr)

        if handled:                          sys.exit(1)
        if isinstance(e, KeyboardInterrupt): sys.exit(0)
        raise

# Writes the checksummed seed phrases out to the file specified in the listvalid argument
# This function runs in its own process and consumes the seeds which are placed in the queue by the worker threads
def write_checked_seeds(worker_out_queue,loaded_wallet):
    current_file_valid_seed_count = 0
    seedfile_suffix = 0
    while worker_out_queue.qsize() < 10: #If the workers haven't started filling the queue yet, just sleep
        time.sleep(10)
    try:
        with open(loaded_wallet._savevalidseeds + "_" + '{:04d}'.format(seedfile_suffix) + ".txt", mode='a', buffering = 10240) as listfile:
            while True:
                listfile.write(" ".join(worker_out_queue.get(timeout = 5)).strip('()[]') + "\n")
                current_file_valid_seed_count += 1
                if current_file_valid_seed_count > loaded_wallet._seedfilecount:
                    listfile.close()
                    seedfile_suffix += 1
                    current_file_valid_seed_count = 0
                    listfile = open(loaded_wallet._savevalidseeds + "_" + '{:04d}'.format(seedfile_suffix) + ".txt", mode='a', buffering = 10240)

    except multiprocessing.queues.Empty:
        print("Save List Writer Finished")

# Should be called after calling parse_arguments()
# Returns a two-element tuple:
#   the first element is the password, if found, otherwise False;
#   the second is a human-readable result iff no password was found; or
#   returns (None, None) for abnormal but not fatal errors (e.g. Ctrl-C)
def main():

    # Once installed, performs cleanup prior to a requested process shutdown on Windows
    # (this is defined inside main so it can access the passwords_tried local)
    def windows_ctrl_handler(signal):
        if signal == 0:   # if it's a Ctrl-C,
           return False   # defer to the native Python handler which works just fine
        #
        # Python on Windows is a bit touchy with signal handlers; it's safest to just do
        # all the cleanup code here (even though it'd be cleaner to throw an exception)
        if savestate:
            do_autosave(args.skip + passwords_tried, inside_interrupt_handler=True)  # do this first, it's most important
            autosave_file.close()
        print("\nInterrupted after finishing password #", args.skip + passwords_tried, file=sys.stderr)
        if sys.stdout.isatty() ^ sys.stderr.isatty():  # if they're different, print to both to be safe
            print("\nInterrupted after finishing password #", args.skip + passwords_tried)
        os._exit(1)

    # Copy a global into local for a small speed boost
    l_savestate = savestate

    # If --listpass was requested, just list out all the passwords and exit
    passwords_count = 0
    if args.listpass:
        password_iterator, skipped_count = password_generator_factory()
        plus_skipped = " (plus " + str(skipped_count) + " skipped)" if skipped_count else ""
        try:
            for password in password_iterator:
                passwords_count += 1
                if type(password[0]) in (tuple, list): # If we are printing seed phrases
                    password = " ".join(password[0])
                    print(password)
                else:
                    print(password[0])
        except BaseException as e:
            handled = handle_oom() if isinstance(e, MemoryError) and passwords_count > 0 else False
            if not handled: print()  # move to the next line
            print("Interrupted after generating", passwords_count, "passwords" + plus_skipped, file=sys.stderr)
            if handled:                          sys.exit(1)
            if isinstance(e, KeyboardInterrupt): sys.exit(0)
            raise
        return None, str(passwords_count) + " password combinations" + plus_skipped

    try:
        print("Wallet Type:", str(type(loaded_wallet))[19:-2])
        print("Wallet difficulty:", loaded_wallet.difficulty_info())
    except AttributeError: pass

    # Measure the performance of the verification function
    # (for CPU, run for about 0.5s; for GPU, run for one global-worksize chunk)
    if args.performance and args.enable_gpu:  # skip this time-consuming & unnecessary measurement in this case
        est_secs_per_password = 0.01          # set this to something relatively big, it doesn't matter exactly what
    else:
        if args.enable_gpu:
            inner_iterations = sum(args.global_ws)
            outer_iterations = 1
            approx_passwords = loaded_wallet.passwords_per_seconds(0.5)
        else:
            # Passwords are verified in "chunks" to reduce call overhead. One chunk includes enough passwords to
            # last for about 1/100th of a second (determined experimentally to be about the best I could do, YMMV)
            CHUNKSIZE_SECONDS = 1.0 / 100.0
            measure_performance_iterations = loaded_wallet.passwords_per_seconds(0.5)
            inner_iterations = int(round(2 * measure_performance_iterations * CHUNKSIZE_SECONDS)) or 1  # the "2*" is due to the 0.5 seconds above
            outer_iterations = max(1, int(round(measure_performance_iterations / inner_iterations)))
            approx_passwords = measure_performance_iterations

        approx_passwords = max(approx_passwords, 1)
        fallback_estimate = 0.5 / float(approx_passwords)

        skip_pre_start = getattr(args, "skip_pre_start", False)
        pre_start_limit = getattr(args, "pre_start_seconds", 30.0)

        if pre_start_limit is not None:
            if pre_start_limit < 0:
                print("Warning: --pre-start-seconds must be >= 0, skipping benchmark", file=sys.stderr)
                skip_pre_start = True
                pre_start_limit = None
            elif pre_start_limit == 0:
                skip_pre_start = True
                pre_start_limit = None

        if skip_pre_start:
            print("Skipping pre-start benchmark; progress estimates may be less accurate.")
            est_secs_per_password = fallback_estimate
        else:
            message = "Pre-start benchmark: measuring verification speed"
            if pre_start_limit is not None:
                message += " (limit {:.3g} seconds)".format(pre_start_limit)
            message += ". Use --skip-pre-start to skip or --pre-start-seconds to limit this step."
            print(message)

            performance_generator = performance_base_password_generator()  # generates dummy passwords
            start = timeit.default_timer()
            iterations_done = 0

            loaded_wallet.pre_start_benchmark = True
            try:
                for o in range(outer_iterations):
                    loaded_wallet.return_verified_password_or_false(list(
                        itertools.islice(filter(custom_final_checker, performance_generator), inner_iterations)))
                    iterations_done += inner_iterations
                    if pre_start_limit is not None and timeit.default_timer() - start >= pre_start_limit:
                        break
            finally:
                loaded_wallet.pre_start_benchmark = False
                del performance_generator

            elapsed = timeit.default_timer() - start
            if iterations_done <= 0 or elapsed <= 0:
                est_secs_per_password = fallback_estimate
            else:
                est_secs_per_password = elapsed / iterations_done
                rate = iterations_done / elapsed
                print("Pre-start benchmark completed in {:.2f}s ({:.2f} passwords/s).".format(elapsed, rate))

        assert isinstance(est_secs_per_password, float) and est_secs_per_password > 0.0

    if args.enable_gpu:
        chunksize = sum(args.global_ws)
    elif args.enable_opencl:
        chunksize = loaded_wallet.chunksize
    else:
        # (see CHUNKSIZE_SECONDS above)
        chunksize = int(round(CHUNKSIZE_SECONDS / est_secs_per_password)) or 1

    # If the time to verify a password is short enough, the time to generate the passwords in this thread
    # becomes comparable to verifying passwords, therefore this should count towards being a "worker" thread
    if est_secs_per_password < 1.0 / 75000.0:
        main_thread_is_worker = True
        spawned_threads   = args.threads - 1      # spawn 1 fewer than requested (might be 0)
        verifying_threads = spawned_threads or 1
    else:
        main_thread_is_worker = False
        spawned_threads   = args.threads if args.threads > 1 else 0
        verifying_threads = args.threads

    # Adjust estimate for the number of verifying threads (final estimate is probably an underestimate)
    est_secs_per_password /= min(verifying_threads, logical_cpu_cores)

    # Count how many passwords there are (excluding skipped ones) so we can display and conform to ETAs
    if not args.no_eta:

        assert args.skip >= 0
        if args.dynamic_passwords_count:
            # this is global because it's used in count_passwords_async
            global passwords_count_generator
            passwords_count_generator = count_and_check_eta_dynamic(est_secs_per_password)
        elif l_savestate and "total_passwords" in l_savestate and args.no_dupchecks:
            passwords_count = l_savestate["total_passwords"]  # we don't need to do a recount
            iterate_time = 0
        else:
            start = time.perf_counter()
            passwords_count = count_and_check_eta(est_secs_per_password)
            iterate_time = time.perf_counter() - start
            if l_savestate:
                if "total_passwords" in l_savestate:
                    assert l_savestate["total_passwords"] == passwords_count, "main: saved password count matches actual count"
                else:
                    l_savestate["total_passwords"] = passwords_count

        if not args.dynamic_passwords_count:
            passwords_count -= args.skip
            if passwords_count <= 0:
                return False, "Skipped all "+str(passwords_count + args.skip)+" passwords, exiting"

        # If additional ETA calculations are required
        if not args.dynamic_passwords_count and (l_savestate or not have_progress):
            eta_seconds = passwords_count * est_secs_per_password
            # if the main thread is sharing CPU time with a verifying thread
            if spawned_threads == 0 and not args.enable_gpu or spawned_threads >= logical_cpu_cores:
                eta_seconds += iterate_time
            if l_savestate:
                est_passwords_per_5min = int(round(passwords_count / eta_seconds * 300.0))
                assert est_passwords_per_5min > 0
            eta_seconds = int(round(eta_seconds)) or 1

    # else if args.no_eta and savestate, calculate a simple approximate of est_passwords_per_5min
    elif l_savestate:
        est_passwords_per_5min = int(round(300.0 / est_secs_per_password))
        assert est_passwords_per_5min > 0

    # If there aren't many passwords, give each of the N workers 1/Nth of the passwords
    # (rounding up) and also don't bother spawning more threads than there are passwords
    # note that if the passwords are counted dynamically, we can't tell that there aren't many passwords
    if not args.dynamic_passwords_count and not args.no_eta and spawned_threads * chunksize > passwords_count:
        if spawned_threads > passwords_count:
            spawned_threads = passwords_count
        chunksize = (passwords_count-1) // spawned_threads + 1

    # Create an iterator which produces the password permutations in chunks, skipping some if so instructed
    if args.skip > 0:
        print("Starting with password #", args.skip + 1)
    password_iterator, skipped_count = password_generator_factory(chunksize)
    if skipped_count < args.skip:
        assert args.no_eta, "discovering all passwords have been skipped this late only happens if --no-eta"
        return False, "Skipped all "+str(skipped_count)+" passwords, exiting"
    assert skipped_count == args.skip

    # Print Timestamp that this step occured
    print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ": ", end="")

    if args.enable_gpu:
        cl_devices = loaded_wallet._cl_devices
        if len(cl_devices) == 1:
            print("Using OpenCL", pyopencl.device_type.to_string(cl_devices[0].type), cl_devices[0].name.strip())
        else:
            print("Using", len(cl_devices), "OpenCL devices:")
            for dev in cl_devices:
                print(" ", pyopencl.device_type.to_string(dev.type), dev.name.strip())
    else:
        print("Using", args.threads, "worker", "threads" if args.threads > 1 else "thread")  # (they're actually worker processes)

    if have_progress:
        if args.no_eta:
            progress = progressbar.ProgressBar(maxval=progressbar.UnknownLength, poll=0.1, widgets=[
                progressbar.AnimatedMarker(),
                progressbar.FormatLabel(" %(value)d  elapsed: %(elapsed)s  rate: "),
                progressbar.FileTransferSpeed(unit="P")
            ])
            progress.update_interval = sys.maxsize  # work around performance bug in ProgressBar
        else:
            if args.dynamic_passwords_count:
                try:
                    passwords_count = passwords_count_generator.__next__()

                except StopIteration:
                    passwords_count = 0
            progress = progressbar.ProgressBar(maxval=passwords_count, poll=0.1, widgets=[
                progressbar.SimpleProgress(), " ",
                progressbar.Bar(left="[", fill="-", right="]"),
                progressbar.FormatLabel(" %(elapsed)s, "),
                progressbar.ETA()
            ])
    else:
        progress = None
        if args.dynamic_passwords_count:
            # TODO: print timeout estimate if not args.no_eta even
            #       if --dynamic-passwords-count is used
            print("Passwords will be counted dynamically")
        elif args.no_eta:
            print("Searching for password ...")
        else:
            # If progressbar is unavailable, print out a time estimate instead
            print("Will try {:,} passwords, ETA ".format(passwords_count), end="")
            eta_hours    = eta_seconds // 3600
            eta_seconds -= 3600 * eta_hours
            eta_minutes  = eta_seconds // 60
            eta_seconds -= 60 * eta_minutes
            if eta_hours   > 0: print(eta_hours,   "hours ",   end="")
            if eta_minutes > 0: print(eta_minutes, "minutes ", end="")
            if eta_hours  == 0: print(eta_seconds, "seconds ", end="")
            print("...")

    # Autosave the starting state now that we're just about ready to start
    if l_savestate: do_autosave(args.skip)

    # Try to release as much memory as possible (before forking if multiple workers are being used)
    # (the initial counting process can be memory intensive)
    gc.collect()

    # Try to create a multiprocessing Queue for inter-process communication.
    # On platforms where _multiprocessing is unavailable (e.g. Termux), fall back to None
    # and operate in single-threaded mode only.
    try:
        worker_out_queue = multiprocessing.Queue()
    except ImportError:
        worker_out_queue = None

    # Create an iterator which actually checks the (remaining) passwords produced by the password_iterator
    # by executing the return_verified_password_or_false worker function in possibly multiple threads
    if spawned_threads == 0 or worker_out_queue is None:
        pool = None
        if loaded_wallet.opencl_algo == 0:
            btcrecover.opencl_helpers.init_opencl_contexts(loaded_wallet)
        password_found_iterator = map(return_verified_password_or_false, password_iterator)
        set_process_priority_idle()  # this, the only thread, should be nice
    else:
        pool = multiprocessing.Pool(spawned_threads, init_worker, (loaded_wallet, tstr, worker_out_queue))
        if args.dynamic_passwords_count:
            current_passwords_count = multiprocessing.Manager().Value('current_passwords_count', progress.maxval if progress else 0)
            passwords_counting_result = pool.apply_async(count_passwords_async, args = (current_passwords_count,))
        password_found_iterator = pool.imap(return_verified_password_or_false, password_iterator)
        if main_thread_is_worker: set_process_priority_idle()  # if this thread is cpu-intensive, be nice

    # If we are writing out the checksummed seed files, spawn a process that will handle taking the seeds produced by the workers and writing them out to a file
    try:
        if loaded_wallet._savevalidseeds and worker_out_queue is not None:
            write_checked_seeds_worker = multiprocessing.Process(target = write_checked_seeds, args = (worker_out_queue,loaded_wallet))
            write_checked_seeds_worker.start()
    except AttributeError: # Not all loaded wallets will have this attribute
        pass

    # Try to catch all types of intentional program shutdowns so we can
    # display password progress information and do a final autosave
    windows_handler_routine = None
    try:
        sigint_handler = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGTERM, sigint_handler)     # OK to call on any OS
        if sys.platform != "win32":
            signal.signal(signal.SIGHUP, sigint_handler)  # can't call this on windows
        else:
            import ctypes, ctypes.wintypes
            HandlerRoutine = ctypes.WINFUNCTYPE(ctypes.wintypes.BOOL, ctypes.wintypes.DWORD)
            SetConsoleCtrlHandler = ctypes.windll.kernel32.SetConsoleCtrlHandler
            SetConsoleCtrlHandler.argtypes = HandlerRoutine, ctypes.wintypes.BOOL
            SetConsoleCtrlHandler.restype  = ctypes.wintypes.BOOL
            windows_handler_routine = HandlerRoutine(windows_ctrl_handler)  # creates a C callback from the Python function
            SetConsoleCtrlHandler(windows_handler_routine, True)
    except Exception: pass

    # Make est_passwords_per_5min evenly divisible by chunksize
    # (so that passwords_tried % est_passwords_per_5min will eventually == 0)
    if l_savestate:
        assert isinstance(est_passwords_per_5min, numbers.Integral)
        assert isinstance(chunksize,              numbers.Integral)
        est_passwords_per_5min = (est_passwords_per_5min // chunksize or 1) * chunksize

    # Iterate through password_found_iterator looking for a successful guess
    password_found  = False
    passwords_tried = 0
    performance_start_time = None
    performance_duration = getattr(args, 'performance_duration', None)
    if args.performance and performance_duration:
        performance_start_time = time.monotonic()
    if progress: progress.start()
    try:
        for password_found, passwords_tried_last in password_found_iterator:
            if password_found:
                if pool:
                    # Close the pool, but don't wait for (join) processes to exit gracefully on
                    # the off chance one is in an inconsistent state (otherwise the found password
                    # may never be printed). We also don't want pool to be garbage-collected when
                    # main() returns (it can cause confusing warnings), so keep a reference to it.
                    pool.close()
                    global _pool
                    _pool = pool
                passwords_tried += passwords_tried_last - 1  # just before the found password
                if progress:
                    progress.next_update = 0  # force a screen update
                    progress.update(passwords_tried)
                    print()  # move down to the line below the progress bar
                break
            passwords_tried += passwords_tried_last
            if progress:
                if args.dynamic_passwords_count:
                    progress.maxval = current_passwords_count.value
                    if passwords_counting_result.ready() and not passwords_counting_result.successful():
                        passwords_counting_result.get()
                progress.update(passwords_tried)
            if l_savestate and passwords_tried % est_passwords_per_5min == 0:
                do_autosave(args.skip + passwords_tried)
            # Check if --performance-duration has elapsed
            if performance_start_time is not None:
                if time.monotonic() - performance_start_time >= performance_duration:
                    if pool:
                        pool.close()
                        _pool = pool
                    if progress:
                        progress.maxval = passwords_tried
                        progress.finish()
                    elapsed = time.monotonic() - performance_start_time
                    rate = passwords_tried / elapsed if elapsed > 0 else 0
                    print("\nPerformance test completed: {:,} passwords in {:.1f}s ({:.2f} passwords/s)".format(
                        passwords_tried, elapsed, rate))
                    return (False, "Performance test completed: {:,} passwords in {:.1f}s ({:.2f} passwords/s)".format(
                        passwords_tried, elapsed, rate))
        else:  # if the for loop exits normally (without breaking)
            if pool: pool.close()
            if progress:
                if args.no_eta:
                    progress.maxval = passwords_tried
                else:
                    progress.widgets.pop()  # remove the ETA
                progress.finish()
            if pool: pool.join()  # if not found, waiting for processes to exit gracefully isn't a problem

    # Gracefully handle any exceptions, printing the count completed so far so that it can be
    # skipped if the user restarts the same run. If the exception was expected (Ctrl-C or some
    # other intentional shutdown, or an out-of-memory condition that can be handled), fall
    # through to the autosave, otherwise re-raise the exception.
    except BaseException as e:
        handled = handle_oom() if isinstance(e, MemoryError) and passwords_tried > 0 else False
        if not handled: print()  # move to the next line if handle_oom() hasn't already done so
        if pool: pool.close()

        print("Interrupted after finishing password #", args.skip + passwords_tried, file=sys.stderr)
        if sys.stdout.isatty() ^ sys.stderr.isatty():  # if they're different, print to both to be safe
            print("Interrupted after finishing password #", args.skip + passwords_tried)

        if not handled and not isinstance(e, KeyboardInterrupt): raise
        password_found = None  # neither False nor True -- unknown
    finally:
        if windows_handler_routine:
            SetConsoleCtrlHandler(windows_handler_routine, False)

    # Autosave the final state (for all non-error cases -- we're shutting down (e.g. Ctrl-C or a
    # reboot), the password was found, or the search was exhausted -- or for handled out-of-memory)
    if l_savestate:
        do_autosave(args.skip + passwords_tried)
        autosave_file.close()

    if worker_out_queue is not None:
        worker_out_queue.close()

    global searchfailedtext
    return (password_found, searchfailedtext if password_found is False else None)


# The wallet classes live in wallets.py; importing them here -- after every core
# definition they depend on -- binds their names into this module's namespace
# (preserving the historical public surface, e.g. btcrpass.WalletBitcoinCore)
# and runs their @register_wallet_class decorators, populating wallet_types.
from .wallets import WalletBitcoinCore, WalletPywallet, WalletMultiBit, EncryptionParams, WalletBitcoinj, WalletCoinomi, WalletMultiBitHD, WalletAndroidSpendingPIN, WalletMsigna, WalletElectrum, WalletElectrum1, WalletElectrum2, WalletElectrumLooseKey, WalletElectrum28, WalletBlockchain, WalletBlockchainSecondpass, WalletBlockIO, WalletBitGo, WalletDogechain, WalletMetamask, WalletBither, public_key_to_address, compress, private_key_to_public_key, bip38decrypt_ec, bip38decrypt_non_ec, prefactor_to_passpoint, WalletBIP38, WalletBIP39, WalletSLIP39, WalletCardano, WalletPyCryptoHDWallet, WalletEthereumValidator, WalletYoroi, WalletBrainwallet, WalletRawPrivateKey, WalletEthKeystore, WalletImtokenKeystore, Walletbtc_com, Wallettoastwallet, WalletNull  # noqa: E402,F401
