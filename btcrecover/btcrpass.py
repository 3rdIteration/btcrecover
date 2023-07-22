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

__version__          =  "1.12.0-Cryptoguide"
__ordering_version__ = b"0.6.4"  # must be updated whenever password ordering changes
disable_security_warnings = True

# Import modules included in standard libraries
import sys, argparse, itertools, string, re, multiprocessing, signal, os, pickle, gc, \
       time, timeit, hashlib, collections, base64, struct, atexit, zlib, math, json, numbers, datetime, binascii

# Import modules bundled with BTCRecover
import btcrecover.opencl_helpers
import lib.cardano.cardano_utils as cardano
from lib.eth_hash.auto import keccak

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

# Import modules from requirements.txt
from Crypto.Cipher import AES

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

# Modules dependant on bitcoinutils
bitcoinutils_available = False
try:
    import lib.block_io
    bitcoinutils_available = True
except:
    pass


searchfailedtext = "\nAll possible passwords (as specified in your tokenlist or passwordlist) have been checked and none are correct for this wallet. You could consider trying again with a different password list or expanded tokenlist..."

def load_customTokenWildcard(customTokenWildcardFile):
    customTokenWildcards = ['']
    if customTokenWildcardFile:
        try:
            customTokenWildcards_File = open(customTokenWildcardFile, "r")
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
        tstr("h") : tstr(string.hexdigits),
        tstr("*") : tstr("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"),
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

# Clears the current set of registered wallets (including those registered by default below)
def clear_registered_wallets():
    global wallet_types, wallet_types_by_id
    wallet_types       = []
    wallet_types_by_id = {}


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
        return WalletMetamask.load_from_filename(wallet_filename)
    except IsADirectoryError:
        return WalletMetamask.load_from_filename(wallet_filename)

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
    global pyopencl, numpy, cl_devices_avail
    if cl_devices_avail is None:
        try:
            import pyopencl, numpy
            cl_devices_avail = filter(lambda d: d.available==1 and d.profile=="FULL_PROFILE" and d.endian_little==1,
                itertools.chain(*[p.get_devices() for p in pyopencl.get_platforms()]))
        except ImportError as e:
            print("Warning:", e, file=sys.stderr)
            cl_devices_avail = []
        except pyopencl.LogicError as e:
            if "platform not found" not in str(e): raise  # unexpected error
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

############### Bitcoin Core ###############

@register_wallet_class
class WalletBitcoinCore(object):
    opencl_algo = -1
    opencl_context_hash_iterations_sha512 = -1

    def data_extract_id():
        return "bc"

    @staticmethod
    def passwords_per_seconds(seconds):
        return max(int(round(10 * seconds)), 1)

    @staticmethod
    def is_wallet_file(wallet_file):
        # Check if it's a legacy (Berkeley DB)
        wallet_file.seek(12)
        if wallet_file.read(8) == b"\x62\x31\x05\x00\x09\x00\x00\x00":  # BDB magic, Btree v9
            return True

        wallet_file.seek(0)
        # returns "maybe yes" or "definitely no" (Bither and Msigna wallets are also SQLite 3)
        return None if wallet_file.read(16) == b"SQLite format 3\0" else False

    def __init__(self, loading = False):
        assert loading, 'use load_from_* to create a ' + self.__class__.__name__
        load_aes256_library()

    def __setstate__(self, state):
        # (re-)load the required libraries after being unpickled
        load_aes256_library(warnings=False)
        self.__dict__ = state

    # Load a Bitcoin Core BDB wallet file given the filename and extract part of the first encrypted master key
    @classmethod
    def load_from_filename(cls, wallet_filename, force_purepython = False):
        mkey = None

        try:
            if not force_purepython:
                try:
                    import bsddb3.db
                except ImportError:
                    force_purepython = True

            if not force_purepython:
                db_env = bsddb3.db.DBEnv()
                wallet_filename = os.path.abspath(wallet_filename)
                try:
                    db_env.open(os.path.dirname(wallet_filename), bsddb3.db.DB_CREATE | bsddb3.db.DB_INIT_MPOOL)
                    db = bsddb3.db.DB(db_env)
                    db.open(wallet_filename, "main", bsddb3.db.DB_BTREE, bsddb3.db.DB_RDONLY)
                except UnicodeEncodeError:
                    error_exit("the entire path and filename of Bitcoin Core wallets must be entirely ASCII")

                mkey = db.get(b"\x04mkey\x01\x00\x00\x00")
                db.close()
                db_env.close()

            else:
                def align_32bits(i):  # if not already at one, return the next 32-bit boundry
                    m = i % 4
                    return i if m == 0 else i + 4 - m

                with open(wallet_filename, "rb") as wallet_file:
                    wallet_file.seek(12)
                    assert wallet_file.read(8) == b"\x62\x31\x05\x00\x09\x00\x00\x00", "is a Btree v9 file"

                    # Don't actually try walking the btree, just look through every btree leaf page
                    # for the value/key pair (yes they are in that order...) we're searching for
                    wallet_file.seek(20)
                    page_size        = struct.unpack(b"<I", wallet_file.read(4))[0]
                    wallet_file_size = os.path.getsize(wallet_filename)
                    for page_base in range(page_size, wallet_file_size, page_size):  # skip the header page
                        wallet_file.seek(page_base + 20)
                        (item_count, first_item_pos, btree_level, page_type) = struct.unpack(b"< H H B B", wallet_file.read(6))
                        if page_type != 5 or btree_level != 1:
                            continue  # skip non-btree and non-leaf pages
                        pos = align_32bits(page_base + first_item_pos)  # position of the first item
                        wallet_file.seek(pos)
                        for i in range(item_count):    # for each item in the current page
                            (item_len, item_type) = struct.unpack(b"< H B", wallet_file.read(3))
                            if item_type & ~0x80 == 1:  # if it's a variable-length key or value
                                if item_type == 1:      # if it's not marked as deleted
                                    if i % 2 == 0:      # if it's a value, save it's position
                                        value_pos = pos + 3
                                        value_len = item_len
                                    # else it's a key, check if it's the key we're looking for
                                    elif item_len == 9 and wallet_file.read(item_len) == b"\x04mkey\x01\x00\x00\x00":
                                        wallet_file.seek(value_pos)
                                        mkey = wallet_file.read(value_len)  # found it!
                                        break
                                pos = align_32bits(pos + 3 + item_len)  # calc the position of the next item
                            else:
                                pos += 12  # the two other item types have a fixed length
                            if i + 1 < item_count:  # don't need to seek if this is the last item in the page
                                assert pos < page_base + page_size, "next item is located in current page"
                                wallet_file.seek(pos)
                        else: continue  # if not found on this page, continue to next page
                        break           # if we broke out of inner loop, break out of this one too

        except Exception:
            pass


        # If we still haven't got a valid mkey, try it as SQLite
        if not mkey:
            #It may be a more modern wallet file
            import sqlite3
            wallet_conn = sqlite3.connect(wallet_filename)
            try:
                for key, value in wallet_conn.execute('SELECT * FROM main'):
                    if b"\x04mkey\x01\x00\x00\x00" in key:
                        mkey = value
            except sqlite3.OperationalError as e:
                if str(e).startswith("no such table"):
                    raise ValueError("Not an Bitcoin Core wallet: " + str(e))  # it might be a Bither or Msigna Core wallet
                else:
                    raise  # unexpected error
            wallet_conn.close()

        if not mkey:
            if force_purepython:
                print("Warning: bsddb (Berkeley DB) module not found; try installing it to resolve key-not-found errors (see INSTALL.md)", file=sys.stderr)
            raise ValueError("Encrypted master key #1 not found in the Bitcoin Core wallet file.\n"+
                             "(is this wallet encrypted? is this a standard Bitcoin Core wallet?)")
        # This is a little fragile because it assumes the encrypted key and salt sizes are
        # 48 and 8 bytes long respectively, which although currently true may not always be
        # (it will loudly fail if this isn't the case; if smarter it could gracefully succeed):
        self = cls(loading=True)
        encrypted_master_key, self._salt, method, self._iter_count = struct.unpack_from(b"< 49p 9p I I", mkey)
        if method != 0: raise NotImplementedError("Unsupported Bitcoin Core key derivation method " + str(method))

        # only need the final 2 encrypted blocks (half of it padding) plus the salt and iter_count saved above
        self._part_encrypted_master_key = encrypted_master_key[-32:]
        return self

    # Import a Bitcoin Core encrypted master key that was extracted by extract-mkey.py
    @classmethod
    def load_from_data_extract(cls, mkey_data):
        # These are the same partial encrypted_master_key, salt, iter_count retrieved by load_from_filename()
        self = cls(loading=True)
        self._part_encrypted_master_key, self._salt, self._iter_count = struct.unpack(b"< 32s 8s I", mkey_data)
        return self

    def difficulty_info(self):
        return "{:,} SHA-512 iterations".format(self._iter_count)

    # Defer to either the cpu or OpenCL implementation
    def return_verified_password_or_false(self, passwords): # Bitcoin Core
        if hasattr(self, "_cl_devices"):
            return self._return_verified_password_or_false_gpu(passwords)
        elif not isinstance(self.opencl_algo,int):
            return self._return_verified_password_or_false_opencl(passwords)
        else:
            return self._return_verified_password_or_false_cpu(passwords)

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def _return_verified_password_or_false_cpu(self, passwords): # Bitcoin Core
        # Copy a global into local for a small speed boost
        l_sha512 = hashlib.sha512

        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        passwords = map(lambda p: p.encode("utf_8", "ignore"), passwords)

        for count, password in enumerate(passwords, 1):
            derived_key = password + self._salt
            for i in range(self._iter_count):
                derived_key = l_sha512(derived_key).digest()
            part_master_key = aes256_cbc_decrypt(derived_key[:32], self._part_encrypted_master_key[:16], self._part_encrypted_master_key[16:])
            #
            # If the last block (bytes 16-31) of part_encrypted_master_key is all padding, we've found it
            if part_master_key == b"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10":
                return password.decode("utf_8", "replace"), count

        return False, count

    def _return_verified_password_or_false_opencl(self, arg_passwords): # Bitcoin Core
        # Copy a global into local for a small speed boost
        l_sha512 = hashlib.sha512

        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        passwords = map(lambda p: p.encode("utf_8", "ignore"), arg_passwords)

        hashed_keys = []
        for password in passwords:
            derived_key = password + self._salt
            hashed_keys.append(l_sha512(derived_key).digest())

        clResult = self.opencl_algo.cl_hash_iterations(self.opencl_context_hash_iterations_sha512, hashed_keys, self._iter_count-1, 8)

        #This list is consumed, so recreated it and zip
        passwords = map(lambda p: p.encode("utf_8", "ignore"), arg_passwords)

        results = zip(passwords, clResult)

        for count, (password,derived_key) in enumerate(results, 1):
            part_master_key = aes256_cbc_decrypt(derived_key[:32], self._part_encrypted_master_key[:16], self._part_encrypted_master_key[16:])
            #
            # If the last block (bytes 16-31) of part_encrypted_master_key is all padding, we've found it
            if part_master_key == b"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10":
                return password.decode("utf_8", "replace"), count

        return False, count

    # Load and initialize the OpenCL kernel for Bitcoin Core, given:
    #   devices - a list of one or more of the devices returned by get_opencl_devices()
    #   global_ws - a list of global work sizes, exactly one per device
    #   local_ws  - a list of local work sizes (or Nones), exactly one per device
    #   int_rate  - number of times to interrupt calculations to prevent hanging
    #               the GPU driver per call to return_verified_password_or_false()
    def init_opencl_kernel(self, devices, global_ws, local_ws, int_rate):
        # Need to save these for return_verified_password_or_false_opencl()
        assert devices, "WalletBitcoinCore.init_opencl_kernel: at least one device is selected"
        assert len(devices) == len(global_ws) == len(local_ws), "WalletBitcoinCore.init_opencl_kernel: one global_ws and one local_ws specified for each device"
        self._cl_devices   = devices
        self._cl_global_ws = global_ws
        self._cl_local_ws  = local_ws

        self._cl_kernel = self._cl_queues = self._cl_hashes_buffers = None  # clear any previously loaded
        cl_context = pyopencl.Context(devices)
        #
        # Load and compile the OpenCL program
        kernel_file = open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "opencl","sha512-bc-kernel.cl"), encoding="ascii", errors="ignore")
        cl_program = pyopencl.Program(cl_context, kernel_file.read()).build("-w")
        kernel_file.close()

        #
        # Configure and store for later the OpenCL kernel (the entrance function)
        self._cl_kernel = cl_program.kernel_sha512_bc
        self._cl_kernel.set_scalar_arg_dtypes([None, numpy.uint32])
        #
        # Check the local_ws sizes
        for i, device in enumerate(devices):
            if local_ws[i] is None: continue
            max_local_ws = self._cl_kernel.get_work_group_info(pyopencl.kernel_work_group_info.WORK_GROUP_SIZE, device)
            if local_ws[i] > max_local_ws:
                error_exit("--local-ws of", local_ws[i], "exceeds max of", max_local_ws, "for GPU '"+device.name.strip()+"' with Bitcoin Core wallets")

        # Create one command queue and one I/O buffer per device
        self._cl_queues         = []
        self._cl_hashes_buffers = []
        for i, device in enumerate(devices):
            self._cl_queues.append(pyopencl.CommandQueue(cl_context, device))
            # Each buffer is of len --global-ws * (size-of-sha512-hash-in-bytes == 512 bits / 8 == 64)
            self._cl_hashes_buffers.append(pyopencl.Buffer(cl_context, pyopencl.mem_flags.READ_WRITE, global_ws[i] * 64))

        # Doing all iter_count iterations at once will hang the GPU, so instead calculate how
        # many iterations should be done at a time based on iter_count and the requested int_rate,
        # rounding up to maximize the number of iterations done in the last set to optimize performance
        assert hasattr(self, "_iter_count") and self._iter_count, "WalletBitcoinCore.init_opencl_kernel: bitcoin core wallet or mkey has been loaded"
        self._iter_count_chunksize = self._iter_count // int_rate or 1
        if self._iter_count_chunksize % int_rate != 0:  # if not evenly divisible,
            self._iter_count_chunksize += 1             # then round up

    def _return_verified_password_or_false_gpu(self, arg_passwords): # Bitcoin Core (Legacy GPU)
        assert len(arg_passwords) <= sum(self._cl_global_ws), "WalletBitcoinCore.return_verified_password_or_false_opencl: at most --global-ws passwords"

        # Convert Unicode strings to UTF-8 bytestrings
        passwords = map(lambda p: p.encode("utf_8", "ignore"), arg_passwords)

        # The first iter_count iteration is done by the CPU
        hashes = numpy.empty([sum(self._cl_global_ws), 64], numpy.uint8)
        for i, password in enumerate(passwords):
            hashes[i] = numpy.frombuffer(hashlib.sha512(password + self._salt).digest(), numpy.uint8)

        # Divide up and copy the starting hashes into the OpenCL buffer(s) (one per device) in parallel
        done   = []  # a list of OpenCL event objects
        offset = 0
        for devnum, ws in enumerate(self._cl_global_ws):
            done.append(pyopencl.enqueue_copy(self._cl_queues[devnum], self._cl_hashes_buffers[devnum],
                                              hashes[offset : offset + ws], is_blocking=False))
            self._cl_queues[devnum].flush()  # Starts the copy operation
            offset += ws
        pyopencl.wait_for_events(done)

        # Doing all iter_count iterations at once will hang the GPU, so instead do iter_count_chunksize
        # iterations at a time, pausing briefly while waiting for them to complete, and then continuing.
        # Because iter_count is probably not evenly divisible by iter_count_chunksize, the loop below
        # performs all but the last of these iter_count_chunksize sets of iterations.

        i = 1 - self._iter_count_chunksize  # used if the loop below doesn't run (when --int-rate == 1)
        for i in range(1, self._iter_count - self._iter_count_chunksize, self._iter_count_chunksize):
            done = []  # a list of OpenCL event objects
            # Start up a kernel for each device to do one set of iter_count_chunksize iterations
            for devnum in range(len(self._cl_devices)):
                done.append(self._cl_kernel(self._cl_queues[devnum], (self._cl_global_ws[devnum],),
                                            None if self._cl_local_ws[devnum] is None else (self._cl_local_ws[devnum],),
                                            self._cl_hashes_buffers[devnum], self._iter_count_chunksize))
                self._cl_queues[devnum].flush()  # Starts the kernel
            pyopencl.wait_for_events(done)

        # Perform the last remaining set of iterations (usually fewer then iter_count_chunksize)
        done = []  # a list of OpenCL event objects
        for devnum in range(len(self._cl_devices)):
            done.append(self._cl_kernel(self._cl_queues[devnum], (self._cl_global_ws[devnum],),
                                        None if self._cl_local_ws[devnum] is None else (self._cl_local_ws[devnum],),
                                        self._cl_hashes_buffers[devnum], self._iter_count - self._iter_count_chunksize - i))
            self._cl_queues[devnum].flush()  # Starts the kernel
        pyopencl.wait_for_events(done)

        # Copy the resulting fully computed hashes back to RAM in parallel
        done   = []  # a list of OpenCL event objects
        offset = 0
        for devnum, ws in enumerate(self._cl_global_ws):
            done.append(pyopencl.enqueue_copy(self._cl_queues[devnum], hashes[offset : offset + ws],
                                              self._cl_hashes_buffers[devnum], is_blocking=False))
            offset += ws
            self._cl_queues[devnum].flush()  # Starts the copy operation
        pyopencl.wait_for_events(done)

        # Convert Unicode strings to UTF-8 bytestrings
        passwords = map(lambda p: p.encode("utf_8", "ignore"), arg_passwords)

        # Using the computed hashes, try to decrypt the master key (in CPU)
        for i, password in enumerate(passwords):
            derived_key = hashes[i].tobytes()
            part_master_key = aes256_cbc_decrypt(derived_key[:32], self._part_encrypted_master_key[:16], self._part_encrypted_master_key[16:])
            # If the last block (bytes 16-31) of part_encrypted_master_key is all padding, we've found it
            if part_master_key == b"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10":
                return password.decode("utf_8", "replace"), i + 1
        return False, i + 1


@register_wallet_class
class WalletPywallet(WalletBitcoinCore):

    def data_extract_id():
        return False  # there is none

    @staticmethod
    def is_wallet_file(wallet_file): return None   # there's no easy way to check this

    # Load a Bitcoin Core encrypted master key from a file created by pywallet.py --dumpwallet
    @classmethod
    def load_from_filename(cls, wallet_filename):
        # pywallet dump files are largish json files often preceded by a bunch of error messages;
        # search through the file in 16k blocks looking for a particular string which occurs twice
        # inside the mkey object we need (because it appears twice, we're guaranteed one copy
        # will appear whole in at least one block even if the other is split across blocks).
        #
        # For the first block, give up if this doesn't look like a text file
        with open(wallet_filename) as wallet_file:
            last_block = ""
            cur_block  = wallet_file.read(16384)
            if sum(1 for c in cur_block if ord(c)>126 or ord(c)==0) > 512: # about 3%
                raise ValueError("Unrecognized pywallet format (does not look like ASCII text)")
            while cur_block:
                found_at = cur_block.find('"nDerivation')
                if found_at >= 0: break
                last_block = cur_block
                cur_block  = wallet_file.read(16384)
            else:
                raise ValueError("Unrecognized pywallet format (can't find mkey)")

            cur_block = last_block + cur_block + wallet_file.read(4096)
        found_at = cur_block.rfind("{", 0, found_at + len(last_block))
        if found_at < 0:
            raise ValueError("Unrecognized pywallet format (can't find mkey opening brace)")
        wallet = json.JSONDecoder().raw_decode(cur_block[found_at:])[0]

        if not all(name in wallet for name in ("nDerivationIterations", "nDerivationMethod", "nID", "salt")):
            raise ValueError("Unrecognized pywallet format (can't find all mkey attributes)")

        if wallet["nID"] != 1:
            raise NotImplementedError("Unsupported Bitcoin Core wallet ID " + wallet["nID"])
        if wallet["nDerivationMethod"] != 0:
            raise NotImplementedError("Unsupported Bitcoin Core key derivation method " + wallet["nDerivationMethod"])

        if "encrypted_key" in wallet:
            encrypted_master_key = wallet["encrypted_key"]
        elif "crypted_key" in wallet:
            encrypted_master_key = wallet["crypted_key"]
        else:
            raise ValueError("Unrecognized pywallet format (can't find [en]crypted_key attribute)")

        # These are the same as retrieved and saved by load_bitcoincore_wallet()
        self = cls(loading=True)
        encrypted_master_key = base64.b16decode(encrypted_master_key, casefold=True)
        self._salt           = base64.b16decode(wallet["salt"], True)
        self._iter_count     = int(wallet["nDerivationIterations"])

        if len(encrypted_master_key) != 48: raise NotImplementedError("Unsupported encrypted master key length")
        if len(self._salt)           != 8:  raise NotImplementedError("Unsupported salt length")
        if self._iter_count          <= 0:  raise NotImplementedError("Unsupported iteration count")

        # only need the final 2 encrypted blocks (half of it padding) plus the salt and iter_count saved above
        self._part_encrypted_master_key = encrypted_master_key[-32:]
        return self


############### MultiBit ###############
# - MultiBit .key backup files
# - MultiDoge .key backup files
# - Bitcoin Wallet for Android/BlackBerry v3.47+ wallet backup files
# - Bitcoin Wallet for Android/BlackBerry v2.24 and older key backup files
# - Bitcoin Wallet for Android/BlackBerry v2.3 - v3.46 key backup files
# - KnC for Android key backup files (same as the above)

@register_wallet_class
class WalletMultiBit(object):
    opencl_algo = -1
    _dump_privkeys_file = None

    def data_extract_id():
        return "mb"

    # MultiBit private key backup file (not the wallet file)
    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(0)
        try:
            base64EncodedData = wallet_file.read(20).lstrip()[:12]
            data = base64.b64decode(base64EncodedData)
        except binascii.Error: return False
        return data.startswith(b"Salted__")

    def __init__(self, loading = False):
        assert loading, 'use load_from_* to create a ' + self.__class__.__name__
        aes_library_name = load_aes256_library().__name__
        self._passwords_per_second = 100000 if aes_library_name == "Crypto" else 5000

    def __setstate__(self, state):
        # (re-)load the required libraries after being unpickled
        load_aes256_library(warnings=False)
        self.__dict__ = state

    # This just dumps the wallet private keys for Android Wallets
    def dump_privkeys(self, wallet_data):
        with open(self._dump_privkeys_file, 'a') as logfile:
            from . import bitcoinj_pb2
            global pylibscrypt
            import lib.pylibscrypt as pylibscrypt
            pad_len = wallet_data[-1]
            if isinstance(pad_len, str):
                pad_len = ord(pad_len)

            # Attempt to dump the menemonic from the wallet (standard BitcoinJ file)
            pbdata = wallet_data[:-pad_len]
            pb_wallet = bitcoinj_pb2.Wallet()
            pb_wallet.ParseFromString(pbdata)
            mnemonic = WalletBitcoinj.extract_mnemonic(pb_wallet)
            logfile.write("Android Wallet Mnemonic: '" + mnemonic.decode() + "' derivation path: m/0'")

    # This just dumps the wallet private keys for Multibit Classic, Multidoge Wallets
    def dump_privkeys_keybackup(self, key1, key2, iv):
        with open(self._dump_privkeys_file, 'a') as logfile:
            decrypted_wallet = aes256_cbc_decrypt(key1 + key2, iv, self._encrypted_wallet).decode().splitlines()
            for line in decrypted_wallet:
                try:
                    key, date = line.split(" ")
                    logfile.write(key + "\n")
                except:
                    pass

    def passwords_per_seconds(self, seconds):
        return max(int(round(self._passwords_per_second * seconds)), 1)

    # Load a Multibit private key backup file (the part of it we need)
    @classmethod
    def load_from_filename(cls, privkey_filename):
        with open(privkey_filename) as privkey_file:
            # Multibit privkey files contain base64 text split into multiple lines;
            # we need the first 48 bytes after decoding, which translates to 64 before.
            data = "".join(privkey_file.read().split())  # join multiple lines into one

        if len(data) < 64: raise EOFError("Expected at least 64 bytes of text in the MultiBit private key file")
        data = base64.b64decode(data)
        assert data.startswith(b"Salted__"), "WalletBitcoinCore.load_from_filename: file starts with base64 'Salted__'"
        if len(data) < 48:  raise EOFError("Expected at least 48 bytes of decoded data in the MultiBit private key file")
        self = cls(loading=True)
        self._encrypted_block = data[16:48]  # the first two 16-byte AES blocks
        self._encrypted_wallet = data[16:]
        self._salt            = data[8:16]
        return self

    # Import a MultiBit private key that was extracted by extract-multibit-privkey.py
    @classmethod
    def load_from_data_extract(cls, privkey_data):
        assert len(privkey_data) == 24
        print("WARNING: read the Usage for MultiBit Classic section of Extract_Scripts.md before proceeding", file=sys.stderr)
        self = cls(loading=True)
        self._encrypted_block = privkey_data[8:]  # a single 16-byte AES block
        self._salt            = privkey_data[:8]
        return self

    def difficulty_info(self):
        return "3 MD5 iterations"

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    assert b"1" < b"9" < b"A" < b"Z" < b"a" < b"z"  # the b58 check below assumes ASCII ordering in the interest of speed
    def return_verified_password_or_false(self, orig_passwords): # Multibit
        # Copy a few globals into local for a small speed boost
        l_md5                 = hashlib.md5
        l_aes256_cbc_decrypt  = aes256_cbc_decrypt
        encrypted_block       = self._encrypted_block
        salt                  = self._salt

        # Convert Unicode strings (lazily) to UTF-16 bytestrings, truncating each code unit to 8 bits
        passwords = map(lambda p: p.encode("utf_16_le", "ignore")[::2], orig_passwords)

        for count, password in enumerate(passwords, 1):
            salted = password + salt
            key1   = l_md5(salted).digest()
            key2   = l_md5(key1 + salted).digest()
            iv     = l_md5(key2 + salted).digest()
            b58_privkey = l_aes256_cbc_decrypt(key1 + key2, iv, encrypted_block[:16])

            # (all this may be fragile, e.g. what if comments or whitespace precede what's expected in future versions?)
            if type(b58_privkey) == str:
                b58_privkey = b58_privkey.encode()
            if chr(b58_privkey[0]) in "LK5Q\x0a#":
                #
                # Does it look like a base58 private key (MultiBit, MultiDoge, or oldest-format Android key backup)?
                if b58_privkey[0] in "LK5Q".encode():  # private keys always start with L, K, or 5, or for MultiDoge Q
                    for c in b58_privkey[1:]:
                        # If it's outside of the base58 set [1-9A-HJ-NP-Za-km-z], break
                        if c > ord("z") or c < ord("1") or ord("9") < c < ord("A") or ord("Z") < c < ord("a") or chr(c) in "IOl":
                            break
                    # If the loop above doesn't break, it's base58-looking so far
                    else:
                        # If another AES block is available, decrypt and check it as well to avoid false positives
                        if len(encrypted_block) >= 32:
                            b58_privkey = l_aes256_cbc_decrypt(key1 + key2, encrypted_block[:16], encrypted_block[16:32])
                            for c in b58_privkey:
                                if c > ord("z") or c < ord("1") or ord("9") < c < ord("A") or ord("Z") < c < ord("a") or chr(c) in "IOl":
                                    break  # not base58
                            # If the loop above doesn't break, it's base58; we've found it
                            else:
                                if self._dump_privkeys_file:
                                    self.dump_privkeys_keybackup(key1, key2, iv)
                                return orig_passwords[count-1], count
                        else:
                            # (when no second block is available, there's a 1 in 300 billion false positive rate here)
                            if self._dump_privkeys_file:
                                self.dump_privkeys_keybackup(key1, key2, iv)
                            return orig_passwords[count - 1], count
                #
                # Does it look like a bitcoinj protobuf (newest Bitcoin for Android backup)
                elif b58_privkey[2:6] == b"org." and b58_privkey[0] == 10 and b58_privkey[1] < 128:
                    for c in b58_privkey[6:14]:
                        # If it doesn't look like a lower alpha domain name of len >= 8 (e.g. 'bitcoin.'), break
                        if c > ord("z") or (c < ord("a") and c != ord(".")):
                            break
                    # If the loop above doesn't break, it looks like a domain name; we've found it
                    else:
                        print("Notice: Found Bitcoin for Android Wallet Password")
                        if self._dump_privkeys_file:
                            #try:
                            if True:
                                wallet_data = l_aes256_cbc_decrypt(key1 + key2, iv, self._encrypted_wallet)
                                self.dump_privkeys(wallet_data)
                            #except:
                            #    print("Unable to decode wallet mnemonic (common for very old wallets)")

                        return orig_passwords[count - 1], count
                #
                #  Does it look like a KnC for Android key backup?
                elif b58_privkey == b"# KEEP YOUR PRIV":
                    if isinstance(orig_passwords[count-1],str):
                        return orig_passwords[count-1], count
                    if isinstance(orig_passwords[count - 1], bytes):
                        return orig_passwords[count-1].decode(), count

        return False, count

############### bitcoinj ###############

# A namedtuple with the same attributes as the protobuf message object from bitcoinj_pb2
# (it's a global so that it's pickleable)
EncryptionParams = collections.namedtuple("EncryptionParams", "salt n r p")

@register_wallet_class
class WalletBitcoinj(object):
    opencl_algo = -1
    _dump_privkeys_file = None

    def data_extract_id():
        return "bj"

    def passwords_per_seconds(self, seconds):
        passwords_per_second = self._passwords_per_second
        if hasattr(self, "_scrypt_n"):
            passwords_per_second /= self._scrypt_n / 16384  # scaled by default N
            passwords_per_second /= self._scrypt_r / 8      # scaled by default r
            passwords_per_second /= self._scrypt_p / 1      # scaled by default p
        return max(int(round(passwords_per_second * seconds)), 1)

    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(0)
        if wallet_file.read(1) == b"\x0a":  # protobuf field number 1 of type length-delimited
            network_identifier_len = ord(wallet_file.read(1))
            if 1 <= network_identifier_len < 128:
                wallet_file.seek(2 + network_identifier_len)
                c = wallet_file.read(1)
                if c and c in b"\x12\x1a":   # field number 2 or 3 of type length-delimited
                    return True
        return False

    # From https://github.com/gurnec/decrypt_bitcoinj_seed
    @staticmethod
    def extract_mnemonic(pb_wallet, password = None):
        from . import bitcoinj_pb2
        """extract and if necessary decrypt (w/scrypt) a BIP39 mnemonic from a bitcoinj wallet protobuf

        :param pb_wallet: a Wallet protobuf message
        :type pb_wallet: wallet_pb2.Wallet
        :param get_password_fn: a callback returning a password that's called iff one is required
        :type get_password_fn: function
        :return: the first BIP39 mnemonic found in the wallet or None if no password was entered when required
        :rtype: str
        """
        for key in pb_wallet.key:
            if key.type == bitcoinj_pb2.Key.DETERMINISTIC_MNEMONIC:

                if key.HasField('secret_bytes'):  # if not encrypted
                    return key.secret_bytes

                elif key.HasField('encrypted_data'):  # if encrypted (w/scrypt)
                    # Derive the encryption key
                    aes_key = pylibscrypt.scrypt(
                        password,
                        pb_wallet.encryption_parameters.salt,
                        pb_wallet.encryption_parameters.n,
                        pb_wallet.encryption_parameters.r,
                        pb_wallet.encryption_parameters.p,
                        32)

                    # Decrypt the mnemonic
                    ciphertext = key.encrypted_data.encrypted_private_key
                    iv = key.encrypted_data.initialisation_vector
                    return aes256_cbc_decrypt(aes_key, iv, ciphertext).decode().replace("\\t", "")

        else:  # if the loop exists normally, no mnemonic was found
            raise ValueError('no BIP39 mnemonic found')

    def __init__(self, loading = False):
        assert loading, 'use load_from_* to create a ' + self.__class__.__name__
        global pylibscrypt
        import lib.pylibscrypt as pylibscrypt
        # This is the base estimate for the scrypt N,r,p defaults of 16384,8,1
        if not pylibscrypt._done:
            print("Warning: can't find an scrypt library, performance will be severely degraded", file=sys.stderr)
            self._passwords_per_second = 0.03
        else:
            self._passwords_per_second = 14
        load_aes256_library()

    def __setstate__(self, state):
        # (re-)load the required libraries after being unpickled
        global pylibscrypt
        import lib.pylibscrypt as pylibscrypt
        load_aes256_library(warnings=False)
        self.__dict__ = state

    # Load a bitcoinj wallet file (the part of it we need)
    @classmethod
    def load_from_filename(cls, wallet_filename):
        with open(wallet_filename, "rb") as wallet_file:
            filedata = wallet_file.read(MAX_WALLET_FILE_SIZE)  # up to 64M, typical size is a few k
        return cls._load_from_filedata(filedata)

    @classmethod
    def _load_from_filedata(cls, filedata):
        try:
            from . import bitcoinj_pb2
        except ModuleNotFoundError:
            print("Warning: Cannot load protobuf module, unable to check if this is a Coinomi wallet"
                  "... Be sure to install all requirements with the command 'pip3 install -r requirements.txt', see https://btcrecover.readthedocs.io/en/latest/INSTALL/")

        pb_wallet = bitcoinj_pb2.Wallet()
        pb_wallet.ParseFromString(filedata)

        if pb_wallet.encryption_type == bitcoinj_pb2.Wallet.UNENCRYPTED:
            print("\nWallet Not Encrypted, Contains the following Private Keys")
            for key in pb_wallet.key:
                from lib.cashaddress import base58
                privkey_wif = base58.b58encode_check(bytes([0x80]) + key.secret_bytes + bytes([0x1]))
                print(privkey_wif)
                print()
            raise ValueError("bitcoinj wallet is not encrypted")
        if pb_wallet.encryption_type != bitcoinj_pb2.Wallet.ENCRYPTED_SCRYPT_AES:
            raise NotImplementedError("Unsupported bitcoinj encryption type "+str(pb_wallet.encryption_type))
        if not pb_wallet.HasField("encryption_parameters"):
            raise ValueError("bitcoinj wallet is missing its scrypt encryption parameters")

        for key in pb_wallet.key:
            if  key.type in (bitcoinj_pb2.Key.ENCRYPTED_SCRYPT_AES, bitcoinj_pb2.Key.DETERMINISTIC_KEY) and key.HasField("encrypted_data"):
                encrypted_len = len(key.encrypted_data.encrypted_private_key)
                if encrypted_len == 48:
                    # only need the final 2 encrypted blocks (half of it padding) plus the scrypt parameters
                    self = cls(loading=True)
                    self._part_encrypted_key = key.encrypted_data.encrypted_private_key[-32:]
                    self._scrypt_salt = pb_wallet.encryption_parameters.salt
                    self._scrypt_n    = pb_wallet.encryption_parameters.n
                    self._scrypt_r    = pb_wallet.encryption_parameters.r
                    self._scrypt_p    = pb_wallet.encryption_parameters.p
                    self.pb_wallet_filedata = filedata
                    return self
                print("Warning: ignoring encrypted key of unexpected length ("+str(encrypted_len)+")", file=sys.stderr)

        raise ValueError("No encrypted keys found in bitcoinj wallet")

    # Import a bitcoinj private key that was extracted by extract-bitcoinj-privkey.py
    @classmethod
    def load_from_data_extract(cls, privkey_data):
        self = cls(loading=True)
        # The final 2 encrypted blocks
        self._part_encrypted_key = privkey_data[:32]
        # The scrypt parameters
        self._scrypt_salt = privkey_data[32:40]
        (self._scrypt_n, self._scrypt_r, self._scrypt_p) = struct.unpack(b"< I H H", privkey_data[40:])
        return self

    def difficulty_info(self):
        return "scrypt N, r, p = {}, {}, {}".format(self._scrypt_n, self._scrypt_r, self._scrypt_p)

    def dump_privkeys(self, derived_key):
        from . import bitcoinj_pb2
        pb_wallet = bitcoinj_pb2.Wallet()
        pb_wallet.ParseFromString(self.pb_wallet_filedata)
        
        from lib.cashaddress import base58
        with open(self._dump_privkeys_file, 'a') as logfile:
            for key in pb_wallet.key:
                privkey = aes256_cbc_decrypt(derived_key, key.encrypted_data.initialisation_vector,
                                               key.encrypted_data.encrypted_private_key)[:32]
                privkey_wif = base58.b58encode_check(bytes([0x80]) + privkey + bytes([0x1]))
                logfile.write(privkey_wif + "\n")

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def return_verified_password_or_false(self, passwords): # Bitcoinj
        # Copy a few globals into local for a small speed boost
        l_scrypt             = pylibscrypt.scrypt
        l_aes256_cbc_decrypt = aes256_cbc_decrypt
        part_encrypted_key   = self._part_encrypted_key
        scrypt_salt          = self._scrypt_salt
        scrypt_n             = self._scrypt_n
        scrypt_r             = self._scrypt_r
        scrypt_p             = self._scrypt_p


        # Convert strings (lazily) to UTF-16BE bytestrings
        passwords = map(lambda p: p.encode("utf_16_be", "ignore"), passwords)

        for count, password in enumerate(passwords, 1):
            derived_key = l_scrypt(password, scrypt_salt, scrypt_n, scrypt_r, scrypt_p, 32)
            part_key    = l_aes256_cbc_decrypt(derived_key, part_encrypted_key[:16], part_encrypted_key[16:])
            # If the last block (bytes 16-31) of part_encrypted_key is all padding, we've found it
            if part_key == b"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10":
                password = password.decode("utf_16_be", "replace")
                if self._dump_privkeys_file:
                    self.dump_privkeys(derived_key)

                return password, count

        return False, count



############### Coinomi ###############

# A namedtuple with the same attributes as the protobuf message object from coinomi_pb2
# (it's a global so that it's pickleable)
EncryptionParams = collections.namedtuple("EncryptionParams", "salt n r p")

@register_wallet_class
class WalletCoinomi(WalletBitcoinj):
    opencl_algo = -1
    _using_extract = False
    _dump_privkeys_file = None

    def data_extract_id():
        return "cn"

    # This just dumps the wallet private keys
    def dump_privkeys(self, derived_key):
        with open(self._dump_privkeys_file, 'a') as logfile:
            logfile.write("Private Keys (BIP39 seed and BIP32 Root Key) are below...\n")
            mnemonic = aes256_cbc_decrypt(derived_key, self._mnemonic_iv, self._mnemonic)
            mnemonic = mnemonic.decode()[:-1]
            if mnemonic[-2:-1] != b'\x0c':
                mnemonic = mnemonic.replace('\x0c', "") + " (BIP39 Passphrase In Use, if you don't have it use BIP32 root key to recover wallet)"

            logfile.write("BIP39 Mnemonic: " + mnemonic + "\n")
            master_key = aes256_cbc_decrypt(derived_key, self._masterkey_encrypted_iv, self._masterkey_encrypted)
            from lib.cashaddress import convert, base58
            xprv = base58.b58encode_check(
                b'\x04\x88\xad\xe4\x00\x00\x00\x00\x00\x00\x00\x00\x00' + self._masterkey_chaincode + b'\x00' + master_key[
                                                                                                                :-16])
            logfile.write("\nBIP32 Root Key: " + xprv)

    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(0)
        if wallet_file.read(1) == b'\x08':  # protobuf field number 1 of type length-delimited
            wallet_file.read(1)
            if wallet_file.read(1) == b'\x12':
                try:
                    from . import coinomi_pb2
                except ModuleNotFoundError:
                    exit(
                        "\nERROR: Cannot load protobuf module... Be sure to install all requirements with the command 'pip3 install -r requirements.txt', see https://btcrecover.readthedocs.io/en/latest/INSTALL/")

                try:
                    wallet_file.seek(0)
                    pb_wallet = coinomi_pb2.Wallet()
                    pb_wallet.ParseFromString(wallet_file.read())
                    pockets = pb_wallet.pockets  # Pockets is a fairly unique coinomi key... #This will certainly fail on non-coinomi protobuf wallets in Python 3.9+
                    return True
                except:
                    pass

        return False

    @classmethod
    def _load_from_filedata(cls, filedata):
        try:
            from . import coinomi_pb2
        except ModuleNotFoundError:
            exit(
                "\nERROR: Cannot load protobuf module... Be sure to install all requirements with the command 'pip3 install -r requirements.txt', see https://btcrecover.readthedocs.io/en/latest/INSTALL/")

        pb_wallet = coinomi_pb2.Wallet()
        pb_wallet.ParseFromString(filedata)
        if pb_wallet.encryption_type == coinomi_pb2.Wallet.UNENCRYPTED:
            raise ValueError("Coinomi wallet is not encrypted")
        if pb_wallet.encryption_type != coinomi_pb2.Wallet.ENCRYPTED_SCRYPT_AES:
            raise NotImplementedError("Unsupported Coinomi wallet encryption type "+str(pb_wallet.encryption_type))
        if not pb_wallet.HasField("encryption_parameters"):
            raise ValueError("Coinomi wallet is missing its scrypt encryption parameters")

        # only need the final 2 encrypted blocks (half of it padding) plus the scrypt parameters
        self = cls(loading=True)
        self._encrypted_masterkey_part = pb_wallet.master_key.encrypted_data.encrypted_private_key[-32:]
        self._scrypt_salt = pb_wallet.encryption_parameters.salt
        self._scrypt_n    = pb_wallet.encryption_parameters.n
        self._scrypt_r    = pb_wallet.encryption_parameters.r
        self._scrypt_p    = pb_wallet.encryption_parameters.p
        self._mnemonic = pb_wallet.seed.encrypted_data.encrypted_private_key
        self._mnemonic_iv = pb_wallet.seed.encrypted_data.initialisation_vector
        self._masterkey_encrypted = pb_wallet.master_key.encrypted_data.encrypted_private_key
        self._masterkey_encrypted_iv = pb_wallet.master_key.encrypted_data.initialisation_vector
        self._masterkey_chaincode = pb_wallet.master_key.deterministic_key.chain_code
        self._masterkey_pubkey = pb_wallet.master_key.public_key
        return self

    # Import a bitcoinj private key that was extracted by extract-bitcoinj-privkey.py
    @classmethod
    def load_from_data_extract(cls, privkey_data):
        self = cls(loading=True)
        # The final 2 encrypted blocks
        self._encrypted_masterkey_part = privkey_data[:32]
        # The scrypt parameters
        self._scrypt_salt = privkey_data[32:40]
        (self._scrypt_n, self._scrypt_r, self._scrypt_p) = struct.unpack(b"< I H H", privkey_data[40:])
        self._using_extract = True
        return self

    def difficulty_info(self):
        return "scrypt N, r, p = {}, {}, {}".format(self._scrypt_n, self._scrypt_r, self._scrypt_p)

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def return_verified_password_or_false(self, passwords): # Bitcoinj
        # Copy a few globals into local for a small speed boost
        l_scrypt             = pylibscrypt.scrypt
        l_aes256_cbc_decrypt = aes256_cbc_decrypt
        _encrypted_masterkey_part   = self._encrypted_masterkey_part
        scrypt_salt          = self._scrypt_salt
        scrypt_n             = self._scrypt_n
        scrypt_r             = self._scrypt_r
        scrypt_p             = self._scrypt_p

        # Convert strings (lazily) to UTF-16BE bytestrings
        passwords = map(lambda p: p.encode("utf_16_be", "ignore"), passwords)

        for count, password in enumerate(passwords, 1):
            derived_key = l_scrypt(password, scrypt_salt, scrypt_n, scrypt_r, scrypt_p, 32)
            part_key    = l_aes256_cbc_decrypt(derived_key, _encrypted_masterkey_part[:16], _encrypted_masterkey_part[16:])

            # If the last block (bytes 16-31) of part_encrypted_key is all padding, we've found it
            if part_key == b"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10":
                if not self._using_extract and self._dump_privkeys_file:
                    self.dump_privkeys(derived_key)

                password = password.decode("utf_16_be", "replace")
                return password, count

        return False, count


############### MultiBit HD ###############

@register_wallet_class
class WalletMultiBitHD(WalletBitcoinj):
    _dump_privkeys_file = None

    def data_extract_id():
        return "m5"
    # id "m2", which *only* supported MultiBit HD prior to v0.5.0 ("m5" supports
    # both before and after), is no longer supported as of btcrecover version 0.15.7

    # This just dumps the wallet private keys
    def dump_privkeys(self, derived_key, password):
        with open(self._dump_privkeys_file, 'a') as logfile:
            decrypted_data = aes256_cbc_decrypt(derived_key, self._iv, self._encrypted_data)
            padding_len = decrypted_data[-1]

            from . import bitcoinj_pb2
            pb_wallet = bitcoinj_pb2.Wallet()
            pb_wallet.ParseFromString(decrypted_data[:-padding_len])
            mnemonic = WalletBitcoinj.extract_mnemonic(pb_wallet, password)
            logfile.write("BIP39 Seed: " + mnemonic)

    @staticmethod
    def is_wallet_file(wallet_file): return None  # there's no easy way to check this

    # Load a MultiBit HD wallet file (the part of it we need)
    @classmethod
    def load_from_filename(cls, wallet_filename):
        # MultiBit HD wallet files look like completely random bytes, so we
        # require that its name remain unchanged in order to "detect" it
        if os.path.basename(wallet_filename) != "mbhd.wallet.aes":
            raise ValueError("MultiBit HD wallet files must be named mbhd.wallet.aes")

        with open(wallet_filename, "rb") as wallet_file:
            encrypted_data = wallet_file.read()
            if len(encrypted_data) < 32:
                raise ValueError("MultiBit HD wallet files must be at least 32 bytes long")

        # The likelihood of of finding a valid encrypted MultiBit HD wallet whose first 16,384
        # bytes have less than 7.8 bits of entropy per byte is... too small for me to figure out
        entropy_bits = est_entropy_bits(encrypted_data)
        if entropy_bits < 7.8:
            raise ValueError("Doesn't look random enough to be an encrypted MultiBit HD wallet (only {:.1f} bits of entropy per byte)".format(entropy_bits))

        self = cls(loading=True)
        self._iv                   = encrypted_data[:16]    # the AES initialization vector (v0.5.0+)
        self._encrypted_block_iv   = encrypted_data[16:32]  # the first 16-byte encrypted block (v0.5.0+)
        self._encrypted_block_noiv = encrypted_data[:16]    # the first 16-byte encrypted block w/hardcoded IV (< v0.5.0)
        self._encrypted_data = encrypted_data[16:]  # Encrypted Data
        self._encrypted_data_noiv = encrypted_data  # Encrypted Data w/hardcoded IV (< v0.5.0)
        return self

    # Import a MultiBit HD encrypted block that was extracted by extract-multibit-hd-data.py
    @classmethod
    def load_from_data_extract(cls, file_data):
        self = cls(loading=True)
        assert len(file_data) == 32
        self._iv                   = file_data[:16]  # the AES initialization vector (v0.5.0+)
        self._encrypted_block_iv   = file_data[16:]  # the first 16-byte encrypted block (v0.5.0+)
        self._encrypted_block_noiv = file_data[:16]  # the first 16-byte encrypted block w/hardcoded IV (< v0.5.0)
        return self

    def difficulty_info(self):
        return "scrypt N, r, p = 16384, 8, 1"

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def return_verified_password_or_false(self, passwords): # MultibitHD
        # Copy a few globals into local for a small speed boost
        l_scrypt             = pylibscrypt.scrypt
        l_aes256_cbc_decrypt = aes256_cbc_decrypt
        iv                   = self._iv
        encrypted_block_iv   = self._encrypted_block_iv
        encrypted_block_noiv = self._encrypted_block_noiv

        # Convert strings (lazily) to UTF-16BE bytestrings
        passwords = map(lambda p: p.encode("utf_16_be", "ignore"), passwords)

        for count, password in enumerate(passwords, 1):
            derived_key = l_scrypt(password, b'\x35\x51\x03\x80\x75\xa3\xb0\xc5', olen=32)  # w/a hardcoded salt
            block_iv    = l_aes256_cbc_decrypt(derived_key, iv, encrypted_block_iv)         # v0.5.0+
            block_noiv  = l_aes256_cbc_decrypt(                                             # < v0.5.0
                derived_key,
                b'\xa3\x44\x39\x1f\x53\x83\x11\xb3\x29\x54\x86\x16\xc4\x89\x72\x3e',        # the hardcoded iv
                encrypted_block_noiv)
            #
            # Does it look like a bitcoinj protobuf file?
            # (there's a 1 in 2 trillion chance this hits but the password is wrong)
            for block in (block_iv, block_noiv):
                if block[2:6] == b"org." and block[0] == 10 and block[1] < 128:
                    if self._dump_privkeys_file:
                        self.dump_privkeys(derived_key, password)

                    password = password.decode("utf_16_be", "replace")
                    return password, count

        return False, count


############### Android Spending PIN ###############

# don't @register_wallet_class -- it's never auto-detected and never used for a --data-extract
class WalletAndroidSpendingPIN(WalletBitcoinj):

    # Decrypt a Bitcoin Wallet for Android/BlackBerry backup into a standard bitcoinj wallet, and load it
    @classmethod
    def load_from_filename(cls, wallet_filename, password = None, force_purepython = False):
        with open(wallet_filename, "rb") as wallet_file:
            # If we're given an unencrypted backup, just return a WalletBitcoinj
            if WalletBitcoinj.is_wallet_file(wallet_file):
                wallet_file.close()
                return WalletBitcoinj.load_from_filename(wallet_filename)

            wallet_file.seek(0)
            data = wallet_file.read(MAX_WALLET_FILE_SIZE)  # up to 64M, typical size is a few k

        data = data.replace(b"\r", b"").replace(b"\n", b"")
        data = base64.b64decode(data)
        if not data.startswith(b"Salted__"):
            raise ValueError("Not a Bitcoin Wallet for Android/BlackBerry encrypted backup (missing 'Salted__')")
        if len(data) < 32:
            raise EOFError  ("Expected at least 32 bytes of decoded data in the encrypted backup file")
        if len(data) % 16 != 0:
            raise ValueError("Not a valid Bitcoin Wallet for Android/BlackBerry encrypted backup (size not divisible by 16)")
        salt = data[8:16]
        data = data[16:]

        if not password:
            password = prompt_unicode_password(
                "Please enter the password for the Bitcoin Wallet for Android/BlackBerry backup: ",
                "encrypted Bitcoin Wallet for Android/BlackBerry backups must be decrypted before searching for the PIN")
        # Convert Unicode string to a UTF-16 bytestring, truncating each code unit to 8 bits
        password = password.encode("utf_16_le", "ignore")[::2]

        # Decrypt the backup file (OpenSSL style)
        load_aes256_library(force_purepython)
        salted = password + salt
        key1   = hashlib.md5(salted).digest()
        key2   = hashlib.md5(key1 + salted).digest()
        iv     = hashlib.md5(key2 + salted).digest()
        data   = aes256_cbc_decrypt(key1 + key2, iv, data)
        #from cStringIO import StringIO
        if not WalletBitcoinj.is_wallet_file(io.BytesIO(data[:100])):
            error_exit("can't decrypt wallet (wrong password?)")
        # Validate and remove the PKCS7 padding
        padding_len = data[-1]
        if not (1 <= padding_len <= 16 and data.endswith((chr(padding_len) * padding_len).encode())):
            error_exit("can't decrypt wallet, invalid padding (wrong password?)")

        return cls._load_from_filedata(data[:-padding_len])  # WalletBitcoinj._load_from_filedata() parses the bitcoinj wallet


############### mSIGNA ###############

@register_wallet_class
class WalletMsigna(object):
    opencl_algo = -1

    def data_extract_id():
        return "ms"

    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(0)
        # returns "maybe yes" or "definitely no" (Bither wallets are also SQLite 3)
        return None if wallet_file.read(16) == b"SQLite format 3\0" else False

    def __init__(self, loading = False):
        assert loading, 'use load_from_* to create a ' + self.__class__.__name__
        aes_library_name = load_aes256_library().__name__
        self._passwords_per_second = 50000 if aes_library_name == "Crypto" else 5000

    def __setstate__(self, state):
        # (re-)load the required libraries after being unpickled
        load_aes256_library(warnings=False)
        self.__dict__ = state

    def passwords_per_seconds(self, seconds):
        return max(int(round(self._passwords_per_second * seconds)), 1)

    # Load an encrypted privkey and salt from the specified keychain given a filename of an mSIGNA vault
    @classmethod
    def load_from_filename(cls, wallet_filename):
        # Find the one keychain to test passwords against or exit trying
        import sqlite3
        wallet_conn = sqlite3.connect(wallet_filename)
        wallet_conn.row_factory = sqlite3.Row
        select = "SELECT * FROM Keychain"
        try:
            if "args" in globals() and args.msigna_keychain:  # args is not defined during unit tests
                wallet_cur = wallet_conn.execute(select + " WHERE name LIKE '%' || ? || '%'", (args.msigna_keychain,))
            else:
                wallet_cur = wallet_conn.execute(select)
        except sqlite3.OperationalError as e:
            if str(e).startswith("no such table"):
                raise ValueError("Not an mSIGNA wallet: " + str(e))  # it might be a Bither or Bitcoin Core wallet
            else:
                raise# unexpected error
        keychain = wallet_cur.fetchone()
        if not keychain:
            error_exit("no such keychain found in the mSIGNA vault")
        keychain_extra = wallet_cur.fetchone()
        if keychain_extra:
            print("Multiple matching keychains found in the mSIGNA vault:", file=sys.stderr)
            print("  ", keychain["name"])
            print("  ", keychain_extra["name"])
            for keychain_extra in wallet_cur:
                print("  ", keychain_extra["name"])
            error_exit("use --msigna-keychain NAME to specify a specific keychain")
        wallet_conn.close()

        privkey_ciphertext = keychain["privkey_ciphertext"]
        if len(privkey_ciphertext) == 32:
            error_exit("mSIGNA keychain '"+keychain["name"]+"' is not encrypted")
        if len(privkey_ciphertext) != 48:
            error_exit("mSIGNA keychain '"+keychain["name"]+"' has an unexpected privkey length")

        # only need the final 2 encrypted blocks (half of which is padding) plus the salt
        self = cls(loading=True)
        self._part_encrypted_privkey = privkey_ciphertext[-32:]
        self._salt                   = struct.pack("< q", keychain["privkey_salt"])
        return self

    # Import an encrypted privkey and salt that was extracted by extract-msigna-privkey.py
    @classmethod
    def load_from_data_extract(cls, privkey_data):
        self = cls(loading=True)
        self._part_encrypted_privkey = privkey_data[:32]
        self._salt                   = privkey_data[32:]
        return self

    def difficulty_info(self):
        return "2 SHA-256 iterations"

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def return_verified_password_or_false(self, passwords): #mSIGNA
        # Copy some vars into local for a small speed boost
        l_sha1                 = hashlib.sha1
        l_sha256               = hashlib.sha256
        part_encrypted_privkey = self._part_encrypted_privkey
        salt                   = self._salt

        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        passwords = map(lambda p: p.encode("utf_8", "ignore"), passwords)

        for count, password in enumerate(passwords, 1):
            password_hashed = l_sha256(l_sha256(password).digest()).digest()  # mSIGNA does this first
            #
            # mSIGNA's remaining KDF is OpenSSL's EVP_BytesToKey using SHA1 and an iteration count of
            # 5. The EVP_BytesToKey outer loop is unrolled with two iterations below which produces
            # 320 bits (2x SHA1's output) which is > 32 bytes (what's needed for the AES-256 key)
            derived_part1 = password_hashed + salt
            for i in range(5):  # 5 is mSIGNA's hard coded iteration count
                derived_part1 = l_sha1(derived_part1).digest()
            derived_part2 = derived_part1 + password_hashed + salt
            for i in range(5):
                derived_part2 = l_sha1(derived_part2).digest()
            #
            part_privkey = aes256_cbc_decrypt(derived_part1 + derived_part2[:12], part_encrypted_privkey[:16], part_encrypted_privkey[16:])
            #
            # If the last block (bytes 16-31) of part_encrypted_privkey is all padding, we've found it
            if part_privkey == b"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10":
                return password.decode("utf_8", "replace"), count

        return False, count


############### Electrum ###############

# Comman base class for all Electrum wallets
class WalletElectrum(object):
    opencl_algo = -1

    def __init__(self, loading = False):
        assert loading, 'use load_from_* to create a ' + self.__class__.__name__
        aes_library_name = load_aes256_library().__name__
        self._passwords_per_second = 100000 if aes_library_name == "Crypto" else 5000

    def __setstate__(self, state):
        # (re-)load the required libraries after being unpickled
        load_aes256_library(warnings=False)
        self.__dict__ = state

    def passwords_per_seconds(self, seconds):
        return max(int(round(self._passwords_per_second * seconds)), 1)

    # Import Electrum encrypted data extracted by an extract-electrum* script
    @classmethod
    def load_from_data_extract(cls, data):
        assert len(data) == 32
        self = cls(loading=True)
        self._iv                  = data[:16]  # the 16-byte IV
        self._part_encrypted_data = data[16:]  # 16-bytes of encrypted data
        return self

    def difficulty_info(self):
        return "2 SHA-256 iterations"

@register_wallet_class
class WalletElectrum1(WalletElectrum):

    def data_extract_id():
        return "el"

    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(0)
        # returns "maybe yes" or "definitely no"
        return None if wallet_file.read(2) == b"{'" else False

    # Load an Electrum wallet file (the part of it we need)
    @classmethod
    def load_from_filename(cls, wallet_filename):
        from ast import literal_eval
        with open(wallet_filename) as wallet_file:
            try:
                wallet = literal_eval(wallet_file.read(MAX_WALLET_FILE_SIZE))  # up to 64M, typical size is a few k
            except SyntaxError as e:  # translate any SyntaxError into a
                raise ValueError(e)   # ValueError as expected by load_wallet()
        return cls._load_from_dict(wallet)

    @classmethod
    def _load_from_dict(cls, wallet):
        seed_version = wallet.get("seed_version")
        if seed_version is None:             raise ValueError("Unrecognized wallet format (Electrum1 seed_version not found)")
        if seed_version != 4:                raise NotImplementedError("Unsupported Electrum1 seed version " + str(seed_version))
        if not wallet.get("use_encryption"): raise RuntimeError("Electrum1 wallet is not encrypted")
        seed_data = base64.b64decode(wallet["seed"])
        if len(seed_data) != 64:             raise RuntimeError("Electrum1 encrypted seed plus iv is not 64 bytes long")
        self = cls(loading=True)
        self._iv                  = seed_data[:16]    # only need the 16-byte IV plus
        self._part_encrypted_data = seed_data[16:32]  # the first 16-byte encrypted block of the seed
        return self

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    assert b"0" < b"9" < b"a" < b"f"  # the hex check below assumes ASCII ordering in the interest of speed
    def return_verified_password_or_false(self, passwords): #Electrum1
        # Copy some vars into local for a small speed boost
        l_sha256             = hashlib.sha256
        l_aes256_cbc_decrypt = aes256_cbc_decrypt
        part_encrypted_seed  = self._part_encrypted_data
        iv                   = self._iv

        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        passwords = map(lambda p: p.encode("utf_8", "ignore"), passwords)

        for count, password in enumerate(passwords, 1):
            key  = l_sha256( l_sha256( password ).digest() ).digest()
            seed = l_aes256_cbc_decrypt(key, iv, part_encrypted_seed)
            # If the first 16 bytes of the encrypted seed is all lower-case hex, we've found it
            for c in seed:
                if type(c) == str:
                    c = ord(c.encode())

                if c > ord("f") or c < ord("0") or ord("9") < c < ord("a"): break  # not hex
            else:  # if the loop above doesn't break, it's all hex
                return password.decode("utf_8", "replace"), count

        return False, count

@register_wallet_class
class WalletElectrum2(WalletElectrum):

    def data_extract_id():
        return "e2"

    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(0)
        # returns "maybe yes" or "definitely no"
        electrumWalletFileStart = wallet_file.read(1)
        return None if electrumWalletFileStart == b"{" else False

    # Load an Electrum wallet file (the part of it we need)
    @classmethod
    def load_from_filename(cls, wallet_filename):
        import json

        with open(wallet_filename) as wallet_file:
            wallet = json.load(wallet_file)
        wallet_type = wallet.get("wallet_type")
        if not wallet_type:
            raise ValueError("Unrecognized wallet format (Electrum2 wallet_type not found)")
        if wallet_type == "old":  # if it's been converted from 1.x to 2.y (y<7), return a WalletElectrum1 object
            return WalletElectrum1._load_from_dict(wallet)
        if not wallet.get("use_encryption"):
            raise ValueError("Electrum2 wallet is not encrypted")
        seed_version = wallet.get("seed_version", "(not found)")
        try:
            if wallet.get("seed_version") < 11:  # all versions above 2.x
                raise NotImplementedError("Unsupported Electrum2 seed version " + str(seed_version))

        except TypeError: # Seed version is none... Likely imported loose key wallet...
            if wallet_type != "imported":
                raise NotImplementedError("Unsupported Electrum2 seed version " + str(seed_version))
            else:
                pass

        xprv = None
        while True:  # "loops" exactly once; only here so we've something to break out of

            # Electrum 2.7+ standard wallets have a keystore
            keystore = wallet.get("keystore")
            if keystore:
                keystore_type = keystore.get("type", "(not found)")

                # Wallets originally created by an Electrum 2.x version
                if keystore_type == "bip32":
                    xprv = keystore.get("xprv")
                    if xprv: break

                # Former Electrum 1.x wallet after conversion to Electrum 2.7+ standard-wallet format
                elif keystore_type == "old":
                    seed_data = keystore.get("seed")
                    if seed_data:
                        # Construct and return a WalletElectrum1 object
                        seed_data = base64.b64decode(seed_data)
                        if len(seed_data) != 64:
                            raise RuntimeError("Electrum1 encrypted seed plus iv is not 64 bytes long")
                        self = WalletElectrum1(loading=True)
                        self._iv                  = seed_data[:16]    # only need the 16-byte IV plus
                        self._part_encrypted_data = seed_data[16:32]  # the first 16-byte encrypted block of the seed
                        return self

                # Imported loose private keys
                elif keystore_type == "imported":
                    for privkey in keystore["keypairs"].values():
                        if privkey:
                            # Construct and return a WalletElectrumLooseKey object
                            privkey = base64.b64decode(privkey)
                            if len(privkey) != 80:
                                raise RuntimeError("Electrum2 private key plus iv is not 80 bytes long")
                            self = WalletElectrumLooseKey(loading=True)
                            self._iv                  = privkey[-32:-16]  # only need the 16-byte IV plus
                            self._part_encrypted_data = privkey[-16:]     # the last 16-byte encrypted block of the key
                            return self

                else:
                    print("Warning: found unsupported keystore type " + keystore_type, file=sys.stderr)

            # Electrum 2.7+ multisig or 2fa wallet
            for i in itertools.count(1):
                x = wallet.get("x{}/".format(i))
                if not x: break
                x_type = x.get("type", "(not found)")
                if x_type == "bip32":
                    xprv = x.get("xprv")
                    if xprv: break
                else:
                    print("Warning: found unsupported key type " + x_type, file=sys.stderr)
            if xprv: break

            # Electrum 2.0 - 2.6.4 wallet with imported loose private keys
            if wallet_type == "imported":
                for imported in wallet["accounts"]["/x"]["imported"].values():
                    privkey = imported[1] if len(imported) >= 2 else None
                    if privkey:
                        # Construct and return a WalletElectrumLooseKey object
                        privkey = base64.b64decode(privkey)
                        if len(privkey) != 80:
                            raise RuntimeError("Electrum2 private key plus iv is not 80 bytes long")
                        self = WalletElectrumLooseKey(loading=True)
                        self._iv                  = privkey[-32:-16]  # only need the 16-byte IV plus
                        self._part_encrypted_data = privkey[-16:]     # the last 16-byte encrypted block of the key
                        return self

            # Electrum 2.0 - 2.6.4 wallet (of any other wallet type)
            else:
                mpks = wallet.get("master_private_keys")
                if mpks:
                    xprv = list(mpks.values())[0]
                    break

            raise RuntimeError("No master private keys or seeds found in Electrum2 wallet")

        xprv_data = base64.b64decode(xprv)
        if len(xprv_data) != 128:
            raise RuntimeError("Unexpected Electrum2 encrypted master private key length")
        self = cls(loading=True)
        self._iv                  = xprv_data[:16]    # only need the 16-byte IV plus
        self._part_encrypted_data = xprv_data[16:32]  # the first 16-byte encrypted block of a master privkey
        return self                                   # (the member variable name comes from the base class)

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    assert b"1" < b"9" < b"A" < b"Z" < b"a" < b"z"  # the b58 check below assumes ASCII ordering in the interest of speed
    def return_verified_password_or_false(self, passwords): #Electrum2
        # Copy some vars into local for a small speed boost
        l_sha256             = hashlib.sha256
        l_aes256_cbc_decrypt = aes256_cbc_decrypt
        part_encrypted_xprv  = self._part_encrypted_data
        iv                   = self._iv

        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        passwords = map(lambda p: p.encode("utf_8", "ignore"), passwords)

        for count, password in enumerate(passwords, 1):
            key  = l_sha256( l_sha256( password ).digest() ).digest()
            xprv = l_aes256_cbc_decrypt(key, iv, part_encrypted_xprv)

            if xprv.startswith(b"xprv"):  # BIP32 extended private key version bytes
                for c in xprv[4:]:
                    # If it's outside of the base58 set [1-9A-HJ-NP-Za-km-z]
                    if c > ord("z") or c < ord("1") or ord("9") < c < ord("A") or ord("Z") < c < ord("a") or chr(c) in "IOl": break  # not base58
                else:  # if the loop above doesn't break, it's base58
                    return password.decode("utf_8", "replace"), count

        return False, count

@register_wallet_class
class WalletElectrumLooseKey(WalletElectrum):

    def data_extract_id():
        return "ek"

    @staticmethod
    def is_wallet_file(wallet_file): return False  # WalletElectrum2.load_from_filename() creates us

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    assert b"1" < b"9" < b"A" < b"Z" < b"a" < b"z"  # the b58 check below assumes ASCII ordering in the interest of speed
    def return_verified_password_or_false(self, passwords): #ElectrumLooseKey
        # Copy some vars into local for a small speed boost
        l_sha256              = hashlib.sha256
        l_aes256_cbc_decrypt  = aes256_cbc_decrypt
        encrypted_privkey_end = self._part_encrypted_data
        iv                    = self._iv

        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        passwords = map(lambda p: p.encode("utf_8", "ignore"), passwords)

        for count, password in enumerate(passwords, 1):
            key         = l_sha256( l_sha256( password ).digest() ).digest()
            privkey_end = l_aes256_cbc_decrypt(key, iv, encrypted_privkey_end)
            padding_len = privkey_end[-1]
            # Check for valid PKCS7 padding for a 52 or 51 byte "WIF" private key
            # (4*16-byte-blocks == 64, 64 - 52 or 51 == 12 or 13
            if (padding_len == 12 or padding_len == 13) and privkey_end.endswith((chr(padding_len) * padding_len).encode()):
                for c in privkey_end[:-padding_len]:
                    # If it's outside of the base58 set [1-9A-HJ-NP-Za-km-z]
                    if c > ord("z") or c < ord("1") or ord("9") < c < ord("A") or ord("Z") < c < ord("a") or chr(c) in "IOl": break  # not base58
                else:  # if the loop above doesn't break, it's base58
                    return password.decode("utf_8", "replace"), count

        return False, count


@register_wallet_class
class WalletElectrum28(object):
    opencl_algo = -1

    def passwords_per_seconds(self, seconds):
        return max(int(round(self._passwords_per_second * seconds)), 1)

    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(0)
        try:
            base64walletData = wallet_file.read(8)
            data = base64.b64decode(base64walletData)
        except: return False
        return data[:4] == b"BIE1"  # Electrum 2.8+ magic

    def __init__(self, loading = False):
        assert loading, 'use load_from_* to create a ' + self.__class__.__name__
        global hmac, coincurve
        import hmac

        try:
            import coincurve
        except ModuleNotFoundError:
            exit("\nERROR: Cannot load coincurve module... Be sure to install all requirements with the command 'pip3 install -r requirements.txt', see https://btcrecover.readthedocs.io/en/latest/INSTALL/")

        pbkdf2_library_name    = load_pbkdf2_library().__name__
        self._aes_library_name = load_aes256_library().__name__
        self._passwords_per_second = 800 if pbkdf2_library_name == "hashlib" else 140

    def __getstate__(self):
        # Serialize unpicklable coincurve.PublicKey object
        state = self.__dict__.copy()
        state["_ephemeral_pubkey"] = self._ephemeral_pubkey.format(compressed=False)
        return state

    def __setstate__(self, state):
        # Restore coincurve.PublicKey object and (re-)load the required libraries
        global hmac, coincurve
        import hmac

        try:
            import coincurve
        except ModuleNotFoundError:
            exit("\nERROR: Cannot load coincurve module... Be sure to install all requirements with the command 'pip3 install -r requirements.txt', see https://btcrecover.readthedocs.io/en/latest/INSTALL/")

        load_pbkdf2_library(warnings=False)
        load_aes256_library(warnings=False)
        self.__dict__ = state
        self._ephemeral_pubkey = coincurve.PublicKey(self._ephemeral_pubkey)

    # Load an Electrum 2.8 encrypted wallet file
    @classmethod
    def load_from_filename(cls, wallet_filename):
        with open(wallet_filename) as wallet_file:
            data = wallet_file.read(MAX_WALLET_FILE_SIZE)  # up to 64M, typical size is a few k
        if len(data) >= MAX_WALLET_FILE_SIZE:
            raise ValueError("Encrypted Electrum wallet file is too big")
        MIN_LEN = 37 + 32 + 32  # header + ciphertext + trailer
        if len(data) < MIN_LEN * 4 / 3:
            raise EOFError("Expected at least {} bytes of text in the Electrum wallet file".format(int(math.ceil(MIN_LEN * 4 / 3))))
        data = base64.b64decode(data)
        if len(data) < MIN_LEN:
            raise EOFError("Expected at least {} bytes of decoded data in the Electrum wallet file".format(MIN_LEN))
        assert data[:4] == b"BIE1", "wallet file has Electrum 2.8+ magic"

        self = cls(loading=True)
        self._ephemeral_pubkey = coincurve.PublicKey(data[4:37])
        self._ciphertext_beg   = data[37:37+16]  # first ciphertext block
        self._ciphertext_end   = data[-64:-32]   # last two blocks (before mac)
        self._mac              = data[-32:]
        self._all_but_mac      = data[:-32]
        return self

    def difficulty_info(self):
        return "1024 PBKDF2-SHA512 iterations + ECC"

    def return_verified_password_or_false(self, passwords): # Electrum28
        return self._return_verified_password_or_false_opencl(passwords) if (not isinstance(self.opencl_algo,int)) \
          else self._return_verified_password_or_false_cpu(passwords)

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def _return_verified_password_or_false_cpu(self, passwords): #Electrum28
        cutils = coincurve.utils

        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        passwords = map(lambda p: p.encode("utf_8", "ignore"), passwords)

        for count, password in enumerate(passwords, 1):

            # Derive the ECIES shared public key, and from it, the AES and HMAC keys
            static_privkey = pbkdf2_hmac("sha512", password, b"", 1024, 64)
            # Electrum uses a 512-bit private key (why?), but libsecp256k1 expects a 256-bit key < group's order:
            static_privkey = cutils.int_to_bytes( cutils.bytes_to_int(static_privkey) % cutils.GROUP_ORDER_INT )
            shared_pubkey  = self._ephemeral_pubkey.multiply(static_privkey).format()
            keys           = hashlib.sha512(shared_pubkey).digest()

            # Check the MAC
            computed_mac = hmac.new(keys[32:], self._all_but_mac, hashlib.sha256).digest()
            if computed_mac == self._mac:
                return password.decode("utf_8", "replace"), count

        return False, count

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def _return_verified_password_or_false_opencl(self, arg_passwords): #Electrum28
        cutils = coincurve.utils

        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        passwords = map(lambda p: p.encode("utf_8", "ignore"), arg_passwords)

        clResult = self.opencl_algo.cl_pbkdf2(self.opencl_context_pbkdf2_sha512, passwords, b"", 1024, 64)

        # This list is consumed, so recreated it and zip
        passwords = map(lambda p: p.encode("utf_8", "ignore"), arg_passwords)

        results = zip(passwords, clResult)

        for count, (password, static_privkey) in enumerate(results, 1):
            # Electrum uses a 512-bit private key (why?), but libsecp256k1 expects a 256-bit key < group's order:
            static_privkey = cutils.int_to_bytes( cutils.bytes_to_int(static_privkey) % cutils.GROUP_ORDER_INT )
            shared_pubkey  = self._ephemeral_pubkey.multiply(static_privkey).format()
            keys           = hashlib.sha512(shared_pubkey).digest()

            # Check the MAC
            computed_mac = hmac.new(keys[32:], self._all_but_mac, hashlib.sha256).digest()
            if computed_mac == self._mac:
                return password.decode("utf_8", "replace"), count

        return False, count


############### Blockchain ###############

@register_wallet_class
class WalletBlockchain(object):

    opencl_algo = -1

    _savepossiblematches = True
    _possible_passwords_file = "possible_passwords.log"

    _dump_privkeys_file = None
    _dump_wallet_file = None
    _using_extract = False

    def data_extract_id():
        return "bk"

    #
    # These are a bit fragile in the interest of simplicity because they assume that certain
    # JSON data will be in the first block of the file
    #

    # Encryption scheme used in newer wallets
    def decrypt_current(self,password, salt_and_iv, iter_count, data):
        key = pbkdf2_hmac("sha1", password, salt_and_iv, iter_count, 32)
        decrypted = aes256_cbc_decrypt(key, salt_and_iv, data)  # CBC mode
        padding = ord(decrypted[-1:])  # ISO 10126 padding length
        # A bit fragile because it assumes the guid is in the first encrypted block,
        # although this has always been the case as of 6/2014 (since 12/2011)
        # As of May 2020, guid no longer appears in the first block, but tx_notes appears there instead
        return decrypted[:-padding] if 1 <= padding <= 16 and re.search(
            b"\"guid\"|\"tx_notes\"|\"address_book|\"double", decrypted) else None

    #
    # Encryption scheme only used in version 0.0 wallets (N.B. this is untested)
    def decrypt_old(self, password, salt_and_iv, data):
        key = pbkdf2_hmac("sha1", password, salt_and_iv, 1, 32)  # only 1 iteration
        decrypted = aes256_ofb_decrypt(key, salt_and_iv, data)  # OFB mode
        # The 16-byte last block, reversed, with all but the first byte of ISO 7816-4 padding removed:
        last_block = tuple(itertools.dropwhile(lambda x: x == b"\0", decrypted[:15:-1]))
        padding = 17 - len(last_block)  # ISO 7816-4 padding length
        return decrypted[:-padding] if 1 <= padding <= 16 and \
                                       decrypted[-padding] == b"\x80" and \
                                       re.match('{\s*"guid"',decrypted.decode()) else None

    def decrypt_wallet(self,password):
        from lib.cashaddress import base58

        # Can't decrypt or dump an extract in any meaninful way...
        if self._using_extract:
            return

        # If we aren't dumping these files, then just return...
        if not (self._dump_wallet_file or self._dump_privkeys_file):
            return

        #print(self._encrypted_wallet)

        # Convert and split encrypted private key
        #encrypted = base64.b64decode(self._encrypted_wallet)
        iv, encrypted = self._encrypted_wallet[:16], self._encrypted_wallet[16:]

        if self._iter_count:  # v2.0 wallets have a single possible encryption scheme
            data = self.decrypt_current(password, iv, self._iter_count, encrypted)
        else:           # v0.0 wallets have three different possible encryption schemes
            data = self.decrypt_current(password, iv, 10, encrypted) or \
                   self.decrypt_current(password, iv, 1, encrypted) or \
                   self.decrypt_old(password, iv, encrypted)

        # Load and parse the now-decrypted wallet
        self._wallet_json = json.loads(data)

        # Add these items to the json for their associated address
        for key in self._wallet_json['keys']:
            try:
                # Need to check that the private key is actually 64 characters (32 bytes) long, as some blockchain wallets
                # have a bug where the base58 private keys in wallet files leave off any leading zeros...
                privkey = binascii.hexlify(base58.b58decode(key["priv"]))
                privkey = privkey.zfill(64)
                privkey = binascii.unhexlify(privkey)

                # Some versions of blockchain wallets can be inconsistent in whether they used compressed or uncompressed addresses
                # Rather than do something clever like check the addr key for to check which, just dump both for now...
                key['privkey_compressed'] = base58.b58encode_check(bytes([0x80]) + privkey + bytes([0x1]))
                key['privkey_uncompressed'] = base58.b58encode_check(bytes([0x80]) + privkey)
            except ValueError:
                print("Error: Private Key not correctly decrypted, likey due to second password being present...")

        if self._dump_wallet_file:
            self.dump_wallet()
        if self._dump_privkeys_file:
            self.dump_privkeys()

    # This just dumps the wallet json as-is (regardless of whether the keys have been decrypted
    def dump_wallet(self):
        with open(self._dump_wallet_file, 'a') as logfile:
                logfile.write(json.dumps(self._wallet_json, indent=4))

    # This just dumps the wallet private keys
    def dump_privkeys(self):
        with open(self._dump_privkeys_file, 'a') as logfile:
            logfile.write("Private Keys (For copy/paste in to Electrum) are below...\n")

            for key in self._wallet_json['keys']:
                # Blockchain.com wallets are fairly inconsistent in whether they used
                # compressed or uncompressed keys, so produce both...
                try:
                    logfile.write(key['privkey_compressed'] + "\n")
                    logfile.write(key['privkey_uncompressed'] + "\n")
                except KeyError:
                    print("Error: Private Key not correctly decrypted, likey due to second password being present...")

            # Older wallets don't have any hd_wallets at all, so handle this gracefully
            try:
                for hd_wallets in self._wallet_json['hd_wallets']:
                    for accounts in hd_wallets['accounts']:
                        logfile.write(accounts['xpriv'] + "\n")
            except:
                pass

    @staticmethod
    def is_wallet_file(wallet_file): return None  # there's no easy way to check this

    def __init__(self, iter_count, loading = False):
        assert loading, 'use load_from_* to create a ' + self.__class__.__name__
        pbkdf2_library_name = load_pbkdf2_library().__name__
        aes_library_name    = load_aes256_library().__name__
        self._iter_count           = iter_count
        self._passwords_per_second = 400000 if pbkdf2_library_name == "hashlib" else 100000
        if iter_count == 0:  # if it's a v0 wallet
            iter_count = 10
        self._passwords_per_second /= iter_count
        if aes_library_name != "Crypto" and self._passwords_per_second > 2000:
            self._passwords_per_second = 2000

    def __setstate__(self, state):
        # (re-)load the required libraries after being unpickled
        load_pbkdf2_library(warnings=False)
        load_aes256_library(warnings=False)
        self.__dict__ = state

    def passwords_per_seconds(self, seconds):
        return max(int(round(self._passwords_per_second * seconds)), 1)

    # Load a Blockchain wallet file (the part of it we need)
    @classmethod
    def load_from_filename(cls, wallet_filename):
        with open(wallet_filename) as wallet_file:
            data, iter_count = cls._parse_encrypted_blockchain_wallet(wallet_file.read(MAX_WALLET_FILE_SIZE))  # up to 64M, typical size is a few k
        self = cls(iter_count, loading=True)
        self._salt_and_iv     = data[:16]    # only need the salt_and_iv plus
        self._encrypted_block = data[16:32]  # the first 16-byte encrypted block
        self._encrypted_wallet = data
        return self

    # Parse the contents of an encrypted blockchain wallet (v0 - v3) or config file returning two
    # values in a tuple: (encrypted_data_blob, iter_count) where iter_count == 0 for v0 wallets
    @staticmethod
    def _parse_encrypted_blockchain_wallet(data):
        iter_count = 0

        while True:  # "loops" exactly once; only here so we've something to break out of
            # Most blockchain files (except v0.0 wallets) are JSON encoded; try to parse it as such
            try:
                data = json.loads(data)
            except ValueError: break

            # Config files have no version attribute; they encapsulate the wallet file plus some detrius
            if "version" not in data:
                try:
                    data = data["payload"]  # extract the wallet file from the config
                except KeyError:
                    raise ValueError("Can't find either version nor payload attributes in Blockchain file")
                try:
                    data = json.loads(data)  # try again to parse a v2.0/v3.0 JSON-encoded wallet file
                except ValueError: break

            # Extract what's needed from a v2.0/3.0 wallet file
            if data["version"] > 4:
                raise NotImplementedError("Unsupported Blockchain wallet version " + str(data["version"]))
            iter_count = data["pbkdf2_iterations"]
            if not isinstance(iter_count, int) or iter_count < 1:
                raise ValueError("Invalid Blockchain pbkdf2_iterations " + str(iter_count))
            data = data["payload"]

            break

        # Either the encrypted data was extracted from the "payload" field above, or
        # this is a v0.0 wallet file whose entire contents consist of the encrypted data
        try:
            data = base64.b64decode(data)
        except TypeError as e:
            raise ValueError("Can't base64-decode Blockchain wallet: "+str(e))
        if len(data) < 32:
            raise ValueError("Encrypted Blockchain data is too short")
        if len(data) % 16 != 0:
            raise ValueError("Encrypted Blockchain data length is not divisible by the encryption blocksize (16)")

        # If this is (possibly) a v0.0 (a.k.a. v1) wallet file, check that the encrypted data
        # looks random, otherwise this could be some other type of base64-encoded file such
        # as a MultiBit key file (it should be safe to skip this test for v2.0+ wallets)
        if not iter_count:  # if this is a v0.0 wallet
            # The likelihood of of finding a valid encrypted blockchain wallet (even at its minimum length
            # of about 500 bytes) with less than 7.4 bits of entropy per byte is less than 1 in 10^6
            # (decreased test below to 7.1 after being shown a wallet with 7.1 entropy bits)
            entropy_bits = est_entropy_bits(data)
            if entropy_bits < 7.1:
                raise ValueError("Doesn't look random enough to be an encrypted Blockchain wallet (only {:.1f} bits of entropy per byte)".format(entropy_bits))

        return data, iter_count  # iter_count == 0 for v0 wallets

    # Import extracted Blockchain file data necessary for main password checking
    @classmethod
    def load_from_data_extract(cls, file_data):
        # These are the same first encrypted block, salt_and_iv, iteration count retrieved above
        encrypted_block, salt_and_iv, iter_count = struct.unpack(b"< 16s 16s I", file_data)
        self = cls(iter_count, loading=True)
        self._encrypted_block = encrypted_block
        self._salt_and_iv     = salt_and_iv
        self._using_extract   = True
        return self

    def difficulty_info(self):
        return "{:,} PBKDF2-SHA1 iterations".format(self._iter_count or 10)

    def init_logfile(self):
        with open(self._possible_passwords_file, 'a') as logfile:
            logfile.write(
        "\n\n" +
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " New Recovery Started...\n" +
        "This file contains passwords and blocks from passwords which `may` not exactly match those that "
        "BTCRecover searches for by default. \n\n"
        "Examples of successfully decrypted blocks will not just be random characters, "
        "some examples of what correctly decryped blocks logs look like are:\n\n"
        "Possible Password ==>btcr-test-password<== in Decrypted Block ==>{\n\"guid\" : \"9bb<==\n"
        "Possible Password ==>testblockchain<== in Decrypted Block ==>{\"address_book\":<==\n"
        "Possible Password ==>btcr-test-password<== in Decrypted Block ==>{\"tx_notes\":{},\"\n"
        "Possible Password ==>Testing123!<== in Decrypted Block ==>{\"double_encrypt<==\n"
        "\n"
        "Note: The markers ==> and <== are not part of either your password or the decrypted block...\n\n"
        "If the password works and was not correctly found, or your wallet detects a false positive, please report the decrypted block data at "
        "https://github.com/3rdIteration/btcrecover/issues/\n\n")
        print("* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *")
        print("*                     Note for Blockchain.com Wallets...                *")
        print("*                                                                       *")
        print("*   Writing all `possibly matched` and fully matched Passwords &        *")
        print("*   Decrypted blocks to ", self._possible_passwords_file)
        print("*   This can be disabled with the --disablesavepossiblematches argument *")
        print("* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *")
        print()

    # A bit fragile because it assumes that some specific text is in the first encrypted block,
    # This was "guid" as of 6/2014 (since 12/2011)
    # As of May 2020, guid no longer appears in the first block, but 'tx_notes' appears there instead
    # Also check to see if the first block starts with 'address_book'
    # first as was apparently the case with some wallets created around Jan 2014
    # (see https://github.com/gurnec/btcrecover/issues/ that start with "double_encryption"
    # as per this issue here: https://github.com/3rdIteration/btcrecover/issues/96
    def check_blockchain_decrypted_block(self, unencrypted_block, password):
        if unencrypted_block[0] == ord("{"):
            if b'"' in unencrypted_block[:4]: # If it really is a json wallet fragment, there will be a double quote in there within the first few characters...
                try:
                    # Try to decode the decrypted block to ascii, this will pretty much always fail on anything other
                    # than the correct password
                    unencrypted_block.decode("ascii")
                    if self._savepossiblematches:
                        with open(self._possible_passwords_file, 'a', encoding="utf_8") as logfile:
                            logfile.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") +
                                          " Possible Password ==>" +
                                          password.decode("utf_8") +
                                          "<== in Decrypted Block ==>" +
                                          unencrypted_block.decode("ascii") +
                                          "<==\n")
                except UnicodeDecodeError:
                    pass

            # Return True if
            if re.search(b"\"guid\"|\"tx_notes\"|\"address_book|\"double", unencrypted_block):
                if self._savepossiblematches:
                    try:
                        with open('possible_passwords.log', 'a', encoding="utf_8") as logfile:
                            logfile.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") +
                                          " Found Password ==>" +
                                          password.decode("utf_8") +
                                          "<== in Decrypted Block ==>" +
                                          unencrypted_block.decode("ascii") +
                                          "<==\n")
                            return True # Only return true if we can successfully decode the block in to ascii

                    except UnicodeDecodeError: # Likely a false positive if we can't...
                        with open('possible_passwords.log', 'a', encoding="utf_8") as logfile:
                            logfile.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") +
                                          " Found Likely False Positive Password (with non-Ascii characters in decrypted block) ==>" +
                                          password.decode("utf_8") +
                                          "<== in Decrypted Block ==>" +
                                          unencrypted_block.decode("utf-8", "ignore") +
                                          "<==\n")
                            

        return False

    def return_verified_password_or_false(self, passwords): # Blockchain.com Main Password
        return self._return_verified_password_or_false_opencl(passwords) if (not isinstance(self.opencl_algo,int)) \
          else self._return_verified_password_or_false_cpu(passwords)

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def _return_verified_password_or_false_cpu(self, arg_passwords): # Blockchain.com Main Password
        # Copy a few globals into local for a small speed boost
        l_pbkdf2_hmac        = pbkdf2_hmac
        l_aes256_cbc_decrypt = aes256_cbc_decrypt
        l_aes256_ofb_decrypt = aes256_ofb_decrypt
        encrypted_block      = self._encrypted_block
        salt_and_iv          = self._salt_and_iv
        iter_count           = self._iter_count

        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        passwords = map(lambda p: p.encode("utf_8", "ignore"), arg_passwords)

        v0 = not iter_count     # version 0.0 wallets don't specify an iter_count
        if v0: iter_count = 10  # the default iter_count for version 0.0 wallets

        for count, password in enumerate(passwords, 1):
            key = l_pbkdf2_hmac("sha1", password, salt_and_iv, iter_count, 32)          # iter_count iterations
            unencrypted_block = l_aes256_cbc_decrypt(key, salt_and_iv, encrypted_block)  # CBC mode

            if self.check_blockchain_decrypted_block(unencrypted_block, password):
                # Decrypt and dump the wallet if required
                self.decrypt_wallet(password)
                return password.decode("utf_8", "replace"), count

        if v0:
            # Convert Unicode strings (lazily) to UTF-8 bytestrings
            passwords = map(lambda p: p.encode("utf_8", "ignore"), arg_passwords)

            # Try the older encryption schemes possibly used in v0.0 wallets
            for count, password in enumerate(passwords, 1):
                key = l_pbkdf2_hmac("sha1", password, salt_and_iv, 1, 32)                   # only 1 iteration
                unencrypted_block = l_aes256_cbc_decrypt(key, salt_and_iv, encrypted_block)  # CBC mode
                # print("CBC:", unencrypted_block)
                if self.check_blockchain_decrypted_block(unencrypted_block, password):
                    return password.decode("utf_8", "replace"), count

                unencrypted_block = l_aes256_ofb_decrypt(key, salt_and_iv, encrypted_block)  # OFB mode
                # print("OBF:", unencrypted_block)
                if self.check_blockchain_decrypted_block(unencrypted_block, password):
                    return password.decode("utf_8", "replace"), count

        return False, count

    def _return_verified_password_or_false_opencl(self, arg_passwords): # Blockchain.com Main Password
        # Copy a few globals into local for a small speed boost
        l_aes256_cbc_decrypt = aes256_cbc_decrypt
        l_aes256_ofb_decrypt = aes256_ofb_decrypt
        encrypted_block      = self._encrypted_block
        salt_and_iv          = self._salt_and_iv
        iter_count           = self._iter_count

        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        passwords = map(lambda p: p.encode("utf_8", "ignore"), arg_passwords)

        clResult = self.opencl_algo.cl_pbkdf2(self.opencl_context_pbkdf2_sha1, passwords, salt_and_iv, iter_count, 32)

        #This list is consumed, so recreated it and zip
        passwords = map(lambda p: p.encode("utf_8", "ignore"), arg_passwords)

        results = zip(passwords, clResult)

        for count, (password,key) in enumerate(results, 1):
            unencrypted_block = l_aes256_cbc_decrypt(key, salt_and_iv, encrypted_block)  # CBC mode
            if self.check_blockchain_decrypted_block(unencrypted_block, password):
                return password.decode("utf_8", "replace"), count

        return False, count


@register_wallet_class
class WalletBlockchainSecondpass(WalletBlockchain):

    _dump_privkeys_file = None
    _dump_wallet_file = None
    _using_extract = False

    def data_extract_id():
        return "bs"

    def decrypt_secondpass_privkey(self, encrypted, password, iterations, legacy_decrypt):
        # Convert and split encrypted private key
        encrypted = base64.b64decode(encrypted)
        iv, encrypted = encrypted[:16], encrypted[16:]

        # Create the decryption key and decrypt the private key
        aeshash = pbkdf2_hmac("sha1", password, iv, iterations, 32)
        if not legacy_decrypt:
            clear = aes256_cbc_decrypt(aeshash, iv, encrypted)
        else:
            clear = aes256_ofb_decrypt(aeshash, iv, encrypted)

        # Remove ISO 10126 Padding
        pad_len = clear[-1]
        decrypted = clear[:-pad_len]
        return decrypted

    def decrypt_wallet(self, password, iter_count, legacy_decrypt = False):
        from lib.cashaddress import base58

        # Can't decrypt or dump an extract in any meaninful way...
        if self._using_extract:
            return

        # If we aren't dumping these files, then just return...
        if not (self._dump_wallet_file or self._dump_privkeys_file):
            return

        # Decrypt the keys and add these items to the json for their associated address
        for key in self._wallet_json['keys']:
            privkey = self.decrypt_secondpass_privkey(key["priv"],
                                                    self._wallet_json['sharedKey'].encode('ascii') + password,
                                                    iter_count, legacy_decrypt)

            key['priv_decrypted'] = base58.b58encode(base58.b58decode(privkey))

            # Need to check that the private key is actually 64 characters (32 bytes) long, as some blockchain wallets
            # have a bug where the base58 private keys in wallet files leave off any leading zeros...
            privkey = binascii.hexlify(base58.b58decode(privkey))
            privkey = privkey.zfill(64)
            privkey = binascii.unhexlify(privkey)

            # Some versions of blockchain wallets can be inconsistent in whether they used compressed or uncompressed addresses
            # Rather than do something clever like check the addr key for to check which, just dump both for now...
            key['privkey_compressed'] = base58.b58encode_check(bytes([0x80]) + privkey + bytes([0x1]))
            key['privkey_uncompressed'] = base58.b58encode_check(bytes([0x80]) + privkey)

        # Older wallets don't have any hd_wallets at all, so handle this gracefully
        try:
            for hd_wallets in self._wallet_json['hd_wallets']:
                for accounts in hd_wallets['accounts']:
                    accounts['xpriv_decrypted'] = self.decrypt_secondpass_privkey(accounts["xpriv"],
                                                              self._wallet_json['sharedKey'].encode('ascii') + password,
                                                              iter_count, legacy_decrypt).decode()
        except:
            pass

        if self._dump_wallet_file:
            self.dump_wallet()

        if self._dump_privkeys_file:
            self.dump_privkeys()

    # This just dumps the wallet json as-is (regardless of whether the keys have been decrypted
    def dump_wallet(self):
        with open(self._dump_wallet_file, 'a') as logfile:
                logfile.write(json.dumps(self._wallet_json, indent=4))

    # This just dumps the wallet private keys
    def dump_privkeys(self):
        with open(self._dump_privkeys_file, 'a') as logfile:
            logfile.write("Private Keys (For copy/paste in to Electrum) are below...\n")

            for key in self._wallet_json['keys']:
                # Blockchain.com wallets are fairly inconsistent in whether they used
                # compressed or uncompressed keys, so produce both...
                logfile.write(key['privkey_compressed'] + "\n")
                logfile.write(key['privkey_uncompressed'] + "\n")

            try:
                for hd_wallets in self._wallet_json['hd_wallets']:
                    for accounts in hd_wallets['accounts']:
                        logfile.write(accounts['xpriv_decrypted']+ "\n")
            except:
                pass


    @staticmethod
    def is_wallet_file(wallet_file): return False  # never auto-detected as this wallet type

    # Load a Blockchain wallet file to get the "Second Password" hash,
    # decrypting the wallet if necessary
    @classmethod
    def load_from_filename(cls, wallet_filename, password = None, force_purepython = False):
        from uuid import UUID

        with open(wallet_filename) as wallet_file:
            data = wallet_file.read(MAX_WALLET_FILE_SIZE)  # up to 64M, typical size is a few k

        try:
            # Assuming the wallet is encrypted, get the encrypted data
            data, iter_count = cls._parse_encrypted_blockchain_wallet(data)
        except ValueError as e:
            # This is the one error to expect and ignore which occurs when the wallet isn't encrypted
            if e.args[0] == "Can't find either version nor payload attributes in Blockchain file":
                pass
            else:
                raise
        except Exception as e:
            error_exit(str(e))
        else:
            # If there were no problems getting the encrypted data, decrypt it
            if not password:
                password = prompt_unicode_password(
                    "Please enter the Blockchain wallet's main password: ",
                    "encrypted Blockchain files must be decrypted before searching for the second password")
            password = password.encode("utf_8")
            data, salt_and_iv = data[16:], data[:16]
            load_pbkdf2_library(force_purepython)
            load_aes256_library(force_purepython)

            if iter_count:  # v2.0 wallets have a single possible encryption scheme
                data = cls.decrypt_current(cls, password, salt_and_iv, iter_count, data)
            else:           # v0.0 wallets have three different possible encryption schemes
                data = cls.decrypt_current(cls, password, salt_and_iv, 10, data) or \
                       cls.decrypt_current(cls, password, salt_and_iv, 1, data) or \
                       cls.decrypt_old(cls, password, salt_and_iv, data)
            if not data:
                error_exit("can't decrypt wallet (wrong main password?)")

        # Load and parse the now-decrypted wallet
        data = json.loads(data)
        if not data.get("double_encryption"):
            error_exit("double encryption with a second password is not enabled for this wallet")

        # Extract and save what we need to perform checking on the second password
        try:
            iter_count = data["options"]["pbkdf2_iterations"]
            if not isinstance(iter_count, int) or iter_count < 1:
                raise ValueError("Invalid Blockchain second password pbkdf2_iterations " + str(iter_count))
        except KeyError:
            iter_count = 0
        self = cls(iter_count, loading=True)
        #
        self._password_hash = base64.b16decode(data["dpasswordhash"], casefold=True)
        if len(self._password_hash) != 32:
            raise ValueError("Blockchain second password hash is not 32 bytes long")
        #

        self._salt = data["sharedKey"].encode("ascii")

        if str(UUID(self._salt.decode().replace("-",""))).encode() != self._salt:
            raise ValueError("Unrecognized Blockchain salt format")

        self._wallet_json = data

        return self

    # Import extracted Blockchain file data necessary for second password checking
    @classmethod
    def load_from_data_extract(cls, file_data):
        from uuid import UUID
        # These are the same second password hash, salt, iteration count retrieved above
        password_hash, uuid_salt, iter_count = struct.unpack(b"< 32s 16s I", file_data)
        self = cls(iter_count, loading=True)
        self._salt          = str(UUID(bytes=uuid_salt))
        self._password_hash = password_hash
        self._using_extract = True
        return self

    def difficulty_info(self):
        return ("{:,}".format(self._iter_count) if self._iter_count else "1-10") + " SHA-256 iterations"

    def return_verified_password_or_false(self, passwords): # Blockchain.com second Password
        return self._return_verified_password_or_false_opencl(passwords) if (not isinstance(self.opencl_algo,int)) \
          else self._return_verified_password_or_false_cpu(passwords)

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def _return_verified_password_or_false_cpu(self, arg_passwords): # Blockchain.com Secondpassword
        # Copy vars into locals for a small speed boost
        l_sha256 = hashlib.sha256
        password_hash = self._password_hash
        salt          = self._salt
        iter_count    = self._iter_count

        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        passwords = map(lambda p: p.encode("utf_8", "ignore"), arg_passwords)

        for count, password in enumerate(passwords, 1):

            # Newer wallets specify an iter_count and use something similar to PBKDF1 with SHA-256
            if iter_count:
                if isinstance(salt,str): running_hash = salt.encode() + password
                if isinstance(salt,bytes): running_hash = salt + password
                for i in range(iter_count):
                    running_hash = l_sha256(running_hash).digest()
                if running_hash == password_hash:
                    #print("Debug: Matched Second pass (Iter-Count present)")
                    # Decrypt wallet and dump if required
                    self.decrypt_wallet(password, iter_count)
                    return password.decode("utf_8", "replace"), count

            # Older wallets used one of three password hashing schemes
            # 2022-03 Update - It also seems that some newer (v3) wallets use these older hashing schemes too...
            if isinstance(salt,str): running_hash = l_sha256(salt.encode() + password).digest()
            if isinstance(salt, bytes): running_hash = l_sha256(salt + password).digest()
            # Just a single SHA-256 hash
            if running_hash == password_hash:
                #print("Debug: Matched Second pass (Single Hash)")
                # Decrypt wallet and dump if required
                self.decrypt_wallet(password, 1)
                return password.decode("utf_8", "replace"), count
            # Exactly 10 hashes (the first of which was done above)
            for i in range(9):
                running_hash = l_sha256(running_hash).digest()
            if running_hash == password_hash:
                #print("Debug: Matched Second pass (Exactly 10 hashes)")
                # Decrypt wallet and dump if required
                self.decrypt_wallet(password, 10)
                return password.decode("utf_8", "replace"), count
            # A single unsalted hash
            if l_sha256(password).digest() == password_hash:
                #print("Debug: Matched Second pass (Single Unsalted Hash)")
                # Decrypt wallet and dump if required
                self.decrypt_wallet(password, 1, True)
                return password.decode("utf_8", "replace"), count

        return False, count

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def _return_verified_password_or_false_opencl(self, arg_passwords): # Blockchain.com Secondpassword
        # Copy vars into locals for a small speed boost
        l_sha256 = hashlib.sha256
        password_hash = self._password_hash
        salt          = self._salt
        iter_count    = self._iter_count

        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        passwords = map(lambda p: p.encode("utf_8", "ignore"), arg_passwords)

        hashed_keys = []
        for password in passwords:
            if isinstance(salt, str): derived_key = salt.encode() + password
            if isinstance(salt, bytes): derived_key = salt + password
            hashed_keys.append(l_sha256(derived_key).digest())

        if iter_count:
            clResult = self.opencl_algo.cl_hash_iterations(self.opencl_context_hash_iterations_sha256, hashed_keys, self._iter_count-1, 8)

            # This list is consumed, so recreated it and zip
            passwords = map(lambda p: p.encode("utf_8", "ignore"), arg_passwords)

            results = zip(passwords, clResult)

        # Newer wallets specify an iter_count and use something similar to PBKDF1 with SHA-256
            for count, (password, derived_key) in enumerate(results, 1):
                if derived_key == password_hash:
                    self.decrypt_wallet(password, iter_count)
                    return password.decode("utf_8", "replace"), count

        # Older wallets used one of three password hashing schemes
        # 2022-03 Update - It also seems that some newer (v3) wallets use these older hashing schemes too...
        # (These older encryption schemes aren't worth running on the GPU, too few iterations)

        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        passwords = map(lambda p: p.encode("utf_8", "ignore"), arg_passwords)

        for count, password in enumerate(passwords, 1):
            if isinstance(salt, str): running_hash = l_sha256(salt.encode() + password).digest()
            if isinstance(salt, bytes): running_hash = l_sha256(salt + password).digest()
            # Just a single SHA-256 hash
            if running_hash == password_hash:
                # print("Debug: Matched Second pass (Single Hash)")
                # Decrypt wallet and dump if required
                self.decrypt_wallet(password, 1)
                return password.decode("utf_8", "replace"), count
            # Exactly 10 hashes (the first of which was done above)
            for i in range(9):
                running_hash = l_sha256(running_hash).digest()
            if running_hash == password_hash:
                # print("Debug: Matched Second pass (Exactly 10 hashes)")
                # Decrypt wallet and dump if required
                self.decrypt_wallet(password, 10)
                return password.decode("utf_8", "replace"), count
            # A single unsalted hash
            if l_sha256(password).digest() == password_hash:
                # print("Debug: Matched Second pass (Single Unsalted Hash)")
                # Decrypt wallet and dump if required
                self.decrypt_wallet(password, 1, True)
                return password.decode("utf_8", "replace"), count


        return False, count

############### Block.io ###############

@register_wallet_class
class WalletBlockIO(object):
    opencl_algo = -1
    _savepossiblematches = False

    _dump_privkeys_file = None
    _dump_wallet_file = None
    _using_extract = False

    def __init__(self):
        try:
            import ecdsa
        except ModuleNotFoundError:
            exit(
                "\nERROR: Cannot load ecdsa module which is required for block.io wallets... You can install it with the command 'pip3 install ecdsa")

        try:
            import bitcoinutils
        except ModuleNotFoundError:
            exit(
                "\nERROR: Cannot load bitcoin-utils module which is required for block.io wallets... You can install it with the command 'pip3 install bitcoin-utils'")

    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(0)
        try:
            walletdata = wallet_file.read()
        except: return False
        return (b"user_key" in walletdata and b"encrypted_passphrase" in walletdata)  # Block.io wallets have a user_key field and emcrypted passphrase fields which are quite unique

    def passwords_per_seconds(self, seconds):
        try:
            if self.user_key['algorithm']['pbkdf2_iterations'] == 2048:
                return 5000
            else:
                return 150 # Newer wallets use over 100,000 PBKDF2 iterations
        except KeyError: # Older Legacy wallets don't have a algorithm key at all...
            return 5000

    # Load a Dogechain wallet file
    @classmethod
    def load_from_filename(cls, wallet_filename):
        self = cls()
        with open(wallet_filename, "rb") as wallet_file:
                wallet_data = wallet_file.read()

        json_data = json.loads(wallet_data)
        # There are two ways that the JSON from block.io can be formatted, depending on which backup the user retrieves
        try:
            self.user_key = json_data['data']['current_user_keys'][0]['user_key']
        except KeyError:
            self.user_key = json_data['data']['user_key']
        return self

    def difficulty_info(self):
        try:
            iter_count = self.user_key['algorithm']['pbkdf2_iterations']
            hash_function = self.user_key['algorithm']['pbkdf2_hash_function']
        except KeyError:
            iter_count = 2048
            hash_function = "SHA256"
        return str(iter_count) + " " + hash_function + " Iterations"

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def return_verified_password_or_false(self, arg_passwords):  # block.io Main Password

        for count, password in enumerate(arg_passwords, 1):
            try:
                key = lib.block_io.BlockIo.Helper.dynamicExtractKey(self.user_key, password)
                if self.user_key['public_key'].encode() == key.pubkey_hex():
                    return password, count

            except lib.block_io.IncorrectDecryptionPasswordError:
                pass
            except binascii.Error:
                pass

        return False, count

############### Dogechain.info ###############

@register_wallet_class
class WalletDogechain(object):
    opencl_algo = -1
    _savepossiblematches = True
    _possible_passwords_file = "possible_passwords.log"

    _dump_privkeys_file = None
    _dump_wallet_file = None
    _using_extract = False

    def data_extract_id():
        return "dc"

    #
    # These are a bit fragile in the interest of simplicity because they assume that certain
    # JSON data will be in the first block of the file
    #
    def decrypt(self, password):
        passwordSHA256 = hashlib.sha256(password).digest()
        passwordbase64 = base64.b64encode(passwordSHA256)
        key = hashlib.pbkdf2_hmac('sha256', passwordbase64, self.salt, self._iter_count, 32)

        decrypted = AES.new(key, AES.MODE_CBC).decrypt(self._encrypted_wallet)
        padding = ord(decrypted[-1:])  # ISO 10126 padding length

        # A bit fragile because it assumes the guid is in the first encrypted block,
        return decrypted[:-padding] if 1 <= padding <= 16 and re.search(
            b"\"guid\"|\"sharedKey\"|\"keys\"", decrypted) else None

    def decrypt_wallet(self, password):
        # Can't decrypt or dump an extract in any meaninful way...
        if self._using_extract:
            return

        # If we aren't dumping these files, then just return...
        if not (self._dump_wallet_file or self._dump_privkeys_file):
            return

        # print(self._encrypted_wallet)
        data = self.decrypt(password)[16:]

        # Load and parse the now-decrypted wallet
        self._wallet_json = json.loads(data)

        if self._dump_wallet_file:
            self.dump_wallet()
        if self._dump_privkeys_file:
            self.dump_privkeys()

    # This just dumps the wallet json as-is (regardless of whether the keys have been decrypted
    def dump_wallet(self):
        with open(self._dump_wallet_file, 'a') as logfile:
            logfile.write(json.dumps(self._wallet_json, indent=4))

    # This just dumps the wallet private keys
    def dump_privkeys(self):
        with open(self._dump_privkeys_file, 'a') as logfile:
            logfile.write("Private Keys (For copy/paste) are below...\n")
            for key in self._wallet_json['keys']:
                try:
                    logfile.write(key['priv'] + "\n")
                except KeyError:
                    print("Error: Private Key not correctly decrypted...")

    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(0)
        try:
            walletdata = wallet_file.read()
        except: return False
        return (b"email" in walletdata and b"two_fa_method" in walletdata)  # Dogechain.info wallets have email and 2fa fields that are fairly unique

    def __init__(self, iter_count, loading=False):
        assert loading, 'use load_from_* to create a ' + self.__class__.__name__
        pbkdf2_library_name = load_pbkdf2_library().__name__
        aes_library_name = load_aes256_library().__name__
        self._iter_count = iter_count
        self._passwords_per_second = 400000 if pbkdf2_library_name == "hashlib" else 100000
        self._passwords_per_second /= iter_count
        if aes_library_name != "Crypto" and self._passwords_per_second > 2000:
            self._passwords_per_second = 2000

    def __setstate__(self, state):
        # (re-)load the required libraries after being unpickled
        load_pbkdf2_library(warnings=False)
        load_aes256_library(warnings=False)
        self.__dict__ = state

    def passwords_per_seconds(self, seconds):
        return max(int(round(self._passwords_per_second * seconds)), 1)

    # Load a Dogechain wallet file
    @classmethod
    def load_from_filename(cls, wallet_filename):
        with open(wallet_filename, "rb") as wallet_file:
                wallet_data = wallet_file.read()
        wallet_json = json.loads(wallet_data)
        self = cls(wallet_json["pbkdf2_iterations"], loading=True)
        self.salt = base64.b64decode(wallet_json["salt"])
        self._encrypted_wallet = base64.b64decode(wallet_json["payload"])
        self._encrypted_block = base64.b64decode(wallet_json["payload"])[:32]
        return self

    @classmethod
    def load_from_data_extract(cls, file_data):
        # These are the same second password hash, salt, iteration count retrieved above
        payload_data, salt, iter_count = struct.unpack(b"< 32s 16s I", file_data)
        self = cls(iter_count, loading=True)
        self.salt = salt
        self._encrypted_wallet = ""
        self._encrypted_block = payload_data
        self._using_extract = True
        return self

    def difficulty_info(self):
        return "{:,} PBKDF2-SHA256 iterations".format(self._iter_count or 10)

    def init_logfile(self):
        with open(self._possible_passwords_file, 'a') as logfile:
            logfile.write(
                "\n\n" +
                datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " New Recovery Started...\n" +
                "This file contains passwords and blocks from passwords which `may` not exactly match those that "
                "BTCRecover searches for by default. \n\n"
                "Examples of successfully decrypted blocks will not just be random characters, "
                "some examples of what correctly decryped blocks logs look like are:\n\n"
                "Possible Password ==>btcr-test-password<== in Decrypted Block ==>{\n\"guid\" : \"9bb<==\n"
                "Possible Password ==>testblockchain<== in Decrypted Block ==>{\"address_book\":<==\n"
                "Possible Password ==>btcr-test-password<== in Decrypted Block ==>{\"tx_notes\":{},\"\n"
                "Possible Password ==>Testing123!<== in Decrypted Block ==>{\"double_encrypt<==\n"
                "\n"
                "Note: The markers ==> and <== are not part of either your password or the decrypted block...\n\n"
                "If the password works and was not correctly found, or your wallet detects a false positive, please report the decrypted block data at "
                "https://github.com/3rdIteration/btcrecover/issues/\n\n")
        print("* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *")
        print("*                     Note for dogechain.info Wallets...                *")
        print("*                                                                       *")
        print("*   Writing all `possibly matched` and fully matched Passwords &        *")
        print("*   Decrypted blocks to ", self._possible_passwords_file)
        print("*   This can be disabled with the --disablesavepossiblematches argument *")
        print("* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *")
        print()

    # A bit fragile because it assumes that some specific text is in the first encrypted block,
    def check_decrypted_block(self, unencrypted_block, password):
        if unencrypted_block[0] == ord("{"):
            if b'"' in unencrypted_block[
                       :4]:  # If it really is a json wallet fragment, there will be a double quote in there within the first few characters...
                try:
                    # Try to decode the decrypted block to ascii, this will pretty much always fail on anything other
                    # than the correct password
                    unencrypted_block.decode("ascii")
                    if self._savepossiblematches:
                        with open(self._possible_passwords_file, 'a') as logfile:
                            logfile.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") +
                                          " Possible Password ==>" +
                                          password.decode("utf_8") +
                                          "<== in Decrypted Block ==>" +
                                          unencrypted_block.decode("ascii") +
                                          "<==\n")
                except UnicodeDecodeError:
                    pass

            # Return True if
            if re.search(b"\"guid\"|\"sharedKey\"|\"keys\"", unencrypted_block):
                if self._savepossiblematches:
                    try:
                        with open('possible_passwords.log', 'a') as logfile:
                            logfile.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") +
                                          " Found Password ==>" +
                                          password.decode("utf_8") +
                                          "<== in Decrypted Block ==>" +
                                          unencrypted_block.decode("ascii") +
                                          "<==\n")
                            return True  # Only return true if we can successfully decode the block in to ascii

                    except UnicodeDecodeError:  # Likely a false positive if we can't...
                        with open('possible_passwords.log', 'a') as logfile:
                            logfile.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") +
                                          " Found Likely False Positive Password (with non-Ascii characters in decrypted block) ==>" +
                                          password.decode("utf_8") +
                                          "<== in Decrypted Block ==>" +
                                          unencrypted_block.decode("utf-8", "ignore") +
                                          "<==\n")

        return False

    def return_verified_password_or_false(self, passwords):  # dogechain.info Main Password
        return self._return_verified_password_or_false_opencl(passwords) if (not isinstance(self.opencl_algo, int)) \
            else self._return_verified_password_or_false_cpu(passwords)

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def _return_verified_password_or_false_cpu(self, arg_passwords):  # dogechain.info Main Password
        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        passwords = map(lambda p: p.encode("utf_8", "ignore"), arg_passwords)

        for count, password in enumerate(passwords, 1):
            #if self.decrypt(password):
            #    return password.decode("utf_8", "replace"), count

            passwordSHA256 = hashlib.sha256(password).digest()
            passwordbase64 = base64.b64encode(passwordSHA256)
            key = hashlib.pbkdf2_hmac('sha256', passwordbase64, self.salt, self._iter_count, 32)

            decrypted_block = AES.new(key, AES.MODE_CBC).decrypt(self._encrypted_block)[16:]

            if self.check_decrypted_block(decrypted_block, password):
                    # Decrypt and dump the wallet if required
                    self.decrypt_wallet(password)
                    return password.decode("utf_8", "replace"), count

        return False, count

    def _return_verified_password_or_false_opencl(self, arg_passwords):  # dogechain.info Main Password

        # Convert Unicode strings
        passwords = map(lambda p: base64.b64encode(hashlib.sha256(p.encode("utf_8", "ignore")).digest()), arg_passwords)

        clResult = self.opencl_algo.cl_pbkdf2(self.opencl_context_pbkdf2_sha256, passwords, self.salt, self._iter_count, 32)

        # This list is consumed, so recreated it and zip
        passwords = map(lambda p: p.encode("utf_8", "ignore"), arg_passwords)

        results = zip(passwords, clResult)

        for count, (password, key) in enumerate(results, 1):
            decrypted_block = AES.new(key, AES.MODE_CBC).decrypt(self._encrypted_block)[16:]
            if self.check_decrypted_block(decrypted_block, password):
                    # Decrypt and dump the wallet if required
                    self.decrypt_wallet(password)
                    return password.decode("utf_8", "replace"), count

        return False, count

############### Metamask ###############

@register_wallet_class
class WalletMetamask(object):
    opencl_algo = -1

    _savepossiblematches = True
    _possible_passwords_file = "possible_passwords.log"

    _dump_privkeys_file = None
    _dump_wallet_file = None

    _using_extract = False

    _mobileWallet = False

    def data_extract_id():
        return "mt"

    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(0)
        try:
            walletdata = wallet_file.read().decode("utf-8","ignore").replace("\\","")
        except: return False
        return ("\"data\"" in walletdata and "\"iv\"" in walletdata and "\"salt\"" in walletdata)  or ("\"lib\":\"original\"" in walletdata) # Metamask wallets have these three keys in the json (Other supported wallet times have one or the other, but not all three), metamask mobile has a lib:original string

    def __init__(self, iter_count, loading=False):
        assert loading, 'use load_from_* to create a ' + self.__class__.__name__
        pbkdf2_library_name = load_pbkdf2_library().__name__
        aes_library_name = load_aes256_library().__name__
        global normalize
        from unicodedata import normalize
        self._iter_count = iter_count
        self._passwords_per_second = 400000 if pbkdf2_library_name == "hashlib" else 100000
        self._passwords_per_second /= iter_count
        if aes_library_name != "Crypto" and self._passwords_per_second > 2000:
            self._passwords_per_second = 2000

    def __setstate__(self, state):
        # (re-)load the required libraries after being unpickled
        load_pbkdf2_library(warnings=False)
        load_aes256_library(warnings=False)
        global normalize
        from unicodedata import normalize
        self.__dict__ = state

    def passwords_per_seconds(self, seconds):
        return max(int(round(self._passwords_per_second * seconds)), 1)

    # Load a metamask wallet file
    @classmethod
    def load_from_filename(cls, wallet_filename):
        tryLoadJSONFile = False
        try:
            leveldb_records = ccl_leveldb.RawLevelDb(wallet_filename)
            walletdata_list = []
            for record in leveldb_records.iterate_records_raw():
                # print(record)
                # For LDB files and Ronin wallet log files
                if b"vault" in record.key or b"encryptedVault" in record.key:
                    data = record.value.decode("utf-8", "ignore").replace("\\", "")
                    if "salt" in data:
                        if data in walletdata_list:
                            continue

                        wallet_data = data[1:-1]

                if b"data" in record.key:
                    data = record.value.decode("utf-8", "ignore").replace("\\", "")
                    if "salt" in data:
                        walletStartText = "vault"

                        wallet_data_start = data.lower().find(walletStartText)

                        wallet_data_trimmed = data[wallet_data_start:]

                        wallet_data_start = wallet_data_trimmed.find("data")
                        wallet_data_trimmed = wallet_data_trimmed[wallet_data_start - 2:]

                        wallet_data_end = wallet_data_trimmed.find("}")
                        wallet_data = wallet_data_trimmed[:wallet_data_end + 1]

        except ValueError:
            tryLoadJSONFile = True

        except NameError:
            print("\n********************************************************************************")
            print("WARNING: Unable to load LevelDB module, likely due to it needing Python 3.8+")
            print("********************************************************************************\n")

            tryLoadJSONFile = True


        if tryLoadJSONFile:
            # Try loading the wallet as a JSON file (If it has been copy/pasted from a browser)
            with open(wallet_filename, "rb") as wallet_file:
                wallet_data = wallet_file.read().decode("utf-8","ignore").replace("\\","")

        try:
            wallet_json = json.loads(wallet_data)

        # The JSON data might be from a Metamask mobile wallet
        except json.decoder.JSONDecodeError:
            walletStartText = "vault"
            wallet_data_start = wallet_data.lower().find(walletStartText)
            wallet_data_trimmed = wallet_data[wallet_data_start:]
            wallet_data_start = wallet_data_trimmed.find("cipher")
            wallet_data_trimmed = wallet_data_trimmed[wallet_data_start - 2:]
            wallet_data_end = wallet_data_trimmed.find("}")
            wallet_data = wallet_data_trimmed[:wallet_data_end + 1]
            wallet_json = json.loads(wallet_data)

        if "\"lib\":\"original\"" in wallet_data:
            self = cls(5000, loading=True)
            self.salt = wallet_json["salt"].encode()
            self.encrypted_vault = base64.b64decode(wallet_json["cipher"])
            self.encrypted_block = base64.b64decode(wallet_json["cipher"])[:16]
            self.iv = binascii.unhexlify(wallet_json["iv"])
            self._mobileWallet = True
        else:
            self = cls(10000, loading=True)
            self.salt = base64.b64decode(wallet_json["salt"])
            self.encrypted_vault = base64.b64decode(wallet_json["data"])
            self.encrypted_block = base64.b64decode(wallet_json["data"])[:16]
            self.iv = base64.b64decode(wallet_json["iv"])
        return self

    # Import extracted Metamask vault data necessary for password checking
    @classmethod
    def load_from_data_extract(cls, file_data):
        # These are the same first encrypted block, iv and salt count retrieved above
        encrypted_block, iv, salt, isMobileWallet = struct.unpack(b"< 16s 16s 32s 1?", file_data)
        if isMobileWallet:
            self = cls(5000, loading=True)
            self.salt = salt[:-8]
        else:
            self = cls(10000, loading=True)
            self.salt = salt
        self.encrypted_block = encrypted_block
        self.iv = iv
        self._mobileWallet = isMobileWallet
        self.encrypted_vault = ""
        self._using_extract   = True
        return self

    def difficulty_info(self):
        if not self._mobileWallet:
            return "10,000 PBKDF2-SHA256 iterations"
        else:
            return "5,000 PBKDF2-SHA512 iterations"

    def init_logfile(self):
        with open(self._possible_passwords_file, 'a') as logfile:
            logfile.write(
        "\n\n" +
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " New Recovery Started...\n" +
        "This file contains passwords and blocks from passwords which `may` not exactly match those that "
        "BTCRecover searches for by default. \n\n"
        "Examples of successfully decrypted blocks will not just be random characters, "
        "some examples of what correctly decryped blocks logs look like are:\n\n"
        "Possible Password ==>btcr-test-password<== in Decrypted Block ==>[{\"type\":\"HD Key<==\n"
        "Possible Password ==>btcr-test-password<== in Decrypted Block ==>\"{\\\"mnemonic\\\":\<==\n"
        "Possible Password ==>BTCR-test-passw0rd<== in Decrypted Block ==>{\"version\":\"v2\",<==\n"
        "Note: The markers ==> and <== are not part of either your password or the decrypted block...\n\n"
        "If the password works and was not correctly found, or your wallet detects a false positive, please report the decrypted block data at "
        "https://github.com/3rdIteration/btcrecover/issues/\n\n")
        print("* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *")
        print("*               Note for Metamask (And related) Wallets...              *")
        print("*                                                                       *")
        print("*   Writing all `possibly matched` and fully matched Passwords &        *")
        print("*   Decrypted blocks to ", self._possible_passwords_file)
        print("*   This can be disabled with the --disablesavepossiblematches argument *")
        print("* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *")
        print()

    # A bit fragile because it assumes that some specific text is in the first encrypted block,
    def check_decrypted_block(self, unencrypted_block, password):
        if unencrypted_block[0] == ord("{") or unencrypted_block[0] == ord("[") or unencrypted_block[0] == ord('"'):
            if b'"' in unencrypted_block[:4]:  # If it really is a json wallet fragment, there will be a double quote in there within the first few characters...
                try:
                    # Try to decode the decrypted block to ascii, this will pretty much always fail on anything other
                    # than the correct password
                    unencrypted_block.decode("ascii")
                    if self._savepossiblematches:
                        with open(self._possible_passwords_file, 'a') as logfile:
                            logfile.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") +
                                          " Possible Password ==>" +
                                          password.decode("utf_8") +
                                          "<== in Decrypted Block ==>" +
                                          unencrypted_block.decode("ascii") +
                                          "<==\n")
                except UnicodeDecodeError:
                    pass

            # Return True if
            if re.search(b"\"type\"|version|mnemonic", unencrypted_block):
                if self._savepossiblematches:
                    try:
                        with open('possible_passwords.log', 'a') as logfile:
                            logfile.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") +
                                          " Found Password ==>" +
                                          password.decode("utf_8") +
                                          "<== in Decrypted Block ==>" +
                                          unencrypted_block.decode("ascii") +
                                          "<==\n")
                            return True  # Only return true if we can successfully decode the block in to ascii

                    except UnicodeDecodeError:  # Likely a false positive if we can't...
                        with open('possible_passwords.log', 'a') as logfile:
                            logfile.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") +
                                          " Found Likely False Positive Password (with non-Ascii characters in decrypted block) ==>" +
                                          password.decode("utf_8") +
                                          "<== in Decrypted Block ==>" +
                                          unencrypted_block.decode("utf-8", "ignore") +
                                          "<==\n")

        return False

    def dump_wallet(self,key):
        # If the dump wallet argument was used, just copy that path to dump-privkeys
        if self._dump_wallet_file:
            self._dump_privkeys_file = self._dump_wallet_file

        if self._dump_privkeys_file and not self._using_extract:
            # Decrypt vault
            if not self._mobileWallet:
                decrypted_vault = AES.new(key, AES.MODE_GCM, nonce=self.iv).decrypt(self.encrypted_vault).decode("utf-8", "ignore")
            else:
                decrypted_vault = AES.new(key, AES.MODE_CBC, self.iv).decrypt(self.encrypted_vault).decode("utf-8", "ignore")

            # Parse to JSON
            decoder = json.JSONDecoder()
            decrypted_vault_json, extrachars = decoder.raw_decode(decrypted_vault)

            try:
                # Convert ascii list to string (Needed for some environments)
                mnemonic = decrypted_vault_json[0]['data']['mnemonic']
                mnemonic = ''.join(map(chr, mnemonic))
                decrypted_vault_json[0]['data']['mnemonic'] = mnemonic
            except TypeError:
                pass # The conversion will fail if mnemonic is stored as a normal string
            except KeyError:
                pass  # The conversion will fail if there are extra items in the wallet and it's a normal string (like with Binance Chain wallet)

            #Dump to file
            with open(self._dump_privkeys_file, 'a') as logfile:
                logfile.write(json.dumps(decrypted_vault_json))

    def return_verified_password_or_false(self, passwords):  # Metamask
        return self._return_verified_password_or_false_opencl(passwords) if (not isinstance(self.opencl_algo, int)) \
            else self._return_verified_password_or_false_cpu(passwords)

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def _return_verified_password_or_false_cpu(self, arg_passwords):  # Metamask
        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        passwords = map(lambda p: p.encode("utf_8", "ignore"), arg_passwords)

        for count, password in enumerate(passwords, 1):
            if not self._mobileWallet:
                key = hashlib.pbkdf2_hmac('sha256', password, self.salt, self._iter_count, 32)
                decrypted_block = AES.new(key, AES.MODE_GCM, nonce=self.iv).decrypt(self.encrypted_block)
            else:
                key = hashlib.pbkdf2_hmac('sha512', password, self.salt, self._iter_count, 32)
                decrypted_block = AES.new(key, AES.MODE_CBC, self.iv).decrypt(self.encrypted_block)


            if self.check_decrypted_block(decrypted_block, password):
                # This just dumps the wallet private keys (if required)
                self.dump_wallet(key)

                return password.decode("utf_8", "replace"), count

        return False, count

    def _return_verified_password_or_false_opencl(self, arg_passwords):
        # Convert Unicode strings (lazily) to normalized UTF-8 bytestrings
        passwords = map(lambda p: normalize("NFKD", p).encode("utf_8", "ignore"), arg_passwords)

        if not self._mobileWallet:
            clResult = self.opencl_algo.cl_pbkdf2(self.opencl_context_pbkdf2_sha256, passwords, self.salt, self._iter_count, 32)
        else:
            clResult = self.opencl_algo.cl_pbkdf2(self.opencl_context_pbkdf2_sha512, passwords, self.salt, self._iter_count, 32)

        # This list is consumed, so recreated it and zip
        passwords = map(lambda p: normalize("NFKD", p).encode("utf_8", "ignore"), arg_passwords)

        results = zip(passwords, clResult)

        for count, (password, result) in enumerate(results, 1):
            if not self._mobileWallet:
                decrypted_block = AES.new(result, AES.MODE_GCM, nonce=self.iv).decrypt(self.encrypted_block)
            else:
                decrypted_block = AES.new(result, AES.MODE_CBC, self.iv).decrypt(self.encrypted_block)

            if self.check_decrypted_block(decrypted_block, password):
                # This just dumps the wallet private keys
                self.dump_wallet(result)

                return password.decode("utf_8", "replace"), count

        return False, count

############### Bither ###############

@register_wallet_class
class WalletBither(object):
    opencl_algo = -1

    def data_extract_id():
        return "bt"

    def passwords_per_seconds(self, seconds):
        return max(int(round(self._passwords_per_second * seconds)), 1)

    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(0)
        wallet_header = wallet_file.read(16)
        # returns "maybe yes" or "definitely no" (mSIGNA wallets are also SQLite 3)
        if wallet_header[0:-1] == b'SQLite format 3' and wallet_header[-1] == 0:
            return None
        else:
            return False

    def __init__(self, loading = False):
        if not hashlib_ripemd160_available:
            print("Warning: Native RIPEMD160 not available via Hashlib, using Pure-Python (This will significantly reduce performance)")

        assert loading, 'use load_from_* to create a ' + self.__class__.__name__
        # loading crypto libraries is done in load_from_*

    def __setstate__(self, state):
        # (re-)load the required libraries after being unpickled
        global pylibscrypt, coincurve
        from lib import pylibscrypt

        try:
            import coincurve
        except ModuleNotFoundError:
            exit(
                "\nERROR: Cannot load coincurve module... Be sure to install all requirements with the command 'pip3 install -r requirements.txt', see https://btcrecover.readthedocs.io/en/latest/INSTALL/")

        load_aes256_library(warnings=False)
        self.__dict__ = state

    # Load a Bither wallet file (the part of it we need)
    @classmethod
    def load_from_filename(cls, wallet_filename):
        import sqlite3
        wallet_conn = sqlite3.connect(wallet_filename)

        is_bitcoinj_compatible  = None
        # Try to find an encrypted loose key first; they're faster to check
        try:
            wallet_cur = wallet_conn.execute("SELECT encrypt_private_key FROM addresses LIMIT 1")
            key_data   = wallet_cur.fetchone()
            if key_data:
                key_data = key_data[0]
                is_bitcoinj_compatible = True  # if found, the KDF & encryption are bitcoinj compatible
            else:
                e1 = "no encrypted keys present in addresses table"
        except sqlite3.OperationalError as e1:
            if str(e1).startswith("no such table"):
                key_data = None
            else: raise  # unexpected error

        if not key_data:
            # Newer wallets w/o loose keys have a password_seed table with a single row
            try:
                wallet_cur = wallet_conn.execute("SELECT password_seed FROM password_seed LIMIT 1")
                key_data   = wallet_cur.fetchone()
            except sqlite3.OperationalError as e2:
                raise ValueError("Not a Bither wallet: {}, {}".format(e1, e2))  # it might be an mSIGNA wallet
            if not key_data:
                error_exit("can't find an encrypted key or password seed in the Bither wallet")
            key_data = key_data[0]

        # Create a bitcoinj wallet (which loads required libraries); we may or may not actually use it
        bitcoinj_wallet = WalletBitcoinj(loading=True)

        # key_data is forward-slash delimited; it contains an optional pubkey hash, an encrypted key, an IV, a salt
        key_data = key_data.split("/")
        if len(key_data) == 1:
            key_data = key_data.split(":")  # old Bither wallets used ":" as the delimiter
        pubkey_hash = key_data.pop(0) if len(key_data) == 4 else None
        if len(key_data) != 3:
            error_exit("unrecognized Bither encrypted key format (expected 3-4 slash-delimited elements, found {})"
                       .format(len(key_data)))
        (encrypted_key, iv, salt) = key_data
        encrypted_key = base64.b16decode(encrypted_key, casefold=True)

        # The first salt byte is optionally a flags byte
        salt = base64.b16decode(salt, casefold=True)
        if len(salt) == 9:
            flags = ord(salt[0])
            salt  = salt[1:]
        else:
            flags = 1  # this is the is_compressed flag; if not present it defaults to compressed
            if len(salt) != 8:
                error_exit("unexpected salt length ({}) in Bither wallet".format(len(salt)))

        # Return a WalletBitcoinj object to do the work if it's compatible with one (it's faster)
        if is_bitcoinj_compatible:
            if len(encrypted_key) != 48:
                error_exit("unexpected encrypted key length in Bither wallet (expected 48, found {})"
                           .format(len(encrypted_key)))
            # only need the last 2 encrypted blocks (half of which is padding) plus the salt (don't need the iv)
            bitcoinj_wallet._part_encrypted_key = encrypted_key[-32:]
            bitcoinj_wallet._scrypt_salt = salt
            bitcoinj_wallet._scrypt_n    = 16384  # Bither hardcodes the rest
            bitcoinj_wallet._scrypt_r    = 8
            bitcoinj_wallet._scrypt_p    = 1
            return bitcoinj_wallet

        # Constuct and return a WalletBither object
        else:
            if not pubkey_hash:
                error_exit("pubkey hash160 not present in Bither password_seed")
            global coincurve

            try:
                import coincurve
            except ModuleNotFoundError:
                exit(
                    "\nERROR: Cannot load coincurve module... Be sure to install all requirements with the command 'pip3 install -r requirements.txt', see https://btcrecover.readthedocs.io/en/latest/INSTALL/")

            self = cls(loading=True)
            self._passwords_per_second = bitcoinj_wallet._passwords_per_second  # they're the same
            self._iv_encrypted_key     = base64.b16decode(iv, casefold=True) + encrypted_key
            self._salt                 = salt  # already hex decoded
            self._pubkey_hash160       = base64.b16decode(pubkey_hash, casefold=True)[1:]  # strip the bitcoin version byte
            self._is_compressed        = bool(flags & 1)  # 1 is the is_compressed flag
            return self

    # Import a Bither private key that was extracted by extract-bither-privkey.py
    @classmethod
    def load_from_data_extract(cls, privkey_data):
        assert len(privkey_data) == 40, "extract-bither-privkey.py only extracts keys from bitcoinj compatible wallets"
        bitcoinj_wallet = WalletBitcoinj(loading=True)
        # The final 2 encrypted blocks
        bitcoinj_wallet._part_encrypted_key = privkey_data[:32]
        # The 8-byte salt and hardcoded scrypt parameters
        bitcoinj_wallet._scrypt_salt = privkey_data[32:]
        bitcoinj_wallet._scrypt_n    = 16384
        bitcoinj_wallet._scrypt_r    = 8
        bitcoinj_wallet._scrypt_p    = 1
        return bitcoinj_wallet

    def difficulty_info(self):
        return "scrypt N, r, p = 16384, 8, 1 + ECC"

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def return_verified_password_or_false(self, passwords): # Bither
        # Copy a few globals into local for a small speed boost
        l_scrypt             = pylibscrypt.scrypt
        l_aes256_cbc_decrypt = aes256_cbc_decrypt
        l_sha256             = hashlib.sha256
        hashlib_new          = hashlib.new
        iv_encrypted_key     = self._iv_encrypted_key  # 16-byte iv + encrypted_key
        salt                 = self._salt
        pubkey_from_secret   = coincurve.PublicKey.from_valid_secret
        cutils               = coincurve.utils

        # Convert strings (lazily) to UTF-16BE bytestrings
        passwords = map(lambda p: p.encode("utf_16_be", "ignore"), passwords)

        for count, password in enumerate(passwords, 1):
            derived_aeskey = l_scrypt(password, salt, 16384, 8, 1, 32)  # scrypt params are hardcoded except the salt

            # Decrypt and check if the last 16-byte block of iv_encrypted_key is valid PKCS7 padding
            privkey_end = l_aes256_cbc_decrypt(derived_aeskey, iv_encrypted_key[-32:-16], iv_encrypted_key[-16:])
            padding_len = privkey_end[-1]
            if not (1 <= padding_len <= 16 and privkey_end.endswith((chr(padding_len) * padding_len).encode())):
                continue
            privkey_end = privkey_end[:-padding_len]  # trim the padding

            # Decrypt the rest of the encrypted_key, derive its pubkey, and compare it to what's expected
            privkey = l_aes256_cbc_decrypt(derived_aeskey, iv_encrypted_key[:16], iv_encrypted_key[16:-16]) + privkey_end
            # privkey can be any size, but libsecp256k1 expects a 256-bit key < the group's order:
            privkey = cutils.int_to_bytes_padded( cutils.bytes_to_int(privkey) % cutils.GROUP_ORDER_INT )
            pubkey  = pubkey_from_secret(privkey).format(self._is_compressed)
            # Compute the hash160 of the public key, and check for a match
            if ripemd160(l_sha256(pubkey).digest()) == self._pubkey_hash160:
                password = password.decode("utf_16_be", "replace")
                return password, count

        return False, count


############### BIP-38 ###############

def public_key_to_address(pubkey, network_prefix):
    ripemd160 = hash160(pubkey)
    #print("Prefix:", network_prefix)
    address = base58.b58encode_check(network_prefix + ripemd160)
    #print("Address:", address)
    return address

def compress(pub):
    x = pub[1:33]
    y = pub[33:]
    if int.from_bytes(y, byteorder='big') % 2:
        prefix = bytes([0x03])
    else:
        prefix = bytes([0x02])
    return prefix + x

def private_key_to_public_key(s):
    sk = ecdsa.SigningKey.from_string(s, curve=ecdsa.SECP256k1)
    return (bytes([0x04]) + sk.verifying_key.to_string())

def bip38decrypt_ec(prefactor, encseedb, encpriv, has_compression_flag, has_lotsequence_flag, outputlotsequence=False, network_prefix='00'):
    owner_entropy = encpriv[4:12]
    enchalf1half1 = encpriv[12:20]
    enchalf2 = encpriv[20:]
    if has_lotsequence_flag:
        lotsequence = owner_entropy[4:]
    else:
        lotsequence = False
    if lotsequence is False:
        passfactor = prefactor
    else:
        passfactor = double_sha256(prefactor + owner_entropy)
    passfactor_int = int.from_bytes(passfactor, byteorder='big')
    if passfactor_int == 0 or passfactor_int >= secp256k1_n:
        if outputlotsequence:
            return False, False, False
        else:
            return False
    key = encseedb[32:]
    aes = AESModeOfOperationECB(key)
    tmp = aes.decrypt(enchalf2)
    enchalf1half2_seedblastthird = int.from_bytes(tmp, byteorder='big') ^ int.from_bytes(encseedb[16:32], byteorder='big')
    enchalf1half2_seedblastthird = enchalf1half2_seedblastthird.to_bytes(16, byteorder='big')
    enchalf1half2 = enchalf1half2_seedblastthird[:8]
    enchalf1 = enchalf1half1 + enchalf1half2
    seedb = aes.decrypt(enchalf1)
    seedb = int.from_bytes(seedb, byteorder='big') ^ int.from_bytes(encseedb[:16], byteorder='big')
    seedb = seedb.to_bytes(16, byteorder='big') + enchalf1half2_seedblastthird[8:]
    assert len(seedb) == 24
    try:
        factorb = double_sha256(seedb)
        factorb_int = int.from_bytes(factorb, byteorder='big')
        assert factorb_int != 0
        assert not factorb_int >= secp256k1_n
    except:
        if outputlotsequence:
            return False, False, False
        else:
            return False
    priv = ((passfactor_int * factorb_int) % secp256k1_n).to_bytes(32, byteorder='big')
    pub = private_key_to_public_key(priv)
    if has_compression_flag:
        privcompress = bytes([0x1])
        pub = compress(pub)
    else:
        privcompress = bytes([])
    address = public_key_to_address(pub, network_prefix)
    addrhex = bytearray(address, 'ascii')
    addresshash = double_sha256(addrhex)[:4]
    if addresshash == encpriv[0:4]:
        priv = base58.b58encode_check(bytes([0x80]) + priv + privcompress)
        if outputlotsequence:
            if lotsequence is not False:
                lotsequence = int(lotsequence, 16)
                sequence = lotsequence % 4096
                lot = (lotsequence - sequence) // 4096
                return priv, lot, sequence
            else:
                return priv, False, False
        else:
            return priv
    else:
        if outputlotsequence:
            return False, False, False
        else:
            return False

def bip38decrypt_non_ec(scrypthash, encpriv, has_compression_flag, has_lotsequence_flag, outputlotsequence=False, network_prefix='00'):
    msg1 = encpriv[4:20]
    msg2 = encpriv[20:36]
    key = scrypthash[32:]
    aes = AESModeOfOperationECB(key)
    msg1 = aes.decrypt(msg1)
    msg2 = aes.decrypt(msg2)
    half1 = int.from_bytes(msg1, byteorder='big') ^ int.from_bytes(scrypthash[:16], byteorder='big')
    half2 = int.from_bytes(msg2, byteorder='big') ^ int.from_bytes(scrypthash[16:32], byteorder='big')
    priv = half1.to_bytes(16, byteorder='big') + half2.to_bytes(16, byteorder='big')
    priv_int = int.from_bytes(priv, byteorder='big')
    if priv_int == 0 or priv_int >= secp256k1_n:
        if outputlotsequence:
            return False, False, False
        else:
            return False
    pub = private_key_to_public_key(priv)
    if has_compression_flag:
        privcompress = bytes([0x1])
        pub = compress(pub)
    else:
        privcompress = bytes([])
    address = public_key_to_address(pub, network_prefix)
    addrhex = bytearray(address, 'ascii')
    addresshash = double_sha256(addrhex)[:4]
    if addresshash == encpriv[0:4]:
        priv = base58.b58encode_check(bytes([0x80]) + priv + privcompress)
        if outputlotsequence:
            return priv, False, False
        else:
            return priv
    else:
        if outputlotsequence:
            return False, False, False
        else:
            return False

def prefactor_to_passpoint(prefactor, has_lotsequence_flag, encpriv):
    owner_entropy = encpriv[4:12]
    if has_lotsequence_flag:
        passfactor = double_sha256(prefactor + owner_entropy)
    else:
        passfactor = prefactor
    passpoint = compress(private_key_to_public_key(passfactor))
    return passpoint

# @register_wallet_class - not a "registered" wallet since there are no wallet files nor extracts
class WalletBIP38(object):
    opencl_algo = -1

    def __init__(self, enc_privkey, bip38_network = 'bitcoin'):
        global pylibscrypt, ecdsa, double_sha256, hash160, normalize, base58, AESModeOfOperationECB, secp256k1_n
        from lib import pylibscrypt
        from lib.bitcoinlib.config.secp256k1 import secp256k1_n
        from lib.bitcoinlib.encoding import double_sha256, hash160
        from lib.bitcoinlib import networks
        from unicodedata import normalize
        from lib.cashaddress import base58
        from lib.pyaes import AESModeOfOperationECB

        try:
            import ecdsa
        except ModuleNotFoundError:
            exit(
                "\nERROR: Cannot load ecdsa module which is required for BIP38 wallets... You can install it with the command 'pip3 install ecdsa")


        self.enc_privkey = base58.b58decode_check(enc_privkey)
        assert len(self.enc_privkey) == 39

        self.network = networks.Network(bip38_network)

        prefix = int.from_bytes(self.enc_privkey[:2], byteorder='big')
        assert prefix == 0x0142 or prefix == 0x0143
        self.ec_multiplied = prefix == 0x0143

        COMPRESSION_FLAGBYTES = [0x20, 0x24, 0x28, 0x2c, 0x30, 0x34, 0x38, 0x3c, 0xe0, 0xe8, 0xf0, 0xf8]
        LOTSEQUENCE_FLAGBYTES = [0x04, 0x0c, 0x14, 0x1c, 0x24, 0x2c, 0x34, 0x3c]
        flagbyte = int.from_bytes(self.enc_privkey[2:3], byteorder='big')
        self.has_compression_flag = flagbyte in COMPRESSION_FLAGBYTES
        self.has_lotsequence_flag = flagbyte in LOTSEQUENCE_FLAGBYTES

        self.enc_privkey = self.enc_privkey[3:]

        if not self.ec_multiplied:
            self.salt = self.enc_privkey[0:4]
        else:
            owner_entropy = self.enc_privkey[4:12]
            self.salt = owner_entropy[:4] if self.has_lotsequence_flag else owner_entropy

    def __setstate__(self, state):
        # (re-)load the required libraries after being unpickled
        global pylibscrypt, ecdsa, double_sha256, hash160, normalize, base58, AESModeOfOperationECB, secp256k1_n
        from lib import pylibscrypt
        from lib.bitcoinlib.config.secp256k1 import secp256k1_n
        from lib.bitcoinlib.encoding import double_sha256, hash160
        from lib.bitcoinlib import networks
        from unicodedata import normalize
        from lib.cashaddress import base58
        from lib.pyaes import AESModeOfOperationECB

        try:
            import ecdsa
        except ModuleNotFoundError:
            exit(
                "\nERROR: Cannot load ecdsa module... Be sure to install all requirements with the command 'pip3 install -r requirements.txt', see https://btcrecover.readthedocs.io/en/latest/INSTALL/")


        self.__dict__ = state

    def passwords_per_seconds(self, seconds):
        return max(int(round(10 * seconds)), 1)

    def difficulty_info(self):
        return "sCrypt N=14, r=8, p=8"

    def return_verified_password_or_false(self, passwords): # BIP38 Encrypted Private Keys
        return self._return_verified_password_or_false_opencl(passwords) if (not isinstance(self.opencl_algo,int)) \
          else self._return_verified_password_or_false_cpu(passwords)

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def _return_verified_password_or_false_opencl(self, arg_passwords): # BIP38 Encrypted Private Keys
        l_scrypt = pylibscrypt.scrypt

        passwords = map(lambda p: normalize("NFC", p).encode("utf_8", "ignore"), arg_passwords)

        if not self.ec_multiplied:
            clResult = self.opencl_algo.cl_scrypt(self.opencl_context_scrypt, passwords, 14, 3, 3, 64, self.salt)
            passwords = map(lambda p: normalize("NFC", p).encode("utf_8", "ignore"), arg_passwords)
            results = zip(passwords, clResult)
            for count, (password, scrypthash) in enumerate(results, 1):
                if bip38decrypt_non_ec(scrypthash, self.enc_privkey, self.has_compression_flag, self.has_lotsequence_flag, network_prefix = self.network.prefix_address):
                    return password.decode("utf_8", "replace"), count
        else:
            clPrefactors = self.opencl_algo.cl_scrypt(self.opencl_context_scrypt, passwords, 14, 3, 3, 32, self.salt)
            passpoints = map(lambda p: prefactor_to_passpoint(p, self.has_lotsequence_flag, self.enc_privkey), clPrefactors)
            encseedbs = map(lambda p: l_scrypt(p, self.enc_privkey[0:12], 1024, 1, 1, 64), passpoints)
            passwords = map(lambda p: normalize("NFC", p).encode("utf_8", "ignore"), arg_passwords)
            results = zip(passwords, clPrefactors, encseedbs)
            for count, (password, prefactor, encseedb) in enumerate(results, 1):
                if bip38decrypt_ec(prefactor, encseedb, self.enc_privkey, self.has_compression_flag, self.has_lotsequence_flag, network_prefix = self.network.prefix_address):
                    return password.decode("utf_8", "replace"), count

        return False, count

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def _return_verified_password_or_false_cpu(self, passwords): # BIP38 Encrypted Private Keys
        l_scrypt = pylibscrypt.scrypt

        passwords = map(lambda p: normalize("NFC", p).encode("utf_8", "ignore"), passwords)
        for count, password in enumerate(passwords, 1):
            if not self.ec_multiplied:
                scrypthash = l_scrypt(password, self.salt, 1 << 14, 8, 8, 64)
                if bip38decrypt_non_ec(scrypthash, self.enc_privkey, self.has_compression_flag, self.has_lotsequence_flag, network_prefix = self.network.prefix_address):
                    return password.decode("utf_8", "replace"), count
            else:
                prefactor = l_scrypt(password, self.salt, 1 << 14, 8, 8, 32)
                passpoint = prefactor_to_passpoint(prefactor, self.has_lotsequence_flag, self.enc_privkey)
                encseedb = l_scrypt(passpoint, self.enc_privkey[0:12], 1024, 1, 1, 64)

                if bip38decrypt_ec(prefactor, encseedb, self.enc_privkey, self.has_compression_flag, self.has_lotsequence_flag, network_prefix = self.network.prefix_address):
                    return password.decode("utf_8", "replace"), count

        return False, count


############### BIP-39 ###############

# @register_wallet_class - not a "registered" wallet since there are no wallet files nor extracts
class WalletBIP39(object):
    opencl_algo = -1

    def __init__(self, mpk = None, addresses = None, address_limit = None, addressdb_filename = None,
                 mnemonic = None, lang = None, path = None, wallet_type = "bip39", is_performance = False, force_p2sh = False, checksinglexpubaddress = False):
        from . import btcrseed

        wallet_type = wallet_type.lower()

        wallet_type_names = []
        for cls, desc in btcrseed.selectable_wallet_classes:
            wallet_type_name = cls.__name__.replace("Wallet", "", 1).lower()
            if wallet_type_name == "electrum1": # Don't include Electrum 1 seeds in the list of options for passphrase recovery
                continue
            else:
                wallet_type_names.append(cls.__name__.replace("Wallet", "", 1).lower())
            if wallet_type_names[-1] == wallet_type:
                btcrseed_cls = cls
                if wallet_type_name == "electrum2": # Need to spell out that "extra words" are required and let the btcrseed class know... (This removes ambiguity around the seed length)
                    btcrseed_cls._passphrase_recovery = True
                break
        else:
            wallet_type_names.sort()
            sys.exit("--wallet-type must be one of: " + ", ".join(wallet_type_names))

        global disable_security_warnings
        btcrseed_cls.set_securityWarningsFlag(disable_security_warnings)
        global normalize, hmac
        from unicodedata import normalize
        import hmac
        load_pbkdf2_library()

        # Create a btcrseed.WalletBIP39 object which will do most of the work;
        # this also interactively prompts the user if not enough command-line options were included
        if addressdb_filename:
            from .addressset import AddressSet
            print("Loading address database ...")
            hash160s = AddressSet.fromfile(open(addressdb_filename, "rb"))
        else:
            hash160s = None

        self.btcrseed_wallet = btcrseed_cls.create_from_params(
            mpk, addresses, address_limit, hash160s, path, is_performance, force_p2sh = force_p2sh, checksinglexpubaddress = checksinglexpubaddress)

        if is_performance and not mnemonic:
            mnemonic = "certain come keen collect slab gauge photo inside mechanic deny leader drop"
        self.btcrseed_wallet.config_mnemonic(mnemonic, lang)

        # Verify that the entered mnemonic is valid
        if not self.btcrseed_wallet.verify_mnemonic_syntax(btcrseed.mnemonic_ids_guess):
            error_exit("one or more words are missing from the mnemonic")
        if not self.btcrseed_wallet._verify_checksum(btcrseed.mnemonic_ids_guess):
            error_exit("invalid mnemonic (the checksum is wrong)")
        # We just verified the mnemonic checksum is valid, so 100% of the guesses will also be valid:
        self.btcrseed_wallet._checksum_ratio = 1

        self._mnemonic = " ".join(btcrseed.mnemonic_ids_guess)

    def __setstate__(self, state):
        # (re-)load the required libraries after being unpickled
        global normalize, hmac
        from unicodedata import normalize
        import hmac
        load_pbkdf2_library(warnings=False)
        self.__dict__ = state

    def passwords_per_seconds(self, seconds):
        return self.btcrseed_wallet.passwords_per_seconds(seconds)

    def difficulty_info(self):
        return "2048 PBKDF2-SHA512 iterations + ECC"

    def return_verified_password_or_false(self, mnemonic_ids_list): # BIP39-Passphrase
        return self._return_verified_password_or_false_opencl(mnemonic_ids_list) if (self.opencl and not isinstance(self.opencl_algo,int)) \
          else self._return_verified_password_or_false_cpu(mnemonic_ids_list)

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def _return_verified_password_or_false_cpu(self, passwords):
        # Convert Unicode strings (lazily) to normalized UTF-8 bytestrings
        passwords = map(lambda p: normalize("NFKD", p).encode("utf_8", "ignore"), passwords)

        for count, password in enumerate(passwords, 1):
            if type(self.btcrseed_wallet) is btcrecover.btcrseed.WalletElectrum2:
                derivation_salt = b"electrum" + password
            else:
                derivation_salt = b"mnemonic" + password

            seed_bytes = pbkdf2_hmac("sha512", self._mnemonic.encode(), derivation_salt, 2048)

            seed_bytes = hmac.new(b"Bitcoin seed", seed_bytes, hashlib.sha512).digest()
            if self.btcrseed_wallet._verify_seed(seed_bytes):
                return password.decode("utf_8", "replace"), count

        return False, count

    def _return_verified_password_or_false_opencl(self, arg_passwords):
        # Convert Unicode strings (lazily) to normalized UTF-8 bytestrings
        passwords = map(lambda p: normalize("NFKD", p).encode("utf_8", "ignore"), arg_passwords)

        salt_list = []
        for password in passwords:
            if type(self.btcrseed_wallet) is btcrecover.btcrseed.WalletElectrum2:
                salt_list.append(b"electrum" + password)
            else:
                salt_list.append(b"mnemonic" + password)

        clResult = self.opencl_algo.cl_pbkdf2_saltlist(self.opencl_context_pbkdf2_sha512, self._mnemonic.encode(), salt_list, 2048, 64)

        #Placeholder until OpenCL kernel can be patched to support this...
        #clResult = []
        #for salt in salt_list:
        #    clResult.append(pbkdf2_hmac("sha512", self._mnemonic.encode(), salt, 2048))

        # This list is consumed, so recreated it and zip
        passwords = map(lambda p: normalize("NFKD", p).encode("utf_8", "ignore"), arg_passwords)

        results = zip(passwords, clResult)

        for count, (password, result) in enumerate(results, 1):
            seed_bytes = hmac.new(b"Bitcoin seed", result, hashlib.sha512).digest()
            if self.btcrseed_wallet._verify_seed(seed_bytes):
                return password.decode("utf_8", "replace"), count

        return False, count

############### SLIP-39 ###############

# @register_wallet_class - not a "registered" wallet since there are no wallet files nor extracts
class WalletSLIP39(object):
    opencl_algo = -1

    def __init__(self, mpk = None, addresses = None, address_limit = None, addressdb_filename = None,
                 slip39_shares = None, lang = None, path = None, wallet_type = "bip39", is_performance = False):

        if not shamir_mnemonic_available:
            print()
            print("ERROR: Cannot import shamir-mnemonic which is required for SLIP39 wallets, install it via 'pip3 install shamir-mnemonic'")
            exit()

        from . import btcrseed

        wallet_type = wallet_type.lower()

        wallet_type_names = []
        for cls, desc in btcrseed.selectable_wallet_classes:
            wallet_type_name = cls.__name__.replace("Wallet", "", 1).lower()
            if wallet_type_name not in ["ethereum", "bip39", "litecoin", "dogecoin", "bch", "dash", "ripple", "digibyte", "vertcoin"]: # SLIP39 implementation only supports common coins for now (Covers most of Trezor T)
                continue
            else:
                wallet_type_names.append(cls.__name__.replace("Wallet", "", 1).lower())
            if wallet_type_names[-1] == wallet_type:
                btcrseed_cls = cls
                break
        else:
            wallet_type_names.sort()
            sys.exit("For SLIP39, --wallet-type must be one of: " + ", ".join(wallet_type_names))

        global disable_security_warnings
        btcrseed_cls.set_securityWarningsFlag(disable_security_warnings)
        global normalize, hmac
        from unicodedata import normalize
        import hmac
        load_pbkdf2_library()

        # Create a btcrseed.WalletBIP39 object which will do most of the work;
        # this also interactively prompts the user if not enough command-line options were included
        if addressdb_filename:
            from .addressset import AddressSet
            print("Loading address database ...")
            hash160s = AddressSet.fromfile(open(addressdb_filename, "rb"))
        else:
            hash160s = None

        self.btcrseed_wallet = btcrseed_cls.create_from_params(
            mpk, addresses, address_limit, hash160s, path, is_performance)

        self.btcrseed_wallet._derivation_salts = [""]

        if is_performance and not slip39_shares:
            slip39_shares = ["duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard"]

        print("\nLoading SLIP39 Shares")

        # Gather the SLIP39 Shares
        # Implementation is a lightly modified version of the recover function from cli.py in the shamir-mnemonic repository
        # https://github.com/trezor/python-shamir-mnemonic/blob/master/shamir_mnemonic/cli.py
        # Licence in the Licences folder...

        recovery_state = shamir_mnemonic.recovery.RecoveryState()

        def print_group_status(idx: int) -> None:
            group_size, group_threshold = recovery_state.group_status(idx)
            group_prefix = style(recovery_state.group_prefix(idx), bold=True)
            bi = style(str(group_size), bold=True)
            if not group_size:
                click.echo(f"{EMPTY} {bi} shares from group {group_prefix}")
            else:
                prefix = FINISHED if group_size >= group_threshold else INPROGRESS
                bt = style(str(group_threshold), bold=True)
                click.echo(f"{prefix} {bi} of {bt} shares needed from group {group_prefix}")

        def print_status() -> None:
            bn = style(str(recovery_state.groups_complete()), bold=True)
            bt = style(str(recovery_state.parameters.group_threshold), bold=True)
            click.echo()
            if recovery_state.parameters.group_count > 1:
                click.echo(f"Completed {bn} of {bt} groups needed:")
            for i in range(recovery_state.parameters.group_count):
                print_group_status(i)

        while not recovery_state.is_complete():
            try:
                if slip39_shares is not None and len(slip39_shares) > 0:
                    mnemonic_str = slip39_shares.pop()
                else:
                    mnemonic_str = click.prompt("Enter a recovery share")
                share = shamir_mnemonic.share.Share.from_mnemonic(mnemonic_str)
                if not recovery_state.matches(share):
                    error("This mnemonic is not part of the current set. Please try again.")
                    continue
                if share in recovery_state:
                    error("Share already entered.")
                    continue

                recovery_state.add_share(share)
                print_status()

            except click.Abort:
                return
            except Exception as e:
                error(str(e))

        print("\nSLIP39 Shares Successfully Loaded\n")

        self.recovery_state = recovery_state

        self.btcrseed_wallet._checksum_ratio = 1

    def __setstate__(self, state):
        # (re-)load the required libraries after being unpickled
        global normalize, hmac
        from unicodedata import normalize
        import hmac
        load_pbkdf2_library(warnings=False)
        self.__dict__ = state

    def passwords_per_seconds(self, seconds):
        return 500

    def difficulty_info(self):
        return "40,000 PBKDF2-SHA256 iterations + ECC"

    def return_verified_password_or_false(self, mnemonic_ids_list): # BIP39-Passphrase
        return self._return_verified_password_or_false_opencl(mnemonic_ids_list) if (self.opencl and not isinstance(self.opencl_algo,int)) \
          else self._return_verified_password_or_false_cpu(mnemonic_ids_list)

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def _return_verified_password_or_false_cpu(self, passwords):
        # Convert Unicode strings (lazily) to normalized UTF-8 bytestrings
        passwords = map(lambda p: normalize("NFKD", p).encode("utf_8", "ignore"), passwords)

        for count, password in enumerate(passwords, 1):
            master_secret = self.recovery_state.recover(password)

            seed_bytes = hmac.new(b"Bitcoin seed", master_secret, hashlib.sha512).digest()

            if self.btcrseed_wallet._verify_seed(seed_bytes):
                return password.decode("utf_8", "replace"), count

        return False, count

    def _return_verified_password_or_false_opencl(self, arg_passwords):
        # Convert Unicode strings (lazily) to normalized UTF-8 bytestrings
        passwords = map(lambda p: normalize("NFKD", p).encode("utf_8", "ignore"), arg_passwords)

        salt_list = []
        for password in passwords:
            if type(self.btcrseed_wallet) is btcrecover.btcrseed.WalletElectrum2:
                salt_list.append(b"electrum" + password)
            else:
                salt_list.append(b"mnemonic" + password)

        clResult = self.opencl_algo.cl_pbkdf2_saltlist(self.opencl_context_pbkdf2_sha512, self._mnemonic.encode(), salt_list, 2048, 64)

        #Placeholder until OpenCL kernel can be patched to support this...
        #clResult = []
        #for salt in salt_list:
        #    clResult.append(pbkdf2_hmac("sha512", self._mnemonic.encode(), salt, 2048))

        # This list is consumed, so recreated it and zip
        passwords = map(lambda p: normalize("NFKD", p).encode("utf_8", "ignore"), arg_passwords)

        results = zip(passwords, clResult)

        for count, (password, result) in enumerate(results, 1):
            seed_bytes = hmac.new(b"Bitcoin seed", result, hashlib.sha512).digest()
            if self.btcrseed_wallet._verify_seed(seed_bytes):
                return password.decode("utf_8", "replace"), count

        return False, count


############### Cardano ###############

# @register_wallet_class - not a "registered" wallet since there are no wallet files nor extracts
class WalletCardano(WalletBIP39):
    opencl_algo = -1

    def __init__(self, addresses=None, addressdb_filename=None,
                 mnemonic=None, lang=None, path=None, is_performance=False):
        from . import btcrseed

        btcrseed_cls = btcrecover.btcrseed.WalletCardano

        global disable_security_warnings
        btcrseed_cls.set_securityWarningsFlag(disable_security_warnings)
        global normalize, hmac
        from unicodedata import normalize
        import hmac
        load_pbkdf2_library()

        # Create a btcrseed.WalletBIP39 object which will do most of the work;
        # this also interactively prompts the user if not enough command-line options were included
        if addressdb_filename:
            from .addressset import AddressSet
            print("Loading address database ...")
            hash160s = AddressSet.fromfile(open(addressdb_filename, "rb"))
        else:
            hash160s = None

        self.btcrseed_wallet = btcrseed_cls.create_from_params(addresses=addresses)
            #addresses, hash160s, path, is_performance)

        if is_performance and not mnemonic:
            mnemonic = "certain come keen collect slab gauge photo inside mechanic deny leader drop"
        self.btcrseed_wallet.config_mnemonic(mnemonic, lang)

        # Verify that the entered mnemonic is valid
        if not self.btcrseed_wallet.verify_mnemonic_syntax(btcrseed.mnemonic_ids_guess):
            error_exit("one or more words are missing from the mnemonic")
        if not self.btcrseed_wallet._verify_checksum(btcrseed.mnemonic_ids_guess):
            error_exit("invalid mnemonic (the checksum is wrong)")
        # We just verified the mnemonic checksum is valid, so 100% of the guesses will also be valid:
        self.btcrseed_wallet._checksum_ratio = 1

        self._mnemonic = " ".join(btcrseed.mnemonic_ids_guess)

    def __setstate__(self, state):
        # (re-)load the required libraries after being unpickled
        global normalize, hmac
        from unicodedata import normalize
        import hmac
        load_pbkdf2_library(warnings=False)
        self.__dict__ = state

    def passwords_per_seconds(self, seconds):
        return self.btcrseed_wallet.passwords_per_seconds(seconds)

    def difficulty_info(self):
        return "4096 PBKDF2-SHA512 iterations (2048 for Ledger)"

    def return_verified_password_or_false(self, mnemonic_ids_list):  # BIP39-Passphrase
        return self._return_verified_password_or_false_opencl(mnemonic_ids_list) if (
                    self.opencl and not isinstance(self.opencl_algo, int)) \
            else self._return_verified_password_or_false_cpu(mnemonic_ids_list)

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def _return_verified_password_or_false_cpu(self, arg_passwords):
        # Convert Unicode strings (lazily) to normalized UTF-8 bytestrings
        passwords = map(lambda p: normalize("NFKD", p).encode("utf_8", "ignore"), arg_passwords)

        _derive_seed_list = self.btcrseed_wallet._derive_seed(self._mnemonic.split(" "), passwords)

        for derivation_type, derived_seed, salt in _derive_seed_list:
            if self.btcrseed_wallet._verify_seed(derivation_type, derived_seed, salt):

                return salt.decode(), arg_passwords.index(salt.decode())+1  # found it

        return False, len(arg_passwords)

    def _return_verified_password_or_false_opencl(self, arg_passwords):
        rootKeys = []

        if self.btcrseed_wallet._check_ledger:
            passwords = map(lambda p: normalize("NFKD", p).encode("utf_8", "ignore"), arg_passwords)
            salt_list = []
            for password in passwords:
                salt_list.append(b"mnemonic" + password)
            mnemonic_list = []

            clResult = self.opencl_algo.cl_pbkdf2_saltlist(self.opencl_context_pbkdf2_sha512_saltlist, self._mnemonic.encode(),
                                                  salt_list, 2048, 64)

            passwords = map(lambda p: normalize("NFKD", p).encode("utf_8", "ignore"), arg_passwords)
            results = zip(passwords, clResult)

            for password, result in results:
                rootKeys.append((password, "ledger", cardano.generateRootKey_Ledger(result)))

        if self.btcrseed_wallet._check_icarus or self.btcrseed_wallet._check_trezor:
            if self.btcrseed_wallet._check_icarus:
                passwords = map(lambda p: normalize("NFKD", p).encode("utf_8", "ignore"), arg_passwords)
                entropy = cardano.mnemonic_to_entropy(words=self._mnemonic,
                                                           wordlist=self.btcrseed_wallet.current_wordlist,
                                                           langcode=self.btcrseed_wallet._lang,
                                                           trezorDerivation=False)


                clResult = self.opencl_algo.cl_pbkdf2(self.opencl_context_pbkdf2_sha512, passwords,
                                                               entropy, 4096, 96)

                passwords = map(lambda p: normalize("NFKD", p).encode("utf_8", "ignore"), arg_passwords)
                results = zip(passwords, clResult)

                for password, result in results:
                    rootKeys.append((password, "icarus", cardano.generateRootKey_Icarus(result)))

            if self.btcrseed_wallet._check_trezor:
                passwords = map(lambda p: normalize("NFKD", p).encode("utf_8", "ignore"), arg_passwords)
                entropy = cardano.mnemonic_to_entropy(words=self._mnemonic,
                                                      wordlist = self.btcrseed_wallet.current_wordlist,
                                                      langcode = self.btcrseed_wallet._lang,
                                                      trezorDerivation = True)


                clResult = self.opencl_algo.cl_pbkdf2(self.opencl_context_pbkdf2_sha512, passwords,
                                                      entropy, 4096, 96)

                passwords = map(lambda p: normalize("NFKD", p).encode("utf_8", "ignore"), arg_passwords)
                results = zip(passwords, clResult)

                for password, result in results:
                    rootKeys.append((password, "trezor", cardano.generateRootKey_Icarus(result)))

        for (password, derivationType, masterkey) in rootKeys:
            if password == b"btcr-test-password":
                print("Derivation Type:", derivationType)
                (kL, kR), AP, cP = masterkey
                print("Master Key")
                print("kL:", kL.hex())
                print("kR:", kR.hex())
                print("AP:", AP.hex())
                print("cP:", cP.hex())

                print("#Rootkeys:", len(rootKeys))

            if self.btcrseed_wallet._verify_seed(derivationType, masterkey, password):
                return password.decode(), arg_passwords.index(password.decode()) + 1  # found it

        return False, len(arg_passwords)

############### Py_Crypto_HD_Wallet Based Wallets ####################
class WalletPyCryptoHDWallet(WalletBIP39):
    def __init__(self, mpk = None, addresses = None, address_limit = None, addressdb_filename = None,
                 mnemonic = None, lang = None, path = None, wallet_type = "bip39", is_performance = False):
        from . import btcrseed

        wallet_type = wallet_type.lower()

        wallet_type_names = []
        for cls, desc in btcrseed.selectable_wallet_classes:
            wallet_type_name = cls.__name__.replace("Wallet", "", 1).lower()
            wallet_type_names.append(cls.__name__.replace("Wallet", "", 1).lower())
            if wallet_type_names[-1] == wallet_type:
                btcrseed_cls = cls
                break
        else:
            wallet_type_names.sort()
            sys.exit("--wallet-type must be one of: " + ", ".join(wallet_type_names))

        global disable_security_warnings
        btcrseed_cls.set_securityWarningsFlag(disable_security_warnings)
        global normalize, hmac
        from unicodedata import normalize
        import hmac

        # Create a btcrseed.WalletBIP39 object which will do most of the work;
        # this also interactively prompts the user if not enough command-line options were included
        if addressdb_filename:
            from .addressset import AddressSet
            print("Loading address database ...")
            hash160s = AddressSet.fromfile(open(addressdb_filename, "rb"))
        else:
            hash160s = None

        self.btcrseed_wallet = btcrseed_cls.create_from_params(
            mpk, addresses, address_limit, hash160s, path, is_performance)

        if is_performance and not mnemonic:
            mnemonic = "certain come keen collect slab gauge photo inside mechanic deny leader drop"
        self.btcrseed_wallet.config_mnemonic(mnemonic, lang)

        # Verify that the entered mnemonic is valid
        if not self.btcrseed_wallet.verify_mnemonic_syntax(btcrseed.mnemonic_ids_guess):
            error_exit("one or more words are missing from the mnemonic")
        if not self.btcrseed_wallet._verify_checksum(btcrseed.mnemonic_ids_guess):
            error_exit("invalid mnemonic (the checksum is wrong)")
        # We just verified the mnemonic checksum is valid, so 100% of the guesses will also be valid:
        self.btcrseed_wallet._checksum_ratio = 1

        self._mnemonic = " ".join(btcrseed.mnemonic_ids_guess)

    def return_verified_password_or_false(self, mnemonic_ids_list): # BIP39-Passphrase
        return self._return_verified_password_or_false_opencl(mnemonic_ids_list) if (self.opencl and not isinstance(self.opencl_algo,int)) \
          else self._return_verified_password_or_false_cpu(mnemonic_ids_list)

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def _return_verified_password_or_false_cpu(self, passwords):
        # Convert Unicode strings (lazily) to normalized UTF-8 bytestrings
        passwords = map(lambda p: normalize("NFKD", p).encode("utf_8", "ignore"), passwords)

        for count, password in enumerate(passwords, 1):

            if self.btcrseed_wallet._verify_seed(mnemonic = self._mnemonic.split(" "), passphrase = password):
                return password.decode("utf_8", "replace"), count

        return False, count


############### Py_Crypto_HD_Wallet Based Wallets ####################
class WalletEthereumValidator(WalletBIP39):

    def __init__(self, mpk = None, addresses = None, address_limit = None, addressdb_filename = None,
                 mnemonic = None, lang = None, path = None, wallet_type = "EthereumValidator", is_performance = False):
        from . import btcrseed

        btcrseed_cls = btcrseed.WalletEthereumValidator

        global disable_security_warnings
        btcrseed_cls.set_securityWarningsFlag(disable_security_warnings)
        global normalize, hmac
        from unicodedata import normalize
        import hmac

        # Create a btcrseed.WalletBIP39 object which will do most of the work;
        # this also interactively prompts the user if not enough command-line options were included
        if addressdb_filename:
            from .addressset import AddressSet
            print("Loading address database ...")
            hash160s = AddressSet.fromfile(open(addressdb_filename, "rb"))
        else:
            hash160s = None

        self.btcrseed_wallet = btcrseed_cls.create_from_params(
            mpk, addresses, address_limit, hash160s, path, is_performance)

        if is_performance and not mnemonic:
            mnemonic = "certain come keen collect slab gauge photo inside mechanic deny leader drop"
        self.btcrseed_wallet.config_mnemonic(mnemonic, lang)

        # Verify that the entered mnemonic is valid
        if not self.btcrseed_wallet.verify_mnemonic_syntax(btcrseed.mnemonic_ids_guess):
            error_exit("one or more words are missing from the mnemonic")
        if not self.btcrseed_wallet._verify_checksum(btcrseed.mnemonic_ids_guess):
            error_exit("invalid mnemonic (the checksum is wrong)")
        # We just verified the mnemonic checksum is valid, so 100% of the guesses will also be valid:
        self.btcrseed_wallet._checksum_ratio = 1

        self._mnemonic = " ".join(btcrseed.mnemonic_ids_guess)

    def difficulty_info(self):
        return "2048 PBKDF2-SHA512 iterations + BLS Derivation"

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def return_verified_password_or_false(self, passwords):
        # Convert Unicode strings (lazily) to normalized UTF-8 bytestrings
        passwords = map(lambda p: normalize("NFKD", p).encode("utf_8", "ignore"), passwords)

        for count, password in enumerate(passwords, 1):

            if self.btcrseed_wallet._verify_seed(mnemonic = self._mnemonic.split(" "), passphrase = password):
                return password.decode("utf_8", "replace"), count

        return False, count

############### Cadano Yoroi Wallet ###############

# @register_wallet_class - not a "registered" wallet since there are no wallet files nor extracts
class WalletYoroi(object):
    opencl_algo = -1

    def __init__(self, master_password = None, is_performance = False):
        if is_performance:
            # Just use a test master password, a modified version of the one from the unit tests
            master_password = b'AA97F83D70BF83B32F8AC936AC32067653EE899979CCFDA67DFCBD535948C42A77DC' \
                              b'9E719BF4ECE7DEB18BA3CD86F53C5EC75DE2126346A791250EC09E570E8241EE4F84' \
                              b'0902CDFCBABC605ABFF30250BFF4903D0090AD1C645CEE4CDA53EA30BF419F4ECEA7' \
                              b'909306EAE4B671FA7EEE3C2F65BE1235DEA4433F20B97F7BB8933521C657C61BBE6C' \
                              b'031A7F1FEEF48C6978090ED009DD578A5382770A'

        self.master_password = master_password

        self.saltHex = master_password[:64]
        self.nonceHex = master_password[64:88]
        self.tagHex = master_password[88:120]
        self.ciphertextHex = master_password[120:]

        self.salt = binascii.unhexlify(self.saltHex)
        self.nonce = binascii.unhexlify(self.nonceHex)
        self.tag = binascii.unhexlify(self.tagHex)
        self.ciphertext = binascii.unhexlify(self.ciphertextHex)

        global emip3

        try:
            from lib.emip3 import emip3
        except ModuleNotFoundError:
            exit(
                "\nERROR: Cannot load pycryptodome module... Be sure to install all requirements with the command 'pip3 install -r requirements.txt', see https://btcrecover.readthedocs.io/en/latest/INSTALL/")


    def __setstate__(self, state):
        # (re-)load the required libraries after being unpickled
        global emip3

        try:
            from lib.emip3 import emip3
        except ModuleNotFoundError:
            exit(
                "\nERROR: Cannot load pycryptodome module... Be sure to install all requirements with the command 'pip3 install -r requirements.txt', see https://btcrecover.readthedocs.io/en/latest/INSTALL/")

        self.__dict__ = state

    def passwords_per_seconds(self, seconds):
        return 260 #This is the approximate performanc on an i7-8750H (The large number of PBKDF2 iterations means this wallet type would get a major boost from GPU acceleration)

    def difficulty_info(self):
        return "19162 PBKDF2-SHA512 iterations + ChaCha20_Poly1305"

    def return_verified_password_or_false(self, mnemonic_ids_list): # Yoroi Cadano Wallet
        return self._return_verified_password_or_false_opencl(mnemonic_ids_list) if (self.opencl and not isinstance(self.opencl_algo,int)) \
          else self._return_verified_password_or_false_cpu(mnemonic_ids_list)

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def _return_verified_password_or_false_cpu(self, passwords): # Yoroi Cadano Wallet
        # Convert Unicode strings (lazily) to normalized UTF-8 bytestrings

        for count, password in enumerate(passwords, 1):
            try:
                emip3.decryptWithPassword(password.encode(), self.master_password)
                return password, count
            except ValueError: #ChaCha20_Poly1305 throws a value error if the password is incorrect
                pass

        return False, count

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def _return_verified_password_or_false_opencl(self, arg_passwords): # Yoroi Cadano Wallet
        from Crypto.Cipher import ChaCha20_Poly1305

        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        passwords = map(lambda p: p.encode("utf_8", "ignore"), arg_passwords)

        clResult = self.opencl_algo.cl_pbkdf2(self.opencl_context_pbkdf2_sha512, passwords, self.salt, 19162, 32)

        # This list is consumed, so recreated it and zip
        passwords = map(lambda p: p.encode("utf_8", "ignore"), arg_passwords)

        results = zip(passwords, clResult)

        for count, (password, key) in enumerate(results, 1):
            try:
                cipher = ChaCha20_Poly1305.new(key=key, nonce=self.nonce)
                plaintext = cipher.decrypt_and_verify(self.ciphertext, self.tag)
                return password.decode("utf_8", "replace"), count
            except ValueError:  # ChaCha20_Poly1305 throws a value error if the password is incorrect
                pass

        return False, count

############### Brainwallet ###############

# @register_wallet_class - not a "registered" wallet since there are no wallet files nor extracts
class WalletBrainwallet(object):
    opencl_algo = -1

    # Dictionary containing all the hash suffixes for memwallet https://github.com/dvdbng/memwallet
    hash_suffix = dict([
        ('bitcoin', 1),
        ('litecoin', 2),
        ('monero', 3),
        ('ethereum', 4)
    ])

    def __init__(self, addresses = None, addressdb = None, check_compressed = True, check_uncompressed = True,
                 force_check_p2sh = False, isWarpwallet = False, salt = None, crypto = 'bitcoin', is_performance = False):
        global hmac, coincurve, base58, pylibscrypt
        if not hashlib_ripemd160_available:
            print("Warning: Native RIPEMD160 not available via Hashlib, using Pure-Python (This will significantly reduce performance)")
        import lib.pylibscrypt as pylibscrypt
        from lib.cashaddress import base58
        import hmac
        try:
            import coincurve
        except ModuleNotFoundError:
            exit("\nERROR: Cannot load coincurve module... Be sure to install all requirements with the command 'pip3 install -r requirements.txt', see https://btcrecover.readthedocs.io/en/latest/INSTALL/")

        load_pbkdf2_library()

        if is_performance and not addresses:
            addresses = "1D6asa4hPt9uomZZgwjKsEmdkSYsCkX542"

        self.compression_checks = []
        if check_compressed : self.compression_checks.append(True)
        if check_uncompressed :  self.compression_checks.append(False)

        self.isWarpwallet = isWarpwallet

        if salt:
            self.salt = salt.encode()
        else:
            self.salt = b""

        if crypto is None:
            self.crypto = 'bitcoin'
        else:
            self.crypto = crypto

        from . import btcrseed
        # Load addresses
        from .addressset import AddressSet

        input_address_p2sh = False
        input_address_standard = False
        self.address_type_checks = []

        if addresses:
            self.hash160s = btcrseed.WalletBase._addresses_to_hash160s(addresses)
            for address in addresses:
                if address[0] == "3":
                    input_address_p2sh = True
                else:
                    input_address_standard = True
        else:
            print("No Addresses Provided ... ")
            print("Loading address database ...")

            if not addressdb:
                print("No AddressDB specified, trying addresses.db")
                addressdb = "addresses.db"

            self.hash160s = AddressSet.fromfile(open(addressdb, "rb"))
            print("Loaded", len(self.hash160s), "addresses from database ...")
            input_address_p2sh = True
            input_address_standard = True

        if input_address_p2sh or force_check_p2sh: self.address_type_checks.append(True)
        if input_address_standard and not (force_check_p2sh): self.address_type_checks.append(False)

    def __setstate__(self, state):
        # (re-)load the required libraries after being unpickled
        global hmac, coincurve, base58, pylibscrypt
        import lib.pylibscrypt as pylibscrypt
        from lib.cashaddress import base58
        import hmac

        try:
            import coincurve
        except ModuleNotFoundError:
            exit(
                "\nERROR: Cannot load coincurve module... Be sure to install all requirements with the command 'pip3 install -r requirements.txt', see https://btcrecover.readthedocs.io/en/latest/INSTALL/")

        load_pbkdf2_library(warnings=False)
        self.__dict__ = state

    def passwords_per_seconds(self, seconds):
        if self.isWarpwallet:
            return 1
        else:
            return 120000 # CPU Processing is going to be in the order if 120,000 kP/s

    def difficulty_info(self):
        if self.isWarpwallet:
            return "sCrypt N=18, r=8, p = 1 + 65536 SHA-256 PBKDF2 Iterations"
        else:
            return "1 SHA-256 iteration"

    def return_verified_password_or_false(self, password_list): # Brainwallet
        return self._return_verified_password_or_false_opencl(password_list) if (self.opencl and not isinstance(self.opencl_algo,int)) \
          else self._return_verified_password_or_false_cpu(password_list)

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def _return_verified_password_or_false_cpu(self, passwords): # Brainwallet
        l_sha256 = hashlib.sha256
        l_scrypt = pylibscrypt.scrypt
        hashlib_new = hashlib.new
        global pbkdf2_hmac
        pubkey_from_secret = coincurve.PublicKey.from_valid_secret

        for count, password in enumerate(passwords, 1):
            # Generate the initial Keypair
            if self.isWarpwallet:
                #print("S1 Params - Pass: ", password.encode() + (self.hash_suffix[self.crypto]).to_bytes(1, 'big'),
                #" Salt: ", self.salt + (self.hash_suffix[self.crypto]).to_bytes(1, 'big'))

                # s1 = scrypt(key=(passphrase||<hashsuffix>), salt=(salt||<hashsuffix>), N=2^18, r=8, p=1, dkLen=32)
                s1 = l_scrypt(password= password.encode() + (self.hash_suffix[self.crypto]).to_bytes(1, 'big'),
                              salt=self.salt + (self.hash_suffix[self.crypto]).to_bytes(1, 'big'),
                              N=1 << 18, r=8, p=1, olen=32)

                # s2 = pbkdf2(key=(passphrase||<hashsuffix+1>), salt=(salt||<hashsuffix+1>), c=2^16, dkLen=32, prf=HMAC_SHA256)
                s2 = pbkdf2_hmac("sha256", password.encode() + (self.hash_suffix[self.crypto] + 1).to_bytes(1, 'big'),
                                 salt=self.salt + (self.hash_suffix[self.crypto] + 1).to_bytes(1, 'big'), iterations= 1 << 16, dklen=32)

                #print("S2:", s2)

                # Privkey = s1 ⊕ s2
                privkey = bytes(x ^ y for x, y in zip(s1, s2))

                #print("Privkey:", privkey.hex())

            else:
                privkey = (l_sha256(password.encode()).digest())


            # Convert the private keys to public keys and addresses for verification.
            for isCompressed in self.compression_checks:
                if isCompressed:
                    privcompress = bytes([0x1])
                else:
                    privcompress = bytes([])

                pubkey = pubkey_from_secret(privkey).format(compressed = isCompressed)

                pubkey_hash160 = ripemd160(l_sha256(pubkey).digest())

                for input_address_p2sh in self.address_type_checks:
                    if (input_address_p2sh):  # Handle P2SH Segwit Address
                        WITNESS_VERSION = "\x00\x14"
                        witness_program = WITNESS_VERSION.encode() + pubkey_hash160

                        hash160 = ripemd160(l_sha256(witness_program).digest())
                    else:
                        hash160 = pubkey_hash160

                    if hash160 in self.hash160s:
                        privkey_wif = base58.b58encode_check(bytes([0x80]) + privkey + privcompress)
                        print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ": NOTE Brainwallet Found using ", end="")
                        if isCompressed:
                            print("COMPRESSED address")
                        else:
                            print("UNCOMPRESSED address")

                        #print("Password Found:", password, ", PrivKey:", privkey_wif, ", Compressed: ", isCompressed)
                        return password, count


        return False, count

    def _return_verified_password_or_false_opencl(self, arg_passwords): # Brainwallet
        l_sha256 = hashlib.sha256
        l_scrypt = pylibscrypt.scrypt
        hashlib_new = hashlib.new
        pubkey_from_secret = coincurve.PublicKey.from_valid_secret

        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        passwords = map(lambda p: p.encode("utf_8", "ignore"), arg_passwords)

        # Generate the initial Keypair
        if self.isWarpwallet:
            # There are actually issues with OpenCL_Brute sCrypt kernel so it doesn't work with the parameters required
            # (The sCrypt library in opencl_brute is hardcoded at N= 15,
            # the one contributed for the BIP38 fork is hardcoded at 14, but even changing this to 18 doesn't produce the
            # correct results...)
            #
            # Have left the equivalent CPU code in for reference, verification and to help anyone else who wants to fix this...
            # Just be aware that you will also need to uncomment the line in the opencl_helper file that creates the context

            # Prepare passwords with correc suffixes for both s1 and s2
            passwords_s1 = []
            passwords_s2 = []
            for password in passwords:
                passwords_s1.append(password + (self.hash_suffix[self.crypto]).to_bytes(1, 'big'))
                passwords_s2.append(password + (self.hash_suffix[self.crypto] + 1).to_bytes(1, 'big'))

            # s1 = scrypt(key=(passphrase||<hashsuffix>), salt=(salt||<hashsuffix>), N=2^18, r=8, p=1, dkLen=32)

            # CPU code for sCrypt. (Testing & Verification)
            clResult_s1 = []
            for password in passwords_s1:
                s1 = l_scrypt(password=password,
                          salt=self.salt + (self.hash_suffix[self.crypto]).to_bytes(1, 'big'),
                          N=1 << 18, r=8, p=1, olen=32)
                #print("S1:", s1)
                clResult_s1.append(s1)

            #print("ClResult (CPU):", clResult_s1)

            # OpenCL Code
            # clResult_s1 = self.opencl_algo_2.cl_scrypt(ctx=self.opencl_context_scrypt,
            #                                            passwords=passwords_s1,
            #                                         N_value=18, r_value=8, p_value=1, desired_key_length=32,
            #                                         hex_salt=self.salt + (self.hash_suffix[self.crypto]).to_bytes(1, 'big'))
            #
            # print("ClResult (GPU):", clResult_s1)

            # s2 = pbkdf2(key=(passphrase||<hashsuffix+1>), salt=(salt||<hashsuffix+1>), c=2^16, dkLen=32, prf=HMAC_SHA256)

            # Placeholder CPU code for sCrypt. (Testing & Verification)
            # clResult_s2 = []
            # for password in passwords_s2:
            #
            #     s2 = pbkdf2_hmac("sha256", password,
            #                      salt=self.salt + (self.hash_suffix[self.crypto] + 1).to_bytes(1, 'big'),
            #                      iterations=1 << 16, dklen=32)
            #
            #     clResult_s2.append(s2)
            #
            # print("ClResult (CPU):", clResult_s2)

            # OpenCL Code
            clResult_s2 = self.opencl_algo_3.cl_pbkdf2(ctx=self.opencl_context_pbkdf2_sha256, passwordlist=passwords_s2,
                                                 salt=self.salt + (self.hash_suffix[self.crypto] + 1).to_bytes(1, 'big'),
                                                   iters=1 << 16, dklen=32)

            #print("ClResult (GPU):", clResult_s2)

            # Privkey = s1 ⊕ s2
            clResult_privkeys = []
            for s1, s2 in zip(clResult_s1, clResult_s2):
                clResult_privkeys.append(bytes(x ^ y for x, y in zip(s1, s2)))

        else:
            # Standard Sha256 Passphrase Hash
            clResult_privkeys = self.opencl_algo.cl_sha256(self.opencl_context_sha256, passwords)

        # Convert the private keys to public keys and addresses for verification.
        for isCompressed in self.compression_checks:

            pubkeys = []
            for privkey in clResult_privkeys:

                if isCompressed:
                    privcompress = bytes([0x1])
                else:
                    privcompress = bytes([])

                pubkeys.append(pubkey_from_secret(privkey).format(compressed=isCompressed))

            clResult_hashed_pubkey = self.opencl_algo.cl_sha256(self.opencl_context_sha256, pubkeys)

            hash160s_standard = []
            for hashed_pubkey in clResult_hashed_pubkey:
                hash160s_standard.append(ripemd160(hashed_pubkey))

            hash160s = []
            for pubkey_hash160 in hash160s_standard:
                for input_address_p2sh in self.address_type_checks:
                    if (input_address_p2sh):  # Handle P2SH Segwit Address
                        WITNESS_VERSION = "\x00\x14"
                        witness_program = WITNESS_VERSION.encode() + pubkey_hash160
                        hash160s.append(ripemd160(l_sha256(witness_program).digest()))
                    else:
                        hash160s.append(pubkey_hash160)

            # This list is consumed, so recreated it and zip
            passwords = map(lambda p: p.encode("utf_8", "ignore"), arg_passwords)

            results = zip(passwords, clResult_privkeys, hash160s)

            for count, (password, privkey, hash160) in enumerate(results, 1):

                # Compute the hash160 of the public key, and check for a match
                if hash160 in self.hash160s:
                    privkey_wif = base58.b58encode_check(bytes([0x80]) + privkey + privcompress)
                    print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ": NOTE Brainwallet Found using ",
                          end="")
                    if isCompressed:
                        print("COMPRESSED address")
                    else:
                        print("UNCOMPRESSED address")

                    #print("Password Found:", password, ", PrivKey:", privkey_wif, ", Compressed: ", isCompressed)
                    return password.decode("utf_8", "replace"), count

        return False, len(arg_passwords)

############### Brainwallet ###############

# @register_wallet_class - not a "registered" wallet since there are no wallet files nor extracts
class WalletRawPrivateKey(object):
    opencl_algo = -1

    # Dictionary containing all the hash suffixes for memwallet https://github.com/dvdbng/memwallet
    hash_suffix = dict([
        ('bitcoin', 1),
        ('litecoin', 2),
        ('monero', 3),
        ('ethereum', 4)
    ])

    def __init__(self, addresses = None, addressdb = None, check_compressed = True, check_uncompressed = True,
                 force_check_p2sh = False, crypto = 'bitcoin', is_performance = False):
        global hmac, coincurve, base58
        if not hashlib_ripemd160_available:
            print("Warning: Native RIPEMD160 not available via Hashlib, using Pure-Python (This will significantly reduce performance)")

        from lib.cashaddress import base58
        import hmac
        try:
            import coincurve
        except ModuleNotFoundError:
            exit("\nERROR: Cannot load coincurve module... Be sure to install all requirements with the command 'pip3 install -r requirements.txt', see https://btcrecover.readthedocs.io/en/latest/INSTALL/")

        load_pbkdf2_library()

        if is_performance and not addresses:
            addresses = "1D6asa4hPt9uomZZgwjKsEmdkSYsCkX542"

        self.compression_checks = []
        if check_compressed : self.compression_checks.append(True)
        if check_uncompressed :  self.compression_checks.append(False)

        if crypto is None:
            self.crypto = 'bitcoin'
        else:
            self.crypto = crypto.lower()

        from . import btcrseed
        # Load addresses
        from .addressset import AddressSet

        input_address_p2sh = False
        input_address_standard = False
        self.address_type_checks = []

        if addresses:
            if self.crypto == 'ethereum':
                self.hash160s = btcrseed.WalletEthereum._addresses_to_hash160s(addresses)
                input_address_standard = True
            else:
                self.hash160s = btcrseed.WalletBase._addresses_to_hash160s(addresses)

                for address in addresses:
                    if address[0] == "3":
                        input_address_p2sh = True
                    else:
                        input_address_standard = True
        else:
            print("No Addresses Provided ... ")
            print("Loading address database ...")

            if not addressdb:
                print("No AddressDB specified, trying addresses.db")
                addressdb = "addresses.db"

            self.hash160s = AddressSet.fromfile(open(addressdb, "rb"))
            print("Loaded", len(self.hash160s), "addresses from database ...")
            input_address_p2sh = True
            input_address_standard = True

        if input_address_p2sh or force_check_p2sh: self.address_type_checks.append(True)
        if input_address_standard and not (force_check_p2sh): self.address_type_checks.append(False)

    def __setstate__(self, state):
        # (re-)load the required libraries after being unpickled
        global hmac, coincurve, base58, pylibscrypt
        import lib.pylibscrypt as pylibscrypt
        from lib.cashaddress import base58
        import hmac

        try:
            import coincurve
        except ModuleNotFoundError:
            exit(
                "\nERROR: Cannot load coincurve module... Be sure to install all requirements with the command 'pip3 install -r requirements.txt', see https://btcrecover.readthedocs.io/en/latest/INSTALL/")

        load_pbkdf2_library(warnings=False)
        self.__dict__ = state

    def passwords_per_seconds(self, seconds):
        return 60000 # CPU Processing is going to be in the order if 120,000 kP/s

    def difficulty_info(self):
        return "1 SHA-256 iteration"

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def return_verified_password_or_false(self, passwords): # Raw Privatekey
        l_sha256 = hashlib.sha256
        hashlib_new = hashlib.new
        pubkey_from_secret = coincurve.PublicKey.from_valid_secret

        for count, password in enumerate(passwords, 1):
            # Generate the initial Keypair
            #print("Key:", password, " Length:", len(password))

            #Just swap a placeholder in for performance measurement
            if ("Measure Performance" in password): password = "9cf68de3a8bec8f4649a5a1eb9340886a68a85c0c3ae722393ef3dd7a6c4da58"

            #Work out what kind of private key we are handling
            WIFPrivKey = False
            if len(password) == 64: # Likely Hex Private Key (Don't need to do anything)
                pass
            elif len(password) == 52 and password[0] in ["L","K"]: #Compressed Private Key
                try:
                    password = binascii.hexlify(base58.b58decode_check(password)[1:-1])
                    WIFPrivKey = True
                except:
                    continue

            elif len(password) == 51 and password[0] == "5":  # Uncompressed Private Key
                try:
                    password = binascii.hexlify(base58.b58decode_check(password)[1:])
                    WIFPrivKey = True
                except:
                    continue


            # Convert the private key from text to raw private key...
            try:
                privkey = binascii.unhexlify(password)
            except binascii.Error as e:
                message = "\n\nWarning: Invalid Private Key (Length or Characters)" + "\nKey Tried: " + password + "\nDouble check your tokenlist/passwordlist and ensure that only valid characters/wildcards are used..." +  "\nSpecific Issue: " + str(e)
                print(message)
                continue

            if len(privkey) != 32:
                message = "\n\nWarning: Invalid Private Key (Should be 64 Characters long)" + "\nKey Tried: " + password + "\nKey Length: " + str(len(privkey)*2) + "\nDouble check your tokenlist/passwordlist and ensure that only valid characters/wildcards are used..."
                print(message)
                continue

            # Convert the private keys to public keys and addresses for verification.
            for isCompressed in self.compression_checks:

                if isCompressed:
                    privcompress = bytes([0x1])
                else:
                    privcompress = bytes([])

                pubkey = pubkey_from_secret(privkey).format(compressed = isCompressed)

                if self.crypto == 'ethereum':
                    pubkey_hash160 = keccak(pubkey[1:])[-20:]
                else:
                    pubkey_hash160 = ripemd160(l_sha256(pubkey).digest())

                for input_address_p2sh in self.address_type_checks:
                    if (input_address_p2sh):  # Handle P2SH Segwit Address
                        WITNESS_VERSION = "\x00\x14"
                        witness_program = WITNESS_VERSION.encode() + pubkey_hash160
                        hash160 = ripemd160(l_sha256(witness_program).digest())
                    else:
                        hash160 = pubkey_hash160

                    if hash160 in self.hash160s:
                        privkey_wif = base58.b58encode_check(bytes([0x80]) + privkey + privcompress)
                        #if self.crypto == 'bitcoin':
                        #    print("\n* * * * *\nPrivkey Found (HEX):", password, ", PrivKey (WIF):", privkey_wif, ", Compressed: ", isCompressed, "\n* * * * *")
                        if WIFPrivKey:
                            return privkey_wif, count
                        else:
                            return password, count


        return False, count

############### Ethereum UTC Keystore ###############

@register_wallet_class
class WalletEthKeystore(object):
    opencl_algo = -1

    _dump_privkeys_file = None

    # This just dumps the wallet private keys
    def dump_privkeys(self, correct_password):
        with open(self._dump_privkeys_file, 'a') as logfile:
            logfile.write("Private Keys (For copy/paste) are below...\n")
            key = eth_keyfile.decode_keyfile_json(self.wallet_json, correct_password)
            logfile.write("0x" + key.hex())

    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(0)
        try:
            walletdata = wallet_file.read()
        except: return False
        return (b"cipherparams" in walletdata and b"kdfparams" in walletdata and b"imTokenMeta" not in walletdata)  # These are fairly distinctive for Eth UTC v3 files

    def __init__(self, loading=False):
        assert loading, 'use load_from_* to create a ' + self.__class__.__name__

    def __setstate__(self, state):
        # (re-)load the required libraries after being unpickled
        self.__dict__ = state

    def passwords_per_seconds(self, seconds):
        if self.wallet_json['crypto']['kdf'] == 'scrypt':
            return 8

        if self.wallet_json['crypto']['kdf'] == 'pbkdf2':
            return 6

    # Load a Eth Keystore file
    @classmethod
    def load_from_filename(cls, wallet_filename):
        if not module_eth_keyfile_available:
            print("eth-keyfile module is required for Eth Keystores (it can normally be installed with the command: pip3 install eth-keyfile)")
            exit()
        wallet_json = eth_keyfile.load_keyfile(wallet_filename)
        self = cls(loading=True)
        self.wallet_json = wallet_json
        return self

    def difficulty_info(self):
        if self.wallet_json['crypto']['kdf'] == 'scrypt':
            return "Scrypt" + \
                   " N=" + str(int(math.log2(self.wallet_json['crypto']['kdfparams']['n'])))  + \
                   " R=" + str(self.wallet_json['crypto']['kdfparams']['r'])  + \
                   " P=" + str(self.wallet_json['crypto']['kdfparams']['p'])

        if self.wallet_json['crypto']['kdf'] == 'pbkdf2':
            return str(self.wallet_json['crypto']['kdfparams']['c']) + " PBKDF2 Iterations"

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def return_verified_password_or_false(self, arg_passwords):  # Ethereum Keystore (UTC) File
        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        passwords = map(lambda p: p.encode("utf_8", "ignore"), arg_passwords)

        for count, password in enumerate(passwords, 1):
            try:
                eth_keyfile.decode_keyfile_json(self.wallet_json,password)
            except ValueError: # Throws a value error if MAC mismatches
                continue

            if self._dump_privkeys_file:
                self.dump_privkeys(password)
            return password.decode("utf_8", "replace"), count

        return False, count

############### Imtoken Keystore ###############

# Imtoken keystores are basically a modified Eth keystore format

@register_wallet_class
class WalletImtokenKeystore(WalletEthKeystore):
    opencl_algo = -1

    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(0)
        try:
            walletdata = wallet_file.read()
        except: return False
        return (b"imTokenMeta" in walletdata)

    @classmethod
    def load_from_filename(cls, wallet_filename):
        if not module_eth_keyfile_available:
            print("eth-keyfile module is required for Eth Keystores (it can normally be installed with the command: pip3 install eth-keyfile)")
            exit()
        wallet_json = eth_keyfile.load_keyfile(wallet_filename)
        wallet_json["version"] = 3
        self = cls(loading=True)
        self.wallet_json = wallet_json
        return self

    def passwords_per_seconds(self, seconds):
        if self.wallet_json['crypto']['kdf'] == 'pbkdf2':
            return 60

    def dump_privkeys(self, correct_password):
        with open(self._dump_privkeys_file, 'a') as logfile:
            try:
                key = eth_keyfile.decode_keyfile_json(self.wallet_json, correct_password)
                logfile.write("BIP39 Root Key (For copy/paste) is below...\n")
                logfile.write(key.decode())
            except:
                print("WARNING KEY DUMP FAILED: Found correct password but can't decode wallet XPRV, try running BTCRecover with identity.json from the imtoken data folder")

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def return_verified_password_or_false(self, arg_passwords):  # Ethereum Keystore (UTC) File
        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        passwords = map(lambda p: p.encode("utf_8", "ignore"), arg_passwords)

        for count, password in enumerate(passwords, 1):
            try:
                eth_keyfile.decode_keyfile_json(self.wallet_json,password)
            except ValueError: # Throws a value error if MAC mismatches
                continue

            if self._dump_privkeys_file:
                self.dump_privkeys(password)
            return password.decode("utf_8", "replace"), count

        return False, count


############### NULL ###############
# A fake wallet which has no correct password;
# used for testing password generation performance

class WalletNull(object):

    def passwords_per_seconds(self, seconds):
        return max(int(round(500000 * seconds)), 1)

    def return_verified_password_or_false(self, passwords):
        return False, len(passwords)


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
        file = io.open(filename, mode, encoding="utf_8_sig", errors=decoding_errors)
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
        for typo_name, typo_args in simple_typo_args.items():
            typo_types_group.add_argument("--typos-"+typo_name, **typo_args)
        typo_types_group.add_argument("--typos-insert",   metavar="WILDCARD-STRING", help="insert a string or wildcard")
        for typo_name in itertools.chain(("swap",), simple_typo_args.keys(), ("insert",)):
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
        parser_common.add_argument("--pause",       action="store_true", help="pause before exiting")
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
        common_seedkey_group.add_argument("--addressdb",  metavar="FILE",    nargs="?", help="if not using addrs, use a full address database (default: %(const)s)", const=ADDRESSDB_DEF_FILENAME)
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
        bip39_group.add_argument("--mnemonic",  metavar="MNEMONIC",       help="Your best guess of the mnemonic (if not entered, you will be prompted)")
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
    assert name not in simple_typos,          "simple typo must not already exist"
    init_parser_common()  # ensure typo_types_group has been initialized
    arg_params = dict(action="store_true")
    if help:
        args["help"] = help
    typo_types_group.add_argument("--typos-"+name, **arg_params)
    typo_types_group.add_argument("--max-typos-"+name, type=int, default=sys.maxsize, metavar="#", help="limit the number of --typos-"+name+" typos")
    def decorator(simple_typo_generator):
        simple_typos[name] = simple_typo_generator
        return simple_typo_generator  # the decorator returns it unmodified, it just gets registered
    return decorator

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
                    perf_iterator = None, inserted_items = None, check_only = None, disable_security_warning_param = False, **kwds):
    # effective_argv is what we are effectively given, either via the command line, via embedded
    # options in the tokenlist file, or as a result of restoring a session, before any argument
    # processing or defaulting is done (unless it's is done by argparse). Each time effective_argv
    # is changed (due to reading a tokenlist or restore file), we redo parser.parse_args() which
    # changes args, so we only do this early on before most args processing takes place.

    # If no args are present on the command line (e.g. user double-clicked the script
    # in the shell), enable --pause by default so user doesn't miss any error messages
    if not effective_argv: enable_pause()

    # Create a parser which can parse any supported option, and run it
    global args
    init_parser_common()
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-h", "--help",   action="store_true", help="show this help message and exit")
    parser.add_argument("--tokenlist",    metavar="FILE",      help="the list of tokens/partial passwords (required)")
    parser.add_argument("--keep-tokens-order", action="store_true",
                        help="try tokens in the order in which they are listed in the file, without trying their permutations")
    parser.add_argument("--seedgenerator", action="store_true",
                               help=argparse.SUPPRESS)  # Flag to be able to indicate to generators that we are doing seed generation, not password generation
    parser.add_argument("--mnemonic-length", type=int,
                               help=argparse.SUPPRESS)  # Argument used for generators in seed generation, not password generation
    parser.add_argument("--seed-transform-wordswaps", type=int,
                               help=argparse.SUPPRESS)  # Flag to be able to indicate to generators that we want to also try swapped words for seed generation
    parser.add_argument("--max-tokens",   type=int, default=sys.maxsize, metavar="COUNT", help="enforce a max # of tokens included per guess")
    parser.add_argument("--min-tokens",   type=int, default=1,          metavar="COUNT", help="enforce a min # of tokens included per guess")
    parser._add_container_actions(parser_common)
    parser.add_argument("--autosave",     metavar="FILE",      help="autosave (5 min) progress to or restore it from a file")
    parser.add_argument("--restore",      metavar="FILE",      help="restore progress and options from an autosave file (must be the only option on the command line)")
    parser.add_argument("--passwordlist", metavar="FILE", nargs="?", const="-", help="instead of using a tokenlist, read complete passwords (exactly one per line) from this file or from stdin")
    parser.add_argument("--has-wildcards",action="store_true", help="parse and expand wildcards inside passwordlists (default: wildcards are only parsed inside tokenlists)")
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
        parser.add_argument("--tokenlist", metavar="FILE", help="the list of tokens/partial passwords (required)")
        parser.add_argument("--max-tokens", type=int, default=sys.maxsize, metavar="COUNT",
                            help="enforce a max # of tokens included per guess")
        parser.add_argument("--min-tokens", type=int, default=1, metavar="COUNT",
                            help="enforce a min # of tokens included per guess")
        parser.add_argument("--seedgenerator", action="store_true",
                            help=argparse.SUPPRESS)  # Flag to be able to indicate to generators that we are doing seed generation, not password generation
        parser.add_argument("--mnemonic-length", type=int,
                            help=argparse.SUPPRESS)  # Argument used for generators in seed generation, not password generation
        parser.add_argument("--seed-transform-wordswaps", type=int,
                            help=argparse.SUPPRESS)  # Flag to be able to indicate to generators that we want to also try swapped words for seed generation
        parser.add_argument("--wildcard-custom-list-e", metavar="FILE",
                            help="Path to a custom list file which will be used fr the %%e expanding wildcard")
        parser.add_argument("--wildcard-custom-list-f", metavar="FILE",
                            help="Path to a custom list file which will be used fr the %%f expanding wildcard")
        parser.add_argument("--wildcard-custom-list-j", metavar="FILE",
                            help="Path to a custom list file which will be used fr the %%j expanding wildcard")
        parser.add_argument("--wildcard-custom-list-k", metavar="FILE",
                            help="Path to a custom list file which will be used fr the %%k expanding wildcard")

        parser._add_container_actions(parser_common)
        # Add these in as non-options so that args gets a copy of their values
        parser.set_defaults(autosave=False, restore=False)
        args = parser.parse_args(effective_argv)

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

    if (not (args.restore or args.passwordlist or args.performance or base_iterator)) or (args.seedgenerator and not args.passwordlist):
        tokenlist_file = open_or_use(args.tokenlist, "r", kwds.get("tokenlist"),
            default_filename=TOKENS_AUTO_FILENAME, permit_stdin=True, make_peekable=True)
        if hasattr(tokenlist_file, "name") and tokenlist_file.name.startswith(TOKENS_AUTO_FILENAME):
            enable_pause()  # enabled by default when using btcrecover-tokens-auto.txt
    else:
        tokenlist_file = None

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
            if re.match("#\s*--", first_line, re.UNICODE):  # if it's additional args, not just a comment
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
    for action in bip39_group._group_actions:
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
        elif args.wallet_type in ['avalanche', 'tron', 'solana', 'cosmos', 'tezos','stellar']:
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
                                    args.language, args.bip32_path, args.wallet_type, args.performance, force_p2sh = args.force_p2sh,checksinglexpubaddress =  args.checksinglexpubaddress)


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
                                          crypto=args.wallet_type)

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
        print("\nDumping Wallet File\Keys...")
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
    passwordlist_file = open_or_use(args.passwordlist, "r", kwds.get("passwordlist"),
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
            if re.match("#\s*--", line, re.UNICODE):
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
            if token.startswith("--") and parser_common._get_option_tuples(token):
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

    # Temporary Fix for the "--keep-tokens-order" argument.
    # Hasn't been fully tested in BTCRecover.py and breaks seedrecover...
    try:
        if args.keep_tokens_order:
            pass
    except:
        if l_seed_generator:
            args.keep_tokens_order = False

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
    global passwordlist_file
    global loaded_wallet

    line_num = 1
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
    return loaded_wallet.return_verified_password_or_false(passwords)

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
        else:
            # Passwords are verified in "chunks" to reduce call overhead. One chunk includes enough passwords to
            # last for about 1/100th of a second (determined experimentally to be about the best I could do, YMMV)
            CHUNKSIZE_SECONDS = 1.0 / 100.0
            measure_performance_iterations = loaded_wallet.passwords_per_seconds(0.5)
            inner_iterations = int(round(2*measure_performance_iterations * CHUNKSIZE_SECONDS)) or 1  # the "2*" is due to the 0.5 seconds above
            outer_iterations = int(round(measure_performance_iterations / inner_iterations))
            assert outer_iterations > 0
        #
        performance_generator = performance_base_password_generator()  # generates dummy passwords
        start = timeit.default_timer()
        # Emulate calling the verification function with lists of size inner_iterations

        loaded_wallet.pre_start_benchmark = True
        for o in range(outer_iterations):
            loaded_wallet.return_verified_password_or_false(list(
                itertools.islice(filter(custom_final_checker, performance_generator), inner_iterations)))
        est_secs_per_password = (timeit.default_timer() - start) / (outer_iterations * inner_iterations)
        del performance_generator
        loaded_wallet.pre_start_benchmark = False
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

    worker_out_queue = multiprocessing.Queue()

    # Create an iterator which actually checks the (remaining) passwords produced by the password_iterator
    # by executing the return_verified_password_or_false worker function in possibly multiple threads
    if spawned_threads == 0:
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
        if loaded_wallet._savevalidseeds:
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

    worker_out_queue.close()

    global searchfailedtext
    return (password_found, searchfailedtext if password_found is False else None)
