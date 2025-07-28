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
from typing import AnyStr, List, Optional, Sequence, TypeVar, Union

# Import modules bundled with BTCRecover
from . import btcrpass
from .addressset import AddressSet
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
try:
    import coincurve
except ModuleNotFoundError:
    exit("\nERROR: Cannot load coincurve module... Be sure to install all requirements with the command 'pip3 install -r requirements.txt', see https://btcrecover.readthedocs.io/en/latest/INSTALL/")

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

eth2_staking_deposit_available = False
try:
    from staking_deposit.key_handling.key_derivation.path import mnemonic_and_path_to_key
    from py_ecc.bls import G2ProofOfPossession as bls

    eth2_staking_deposit_available = True
except:
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
    pathlist_file = open(pathlistFile, "r")
    pathlist_lines = pathlist_file.readlines()
    pathlist = []
    for path in pathlist_lines:
        if path[0] == '#' or len(path.strip()) == 0:
            continue
        pathlist.append(path.split("#")[0].strip())
    pathlist_file.close()
    return pathlist

def load_passphraselist(passphraselistFile):
    passphraselist_file = open(passphraselistFile, "r")
    passphraselist = passphraselist_file.read().splitlines()
    passphraselist_file.close()
    return passphraselist

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
wordlists_dir = os.path.join(os.path.dirname(__file__), "wordlists")
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

############### WalletBase ###############

# Methods common to most wallets, but overridden by WalletEthereum
class WalletBase(object):
    opencl = False
    opencl_algo = -1
    opencl_context_pbkdf2_sha512 = -1
    pre_start_benchmark = False
    _skip_worker_checksum = False
    _savevalidseeds = False

    def __init__(self, loading = False):
        if not hashlib_ripemd160_available:
            print("Warning: Native RIPEMD160 not available via Hashlib, using Pure-Python (This will significantly reduce performance)")
        assert loading, "use load_from_filename or create_from_params to create a " + self.__class__.__name__

    @staticmethod
    def set_securityWarningsFlag(setflag):
        global disable_security_warnings
        disable_security_warnings = setflag

    @staticmethod
    def _addresses_to_hash160s(addresses):
        hash160s = set()
        for address in addresses:
            if address[:1] == "r": # Convert XRP addresses to standard Bitcoin Legacy Addresses
                address = base58_tools.b58encode(
                    base58_tools.b58decode(address, alphabet=base58_tools.XRP_ALPHABET)).decode()
            try:
                # Check if we are getting BCH Cashaddresses and if so, convert them to standard legacy addresses
                if address[:12].lower() == "bitcoincash:":
                    address = convert.to_legacy_address(address)
                else:
                    try:
                        address = convert.to_legacy_address("bitcoincash:" + address)
                    except convert.InvalidAddress:
                        pass
                hash160 = binascii.unhexlify(encoding.addr_base58_to_pubkeyhash(address, True)) #assume we have a P2PKH (Legacy) or Segwit (P2SH) so try a Base58 conversion
            except (encoding.EncodingError, AssertionError) as e:
                try:
                    hash160 = binascii.unhexlify(encoding.grs_addr_base58_to_pubkeyhash(address, True)) #assume we have a P2PKH (Legacy) or Segwit (P2SH) so try a Base58 conversion
                except Exception as e:
                    try:
                        hash160 = binascii.unhexlify(encoding.addr_bech32_to_pubkeyhash(address, prefix=None,  include_witver=False, as_hex=True)) #Base58 conversion above will give a keyError if attempted with a Bech32 address for things like BTC
                    except Exception as e:
                        if bundled_bitcoinlib_mod_available:
                            # Try for some obscure altcoins which require modified versions of Bitcoinlib
                            try:
                                hash160 = binascii.unhexlify(encoding_mod.grs_addr_base58_to_pubkeyhash(address, True))
                            except Exception as e:
                                hash160 = binascii.unhexlify(encoding_mod.addr_bech32_to_pubkeyhash(address, prefix=None,  include_witver=False, as_hex=True))
                        else:
                            print("Address not valid and unable to load modified bitcoinlib on this platform...")

            hash160s.add(hash160)
        return hash160s

    @staticmethod
    def pubkey_to_hash160(uncompressed_pubkey):
        """convert from an uncompressed public key to its Bitcoin compressed-pubkey hash160 form

        :param uncompressed_pubkey: SEC 1 EllipticCurvePoint OctetString
        :type uncompressed_pubkey: str
        :return: ripemd160(sha256(compressed_pubkey))
        :rtype: str
        """
        return ripemd160(hashlib.sha256(compress_pubkey(uncompressed_pubkey)).digest())

    # Simple accessor to be able to identify the BIP44 coin number of the wallet
    def get_path_coin(self):
        coin = 0  # Just assume bitcoin by default
        try:
            coin = self._path_indexes[0][1] - 2 ** 31
        except:
            pass

        return coin

############### Electrum1 ###############

@register_selectable_wallet_class("Electrum 1.x (including wallets later upgraded to 2.x)")
class WalletElectrum1(WalletBase):

    _words = None
    @classmethod
    def _load_wordlist(cls):
        if not cls._words:
            cls._words      = tuple(map(str, load_wordlist("electrum1", "en")))  # also converts to ASCII
            cls._word_to_id = { word:id for id,word in enumerate(cls._words) }

    @property
    def word_ids(self):      return range(len(self._words))
    @classmethod
    def id_to_word(cls, id): return cls._words[id]

    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(0)
        # returns "maybe yes" or "definitely no"
        return None if wallet_file.read(2) == b"{'" else False

    def __init__(self, loading = False):
        super(WalletElectrum1, self).__init__(loading)
        self._master_pubkey        = None
        self._passwords_per_second = None

        self._load_wordlist()
        self._num_words = len(self._words)  # needs to be an instance variable so it can be pickled

    def passwords_per_seconds(self, seconds):
        if not self._passwords_per_second:
            self._passwords_per_second = \
                calc_passwords_per_second(1, 0.12, 1 if self._master_pubkey else self._addrs_to_generate + 1)
        return max(int(round(self._passwords_per_second * seconds)), 1)

    # Load an Electrum1 wallet file (the part of it we need, just the master public key)
    @classmethod
    def load_from_filename(cls, wallet_filename):
        from ast import literal_eval
        with open(wallet_filename) as wallet_file:
            wallet = literal_eval(wallet_file.read(btcrpass.MAX_WALLET_FILE_SIZE))  # up to 64M, typical size is a few k
        return cls._load_from_dict(wallet)

    @classmethod
    def _load_from_dict(cls, wallet):
        seed_version = wallet.get("seed_version")
        if seed_version is None:             raise ValueError("Unrecognized wallet format (Electrum1 seed_version not found)")
        if seed_version != 4:                raise NotImplementedError("Unsupported Electrum1 seed version " + seed_version)
        if not wallet.get("use_encryption"): raise ValueError("Electrum1 wallet is not encrypted")
        master_pubkey = base64.b16decode(wallet["master_public_key"], casefold=True)
        if len(master_pubkey) != 64:         raise ValueError("Electrum1 master public key is not 64 bytes long")
        self = cls(loading=True)
        self._master_pubkey = "\x04".encode() + master_pubkey  # prepend the uncompressed tag
        return self

    # Creates a wallet instance from either an mpk, an addresses container and address_limit,
    # or a hash160s container. If none of these were supplied, prompts the user for each.
    @classmethod
    def create_from_params(cls, mpk = None, addresses = None, address_limit = None, hash160s = None, is_performance = False, address_start_index = None, force_p2sh = False, checksinglexpubaddress = False, force_p2tr = False):
        self = cls(loading=True)

        # Process the mpk (master public key) argument
        if mpk:
            if len(mpk) != 128:
                raise ValueError("an Electrum 1.x master public key must be exactly 128 hex digits long")
            try:
                mpk = base64.b16decode(mpk, casefold=True)
                # (it's assigned to the self._master_pubkey later)
            except TypeError as e:
                raise ValueError(e)  # consistently raise ValueError for any bad inputs

        # Process the hash160s argument
        if hash160s:
            if mpk:
                print("warning: addressdb is ignored when an mpk is provided", file=sys.stderr)
                hash160s = None
            else:
                self._known_hash160s = hash160s

        # Process the addresses argument
        if addresses:
            if mpk or hash160s:
                print("warning: addresses are ignored when an mpk or addressdb is provided", file=sys.stderr)
                addresses = None
            else:
                self._known_hash160s = self._addresses_to_hash160s(addresses)

        # Process the address_limit argument
        if address_limit:
            if mpk:
                print("warning: address limit is ignored when an mpk is provided", file=sys.stderr)
                address_limit = None
            else:
                address_limit = int(address_limit)
                if address_limit <= 0:
                    raise ValueError("the address limit must be > 0")
                # (it's assigned to self._addrs_to_generate later)

        if address_start_index:
            self._address_start_index = address_start_index
            if address_limit < 0:
                raise ValueError("the address limit must zero or positive")
        else:
            self._address_start_index = 0

        # If mpk, addresses, and hash160s arguments were all not provided, prompt the user for an mpk first
        if not mpk and not addresses and not hash160s:
            init_gui()
            while True:
                if tk_root:  # Skip if TK is not available...
                    mpk = tk.simpledialog.askstring("Electrum 1.x master public key",
                        "Please enter your master public key if you have it, or click Cancel to search by an address instead:",
                        initialvalue="c79b02697b32d9af63f7d2bd882f4c8198d04f0e4dfc5c232ca0c18a87ccc64ae8829404fdc48eec7111b99bda72a7196f9eb8eb42e92514a758f5122b6b5fea"
                            if is_performance else None)
                else:
                    print("Error: No MPK or addresses specified... Exiting...")
                    exit()

                if not mpk:
                    break  # if they pressed Cancel, stop prompting for an mpk
                mpk = mpk.strip()
                try:
                    if len(mpk) != 128:
                        raise TypeError()
                    mpk = base64.b16decode(mpk, casefold=True)  # raises TypeError() on failure
                    break
                except TypeError:
                    tk.messagebox.showerror("Master public key", "The entered Electrum 1.x key is not exactly 128 hex digits long")

        # If an mpk has been provided (in the function call or from a user), convert it to the needed format
        if mpk:
            assert len(mpk) == 64, "mpk is 64 bytes long (after decoding from hex)"
            self._master_pubkey = "\x04".encode() + mpk  # prepend the uncompressed tag

        # If an mpk wasn't provided (at all), and addresses and hash160s arguments also
        # weren't provided (in the original function call), prompt the user for addresses.
        else:
            if not addresses and not hash160s:
                # init_gui() was already called above
                self._known_hash160s = None
                while True:
                    addresses = tk.simpledialog.askstring("Addresses",
                        "Please enter at least one address from your wallet, "
                        "preferably some created early in your wallet's lifetime:",
                        initialvalue="17LGpN2z62zp7RS825jXwYtE7zZ19Mxxu8" if is_performance else None)
                    if not addresses: break
                    addresses.replace(",", " ")
                    addresses.replace(";", " ")
                    addresses = addresses.split()
                    if not addresses: break
                    try:
                        # (raises ValueError or TypeError on failure):
                        self._known_hash160s = self._addresses_to_hash160s(addresses)
                        break
                    except (ValueError, TypeError) as e:
                        tk.messagebox.showerror("Addresses", "An entered address is invalid ({})".format(e))

                # If there are still no hash160s available (and no mpk), check for an address database before giving up
                if not self._known_hash160s:
                    if os.path.isfile(ADDRESSDB_DEF_FILENAME):
                        print("Using address database file '"+ADDRESSDB_DEF_FILENAME+"' in the current directory.")
                    else:
                        print("notice: address database file '"+ADDRESSDB_DEF_FILENAME+"' does not exist in current directory", file=sys.stderr)
                        sys.exit("canceled")

            if not address_limit:
                init_gui()  # might not have been called yet
                before_the = "one(s) you just entered" if addresses else "first one in actual use"
                if tk_root:  # Skip if TK is not available...
                    address_limit = tk.simpledialog.askinteger("Address limit",
                        "Please enter the address generation limit. Smaller will\n"
                        "be faster, but it must be equal to at least the number\n"
                        "of addresses created before the "+before_the+":\n"
                        "(If unsure, 10 is a sensible default...)", minvalue=1, initialvalue=10)
                else:
                    print("No address generation limit specified... Exiting...")
                    exit()

                if not address_limit:
                    sys.exit("canceled")
            self._addrs_to_generate = address_limit

            if not self._known_hash160s:
                print("Loading address database ...")
                self._known_hash160s = AddressSet.fromfile(open(ADDRESSDB_DEF_FILENAME, "rb"))
                print("Loaded", len(self._known_hash160s), "addresses from database ...")

        return self

    # Performs basic checks so that clearly invalid mnemonic_ids can be completely skipped
    @staticmethod
    def verify_mnemonic_syntax(mnemonic_ids):
        return len(mnemonic_ids) in [12,24] and None not in mnemonic_ids

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a mnemonic
    # is correct return it, else return False for item 0; return a count of mnemonics checked for item 1
    def return_verified_password_or_false(self, mnemonic_ids_list):
        # Copy some vars into local for a small speed boost
        l_sha256     = hashlib.sha256
        hashlib_new  = hashlib.new
        num_words    = self._num_words
        num_words2   = num_words * num_words

        for count, mnemonic_ids in enumerate(mnemonic_ids_list, 1):
            # In the event that a tokenlist based recovery is happening, convert the list from string sback to ints
            if (type(mnemonic_ids[0]) == str):
                new_mnemonic_ids = []
                for word in mnemonic_ids:
                    new_mnemonic_ids.append(self._words.index(word))
                mnemonic_ids = new_mnemonic_ids

            # Compute the binary seed from the word list the Electrum1 way
            seed = ""
            for i in range(0, len(mnemonic_ids), 3):
                seed += "{:08x}".format( mnemonic_ids[i    ]
                     + num_words  * (   (mnemonic_ids[i + 1] - mnemonic_ids[i    ]) % num_words )
                     + num_words2 * (   (mnemonic_ids[i + 2] - mnemonic_ids[i + 1]) % num_words ))
            #

            unstretched_seed = seed
            for i in range(100000):  # Electrum1's seed stretching

                #Check the types of the seed and stretched_seed variables and force back to bytes (Allows most code to stay as-is for Py3)
                if type(seed) is str:
                    seed = seed.encode()
                if type(unstretched_seed) is str:
                    unstretched_seed = unstretched_seed.encode()

                seed = l_sha256(seed + unstretched_seed).digest()

            # If a master public key was provided, check the pubkey derived from the seed against it
            if self._master_pubkey:
                try:
                    if coincurve.PublicKey.from_valid_secret(seed).format(compressed=False) == self._master_pubkey:
                        return mnemonic_ids, count  # found it
                except ValueError: continue

            # Else derive addrs_to_generate addresses from the seed, searching for a match with known_hash160s
            else:
                master_privkey = bytes_to_int(seed)

                try: master_pubkey_bytes = coincurve.PublicKey.from_valid_secret(seed).format(compressed=False)[1:]
                except ValueError: continue

                for seq_num in range(self._address_start_index, self._address_start_index + self._addrs_to_generate):
                    # Compute the next deterministic private/public key pair the Electrum1 way.
                    # FYI we derive a privkey first, and then a pubkey from that because it's
                    # likely faster than deriving a pubkey directly from the base point and
                    # seed -- it means doing a simple modular addition instead of a point
                    # addition (plus a scalar point multiplication which is needed for both).
                    derivation = b"".join([str(seq_num).encode(), b":0:", master_pubkey_bytes])
                    d_offset  = bytes_to_int( l_sha256(l_sha256(
                            derivation  # 0 means: not a change address
                        ).digest()).digest() )
                    d_privkey = int_to_bytes((master_privkey + d_offset) % GENERATOR_ORDER, 32)

                    d_pubkey  = coincurve.PublicKey.from_valid_secret(d_privkey).format(compressed=False)

                    # Compute the hash160 of the *uncompressed* public key, and check for a match

                    if ripemd160(l_sha256(d_pubkey).digest()) in self._known_hash160s:
                        return mnemonic_ids, count  # found it

        return False, count

    # Configures the values of four globals used later in config_btcrecover():
    # mnemonic_ids_guess, close_mnemonic_ids, num_inserts, and num_deletes
    @classmethod
    def config_mnemonic(cls, mnemonic_guess = None, closematch_cutoff = 0.65, expected_len = None):
        if expected_len:
            if expected_len not in [12,24]:
                raise ValueError("Electrum1 mnemoincs can only be 12 or 24 words lon")

        # If a mnemonic guess wasn't provided, prompt the user for one
        if not mnemonic_guess:
            init_gui()
            if tk_root:  # Skip if TK is not available...
                mnemonic_guess = tk.simpledialog.askstring("Electrum seed",
                    "Please enter your best guess for your Electrum seed:")
            else:
                print("No mnemonic guess specified... Exiting...")
                exit()

            if not mnemonic_guess:
                sys.exit("canceled")

        mnemonic_guess = str(mnemonic_guess)  # ensures it's ASCII

        # Convert the mnemonic words into numeric ids and pre-calculate similar mnemonic words
        global mnemonic_ids_guess, close_mnemonic_ids
        mnemonic_ids_guess = ()
        # close_mnemonic_ids is a dict; each dict key is a mnemonic_id (int), and each
        # dict value is a tuple containing length 1 tuples, and finally each of the
        # length 1 tuples contains a single mnemonic_id which is similar to the dict's key
        close_mnemonic_ids = {}
        for word in mnemonic_guess.lower().split():
            close_words = difflib.get_close_matches(word, cls._words, sys.maxsize, closematch_cutoff)
            if close_words:
                if close_words[0] != word:
                    print("'{}' was in your guess, but it's not a valid Electrum seed word;\n"
                          "    trying '{}' instead.".format(word, close_words[0]))
                mnemonic_ids_guess += cls._word_to_id[close_words[0]],
                close_mnemonic_ids[mnemonic_ids_guess[-1]] = tuple( (cls._word_to_id[w],) for w in close_words[1:] )
            else:
                if word != 'seed_token_placeholder':
                    print("'{}' was in your guess, but there is no similar Electrum seed word;\n"
                          "    trying all possible seed words here instead.".format(word))
                mnemonic_ids_guess += None,

        guess_len = len(mnemonic_ids_guess)
        if not expected_len:
            if guess_len < 12:
                expected_len = 12
            elif guess_len > 24:
                expected_len = 24
            else:
                off_by = guess_len % 3
                if off_by == 0: # If the supplied guess is a valid length, assume that all words have been supplied
                    expected_len = guess_len
                else: # If less words have been supplied, round up to the nearest valid seed length (Assume words are missing by default)
                    expected_len = guess_len + 3 - off_by

            print("Assuming a", expected_len, "word mnemonic. (This can be overridden with --mnemonic-length)")

        global num_inserts, num_deletes
        num_inserts = max(expected_len - len(mnemonic_ids_guess), 0)
        num_deletes = max(len(mnemonic_ids_guess) - expected_len, 0)
        if num_inserts:
            print("Seed sentence was too short, inserting {} word{} into each guess."
                  .format(num_inserts, "s" if num_inserts > 1 else ""))
        if num_deletes:
            print("Seed sentence was too long, deleting {} word{} from each guess."
                  .format(num_deletes, "s" if num_deletes > 1 else ""))

    # Produces a long stream of differing and incorrect mnemonic_ids guesses (for testing)
    @staticmethod
    def performance_iterator():
        # See WalletBIP39.performance_iterator() for details
        prefix = tuple(random.randrange(len(WalletElectrum1._words)) for i in range(8))
        for guess in itertools.product(range(len(WalletElectrum1._words)), repeat = 4):
            yield prefix + guess

### Blockchain.info password seed ###

class BlockChainPassword(WalletBase):
    _words = None
    _v2words = None

    @property
    def word_ids(self):      return range(self._num_words)

    @classmethod
    def id_to_word(self, id): return self._words[id]

    @classmethod
    def _load_wordlist(self, wordlist):
        self._words = tuple(map(str, load_wordlist(wordlist, "en")))
        self._num_words = len(self._words)
        self._word_to_id = { word:id for id,word in enumerate(self._words) }
        return self._words, self._word_to_id

    def __init__(self, loading = False):
        super(BlockChainPassword, self).__init__(loading)
        self._passwords_per_second = None
        # v2 words are used by v3+ also
        self._v2words = tuple(map(str, load_wordlist("blockchainpassword_words_v2", "en")))
        self._v2word_to_id = { word:id for id,word in enumerate(self._v2words) }

    def passwords_per_seconds(self, seconds):
        if not self._passwords_per_second:
            self._passwords_per_second = \
                calc_passwords_per_second(0.1, 0.1, 1)
        return max(int(round(self._passwords_per_second * seconds)), 1)
    
    # Creates a wallet instance
    @classmethod
    def create_from_params(self, is_performance = False, force_p2tr = False):
        self = self(loading=True)
        return self
    
    # Performs basic checks so that clearly invalid mnemonic_ids can be completely skipped
    @staticmethod
    def verify_mnemonic_syntax(mnemonic_ids):
        return len(mnemonic_ids) == len(mnemonic_ids_guess) + num_inserts - num_deletes
    
    # Configures the values of four globals used later in config_btcrecover():
    # mnemonic_ids_guess, close_mnemonic_ids, num_inserts, and num_deletes
    def config_mnemonic(cls, mnemonic_guess = None, closematch_cutoff = 0.65, expected_len = None):
        # If a mnemonic guess wasn't provided, prompt the user for one
        if not mnemonic_guess:
            init_gui()
            if tk_root:
                mnemonic_guess = tk.simpledialog.askstring("Blockchain Legacy Wallet Recovery Mnemonic",
                    "Please enter your best guess for your Blockchain Legacy Wallet Recovery Mnemonic:")
            else:
                print("No mnemonic guess specified... Exiting...")
                exit()

            if not mnemonic_guess:
                sys.exit("canceled")
        if not expected_len:
            init_gui()
            if tk_root:
                expected_len = tk.simpledialog.askinteger("Blockchain Legacy Wallet Recovery Mnemonic number of words",
                    "Please enter your best guess for number of words in your BitcoinPassword seed:")
            else:
                print("No number of words specified... Exiting...")
                exit()

            if not expected_len:
                sys.exit("canceled")                
        cls.expected_len = expected_len
        cls._initial_words_valid = False
        mnemonic_guess = str(mnemonic_guess)  # ensures it's ASCII

        # Convert the mnemonic words into numeric ids and pre-calculate similar mnemonic words
        global mnemonic_ids_guess, close_mnemonic_ids
        mnemonic_ids_guess = ()
        # close_mnemonic_ids is a dict; each dict key is a mnemonic_id (int), and each
        # dict value is a tuple containing length 1 tuples, and finally each of the
        # length 1 tuples contains a single mnemonic_id which is similar to the dict's key
        close_mnemonic_ids = {}
        for word in mnemonic_guess.lower().split():
            close_words = difflib.get_close_matches(word, cls._words, sys.maxsize, closematch_cutoff)
            if close_words:
                if close_words[0] != word:
                    print("'{}' was in your guess, but it's not a valid BlockchainPassword seed word;\n"
                          "    trying '{}' instead.".format(word, close_words[0]))
                mnemonic_ids_guess += cls._word_to_id[close_words[0]],
                close_mnemonic_ids[mnemonic_ids_guess[-1]] = tuple( (cls._word_to_id[w],) for w in close_words[1:] )
            else:
                if word != 'seed_token_placeholder':
                    print("'{}' was in your guess, but there is no similar BlockchainPassword seed word;\n"
                          "    trying all possible seed words here instead.".format(word))
                mnemonic_ids_guess += None,

        global num_inserts, num_deletes
        num_inserts = max(expected_len - len(mnemonic_ids_guess), 0)
        num_deletes = max(len(mnemonic_ids_guess) - expected_len, 0)
        if num_inserts:
            print("Seed sentence was too short, inserting {} word{} into each guess."
                  .format(num_inserts, "s" if num_inserts > 1 else ""))
        if num_deletes:
            print("Seed sentence was too long, deleting {} word{} from each guess."
                  .format(num_deletes, "s" if num_deletes > 1 else ""))

    # Produces a long stream of differing and incorrect mnemonic_ids guesses (for testing)
    def performance_iterator(self):
        # See WalletBIP39.performance_iterator(self) for details
        length = len(mnemonic_ids_guess) + num_inserts - num_deletes
        for guess in itertools.product(self.word_ids, repeat=length):
            yield guess

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a mnemonic
    # is correct return it, else return False for item 0; return a count of mnemonics checked for item 1
    def return_verified_password_or_false(self, mnemonic_ids_list):
        # Copy some vars into local for a small speed boost
        for count, mnemonic_ids in enumerate(mnemonic_ids_list, 1):
            result = False
            try:
                result = self._verify_checksum(mnemonic_ids)
                if result == False: continue
            except ValueError: continue
            except Exception as e:
                print(e)
            return mnemonic_ids, count
        return False, count
    
    def _verify_checksum(self, words):
        raise ValueError

    @staticmethod    
    def mn_mod(a, b):
        return b + a if a < 0 else a % b
    
    @staticmethod
    def words_to_bytes(words):
        byte_array = []
        for word in words:
            byte_array.extend(word.to_bytes(4, byteorder='big', signed=False))
        return byte_array
    
    @staticmethod
    def bytes_to_words(byte_array):
        words = []
        for i in range(0, len(byte_array), 4):
            word = int.from_bytes(byte_array[i:i+4], byteorder='big', signed=False)
            words.append(word)
        return words

    @staticmethod
    def bytes_to_string(byte_array):
        return bytes(byte_array).decode('utf-8', errors='ignore')
    
    def decode_v2(self, word1, word2, word3):
        if not word2 or not word3:
            raise ValueError("seeds are not a multiple of 3")
        n = len(self._v2words)
        w1 = word1
        w2 = word2 % n
        w3 = word3 % n
        return w1 + n * self.mn_mod(w2 - w1, n) + n * n * self.mn_mod(w3 - w2, n)
        
    @staticmethod  
    def safe_get(lst, index):
        try:
            return lst[index]
        except IndexError:
            return None
                

@register_selectable_wallet_class("Blockchain.info Legacy Wallet Recovery Mnemonic v3")
class BlockChainPasswordV3(BlockChainPassword):

    def __init__(self, loading = False):
        self._words, self._word_to_id = self._load_wordlist("blockchainpassword_words_v3")
        self._num_words = len(self._words)
        super(BlockChainPasswordV3, self).__init__(loading)

    def _verify_checksum(self, words):
        if len(words) < 3:
            raise ValueError('Mnemonic must have at least 2 words to do checksum')
        
        try:
            # get the v2 ids of the first 3 words to calculate the checksum
            seedwords = [self._words[seedid] for seedid in words[:3]]
            try:
                v2seedids = [self._v2word_to_id[seedword] for seedword in seedwords]
            except KeyError:
                raise ValueError
            except Exception as e:
                print(e)            
            checksum = self.decode_v2(v2seedids[0], v2seedids[1], v2seedids[2])

            version = int_to_bytes(checksum, 4)[0]
            if version not in (3, 4, 5, 6): return False

            obj = self.decode_v3456_word_list(words[3:], version, checksum)
            print('\nPassword found: ' + obj['password'] + '\n')
            if obj['guid']:
                print('\nAccount ID found: ' + obj['guid'] + '\n')
            
            return True
        except ValueError:
            return False
        except Exception as e:
            print(e)
            return False
    
    def decode_v3(self, word1, word2):
        val1 = word1
        if word2 is None:
            if val1 == -1:
                raise ValueError('Unknown Word ' + self._words[word1])
            b1 = self.words_to_bytes([val1])
            return self.bytes_to_words([b1[2], b1[3], 0, 0])
        else:
            val2 = word2
            if val1 == -1 or val2 == -1:
                raise ValueError('Unknown Word ' + self._words[word1] + ' or ' + self._words[word2])
            b1 = self.words_to_bytes([val1])
            b2 = self.words_to_bytes([val2])
            try:
                return self.bytes_to_words([b1[2], b1[3], b2[2], b2[3]])
            except:
                raise ValueError
            
    def decode_v3456_word_list(self, wlist, version, checksum):
        words = [self.decode_v3(wlist[i], self.safe_get(wlist, i + 1))[0] for i in range(0, len(wlist), 2)]
        str_bytes = self.words_to_bytes(words)
        str_bytes = bytearray([byte for byte in str_bytes if byte != 0])

        restored_checksum_bytes = hashlib.sha256(str_bytes).digest()[:3]
        version_byte = version.to_bytes(1, byteorder='big')
        restored_checksum_bytes = version_byte + restored_checksum_bytes
        restored_checksum = int.from_bytes(restored_checksum_bytes, byteorder='big')

        if restored_checksum < 0:
            restored_checksum = -restored_checksum
        if checksum != restored_checksum:
            raise ValueError('Invalid Mnemonic Checksum. Please enter it carefully.')

        obj = {}
        if version == 4:
            guid_part = str_bytes[:16]
            obj['guid'] = '-'.join([''.join('{:02x}'.format(b) for b in guid_part[i:i + 2]) for i in range(0, 16, 2)])
        elif version == 5:
            obj['time'] = bytes_to_int(str_bytes[:4], 4)
        obj['password'] = self.bytes_to_string(str_bytes)
        return obj
            
@register_selectable_wallet_class("Blockchain.info Legacy Wallet Recovery Mnemonic v2")
class BlockChainPasswordV2(BlockChainPassword):

    def __init__(self, loading = False):
        self._words, self._word_to_id = self._load_wordlist("blockchainpassword_words_v2")
        self._v2words = self._words
        self._v2word_to_id = self._word_to_id
        super(BlockChainPasswordV2, self).__init__(loading)

    def config_mnemonic(self, mnemonic_guess = None, closematch_cutoff = 0.65, expected_len = None):
        super(BlockChainPasswordV2, self).config_mnemonic(mnemonic_guess, closematch_cutoff, expected_len) 
        length = len(mnemonic_ids_guess) + num_inserts - num_deletes
        if length % 3 != 0:
            exit("BlockChain Password V2 seeds should be a length divisible by 3")

    def _verify_checksum(self, words):
        if len(words) < 3:
            raise ValueError('Mnemonic must have at least 3 words do checksum')
        
        try:
            # Try decoding the first two words using version 3 logic
            checksum = self.decode_v2(words[0], words[1], words[2])
            version = int_to_bytes(checksum, 1)[0]
            if version != 2: return False

            obj = self.decode_v2_word_list(words, checksum)
            print(obj.password) 
            return True
        except ValueError:
            return False
        except Exception as e:
            print(e)
            return False    
        
    def decode_v2_word_list(self, wlist, checksum):
        try:
            words = [self.decode_v2(wlist[i], self.safe_get(wlist, i + 1), self.safe_get(wlist, i + 2)) for i in range(0, len(wlist), 3)]
            str_bytes = self.words_to_bytes(words)
            str_bytes = bytearray([byte for byte in str_bytes if byte != 0])

            restored_checksum = bytes_to_int(hashlib.sha256(str_bytes).digest()[:3])
            if restored_checksum < 0:
                restored_checksum = -restored_checksum
            if checksum != restored_checksum:
                raise ValueError('Invalid Mnemonic Checksum. Please enter it carefully.')
            else:
                return {'password': self.bytes_to_string(str_bytes)}
        except ValueError:
            raise ValueError()
        except Exception as e:
            print(e)
            return False             
             
############### BIP32 ###############

class WalletBIP32(WalletBase):

    def __init__(self, arg_derivationpath = None, loading = False):
        super(WalletBIP32, self).__init__(loading)
        self._chaincode            = None
        self._passwords_per_second = None

        derivation_paths = []
        self._append_last_index = False
        # Split the BIP32 key derivation path into its constituent indexes
        if not arg_derivationpath:  # Defaults to testing BIP44, BIP49 and BIP84 for Bitcoin
            derivation_paths = ["m/44'/0'/0'/", "m/49'/0'/0'/", "m/84'/0'/0'/"]
            # Append the internal/external (change) index to the path in create_from_params()
            self._append_last_index = True
        else:
            for arg_path in arg_derivationpath:
                derivation_paths.append(arg_path)

        self._path_indexes = []
        for path in derivation_paths:
            path_indexes = path.split("/")
            if path_indexes[0] == "m" or path_indexes[0] == "":
                del path_indexes[0]   # the optional leading "m/"
            if path_indexes[-1] == "":
                del path_indexes[-1]  # the optional trailing "/"
            current_path_indexes = []
            for path_index in path_indexes:
                if path_index.endswith("'"):
                    current_path_indexes += int(path_index[:-1]) + 2**31,
                else:
                    current_path_indexes += int(path_index),

            self._path_indexes.append(current_path_indexes)

    def passwords_per_seconds(self, seconds):
        if not self._passwords_per_second:
            scalar_multiplies = 0
            for i in self._path_indexes[0]: # Just use the first derivation path for this...
                if i < 2147483648:          # if it's a normal child key
                    scalar_multiplies += 1  # then it requires a scalar multiply
            if not self._chaincode:
                scalar_multiplies += self._addrs_to_generate + 1  # each addr. to generate req. a scalar multiply
            self._passwords_per_second = \
                calc_passwords_per_second(self._checksum_ratio, self._kdf_overhead, scalar_multiplies)
        passwords_per_second = max(int(round(self._passwords_per_second * seconds)), 1)
        # Divide the speed by however many passphrases we are testing for each seed (Otherwise the benchmarking step takes ages)
        return  passwords_per_second / len(self._derivation_salts)



    # Creates a wallet instance from either an mpk, an addresses container and address_limit,
    # or a hash160s container. If none of these were supplied, prompts the user for each.
    # (the BIP32 key derivation path is by default BIP44's account 0)
    @classmethod
    def create_from_params(cls, mpk = None, addresses = None, address_limit = None, hash160s = None, path = None, is_performance = False, address_start_index =  None, force_p2sh = False, checksinglexpubaddress = False, force_p2tr = False):
        self = cls(path, loading=True)

        # Process the mpk (master public key) argument
        if mpk:
            mpk = convert_to_xpub(mpk)
            if not mpk.startswith("xpub"):
                raise ValueError("the BIP32 extended public key must begin with 'xpub, ypub or zpub'" + " " + mpk)
            mpk = base58check_to_bip32(mpk)
            # (it's processed more later)

        # Process the hash160s argument
        if hash160s:
            if mpk:
                print("warning: addressdb is ignored when an mpk is provided", file=sys.stderr)
                hash160s = None
            else:
                self._known_hash160s = hash160s

        # Process the addresses argument
        if addresses:
            if mpk or hash160s:
                print("warning: addresses are ignored when an mpk or addressdb is provided", file=sys.stderr)
                addresses = None
            else:
                self._known_hash160s = self._addresses_to_hash160s(addresses)

        # Process the address_limit argument
        if address_limit:
            if mpk:
                print("warning: address limit is ignored when an mpk is provided", file=sys.stderr)
                address_limit = None
            else:
                address_limit = int(address_limit)
                if address_limit <= 0:
                    raise ValueError("the address limit must be > 0")
                # (it's assigned to self._addrs_to_generate later)

        if address_start_index:
            self._address_start_index = address_start_index
            if address_limit < 0:
                raise ValueError("the address limit must zero or positive")
        else:
            self._address_start_index = 0

        # Set other wallet parameters
        self.force_p2sh = force_p2sh
        self.checksinglexpubaddress = checksinglexpubaddress
        self.force_p2tr = force_p2tr

        # If mpk, addresses, and hash160s arguments were all not provided, prompt the user for an mpk first
        if not mpk and not addresses and not hash160s:
            init_gui()
            while True:
                if tk_root:  # Skip if TK is not available...
                    mpk = tk.simpledialog.askstring("Master extended public key",
                        "Please enter your account extended public key (xpub, ypub or zpub) if you "
                        "have it, or click Cancel to search by an address instead:",
                        initialvalue=self._performance_xpub() if is_performance else None)
                else:
                    print("Error: No MPK or addresses specified... Exiting...")
                    exit()

                if not mpk:
                    break  # if they pressed Cancel, stop prompting for an mpk
                mpk = mpk.strip()
                try:
                    mpk = convert_to_xpub(mpk)
                    if not mpk.startswith("xpub"):
                        raise ValueError("not a BIP32 extended public key (doesn't start with 'xpub', 'ypub' or 'zpub')")
                    mpk = base58check_to_bip32(mpk)
                    break
                except ValueError as e:
                    tk.messagebox.showerror("Master extended public key", "The entered key is invalid ({})".format(e))

        # If an mpk has been provided (in the function call or from a user), extract the
        # required chaincode and adjust the path to match the mpk's depth and child number
        if mpk:
            if mpk.depth == 0:
                print("xpub depth: 0")
                assert mpk.child_number == 0, "child_number == 0 when depth == 0"
            else:
                if mpk.child_number < 2**31:
                    child_num = mpk.child_number
                else:
                    child_num = str(mpk.child_number - 2**31) + "'"
                print("xpub depth:       {}\n"
                      "xpub parent fingerprint: {}\n"
                      "xpub child #:     {}"
                      .format(mpk.depth, base64.b16encode(mpk.fingerprint), child_num))
            self._chaincode = mpk.chaincode
            for i in range(0, len(self._path_indexes)):
                if mpk.depth <= len(self._path_indexes[i]):                  # if this, ensure the path
                    self._path_indexes[i] = self._path_indexes[i][:mpk.depth]   # length matches the depth
                    if self._path_indexes[i] and self._path_indexes[i][-1] != mpk.child_number:
                        if len(self._path_indexes) > 1: #If multiple derivation paths have been specified
                            #Just throw a warning
                            print("WARNING: Derivaton path: " + str(i+1) + " does not match the xpub you have provided.")
                        else:
                            raise ValueError("the extended public key's child # doesn't match "
                                             "the corresponding index of this wallet's path")
                elif mpk.depth == 1 + len(self._path_indexes[i]) and self._append_last_index:
                    self._path_indexes[i] += mpk.child_number,
                else:
                    if len(self._path_indexes) > 1:  # If multiple derivation paths have been specified
                        # Just throw a warning
                        print("WARNING: Derivaton path: " + str(i+1) + " does not match the xpub you have provided.")
                    else:
                        raise ValueError(
                            "the extended public key's depth exceeds the length of this wallet's path ({})"
                            .format(len(self._path_indexes[i])))

        else:  # else if not mpk

            # If we don't have an mpk but need to append the last
            # index, assume it's the external (non-change) chain
            if self._append_last_index:
                for current_path_indexes in self._path_indexes:
                    current_path_indexes += 0,

            # If an mpk Testing Mnemonic:'t provided (at all), and addresses and hash160s arguments also
            # weren't provided (in the original function call), prompt the user for addresses.
            if not addresses and not hash160s:
                # init_gui() was already called above
                self._known_hash160s = None
                while True:
                    addresses = tk.simpledialog.askstring("Addresses",
                        "Please enter at least one address from the first account in your wallet, "
                        "preferably some created early in the account's lifetime:",
                        initialvalue="17LGpN2z62zp7RS825jXwYtE7zZ19Mxxu8" if is_performance else None)
                    if not addresses: break
                    addresses.replace(",", " ")
                    addresses.replace(";", " ")
                    addresses = addresses.split()
                    if not addresses: break
                    try:
                        # (raises ValueError or TypeError on failure):
                        self._known_hash160s = self._addresses_to_hash160s(addresses)
                        break
                    except (ValueError, TypeError) as e:
                        tk.messagebox.showerror("Addresses", "An entered address is invalid ({})".format(e))

                # If there are still no hash160s available (and no mpk), check for an address database before giving up
                if not self._known_hash160s:
                    if os.path.isfile(ADDRESSDB_DEF_FILENAME):
                        print("Using address database file '"+ADDRESSDB_DEF_FILENAME+"' the in current directory.")
                    else:
                        print("notice: address database file '"+ADDRESSDB_DEF_FILENAME+"' does not exist in current directory", file=sys.stderr)
                        sys.exit("canceled")

            # There are some wallets where address generation limit doesn't apply at all...
            if type(self) in [btcrecover.btcrseed.WalletPolkadotSubstrate]:
                address_limit = 1

            if not address_limit:
                init_gui()  # might not have been called yet
                before_the = "one(s) you just entered" if addresses else "first one in actual use"

                suggested_addr_limit = 10
                # There are some wallets where account Generation limit isn't generally relevant, so suggest to set it as 1
                if type(self) in [btcrecover.btcrseed.WalletTron, btcrecover.btcrseed.WalletEthereum, btcrecover.btcrseed.WalletSolana,
                                  btcrecover.btcrseed.WalletCosmos, btcrecover.btcrseed.WalletStellar]:
                    suggested_addr_limit = 1

                if tk_root:  # Skip if TK is not available...
                    address_limit = tk.simpledialog.askinteger("Address limit",
                        "Please enter the address generation limit. Smaller will\n"
                        "be faster, but it must be equal to at least the number\n"
                        "of addresses created before the "+before_the+":\n"
                        "(If unsure, the number below is a sensible default...)", minvalue=1, initialvalue=suggested_addr_limit)
                else:
                    print("No address generation limit specified... Exiting...")
                    exit()

                if not address_limit:
                    sys.exit("canceled")
            self._addrs_to_generate = address_limit

            if not self._known_hash160s:
                print("Loading address database ...")
                self._known_hash160s = AddressSet.fromfile(open(ADDRESSDB_DEF_FILENAME, "rb"))
                print("Loaded", len(self._known_hash160s), "addresses from database ...")

        return self

    #def convert_to_xpub(self, mpk):
    #    convert_to_xpub(mpk)

    # Performs basic checks so that clearly invalid mnemonic_ids can be completely skipped
    @staticmethod
    def verify_mnemonic_syntax(mnemonic_ids):
        # Length must be divisible by 3 and all ids must be present
        return len(mnemonic_ids) % 3 == 0 and None not in mnemonic_ids

    def return_verified_password_or_false(self, mnemonic_ids_list):
        return self._return_verified_password_or_false_opencl(mnemonic_ids_list) if not isinstance(self.opencl_algo,int) \
          else self._return_verified_password_or_false_cpu(mnemonic_ids_list)

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a mnemonic
    # is correct return it, else return False for item 0; return a count of mnemonics checked for item 1
    def _return_verified_password_or_false_cpu(self, mnemonic_ids_list):
        for count, mnemonic_ids in enumerate(mnemonic_ids_list, 1):

            if self.pre_start_benchmark or (not self._checksum_in_generator and not self._skip_worker_checksum):
                # Check the (BIP39 or Electrum2) checksum; most guesses will fail this test (Only required at the benchmark step, this is handled in the password generator now)
                if not self._verify_checksum(mnemonic_ids):
                    continue

            # If we are writing out the checksummed seeds, add them to the queue
            if self._savevalidseeds and not self.pre_start_benchmark:
                self.worker_out_queue.put(mnemonic_ids)
                continue

            # Convert the mnemonic sentence to seed bytes (according to BIP39 or Electrum2)
            _derive_seed_list = self._derive_seed(mnemonic_ids)

            for derived_seed, salt in _derive_seed_list:
                if type(self) is not WalletXLM:
                    seed_bytes = hmac.new("Bitcoin seed".encode('utf-8'), derived_seed, hashlib.sha512).digest()
                else:
                    seed_bytes = derived_seed

                if self._verify_seed(seed_bytes, salt):
                    return mnemonic_ids, count  # found it

        return False, count

    def _return_verified_password_or_false_opencl(self, mnemonic_ids_list):
        cleaned_mnemonic_ids_list = []

        for mnemonic in mnemonic_ids_list:
            if not self._checksum_in_generator and not self._skip_worker_checksum:
                if self._verify_checksum(mnemonic):
                    if (type(self) is WalletElectrum2):
                        cleaned_mnemonic_ids_list.append(self._space.join(mnemonic).encode())
                    else:
                        cleaned_mnemonic_ids_list.append(" ".join(mnemonic).encode())

            else:
                if type(self) is WalletElectrum2:
                    cleaned_mnemonic_ids_list.append(self._space.join(mnemonic).encode())
                else:
                    cleaned_mnemonic_ids_list.append(" ".join(mnemonic).encode())

        for i, salt in enumerate(self._derivation_salts,0):
            if type(self) is WalletElectrum2:
                salt = b"electrum" + salt
            else:
                salt = b"mnemonic" + salt

            clResult = self.opencl_algo.cl_pbkdf2(self.opencl_context_pbkdf2_sha512[i], cleaned_mnemonic_ids_list,
                                                      salt, 2048, 64)

            results = zip(cleaned_mnemonic_ids_list,clResult)

            for cleaned_mnemonic, derived_seed in results:
                if type(self) is not WalletXLM:
                    seed_bytes = hmac.new("Bitcoin seed".encode('utf-8'), derived_seed, hashlib.sha512).digest()
                else:
                    seed_bytes = derived_seed

                if self._verify_seed(seed_bytes, salt):
                    if isinstance(mnemonic_ids_list[0], list):
                        found_mnemonic = cleaned_mnemonic.decode().split(" ")
                    else:
                        found_mnemonic = tuple(cleaned_mnemonic.decode().split(" "))
                    return found_mnemonic, mnemonic_ids_list.index(found_mnemonic) + 1 # found it

        return False, len(mnemonic_ids_list)

    def _verify_seed(self, arg_seed_bytes, salt = None):
        if salt is None:
            salt = self._derivation_salts[0]
        # Derive the chain of private keys for the specified path as per BIP32
        
        if self.checksinglexpubaddress: #Atomic (Eth), MyBitcoinWallet, PT.BTC Wallet Single Address (Does things in a very non-standard way)
            seed_bytes = arg_seed_bytes
            privkey_bytes = seed_bytes[:32] # These wallets basically use the xprv a single private key...
            pubkey = coincurve.PublicKey.from_valid_secret(privkey_bytes).format(compressed = False)
            pubkey_hash160 = self.pubkey_to_hash160(pubkey)
            if pubkey_hash160 in self._known_hash160s:
                privkey_wif = base58.b58encode_check(bytes([0x80]) + privkey_bytes + bytes([0x1]))
                print("Match found on Non-Standard Single Address, Privkey (Bitcoin Base58): ", privkey_wif)
                print("Match found on Non-Standard Single Address, Privkey (Generic Hex): ", privkey_bytes.hex())
                return True

        for current_path_index in self._path_indexes:
            seed_bytes = arg_seed_bytes
            privkey_bytes = seed_bytes[:32]
            chaincode_bytes = seed_bytes[32:]

            for i in current_path_index:
                if i < 2147483648:  # if it's a normal child key, derive the compressed public key
                    try: data_to_hmac = coincurve.PublicKey.from_valid_secret(privkey_bytes).format()
                    except ValueError: break
                else:               # else it's a hardened child key
                    data_to_hmac = b"\0" + privkey_bytes  # prepended "\0" as per BIP32
                data_to_hmac += struct.pack(">I", i)  # append the index (big-endian) as per BIP32

                seed_bytes = hmac.new(chaincode_bytes, data_to_hmac, hashlib.sha512).digest()

                # The child private key is the parent one + the first half of the seed_bytes (mod n)
                privkey_bytes   = int_to_bytes((bytes_to_int(seed_bytes[:32]) +
                                                bytes_to_int(privkey_bytes)) % GENERATOR_ORDER, 32)
                chaincode_bytes = seed_bytes[32:]

            # If an extended public key was provided, check the derived chain code against it
            if self._chaincode:
                if chaincode_bytes == self._chaincode:
                    return True  # found it

            else:
                # (note: the rest assumes the address index isn't hardened)

                # Derive the final public keys, searching for a match with known_hash160s
                # (these first steps below are loop invariants)
                try: data_to_hmac = coincurve.PublicKey.from_valid_secret(privkey_bytes).format()
                except ValueError: break
                privkey_int = bytes_to_int(privkey_bytes)

                for i in range(self._address_start_index, self._address_start_index + self._addrs_to_generate):
                    seed_bytes = hmac.new(chaincode_bytes,
                        data_to_hmac + struct.pack(">I", i), hashlib.sha512).digest()

                    # The final derived private key is the parent one + the first half of the seed_bytes
                    d_privkey_bytes = int_to_bytes((bytes_to_int(seed_bytes[:32]) +
                                                    privkey_int) % GENERATOR_ORDER, 32)

                    if ((current_path_index[0] - 2 ** 31) == 86 or self.force_p2tr):  # BIP86 Derivation Path & address
                        d_pubkey = coincurve.PublicKey.from_valid_secret(d_privkey_bytes)
                        d_pubkey = P2TR_tools._P2TRUtils.TweakPublicKey(d_pubkey)
                        if len(d_pubkey) != 32: return False
                        test_hash160 = d_pubkey
                    else:
                        d_pubkey = coincurve.PublicKey.from_valid_secret(d_privkey_bytes).format(compressed=False)
                        test_hash160 = self.pubkey_to_hash160(
                            d_pubkey)  # Start off assuming that we have a standard BIP44/84 derivation path & address

                        if((current_path_index[0] - 2**31)==49 or self.force_p2sh): #BIP49 Derivation Path & address
                            pubkey_hash160 = self.pubkey_to_hash160(d_pubkey)
                            WITNESS_VERSION = "\x00\x14"
                            witness_program = WITNESS_VERSION.encode() + pubkey_hash160
                            test_hash160 = ripemd160(hashlib.sha256(witness_program).digest())

                    #Basic comparison content for Debugging
                    #for hash160 in self._known_hash160s:
                    #    print("Path: m/", current_path_index[0] - 2**31, "'/", current_path_index[1] - 2**31, "' Testing: ", binascii.hexlify(test_hash160), "against: ", binascii.hexlify(hash160),file=open("HashCheck.txt", "a"))

                    if test_hash160 in self._known_hash160s: #Check if this hash160 is in our list of known hash160s
                            global seedfoundpath
                            seedfoundpath = "m/"
                            for index in current_path_index:
                                if index >= 2147483648:
                                    index -= 2 ** 31
                                    seedfoundpath += str(index) + "'"
                                else:
                                    seedfoundpath += str(index)

                                seedfoundpath += "/"

                            seedfoundpath += str(i)

                            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ": ***MATCHING SEED FOUND***, Matched on Address at derivation path:", seedfoundpath)
                            #print("Found match with Hash160: ", binascii.hexlify(test_hash160))

                            if(len(self._derivation_salts) > 1):
                                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ": ***MATCHING SEED FOUND***, Matched with BIP39 Passphrase:", salt.decode())

                            return True
        return False

    # Returns a dummy xpub for performance testing purposes
    @staticmethod
    def _performance_xpub():
        # an xpub at path m/44'/0'/0', as Mycelium for Android would export
        return "xpub6BgCDhMefYxRS1gbVbxyokYzQji65v1eGJXGEiGdoobvFBShcNeJt97zoJBkNtbASLyTPYXJHRvkb3ahxaVVGEtC1AD4LyuBXULZcfCjBZx"


############### BIP39 ###############

@register_selectable_wallet_class("Bitcoin Standard BIP39/BIP44")
class WalletBIP39(WalletBIP32):
    FIRSTFOUR_TAG = "-firstfour"
    _checksum_in_generator = False

    # Load the wordlists for all languages (actual one to use is selected in config_mnemonic() )
    _language_words = {}
    @classmethod
    def _load_wordlists(cls):
        assert not cls._language_words, "_load_wordlists() should only be called once from the first init()"
        cls._do_load_wordlists("bip39")
        for wordlist_lang in list(cls._language_words):  # takes a copy of the keys so the dict can be safely changed
            wordlist = cls._language_words[wordlist_lang]
            assert len(wordlist) == 2048, "BIP39 wordlist has 2048 words"
            # Special case for the four languages whose words may be truncated to the first four letters
            if wordlist_lang in ("en", "es", "fr", "it", "pt", "cs"):
                cls._language_words[wordlist_lang + cls.FIRSTFOUR_TAG] = [ w[:4] for w in wordlist ]
    #
    @classmethod
    def _do_load_wordlists(cls, name, wordlist_langs = None):
        if not wordlist_langs:
            wordlist_langs = []
            for filename in glob.iglob(os.path.join(wordlists_dir, name + "-??*.txt")):
                wordlist_langs.append(os.path.basename(filename)[len(name)+1:-4])  # e.g. "en", or "zh-hant"
        for lang in wordlist_langs:
            assert lang not in cls._language_words, "wordlist not already loaded"
            cls._language_words[lang] = load_wordlist(name, lang)

    @property
    def word_ids(self): return self._words
    @staticmethod
    def id_to_word(id): return id  # returns a UTF-8 encoded bytestring

    def __init__(self, path = None, loading = False):
        if not path: path = load_pathlist("./derivationpath-lists/BTC.txt")
        super(WalletBIP39, self).__init__(path, loading)
        if not self._language_words:
            self._load_wordlists()
        pbkdf2_library_name = btcrpass.load_pbkdf2_library().__name__  # btcrpass's pbkdf2 library is used in _derive_seed()
        self._kdf_overhead = 0.0026 if pbkdf2_library_name == "hashlib" else 0.013

    def __setstate__(self, state):
        # (Re)load the pbkdf2 library if necessary
        btcrpass.load_pbkdf2_library()
        self.__dict__ = state

    # Converts a mnemonic word from a Python unicode (as produced by load_wordlist())
    # into a bytestring (of type str) in the format required by BIP39
    @staticmethod
    def _unicode_to_bytes(word):
        assert isinstance(word, str)
        return sys.intern(unicodedata.normalize("NFKD", word))

    # Configures the values of four globals used later in config_btcrecover():
    # mnemonic_ids_guess, close_mnemonic_ids, num_inserts, and num_deletes;
    # also selects the appropriate wordlist language to use
    def config_mnemonic(self, mnemonic_guess = None, lang = None, passphrases = [u"",], expected_len = None, closematch_cutoff = 0.65):
        if expected_len:
            if expected_len < 12:
                raise ValueError("minimum BIP39 sentence length is 12 words")
            if expected_len > 24:
                raise ValueError("maximum BIP39 sentence length is 24 words")
            if expected_len % 3 != 0:
                raise ValueError("BIP39 sentence length must be evenly divisible by 3")

        # Do most of the work in this function:
        passphrases = self._config_mnemonic(mnemonic_guess, lang, passphrases, expected_len, closematch_cutoff)

        self._derivation_salts = []

        # The pbkdf2-derived salt, based on the passphrase, as per BIP39 (needed by _derive_seed());
        # first ensure that this version of Python supports the characters present in the passphrase
        for passphrase in passphrases:
            if sys.maxunicode < 65536:  # if this Python is a "narrow" Unicode build
                for c in passphrase:
                    c = ord(c)
                    if 0xD800 <= c <= 0xDBFF or 0xDC00 <= c <= 0xDFFF:
                        raise ValueError("this version of Python doesn't support passphrases with Unicode code points > "+str(sys.maxunicode))

            _derivation_salt = self._unicode_to_bytes(passphrase)

            self._derivation_salts.append(_derivation_salt.encode())

        # Special case for wallets which tell users to record only the first four letters of each word;
        # convert all short words into long ones (intentionally done *after* the finding of close words).
        # Specifically, update self._words and the globals mnemonic_ids_guess and close_mnemonic_ids.
        if self._lang.endswith(self.FIRSTFOUR_TAG):
            long_lang_words = self._language_words[self._lang[:-len(self.FIRSTFOUR_TAG)]]
            assert isinstance(long_lang_words[0], str),  "long words haven't yet been converted into bytes"
            assert isinstance(self._words[0],     str),    "short words have already been converted into bytes"
            assert len(long_lang_words) == len(self._words), "long and short word lists have the same length"
            long_lang_words = [ self._unicode_to_bytes(l) for l in long_lang_words ]
            short_to_long   = { s:l for s,l in zip(self._words, long_lang_words) }
            self._words     = long_lang_words
            #
            global mnemonic_ids_guess  # the to-be-replaced short-words guess
            long_ids_guess = ()        # the new long-words guess
            for short_id in mnemonic_ids_guess:
                long_ids_guess += None if short_id is None else short_to_long[short_id],
            mnemonic_ids_guess = long_ids_guess
            #
            global close_mnemonic_ids
            close_mnemonic_ids_forKeys = copy.deepcopy(close_mnemonic_ids) # Make a copy of the dictionary so that we can edit the keys safely
            if close_mnemonic_ids:
                assert isinstance(iter(close_mnemonic_ids).__next__(),       str), "close word keys have already been converted into bytes"
                assert isinstance(iter(close_mnemonic_ids.values()).__next__()[0][0], str), "close word values have already been converted into bytes"
                for key in close_mnemonic_ids_forKeys.keys():
                    vals = close_mnemonic_ids.pop(key)
                    # vals is a tuple containing length-1 tuples which in turn each contain one word in bytes-format
                    expanded_vals = []
                    for v in vals:
                        expanded_vals.append((short_to_long[v[0]],))

                    close_mnemonic_ids.update({short_to_long[key] : tuple(expanded_vals)})

        # Calculate each word's index in binary (needed by _verify_checksum())
        self._word_to_binary = { word : "{:011b}".format(i) for i,word in enumerate(self._words) }

        # Chances a checksum is valid, e.g. 1/16 for 12 words, 1/256 for 24 words
        self._checksum_ratio = 2.0**( -( len(mnemonic_ids_guess) + num_inserts - num_deletes )//3 )
    #
    def _config_mnemonic(self, mnemonic_guess, lang, passphrases, expected_len, closematch_cutoff):

        # If a mnemonic guess wasn't provided, prompt the user for one
        if not mnemonic_guess:
            init_gui()
            if tk_root:  # Skip if TK is not available...
                mnemonic_guess = tk.simpledialog.askstring("Seed",
                    "Please enter your best guess for your seed (mnemonic):")
            else:
                print("No mnemonic guess specified... Exiting...")
                exit()

            if not mnemonic_guess:
                sys.exit("canceled")

        # Note: this is not in BIP39's preferred encoded form yet, instead it's
        # in the same format as load_wordlist creates (NFC normalized Unicode)
        mnemonic_guess = unicodedata.normalize("NFC", str(mnemonic_guess).lower()).split()
        if len(mnemonic_guess) == 1:  # assume it's a logographic script (no spaces, e.g. Chinese)
            mnemonic_guess = tuple(mnemonic_guess)

        # Select the appropriate wordlist language to use
        if not lang:
            #print("Debug Loaded Languages")
            #for lang, one_languages_words in self._language_words.items():
            #        print(lang)
            language_word_hits = {}  # maps a language id to the # of words found in that language
            for word in mnemonic_guess:
                for lang, one_languages_words in self._language_words.items():
                    if word in one_languages_words:
                        language_word_hits.setdefault(lang, 0)
                        language_word_hits[lang] += 1
            if len(language_word_hits) == 0:
                raise ValueError("can't guess wordlist language: 0 valid words")
            if len(language_word_hits) == 1:
                best_guess = language_word_hits.popitem()
            else:
                sorted_hits = language_word_hits.items()
                #sorted_hits.sort(key=lambda x: x[1])  # sort based on hit count
                sorted_hits = sorted(sorted_hits, key=lambda x: x[1])
                best_guess   = sorted_hits[-1]
                second_guess = sorted_hits[-2]
                # at least 20% must be exclusive to the best_guess language
                if best_guess[1] - second_guess[1] < 0.2 * len(mnemonic_guess):
                    if (best_guess[1] == second_guess[1] and
                        best_guess[0][:2] == second_guess[0][:2] and
                        "-firstfour" in best_guess[0]+second_guess[0]):
                        pass
                    else:
                        raise ValueError("can't guess wordlist language: top best guesses ({}, {}) are too close ({}, {})"
                                     .format(best_guess[0], second_guess[0], best_guess[1], second_guess[1]))
            # at least half must be valid words
            if best_guess[1] < 0.5 * len(mnemonic_guess):
                raise ValueError("can't guess wordlist language: best guess ({}) has only {} valid word(s)"
                                 .format(best_guess[0], best_guess[1]))
            lang = best_guess[0]
        #
        try:
            words = self._language_words[lang]
            self.current_wordlist = words
        except KeyError:  # consistently raise ValueError for any bad inputs
            raise ValueError("can't find wordlist for language code '{}'".format(lang))
        self._lang = lang

        print("Using the '{}' wordlist.".format(lang))

        # Build the mnemonic_ids_guess and pre-calculate similar mnemonic words
        global mnemonic_ids_guess, close_mnemonic_ids
        self._initial_words_valid = True  # start off by assuming they're all valid
        mnemonic_ids_guess        = ()    # the best initial guess (w/no invalid words)
        #
        # close_mnemonic_ids is a dict; each dict key is a mnemonic_id (a string), and
        # each dict value is a tuple containing length 1 tuples, and finally each of the
        # length 1 tuples contains a single mnemonic_id which is similar to the dict's key;
        # e.g.: { "a-word" : ( ("a-ward", ), ("a-work",) ), "other-word" : ... }
        close_mnemonic_ids = {}
        for word in mnemonic_guess:
            close_words = difflib.get_close_matches(word, words, sys.maxsize, closematch_cutoff)
            if close_words:
                if close_words[0] != word:
                    print(u"'{}' was in your guess, but it's not a valid seed word;\n"
                          u"    trying '{}' instead.".format(word, close_words[0]))
                    self._initial_words_valid = False
                mnemonic_ids_guess += self._unicode_to_bytes(close_words[0]),  # *now* convert to BIP39's format
                close_mnemonic_ids[mnemonic_ids_guess[-1]] = \
                    tuple( (self._unicode_to_bytes(w),) for w in close_words[1:] )
            else:
                if __name__ == b"__main__":
                    print(u"'{}' was in your guess, but there is no similar seed word;\n"
                          u"    trying all possible seed words here instead.".format(word))
                else:
                    if word != 'seed_token_placeholder':
                        print(u"'{}' was in your seed, but there is no similar seed word.".format(word))
                self._initial_words_valid = False
                mnemonic_ids_guess += None,

        guess_len = len(mnemonic_ids_guess)
        if not expected_len:  # (this is always explicitly specified for Electrum 2 seeds)
            assert not isinstance(self, WalletElectrum2), "WalletBIP39._config_mnemonic: expected_len is specified for WalletElectrum2 objects"
            if guess_len < 12:
                expected_len = 12
            elif guess_len > 24:
                expected_len = 24
            else:
                off_by = guess_len % 3
                if off_by == 0: # If the supplied guess is a valid length, assume that all words have been supplied
                    expected_len = guess_len
                else: # If less words have been supplied, round up to the nearest valid seed length (Assume words are missing by default)
                    expected_len = guess_len + 3 - off_by

            print("Assuming a", expected_len, "word mnemonic. (This can be overridden with --mnemonic-length)")
            if expected_len not in (12,24):
                print("WARNING: Assuming an uncommon mnemonic length... (Normally 12 or 24) Double check your wallet documentation to see what mnemonic lengths it supports...")

        global num_inserts, num_deletes
        num_inserts = max(expected_len - guess_len, 0)
        num_deletes = max(guess_len - expected_len, 0)
        if num_inserts and not isinstance(self, WalletElectrum2):
            print("Seed sentence was too short, inserting {} word{} into each guess."
                  .format(num_inserts, "s" if num_inserts > 1 else ""))
        if num_deletes:
            print("Seed sentence was too long, deleting {} word{} from each guess."
                  .format(num_deletes, "s" if num_deletes > 1 else ""))

        # Now that we're done with the words in Unicode format,
        # convert them to BIP39's encoding and save for future reference
        self._words = tuple(map(self._unicode_to_bytes, words))

        if passphrases is True:
            init_gui()
            while True:
                if tk_root:  # Skip if TK is not available...
                    entered_passphrase = tk.simpledialog.askstring("Passphrase",
                        "Please enter the passphrase you added when the seed was first created:", show="*")
                else:
                    print("No passphrase specified... Exiting...")
                    exit()

                if not entered_passphrase:
                    sys.exit("canceled")
                if entered_passphrase == tk.simpledialog.askstring("Passphrase", "Please re-enter the passphrase:", show="*"):
                    passphrases = [entered_passphrase, ]
                    break
                tk.messagebox.showerror("Passphrase", "The passphrases did not match, try again.")

        return passphrases

    # Called by WalletBIP32.return_verified_password_or_false() to verify a BIP39 checksum
    def _verify_checksum(self, mnemonic_words):
        # Convert from the mnemonic_words (ids) back to the entropy bytes + checksum
        try:
            bit_string        = "".join(self._word_to_binary[w] for w in mnemonic_words)
        except:
		    # only get here if there was something wrong with the nemonic words
            print ("invalid nemonic sentence: ")
            print (mnemonic_words)
            return False		
        cksum_len_in_bits = len(mnemonic_words) // 3  # as per BIP39
        entropy_bytes     = bytearray()
        for i in range(0, len(bit_string) - cksum_len_in_bits, 8):
            entropy_bytes.append(int(bit_string[i:i+8], 2))
        cksum_int = int(bit_string[-cksum_len_in_bits:], 2)
        #
        # Calculate and verify the checksum
        return ord(hashlib.sha256(entropy_bytes).digest()[:1]) >> 8-cksum_len_in_bits \
               == cksum_int

    # Called by WalletBIP32.return_verified_password_or_false() to create a binary seed
    def _derive_seed(self, mnemonic_words):
        # Note: the words are already in BIP39's normalized form
        seedList = []
        for salt in self._derivation_salts:
            seedList.append(btcrpass.pbkdf2_hmac("sha512", " ".join(mnemonic_words).encode('utf-8'), b"mnemonic" + salt, 2048))

        return zip(seedList,self._derivation_salts)

    # Produces a long stream of differing and incorrect mnemonic_ids guesses (for testing)
    # (uses mnemonic_ids_guess, num_inserts, and num_deletes globals as set by config_mnemonic())
    def performance_iterator(self):
        # This used to just itereate through the entire space, starting at "abandon abandon abandon ..."
        # and "counting" up from there. However "abandon abandon ... abandon about" is actually in use
        # in the blockchain (buggy software or people just messing around), and in address-database
        # mode this creates an unwanted positive hit, so now we have to start with a random prefix.
        length = len(mnemonic_ids_guess) + num_inserts - num_deletes
        assert length >= 12
        prefix = tuple(random.choice(self._words) for i in range(length-4))
        for guess in itertools.product(self._words, repeat=4):
            yield prefix + guess


    def init_opencl_kernel(self):
        # keep btcrseed checks happy
        pass


############### bitcoinj ###############

@register_selectable_wallet_class("Bitcoinj compatible")
class WalletBitcoinj(WalletBIP39):

    def __init__(self, path = None, loading = False):
        # Just calls WalletBIP39.__init__() with a hardcoded path
        if path: raise ValueError("can't specify a BIP32 path with Bitcoinj wallets")
        super(WalletBitcoinj, self).__init__(["m/0'/0/"], loading)

    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(0)
        if wallet_file.read(1) == b"\x0a":  # protobuf field number 1 of type length-delimited
            network_identifier_len = ord(wallet_file.read(1))
            if 1 <= network_identifier_len < 128:
                wallet_file.seek(2 + network_identifier_len)
                if wallet_file.read(1) in b"\x12\x1a":   # field number 2 or 3 of type length-delimited
                    return True
        return False

    # Load a bitcoinj wallet file (the part of it we need, just the chaincode)
    @classmethod
    def load_from_filename(cls, wallet_filename):
        from . import wallet_pb2
        pb_wallet = wallet_pb2.Wallet()
        with open(wallet_filename, "rb") as wallet_file:
            pb_wallet.ParseFromString(wallet_file.read(btcrpass.MAX_WALLET_FILE_SIZE))  # up to 64M, typical size is a few k
        if pb_wallet.encryption_type == wallet_pb2.Wallet.UNENCRYPTED:
            raise ValueError("this bitcoinj wallet is not encrypted")

        # Search for the (one and only) master public extended key (whose path length is 0)
        self = None
        for key in pb_wallet.key:
            if  key.HasField("deterministic_key") and len(key.deterministic_key.path) == 0:
                assert not self, "only one master public extended key is in the wallet file"
                assert len(key.deterministic_key.chain_code) == 32, "chaincode length is 32 bytes"
                self = cls(loading=True)
                self._chaincode = key.deterministic_key.chain_code
                # Because it's the *master* xpub, it has an empty path
                self._path_indexes = ()

        if not self:
            raise ValueError("No master public extended key was found in this bitcoinj wallet file")
        return self

    # Returns a dummy xpub for performance testing purposes
    @staticmethod
    def _performance_xpub():
        # an xpub at path m/0', as Bitcoin Wallet for Android/BlackBerry would export
        return "xpub67tjk7ug7iNivs1f1pmDswDDbk6kRCe4U1AXSiYLbtp6a2GaodSUovt3kNrDJ2q18TBX65aJZ7VqRBpnVJsaVQaBY2SANYw6kgZf4QLCpPu"


############### Electrum2 ###############
# Electron-Cash forked after Electrum 2.7, so this is the option to use with Electron-Cash (And likely other Electrum forks)

@register_selectable_wallet_class('Electrum 2+ or Electron-Cash ("standard" wallets initially created with Electrum 2 or later)')
class WalletElectrum2(WalletBIP39):

    # From Electrum 2.x's mnemonic.py (coalesced)
    CJK_INTERVALS = (
        ( 0x1100,  0x11ff),
        ( 0x2e80,  0x2fdf),
        ( 0x2ff0,  0x2fff),
        ( 0x3040,  0x31ff),
        ( 0x3400,  0x4dbf),
        ( 0x4e00,  0xa4ff),
        ( 0xa960,  0xa97f),
        ( 0xac00,  0xd7ff),
        ( 0xf900,  0xfaff),
        ( 0xff00,  0xffef),
        (0x16f00, 0x16f9f),
        (0x1b000, 0x1b0ff),
        (0x20000, 0x2a6df),
        (0x2a700, 0x2b81f),
        (0x2f800, 0x2fa1d),
        (0xe0100, 0xe01ef))

    # Load the wordlists for all languages (actual one to use is selected in config_mnemonic() )
    @classmethod
    def _load_wordlists(cls):
        assert not cls._language_words, "_load_wordlists() should only be called once from the first init()"
        cls._do_load_wordlists("electrum2")
        cls._do_load_wordlists("bip39", ("en", "es", "ja", "zh-hans"))  # only the four bip39 ones used by Electrum2
        assert all(len(w) >= 1411 for w in cls._language_words.values()), \
               "Electrum2 wordlists are at least 1411 words long" # because we assume a max mnemonic length of 13

    def __init__(self, path = None, loading = False):
        # Just calls WalletBIP39.__init__() with default Electrum path if none specified
        try:
            if not path:
                path = load_pathlist("./derivationpath-lists/Electrum.txt")

            #Throw a warning if someone is attempting to use a BIP39 derivation path with an Electrum wallet
            elif path[2] == '4':
                print("")
                print("* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * ")
                print("WARNINIG: Electrum wallets don't use standard BIP39 derivation Paths..")
                print("          You probably want to use m/0'/0 for a Segwit wallet, m/0 Legacy...")
                print("          (Or just run without --bip32-path to check both types")
                print("* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * ")
                print("")
        except IndexError:
            pass #Handle the error if only valid paths have been passed

        super(WalletElectrum2, self).__init__(path, loading)
        self._checksum_ratio   = 2.0 / 256.0  # 2 in 256 checksums are valid on average
        self._needs_passphrase = None

    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(0)
        data = wallet_file.read(8)
        if data[0] == ord('{'):
            return None  # "maybe yes"
        try:
            data = base64.b64decode(data)
        except TypeError: return False  # "definitely no"
        if data.startswith(b"BIE1"):
            sys.exit("error: Electrum 2.8+ fully-encrypted wallet files cannot be read,\n"
                     "try to recover from your master extended public key or an address instead")
        return False  # "definitely no"

    # Load an Electrum2 wallet file (the part of it we need, just the master public key)
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
        if wallet.get("seed_version") not in (11, 12, 13):  # all 2.x versions as of April 2022
            raise NotImplementedError("Unsupported Electrum2 seed version " + str(seed_version))
        if wallet_type != "standard":
            raise NotImplementedError("Unsupported Electrum2 wallet type: " + wallet_type)

        mpk = needs_passphrase = None
        while True:  # "loops" exactly once; only here so we've something to break out of

            # Electrum 2.7+ standard wallets have a keystore
            keystore = wallet.get("keystore")
            if keystore:
                keystore_type = keystore.get("type", "(not found)")

                # Wallets originally created by an Electrum 2.x version
                if keystore_type == "bip32":
                    mpk = keystore["xpub"]
                    if keystore.get("passphrase"):
                        needs_passphrase = True
                    break

                # Former Electrum 1.x wallet after conversion to Electrum 2.7+ standard-wallet format
                elif keystore_type == "old":
                    # Construct and return a WalletElectrum1 object
                    mpk = base64.b16decode(keystore["mpk"], casefold=True)
                    if len(mpk) != 64:
                        raise ValueError("Electrum1 master public key is not 64 bytes long")
                    self = WalletElectrum1(loading=True)
                    self._master_pubkey = "\x04".encode() + mpk  # prepend the uncompressed tag
                    return self

                else:
                    print("warning: found unsupported keystore type " + keystore_type, file=sys.stderr)

            # Electrum 2.0 - 2.6.4 wallet (of any wallet type)
            mpks = wallet.get("master_public_keys")
            if mpks:
                mpk = list(mpks.values())[0]
                break

            raise RuntimeError("No master public keys found in Electrum2 wallet")

        assert mpk
        wallet = cls.create_from_params(mpk)
        wallet._needs_passphrase = needs_passphrase
        return wallet

    # Converts a mnemonic word from a Python unicode (as produced by load_wordlist())
    # into a bytestring (of type str) via the same method as Electrum 2.x
    @staticmethod
    def _unicode_to_bytes(word):
        assert isinstance(word, str)
        word = unicodedata.normalize("NFKD", word)
        word = filter(lambda c: not unicodedata.combining(c), word)  # Electrum 2.x removes combining marks
        return sys.intern("".join(word))

    def config_mnemonic(self, mnemonic_guess = None, lang = None, passphrases = [u"",], expected_len = None, closematch_cutoff = 0.65):
        if expected_len is None:
            expected_len_specified = False
            if self._needs_passphrase or getattr(self, "_passphrase_recovery", False):
                expected_len = 12
                print("notice: presence of a mnemonic passphrase implies a 12-word long Electrum 2.7+ mnemonic",
                      file=sys.stderr)
            else:
                init_gui()
                if tk_root:  # Skip if TK is not available...
                    if tk.messagebox.askyesno("Electrum 2.x version",
                            "Did you CREATE your wallet with Electrum version 2.7 (released Oct 2 2016) or later? (Or using a fork like Electron-Cash)"
                            "\n\nPlease choose No if you're unsure.",
                            default=tk.messagebox.NO):
                        expected_len = 12
                    else:
                        expected_len = 13
                else:
                    print("No You need to specify expected mnemonic length with this versonof electrum2 wallet.. Exiting...")
                    exit()

            print("Assuming a", expected_len, "word mnemonic. (This can be overridden with --mnemonic-length)")

        else:
            expected_len_specified = True
            if expected_len > 13:
                print("WARNING: Maximum mnemonic length for standard Electrum2 wallets is 13 words, you specified", expected_len)

        if self._needs_passphrase and not passphrase:
            passphrase = True  # tells self._config_mnemonic() to prompt for a passphrase below
            init_gui()
            if tk_root:  # Skip if TK is not available...
                tk.messagebox.showwarning("Passphrase",
                    'This Electrum seed was extended with "custom words" (a seed passphrase) when it '
                    "was first created. You will need to enter it to continue.\n\nNote that this seed "
                    "passphrase is NOT the same as the wallet password that's entered to spend funds.")
            else:
                print("No passphrase specified... Exiting...")
                exit()

        # Calls WalletBIP39's generic version (note the leading _) with the mnemonic
        # length (which for Electrum2 wallets alone is treated only as a maximum length)
        passphrases = self._config_mnemonic(mnemonic_guess, lang, passphrases, expected_len, closematch_cutoff)

        # Python 2.x running Electrum 2.x has a Unicode bug where if there are any code points > 65535,
        # they might be normalized differently between different Python 2 builds (narrow vs. wide Unicode)
        self._derivation_salts = []
        for passphrase in passphrases:
            assert isinstance(passphrase, str)
            if sys.maxunicode < 65536:  # the check for narrow Unicode builds looks for UTF-16 surrogate pairs:
                maybe_buggy = any(0xD800 <= ord(c) <= 0xDBFF or 0xDC00 <= ord(c) <= 0xDFFF for c in passphrase)
            else:                       # the check for wide Unicode builds:
                maybe_buggy = any(ord(c) > 65535 for c in passphrase)
            if maybe_buggy:
                print("warning: due to Unicode incompatibilities, it's strongly recommended\n"
                      "         that you run seedrecover.py on the same computer (or at least\n"
                      "         the same OS) where you created your wallet", file=sys.stderr)

            if expected_len_specified and num_inserts:
                print("notice: for Electrum 2.x, --mnemonic-length is the max length tried, but not necessarily the min",
                      file=sys.stderr)

            # The pbkdf2-derived salt (needed by _derive_seed()); Electrum 2.x is similar to BIP39,
            # however it differs in the iffy(?) normalization procedure and the prepended string
            import string
            passphrase = unicodedata.normalize("NFKD", passphrase)  # problematic w/Python narrow Unicode builds, same as Electrum
            passphrase = passphrase.lower()  # (?)
            passphrase = filter(lambda c: not unicodedata.combining(c), passphrase)  # remove combining marks
            passphrase = "".join(passphrase)
            passphrase = " ".join(passphrase.split())  # replace whitespace sequences with a single ASCII space
            # remove ASCII whitespace between CJK characters (?)
            passphrase = "".join(c for i,c in enumerate(passphrase) if not (
                    c in string.whitespace
                and any(intvl[0] <= ord(passphrase[i-1]) <= intvl[1] for intvl in self.CJK_INTERVALS)
                and any(intvl[0] <= ord(passphrase[i+1]) <= intvl[1] for intvl in self.CJK_INTERVALS)))

            _derivation_salt = passphrase

            self._derivation_salts.append(_derivation_salt.encode())

        # Electrum 2.x doesn't separate mnemonic words with spaces in sentences for any CJK
        # scripts when calculating the checksum or deriving a binary seed (even though this
        # seem inappropriate for some CJK scripts such as Hiragana as used by the ja wordlist)
        self._space = "" if self._lang in ("ja", "zh-hans", "zh-hant") else " "

    # Performs basic checks so that clearly invalid mnemonic_ids can be completely skipped
    @staticmethod
    def verify_mnemonic_syntax(mnemonic_ids):
        # a valid electrum mnemonic is at most 13 words long (and all ids must be present)
        # Some wallets (Cakewallet) also create 24 word seeds that use electrum checksum & derivation.
        return len(mnemonic_ids) in (list(range(1,14)) + [24]) and None not in mnemonic_ids

    # Called by WalletBIP32.return_verified_password_or_false() to verify an Electrum2 checksum
    def _verify_checksum(self, mnemonic_words):
        testDigest = hmac.new("Seed version".encode(), self._space.join(mnemonic_words).encode(), hashlib.sha512) \
            .digest()[0]
        return testDigest in [1,16]

    # Called by WalletBIP32.return_verified_password_or_false() to create a binary seed
    def _derive_seed(self, mnemonic_words):
        # Note: the words are already in Electrum2's normalized form
        seedList = []
        for salt in self._derivation_salts:
            seedList.append(btcrpass.pbkdf2_hmac("sha512", self._space.join(mnemonic_words).encode(), b"electrum" + salt, 2048))

        return zip(seedList,self._derivation_salts)

    # Returns a dummy xpub for performance testing purposes
    @staticmethod
    def _performance_xpub():
        # an xpub at path m, as Electrum would export
        return "xpub661MyMwAqRbcGsUXkGBkytQkYZ6M16bFWwTocQDdPSm6eJ1wUsxG5qty1kTCUq7EztwMscUstHVo1XCJMxWyLn4PP1asLjt4gPt3HkA81qe"


############### Ethereum ###############

@register_selectable_wallet_class('Ethereum Standard BIP39/BIP44 (Or Most EVM Wallets)')
class WalletEthereum(WalletBIP39):

    def __init__(self, path = None, loading = False):
        if not path: path = load_pathlist("./derivationpath-lists/ETH.txt")
        super(WalletEthereum, self).__init__(path, loading)


    def __setstate__(self, state):
        import lib.eth_hash.auto
        super(WalletEthereum, self).__setstate__(state)
        # (re-)load the required libraries after being unpickled

    @classmethod
    def create_from_params(cls, *args, **kwargs):
        self = super(WalletEthereum, cls).create_from_params(*args, **kwargs)
        return self

    @staticmethod
    def _addresses_to_hash160s(addresses):
        hash160s = set()
        for address in addresses:
            if address[:2].lower() == "0x":
                address = address[2:]
            if len(address) != 40:
                raise ValueError("length (excluding any '0x' prefix) of Ethereum addresses must be 40")
            cur_hash160 = base64.b16decode(address, casefold=True)
            if not address.islower():  # verify the EIP55 checksum unless all letters are lowercase
                checksum = keccak(base64.b16encode(cur_hash160).lower())
                for nibble, c in enumerate(address, 0):
                    if c.isalpha() and \
                       c.isupper() != bool(checksum[nibble // 2] & (0b1000 if nibble&1 else 0b10000000)):
                            raise ValueError("invalid EIP55 checksum")
            hash160s.add( (cur_hash160) )
        return hash160s

    @staticmethod
    def pubkey_to_hash160(uncompressed_pubkey):
        """convert from an uncompressed public key to its Ethereum hash160 form

        :param uncompressed_pubkey: SEC 1 EllipticCurvePoint OctetString
        :type uncompressed_pubkey: str
        :return: last 20 bytes of keccak256(raw_64_byte_pubkey)
        :rtype: str
        """
        assert len(uncompressed_pubkey) == 65 and uncompressed_pubkey[0] == 4
        return keccak(uncompressed_pubkey[1:])[-20:]

############### Ethereum Validator ###############

@register_selectable_wallet_class('Ethereum Validator BIP39')
class WalletEthereumValidator(WalletBIP39):

    def __init__(self, path = None, loading = False):
        if not eth2_staking_deposit_available:
            exit("Ethereum Validator Seed Recovery requires the staking-deposit and py_ecc modules, please see the installation documentation at http://btcrecover.readthedocs.io/INSTALL/#staking-deposit for further information")
        super(WalletEthereumValidator, self).__init__(None, loading)

    # Default method for adding addresses, doesn't worry about validating the addresses
    @staticmethod
    def _addresses_to_hash160s(addresses):
        hash160s = set()

        #With Py_Crypto_HD_Wallet type wallets we don't worry about converting to hash160
        # (Minor performancce hit, but not an issue)
        for address in addresses:
            if address[:2].lower() == "0x":
                address = address[2:]
            if len(address) == 96:
                hash160s.add(address)
            else:
                raise ValueError("length (excluding any '0x' prefix) of Ethereum Validator pubkey must be 96")

        return hash160s

    def passwords_per_seconds(self, seconds):
        # Eth2 validator derivation is *very* slow when compared to BIP39, the below figure is a realistic minimum for an i5 laptop from 2021
        return 40 / self._checksum_ratio / self._addrs_to_generate / len(self._derivation_salts)


    def _verify_seed(self, mnemonic, passphrase = None):
        if passphrase:
            testSaltList = [passphrase]
        else:
            testSaltList = self._derivation_salts

        for salt in testSaltList:

            for account_index in range(self._address_start_index, self._address_start_index + self._addrs_to_generate):

                # Set path as EIP-2334 format
                # https://eips.ethereum.org/EIPS/eip-2334
                purpose = '12381'
                coin_type = '3600'
                account = account_index
                withdrawal_key_path = f'm/{purpose}/{coin_type}/{account}/0'
                signing_key_path = f'{withdrawal_key_path}/0'

                signing_sk = mnemonic_and_path_to_key(mnemonic=" ".join(mnemonic), path=signing_key_path,
                                                      password=salt.decode())

                signing_pk = bls.SkToPk(signing_sk)

                if signing_pk.hex() in self._known_hash160s:
                    return True

        return False

    def return_verified_password_or_false(self, mnemonic_list):

        for count, mnemonic in enumerate(mnemonic_list, 1):

            if self.pre_start_benchmark or (not self._checksum_in_generator and not self._skip_worker_checksum):
                # Check the (BIP39 or Electrum2) checksum; most guesses will fail this test (Only required at the benchmark step, this is handled in the password generator now)
                if not self._verify_checksum(mnemonic):
                    continue

            if self._verify_seed(mnemonic):
                return mnemonic, count  # found it

        return False, count

############### Zilliqa ###############

@register_selectable_wallet_class('Zilliqa Standard BIP39/44 (***Ledger Nano CURRENTLY UNSUPPORTED***)')
class WalletZilliqa(WalletBIP39):

    def __init__(self, path = None, loading = False):
        if not path: path = load_pathlist("./derivationpath-lists/ZIL.txt")
        super(WalletZilliqa, self).__init__(path, loading)


    def __setstate__(self, state):
        super(WalletZilliqa, self).__setstate__(state)
        # (re-)load the required libraries after being unpickled

    @classmethod
    def create_from_params(cls, *args, **kwargs):
        self = super(WalletZilliqa, cls).create_from_params(*args, **kwargs)
        return self

    @staticmethod
    def _addresses_to_hash160s(addresses):
        hash160s = set()
        for address in addresses:
            cur_hash160= base64.b16decode(zilliqa_account(address=address).address, casefold=True)

            hash160s.add(cur_hash160)
        return hash160s

    @staticmethod
    def pubkey_to_hash160(uncompressed_pubkey):
        """convert from an uncompressed public key to its Ethereum hash160 form

        :param uncompressed_pubkey: SEC 1 EllipticCurvePoint OctetString
        :type uncompressed_pubkey: str
        :return: last 20 bytes of sha256(raw_64_byte_pubkey)
        :rtype: str
        """
        assert len(uncompressed_pubkey) == 65 and uncompressed_pubkey[0] == 4
        #print(compress_pubkey(uncompressed_pubkey))
        #print(binascii.hexlify(compress_pubkey(uncompressed_pubkey)))
        hash160 = hashlib.sha256(compress_pubkey(uncompressed_pubkey)).digest()[-20:]

        return hash160

############### Cardano ###############

@register_selectable_wallet_class('Cardano Shelly-Era BIP39/44')
class WalletCardano(WalletBIP39):

    def __init__(self, path = None, loading = False):
        super(WalletCardano, self).__init__(None, loading)
        if not path: path = load_pathlist("./derivationpath-lists/ADA.txt")
        self._path_list = path

        self._check_icarus = False
        self._check_ledger = False
        self._check_trezor = False

        for current_path in self._path_list:
            root_node_derivation_type, current_path = current_path.split(":")
            if root_node_derivation_type == "icarus": self._check_icarus = True
            if root_node_derivation_type == "ledger": self._check_ledger = True
            if root_node_derivation_type == "trezor": self._check_trezor = True
            if root_node_derivation_type == "byron":
                print("Byron derivation not currently supported")
                exit()

    def __setstate__(self, state):
        super(WalletCardano, self).__setstate__(state)
        # (re-)load the required libraries after being unpickled

    @classmethod
    def create_from_params(cls, *args, **kwargs):
        kwargs["address_limit"] = 1 #Address limit not relevant in Cardano-Shelly
        self = super(WalletCardano, cls).create_from_params(*args, **kwargs)
        return self

    def passwords_per_seconds(self, seconds):
        if not self._passwords_per_second:
            scalar_multiplies = 0
            for i in self._path_indexes[0]: # Just use the first derivation path for this...
                if i < 2147483648:          # if it's a normal child key
                    scalar_multiplies += 1  # then it requires a scalar multiply
            if not self._chaincode:
                scalar_multiplies += self._addrs_to_generate + 1  # each addr. to generate req. a scalar multiply
            self._passwords_per_second = \
                calc_passwords_per_second(self._checksum_ratio, self._kdf_overhead, scalar_multiplies)
        passwords_per_second = max(int(round(self._passwords_per_second * seconds)), 1)
        # Divide the speed by however many passphrases we are testing for each seed (Otherwise the benchmarking step takes ages)
        return  passwords_per_second / len(self._derivation_salts) / 5

    @staticmethod
    def _addresses_to_hash160s(addresses):
        hash160s = set()

        for address in addresses:
            address_data = bech32.bech32_decode(address)

            if address_data[0] not in ("addr","stake"):
                raise ValueError("Error: Invalid Cardano-Shelly Address: ", address)
            address_hexlist = bech32.convertbits(address_data[1], 5, 8, False)
            addr_hash = ''.join([f'{c:02x}' for c in address_hexlist])

            #hash160s.add(addr_hash)
            hash160s.add(addr_hash[-56:])

        return hash160s

    # Called by WalletCardano.return_verified_password_or_false() to create a binary seed
    def _derive_seed(self, mnemonic_words, passphrase_list = None):
        if not passphrase_list:
            salts = self._derivation_salts
        else:
            salts = passphrase_list

        seedList = []
        for salt in salts:
            if self._check_icarus:
                seedList.append(("icarus",
                                 cardano.generateMasterKey_Icarus(mnemonic=mnemonic_words,
                                                                            passphrase=salt,
                                                                            wordlist=self.current_wordlist,
                                                                            langcode=self._lang,
                                                                            trezor=False)
                                 ,salt))

            if self._check_ledger:
                seedList.append(("ledger",
                                 cardano.generateMasterKey_Ledger(mnemonic=" ".join(mnemonic_words),
                                                                            passphrase=salt)
                                 ,salt))

            if self._check_trezor:
                seedList.append(("trezor",
                                 cardano.generateMasterKey_Icarus(mnemonic=mnemonic_words,
                                                                            passphrase=salt,
                                                                            wordlist=self.current_wordlist,
                                                                            langcode=self._lang,
                                                                            trezor=True)
                                 ,salt))

        return seedList

    def _verify_seed(self, derivation_type, root_node, salt = None):
        if salt is None:
            salt = self._derivation_salts[0]
        # Derive the chain of private keys for the specified path as per BIP32

        for current_path in self._path_list:
            root_node_derivation_type, current_path = current_path.split(":")
            if root_node_derivation_type != derivation_type:
                continue

            # Note:
            # Address generation limit isn't actually relevant for most Cardano wallets, as all "base addresses"
            # include the same account staking key.
            # As such, you can simply derive the stake public key and check against that.
            # (This gives a performance boost, even for an address limit of 1)

            #account_node = cardano.derive_child_keys(root_node, current_path, True)
            ((Stake_kLP, Stake_kRP), Stake_AP, Stake_cP) = cardano.derive_child_keys(root_node, current_path + "/2/0", True)
            stake_pubkeyhash = hashlib.blake2b(Stake_AP, digest_size=28).digest()
            bech32_data = stake_pubkeyhash.hex()
            if bech32_data in self._known_hash160s:  # Check if this hash160 is in our list of known hash160s
                global seedfoundpath
                seedfoundpath = "m/" + current_path

                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                      ": ***MATCHING SEED FOUND***, Matched on Address at derivation path:", seedfoundpath)
                # print("Found match with Hash160: ", binascii.hexlify(test_hash160))

                if (len(self._derivation_salts) > 1):
                    print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                          ": ***MATCHING SEED FOUND***, Matched with BIP39 Passphrase:", salt[8:])

                return True

            # Child key derivation for Cardano is not required (see above) but leaving it here as it might be useful in the future

            # for i in range(self._address_start_index, self._address_start_index + self._addrs_to_generate):
            #
            #    Spend_AP, Spend_cP = cardano.derive_child_keys(account_node, "0/%d"%i, False)
            #    Stake_AP, Stake_cP = cardano.derive_child_keys(account_node, "2/0", False)
            #
            #    spend_pubkeyhash = hashlib.blake2b(Spend_AP, digest_size=28).digest()
            #    stake_pubkeyhash = hashlib.blake2b(Stake_AP, digest_size=28).digest()
            #
            #    bech32_data = (b"\x01" + spend_pubkeyhash + stake_pubkeyhash).hex()
            #    bech32_data = stake_pubkeyhash.hex()
            #
            #    if bech32_data in self._known_hash160s: #Check if this hash160 is in our list of known hash160s
            #            global seedfoundpath
            #            seedfoundpath = "m/" + current_path + "/0/%d"%i
            #
            #            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ": ***MATCHING SEED FOUND***, Matched on Address at derivation path:", seedfoundpath)
            #            #print("Found match with Hash160: ", binascii.hexlify(test_hash160))
            #
            #            if(len(self._derivation_salts) > 1):
            #                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ": ***MATCHING SEED FOUND***, Matched with BIP39 Passphrase:", salt[8:])
            #
            #            return True
        return False


    def return_verified_password_or_false(self, mnemonic_ids_list):
        return self._return_verified_password_or_false_opencl(mnemonic_ids_list) if not isinstance(self.opencl_algo,int) \
          else self._return_verified_password_or_false_cpu(mnemonic_ids_list)

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a mnemonic
    # is correct return it, else return False for item 0; return a count of mnemonics checked for item 1
    def _return_verified_password_or_false_cpu(self, mnemonic_ids_list):
        for count, mnemonic_ids in enumerate(mnemonic_ids_list, 1):

            if self.pre_start_benchmark or (not self._checksum_in_generator and not self._skip_worker_checksum):
                # Check the (BIP39 or Electrum2) checksum; most guesses will fail this test (Only required at the benchmark step, this is handled in the password generator now)
                if not self._verify_checksum(mnemonic_ids):
                    continue

            # If we are writing out the checksummed seeds, add them to the queue
            if self._savevalidseeds and not self.pre_start_benchmark:
                self.worker_out_queue.put(mnemonic_ids)
                continue

            # Convert the mnemonic sentence to seed bytes
            _derive_seed_list = self._derive_seed(mnemonic_ids)

            for derivation_type, derived_seed, salt in _derive_seed_list:
                if self._verify_seed(derivation_type, derived_seed, salt):
                    return mnemonic_ids, count  # found it

        return False, count

    def _return_verified_password_or_false_opencl(self, mnemonic_ids_list):
        checksummed_mnemonic_ids_list = []
        for mnemonic in mnemonic_ids_list:
            if self._verify_checksum(mnemonic):
                checksummed_mnemonic_ids_list.append(mnemonic)

        rootKeys = []

        for i, salt in enumerate(self._derivation_salts,0):
            if self._check_ledger:
                mnemonic_list = []
                for mnemonic in checksummed_mnemonic_ids_list:

                    mnemonic_list.append(" ".join(mnemonic).encode())

                clResult = self.opencl_algo.cl_pbkdf2(self.opencl_context_pbkdf2_sha512[i], mnemonic_list, b"mnemonic"+salt, 2048, 64)

                results = zip(checksummed_mnemonic_ids_list, clResult)

                for mnemonic, result in results:
                    rootKeys.append((mnemonic, "ledger", cardano.generateRootKey_Ledger(result), salt))

            if self._check_icarus or self._check_trezor:
                if self._check_icarus:
                    entropy_list = []
                    for mnemonic in checksummed_mnemonic_ids_list:
                        entropy_list.append(cardano.mnemonic_to_entropy(words=mnemonic,
                                                                        wordlist=self.current_wordlist,
                                                                        langcode=self._lang,
                                                                        trezorDerivation=False))

                    clResult = self.opencl_algo.cl_pbkdf2_saltlist(self.opencl_context_pbkdf2_sha512_saltlist, salt, entropy_list, 4096, 96)

                    results = zip(checksummed_mnemonic_ids_list, clResult)

                    for mnemonic, result in results:
                        rootKeys.append((mnemonic, "icarus", cardano.generateRootKey_Icarus(result), salt))

                if self._check_trezor:
                    entropy_list = []
                    for mnemonic in checksummed_mnemonic_ids_list:
                        entropy_list.append(cardano.mnemonic_to_entropy(words=mnemonic,
                                                                        wordlist=self.current_wordlist,
                                                                        langcode=self._lang,
                                                                        trezorDerivation=True))

                    clResult = self.opencl_algo.cl_pbkdf2_saltlist(self.opencl_context_pbkdf2_sha512_saltlist, salt, entropy_list, 4096, 96)

                    results = zip(checksummed_mnemonic_ids_list, clResult)

                    for mnemonic, result in results:
                        rootKeys.append((mnemonic, "trezor", cardano.generateRootKey_Icarus(result), salt))

            for (mnemonic_full, derivationType, masterkey, salt) in rootKeys:
                if " ".join(mnemonic_full) == "cave table seven there praise limit fat decorate middle gold ten battle trigger luggage demand":
                    print("Derivation Type:", derivationType)
                    (kL, kR), AP, cP = masterkey
                    print("Master Key")
                    print("kL:", kL.hex())
                    print("kR:", kR.hex())
                    print("AP:", AP.hex())
                    print("cP:", cP.hex())

                    print("#Rootkeys:", len(rootKeys))

                if self._verify_seed(derivationType, masterkey, salt):
                    return mnemonic_full, mnemonic_ids_list.index(mnemonic_full)+1  # found it

        return False, len(mnemonic_ids_list)

############### Py_Crypto_HD_Wallet Based Wallets ####################
class WalletPyCryptoHDWallet(WalletBIP39):
    def __init__(self, path = None, loading = False):
        if not py_crypto_hd_wallet_available:
            print()
            print("ERROR: Cannot import py_crypto_hd_wallet which is required for this wallet type, install it via 'pip3 install py_crypto_hd_wallet'")
            exit()

        super(WalletPyCryptoHDWallet, self).__init__(None, loading)


    def __setstate__(self, state):
        super(WalletPyCryptoHDWallet, self).__setstate__(state)
        # (re-)load the required libraries after being unpickled

    @classmethod
    def create_from_params(cls, *args, **kwargs):
        self = super(WalletPyCryptoHDWallet, cls).create_from_params(*args, **kwargs)
        return self

    def passwords_per_seconds(self, seconds):
        if self.opencl:
            exit("Error: Wallet Type does not support OpenCL acceleration")

        if not self._passwords_per_second:
            scalar_multiplies = 0
            for i in self._path_indexes[0]: # Just use the first derivation path for this...
                if i < 2147483648:          # if it's a normal child key
                    scalar_multiplies += 1  # then it requires a scalar multiply
            if not self._chaincode:
                scalar_multiplies += self._addrs_to_generate + 1  # each addr. to generate req. a scalar multiply
            self._passwords_per_second = \
                calc_passwords_per_second(self._checksum_ratio, self._kdf_overhead, scalar_multiplies)
        passwords_per_second = max(int(round(self._passwords_per_second * seconds)), 1)
        # Divide the speed by however many passphrases we are testing for each seed (Otherwise the benchmarking step takes ages)
        return  passwords_per_second / len(self._derivation_salts) / 10

    # Default method for adding addresses, doesn't worry about validating the addresses
    @staticmethod
    def _addresses_to_hash160s(addresses):
        hash160s = set()

        #With Py_Crypto_HD_Wallet type wallets we don't worry about converting to hash160
        # (Minor performancce hit, but not an issue)
        for address in addresses:
            hash160s.add(address)

        return hash160s

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a mnemonic
    # is correct return it, else return False for item 0; return a count of mnemonics checked for item 1
    def return_verified_password_or_false(self, mnemonic_ids_list):

        for count, mnemonic_ids in enumerate(mnemonic_ids_list, 1):

            if self.pre_start_benchmark or (not self._checksum_in_generator and not self._skip_worker_checksum):
                # Check the (BIP39 or Electrum2) checksum; most guesses will fail this test (Only required at the benchmark step, this is handled in the password generator now)
                if not self._verify_checksum(mnemonic_ids):
                    continue

            # If we are writing out the checksummed seeds, add them to the queue
            if self._savevalidseeds and not self.pre_start_benchmark:
                self.worker_out_queue.put(mnemonic_ids)
                continue

            if self._verify_seed(mnemonic_ids):
                return mnemonic_ids, mnemonic_ids_list.index(mnemonic_ids)+1  # found it

        return False, len(mnemonic_ids_list)

############### Solana ###############

@register_selectable_wallet_class('Solana BIP39/44 (Currently only on m/44\'/501\'/0\'/0\' derivation path)')
class WalletSolana(WalletPyCryptoHDWallet):

    def _verify_seed(self, mnemonic, passphrase = None):
        if passphrase:
            testSaltList = [passphrase]
        else:
            testSaltList = self._derivation_salts

        for salt in testSaltList:

            wallet = py_crypto_hd_wallet.HdWalletBipFactory(py_crypto_hd_wallet.HdWalletBip44Coins.SOLANA)

            wallet2 = wallet.CreateFromMnemonic("Solana", mnemonic = " ".join(mnemonic), passphrase = salt.decode())

            for account_index in range(self._address_start_index, self._address_start_index + self._addrs_to_generate):
                wallet2.Generate(addr_num=1, addr_off=0, acc_idx=account_index,
                                 change_idx=py_crypto_hd_wallet.HdWalletBipChanges.CHAIN_EXT)

                testAddress = wallet2.ToDict()['change_key']['address']

                if testAddress in self._known_hash160s:
                    return True

        return False

############### Avax ###############

@register_selectable_wallet_class('Avalanche BIP39/44 (X-Addresses)')
class WalletAvalanche(WalletPyCryptoHDWallet):
    def _verify_seed(self, mnemonic, passphrase = None):
        if passphrase:
           testSaltList = [passphrase]
        else:
           testSaltList = self._derivation_salts

        for salt in testSaltList:

           wallet = py_crypto_hd_wallet.HdWalletBipFactory(py_crypto_hd_wallet.HdWalletBip44Coins.AVAX_X_CHAIN)

           wallet2 = wallet.CreateFromMnemonic("Avalanche", mnemonic = " ".join(mnemonic), passphrase = salt.decode())

           wallet2.Generate(addr_num=self._addrs_to_generate, addr_off=self._address_start_index, acc_idx=0,
                             change_idx=py_crypto_hd_wallet.HdWalletBipChanges.CHAIN_EXT)

           walletDict = wallet2.ToDict()['address']

           for address in walletDict:
               if walletDict[address]['address'] in self._known_hash160s:
                   return True

        return False


############### Stellar ###############

@register_selectable_wallet_class('Stellar BIP39/44')
class WalletStellar(WalletPyCryptoHDWallet):
    def _verify_seed(self, mnemonic, passphrase = None):
        if passphrase:
            testSaltList = [passphrase]
        else:
            testSaltList = self._derivation_salts

        for salt in testSaltList:

            wallet = py_crypto_hd_wallet.HdWalletBipFactory(py_crypto_hd_wallet.HdWalletBip44Coins.STELLAR)

            wallet2 = wallet.CreateFromMnemonic("Stellar", mnemonic = " ".join(mnemonic), passphrase = salt.decode())

            for account_index in range(self._address_start_index, self._address_start_index + self._addrs_to_generate):
                wallet2.Generate(addr_num=1, addr_off=0, acc_idx=account_index,
                                 change_idx=py_crypto_hd_wallet.HdWalletBipChanges.CHAIN_EXT)

                if wallet2.ToDict()['account_key']['address'] in self._known_hash160s:
                    return True

        return False

############### Tron ###############

@register_selectable_wallet_class('Tron BIP39/44')
class WalletTron(WalletPyCryptoHDWallet):

    def _verify_seed(self, mnemonic, passphrase = None):
        if passphrase:
            testSaltList = [passphrase]
        else:
            testSaltList = self._derivation_salts

        for salt in testSaltList:

            wallet = py_crypto_hd_wallet.HdWalletBipFactory(py_crypto_hd_wallet.HdWalletBip44Coins.TRON)

            wallet2 = wallet.CreateFromMnemonic("Tron", mnemonic = " ".join(mnemonic), passphrase = salt.decode())

            for account_index in range(self._address_start_index, self._address_start_index + self._addrs_to_generate):
                wallet2.Generate(addr_num=1, addr_off=0, acc_idx=account_index,
                                 change_idx=py_crypto_hd_wallet.HdWalletBipChanges.CHAIN_EXT)

                address = wallet2.ToDict()['address']['address_0']['address']
                wallet_hex = base58_tools.b58decode_check(address)[1:]
                #print(binascii.hexlify(wallet_hex))
                if wallet_hex in self._known_hash160s:
                    #print("correct:", binascii.hexlify(wallet_hex))
                    return True

        return False

    @staticmethod
    def _addresses_to_hash160s(addresses):
        hash160s = set()
        # Convert Tron addresses back to their equivalant HEX representation

        for address in addresses:
            address_hex = base58_tools.b58decode_check(address)[1:]
            hash160s.add(address_hex)

        return hash160s

############### Polkadot (Substrate) ###############

@register_selectable_wallet_class('Polkdadot Substrate Wallet (sr25519)')
class WalletPolkadotSubstrate(WalletPyCryptoHDWallet):
    substratePaths = [""]

    def __init__(self, path = None, loading = False):
        if not py_crypto_hd_wallet_available:
            print()
            print("ERROR: Cannot import py_crypto_hd_wallet which is required for Polkadot wallets, install it via 'pip3 install py_crypto_hd_wallet'")
            exit()

        if path:
            self.substratePaths = path

        super(WalletPyCryptoHDWallet, self).__init__(None, loading)

    def _verify_seed(self, mnemonic, passphrase = None):
        if passphrase:
            testSaltList = [passphrase]
        else:
            testSaltList = self._derivation_salts

        for salt in testSaltList:
            wallet = py_crypto_hd_wallet.HdWalletSubstrateFactory(py_crypto_hd_wallet.HdWalletSubstrateCoins.POLKADOT)

            wallet2 = wallet.CreateFromMnemonic("PolkadotSubstrate", mnemonic = " ".join(mnemonic), passphrase = salt.decode())

            for path in self.substratePaths:
                wallet2.Generate(path = path)
                if wallet2.ToDict()['key']['address'] in self._known_hash160s:
                  return True
                
        return False

############### Cosmos ###############

@register_selectable_wallet_class('Cosmos BIP44 + Any many other Cosmos Chains (Nym, GravityBridge, etc)')
class WalletCosmos(WalletPyCryptoHDWallet):
    def _verify_seed(self, mnemonic, passphrase = None):
        if passphrase:
           testSaltList = [passphrase]
        else:
           testSaltList = self._derivation_salts

        for salt in testSaltList:

           wallet = py_crypto_hd_wallet.HdWalletBipFactory(py_crypto_hd_wallet.HdWalletBip44Coins.COSMOS)

           wallet2 = wallet.CreateFromMnemonic("Cosmos", mnemonic = " ".join(mnemonic), passphrase = salt.decode())

           for account_index in range(self._address_start_index, self._address_start_index + self._addrs_to_generate):
               wallet2.Generate(addr_num=1, addr_off=0, acc_idx=account_index,
                                change_idx=py_crypto_hd_wallet.HdWalletBipChanges.CHAIN_EXT)

               if wallet2.ToDict()['address']['address_0']['address'] in self._known_hash160s:
                   return True

        return False

    # Override method for adding addresses, allows easy use of Cosmos Clones (
    @staticmethod
    def _addresses_to_hash160s(addresses):
        hash160s = set()

        #With Py_Crypto_HD_Wallet type wallets we don't worry about converting to hash160
        # (Minor performancce hit, but not an issue)
        for address in addresses:
            hrp, pkey = bech32.bech32_decode(address)

            # Basically just convert all addresses to the equivalent cosmos address
            cosmos_address = bech32.bech32_encode('cosmos', pkey)

            hash160s.add(cosmos_address)

        return hash160s

############### Tezos ###############

@register_selectable_wallet_class('Tezos BIP44')
class WalletTezos(WalletPyCryptoHDWallet):
    def _verify_seed(self, mnemonic, passphrase = None):
        if passphrase:
            testSaltList = [passphrase]
        else:
            testSaltList = self._derivation_salts

        for salt in testSaltList:

            wallet = py_crypto_hd_wallet.HdWalletBipFactory(py_crypto_hd_wallet.HdWalletBip44Coins.TEZOS)

            wallet2 = wallet.CreateFromMnemonic("Tezos", mnemonic = " ".join(mnemonic), passphrase = salt.decode())

            for account_index in range(self._address_start_index, self._address_start_index + self._addrs_to_generate):
                wallet2.Generate(addr_num=1, addr_off=0, acc_idx=account_index,
                                 change_idx=py_crypto_hd_wallet.HdWalletBipChanges.CHAIN_EXT)

                if wallet2.ToDict()['change_key']['address'] in self._known_hash160s:
                    return True

        return False

############### Secret Network ###############

@register_selectable_wallet_class('Secret Network BIP44 (Old/Ledger Derivation Path)')
class WalletSecretNetworkOld(WalletPyCryptoHDWallet):
      def _verify_seed(self, mnemonic, passphrase = None):
        if passphrase:
            testSaltList = [passphrase]
        else:
            testSaltList = self._derivation_salts

        for salt in testSaltList:

            wallet = py_crypto_hd_wallet.HdWalletBipFactory(py_crypto_hd_wallet.HdWalletBip44Coins.SECRET_NETWORK_OLD)

            wallet2 = wallet.CreateFromMnemonic("Cosmos", mnemonic = " ".join(mnemonic), passphrase = salt.decode())

            for account_index in range(self._address_start_index, self._address_start_index + self._addrs_to_generate):
                wallet2.Generate(addr_num=1, addr_off=0, acc_idx=account_index,
                                 change_idx=py_crypto_hd_wallet.HdWalletBipChanges.CHAIN_EXT)

                if wallet2.ToDict()['address']['address_0']['address'] in self._known_hash160s:
                    return True

        return False

@register_selectable_wallet_class('Secret Network BIP44 (New Derivation Path)')
class WalletSecretNetworkNew(WalletPyCryptoHDWallet):
      def _verify_seed(self, mnemonic, passphrase = None):
        if passphrase:
            testSaltList = [passphrase]
        else:
            testSaltList = self._derivation_salts

        for salt in testSaltList:

            wallet = py_crypto_hd_wallet.HdWalletBipFactory(py_crypto_hd_wallet.HdWalletBip44Coins.SECRET_NETWORK_NEW)

            wallet2 = wallet.CreateFromMnemonic("Cosmos", mnemonic = " ".join(mnemonic), passphrase = salt.decode())

            for account_index in range(self._address_start_index, self._address_start_index + self._addrs_to_generate):
                wallet2.Generate(addr_num=1, addr_off=0, acc_idx=account_index,
                                 change_idx=py_crypto_hd_wallet.HdWalletBipChanges.CHAIN_EXT)

                if wallet2.ToDict()['address']['address_0']['address'] in self._known_hash160s:
                    return True

        return False


############### MultiverseX ###############

@register_selectable_wallet_class('MultiversX BIP39/44')
class WalletMultiversX(WalletPyCryptoHDWallet):

    def _verify_seed(self, mnemonic, passphrase = None):
        if passphrase:
            testSaltList = [passphrase]
        else:
            testSaltList = self._derivation_salts

        for salt in testSaltList:

            wallet = py_crypto_hd_wallet.HdWalletBipFactory(py_crypto_hd_wallet.HdWalletBip44Coins.ELROND)

            wallet2 = wallet.CreateFromMnemonic("Elrond", mnemonic = " ".join(mnemonic), passphrase = salt.decode())

            wallet2.Generate(addr_num=self._addrs_to_generate, addr_off=self._address_start_index, acc_idx=0,
                                 change_idx=py_crypto_hd_wallet.HdWalletBipChanges.CHAIN_EXT)

            test_addresses_dicts = wallet2.ToDict()['address']

            test_addresses = test_addresses_dicts.values()

            for test_address in test_addresses:
                if test_address['address'] in self._known_hash160s:
                    return True

        return False


# This uses the PyCryptoHDWallet implementation of Cardano Shelly, which is a bit more limited in terms of derivation path
# and wallet support, but is also several times faster. (ToDo: Implement speed improvement in to other implementation)
#
# ############### pyhd-cardano-shelly-ledger ###############
# @register_selectable_wallet_class('PyCryptoHD-Cardano-Shelly-Ledger')
# class WalletPyCryptoCardanoShellyLedger(WalletPyCryptoHDWallet):
#
#     def _verify_seed(self, mnemonic, passphrase = None):
#         if passphrase:
#             testSaltList = [passphrase]
#         else:
#             testSaltList = self._derivation_salts
#
#         for salt in testSaltList:
#
#             wallet = py_crypto_hd_wallet.HdWalletCardanoShelleyFactory(py_crypto_hd_wallet.HdWalletCardanoShelleyCoins.CARDANO_LEDGER)
#
#             wallet2 = wallet.CreateFromMnemonic("Tron", mnemonic = " ".join(mnemonic), passphrase = salt.decode())
#
#             for account_index in range(self._address_start_index, self._address_start_index + self._addrs_to_generate):
#                 wallet2.Generate(addr_num=1, addr_off=0, acc_idx=account_index,
#                                  change_idx=py_crypto_hd_wallet.HdWalletBipChanges.CHAIN_EXT)
#
#                 if wallet2.ToDict()['address']['address_0']['address'] in self._known_hash160s:
#                     return True
#
#                 if wallet2.ToDict()['staking_key']['address'] in self._known_hash160s:
#                     return True
#
#         return False

############### Helium ###############

@register_selectable_wallet_class('Helium BIP39/44 & Mobile')
class WalletHelium(WalletBIP39):

    def __init__(self, path = None, loading = False):
        if not nacl_available:
            exit("Helium Wallet Requires the nacl module, this can be installed via pip3 install pynacl")
        if not bitstring_available:
            exit("Helium Wallet Requires the bitstring module, this can be installed via pip3 install bitstring")
        super(WalletHelium, self).__init__(None, loading)


    def __setstate__(self, state):
        super(WalletHelium, self).__setstate__(state)
        # (re-)load the required libraries after being unpickled

    @classmethod
    def create_from_params(cls, *args, **kwargs):
        kwargs["address_limit"] = 1 #Address limit not relevant in Helium Wallets

        self = super(WalletHelium, cls).create_from_params(*args, **kwargs)
        return self

    def passwords_per_seconds(self, seconds):
        # A bit ugly to put this here, but a good spot in that it only gets called once before anyhting starts...
        if self._savevalidseeds:
            exit("Error: Save Valid Seeds not supported for Helium Wallets")
        if self._checksum_in_generator:
            exit("Error: Checksum in Generator not supported for Helium Wallets")
        if self.opencl:
            exit("Error: Wallet Type does not support OpenCL acceleration")

        return 20000

    @staticmethod
    def _addresses_to_hash160s(addresses):
        hash160s = set()

        for address in addresses:

            address_data = base58.b58decode_check(address)

            hash160s.add(address_data[2:])

        return hash160s

    # Pulled from https://github.com/trezor/python-mnemonic and modified to fix bug in Trezor derivation
    # See https://github.com/trezor/trezor-firmware/pull/1388
    def _verify_seed(self, words: Union[List[str], str]):
        wordlist = self.current_wordlist
        langcode = self._lang
        if not isinstance(words, tuple) and not isinstance(words, list):
            words = words.split(" ")
        if len(words) not in [12, 15, 18, 21, 24]:
            raise ValueError(
                "Number of words must be one of the following: [12, 15, 18, 21, 24], but it is not (%d)."
                % len(words)
            )
        # Look up all the words in the list and construct the
        # concatenation of the original entropy and the checksum.
        concatLenBits = len(words) * 11
        concatBits = [False] * concatLenBits
        wordindex = 0
        if langcode == "en":
            use_binary_search = True
        else:
            use_binary_search = False
        for word in words:
            # Find the words index in the wordlist
            ndx = (
                binary_search(wordlist, word)
                if use_binary_search
                else wordlist.index(word)
            )
            if ndx < 0:
                raise LookupError('Unable to find "%s" in word list.' % word)
            # Set the next 11 bits to the value of the index.
            for ii in range(11):
                concatBits[(wordindex * 11) + ii] = (ndx & (1 << (10 - ii))) != 0
            wordindex += 1
        checksumLengthBits = concatLenBits // 33
        entropyLengthBits = concatLenBits - checksumLengthBits
        # Extract original entropy as bytes.
        entropy = bytearray(entropyLengthBits // 8)

        for ii in range(len(entropy)):
            for jj in range(8):
                if concatBits[(ii * 8) + jj]:
                    entropy[ii] |= 1 << (7 - jj)
        # Take the digest of the entropy.
        hashBytes = hashlib.sha256(entropy).digest()
        hashBits = list(
            itertools.chain.from_iterable(
                [c & (1 << (7 - i)) != 0 for i in range(8)] for c in hashBytes
            )
        )

        # Need to just keep a copy of the BIP39 checksum
        entropyLengthBits = concatLenBits - checksumLengthBits
        checksumBits = BitArray(concatBits).bin[-checksumLengthBits:]

        # Mobile wallet generates seeds with a checksum of 0000
        if (checksumBits != '0000'):
            # Check all the checksum bits for BIP39 seeds
            for i in range(checksumLengthBits):
                if concatBits[entropyLengthBits + i] != hashBits[i]:
                    if not self._skip_worker_checksum: #Can ignore the checksum if forced
                        return False

        seed = bytes(entropy + entropy)

        public_key, secret_key = nacl.bindings.crypto_sign_seed_keypair(seed)

        if public_key in self._known_hash160s:
            return True

        return False

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a mnemonic
    # is correct return it, else return False for item 0; return a count of mnemonics checked for item 1
    def return_verified_password_or_false(self, mnemonic_ids_list):
        for count, mnemonic_ids in enumerate(mnemonic_ids_list, 1):

            if self._verify_seed(mnemonic_ids):
                return mnemonic_ids, count  # found it

        return False, count


############### BCH ###############

@register_selectable_wallet_class('BCH Standard BIP39/44')
class WalletBCH(WalletBIP39):

    def __init__(self, path = None, loading = False):
        if not path: path = load_pathlist("./derivationpath-lists/BCH.txt")
        super(WalletBCH, self).__init__(path, loading)


    def __setstate__(self, state):
        super(WalletBCH, self).__setstate__(state)
        # (re-)load the required libraries after being unpickled

    @classmethod
    def create_from_params(cls, *args, **kwargs):
        self = super(WalletBCH, cls).create_from_params(*args, **kwargs)
        return self

############### Dash ###############

@register_selectable_wallet_class('Dash Standard BIP39/44')
class WalletDash(WalletBIP39):

    def __init__(self, path = None, loading = False):
        if not path: path = load_pathlist("./derivationpath-lists/DASH.txt")
        super(WalletDash, self).__init__(path, loading)


    def __setstate__(self, state):
        super(WalletDash, self).__setstate__(state)
        # (re-)load the required libraries after being unpickled

    @classmethod
    def create_from_params(cls, *args, **kwargs):
        self = super(WalletDash, cls).create_from_params(*args, **kwargs)
        return self

############### Dogecoin ###############

@register_selectable_wallet_class('Dogecoin Standard BIP39/44')
class WalletDogecoin(WalletBIP39):

    def __init__(self, path = None, loading = False):
        if not path: path = load_pathlist("./derivationpath-lists/DOGE.txt")
        super(WalletDogecoin, self).__init__(path, loading)


    def __setstate__(self, state):
        super(WalletDogecoin, self).__setstate__(state)
        # (re-)load the required libraries after being unpickled

    @classmethod
    def create_from_params(cls, *args, **kwargs):
        self = super(WalletDogecoin, cls).create_from_params(*args, **kwargs)
        return self

############### Vertcoin ###############

@register_selectable_wallet_class('Vertcoin Standard BIP39/44')
class WalletVertcoin(WalletBIP39):

    def __init__(self, path = None, loading = False):
        if not path: path = load_pathlist("./derivationpath-lists/VTC.txt")
        super(WalletVertcoin, self).__init__(path, loading)


    def __setstate__(self, state):
        super(WalletVertcoin, self).__setstate__(state)
        # (re-)load the required libraries after being unpickled

    @classmethod
    def create_from_params(cls, *args, **kwargs):
        self = super(WalletVertcoin, cls).create_from_params(*args, **kwargs)
        return self

############### Litecoin ###############

@register_selectable_wallet_class('Litecoin Standard BIP39/44')
class WalletLitecoin(WalletBIP39):

    def __init__(self, path = None, loading = False):
        if not path: path = load_pathlist("./derivationpath-lists/LTC.txt")
        super(WalletLitecoin, self).__init__(path, loading)


    def __setstate__(self, state):
        super(WalletLitecoin, self).__setstate__(state)
        # (re-)load the required libraries after being unpickled

    @classmethod
    def create_from_params(cls, *args, **kwargs):
        self = super(WalletLitecoin, cls).create_from_params(*args, **kwargs)
        return self

############### Monacoin ###############

@register_selectable_wallet_class('Monacoin Standard BIP39/44')
class WalletMonacoin(WalletBIP39):

    def __init__(self, path = None, loading = False):
        if not path: path = load_pathlist("./derivationpath-lists/MONA.txt")
        super(WalletMonacoin, self).__init__(path, loading)


    def __setstate__(self, state):
        super(WalletMonacoin, self).__setstate__(state)
        # (re-)load the required libraries after being unpickled

    @classmethod
    def create_from_params(cls, *args, **kwargs):
        self = super(WalletMonacoin, cls).create_from_params(*args, **kwargs)
        return self

############### DigiByte ###############

@register_selectable_wallet_class('DigiByte Standard BIP39/44')
class WalletDigiByte(WalletBIP39):

    def __init__(self, path = None, loading = False):
        if not path: path = load_pathlist("./derivationpath-lists/DGB.txt")
        super(WalletDigiByte, self).__init__(path, loading)


    def __setstate__(self, state):
        super(WalletDigiByte, self).__setstate__(state)
        # (re-)load the required libraries after being unpickled

    @classmethod
    def create_from_params(cls, *args, **kwargs):
        self = super(WalletDigiByte, cls).create_from_params(*args, **kwargs)
        return self

############### Groestlcoin  ###############

@register_selectable_wallet_class('Groestlcoin Standard BIP39/44')
class WalletGroestlecoin(WalletBIP39):

    def __init__(self, path = None, loading = False):
        global groestlcoin_hash
        try:
            import groestlcoin_hash
        except ModuleNotFoundError:
            print()
            print("ERROR: Cannot import groestlcoin_hash which is required for GRS wallets, install it via 'pip3 install groestlcoin_hash'")
            exit()

        if not path: path = load_pathlist("./derivationpath-lists/GRS.txt")
        super(WalletGroestlecoin, self).__init__(path, loading)


    def __setstate__(self, state):
        super(WalletGroestlecoin, self).__setstate__(state)
        # (re-)load the required libraries after being unpickled

    @classmethod
    def create_from_params(cls, *args, **kwargs):
        self = super(WalletGroestlecoin, cls).create_from_params(*args, **kwargs)
        return self

############### Ripple  ###############

@register_selectable_wallet_class('Ripple Standard BIP39/44')
class WalletRipple(WalletBIP39):

    def __init__(self, path = None, loading = False):
        if not path: path = load_pathlist("./derivationpath-lists/XRP.txt")
        super(WalletRipple, self).__init__(path, loading)


    def __setstate__(self, state):
        super(WalletRipple, self).__setstate__(state)
        # (re-)load the required libraries after being unpickled

    @classmethod
    def create_from_params(cls, *args, **kwargs):
        self = super(WalletRipple, cls).create_from_params(*args, **kwargs)
        return self

############### Stacks (STX)  ###############

@register_selectable_wallet_class('Stacks Standard BIP39/44')
class WalletStacks(WalletBIP39):

    def __init__(self, path = None, loading = False):
        if not path: path = ["m/44'/5757'/0'/0"]
        super(WalletStacks, self).__init__(path, loading)


    def __setstate__(self, state):
        super(WalletStacks, self).__setstate__(state)
        # (re-)load the required libraries after being unpickled

    @classmethod
    def create_from_params(cls, *args, **kwargs):
        self = super(WalletStacks, cls).create_from_params(*args, **kwargs)
        return self

    @staticmethod
    def _addresses_to_hash160s(addresses):
        hash160s = set()
        for address in addresses:
            ver, hash160 = c32.c32addressDecode(address)
            hash160s.add(binascii.unhexlify(hash160))
        return hash160s

@register_selectable_wallet_class("Stellar (XLM) BIP39")
class WalletXLM(WalletBIP39):
    def __init__(self, path=None, loading=False):
        # Use Stellar's default derivation path if none specified
        if not path: path = ["m/44'/148'"]
        super(WalletXLM, self).__init__(path, loading)

    def _verify_seed(self, arg_seed_bytes, passphrase=None):
        try:
            from slip10 import SLIP10, HARDENED_INDEX
        except ImportError:
            exit(
                "\nERROR: Cannot Load slip10, install it via pip3 install slip10")

        try:
            from stellar_sdk import Keypair
        except ImportError:
            exit(
                "\nERROR: Cannot Load stellar_sdk, install it via pip3 install stellar_sdk")

        """
        Verify whether BIP39-derived seed bytes match a known Stellar address.
        Uses SLIP-0010 / Ed25519 via Trezor python-slip10.
        """
        if passphrase:
            testSaltList = [passphrase]
        else:
            testSaltList = self._derivation_salts

        for salt in testSaltList:

            for account_index in range(self._address_start_index, self._address_start_index + self._addrs_to_generate):

                # Initialize SLIP10 with Ed25519 curve
                slip = SLIP10.from_seed(arg_seed_bytes, curve_name="ed25519")

                # Stellar increments addresses on what is normally the account index. All addresses are also hardened...
                bip, coin = self._path_indexes[0]
                path = [
                    bip,
                    coin,
                    account_index + HARDENED_INDEX
                ]

                derived = slip.get_child_from_path(path)

                # Extract private key (32 bytes)
                privkey = derived.get_privkey_from_path([])

                # Derive Stellar address (G...)
                kp = Keypair.from_raw_ed25519_seed(privkey)
                pubkey = kp.raw_public_key()

                # Check for match
                if pubkey in self._known_hash160s:
                    if salt and len(self._derivation_salts) > 1:
                        print("Passphrase:", salt.decode())
                    return True

        return False

    def _addresses_to_hash160s(self, addresses):
        """
        Override for Stellar: Just store the pubkey (despite the function name)
        """
        try:
            from stellar_sdk import StrKey
        except ImportError:
            exit(
                "\nERROR: Cannot Load stellar_sdk, install it via pip3 install stellar_sdk")

        hash160s = []

        for addr in addresses:
            try:
                pubkey_bytes = StrKey.decode_ed25519_public_key(addr)
                hash160s.append(pubkey_bytes)
            except Exception as e:
                print(f"Warning: Could not decode Stellar address '{addr}': {e}")
                continue

        return hash160s

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
def run_btcrecover(typos, big_typos = 0, min_typos = 0, is_performance = False, extra_args = [], tokenlist = None, passwordlist = None, listpass = None, min_tokens = None, max_tokens = None, mnemonic_length = None, seed_transform_wordswaps = None, keep_tokens_order = False):
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

    # Start building the command-line arguments
    btcr_args = "--typos " + str(typos)

    if tokenlist:
        btcr_args += " --tokenlist " + str(tokenlist)

        if max_tokens:
            btcr_args += " --max-tokens " + str(max_tokens)
        else:
            btcr_args += " --max-tokens " + str(big_typos)

        if min_tokens:
            btcr_args += " --min-tokens " + str(min_tokens)
        else:
            btcr_args += " --min-tokens " + str(big_typos)

        btcr_args += " --seedgenerator"
        btcr_args += " --mnemonic-length " + str(mnemonic_length)

    if keep_tokens_order:
        btcr_args += " --keep-tokens-order"

    if passwordlist:
        btcr_args += " --passwordlist " + str(passwordlist)
        btcr_args += " --seedgenerator"

    if listpass:
        btcr_args += " --listpass"

    if is_performance:
        btcr_args += " --performance"
        # These typos are not supported by seedrecover with --performance testing:
        l_num_inserts = l_num_deletes = num_wrong = 0

    if seed_transform_wordswaps:
        btcr_args += " --seed-transform-wordswaps " + str(seed_transform_wordswaps)

    # First, check if there are any required typos (if there are missing or extra
    # words in the guess) and adjust the max number of other typos to later apply

    any_typos  = typos  # the max number of typos left after removing required typos
    #big_typos =        # the max number of "big" typos after removing required typos (an arg from above)

    if l_num_deletes:  # if the guess is too long (extra words need to be deleted)
        any_typos -= l_num_deletes
        btcr_args += " --typos-deleteword"
        if l_num_deletes < typos:
            btcr_args += " --max-typos-deleteword " + str(l_num_deletes)

    if num_wrong:      # if any of the words were invalid (and need to be replaced)
        any_typos -= num_wrong
        big_typos -= num_wrong
        btcr_args += " --typos-replacewrongword"
        if num_wrong < typos:
            btcr_args += " --max-typos-replacewrongword " + str(num_wrong)

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
        l_btcr_args = btcr_args

        ids_to_try_inserting = None
        if cur_num_inserts:  # if the guess is too short (words need to be inserted)
            l_any_typos -= cur_num_inserts
            l_big_typos -= cur_num_inserts
            # (instead of --typos-insert we'll set inserted_items=ids_to_try_inserting below)
            ids_to_try_inserting = ((id,) for id in loaded_wallet.word_ids)
            l_btcr_args += " --max-adjacent-inserts " + str(cur_num_inserts)
            if cur_num_inserts < typos:
                l_btcr_args += " --max-typos-insert " + str(cur_num_inserts)

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
            l_btcr_args += " --min-typos " + str(min_typos)

        # Next, if the required typos above haven't consumed all available typos
        # (as specified by the function's args), add some "optional" typos

        if l_any_typos:
            l_btcr_args += " --typos-swap"
            if l_any_typos < typos:
                l_btcr_args += " --max-typos-swap " + str(l_any_typos)

            if l_big_typos:  # if there are any big typos left, add the replaceword typo
                l_btcr_args += " --typos-replaceword"
                if l_big_typos < typos:
                    l_btcr_args += " --max-typos-replaceword " + str(l_big_typos)

            # only add replacecloseword typos if they're not already covered by the
            # replaceword typos added above and there exists at least one close word
            num_replacecloseword = l_any_typos - l_big_typos
            if num_replacecloseword > 0 and any(len(ids) > 0 for ids in close_mnemonic_ids.values()):
                l_btcr_args += " --typos-replacecloseword"
                if num_replacecloseword < typos:
                    l_btcr_args += " --max-typos-replacecloseword " + str(num_replacecloseword)

        btcrpass.parse_arguments(
            l_btcr_args.split() + extra_args,
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

def main(argv):
    global loaded_wallet
    loaded_wallet = wallet_type = None
    create_from_params     = {}  # additional args to pass to wallet_type.create_from_params()
    config_mnemonic_params = {}  # additional args to pass to wallet.config_mnemonic()
    phase                  = {}  # if only one phase is requested, the args to pass to run_btcrecover()
    extra_args             = []  # additional args to pass to btcrpass.parse_arguments() (in run_btcrecover())
    listseeds = False

    if argv or "_ARGCOMPLETE" in os.environ:
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument("--wallet",      metavar="FILE",        help="the wallet file")
        parser.add_argument("--wallet-type", metavar="TYPE",        help="if not using a wallet file, the wallet type")
        parser.add_argument("--mpk",         metavar="XPUB-OR-HEX", help="if not using a wallet file, the master public key (xpub, ypub or zpub)")
        parser.add_argument("--addrs",       metavar="ADDRESS",     nargs="+", help="if not using an mpk, address(es) in the wallet")
        parser.add_argument("--addressdb",   metavar="FILE", nargs="?", help="if not using addrs, use a full address database (default: %(const)s)", const=ADDRESSDB_DEF_FILENAME)
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
        parser.add_argument("--checksinglexpubaddress", action="store_true", help="Check non-standard single address wallets (Like Atomic, MyBitcoinWallet, PT.BTC")
        parser.add_argument("--force-p2sh",  action="store_true",   help="Force checking of P2SH segwit addresses for all derivation paths (Required for devices like CoolWallet S if if you are using P2SH segwit accounts on a derivation path that doesn't start with m/49')")
        parser.add_argument("--force-p2tr",  action="store_true",   help="Force checking of P2TR (Taproot) addresses for all derivation paths (Required for wallets like Bitkeep/Bitget that put all accounts on  m/44')")
        parser.add_argument("--pathlist",    metavar="FILE",        help="A list of derivation paths to be searched")
        parser.add_argument("--transform-wordswaps",   type=int, metavar="COUNT", help="Test swapping COUNT pairs of words within the mnemonic")
        parser.add_argument("--skip",        type=int, metavar="COUNT", help="skip this many initial passwords for continuing an interrupted search")
        parser.add_argument("--threads", type=int, metavar="COUNT", help="number of worker threads (default: For CPU Processing, logical CPU cores, for GPU, physical CPU cores)")
        parser.add_argument("--worker",      metavar="ID#(ID#2, ID#3)/TOTAL#",   help="divide the workload between TOTAL# servers, where each has a different ID# between 1 and TOTAL# (You can optionally assign between 1 and TOTAL IDs of work to a server (eg: 1,2/3 will assign both slices 1 and 2 of the 3 to the server...)")
        parser.add_argument("--max-eta",     type=int,              help="max estimated runtime before refusing to even start (default: 168 hours, i.e. 1 week)")
        parser.add_argument("--no-eta",      action="store_true",   help="disable calculating the estimated time to completion")
        parser.add_argument("--no-dupchecks", "-d", action="count", default=0, help="disable duplicate guess checking to save memory; specify up to four times for additional effect")
        parser.add_argument("--no-progress", action="store_true",   help="disable the progress bar")
        parser.add_argument("--no-pause",    action="store_true",   help="never pause before exiting (default: auto)")
        parser.add_argument("--no-gui", action="store_true", help="Force disable the gui elements")
        parser.add_argument("--performance", action="store_true",   help="run a continuous performance test (Ctrl-C to exit)")
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

        # Pass an argument so that btcrpass knows that we are running a seed recovery
        extra_args.append("--btcrseed")

        #Disable Security Warnings if parameter set...
        global disable_security_warnings
        if args.disablesecuritywarnings:
            disable_security_warnings = True
        else:
            disable_security_warnings = False

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
        if args.wallet_type:
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

        if args.transform_wordswaps:
            print("SEED-TRANSFORM: Checking", args.transform_wordswaps, "pairs of swapped words for each possible mnemonic")
            phase["seed_transform_wordswaps"] = args.transform_wordswaps
            
        if args.checksinglexpubaddress:
            create_from_params["checksinglexpubaddress"] = True

        # These arguments and their values are passed on to btcrpass.parse_arguments()
        for argkey in "skip", "threads", "worker", "max_eta":
            if args.__dict__[argkey] is not None:
                extra_args.extend(("--"+argkey.replace("_", "-"), str(args.__dict__[argkey])))


        # These arguments (which have no values) are passed on to btcrpass.parse_arguments()
        for argkey in "no_eta", "no_progress":
            if args.__dict__[argkey]:
                extra_args.append("--"+argkey.replace("_", "-"))

        # Special Case for --no-dupchecks
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

    if phase:
        phases = (phase,)
    # Set reasonable defaults for the search phases
    else:
        # If each guess is very slow, separate out the first two phases
        passwords_per_seconds = loaded_wallet.passwords_per_seconds(1)
        if passwords_per_seconds < 25:
            phases = [ dict(typos=1), dict(typos=2, min_typos=2) ]
        else:
            phases = [ dict(typos=2) ]
        #
        # These two phases are added to all searches
        phases.extend(( dict(typos=1, big_typos=1), dict(typos=2, big_typos=1, min_typos=2) ))
        #
        # Add a final more thorough phase (This one will take a few hours)
        phases.append(dict(typos=2, big_typos=2, min_typos=2, extra_args=["--no-dupchecks"]))

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
