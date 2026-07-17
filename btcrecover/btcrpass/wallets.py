# wallets.py -- btcrecover wallet classes
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

# The wallet classes extracted from _engine.py. This module is imported at the
# very end of _engine.py (see the `from .wallets import *` there), which binds
# the wallet class names back into _engine's namespace and runs their
# @register_wallet_class decorators. Some _engine module globals are reassigned
# at runtime (by load_aes256_library(), load_pbkdf2_library(),
# parse_arguments(), and the security-warning flags); those are always read
# here via `_engine.<name>` attribute access so the current value is used.

from . import _engine

import base64
import binascii
import collections
import datetime
import hashlib
import io
import itertools
import json
import math
import os
import re
import struct
import sys

import btcrecover.opencl_helpers  # binds the `btcrecover` package name (btcrecover.btcrseed etc.)

from ._engine import (
    AES,
    GROUP_ORDER_INT,
    MAX_WALLET_FILE_SIZE,
    Mnemonic,
    _BlockIODecryptionError,
    _base58_bytes,
    _block_io_extract_pubkey,
    bytes_to_int,
    cardano,
    chacha20_poly1305_new,
    error_exit,
    est_entropy_bits,
    hashlib_ripemd160_available,
    int_to_bytes_padded,
    keccak,
    load_aes256_library,
    load_pbkdf2_library,
    module_eth_keyfile_available,
    multiply_pubkey,
    nacl_available,
    privkey_to_pubkey,
    prompt_unicode_password,
    pubkey_from_bytes,
    pubkey_to_bytes,
    register_wallet_class,
    ripemd160,
    shamir_mnemonic_available,
    sjcl_available,
)

# Optional dependencies: bind each only if _engine managed to import it, so the
# wallet code keeps its historical NameError-based fallbacks when one is missing.
try:
    from ._engine import SJCL
except ImportError:
    pass
try:
    from ._engine import ccl_leveldb
except ImportError:
    pass
try:
    from ._engine import eth_keyfile
except ImportError:
    pass
try:
    from ._engine import nacl
except ImportError:
    pass
try:
    from ._engine import EMPTY, FINISHED, INPROGRESS, click, error, shamir_mnemonic, style
except ImportError:
    pass

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
            part_master_key = _engine.aes256_cbc_decrypt(derived_key[:32], self._part_encrypted_master_key[:16], self._part_encrypted_master_key[16:])
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
            part_master_key = _engine.aes256_cbc_decrypt(derived_key[:32], self._part_encrypted_master_key[:16], self._part_encrypted_master_key[16:])
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
        cl_context = _engine.pyopencl.Context(devices)
        #
        # Load and compile the OpenCL program
        # Detect Apple Silicon GPU and pass appropriate build flags.
        # Apple's Metal-based OpenCL translation layer has bugs with 64-bit
        # rotate() and bitselect() built-ins, so the kernel must use
        # portable shift-based fallbacks.
        build_options = "-w"
        for device in devices:
            if "apple" in device.vendor.lower():
                build_options += " -DAPPLE_GPU"
                break
        # The kernel lives in btcrecover/opencl/; this module is
        # btcrecover/btcrpass/wallets.py, so go up two levels to btcrecover/.
        kernel_file = open(os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), "opencl","sha512-bc-kernel.cl"), encoding="ascii", errors="ignore")
        cl_program = _engine.pyopencl.Program(cl_context, kernel_file.read()).build(build_options)
        kernel_file.close()

        #
        # Configure and store for later the OpenCL kernel (the entrance function)
        self._cl_kernel = cl_program.kernel_sha512_bc
        self._cl_kernel.set_scalar_arg_dtypes([None, _engine.numpy.uint32])
        #
        # Check the local_ws sizes
        for i, device in enumerate(devices):
            if local_ws[i] is None: continue
            max_local_ws = self._cl_kernel.get_work_group_info(_engine.pyopencl.kernel_work_group_info.WORK_GROUP_SIZE, device)
            if local_ws[i] > max_local_ws:
                error_exit("--local-ws of", local_ws[i], "exceeds max of", max_local_ws, "for GPU '"+device.name.strip()+"' with Bitcoin Core wallets")

        # Create one command queue and one I/O buffer per device
        self._cl_queues         = []
        self._cl_hashes_buffers = []
        for i, device in enumerate(devices):
            self._cl_queues.append(_engine.pyopencl.CommandQueue(cl_context, device))
            # Each buffer is of len --global-ws * (size-of-sha512-hash-in-bytes == 512 bits / 8 == 64)
            self._cl_hashes_buffers.append(_engine.pyopencl.Buffer(cl_context, _engine.pyopencl.mem_flags.READ_WRITE, global_ws[i] * 64))

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
        hashes = _engine.numpy.empty([sum(self._cl_global_ws), 64], _engine.numpy.uint8)
        for i, password in enumerate(passwords):
            hashes[i] = _engine.numpy.frombuffer(hashlib.sha512(password + self._salt).digest(), _engine.numpy.uint8)

        # Divide up and copy the starting hashes into the OpenCL buffer(s) (one per device) in parallel
        done   = []  # a list of OpenCL event objects
        offset = 0
        for devnum, ws in enumerate(self._cl_global_ws):
            done.append(_engine.pyopencl.enqueue_copy(self._cl_queues[devnum], self._cl_hashes_buffers[devnum],
                                              hashes[offset : offset + ws], is_blocking=False))
            self._cl_queues[devnum].flush()  # Starts the copy operation
            offset += ws
        _engine.pyopencl.wait_for_events(done)

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
            _engine.pyopencl.wait_for_events(done)

        # Perform the last remaining set of iterations (usually fewer then iter_count_chunksize)
        done = []  # a list of OpenCL event objects
        for devnum in range(len(self._cl_devices)):
            done.append(self._cl_kernel(self._cl_queues[devnum], (self._cl_global_ws[devnum],),
                                        None if self._cl_local_ws[devnum] is None else (self._cl_local_ws[devnum],),
                                        self._cl_hashes_buffers[devnum], self._iter_count - self._iter_count_chunksize - i))
            self._cl_queues[devnum].flush()  # Starts the kernel
        _engine.pyopencl.wait_for_events(done)

        # Copy the resulting fully computed hashes back to RAM in parallel
        done   = []  # a list of OpenCL event objects
        offset = 0
        for devnum, ws in enumerate(self._cl_global_ws):
            done.append(_engine.pyopencl.enqueue_copy(self._cl_queues[devnum], hashes[offset : offset + ws],
                                              self._cl_hashes_buffers[devnum], is_blocking=False))
            offset += ws
            self._cl_queues[devnum].flush()  # Starts the copy operation
        _engine.pyopencl.wait_for_events(done)

        # Convert Unicode strings to UTF-8 bytestrings
        passwords = map(lambda p: p.encode("utf_8", "ignore"), arg_passwords)

        # Using the computed hashes, try to decrypt the master key (in CPU)
        for i, password in enumerate(passwords):
            derived_key = hashes[i].tobytes()
            part_master_key = _engine.aes256_cbc_decrypt(derived_key[:32], self._part_encrypted_master_key[:16], self._part_encrypted_master_key[16:])
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
            from .. import bitcoinj_pb2
            global pylibscrypt
            import lib.pylibscrypt as pylibscrypt
            pad_len = wallet_data[-1]
            if isinstance(pad_len, str):
                pad_len = ord(pad_len)

            # Attempt to dump the menemonic from the wallet (standard BitcoinJ file)
            pbdata = wallet_data[:-pad_len]
            pb_wallet = bitcoinj_pb2.Wallet()
            pb_wallet.ParseFromString(bytes(pbdata))
            mnemonic = WalletBitcoinj.extract_mnemonic(pb_wallet)
            logfile.write("Android Wallet Mnemonic: '" + mnemonic.decode() + "' derivation path: m/0'")

    # This just dumps the wallet private keys for Multibit Classic, Multidoge Wallets
    def dump_privkeys_keybackup(self, key1, key2, iv):
        with open(self._dump_privkeys_file, 'a') as logfile:
            decrypted_wallet = _engine.aes256_cbc_decrypt(key1 + key2, iv, self._encrypted_wallet).decode().splitlines()
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
        # Add OpenCL dispatch like other wallet types
        if not isinstance(self.opencl_algo, int):
            return self._return_verified_password_or_false_opencl(orig_passwords)
        else:
            return self._return_verified_password_or_false_cpu(orig_passwords)

    def _return_verified_password_or_false_cpu(self, orig_passwords): # Multibit
        # Copy a few globals into local for a small speed boost
        l_md5                 = hashlib.md5
        l_aes256_cbc_decrypt  = _engine.aes256_cbc_decrypt
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
                    if all(c in _base58_bytes for c in b58_privkey[1:]):
                        # If another AES block is available, decrypt and check it as well to avoid false positives
                        if len(encrypted_block) >= 32:
                            b58_privkey = l_aes256_cbc_decrypt(key1 + key2, encrypted_block[:16], encrypted_block[16:32])
                            if all(c in _base58_bytes for c in b58_privkey):
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
    
    def _return_verified_password_or_false_opencl(self, arg_passwords):
        # Copy a few globals into local for a small speed boost
        l_aes256_cbc_decrypt  = _engine.aes256_cbc_decrypt
        encrypted_block       = self._encrypted_block

        # Convert Unicode strings to UTF-16 bytestrings, truncating each code unit to 8 bits
        passwords = map(lambda p: p.encode("utf_16_le", "ignore")[::2], arg_passwords)

        # Use OpenCL for MD5 computation and AES decryption of first block
        # Returns: match flag (4B) + decrypted block (16B) + key1 (16B) + key2 (16B) + iv (16B) = 68 bytes
        clResult = self.opencl_algo.cl_multibit_md5(self.opencl_context_multibit_md5,
                                                    passwords, self._salt,
                                                    self._encrypted_block[:16])
        # Process results on CPU (further validation of decrypted data)
        for count, derived in enumerate(clResult, 1):
            match_flag = derived[0]
            if not match_flag:
                continue  # skip non-matching results immediately
            # Extract results from OpenCL output
            b58_privkey = derived[4:20]
            key1        = derived[20:36]
            key2        = derived[36:52]
            iv          = derived[52:68]

            # (all this may be fragile, e.g. what if comments or whitespace precede what's expected in future versions?)
            if isinstance(b58_privkey, str):
                b58_privkey = b58_privkey.encode()

            if chr(b58_privkey[0]) in "LK5Q\x0a#":
                #
                # Does it look like a base58 private key (MultiBit, MultiDoge, or oldest-format Android key backup)?
                if b58_privkey[0] in "LK5Q".encode():  # private keys always start with L, K, or 5, or for MultiDoge Q
                    if all(c in _base58_bytes for c in b58_privkey[1:]):
                        # If another AES block is available, decrypt and check it as well to avoid false positives
                        if len(encrypted_block) >= 32:
                            b58_privkey = l_aes256_cbc_decrypt(key1 + key2, encrypted_block[:16], encrypted_block[16:32])
                            if all(c in _base58_bytes for c in b58_privkey):
                                if self._dump_privkeys_file:
                                    self.dump_privkeys_keybackup(key1, key2, iv)
                                return arg_passwords[count - 1], count
                        else:
                            # (when no second block is available, there's a 1 in 300 billion false positive rate here)
                            if self._dump_privkeys_file:
                                self.dump_privkeys_keybackup(key1, key2, iv)
                            return arg_passwords[count - 1], count
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

                        return arg_passwords[count - 1], count
                #
                #  Does it look like a KnC for Android key backup?
                elif b58_privkey == b"# KEEP YOUR PRIV":
                    if isinstance(arg_passwords[count - 1], str):
                        return arg_passwords[count - 1], count
                    if isinstance(arg_passwords[count - 1], bytes):
                        return arg_passwords[count - 1].decode(), count

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
        from .. import bitcoinj_pb2
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
                    return _engine.aes256_cbc_decrypt(aes_key, iv, ciphertext).decode().replace("\\t", "")

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
        return cls._load_from_filedata(filedata, filename=wallet_filename)

    @classmethod
    def _load_from_filedata(cls, filedata, filename=None):
        try:
            from .. import bitcoinj_pb2
        except ModuleNotFoundError:
            raise ValueError(
                "Cannot load protobuf module, unable to process this bitcoinj wallet."
                " Install protobuf with: pip3 install -r requirements.txt"
                " (see https://btcrecover.readthedocs.io/en/latest/INSTALL/)")

        pb_wallet = bitcoinj_pb2.Wallet()
        pb_wallet.ParseFromString(bytes(filedata))

        if pb_wallet.encryption_type == bitcoinj_pb2.Wallet.UNENCRYPTED:
            if filename:
                print("\nWallet Not Encrypted (File: {})".format(filename))
            else:
                print("\nWallet Not Encrypted")
            print("Contains the following Private Keys:")
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
                if filename:
                    print("Warning: {} - ignoring encrypted key of unexpected length ({})".format(filename, encrypted_len), file=sys.stderr)
                else:
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
        from .. import bitcoinj_pb2
        pb_wallet = bitcoinj_pb2.Wallet()
        pb_wallet.ParseFromString(bytes(self.pb_wallet_filedata))
        
        from lib.cashaddress import base58
        with open(self._dump_privkeys_file, 'a') as logfile:
            for key in pb_wallet.key:
                privkey = _engine.aes256_cbc_decrypt(derived_key, key.encrypted_data.initialisation_vector,
                                               key.encrypted_data.encrypted_private_key)[:32]
                privkey_wif = base58.b58encode_check(bytes([0x80]) + privkey + bytes([0x1]))
                logfile.write(privkey_wif + "\n")

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def return_verified_password_or_false(self, passwords): # Bitcoinj
        # Copy a few globals into local for a small speed boost
        l_scrypt             = pylibscrypt.scrypt
        l_aes256_cbc_decrypt = _engine.aes256_cbc_decrypt
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
            mnemonic = _engine.aes256_cbc_decrypt(derived_key, self._mnemonic_iv, self._mnemonic)
            mnemonic = mnemonic.decode()[:-1]
            if mnemonic[-2:-1] != b'\x0c':
                mnemonic = mnemonic.replace('\x0c', "") + " (BIP39 Passphrase In Use, if you don't have it use BIP32 root key to recover wallet)"

            logfile.write("BIP39 Mnemonic: " + mnemonic + "\n")
            master_key = _engine.aes256_cbc_decrypt(derived_key, self._masterkey_encrypted_iv, self._masterkey_encrypted)
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
                    from .. import coinomi_pb2
                except ModuleNotFoundError:
                    return False

                try:
                    wallet_file.seek(0)
                    pb_wallet = coinomi_pb2.Wallet()
                    pb_wallet.ParseFromString(bytes(wallet_file.read()))
                    pockets = pb_wallet.pockets  # Pockets is a fairly unique coinomi key... #This will certainly fail on non-coinomi protobuf wallets in Python 3.9+
                    return True
                except:
                    pass

        return False

    @classmethod
    def _load_from_filedata(cls, filedata, filename=None):
        try:
            from .. import coinomi_pb2
        except ModuleNotFoundError:
            raise ValueError(
                "Cannot load protobuf module, unable to process this Coinomi wallet."
                " Install protobuf with: pip3 install -r requirements.txt"
                " (see https://btcrecover.readthedocs.io/en/latest/INSTALL/)")

        pb_wallet = coinomi_pb2.Wallet()
        pb_wallet.ParseFromString(bytes(filedata))
        if pb_wallet.encryption_type == coinomi_pb2.Wallet.UNENCRYPTED:
            raise ValueError("Coinomi wallet is not encrypted" + (f" ({filename})" if filename else ""))
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
        l_aes256_cbc_decrypt = _engine.aes256_cbc_decrypt
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
            decrypted_data = _engine.aes256_cbc_decrypt(derived_key, self._iv, self._encrypted_data)
            padding_len = decrypted_data[-1]

            from .. import bitcoinj_pb2
            pb_wallet = bitcoinj_pb2.Wallet()
            pb_wallet.ParseFromString(bytes(decrypted_data[:-padding_len]))
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
        l_aes256_cbc_decrypt = _engine.aes256_cbc_decrypt
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
        data   = _engine.aes256_cbc_decrypt(key1 + key2, iv, data)
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
            # _engine.args may be absent entirely (library use), or present but without
            # msigna_keychain (unit tests, or another wallet type's arg parse).
            msigna_keychain = getattr(getattr(_engine, "args", None), "msigna_keychain", None)
            if msigna_keychain:
                wallet_cur = wallet_conn.execute(select + " WHERE name LIKE '%' || ? || '%'", (msigna_keychain,))
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
            part_privkey = _engine.aes256_cbc_decrypt(derived_part1 + derived_part2[:12], part_encrypted_privkey[:16], part_encrypted_privkey[16:])
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
        l_aes256_cbc_decrypt = _engine.aes256_cbc_decrypt
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
                    print("Warning: {} - found unsupported keystore type {}".format(wallet_filename, keystore_type), file=sys.stderr)

            # Electrum 2.7+ multisig or 2fa wallet
            for i in itertools.count(1):
                x = wallet.get("x{}/".format(i))
                if not x: break
                x_type = x.get("type", "(not found)")
                if x_type == "bip32":
                    xprv = x.get("xprv")
                    if xprv: break
                else:
                    print("Warning: {} - found unsupported key type {}".format(wallet_filename, x_type), file=sys.stderr)
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
        l_aes256_cbc_decrypt = _engine.aes256_cbc_decrypt
        part_encrypted_xprv  = self._part_encrypted_data
        iv                   = self._iv

        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        passwords = map(lambda p: p.encode("utf_8", "ignore"), passwords)

        for count, password in enumerate(passwords, 1):
            key  = l_sha256( l_sha256( password ).digest() ).digest()
            xprv = l_aes256_cbc_decrypt(key, iv, part_encrypted_xprv)

            if xprv.startswith(b"xprv") or xprv.startswith(b"zprv"):  # BIP32 extended private key version bytes
                if all(c in _base58_bytes for c in xprv[4:]):
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
        l_aes256_cbc_decrypt  = _engine.aes256_cbc_decrypt
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
            if (padding_len == 12 or padding_len == 13) and privkey_end.endswith(bytes([padding_len]) * padding_len):
                if all(c in _base58_bytes for c in privkey_end[:-padding_len]):
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
        global hmac
        import hmac

        pbkdf2_library_name    = load_pbkdf2_library().__name__
        self._aes_library_name = load_aes256_library().__name__
        self._passwords_per_second = 800 if pbkdf2_library_name == "hashlib" else 140

    def __getstate__(self):
        # The ephemeral public key is stored as serialized bytes (see
        # pubkey_from_bytes), so it pickles cleanly without special handling.
        return self.__dict__.copy()

    def __setstate__(self, state):
        # (Re-)load the required libraries after being unpickled
        global hmac
        import hmac

        load_pbkdf2_library(warnings=False)
        load_aes256_library(warnings=False)
        self.__dict__ = state

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
        self._ephemeral_pubkey = pubkey_to_bytes(pubkey_from_bytes(data[4:37]), compressed=True)
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

        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        passwords = map(lambda p: p.encode("utf_8", "ignore"), passwords)

        for count, password in enumerate(passwords, 1):

            # Derive the ECIES shared public key, and from it, the AES and HMAC keys
            static_privkey = _engine.pbkdf2_hmac("sha512", password, b"", 1024, 64)
            # Electrum uses a 512-bit private key (why?), but libsecp256k1 expects a 256-bit key < group's order:
            static_privkey = int_to_bytes_padded( bytes_to_int(static_privkey) % GROUP_ORDER_INT )
            shared_pubkey  = multiply_pubkey(self._ephemeral_pubkey, static_privkey)
            keys           = hashlib.sha512(shared_pubkey).digest()

            # Check the MAC
            computed_mac = hmac.new(keys[32:], self._all_but_mac, hashlib.sha256).digest()
            if computed_mac == self._mac:
                return password.decode("utf_8", "replace"), count

        return False, count

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def _return_verified_password_or_false_opencl(self, arg_passwords): #Electrum28

        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        passwords = map(lambda p: p.encode("utf_8", "ignore"), arg_passwords)

        clResult = self.opencl_algo.cl_pbkdf2(self.opencl_context_pbkdf2_sha512, passwords, b"", 1024, 64)

        # This list is consumed, so recreated it and zip
        passwords = map(lambda p: p.encode("utf_8", "ignore"), arg_passwords)

        results = zip(passwords, clResult)

        for count, (password, static_privkey) in enumerate(results, 1):
            # Electrum uses a 512-bit private key (why?), but libsecp256k1 expects a 256-bit key < group's order:
            static_privkey = int_to_bytes_padded( bytes_to_int(static_privkey) % GROUP_ORDER_INT )
            shared_pubkey  = multiply_pubkey(self._ephemeral_pubkey, static_privkey)
            keys           = hashlib.sha512(shared_pubkey).digest()

            # Check the MAC
            computed_mac = hmac.new(keys[32:], self._all_but_mac, hashlib.sha256).digest()
            if computed_mac == self._mac:
                return password.decode("utf_8", "replace"), count

        return False, count


############### Blockchain ###############

@register_wallet_class
class WalletBlockchain(object):

    #Some of these strings are concatenated to 10 chars, as a the full string may not fit in the single decrypted block
    matchStrings = b"\"guid\"|\"sharedKey\"|\"double_enc|\"dpasswordh|\"metadataHD|\"options\"|\"address_bo|\"tx_notes\"|\"tx_names\"|\"keys\"|\"hd_wallets|\"paidTo\"|\"tag_names\""

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
        key = _engine.pbkdf2_hmac("sha1", password, salt_and_iv, iter_count, 32)
        decrypted = _engine.aes256_cbc_decrypt(key, salt_and_iv, data)  # CBC mode
        padding = ord(decrypted[-1:])  # ISO 10126 padding length
        # A bit fragile because it assumes the guid is in the first encrypted block,
        # although this has always been the case as of 6/2014 (since 12/2011)
        # As of May 2020, guid no longer appears in the first block, but tx_notes appears there instead
        return decrypted[:-padding] if 1 <= padding <= 16 and re.search(self.matchStrings, decrypted) else None

    #
    # Encryption scheme only used in version 0.0 wallets
    def decrypt_old(self, password, salt_and_iv, data):
        key = _engine.pbkdf2_hmac("sha1", password, salt_and_iv, 1, 32)  # only 1 iteration
        decrypted = _engine.aes256_ofb_decrypt(key, salt_and_iv, data)  # OFB mode
        # The 16-byte last block, reversed, with all but the first byte of ISO 7816-4 padding removed.
        # Note: indexing a bytes object returns an int, so compare to 0 (not b"\0") to drop NULs.
        last_block = tuple(itertools.dropwhile(lambda x: x == 0, decrypted[:15:-1]))
        padding = 17 - len(last_block)  # ISO 7816-4 padding length
        # If padding parsing succeeded, accept; otherwise, also accept if the decrypted bytes look
        # like JSON containing one of our matchStrings (handles wallets where ISO 7816-4 padding
        # detection fails but the plaintext is clearly correct).
        if 1 <= padding <= 16 and decrypted[-padding] == 0x80 and \
                re.search(self.matchStrings, decrypted):
            return decrypted[:-padding]
        if re.search(self.matchStrings, decrypted):
            return decrypted
        return None

    # Wrapper around decrypt_current that returns None instead of raising when the
    # data isn't a multiple of the AES block size (which happens for v0.0 wallets
    # encrypted with OFB mode when we speculatively try CBC).
    def _try_decrypt_current(self, password, iv, iter_count, encrypted):
        try:
            return self.decrypt_current(password, iv, iter_count, encrypted)
        except ValueError:
            return None

    # Wrapper around decrypt_old that returns None instead of raising when the
    # decrypted bytes can't be decoded for the matchStrings check.
    def _try_decrypt_old(self, password, iv, encrypted):
        try:
            return self.decrypt_old(password, iv, encrypted)
        except (ValueError, UnicodeDecodeError):
            return None

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
            data = self._try_decrypt_current(password, iv, self._iter_count, encrypted)
        else:           # v0.0 wallets have three different possible encryption schemes
            data = self._try_decrypt_current(password, iv, 10, encrypted) or \
                   self._try_decrypt_current(password, iv, 1, encrypted) or \
                   self._try_decrypt_old(password, iv, encrypted)

        if not data:
            print("Warning: Failed to decrypt wallet for dumping (unknown encryption scheme)")
            return

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
                        # Legacy v3 format: xpriv directly on the account
                        if 'xpriv' in accounts:
                            logfile.write(accounts['xpriv'] + "\n")
                        # v4+ format: one xpriv per derivation/script-type
                        for derivation in accounts.get('derivations', []):
                            if 'xpriv' in derivation:
                                logfile.write(derivation['xpriv'] + "\n")
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
            data, iter_count, reason = cls._parse_encrypted_blockchain_wallet(wallet_file.read(MAX_WALLET_FILE_SIZE))  # up to 64M, typical size is a few k
        self = cls(iter_count, loading=True)
        self.detection_reason = reason
        # v2+ wallets have valid JSON structure (definite); v0 wallets are heuristic (possible)
        self.detection_confidence = "definite" if iter_count else "possible"
        self._salt_and_iv     = data[:16]    # only need the salt_and_iv plus
        self._encrypted_block = data[16:32]  # the first 16-byte encrypted block
        self._encrypted_wallet = data
        return self

    # Parse the contents of an encrypted blockchain wallet (v0 - v3) or config file returning three
    # values in a tuple: (encrypted_data_blob, iter_count, detection_reason)
    # detection_reason explains why the file was matched as a Blockchain wallet
    @staticmethod
    def _parse_encrypted_blockchain_wallet(data):
        iter_count = 0
        reason_parts = []

        while True:  # "loops" exactly once; only here so we've something to break out of
            # Most blockchain files (except v0.0 wallets) are JSON encoded; try to parse it as such
            try:
                data = json.loads(data)
                reason_parts.append("valid JSON")
            except ValueError:
                reason_parts.append("not valid JSON, treating as v0 raw data")
                break

            # Config files have no version attribute; they encapsulate the wallet file plus some detrius
            if "version" not in data:
                reason_parts.append("no version field, checking for payload field")
                try:
                    data = data["payload"]  # extract the wallet file from the config
                    reason_parts.append("found payload field")
                except KeyError:
                    raise ValueError("Can't find either version nor payload attributes in Blockchain file")
                try:
                    data = json.loads(data)  # try again to parse a v2.0/v3.0 JSON-encoded wallet file
                    reason_parts.append("payload is valid JSON")
                except ValueError:
                    reason_parts.append("payload is not JSON, treating as v0 raw data")
                    break

            # Extract what's needed from a v2.0/3.0/4 wallet file
            if data["version"] > 4:
                raise NotImplementedError("Unsupported Blockchain wallet version " + str(data["version"]))
            reason_parts.append("version: " + str(data["version"]))
            iter_count = data["pbkdf2_iterations"]
            if not isinstance(iter_count, int) or iter_count < 1:
                raise ValueError("Invalid Blockchain pbkdf2_iterations " + str(iter_count))
            reason_parts.append("pbkdf2_iterations: " + str(iter_count))
            data = data["payload"]

            break

        # Either the encrypted data was extracted from the "payload" field above, or
        # this is a v0.0 wallet file whose entire contents consist of the encrypted data

        # For v0 wallets, verify the raw content is valid base64 (with optional
        # backslash escaping present in some exported wallets). This rules out
        # non-wallet files (Python source, docs, etc.) that happen to contain
        # base64-decodable substrings but are not actual blockchain wallets.
        if not iter_count:  # v0 path - data is raw file content or config payload
            b64_alphabet = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
            ws_chars = set(' \t\n\r\x0b\x0c')
            bad = [c for c in data if c not in b64_alphabet and c not in ws_chars]
            if bad and not all(c == '\\' for c in bad):
                raise ValueError("Doesn't look like an encrypted Blockchain wallet (contains non-base64 characters: " +
                                 ''.join(sorted(set(bad))[:10]) + ")")
            if bad:
                reason_parts.append("backslash chars stripped")

        try:
            data = base64.b64decode(data)
            reason_parts.append("base64 decoded")
        except TypeError as e:
            raise ValueError("Can't base64-decode Blockchain wallet: "+str(e))
        if len(data) < 32:
            raise ValueError("Encrypted Blockchain data is too short")
        reason_parts.append("decoded length: " + str(len(data)) + " bytes")

        # If this is (possibly) a v0.0 (a.k.a. v1) wallet file, check that the encrypted data
        # looks random, otherwise this could be some other type of base64-encoded file such
        # as a MultiBit key file (it should be safe to skip this test for v2.0+ wallets)
        if not iter_count:  # if this is a v0.0 wallet
            # The likelihood of of finding a valid encrypted blockchain wallet (even at its minimum length
            # of about 500 bytes) with less than 7.4 bits of entropy per byte is less than 1 in 10^4
            # (decreased test below to 7.0 after being shown a wallet with 7.0 entropy bits)
            entropy_bits = est_entropy_bits(data)
            if entropy_bits < 7.0:
                raise ValueError("Doesn't look random enough to be an encrypted Blockchain wallet (only {:.1f} bits of entropy per byte)".format(entropy_bits))
            reason_parts.append("entropy: {:.1f} bits/byte".format(entropy_bits))
            reason_parts.append("wallet type: v0")

        reason = ", ".join(reason_parts)
        return data, iter_count, reason  # iter_count == 0 for v0 wallets

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
        # Return True if
        if re.search(self.matchStrings, unencrypted_block):
            if self._savepossiblematches:
                try:
                    return True  # Only return true if we can successfully decode the block in to ascii

                except UnicodeDecodeError:  # Likely a false positive if we can't...
                    with open('possible_passwords.log', 'a', encoding="utf_8") as logfile:
                        logfile.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") +
                                      " Found Likely False Positive Password (with non-Ascii characters in decrypted block) ==>" +
                                      password.decode("utf_8") +
                                      "<== in Decrypted Block ==>" +
                                      unencrypted_block.decode("utf-8", "ignore") +
                                      "<==\n")
                        print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                              "**NOTICE** Possible (Unlikely) Match Found, recorded in possible_passwords.log")

        elif unencrypted_block[0] == ord("{"):
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
                            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                  "**NOTICE** Possible (Unlikely) Match Found, recorded in possible_passwords.log")
                except UnicodeDecodeError:
                    pass

                            

        return False

    def return_verified_password_or_false(self, passwords): # Blockchain.com Main Password
        return self._return_verified_password_or_false_opencl(passwords) if (not isinstance(self.opencl_algo,int)) \
          else self._return_verified_password_or_false_cpu(passwords)

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def _return_verified_password_or_false_cpu(self, arg_passwords): # Blockchain.com Main Password
        # Copy a few globals into local for a small speed boost
        l_pbkdf2_hmac        = _engine.pbkdf2_hmac
        l_aes256_cbc_decrypt = _engine.aes256_cbc_decrypt
        l_aes256_ofb_decrypt = _engine.aes256_ofb_decrypt
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
                    # Decrypt and dump the wallet if required
                    self.decrypt_wallet(password)
                    return password.decode("utf_8", "replace"), count

                unencrypted_block = l_aes256_ofb_decrypt(key, salt_and_iv, encrypted_block)  # OFB mode
                # print("OBF:", unencrypted_block)
                if self.check_blockchain_decrypted_block(unencrypted_block, password):
                    # Decrypt and dump the wallet if required
                    self.decrypt_wallet(password)
                    return password.decode("utf_8", "replace"), count

        return False, count

    def _return_verified_password_or_false_opencl(self, arg_passwords): # Blockchain.com Main Password
        # Copy a few globals into local for a small speed boost
        l_aes256_cbc_decrypt = _engine.aes256_cbc_decrypt
        l_aes256_ofb_decrypt = _engine.aes256_ofb_decrypt
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
                # Decrypt and dump the wallet if required
                self.decrypt_wallet(password)
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
        aeshash = _engine.pbkdf2_hmac("sha1", password, iv, iterations, 32)
        if not legacy_decrypt:
            clear = _engine.aes256_cbc_decrypt(aeshash, iv, encrypted)
        else:
            clear = _engine.aes256_ofb_decrypt(aeshash, iv, encrypted)

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
                    # Legacy v3 format: xpriv directly on the account
                    if 'xpriv' in accounts:
                        accounts['xpriv_decrypted'] = self.decrypt_secondpass_privkey(accounts["xpriv"],
                                                                  self._wallet_json['sharedKey'].encode('ascii') + password,
                                                                  iter_count, legacy_decrypt).decode()
                    # v4+ format: one xpriv per derivation/script-type
                    for derivation in accounts.get('derivations', []):
                        if 'xpriv' in derivation:
                            derivation['xpriv_decrypted'] = self.decrypt_secondpass_privkey(derivation["xpriv"],
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
                        # Legacy v3 format: xpriv directly on the account
                        if 'xpriv_decrypted' in accounts:
                            logfile.write(accounts['xpriv_decrypted']+ "\n")
                        # v4+ format: one xpriv per derivation/script-type
                        for derivation in accounts.get('derivations', []):
                            if 'xpriv_decrypted' in derivation:
                                logfile.write(derivation['xpriv_decrypted']+ "\n")
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
            data, iter_count, _ = cls._parse_encrypted_blockchain_wallet(data)
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
                pubkey_hex = _block_io_extract_pubkey(self.user_key, password)
                if self.user_key['public_key'].encode() == pubkey_hex:
                    return password, count

            except _BlockIODecryptionError:
                pass
            except binascii.Error:
                pass

        return False, count

############### Bitgo User Key ###############

@register_wallet_class
class WalletBitGo(object):
    opencl_algo = -1
    _savepossiblematches = False

    _dump_privkeys_file = None
    _dump_wallet_file = None
    _using_extract = False

    def __init__(self):
        if not sjcl_available:
            exit(
                "\nERROR: Cannot load SJCL module which is required for BitGo wallets... You can install it with the command 'pip3 install sjcl")

    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(0)
        try:
            walletdata = wallet_file.read()
            json.loads(walletdata) # Check if it's a valid JSON
        except: return False

        # Require the quoted SJCL field names rather than bare substrings: "adata" as a bare
        # substring matches inside "metadata", which made ordinary application JSON files
        # (telemetry, i18n, catalogs) detect as BitGo wallets.
        return (b'"adata"' in walletdata and b'"iv"' in walletdata
                and b'"salt"' in walletdata and b'"ct"' in walletdata)

    def passwords_per_seconds(self, seconds):
        return 5

    # Load a Dogechain wallet file
    @classmethod
    def load_from_filename(cls, wallet_filename):
        self = cls()
        with open(wallet_filename, "rb") as wallet_file:
                wallet_data = wallet_file.read()

        self.user_key = json.loads(wallet_data)

        return self

    def difficulty_info(self):
        iter_count = self.user_key['iter']
        hash_function = str(self.user_key['ks'])
        return str(iter_count) + " SHA" + hash_function + " Iterations"

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def return_verified_password_or_false(self, arg_passwords):  # block.io Main Password

        for count, password in enumerate(arg_passwords, 1):
            try:
                key = SJCL().decrypt(self.user_key, password)
                return password, count

            except ValueError:
                pass

        return False, count

############### Dogechain.info ###############

@register_wallet_class
class WalletDogechain(object):
    opencl_algo = -1
    _savepossiblematches = True
    _possible_passwords_file = "possible_passwords.log"

    matchStrings = b"\"guid\"|\"sharedKey\"|\"keys\""

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

        decrypted = AES.new(key, AES.MODE_CBC, self.iv).decrypt(self._encrypted_wallet)
        padding = decrypted[-1]  # ISO 10126 padding length

        # A bit fragile because it assumes the guid is in the first encrypted block,
        return decrypted[:-padding] if 1 <= padding <= 16 and re.search(
            self.matchStrings, decrypted) else None

    def decrypt_wallet(self, password):
        # Can't decrypt or dump an extract in any meaninful way...
        if self._using_extract:
            return

        # If we aren't dumping these files, then just return...
        if not (self._dump_wallet_file or self._dump_privkeys_file):
            return

        if self.aes_cipher == "AES-CBC":
            data = self.decrypt(password)
            if data is None:
                return
        else:  # AES-GCM
            passwordSHA256 = hashlib.sha256(password).digest()
            passwordbase64 = base64.b64encode(passwordSHA256)
            key = hashlib.pbkdf2_hmac('sha256', passwordbase64, self.salt, self._iter_count, 32)
            try:
                data = AES.new(key, AES.MODE_GCM, self.iv).decrypt_and_verify(
                    self._encrypted_wallet, self.aes_auth_tag)
            except ValueError:
                return

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
        isWallet = False
        if (b"email" in walletdata and b"two_fa_method" in walletdata):  # Older Dogechain.info wallets have email and 2fa fields that are fairly unique
            isWallet = True
        elif (b"salt" in walletdata and b"cipher" in walletdata and b"payload" in walletdata):  # Newer Dogechain.info wallets have cipher, salt and payload fields
            isWallet = True
        return isWallet

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
        try:
            self.aes_cipher = wallet_json["cipher"]
        except:
            self.aes_cipher = "AES-CBC"

        if self.aes_cipher == "AES-CBC":
            self.iv = base64.b64decode(wallet_json["payload"])[:16]
            self._encrypted_wallet = base64.b64decode(wallet_json["payload"])[16:]
        else: # AES GCM
            self.iv = base64.b64decode(wallet_json["payload"])[:12]
            self.aes_auth_tag = base64.b64decode(wallet_json["payload"])[12:12+16]
            self._encrypted_wallet = base64.b64decode(wallet_json["payload"])[12+16:]

        self._encrypted_block = self._encrypted_wallet[:32]

        if ";" in wallet_json["payload"]:
            exit("\n**ERROR**\nFound RSA-encrypted Dogechain wallet payload, this means it wasn't downloaded in a way that supports password recovery or decryption... You cannot decrypt this wallet and will need to download it correctly or request your encrypted wallet from dogechain)")

        return self

    @classmethod
    def load_from_data_extract(cls, file_data):
        # These are the same second password hash, salt, iteration count retrieved above
        payload_data, salt, iter_count = struct.unpack(b"< 32s 16s I", file_data)
        self = cls(iter_count, loading=True)
        self.salt = salt
        self._encrypted_wallet = ""
        self.iv = payload_data[:16]
        self._encrypted_block = payload_data[16:]
        self._using_extract = True
        self.aes_cipher = "AES-CBC"
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
            if re.search(self.matchStrings, unencrypted_block):
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

            if self.aes_cipher == "AES-CBC":
                decrypted_block = AES.new(key, AES.MODE_CBC, self.iv).decrypt(self._encrypted_block)

                if self.check_decrypted_block(decrypted_block, password):
                    # Decrypt and dump the wallet if required
                    self.decrypt_wallet(password)
                    return password.decode("utf_8", "replace"), count
            else:
                try:
                    # For AES-GCM we need to decrypt the whole wallet, not just a block,
                    # also don't need to manually check the file contents as verification is part of the decryption
                    decrypted_block = AES.new(key, AES.MODE_GCM, self.iv).decrypt_and_verify(self._encrypted_wallet, self.aes_auth_tag)
                    # Decrypt and dump the wallet if required
                    self.decrypt_wallet(password)
                    return password.decode("utf_8", "replace"), count
                except ValueError:
                    continue

        return False, count

    def _return_verified_password_or_false_opencl(self, arg_passwords):  # dogechain.info Main Password

        # Convert Unicode strings
        passwords = map(lambda p: base64.b64encode(hashlib.sha256(p.encode("utf_8", "ignore")).digest()), arg_passwords)

        clResult = self.opencl_algo.cl_pbkdf2(self.opencl_context_pbkdf2_sha256, passwords, self.salt, self._iter_count, 32)

        # This list is consumed, so recreated it and zip
        passwords = map(lambda p: p.encode("utf_8", "ignore"), arg_passwords)

        results = zip(passwords, clResult)

        for count, (password, key) in enumerate(results, 1):
            if self.aes_cipher == "AES-CBC":
                decrypted_block = AES.new(key, AES.MODE_CBC, self.iv).decrypt(self._encrypted_block)
                if self.check_decrypted_block(decrypted_block, password):
                    # Decrypt and dump the wallet if required
                    self.decrypt_wallet(password)
                    return password.decode("utf_8", "replace"), count
            else:
                try:
                    decrypted_block = AES.new(key, AES.MODE_GCM, self.iv).decrypt_and_verify(self._encrypted_wallet,
                                                                                             self.aes_auth_tag)
                    # Decrypt and dump the wallet if required
                    self.decrypt_wallet(password)
                    return password.decode("utf_8", "replace"), count
                except ValueError:
                    continue

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
                    if "\"salt\"" in data:
                        if data in walletdata_list:
                            continue

                        wallet_data = data[1:-1]

                if b"data" in record.key:
                    data = record.value.decode("utf-8", "ignore").replace("\\", "")
                    if "\"salt\"" in data:
                        walletStartText = "\"vault\""

                        wallet_data_start = data.lower().find(walletStartText)

                        wallet_data_trimmed = data[wallet_data_start:]

                        wallet_data_start = wallet_data_trimmed.find("\"data\"")
                        wallet_data_trimmed = wallet_data_trimmed[wallet_data_start - 1:]

                        wallet_data_end = wallet_data_trimmed.find("}\"}")
                        wallet_data = wallet_data_trimmed[:wallet_data_end + 1]

                        if wallet_data in walletdata_list:
                            continue

                        walletdata_list.append(wallet_data)

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
        elif "keyMetadata" in wallet_data:
            hash_iterations = wallet_json["keyMetadata"]["params"]["iterations"]
            self = cls(hash_iterations, loading=True)
            self.salt = base64.b64decode(wallet_json["salt"])
            self.encrypted_vault = base64.b64decode(wallet_json["data"])
            self.encrypted_block = base64.b64decode(wallet_json["data"])[:16]
            self.iv = base64.b64decode(wallet_json["iv"])
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
        extract_with_iterations = struct.calcsize("< 16s 16s 32s I 1?")
        extract_without_iterations = struct.calcsize("< 16s 16s 32s 1?")

        if len(file_data) == extract_with_iterations:
            encrypted_block, iv, salt, hash_iterations, isMobileWallet = struct.unpack(b"< 16s 16s 32s I 1?", file_data)
        elif len(file_data) == extract_without_iterations:
            encrypted_block, iv, salt, isMobileWallet = struct.unpack(b"< 16s 16s 32s 1?", file_data)
            hash_iterations = 5000 if isMobileWallet else 10000
        else:
            raise ValueError("unrecognized metamask extract format")

        self = cls(hash_iterations, loading=True)
        if isMobileWallet:
            self.salt = salt[:-8]
        else:
            self.salt = salt
        self.encrypted_block = encrypted_block
        self.iv = iv
        self._mobileWallet = isMobileWallet
        self.encrypted_vault = ""
        self._using_extract   = True
        return self

    def difficulty_info(self):
        if not self._mobileWallet:
            return str(self._iter_count) + " PBKDF2-SHA256 iterations"
        else:
            return format(self._iter_count, ",") + " PBKDF2-SHA512 iterations"

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
        "Possible Password ==>btcr-test-password<== in Decrypted Block ==>\"{\\\"mnemonic\\\":<==\n"
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
        global pylibscrypt
        from lib import pylibscrypt

        load_aes256_library(warnings=False)
        self.__dict__ = state

    # Load a Bither wallet file (the part of it we need)
    @classmethod
    def load_from_filename(cls, wallet_filename):
        import sqlite3
        wallet_conn = sqlite3.connect(wallet_filename)

        is_bitcoinj_compatible  = None
        e1 = None
        # Try to find an encrypted loose key first; they're faster to check
        try:
            wallet_cur = wallet_conn.execute("SELECT encrypt_private_key FROM addresses LIMIT 1")
            key_data   = wallet_cur.fetchone()
            if key_data:
                key_data = key_data[0]
                is_bitcoinj_compatible = True  # if found, the KDF & encryption are bitcoinj compatible
            else:
                e1 = "no encrypted keys present in addresses table"
        except sqlite3.OperationalError as e:
            # Python unbinds an "except ... as" name when the block ends, so the
            # message must be copied out for the ValueError raised further below.
            e1 = str(e)
            if e1.startswith("no such table"):
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
        l_aes256_cbc_decrypt = _engine.aes256_cbc_decrypt
        l_sha256             = hashlib.sha256
        hashlib_new          = hashlib.new
        iv_encrypted_key     = self._iv_encrypted_key  # 16-byte iv + encrypted_key
        salt                 = self._salt

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
            privkey = int_to_bytes_padded( bytes_to_int(privkey) % GROUP_ORDER_INT )
            pubkey  = privkey_to_pubkey(privkey, compressed=self._is_compressed)
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
            try:
                clResult = self.opencl_algo.cl_scrypt(self.opencl_context_scrypt, passwords, 14, 3, 3, 64, self.salt)
            except Exception as e:
                # OpenCL buffer allocation can fail under memory pressure (e.g. multiple workers).
                # Fall back to CPU verification for this batch instead of crashing.
                print(f"Warning: OpenCL sCrypt failed ({type(e).__name__}: {e}), falling back to CPU", file=sys.stderr)
                return self._return_verified_password_or_false_cpu(arg_passwords)
            passwords = map(lambda p: normalize("NFC", p).encode("utf_8", "ignore"), arg_passwords)
            results = zip(passwords, clResult)
            for count, (password, scrypthash) in enumerate(results, 1):
                self.decrypted_privkey = bip38decrypt_non_ec(scrypthash, self.enc_privkey, self.has_compression_flag, self.has_lotsequence_flag, network_prefix = self.network.prefix_address)
                if self.decrypted_privkey:
                    print("Decrypted BIP38 Key:", self.decrypted_privkey)
                    return password.decode("utf_8", "replace"), count
        else:
            try:
                clPrefactors = self.opencl_algo.cl_scrypt(self.opencl_context_scrypt, passwords, 14, 3, 3, 32, self.salt)
            except Exception as e:
                print(f"Warning: OpenCL sCrypt failed ({type(e).__name__}: {e}), falling back to CPU", file=sys.stderr)
                return self._return_verified_password_or_false_cpu(arg_passwords)
            passpoints = map(lambda p: prefactor_to_passpoint(p, self.has_lotsequence_flag, self.enc_privkey), clPrefactors)
            encseedbs = map(lambda p: l_scrypt(p, self.enc_privkey[0:12], 1024, 1, 1, 64), passpoints)
            passwords = map(lambda p: normalize("NFC", p).encode("utf_8", "ignore"), arg_passwords)
            results = zip(passwords, clPrefactors, encseedbs)
            for count, (password, prefactor, encseedb) in enumerate(results, 1):
                self.decrypted_privkey = bip38decrypt_ec(prefactor, encseedb, self.enc_privkey, self.has_compression_flag, self.has_lotsequence_flag, network_prefix = self.network.prefix_address)
                if self.decrypted_privkey:
                    print("Decrypted BIP38 Key:", self.decrypted_privkey)
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
                self.decrypted_privkey = bip38decrypt_non_ec(scrypthash, self.enc_privkey, self.has_compression_flag, self.has_lotsequence_flag, network_prefix = self.network.prefix_address)
                if self.decrypted_privkey:
                    print("Decrypted BIP38 Key:", self.decrypted_privkey)
                    return password.decode("utf_8", "replace"), count
            else:
                prefactor = l_scrypt(password, self.salt, 1 << 14, 8, 8, 32)
                passpoint = prefactor_to_passpoint(prefactor, self.has_lotsequence_flag, self.enc_privkey)
                encseedb = l_scrypt(passpoint, self.enc_privkey[0:12], 1024, 1, 1, 64)
                self.decrypted_privkey = bip38decrypt_ec(prefactor, encseedb, self.enc_privkey, self.has_compression_flag, self.has_lotsequence_flag, network_prefix = self.network.prefix_address)
                if self.decrypted_privkey:
                    print("Decrypted BIP38 Key:", self.decrypted_privkey)
                    return password.decode("utf_8", "replace"), count

        return False, count


############### BIP-39 ###############

# @register_wallet_class - not a "registered" wallet since there are no wallet files nor extracts
class WalletBIP39(object):
    opencl_algo = -1
    def __init__(
        self,
        mpk=None,
        addresses=None,
        address_limit=None,
        addressdb_filename=None,
        mnemonic=None,
        lang=None,
        path=None,
        wallet_type="bip39",
        is_performance=False,
        force_p2sh=False,
        checksinglexpubaddress=False,
        force_p2tr=False,
        force_bip44=False,
        force_bip84=False,
        disable_p2sh=False,
        disable_p2tr=False,
        disable_bip44=False,
        disable_bip84=False,
    ):
        from .. import btcrseed

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

        btcrseed_cls.set_securityWarningsFlag(_engine.disable_security_warnings)
        global normalize, hmac
        from unicodedata import normalize
        import hmac
        load_pbkdf2_library()

        # Create a btcrseed.WalletBIP39 object which will do most of the work;
        # this also interactively prompts the user if not enough command-line options were included
        if addressdb_filename:
            from ..addressset import AddressSet
            print("Loading address database ...")
            hash160s = AddressSet.fromfile(open(addressdb_filename, "rb"))
        else:
            hash160s = None

        self.btcrseed_wallet = btcrseed_cls.create_from_params(
            mpk,
            addresses,
            address_limit,
            hash160s,
            path,
            is_performance,
            force_p2sh=force_p2sh,
            checksinglexpubaddress=checksinglexpubaddress,
            force_p2tr=force_p2tr,
            force_bip44=force_bip44,
            force_bip84=force_bip84,
            disable_p2sh=disable_p2sh,
            disable_p2tr=disable_p2tr,
            disable_bip44=disable_bip44,
            disable_bip84=disable_bip84,
        )

        if is_performance and not mnemonic:
            mnemonic = "certain come keen collect slab gauge photo inside mechanic deny leader drop"
        self.btcrseed_wallet.config_mnemonic(mnemonic, lang)

        # Verify that the entered mnemonic is valid
        if not self.btcrseed_wallet.verify_mnemonic_syntax(btcrseed.mnemonic_ids_guess):
            error_exit("one or more words are missing from the mnemonic")
        skip_checksum = getattr(_engine.args, "skip_mnemonic_checksum", False)
        if not skip_checksum and not self.btcrseed_wallet._verify_checksum(btcrseed.mnemonic_ids_guess):
            error_exit("invalid mnemonic (the checksum is wrong)")
        # Either the checksum was verified or the user chose to skip verification, so
        # assume all mnemonic guesses will be processed:
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

            seed_bytes = _engine.pbkdf2_hmac("sha512", self._mnemonic.encode(), derivation_salt, 2048)

            if type(self.btcrseed_wallet) is not btcrecover.btcrseed.WalletXLM:
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
        #    clResult.append(_engine.pbkdf2_hmac("sha512", self._mnemonic.encode(), salt, 2048))

        # This list is consumed, so recreated it and zip
        passwords = map(lambda p: normalize("NFKD", p).encode("utf_8", "ignore"), arg_passwords)

        results = zip(passwords, clResult)

        for count, (password, result) in enumerate(results, 1):
            if type(self.btcrseed_wallet) is not btcrecover.btcrseed.WalletXLM:
                seed_bytes = hmac.new(b"Bitcoin seed", result, hashlib.sha512).digest()
            else:
                seed_bytes = result

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
            print("ERROR: Cannot import shamir-mnemonic which is required for SLIP39 wallets, install it via 'pip3 install shamir-mnemonic[cli]'")
            exit()

        from .. import btcrseed

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

        btcrseed_cls.set_securityWarningsFlag(_engine.disable_security_warnings)
        global normalize, hmac
        from unicodedata import normalize
        import hmac
        load_pbkdf2_library()

        # Create a btcrseed.WalletBIP39 object which will do most of the work;
        # this also interactively prompts the user if not enough command-line options were included
        if addressdb_filename:
            from ..addressset import AddressSet
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
        #    clResult.append(_engine.pbkdf2_hmac("sha512", self._mnemonic.encode(), salt, 2048))

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
        from .. import btcrseed

        btcrseed_cls = btcrecover.btcrseed.WalletCardano

        btcrseed_cls.set_securityWarningsFlag(_engine.disable_security_warnings)
        global normalize, hmac
        from unicodedata import normalize
        import hmac
        load_pbkdf2_library()

        # Create a btcrseed.WalletBIP39 object which will do most of the work;
        # this also interactively prompts the user if not enough command-line options were included
        if addressdb_filename:
            from ..addressset import AddressSet
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
        skip_checksum = getattr(_engine.args, "skip_mnemonic_checksum", False)
        if not skip_checksum and not self.btcrseed_wallet._verify_checksum(btcrseed.mnemonic_ids_guess):
            error_exit("invalid mnemonic (the checksum is wrong)")
        # Either the checksum was verified or the user chose to skip verification
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
        from .. import btcrseed

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

        btcrseed_cls.set_securityWarningsFlag(_engine.disable_security_warnings)
        global normalize, hmac
        from unicodedata import normalize
        import hmac

        # Create a btcrseed.WalletBIP39 object which will do most of the work;
        # this also interactively prompts the user if not enough command-line options were included
        if addressdb_filename:
            from ..addressset import AddressSet
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
        skip_checksum = getattr(_engine.args, "skip_mnemonic_checksum", False)
        if not skip_checksum and not self.btcrseed_wallet._verify_checksum(btcrseed.mnemonic_ids_guess):
            error_exit("invalid mnemonic (the checksum is wrong)")
        # Either the checksum was verified or skipping was requested
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
        from .. import btcrseed

        btcrseed_cls = btcrseed.WalletEthereumValidator

        btcrseed_cls.set_securityWarningsFlag(_engine.disable_security_warnings)
        global normalize, hmac
        from unicodedata import normalize
        import hmac

        # Create a btcrseed.WalletBIP39 object which will do most of the work;
        # this also interactively prompts the user if not enough command-line options were included
        if addressdb_filename:
            from ..addressset import AddressSet
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
        skip_checksum = getattr(_engine.args, "skip_mnemonic_checksum", False)
        if not skip_checksum and not self.btcrseed_wallet._verify_checksum(btcrseed.mnemonic_ids_guess):
            error_exit("invalid mnemonic (the checksum is wrong)")
        # Either the checksum was verified or verification was skipped
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
        except Exception:
            exit(
                "\nERROR: Cannot load EMIP-3 module required for this wallet (Yoroi/Cardano)... Be sure to install all requirements with the command 'pip3 install -r requirements.txt', see https://btcrecover.readthedocs.io/en/latest/INSTALL/")

    def __setstate__(self, state):
        # (re-)load the required libraries after being unpickled
        global emip3

        try:
            from lib.emip3 import emip3
        except Exception:
            exit(
                "\nERROR: Cannot load EMIP-3 module required for this wallet (Yoroi/Cardano)... Be sure to install all requirements with the command 'pip3 install -r requirements.txt', see https://btcrecover.readthedocs.io/en/latest/INSTALL/")

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
    def _return_verified_password_or_false_opencl(self, arg_passwords): # Yoroi Cardano Wallet

        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        passwords = map(lambda p: p.encode("utf_8", "ignore"), arg_passwords)

        clResult = self.opencl_algo.cl_pbkdf2(self.opencl_context_pbkdf2_sha512, passwords, self.salt, 19162, 32)

        # This list is consumed, so recreated it and zip
        passwords = map(lambda p: p.encode("utf_8", "ignore"), arg_passwords)

        results = zip(passwords, clResult)

        for count, (password, key) in enumerate(results, 1):
            try:
                cipher = chacha20_poly1305_new(key=key, nonce=self.nonce)
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
        global hmac, base58, pylibscrypt
        if not hashlib_ripemd160_available:
            print("Warning: Native RIPEMD160 not available via Hashlib, using Pure-Python (This will significantly reduce performance)")
        import lib.pylibscrypt as pylibscrypt
        from lib.cashaddress import base58
        import hmac

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

        from .. import btcrseed
        # Load addresses
        from ..addressset import AddressSet

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
        global hmac, base58, pylibscrypt
        import lib.pylibscrypt as pylibscrypt
        from lib.cashaddress import base58
        import hmac

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
                s2 = _engine.pbkdf2_hmac("sha256", password.encode() + (self.hash_suffix[self.crypto] + 1).to_bytes(1, 'big'),
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

                pubkey = privkey_to_pubkey(privkey, compressed = isCompressed)

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
            #     s2 = _engine.pbkdf2_hmac("sha256", password,
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

                pubkeys.append(privkey_to_pubkey(privkey, compressed=isCompressed))

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
                 force_check_p2sh = False, crypto = 'bitcoin', is_performance = False, correct_wallet_password = None):
        global hmac, base58
        if not hashlib_ripemd160_available:
            print("Warning: Native RIPEMD160 not available via Hashlib, using Pure-Python (This will significantly reduce performance)")

        from lib.cashaddress import base58
        import hmac

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

        from .. import btcrseed
        # Load addresses
        from ..addressset import AddressSet

        input_address_p2sh = False
        input_address_standard = False
        self.address_type_checks = []

        self.hash160s = None

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

        if addressdb:
            self.hash160s = AddressSet.fromfile(open(addressdb, "rb"))
            print("Loaded", len(self.hash160s), "addresses from database ...")
            input_address_p2sh = True
            input_address_standard = True

        if input_address_p2sh or force_check_p2sh: self.address_type_checks.append(True)
        if input_address_standard and not (force_check_p2sh): self.address_type_checks.append(False)

        self.correct_wallet_password = correct_wallet_password

    def __setstate__(self, state):
        # (re-)load the required libraries after being unpickled
        global hmac, base58, pylibscrypt
        import lib.pylibscrypt as pylibscrypt
        from lib.cashaddress import base58
        import hmac

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
                    # Check whether we have a valid Base58check first (This will weed out most invalid options)
                    base58.b58decode_check(password)
                    print("***NOTICE*** Found possible Private key (Has valid Base58Checksum):", password, "checking if supplied address matches...")

                    # Convert to Hex for checking against supplied address
                    password = binascii.hexlify(base58.b58decode_check(password)[1:-1])
                    WIFPrivKey = True

                except:
                    continue

            elif len(password) == 51 and password[0] == "5":  # Uncompressed Private Key
                try:
                    # Check whether we have a valid Base58check first (This will weed out most invalid options)
                    base58.b58decode_check(password)
                    print("***NOTICE*** Found possible Private key (Has valid Base58Checksum):", password, "checking if supplied address matches...")

                    # Convert to Hex for checking against supplied address
                    password = binascii.hexlify(base58.b58decode_check(password)[1:])
                    WIFPrivKey = True
                except:
                    continue
            elif len(password) == 58 and password[0:3] == "6Pn": # BIP38 Encrypted Private key
                try:
                    # Check whether we have a valid Base58check first (This will weed out most invalid options)
                    base58.b58decode_check(password)
                    print("***NOTICE*** Found possible BIP38 Private key (Has valid Base58Checksum):", password, "checking if supplied address matches...")

                except:
                    continue

                if self.correct_wallet_password:
                    print("Attempting BIP38 decryption...")
                    test_wallet = WalletBIP38(enc_privkey = password)
                    correct_password, count = test_wallet.return_verified_password_or_false([self.correct_wallet_password])
                    if correct_password:
                        password = binascii.hexlify(base58.b58decode_check(test_wallet.decrypted_privkey)[1:-1])
                    else:
                        print("Incorrect decryption password supplied, unable to check further...")
                        continue

                    WIFPrivKey = True
                else:
                    print("No decryption password supplied, unable to check further...")
                    continue
            else: # Unsupported Private Key
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

            # Don't spam this at performance measurement step
            if password != "9cf68de3a8bec8f4649a5a1eb9340886a68a85c0c3ae722393ef3dd7a6c4da58":
                if not self.hash160s:
                    if WIFPrivKey:
                        print("Warning: No addresses supplied, unable to check Base58 private key any further.. ")
                    else:
                        print("Warning: No addresses supplied combined with hexidicimal private key, this will never find a result... ")


            # Convert the private keys to public keys and addresses for verification.
            for isCompressed in self.compression_checks:

                if isCompressed:
                    privcompress = bytes([0x1])
                else:
                    privcompress = bytes([])

                # Sometimes it's possible that a privatekey (with a valid checksum) will still be invalid in terms of generating a usable address
                try:
                    pubkey = privkey_to_pubkey(privkey, compressed = isCompressed)
                except Exception as e:
                    print("Exception for Privkey: ", password, " : ", e)
                    continue

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

############### btc.com Wallet (blocktrail wallet) ###############
# Used to recover the wallet password to enable recovery from the btc.com recovery PDF.
# The logic and variable names here follow the code/logic from https://github.com/blocktrail/wallet-recovery-tool/
# as closely as possible

@register_wallet_class
class Walletbtc_com(object):
    opencl_algo = -1

    def decode(self, mnemonic):
        paddingDummy = 129  # Because salts with length > 128 should be forbidden
        mnemo = Mnemonic("english")
        decoded_data = mnemo.to_entropy(mnemonic)

        padFinish = 0
        while True:
            if decoded_data[padFinish] == paddingDummy:
                padFinish = padFinish + 1
            else:
                break

        return decoded_data[padFinish:]

    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(0)
        try:
            walletdata = wallet_file.read()
        except: return False
        return (b"passwordEncryptedSecretMnemonic" in walletdata) # A pretty unique tag in

    @classmethod
    def load_from_filename(cls, wallet_filename):
        self = cls()

        # Open a JSON file containing the wallet data, as parsed by the browser based btc.com wallet recovery tool
        # (You can manually create this file, all BTCRecover uses is the password encrypted secret mnemonic,
        # you can leave the rest out to avoid exposing the actal wallet private keys to the system running BTCRecover)
        with open(wallet_filename) as wallet_file:
            wallet_json = json.load(wallet_file)

        PasswordEncryptedSecret = wallet_json['passwordEncryptedSecretMnemonic'].strip()
        passwordEncryptedSecretMnemonic = self.decode(PasswordEncryptedSecret)

        # Save the salt length
        self.saltLen = passwordEncryptedSecretMnemonic[0]
        passwordEncryptedSecretMnemonic = passwordEncryptedSecretMnemonic[1:]

        # Save the salt
        self.salt = passwordEncryptedSecretMnemonic[:self.saltLen]
        passwordEncryptedSecretMnemonic = passwordEncryptedSecretMnemonic[self.saltLen:]

        # Save the iterations #
        self.iterations = int.from_bytes(passwordEncryptedSecretMnemonic[:4], 'little')
        passwordEncryptedSecretMnemonic = passwordEncryptedSecretMnemonic[4:]

        # Construct and save the header
        self.header = self.decode(PasswordEncryptedSecret)[:1 + self.saltLen + 4]

        # Save the IV
        self.iv = passwordEncryptedSecretMnemonic[:16]
        passwordEncryptedSecretMnemonic = passwordEncryptedSecretMnemonic[16:]

        # Save the cyphertext and tag
        self.ct_t = passwordEncryptedSecretMnemonic
        return self

    def passwords_per_seconds(self, seconds):
        # Haven't worked this out, but this is a ballpark figure
        return 200

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def return_verified_password_or_false(self, arg_passwords):  # btc.com wallet password
        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        passwords = map(lambda p: p.encode("utf_8", "ignore"), arg_passwords)

        for count, password in enumerate(passwords, 1):
            key = hashlib.pbkdf2_hmac('sha512', password, self.salt, self.iterations, 32)
            cipher = AES.new(key, AES.MODE_GCM, self.iv)
            cipher.update(self.header)
            try:
                decrypted_data = cipher.decrypt_and_verify(self.ct_t[:32], self.ct_t[32:])
            except ValueError: # Throws a value error if MAC mismatches
                continue

            return password.decode("utf_8", "replace"), count

        return False, count


############### ToastWallet  ###############
@register_wallet_class
class Wallettoastwallet(object):
    opencl_algo = -1
    _dump_privkeys_file = None

    def __init__(self, loading = False):
        if not nacl_available:
            exit("Toastwallet Requires the nacl module, this can be installed via pip3 install pynacl")

    def dump_privkeys(self, hash1):
        with open(self._dump_privkeys_file, 'a') as logfile:
            logfile.write("Below are all of the accounts in the wallet, these private keys can be imported into XRP wallets like Xaman\nNickname      Address      Privkey\n")
            for account in self.wallet_json['accounts'].keys():
                addr_salt = binascii.unhexlify(
                    self.wallet_json['accounts'][account]['ppsalt'].encode())[4:]
                addr_secret = binascii.unhexlify(
                    self.wallet_json['accounts'][account]['ppsecret'].encode())[4:]

                ppsecretk32key = nacl.pwhash.scrypt.kdf(size=32, password=hash1, salt=addr_salt, opslimit=4,
                                                        memlimit=33554432)

                box = nacl.secret.SecretBox(ppsecretk32key)

                secret_clear = box.decrypt(addr_secret)

                logfile.write(self.wallet_json['accounts'][account]['nickname'] + " " + account + " " + bytes.fromhex(secret_clear.hex()).decode() + "\n")

    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(0)
        try:
            walletdata = wallet_file.read()
        except: return False
        return (b"ppdata" in walletdata) and (b"rpdata" in walletdata)

    @classmethod
    def load_from_filename(cls, wallet_filename):
        self = cls()

        # Open a JSON file containing the wallet data, as parsed by the browser based btc.com wallet recovery tool
        # (You can manually create this file, all BTCRecover uses is the password encrypted secret mnemonic,
        # you can leave the rest out to avoid exposing the actal wallet private keys to the system running BTCRecover)
        with open(wallet_filename) as wallet_file:
            wallet_file.seek(8)  # Skip over the wallet fingerprint at the start
            wallet_json = json.load(wallet_file)

        self.salt1 = binascii.unhexlify(wallet_json['ppdata']['salt1'].encode())[4:]
        self.salt2 = binascii.unhexlify(wallet_json['ppdata']['salt2'].encode())[4:]
        self.target_hash = binascii.unhexlify(wallet_json['ppdata']['hash'].encode())[4:]
        self.wallet_json = wallet_json

        return self

    def passwords_per_seconds(self, seconds):
        # Haven't worked this out, but this is a ballpark figure
        return 2000

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def return_verified_password_or_false(self, arg_passwords):  # toastwallet wallet password
        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        passwords = map(lambda p: p.encode("utf_8", "ignore"), arg_passwords)

        for count, password in enumerate(passwords, 1):
            hash1 = nacl.pwhash.scrypt.kdf(size=16, password=password, salt=self.salt1, opslimit=4, memlimit=33554432)
            hash2 = nacl.pwhash.scrypt.kdf(size=16, password=hash1, salt=self.salt2, opslimit=4, memlimit=33554432)

            if self.target_hash == hash2:
                # If we aren't dumping these files, then just return...
                if self._dump_privkeys_file:
                    # This just dumps the wallet private keys (if required)
                    self.dump_privkeys(hash1)

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


