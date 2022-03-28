#!/usr/bin/env python

# extract-bitcoincore-mkey.py -- Bitcoin wallet master key extractor
# Copyright (C) 2014, 2015 Christopher Gurnee
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

import sys, os.path, struct, base64, zlib

prog = os.path.basename(sys.argv[0])

if len(sys.argv) != 2 or sys.argv[1].startswith("-"):
    print("usage:", prog, "BITCOINCORE_WALLET_FILE", file=sys.stderr)
    sys.exit(2)

wallet_filename = os.path.abspath(sys.argv[1])

with open(wallet_filename, "rb") as wallet_file:
    isBDB = False
    isSQLite = False

    wallet_file.seek(12)
    if wallet_file.read(8) == b"\x62\x31\x05\x00\x09\x00\x00\x00":  # BDB magic, Btree v9
        isBDB = True

    wallet_file.seek(0)
    if wallet_file.read(16) == b"SQLite format 3\0":
        isSQLite = True

    if not isBDB and not isSQLite:
        print(prog+": error: file is not a Bitcoin Core wallet", file=sys.stderr)
        sys.exit(1)

force_purepython = False
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
            exit("the entire path and filename of Bitcoin Core wallets must be entirely ASCII")
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
            page_size = struct.unpack(b"<I", wallet_file.read(4))[0]
            wallet_file_size = os.path.getsize(wallet_filename)
            for page_base in range(page_size, wallet_file_size, page_size):  # skip the header page
                wallet_file.seek(page_base + 20)
                (item_count, first_item_pos, btree_level, page_type) = struct.unpack(b"< H H B B", wallet_file.read(6))
                if page_type != 5 or btree_level != 1:
                    continue  # skip non-btree and non-leaf pages
                pos = align_32bits(page_base + first_item_pos)  # position of the first item
                wallet_file.seek(pos)
                for i in range(item_count):  # for each item in the current page
                    (item_len, item_type) = struct.unpack(b"< H B", wallet_file.read(3))
                    if item_type & ~0x80 == 1:  # if it's a variable-length key or value
                        if item_type == 1:  # if it's not marked as deleted
                            if i % 2 == 0:  # if it's a value, save it's position
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
                else:
                    continue  # if not found on this page, continue to next page
                break  # if we broke out of inner loop, break out of this one too

except AssertionError:
    pass

#If we still haven't got a valid mkey, try it as SQLite
if not mkey:
    # It may be a more modern wallet file
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
    raise ValueError("Encrypted master key #1 not found in the Bitcoin Core wallet file.\n"+
                     "(is this wallet encrypted? is this a standard Bitcoin Core wallet?)")

# This is a little fragile because it assumes the encrypted key and salt sizes are
# 48 and 8 bytes long respectively, which although currently true may not always be:
# (it will loudly fail if this isn't the case; if smarter it could gracefully succeed):
encrypted_master_key, salt, method, iter_count = struct.unpack_from("< 49p 9p I I", mkey)
if method != 0:
    print(prog+": warning: unexpected Bitcoin Core key derivation method", str(method), file=sys.stderr)

print("Partial Bitcoin Core encrypted master key, salt, iter_count, and crc in base64:", file=sys.stderr)

# Only include the last two AES blocks (last 32 bytes) of the 48-byte encrypted master key
bytes = b"bc:" + encrypted_master_key[-32:] + salt + struct.pack("<I", iter_count)
crc_bytes = struct.pack("<I", zlib.crc32(bytes) & 0xffffffff)

print(base64.b64encode(bytes + crc_bytes).decode())
