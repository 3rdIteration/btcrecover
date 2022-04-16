#!/usr/bin/env python

# extract-metamask-data.py -- Metamask data extractor
# Copyright (C) 2021 Stephen Rothery
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


import sys, os.path, base64, json, zlib, struct, binascii

prog = os.path.basename(sys.argv[0])

if len(sys.argv) != 2 or sys.argv[1].startswith("-"):
    print("usage:", prog, "METAMASK_EXTENSION_FILE", file=sys.stderr)
    sys.exit(2)

wallet_filename = sys.argv[1]

try:
    with open(wallet_filename, "rb") as wallet_file:
        wallet_data_full = wallet_file.read().decode("utf-8", "ignore").replace("\\", "")
except PermissionError:
    print("Error: Unable to open wallet, if you are trying to open a Metamask wallet folder, you must first extract the desired vault (extract-metamask-vaults.py) and then use this script to create an extract")
    exit()

if "\"lib\":\"original\"" in wallet_data_full:
     isMobileWallet = True
     vaultStartString = "cipher"
else:
    isMobileWallet = False
    vaultStartString = "data"

# Try loading the file directly to see if it is valid JSON (Will be if it was extracted from javascript console)
try:
    wallet_json = json.loads(wallet_data_full)
    wallet_data = wallet_data_full

# Try finding extracting just the fault data (Will be if it was taken from the extension files directly)
except json.decoder.JSONDecodeError:
    walletStartText = "vault"

    wallet_data_start = wallet_data_full.lower().find(walletStartText)

    wallet_data_trimmed = wallet_data_full[wallet_data_start:]

    wallet_data_start = wallet_data_trimmed.find(vaultStartString)
    wallet_data_trimmed = wallet_data_trimmed[wallet_data_start - 2:]

    wallet_data_end = wallet_data_trimmed.find("}")
    wallet_data = wallet_data_trimmed[:wallet_data_end + 1]

    wallet_json = json.loads(wallet_data)


if "\"lib\":\"original\"" in wallet_data:
    salt = wallet_json["salt"].encode()
    encrypted_block = base64.b64decode(wallet_json["cipher"])[:16]
    iv = binascii.unhexlify(wallet_json["iv"])
else:
    salt = base64.b64decode(wallet_json["salt"])
    encrypted_block = base64.b64decode(wallet_json["data"])[:16]
    iv = base64.b64decode(wallet_json["iv"])

print("Metamask first 16 encrypted bytes, iv, and salt in base64:", file=sys.stderr)

bytes = b"mt:" + struct.pack("< 16s 16s 32s 1?", encrypted_block, iv, salt, isMobileWallet)
crc_bytes = struct.pack("<I", zlib.crc32(bytes) & 0xffffffff)

print(base64.b64encode(bytes + crc_bytes).decode())
