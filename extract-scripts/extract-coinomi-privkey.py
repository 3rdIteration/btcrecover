#!/usr/bin/env python

# extract-coinomi-privkey.py -- MultiBit private key extractor
# Copyright (C) 2014, 2015 Christopher Gurnee
#               2021 Stephen Rothery
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

import sys, os.path, base64, zlib, struct

prog = os.path.basename(sys.argv[0])

if len(sys.argv) != 2 or sys.argv[1].startswith("-"):
    print("usage:", prog, "COINOMI_PRIVATE_KEY_FILE", file=sys.stderr)
    sys.exit(2)

privkey_filename = sys.argv[1]

with open(privkey_filename, "rb") as privkey_file:
    filedata = privkey_file.read()

    import sys
    sys.path.append('../')
    try:
        from btcrecover import coinomi_pb2
    except ModuleNotFoundError:
        exit(
            "\nERROR: Cannot load protobuf module... Be sure to install all requirements with the command 'pip3 install -r requirements.txt', see https://btcrecover.readthedocs.io/en/latest/INSTALL/")

    pb_wallet = coinomi_pb2.Wallet()
    pb_wallet.ParseFromString(filedata)
    # print(pb_wallet)
    if pb_wallet.encryption_type == coinomi_pb2.Wallet.UNENCRYPTED:
        raise ValueError("Coinomi wallet is not encrypted")
    if pb_wallet.encryption_type != coinomi_pb2.Wallet.ENCRYPTED_SCRYPT_AES:
        raise NotImplementedError("Unsupported Coinomi wallet encryption type " + str(pb_wallet.encryption_type))
    if not pb_wallet.HasField("encryption_parameters"):
        raise ValueError("Coinomi wallet is missing its scrypt encryption parameters")

    # only need the final 2 encrypted blocks (half of it padding) plus the scrypt parameters
    encrypted_masterkey_part = pb_wallet.master_key.encrypted_data.encrypted_private_key[-32:]
    scrypt_salt = pb_wallet.encryption_parameters.salt
    scrypt_n = pb_wallet.encryption_parameters.n
    scrypt_r = pb_wallet.encryption_parameters.r
    scrypt_p = pb_wallet.encryption_parameters.p

print("Coinomi partial first encrypted private key, salt, n, r, p and crc in base64:", file=sys.stderr)
bytes = b"cn:" + struct.pack("< 32s 8s I H H", encrypted_masterkey_part, scrypt_salt, scrypt_n, scrypt_r, scrypt_p)
crc_bytes = struct.pack("<I", zlib.crc32(bytes) & 0xffffffff)

print(base64.b64encode(bytes + crc_bytes).decode())
