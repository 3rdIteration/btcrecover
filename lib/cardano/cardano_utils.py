# cardano_utils.py - Cardano derivation functions (Not an exhaustive implementation, only those required for BTCRecover)
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

from lib.ecpy.curves import Curve,Point
import lib.cardano.orakolo.HDEd25519 as HDEd25519
import hashlib, hmac
import bisect

from typing import AnyStr, List, Optional, Sequence, TypeVar, Union

_T = TypeVar("_T")

def generateMasterKey_Icarus(mnemonic, passphrase, wordlist, langcode, trezor = False):
    return generateRootKey_Icarus(generateHashKey_Icarus(mnemonic, passphrase, wordlist, langcode, trezor))

def generateHashKey_Icarus(mnemonic, passphrase, wordlist, langcode, trezor = False):
    seed = mnemonic_to_entropy(words=mnemonic, wordlist=wordlist, langcode=langcode, trezorDerivation=trezor)

    data = hashlib.pbkdf2_hmac("SHA512", password=passphrase, salt=seed, iterations=4096, dklen=96)

    return data

def generateRootKey_Icarus(keyData):
    kL, kR, cP = keyData[:32], keyData[32:64], keyData[64:]

    kL = tweakBits_shelly(bytearray(kL));

    AP = root_public_key(kL)

    return (kL, kR), AP, cP

def generateMasterKey_Ledger(mnemonic, passphrase):
    return generateRootKey_Ledger(generateHashKey_Ledger(mnemonic, passphrase))

def generateHashKey_Ledger(mnemonic, passphrase):
    derivation_salt = b"mnemonic" + passphrase
    derivation_password = mnemonic.encode()

    data = hashlib.pbkdf2_hmac("SHA512", password=derivation_password, salt=derivation_salt, iterations=2048, dklen=64)

    return data

def generateRootKey_Ledger(keyData):
    cP = hmac.new(key=b"ed25519 seed", msg=b'\x01' + keyData, digestmod=hashlib.sha256).digest()

    kL, kR = hashRepeatedly_ledger(keyData);

    kL = tweakBits_shelly(bytearray(kL))

    AP = root_public_key(kL)

    return (kL, kR), AP, cP


def hashRepeatedly_ledger(message):
    kL_kR = hmac.new(key=b"ed25519 seed", msg=message, digestmod=hashlib.sha512).digest()

    kL, kR = kL_kR[:32], kL_kR[32:]

    if (kL[31] & 0b00100000):
        return hashRepeatedly_ledger(kL + kR)

    return (kL, kR)

def tweakBits_shelly(data):
    # on the ed25519 scalar leftmost 32 bytes:
    # clear the lowest 3 bits
    # clear the highest bit
    # clear the 3rd highest bit
    # set the highest 2nd bit
    data[0]  = data[0]  & 0b11111000
    data[31] = data[31] & 0b00011111
    data[31] = data[31] | 0b01000000

    return bytes(data)

# Pulled from orakolo HDEd25519 root_key_slip10 (Using it here for more genralised address derivation)
def root_public_key(kL):
    # root public key
    #A = _crypto_scalarmult_curve25519_base(bytes(kL))
    cv25519 = Curve.get_curve("Ed25519")
    k_scalar = int.from_bytes(bytes(kL), 'little')
    P = k_scalar*cv25519.generator
    A =  cv25519.encode_point(P)
    return A

# Pulled from orakolo HDEd25519 derive_seed (Using it here for more flexibility in terms of derivation)
def derive_child_keys(parent_node, path, private):

    if private:
        node = parent_node
    else :
        (kLP, kRP), AP, cP = parent_node
        node = (AP,cP)

    BIP32Ed25519_class = HDEd25519.BIP32Ed25519()
    for i in path.split('/'):
        if i.endswith("'"):
            i = int(i[:-1]) + 2**31
        else:
            i = int(i)

        if private:
          node = BIP32Ed25519_class.private_child_key(node, i)
          ((kLP, kRP), AP, cP) = node
        else:
          node = BIP32Ed25519_class.public_child_key(node, i)
          (AP, cP) = node

    return node

# Pulled from https://github.com/trezor/python-mnemonic and modified to fix bug in Trezor derivation
# See https://github.com/trezor/trezor-firmware/pull/1388
def mnemonic_to_entropy(words: Union[List[str], str], wordlist, langcode, trezorDerivation = False ) -> bytearray:
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

    if trezorDerivation and len(words) == 24:
        entropyLengthBits = concatLenBits# - checksumLengthBits
    else:
        entropyLengthBits = concatLenBits - checksumLengthBits
    # Extract original entropy as bytes.
    entropy = bytearray(entropyLengthBits // 8)
    for ii in range(len(entropy)):
        for jj in range(8):
            if concatBits[(ii * 8) + jj]:
                entropy[ii] |= 1 << (7 - jj)
    return entropy

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

# Note: This doesn't appear to work when compared to the CIP-003 Test Vectors, haven't validated them any further
def generateMasterKey_Byron(mnemonic):
    mnemo = Mnemonic("english")
    seed = mnemo.to_entropy(mnemonic)
    return hashRepeatedly_byron(seed, 1)

# Note: This doesn't appear to work when compared to the CIP-003 Test Vectors, haven't validated them any further
def hashRepeatedly_byron(key, i):
    iL_iR = hmac.new(key=bytes(key), msg=b"Root Seed Chain %d" % i, digestmod=hashlib.sha512).digest()

    iL, iR = iL_iR[:32], iL_iR[32:]

    prv = cardano_tweakBits_byron(bytearray(hashlib.sha512(iL).digest()))

    # print("{:08b}".format(prv[31] & 0b00100000))
    if (prv[31] & 0b00100000):
        print("Repeat")
        return hashRepeatedly_byron(key, i + 1)

    return (prv + iR)

# Note: This doesn't appear to work when compared to the CIP-003 Test Vectors, haven't validated them any further
def cardano_tweakBits_byron(data):
    # clear the lowest 3 bits
    # clear the highest bit
    # set the highest 2nd bit
    data[0]  = data[0]  & 0b11111000
    data[31] = data[31] & 0b01111111
    data[31] = data[31] | 0b01000000;

    return bytes(data);