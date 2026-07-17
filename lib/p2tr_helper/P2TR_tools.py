# Extracts from From https://github.com/ebellocchia/bip_utils/ (Modified to work directly with CoinCurve)

# Copyright (c) 2021 Emanuele Bellocchia
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""
Module for P2TR address encoding/decoding.

References:
    https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
    https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
"""

# Imports
from typing import Any, Union
import hashlib

from btcrecover.crypto_backends import (
    privkey_to_pubkey,
    pubkey_from_bytes,
    pubkey_point,
    lift_x,
    tweak_pubkey,
)

# The generator point G is handled internally by crypto_backends.tweak_pubkey()

class P2TRConst:
    """Class container for P2TR constants."""

    # Secp256k1 field size
    FIELD_SIZE: int = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    # SHA256 of "TapTweak"
    TAP_TWEAK_SHA256: bytes = bytes.fromhex('e80fe1639c9ca050e3af1b39c143c63e429cbceb15d940fbb5c5a1f4af57c5e9')
    # Witness version is fixed to one for P2TR
    WITNESS_VER: int = 1


class _P2TRUtils:
    """Class container for P2TR utility functions."""

    @staticmethod
    def TaggedHash(tag: Union[bytes, str],
                   data_bytes: bytes) -> bytes:
        """
        Implementation of the hash tag function as defined by BIP-0340.
        Tagged hash = SHA256(SHA256(tag) || SHA256(tag) || data)

        Args:
            tag (bytes or str): Tag, if bytes it'll be considered already hashed
            data_bytes (bytes): Data bytes

        Returns:
            bytes: Tagged hash
        """
        tag_hash = hashlib.sha256(tag).digest() if isinstance(tag, str) else tag

        return hashlib.sha256(tag_hash + tag_hash + data_bytes).digest()

    @staticmethod
    def HashTapTweak(pub_key_bytes: bytes) -> bytes:
        """
        Compute the HashTapTweak of the specified public key.

        Args:
            pub_key_bytes (bytes): Serialized (compressed or uncompressed) public key

        Returns:
            bytes: Computed hash
        """
        x = pubkey_point(pub_key_bytes)[0]
        # Use the pre-computed SHA256 of "TapTweak" for speeding up
        return _P2TRUtils.TaggedHash(
            P2TRConst.TAP_TWEAK_SHA256,
            x.to_bytes(32, byteorder="big")
        )

    @staticmethod
    def LiftX(pub_key_bytes: bytes):
        """
        Implementation of the lift_x function as defined by BIP-0340.
        It computes the point P for which P.X() = pub_key.X() and has_even_y(P).

        Args:
            pub_key_bytes (bytes): Serialized public key

        Returns:
            bytes: Serialized (compressed) public key with even Y
        """
        p = P2TRConst.FIELD_SIZE
        x = pubkey_point(pub_key_bytes)[0]
        if x >= p:
            raise ValueError("Unable to compute LiftX point")
        c = (pow(x, 3, p) + 7) % p
        y = pow(c, (p + 1) // 4, p)
        if c != pow(y, 2, p):
            raise ValueError("Unable to compute LiftX point")
        return lift_x(pub_key_bytes)

    @staticmethod
    def TweakPublicKey(pub_key_bytes: bytes) -> bytes:
        """
        Tweak a public key as defined by BIP-0086.
        tweaked_pub_key = lift_x(pub_key.X()) + int(HashTapTweak(bytes(pub_key.X()))) * G

        Args:
            pub_key_bytes (bytes): Serialized public key

        Returns:
            bytes: X coordinate of the tweaked public key
        """
        h = _P2TRUtils.HashTapTweak(pub_key_bytes)
        out_point = tweak_pubkey(lift_x(pub_key_bytes), h)
        return pubkey_point(out_point)[0].to_bytes(32, byteorder="big")
