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
import coincurve
import hashlib

G = coincurve.PublicKey.from_point(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
                                   0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

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
    def HashTapTweak(pub_key: coincurve.PublicKey) -> bytes:
        """
        Compute the HashTapTweak of the specified public key.

        Args:
            pub_key (IPublicKey object): Public key

        Returns:
            bytes: Computed hash
        """

        # Use the pre-computed SHA256 of "TapTweak" for speeding up
        return _P2TRUtils.TaggedHash(
            P2TRConst.TAP_TWEAK_SHA256,
            pub_key.point()[0].to_bytes(32, byteorder="big")
        )

    @staticmethod
    def LiftX(pub_key: coincurve.PublicKey):
        """
        Implementation of the lift_x function as defined by BIP-0340.
        It computes the point P for which P.X() = pub_key.X() and has_even_y(P).

        Args:
            pub_key (IPublicKey object): Public key

        Returns:
            IPoint: Computed point

        Raises:
            ValueError: If the point doesn't exist
        """
        p = P2TRConst.FIELD_SIZE
        x = pub_key.point()[0]
        if x >= p:
            raise ValueError("Unable to compute LiftX point")
        c = (pow(x, 3, p) + 7) % p
        y = pow(c, (p + 1) // 4, p)
        if c != pow(y, 2, p):
            raise ValueError("Unable to compute LiftX point")
        return coincurve.PublicKey.from_point(x, y if y % 2 == 0 else p - y)

    @staticmethod
    def TweakPublicKey(pub_key: coincurve.PublicKey) -> bytes:
        """
        Tweak a public key as defined by BIP-0086.
        tweaked_pub_key = lift_x(pub_key.X()) + int(HashTapTweak(bytes(pub_key.X()))) * G

        Args:
            pub_key (IPublicKey object): Public key

        Returns:
            bytes: X coordinate of the tweaked public key
        """
        h = _P2TRUtils.HashTapTweak(pub_key)
        out_point = _P2TRUtils.LiftX(pub_key).combine([G.multiply(h)])
        return out_point.point()[0].to_bytes(32, byteorder="big")
