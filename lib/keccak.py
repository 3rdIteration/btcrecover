# Pure-python Keccak-256 implementation.
#
# Provides a drop-in for Crypto.Hash.keccak_256 when pycryptodome is not
# installed. Implements the original Keccak sponge construction (not NIST
# SHA-3) with the parameters used by Ethereum.

import struct


_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

_RHO = [
    [ 0, 36,  3, 41, 18],
    [ 1, 44, 10, 45,  2],
    [62,  6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39,  8, 14],
]


def _rotl64(v, n):
    return ((v << n) | (v >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def _keccak_f(state):
    for rnd in range(24):
        C = [0] * 5
        for x in range(5):
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
        for x in range(5):
            d = C[(x - 1) % 5] ^ _rotl64(C[(x + 1) % 5], 1)
            for y in range(5):
                state[x + 5 * y] ^= d

        old = state[:]
        for x in range(5):
            for y in range(5):
                nx = y
                ny = (2 * x + 3 * y) % 5
                state[nx + 5 * ny] = _rotl64(old[x + 5 * y], _RHO[x][y])

        for y in range(5):
            base = 5 * y
            t0, t1, t2, t3, t4 = state[base:base + 5]
            state[base]     = t0 ^ ((~t1) & t2)
            state[base + 1] = t1 ^ ((~t2) & t3)
            state[base + 2] = t2 ^ ((~t3) & t4)
            state[base + 3] = t3 ^ ((~t4) & t0)
            state[base + 4] = t4 ^ ((~t0) & t1)

        state[0] ^= _RC[rnd]
    return state


class Keccak256:
    def __init__(self, data=None):
        self._state = [0] * 25
        self._rate = 136
        self._offset = 0
        if data is not None:
            self.update(data)

    def update(self, data):
        if isinstance(data, str):
            data = data.encode()
        for b in data:
            self._state[self._offset >> 3] ^= b << ((self._offset & 7) << 3)
            self._offset += 1
            if self._offset == self._rate:
                self._state = _keccak_f(self._state)
                self._offset = 0

    def digest(self):
        self._state[self._offset >> 3] ^= 0x01 << ((self._offset & 7) << 3)
        if (self._offset & 0x7F) == 0x7F:
            self._state = _keccak_f(self._state)
        self._state[(self._rate - 1) >> 3] ^= 0x80 << (((self._rate - 1) & 7) << 3)
        self._state = _keccak_f(self._state)
        result = bytearray()
        for i in range(32):
            result.append((self._state[i >> 3] >> ((i & 7) << 3)) & 0xFF)
        return bytes(result)


def new(data=b'', digest_bits=256):
    if digest_bits != 256:
        raise ValueError("Only digest_bits=256 is supported")
    return Keccak256(data)
