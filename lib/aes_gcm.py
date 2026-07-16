# Pure-python AES-GCM using lib.pyaes for AES-CTR + bundled GHASH.
#
# Provides AES-GCM encrypt/decrypt with optional AAD and tag verification,
# matching the relevant subset of Crypto.Cipher.AES.new(key, MODE_GCM, ...).

import struct
from lib.pyaes import AES as _AES, Counter as _Counter


# ---------------------------------------------------------------------------
# GF(2^128) GHASH
# ---------------------------------------------------------------------------

def _ghash_mul(x, y):
    R = 0xE1000000000000000000000000000000
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ R
        else:
            v >>= 1
    return z


def _bytes_to_int128(b):
    return int.from_bytes(b, 'big')


def _int128_to_bytes(n):
    return n.to_bytes(16, 'big')


def _ghash(h_int, data):
    y = 0
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        if len(block) < 16:
            block = block + b'\x00' * (16 - len(block))
        y = _ghash_mul(y ^ _bytes_to_int128(block), h_int)
    return y


# ---------------------------------------------------------------------------
# AES-GCM
# ---------------------------------------------------------------------------

def _inc32(block):
    ctr = _bytes_to_int128(block)
    return _int128_to_bytes(((ctr >> 32) + 1) << 32 | (ctr & 0xFFFFFFFF))


def _aes_ctr_encrypt(aes_ecb, counter_init, data):
    out = bytearray()
    ctr = counter_init
    for i in range(0, len(data), 16):
        ks = aes_ecb.encrypt(ctr)
        chunk = data[i:i + 16]
        for j in range(len(chunk)):
            out.append(chunk[j] ^ ks[j])
        ctr = _inc32(ctr)
    return bytes(out)


def gcm_decrypt(key, nonce, ciphertext, tag=None, aad=None, decrypt_only=False):
    if len(key) not in (16, 24, 32):
        raise ValueError("Invalid key size")
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes")
    aes_ecb = _AES(key)
    h = _bytes_to_int128(aes_ecb.encrypt(b'\x00' * 16))
    j0 = nonce + b'\x00\x00\x00\x01'
    if not decrypt_only and tag is not None:
        if len(tag) not in (4, 8, 12, 13, 14, 15, 16):
            raise ValueError("Invalid tag length")
    if aad is None:
        aad = b''

    plaintext = _aes_ctr_encrypt(aes_ecb, _inc32(j0), ciphertext)

    if not decrypt_only and tag is not None:
        u = (16 - len(ciphertext) % 16) % 16
        v = (16 - len(aad) % 16) % 16
        ghash_data = aad + b'\x00' * v + ciphertext + b'\x00' * u + struct.pack('>Q', len(aad) * 8) + struct.pack('>Q', len(ciphertext) * 8)
        mac = _int128_to_bytes(_ghash(h, ghash_data))
        tag_expected_bytes = _aes_ctr_encrypt(aes_ecb, j0, mac)
        tag_expected = tag_expected_bytes[:len(tag)]
        if not _consttime_compare(tag_expected, tag):
            raise ValueError("MAC check failed")

    return plaintext


class _AES_GCM_Cipher:
    def __init__(self, key, nonce):
        self._key = bytes(key)
        self._nonce = bytes(nonce)
        self._aad = bytearray()
        self._ciphertext = bytearray()
        self._finalized = False

    def update(self, aad_bytes):
        if self._finalized:
            raise ValueError("Already finalized")
        if isinstance(aad_bytes, str):
            aad_bytes = aad_bytes.encode()
        self._aad.extend(aad_bytes)
        return aad_bytes

    def encrypt(self, plaintext):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        aes_ecb = _AES(self._key)
        j0 = self._nonce + b'\x00\x00\x00\x01'
        ct = _aes_ctr_encrypt(aes_ecb, _inc32(j0), plaintext)
        self._ciphertext.extend(ct)
        return ct

    def encrypt_and_digest(self, plaintext):
        ct = self.encrypt(plaintext)
        tag = self._compute_tag(bytes(self._ciphertext))
        return ct, tag

    def decrypt(self, ciphertext):
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode()
        aes_ecb = _AES(self._key)
        j0 = self._nonce + b'\x00\x00\x00\x01'
        pt = _aes_ctr_encrypt(aes_ecb, _inc32(j0), ciphertext)
        self._ciphertext.extend(ciphertext)
        return pt

    def decrypt_and_verify(self, ciphertext, tag):
        pt = self.decrypt(ciphertext)
        expected = self._compute_tag(bytes(self._ciphertext))
        if len(tag) != 16 or not _consttime_compare(expected, tag):
            raise ValueError("MAC check failed")
        return pt

    def _compute_tag(self, ct):
        aes_ecb = _AES(self._key)
        h = _bytes_to_int128(aes_ecb.encrypt(b'\x00' * 16))
        j0 = self._nonce + b'\x00\x00\x00\x01'
        aad = bytes(self._aad)
        u = (16 - len(ct) % 16) % 16
        v = (16 - len(aad) % 16) % 16
        ghash_data = aad + b'\x00' * v + ct + b'\x00' * u + struct.pack('>Q', len(aad) * 8) + struct.pack('>Q', len(ct) * 8)
        mac = _int128_to_bytes(_ghash(h, ghash_data))
        tag_bytes = _aes_ctr_encrypt(aes_ecb, j0, mac)
        return tag_bytes

    def digest(self):
        return self._compute_tag(bytes(self._ciphertext))

    def verify(self, tag):
        expected = self._compute_tag(bytes(self._ciphertext))
        if len(tag) != 16 or not _consttime_compare(expected, tag):
            raise ValueError("MAC check failed")


def _consttime_compare(a, b):
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0
