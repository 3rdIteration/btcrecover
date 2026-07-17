# Pure-python ChaCha20 stream cipher and Poly1305 MAC (RFC 8439)
#
# Provides a drop-in replacement for Crypto.Cipher.ChaCha20_Poly1305
# from pycryptodome when that package is not installed.

import struct


# ---------------------------------------------------------------------------
# ChaCha20 quarter round and block function
# ---------------------------------------------------------------------------

def _quarter_round(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = ((state[d] << 16) | (state[d] >> 16)) & 0xFFFFFFFF

    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = ((state[b] << 12) | (state[b] >> 20)) & 0xFFFFFFFF

    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = ((state[d] << 8) | (state[d] >> 24)) & 0xFFFFFFFF

    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = ((state[b] << 7) | (state[b] >> 25)) & 0xFFFFFFFF


def _chacha20_block(key, counter, nonce):
    state = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        struct.unpack('<I', key[0:4])[0],
        struct.unpack('<I', key[4:8])[0],
        struct.unpack('<I', key[8:12])[0],
        struct.unpack('<I', key[12:16])[0],
        struct.unpack('<I', key[16:20])[0],
        struct.unpack('<I', key[20:24])[0],
        struct.unpack('<I', key[24:28])[0],
        struct.unpack('<I', key[28:32])[0],
        counter,
        struct.unpack('<I', nonce[0:4])[0],
        struct.unpack('<I', nonce[4:8])[0],
        struct.unpack('<I', nonce[8:12])[0],
    ]
    initial = state[:]
    for _ in range(10):
        _quarter_round(state, 0, 4, 8, 12)
        _quarter_round(state, 1, 5, 9, 13)
        _quarter_round(state, 2, 6, 10, 14)
        _quarter_round(state, 3, 7, 11, 15)
        _quarter_round(state, 0, 5, 10, 15)
        _quarter_round(state, 1, 6, 11, 12)
        _quarter_round(state, 2, 7, 8, 13)
        _quarter_round(state, 3, 4, 9, 14)
    out = bytearray()
    for i in range(16):
        out.extend(struct.pack('<I', (state[i] + initial[i]) & 0xFFFFFFFF))
    return bytes(out)


def _chacha20_encrypt(key, counter, nonce, data):
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = _chacha20_block(key, counter + i // 64, nonce)
        chunk = data[i:i + 64]
        for j in range(len(chunk)):
            out.append(chunk[j] ^ ks[j])
    return bytes(out)


# ---------------------------------------------------------------------------
# Poly1305 MAC
# ---------------------------------------------------------------------------

_P = 2 ** 130 - 5


def _poly1305_mac(key, data):
    r_clamped = int.from_bytes(key[:16], 'little') & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], 'little')
    h = 0
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        n = int.from_bytes(block, 'little')
        n |= 1 << (8 * len(block))
        h = (h + n) % _P
        h = (h * r_clamped) % _P
    h = (h + s) & ((1 << 128) - 1)
    return h.to_bytes(16, 'little')


def _pad16(data):
    if len(data) % 16 == 0:
        return data
    return data + b'\x00' * (16 - len(data) % 16)


# ---------------------------------------------------------------------------
# ChaCha20-Poly1305 AEAD
# ---------------------------------------------------------------------------

class ChaCha20Poly1305Cipher:
    def __init__(self, key, nonce):
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes")
        if len(nonce) != 12:
            raise ValueError("Nonce must be 12 bytes")
        self._key = bytes(key)
        self._nonce = bytes(nonce)
        self._poly_key = _chacha20_block(self._key, 0, self._nonce)
        self._aad = bytearray()
        self._ct = bytearray()
        self._counter = 1

    def update(self, aad_bytes):
        if isinstance(aad_bytes, str):
            aad_bytes = aad_bytes.encode()
        self._aad.extend(aad_bytes)
        return aad_bytes

    def _crypt(self, data):
        remaining = len(data)
        offset = 0
        out = bytearray()
        while remaining > 0:
            ks = _chacha20_block(self._key, self._counter, self._nonce)
            take = min(remaining, 64)
            for j in range(take):
                out.append(data[offset + j] ^ ks[j])
            offset += take
            remaining -= take
            self._counter += 1
        return bytes(out)

    def encrypt(self, plaintext):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        ct = self._crypt(plaintext)
        self._ct.extend(ct)
        return ct

    def decrypt(self, ciphertext):
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode()
        pt = self._crypt(ciphertext)
        self._ct.extend(bytes(ciphertext))
        return pt

    def _compute_tag(self):
        aad = bytes(self._aad)
        ct = bytes(self._ct)
        mac_data = (_pad16(aad) + _pad16(ct) +
                    struct.pack('<Q', len(aad)) +
                    struct.pack('<Q', len(ct)))
        return _poly1305_mac(self._poly_key, mac_data)

    def encrypt_and_digest(self, plaintext):
        ct = self.encrypt(plaintext)
        return ct, self._compute_tag()

    def decrypt_and_verify(self, ciphertext, mac_tag):
        pt = self.decrypt(ciphertext)
        expected = self._compute_tag()
        if len(mac_tag) != 16 or not _consttime_compare(expected, mac_tag):
            raise ValueError("MAC check failed")
        return pt

    def digest(self):
        return self._compute_tag()


def _consttime_compare(a, b):
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


# ---------------------------------------------------------------------------
# API matching Crypto.Cipher.ChaCha20_Poly1305.new()
# ---------------------------------------------------------------------------

def new(key, nonce):
    return ChaCha20Poly1305Cipher(key, nonce)
