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

_P = 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB


def _poly1305_mac(key, data):
    r0 = struct.unpack('<I', key[0:4])[0] & 0x0FFFFFFF
    r1 = struct.unpack('<I', key[4:8])[0] & 0x0FFFFFFC
    r2 = struct.unpack('<I', key[8:12])[0] & 0x0FFFFFFC
    r3 = struct.unpack('<I', key[12:16])[0] & 0x0FFFFFFC
    r4 = struct.unpack('<I', key[16:20])[0] & 0x0FFFFFFC
    s1 = struct.unpack('<I', key[20:24])[0]
    s2 = struct.unpack('<I', key[24:28])[0]
    s3 = struct.unpack('<I', key[28:32])[0]
    s4 = struct.unpack('<I', key[32:36])[0]
    h0 = h1 = h2 = h3 = h4 = 0
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        if len(block) == 16:
            n = struct.unpack('<IIII', block)
            n0, n1, n2, n3 = n[0], n[1], n[2], n[3]
        else:
            n0 = struct.unpack('<I', block[:4])[0]
            n1 = struct.unpack('<I', block[4:8])[0] if len(block) >= 8 else 0
            n2 = struct.unpack('<I', block[8:12])[0] if len(block) >= 12 else 0
            n3 = int.from_bytes(block[12:] + b'\x01', 'little') if len(block) < 16 else 0
        h0 = (h0 + n0) & 0xFFFFFFFF
        h1 = (h1 + n1) & 0xFFFFFFFF
        h2 = (h2 + n2) & 0xFFFFFFFF
        h3 = (h3 + n3) & 0xFFFFFFFF
        h4 = (h4 + (1 if len(block) < 16 else 0)) & 0x3
        d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1
        d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2
        d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3
        d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4
        d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0
        h0 = d0 & 0xFFFFFFFF
        h1 = (d0 >> 32 | d1 << 32) & 0xFFFFFFFF
        h2 = (d1 >> 32 | d2 << 32) & 0xFFFFFFFF
        h3 = (d2 >> 32 | d3 << 32) & 0xFFFFFFFF
        h4 = (d3 >> 32 | d4 << 32) & 0xFFFFFFFF
        h0 = (h0 | (h1 & 0x3) << 32) % _P
        h1 = ((h1 >> 2) | (h2 & 0xF) << 30) % _P
        h2 = ((h2 >> 4) | (h3 & 0x3F) << 28) % _P
        h3 = ((h3 >> 6) | (h4 & 0xFFF) << 26) % _P
        h4 = 0
    mac = struct.pack('<IIII', h0, h1, h2, h3)
    mac = int.from_bytes(mac, 'little') + int.from_bytes(key[36:52], 'little')
    return (mac & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF).to_bytes(16, 'little')


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
