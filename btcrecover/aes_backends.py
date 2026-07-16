# BTCRecover AES / ChaCha20-Poly1305 backend abstraction.
#
# Provides a common interface for symmetric crypto operations so that
# BTCRecover can run with one of two backends:
#
#   1. pycryptodome (C-backed, fast, full-featured)
#   2. pure python  (bundled implementations, slow but always available)
#
# If pycryptodome is not available, the pure-python backend is selected
# and a warning is printed at import time.

import struct
import warnings

_initial_warning = False

# ---------------------------------------------------------------------------
# Backend detection
# ---------------------------------------------------------------------------

_HAS_CRYPTO = False
_CRYPTO_AES = None
_CRYPTO_CHACHA = None

try:
    from Crypto.Cipher import AES as _CRYPTO_AES
    from Crypto.Cipher import ChaCha20_Poly1305 as _CRYPTO_CHACHA
    _HAS_CRYPTO = True
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Mode constants (match pycryptodome exactly)
# ---------------------------------------------------------------------------

MODE_ECB = 1
MODE_CBC = 2
MODE_GCM = 11
MODE_OFB = 5

# ---------------------------------------------------------------------------
# ChaCha20-Poly1305 convenience
# ---------------------------------------------------------------------------

def chacha20_poly1305_new(key, nonce):
    if _HAS_CRYPTO:
        return _CRYPTO_CHACHA.new(key=key, nonce=nonce)
    from lib import chacha20_poly1305
    return chacha20_poly1305.new(key, nonce)


# ---------------------------------------------------------------------------
# Pure-python AES multi-block helpers (pyaes only does 16-byte blocks)
# ---------------------------------------------------------------------------

def _split_blocks(data):
    for i in range(0, len(data), 16):
        yield data[i:i + 16]


def _pp_ecb_decrypt(key, data):
    from lib.pyaes import AES as _AES
    aes = _AES(key)
    result = bytearray()
    for block in _split_blocks(data):
        result.extend(aes.decrypt(block))
    return bytes(result)


def _pp_ecb_encrypt(key, data):
    from lib.pyaes import AES as _AES
    aes = _AES(key)
    result = bytearray()
    for block in _split_blocks(data):
        result.extend(aes.encrypt(block))
    return bytes(result)


def _pp_cbc_decrypt(key, iv, data):
    from lib.pyaes import AES as _AES
    aes = _AES(key)
    prev = iv
    result = bytearray()
    for block in _split_blocks(data):
        dec = aes.decrypt(block)
        for j in range(16):
            result.append(dec[j] ^ prev[j])
        prev = block
    return bytes(result)


def _pp_cbc_encrypt(key, iv, data):
    from lib.pyaes import AES as _AES
    aes = _AES(key)
    prev = iv
    result = bytearray()
    for block in _split_blocks(data):
        xored = bytes([block[j] ^ prev[j] for j in range(16)])
        enc = aes.encrypt(xored)
        result.extend(enc)
        prev = enc
    return bytes(result)


# ---------------------------------------------------------------------------
# Pure-python cipher wrappers
# ---------------------------------------------------------------------------

class _PurePythonAES:
    def __init__(self, key, mode, *args, **kwargs):
        self._mode = mode
        if mode == MODE_ECB:
            self._key = key
        elif mode == MODE_CBC:
            self._key = key
            self._iv = args[0] if args else kwargs.get('iv', b'\x00' * 16)
        elif mode == MODE_GCM:
            nonce = args[0] if args else kwargs.get('nonce', None)
            if nonce is None:
                nonce = kwargs.get('iv', b'\x00' * 12)
            from lib.aes_gcm import _AES_GCM_Cipher
            self._gcm_impl = _AES_GCM_Cipher(key, nonce)

    def encrypt(self, data):
        if self._mode == MODE_ECB:
            return _pp_ecb_encrypt(self._key, data)
        elif self._mode == MODE_CBC:
            return _pp_cbc_encrypt(self._key, self._iv, data)

    def decrypt(self, data):
        if self._mode == MODE_ECB:
            return _pp_ecb_decrypt(self._key, data)
        elif self._mode == MODE_CBC:
            return _pp_cbc_decrypt(self._key, self._iv, data)
        elif self._mode == MODE_GCM:
            return self._gcm_impl.decrypt(data)

    def update(self, aad):
        if self._mode == MODE_GCM:
            return self._gcm_impl.update(aad)
        raise ValueError("update not supported for mode %d" % self._mode)

    def decrypt_and_verify(self, data, tag):
        if self._mode == MODE_GCM:
            return self._gcm_impl.decrypt_and_verify(data, tag)
        raise ValueError("decrypt_and_verify not supported for mode %d" % self._mode)

    def encrypt_and_digest(self, data):
        if self._mode == MODE_GCM:
            return self._gcm_impl.encrypt_and_digest(data)
        raise ValueError("encrypt_and_digest not supported for mode %d" % self._mode)

    def digest(self):
        if self._mode == MODE_GCM:
            return self._gcm_impl.digest()
        raise ValueError("digest not supported for mode %d" % self._mode)

    def verify(self, tag):
        if self._mode == MODE_GCM:
            return self._gcm_impl.verify(tag)
        raise ValueError("verify not supported for mode %d" % self._mode)


# ---------------------------------------------------------------------------
# Public AES API
# ---------------------------------------------------------------------------

class _AESModule:
    MODE_ECB = MODE_ECB
    MODE_CBC = MODE_CBC
    MODE_GCM = MODE_GCM
    MODE_OFB = MODE_OFB

    def new(self, key, mode, *args, **kwargs):
        global _initial_warning
        if _HAS_CRYPTO:
            return _CRYPTO_AES.new(key, mode, *args, **kwargs)
        if not _initial_warning:
            warnings.warn(
                "pycryptodome is not installed; falling back to bundled "
                "pure-Python AES implementation. This is significantly slower "
                "and should only be used when pycryptodome cannot be installed.",
                RuntimeWarning,
            )
            _initial_warning = True
        return _PurePythonAES(key, mode, *args, **kwargs)


AES = _AESModule()
