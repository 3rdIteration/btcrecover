# BTCRecover crypto backend abstraction.
#
# Provides a common interface for secp256k1 public-key operations so that
# BTCRecover can run with one of three backends, in order of preference:
#
#   1. coincurve   - C-backed, wraps libsecp256k1 (fast, default)
#   2. wallycore   - C-backed, wraps libwally-core (fast alternative)
#   3. pure python - bundled ecpy library (slow, always available)
#
# If neither coincurve nor wallycore can be imported, the pure-python backend
# is selected and a warning is printed at import time.

import os
import warnings

# secp256k1 field prime and group order (used by callers that previously
# relied on coincurve.utils.GROUP_ORDER_INT and friends)
FIELD_PRIME = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
GROUP_ORDER_INT = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

PUBLIC_KEY_COMPRESSED_LEN = 33
PUBLIC_KEY_UNCOMPRESSED_LEN = 65

# ---------------------------------------------------------------------------
# Shared helpers (backend independent)
# ---------------------------------------------------------------------------

def bytes_to_int(data):
    return int.from_bytes(data, "big")


def int_to_bytes(n):
    # Minimal big-endian encoding (no fixed width)
    if n == 0:
        return b"\x00"
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")


def int_to_bytes_padded(n, length=32):
    # Fixed-width big-endian encoding, matching coincurve.utils.int_to_bytes_padded
    return n.to_bytes(length, "big")


def _privkey_valid(priv):
    # priv must be a 32-byte scalar in (0, GROUP_ORDER)
    if len(priv) != 32:
        return False
    n = bytes_to_int(priv)
    return 0 < n < GROUP_ORDER_INT


# ---------------------------------------------------------------------------
# Pure-python backend (uses the bundled ecpy library)
# ---------------------------------------------------------------------------

def _make_purepython_backend():
    import os
    import sys

    # ecpy imports itself as a top-level package ("import ecpy.curves"), so the
    # repo root (the parent directory of the bundled lib/ directory) must be on
    # sys.path. Add it if necessary.
    _repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _repo_root not in sys.path:
        sys.path.insert(0, _repo_root)

    import lib.ecpy as _ecpy_pkg
    import sys as _sys
    # ecpy imports itself as a top-level package ("import ecpy.curves"); expose
    # the bundled lib.ecpy package under that name so its internal imports work.
    _sys.modules.setdefault("ecpy", _ecpy_pkg)

    from lib.ecpy.curves import WeierstrassCurve as Curve, Point
    from lib.ecpy.curve_defs import curves as _ecpy_curves
    from lib.ecpy.keys import ECPublicKey, ECPrivateKey

    # Locate secp256k1 in ecpy's bundled curve definitions
    _curve = None
    for c in _ecpy_curves:
        if c.get("name") == "secp256k1":
            _curve = Curve(c)
            break
    if _curve is None:
        raise RuntimeError("secp256k1 curve not found in bundled ecpy library")

    def privkey_to_pubkey(priv, compressed=True):
        if not _privkey_valid(priv):
            raise ValueError("Invalid private key")
        pub = ECPrivateKey(bytes_to_int(priv), _curve).get_public_key()
        return _point_to_bytes(pub.W, compressed)

    def _point_to_bytes(pt, compressed=True):
        if compressed:
            prefix = b"\x02" if pt.y % 2 == 0 else b"\x03"
            return prefix + int_to_bytes_padded(pt.x, 32)
        return b"\x04" + int_to_bytes_padded(pt.x, 32) + int_to_bytes_padded(pt.y, 32)

    def _bytes_to_point(b):
        if b[0] == 0x04:
            x = bytes_to_int(b[1:33])
            y = bytes_to_int(b[33:65])
        else:
            x = bytes_to_int(b[1:33])
            beta = pow((pow(x, 3, FIELD_PRIME) + 7) % FIELD_PRIME,
                       (FIELD_PRIME + 1) // 4, FIELD_PRIME)
            y = beta if (b[0] == 0x02) == (beta % 2 == 0) else FIELD_PRIME - beta
        return Point(x, y, _curve)

    def pubkey_from_bytes(b):
        return _bytes_to_point(b)

    def pubkey_to_bytes(pub, compressed=True):
        if isinstance(pub, (bytes, bytearray)):
            # already serialized; re-serialize to requested format
            pub = _bytes_to_point(bytes(pub))
        return _point_to_bytes(pub, compressed)

    def pubkey_point(pub):
        if isinstance(pub, (bytes, bytearray)):
            pub = _bytes_to_point(bytes(pub))
        return (pub.x, pub.y)

    def multiply_pubkey(pub, scalar):
        if isinstance(pub, (bytes, bytearray)):
            pub = _bytes_to_point(bytes(pub))
        pt = (bytes_to_int(scalar)) * pub
        return _point_to_bytes(pt, compressed=True)

    def lift_x(pub):
        if isinstance(pub, (bytes, bytearray)):
            pub = _bytes_to_point(bytes(pub))
        if pub.y % 2 == 1:
            pub = -pub
        return pub

    def tweak_pubkey(pub, scalar):
        if isinstance(pub, (bytes, bytearray)):
            pub = _bytes_to_point(bytes(pub))
        pt = pub + (bytes_to_int(scalar)) * _curve.generator
        return _point_to_bytes(pt, compressed=True)

    return dict(
        name="purepython",
        privkey_to_pubkey=privkey_to_pubkey,
        pubkey_from_bytes=pubkey_from_bytes,
        pubkey_to_bytes=pubkey_to_bytes,
        pubkey_point=pubkey_point,
        multiply_pubkey=multiply_pubkey,
        lift_x=lift_x,
        tweak_pubkey=tweak_pubkey,
    )


# ---------------------------------------------------------------------------
# coincurve backend
# ---------------------------------------------------------------------------

def _make_coincurve_backend():
    import coincurve

    def privkey_to_pubkey(priv, compressed=True):
        # coincurve raises ValueError for invalid secrets, matching prior behavior
        return coincurve.PublicKey.from_valid_secret(priv).format(compressed=compressed)

    def pubkey_from_bytes(b):
        return coincurve.PublicKey(bytes(b))

    def pubkey_to_bytes(pub, compressed=True):
        if isinstance(pub, (bytes, bytearray)):
            pub = coincurve.PublicKey(bytes(pub))
        return pub.format(compressed=compressed)

    def pubkey_point(pub):
        if isinstance(pub, (bytes, bytearray)):
            pub = coincurve.PublicKey(bytes(pub))
        return pub.point()

    def multiply_pubkey(pub, scalar):
        if isinstance(pub, (bytes, bytearray)):
            pub = coincurve.PublicKey(bytes(pub))
        return pub.multiply(scalar).format(compressed=True)

    def lift_x(pub):
        if isinstance(pub, (bytes, bytearray)):
            pub = coincurve.PublicKey(bytes(pub))
        x, y = pub.point()
        if y % 2 == 1:
            pub = coincurve.PublicKey.from_point(x, FIELD_PRIME - y)
        return pub.format(compressed=True)

    def tweak_pubkey(pub, scalar):
        if isinstance(pub, (bytes, bytearray)):
            pub = coincurve.PublicKey(bytes(pub))
        x, y = pub.point()
        if y % 2 == 1:
            pub = coincurve.PublicKey.from_point(x, FIELD_PRIME - y)
        g = coincurve.PublicKey.from_point(
            0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
            0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
        return pub.combine([g.multiply(scalar)])

    return dict(
        name="coincurve",
        privkey_to_pubkey=privkey_to_pubkey,
        pubkey_from_bytes=pubkey_from_bytes,
        pubkey_to_bytes=pubkey_to_bytes,
        pubkey_point=pubkey_point,
        multiply_pubkey=multiply_pubkey,
        lift_x=lift_x,
        tweak_pubkey=tweak_pubkey,
    )


# ---------------------------------------------------------------------------
# wallycore backend
# ---------------------------------------------------------------------------

def _make_wallycore_backend():
    import functools
    import wallycore as w

    # Only reachable from multiply_pubkey's fallbacks below, so it is built on
    # first use rather than paying ecpy's curve setup on every import.
    @functools.lru_cache(maxsize=1)
    def _purepython():
        return _make_purepython_backend()

    def privkey_to_pubkey(priv, compressed=True):
        if not _privkey_valid(priv):
            raise ValueError("Invalid private key")
        pub = w.ec_public_key_from_private_key(bytes(priv))
        if compressed:
            return pub
        return w.ec_public_key_decompress(pub)

    def pubkey_from_bytes(b):
        # wally operates on serialized keys; keep the bytes as the pubkey handle
        return bytes(b)

    def pubkey_to_bytes(pub, compressed=True):
        pub = bytes(pub)
        if compressed:
            return _normalize_compressed(pub)
        return _normalize_uncompressed(pub)

    def _normalize_compressed(p):
        p = bytes(p)
        if len(p) == PUBLIC_KEY_COMPRESSED_LEN:
            return p
        return _compress(p)

    def _normalize_uncompressed(p):
        p = bytes(p)
        if len(p) == PUBLIC_KEY_UNCOMPRESSED_LEN:
            return p
        return w.ec_public_key_decompress(p)

    def _compress(p):
        p = bytes(p)
        unc = w.ec_public_key_decompress(p) if len(p) == PUBLIC_KEY_COMPRESSED_LEN else p
        x = unc[1:33]
        y = unc[33:65]
        prefix = b"\x02" if bytes_to_int(y) % 2 == 0 else b"\x03"
        return prefix + x

    def pubkey_point(pub):
        unc = _normalize_uncompressed(pub)
        return (bytes_to_int(unc[1:33]), bytes_to_int(unc[33:65]))

    # wallycore exposes no arbitrary point-scalar multiplication, but ECDSA
    # public key recovery is one in disguise. Recovery computes
    #     Q = r^-1 (sR - eG)
    # so with e = 0, R = P (r = P.x, recid = P.y parity) and s = k*P.x mod n,
    # it returns Q = r^-1 * k * r * P = k*P, entirely inside libsecp256k1. This
    # is ~50x faster than the bundled pure-python fallback.
    _ZERO_MSG = b"\x00" * 32

    @functools.lru_cache(maxsize=4)
    def _recovery_prefix(pub):
        # Cached because Electrum 2.8's ephemeral pubkey is constant for a whole
        # run, making the decompression a one-time rather than per-password cost.
        unc = _normalize_uncompressed(pub)
        x = bytes_to_int(unc[1:33])
        y = bytes_to_int(unc[33:65])
        if not 0 < x < GROUP_ORDER_INT:
            return None  # x has to be a valid scalar to stand in as r
        # libwally recoverable signature layout: [27 + 4 + recid] || r || s
        return x, bytes([27 + 4 + (y & 1)]) + unc[1:33]

    def _multiply_pubkey_recovery(pub, scalar):
        prefix = _recovery_prefix(bytes(pub))
        if prefix is not None:
            x, sig_prefix = prefix
            # k*P == (k mod n)*P, so reducing here also handles scalar >= n.
            s = (bytes_to_int(scalar) * x) % GROUP_ORDER_INT
            if s:
                return w.ec_sig_to_public_key(
                    _ZERO_MSG, sig_prefix + int_to_bytes_padded(s, 32))
        # P.x >= n (~2^-128), or a scalar that degenerates to s == 0.
        return _purepython()["multiply_pubkey"](pub, scalar)

    # Known-answer test for the trick above, generated from the bundled
    # pure-python backend and covering both recid parities. A libwally that
    # encodes recoverable signatures differently fails this and falls back
    # loudly, rather than silently returning wrong ECIES shared secrets.
    _KAT_SCALAR = bytes.fromhex(
        "0fedcba9876543210fedcba9876543210fedcba9876543210fedcba987654321")
    _KAT_VECTORS = (  # (pubkey, _KAT_SCALAR * pubkey)
        ("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
         "03fd1b7de8c449eecda5e5e2f3b4d7dcb5c241d0bb727d1c2098a4d3f423857b62"),
        ("03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556",
         "02d7709d1a7407ada96362092b63e266696428ff5fcdb17fd4355ba3971c114c3a"),
    )

    def _recovery_multiply_works():
        try:
            return all(
                _multiply_pubkey_recovery(bytes.fromhex(pub), _KAT_SCALAR)
                == bytes.fromhex(expected)
                for pub, expected in _KAT_VECTORS)
        except Exception:
            return False

    if _recovery_multiply_works():
        multiply_pubkey = _multiply_pubkey_recovery
    else:
        warnings.warn(
            "This wallycore build does not recover public keys the way BTCRecover "
            "expects, so Electrum 2.8 ECIES will fall back to the much slower "
            "bundled pure-Python implementation. Results stay correct. Please "
            "report this along with your wallycore version.", RuntimeWarning)

        def multiply_pubkey(pub, scalar):
            return _purepython()["multiply_pubkey"](pub, scalar)

    def lift_x(pub):
        x, y = pubkey_point(pub)
        if y % 2 == 1:
            return _compress(w.ec_public_key_negate(bytes(pub)))
        return _compress(bytes(pub))

    def tweak_pubkey(pub, scalar):
        # pub + scalar*G  (matches coincurve's LiftX(pub).combine([G.multiply(h)]))
        return w.ec_public_key_tweak(_normalize_compressed(pub), bytes(scalar))

    return dict(
        name="wallycore",
        privkey_to_pubkey=privkey_to_pubkey,
        pubkey_from_bytes=pubkey_from_bytes,
        pubkey_to_bytes=pubkey_to_bytes,
        pubkey_point=pubkey_point,
        multiply_pubkey=multiply_pubkey,
        lift_x=lift_x,
        tweak_pubkey=tweak_pubkey,
    )


# ---------------------------------------------------------------------------
# Backend selection
# ---------------------------------------------------------------------------

def _select_backend():
    # Allow forcing a specific backend via the BTCR_BACKEND environment variable
    # (useful for testing and for pinning a backend in constrained environments).
    forced = os.environ.get("BTCR_BACKEND", "").strip().lower()
    if forced in ("coincurve", "wallycore", "purepython"):
        factories = {
            "coincurve": _make_coincurve_backend,
            "wallycore": _make_wallycore_backend,
            "purepython": _make_purepython_backend,
        }
        try:
            return factories[forced]()
        except Exception as e:
            warnings.warn(
                "BTCR_BACKEND=%s was requested but could not be initialized (%s); "
                "falling back to automatic backend selection." % (forced, e),
                RuntimeWarning,
            )

    for factory in (_make_coincurve_backend, _make_wallycore_backend):
        try:
            return factory()
        except Exception:
            continue
    warnings.warn(
        "Neither coincurve nor wallycore could be imported; falling back to the "
        "bundled pure-Python secp256k1 implementation. This is significantly slower "
        "and should only be used when a C-backed library cannot be installed.",
        RuntimeWarning,
    )
    return _make_purepython_backend()


_backend = _select_backend()

# Public API (delegates to the selected backend)
BACKEND_NAME = _backend["name"]
privkey_to_pubkey = _backend["privkey_to_pubkey"]
pubkey_from_bytes = _backend["pubkey_from_bytes"]
pubkey_to_bytes = _backend["pubkey_to_bytes"]
pubkey_point = _backend["pubkey_point"]
multiply_pubkey = _backend["multiply_pubkey"]
lift_x = _backend["lift_x"]
tweak_pubkey = _backend["tweak_pubkey"]
