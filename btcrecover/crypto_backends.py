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
    import wallycore as w

    # wallycore lacks point-scalar multiplication for an arbitrary point, so the
    # Electrum 2.8 ECIES path reuses the pure-python backend (built once here).
    _pp_backend = _make_purepython_backend()

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

    def multiply_pubkey(pub, scalar):
        # wallycore has no public point-scalar multiplication for an arbitrary
        # point; fall back to the bundled pure-python ecpy implementation.
        return _pp_backend["multiply_pubkey"](pub, scalar)

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
