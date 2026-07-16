#!/usr/bin/env python3
"""
benchmark_crypto_backends.py -- compares the speed of the three secp256k1
backends supported by btcrecover.crypto_backends:

    1. coincurve   (C, libsecp256k1)
    2. wallycore   (C, libwally-core)
    3. purepython  (bundled ecpy, slow)

For each available backend it measures the throughput of the operations that
matter most to wallet recovery: deriving a compressed/uncompressed public key
from a private key, the P2TR tap-tweak, and the ECIES point multiplication used
by Electrum 2.8 wallets.

Usage:
    python benchmark_crypto_backends.py [iterations]

The default iteration count is chosen so the whole benchmark finishes in a few
seconds for the C backends and a little longer for the pure-Python one.
"""

import os
import sys
import time

# Make sure the repo root (parent of btcrecover/) is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from btcrecover import crypto_backends as cb


# Number of operations per timed block. Kept modest because the pure-Python
# backend is intentionally slow.
ITERATIONS = int(sys.argv[1]) if len(sys.argv) > 1 else 2000


def _make_backend(name):
    """Build a single backend's function dict directly (bypassing auto-select)."""
    if name == "coincurve":
        try:
            return cb._make_coincurve_backend()
        except Exception as e:  # pragma: no cover
            print("coincurve unavailable: %s" % e)
            return None
    if name == "wallycore":
        try:
            return cb._make_wallycore_backend()
        except Exception as e:  # pragma: no cover
            print("wallycore unavailable: %s" % e)
            return None
    if name == "purepython":
        try:
            return cb._make_purepython_backend()
        except Exception as e:  # pragma: no cover
            print("purepython unavailable: %s" % e)
            return None
    raise ValueError(name)


def _time_it(fn, iters):
    # warm up
    fn()
    start = time.perf_counter()
    for _ in range(iters):
        fn()
    elapsed = time.perf_counter() - start
    return elapsed, iters / elapsed if elapsed else float("inf")


def main():
    priv = (0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF).to_bytes(32, "big")
    epub = cb.privkey_to_pubkey(priv, compressed=True)
    tweak = (0x01).to_bytes(31, "big") + b"\x02"
    h = b"\x11" * 32

    backends = []
    for name in ("coincurve", "wallycore", "purepython"):
        be = _make_backend(name)
        if be is not None:
            backends.append((name, be))

    if not backends:
        print("No secp256k1 backend available!")
        sys.exit(1)

    print("Benchmarking %d operations per backend\n" % ITERATIONS)
    header = "%-12s | %12s | %12s | %12s | %12s" % (
        "backend", "pubkey(comp)", "pubkey(unc)", "p2tr tweak", "ecies mult")
    print(header)
    print("-" * len(header))

    results = {}
    for name, be in backends:
        comp_t, comp_ops = _time_it(lambda: be["privkey_to_pubkey"](priv, True), ITERATIONS)
        unc_t, unc_ops = _time_it(lambda: be["privkey_to_pubkey"](priv, False), ITERATIONS)
        tweak_t, tweak_ops = _time_it(lambda: be["tweak_pubkey"](be["lift_x"](epub), h), ITERATIONS)
        mult_t, mult_ops = _time_it(lambda: be["multiply_pubkey"](epub, tweak), ITERATIONS)
        results[name] = (comp_ops, unc_ops, tweak_ops, mult_ops)
        print("%-12s | %12.1f | %12.1f | %12.1f | %12.1f" % (
            name, comp_ops, unc_ops, tweak_ops, mult_ops))

    # Relative speed-up of the fastest C backend vs pure-python (if both present)
    if "purepython" in results:
        fastest = max((n for n in results if n != "purepython"),
                      key=lambda n: results[n][0], default=None)
        if fastest:
            speedup = results[fastest][0] / results["purepython"][0]
            print("\nFastest C backend (%s) is ~%.1fx faster than pure-python "
                  "for pubkey derivation." % (fastest, speedup))

    print("\nActive backend selected at import time: %s" % cb.BACKEND_NAME)


if __name__ == "__main__":
    main()
