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
    python benchmark_crypto_backends.py [iterations] [--backend NAME]
                                         [--output FILE] [--comment TEXT]

    iterations   number of operations per timed block (default: 2000)
    --backend    force a single backend: coincurve, wallycore, or purepython.
                 When omitted, every available backend is benchmarked.
    --output     write the results as JSON to FILE.
    --comment    free-text note recorded in the JSON output (e.g. the host).

The default iteration count is chosen so the whole benchmark finishes in a few
seconds for the C backends and a little longer for the pure-Python one.
"""

import argparse
import datetime
import json
import os
import sys
import time

# Make sure the repo root (parent of btcrecover/) is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from btcrecover import crypto_backends as cb


VALID_BACKENDS = ("coincurve", "wallycore", "purepython")


# Number of operations per timed block. Kept modest because the pure-Python
# backend is intentionally slow.
DEFAULT_ITERATIONS = 2000


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
    parser = argparse.ArgumentParser(
        description="Benchmark BTCRecover secp256k1 backends.")
    parser.add_argument("iterations", nargs="?", type=int,
                        default=DEFAULT_ITERATIONS,
                        help="operations per timed block (default: %d)" % DEFAULT_ITERATIONS)
    parser.add_argument("--backend", choices=VALID_BACKENDS, default=None,
                        help="force a single backend instead of benchmarking all")
    parser.add_argument("--output", default=None,
                        help="write results as JSON to this file")
    parser.add_argument("--comment", default=None,
                        help="free-text note recorded in the JSON output")
    args = parser.parse_args()

    iters = args.iterations
    forced = args.backend

    priv = (0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF).to_bytes(32, "big")
    epub = cb.privkey_to_pubkey(priv, compressed=True)
    tweak = (0x01).to_bytes(31, "big") + b"\x02"
    h = b"\x11" * 32

    if forced is not None:
        be = _make_backend(forced)
        if be is None:
            print("Requested backend '%s' is not available; aborting." % forced)
            sys.exit(1)
        backends = [(forced, be)]
    else:
        backends = []
        for name in VALID_BACKENDS:
            be = _make_backend(name)
            if be is not None:
                backends.append((name, be))

    if not backends:
        print("No secp256k1 backend available!")
        sys.exit(1)

    scope = forced if forced is not None else "all available"
    print("Benchmarking %d operations per backend (%s)\n" % (iters, scope))
    header = "%-12s | %12s | %12s | %12s | %12s" % (
        "backend", "pubkey(comp)", "pubkey(unc)", "p2tr tweak", "ecies mult")
    print(header)
    print("-" * len(header))

    results = {}
    for name, be in backends:
        comp_t, comp_ops = _time_it(lambda: be["privkey_to_pubkey"](priv, True), iters)
        unc_t, unc_ops = _time_it(lambda: be["privkey_to_pubkey"](priv, False), iters)
        tweak_t, tweak_ops = _time_it(lambda: be["tweak_pubkey"](be["lift_x"](epub), h), iters)
        mult_t, mult_ops = _time_it(lambda: be["multiply_pubkey"](epub, tweak), iters)
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
    if forced is not None:
        print("Forced backend for this run: %s" % forced)

    if args.output:
        payload = {
            "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
            "iterations": iters,
            "forced_backend": forced,
            "active_backend_at_import": cb.BACKEND_NAME,
            "comment": args.comment,
            "results": {
                name: {
                    "pubkey_comp": comp_ops,
                    "pubkey_unc": unc_ops,
                    "p2tr_tweak": tweak_ops,
                    "ecies_mult": mult_ops,
                }
                for name, (comp_ops, unc_ops, tweak_ops, mult_ops) in results.items()
            },
        }
        with open(args.output, "w") as fh:
            json.dump(payload, fh, indent=2)
        print("\nWrote results to %s" % args.output)


if __name__ == "__main__":
    main()
