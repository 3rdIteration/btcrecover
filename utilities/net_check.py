#!/usr/bin/env python3
"""net_check.py - verify whether this machine has network connectivity.

Standard-library only (socket), so it runs anywhere Python runs - including
minimal sandboxes/containers that ship without ``ping``, ``curl`` or
``nslookup``. Intended for the BTCRecover offline gate: before entering real
secrets, the recovery machine must be OFFLINE, and this gives a deterministic,
parseable answer instead of relying on tools that may not be installed.

It does NOT send any secret or wallet data anywhere. It only attempts short TCP
connections to well-known public DNS resolvers to decide reachability.

Result (printed on the last line and reflected in the exit code):
    OFFLINE  -> exit 0   (safe to proceed with secret entry / recovery)
    ONLINE   -> exit 1   (do NOT proceed; disconnect first)
    UNKNOWN  -> exit 2   (could not determine; treat as online / unsafe)

Usage:
    python utilities/net_check.py            # default probes, ~2s timeout each
    python utilities/net_check.py --timeout 1
    python utilities/net_check.py --quiet     # print only OFFLINE/ONLINE/UNKNOWN
"""

import argparse
import socket
import sys

# (host, port) probes. TCP/53 (DNS) on major public resolvers is reachable from
# almost any online network and blocked/absent when truly offline.
DEFAULT_PROBES = [
    ("8.8.8.8", 53),   # Google DNS
    ("1.1.1.1", 53),   # Cloudflare DNS
    ("9.9.9.9", 53),   # Quad9 DNS
]


def probe(host, port, timeout):
    """Return True if a TCP connection to host:port succeeds within timeout."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check network connectivity (stdlib only).")
    parser.add_argument("--timeout", type=float, default=2.0,
                        help="per-probe timeout in seconds (default: 2.0)")
    parser.add_argument("--quiet", action="store_true",
                        help="print only the final OFFLINE/ONLINE/UNKNOWN verdict")
    args = parser.parse_args(argv)

    reachable = []
    errors = 0
    for host, port in DEFAULT_PROBES:
        ok = probe(host, port, args.timeout)
        if ok:
            reachable.append("%s:%d" % (host, port))
        if not args.quiet:
            print("  probe %-12s -> %s" % ("%s:%d" % (host, port),
                                           "reachable" if ok else "no route/refused"))

    if reachable:
        if not args.quiet:
            print("Reached: %s" % ", ".join(reachable))
        print("ONLINE")
        return 1

    # No probe reached. Distinguish "definitely offline" from "couldn't tell":
    # if we cannot even resolve a hostname, networking is down -> OFFLINE.
    try:
        socket.getaddrinfo("one.one.one.one", 53)
        # DNS resolved but no TCP probe reached - ambiguous (filtered network).
        print("UNKNOWN")
        return 2
    except OSError:
        if not args.quiet:
            print("No probes reachable and DNS resolution failed.")
        print("OFFLINE")
        return 0


if __name__ == "__main__":
    sys.exit(main())
