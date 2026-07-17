"""A Model Context Protocol (MCP) server exposing btcrecover to AI agents.

This lets tools like Claude drive recovery natively instead of shelling out and
scraping stdout. It exposes a few tools built on :mod:`btcrecover.api`:

* ``recover_password`` -- run the password recovery engine
* ``recover_seed``     -- run the seed / mnemonic recovery engine
* ``inspect_wallet``   -- autodetect a wallet file's type and difficulty
* ``list_wallet_types``-- enumerate supported wallet types

Run it (stdio transport) with::

    python -m btcrecover.mcp_server
    # or, once installed:  btcrecover-mcp

The ``mcp`` package is an optional dependency (``pip install btcrecover[mcp]``);
the tool *functions* below import cleanly without it so they can be unit-tested,
and only serving requires the SDK.

Safety / usage notes
--------------------
The recovery tools run the search synchronously and can take a long time. Agents
should scope work to keep calls bounded -- e.g. a small ``--passwordlist`` or
tokenlist, and a low ``--addr-limit`` -- and treat a long-running call as
expected for large search spaces rather than retrying it.
"""

import contextlib
import sys

from btcrecover import api

__all__ = [
    "recover_password_tool",
    "recover_seed_tool",
    "inspect_wallet_tool",
    "list_wallet_types_tool",
    "build_server",
    "main",
]


def recover_password_tool(args: list[str]) -> dict:
    """Recover a wallet password / passphrase.

    ``args`` is the argument list the ``btcrecover`` CLI accepts (without the
    program name), e.g. ``["--wallet", "wallet.dat", "--passwordlist",
    "guesses.txt"]``. Returns a structured result: ``status`` (found /
    not_found / interrupted / error), ``found`` (bool), and ``password``.
    """
    from btcrecover import btcrpass

    # A prior recover_seed call in this process may have swapped the shared
    # wallet registry over to seed autodetection; restore the default password
    # wallet set so a --wallet file can still be detected.
    btcrpass.restore_default_registered_wallets()
    return api.recover_password(args, quiet=True).to_dict()


def recover_seed_tool(args: list[str]) -> dict:
    """Recover a wallet seed / mnemonic sentence.

    ``args`` is the argument list the ``seedrecover`` CLI accepts, e.g.
    ``["--wallet-type", "bip39", "--addrs", "bc1...", "--mnemonic", "word1 ...",
    "--addr-limit", "10"]``. Returns a structured result: ``status``, ``found``,
    ``mnemonic``, and ``path_coin``.
    """
    return api.recover_seed(args, quiet=True).to_dict()


def inspect_wallet_tool(wallet_path: str) -> dict:
    """Autodetect a wallet file's type and report its cracking difficulty.

    Does not attempt any recovery. Returns ``wallet_type`` and, when available,
    a human-readable ``difficulty`` string, or an ``error`` if the file is not a
    recognized wallet.
    """
    from btcrecover import btcrpass

    with contextlib.redirect_stdout(sys.stderr):
        # A prior recover_seed call in this process may have swapped the shared
        # wallet registry over to seed autodetection; restore the default
        # password wallet set so file detection works.
        btcrpass.restore_default_registered_wallets()
        try:
            wallet = btcrpass.load_wallet(wallet_path)
        except SystemExit:
            return {"wallet_path": wallet_path, "error": "unrecognized or unreadable wallet file"}
        except Exception as e:  # noqa: BLE001 -- surface any load failure as data
            return {"wallet_path": wallet_path, "error": str(e)}

    info = {"wallet_path": wallet_path, "wallet_type": type(wallet).__name__}
    difficulty = getattr(wallet, "difficulty_info", None)
    if callable(difficulty):
        try:
            info["difficulty"] = difficulty()
        except Exception:  # noqa: BLE001
            pass
    return info


def list_wallet_types_tool() -> dict:
    """List the wallet types btcrecover supports.

    Returns ``password_wallet_types`` (for the password tool) and
    ``seed_wallet_types`` (for the seed tool).
    """
    from btcrecover import btcrpass, btcrseed

    password_types = sorted(
        wt.__name__ for wt in getattr(btcrpass, "wallet_types", [])
    )
    # selectable_wallet_classes is a list of (class, description) tuples.
    seed_types = sorted(
        description
        for _cls, description in getattr(btcrseed, "selectable_wallet_classes", [])
    )
    return {
        "password_wallet_types": password_types,
        "seed_wallet_types": seed_types,
    }


def build_server():
    """Construct the FastMCP server with all tools registered.

    Imports the ``mcp`` SDK lazily so the rest of this module is usable without
    it installed.
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as e:  # pragma: no cover - depends on optional extra
        raise SystemExit(
            "The MCP server requires the 'mcp' package. Install it with:\n"
            "    pip install btcrecover[mcp]\n"
            "or\n"
            "    pip install mcp"
        ) from e

    server = FastMCP("btcrecover")
    server.tool(name="recover_password")(recover_password_tool)
    server.tool(name="recover_seed")(recover_seed_tool)
    server.tool(name="inspect_wallet")(inspect_wallet_tool)
    server.tool(name="list_wallet_types")(list_wallet_types_tool)
    return server


def main():
    """Entry point: serve over stdio."""
    build_server().run()


if __name__ == "__main__":
    main()
