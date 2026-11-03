"""Seed/mnemonic-recovery engine package.

Historically this was a single ``btcrecover/btcrseed.py`` module. It is being
split into smaller modules for maintainability; the engine currently lives in
:mod:`btcrecover.btcrseed._engine`.

To keep the long-standing public surface working unchanged -- ``from btcrecover
import btcrseed`` then ``btcrseed.main()``, ``btcrseed.WalletBIP39``, and globals
the engine reassigns at runtime or that callers set directly
(``btcrseed.loaded_wallet = ...``, ``btcrseed.tk_root``) -- this package is a
transparent proxy onto ``_engine``: attribute get/set/del are delegated live to
``_engine`` (see :mod:`btcrecover._engine_proxy`), so reads see current values,
external writes reach the engine's own globals, and wallet-class identity checks
(``type(w) is btcrseed.WalletX``) still hold.
"""

from . import _engine
from .._engine_proxy import install as _install_proxy

# Support ``from btcrecover.btcrseed import *`` -- names resolve live via the
# proxy installed below.
__all__ = [name for name in dir(_engine) if not name.startswith("_")]

_install_proxy(__name__, _engine)
