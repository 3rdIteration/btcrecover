"""Password-recovery engine package.

Historically this was a single ``btcrecover/btcrpass.py`` module. It is being
split into smaller modules for maintainability; the engine currently lives in
:mod:`btcrecover.btcrpass._engine`.

To keep the long-standing public surface working unchanged -- ``from btcrecover
import btcrpass`` then ``btcrpass.main()``, ``btcrpass.WalletBitcoinCore``,
``btcrpass.args`` (which the engine reassigns at runtime), etc. -- this package
is a transparent proxy onto ``_engine``: attribute access is delegated live via a
module-level ``__getattr__`` (PEP 562), so reassigned globals always resolve to
their current value and wallet-class identity checks (``type(w) is
btcrpass.WalletX``) still hold.
"""

from . import _engine

# Support ``from btcrecover.btcrpass import *`` -- each name is resolved live
# through __getattr__ below.
__all__ = [name for name in dir(_engine) if not name.startswith("_")]


def __getattr__(name):
    return getattr(_engine, name)


def __dir__():
    return sorted(set(list(globals()) + dir(_engine)))
