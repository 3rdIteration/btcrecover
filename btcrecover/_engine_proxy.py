"""Helper to make an engine package transparently proxy to its ``_engine`` module.

Both ``btcrecover.btcrpass`` and ``btcrecover.btcrseed`` were historically single
modules whose *public API includes module-level globals that callers read AND
write* -- e.g. tests do ``btcrpass.args = ...`` or ``btcrseed.loaded_wallet =
...`` and the engine then reads those globals internally.

When the engine code lives in a ``_engine`` submodule, a plain package
``__getattr__`` only covers reads; an external write like ``pkg.foo = x`` would
land on the package's own namespace, so the engine (reading ``_engine.foo``)
never sees it. To stay fully transparent we swap the package module's class for a
subclass that delegates attribute get/set/del to ``_engine``. The package still
has ``__path__``, so future sibling submodules import normally.
"""

import sys
import types


def install(package_name, engine_module):
    """Turn the already-imported package *package_name* into a live proxy onto
    *engine_module* (its ``_engine`` submodule)."""

    class _EngineProxyModule(types.ModuleType):
        def __getattr__(self, name):
            # Only reached when the attribute isn't found on the package module
            # itself (so package machinery like __path__/__spec__ is unaffected).
            return getattr(engine_module, name)

        def __setattr__(self, name, value):
            setattr(engine_module, name, value)

        def __delattr__(self, name):
            delattr(engine_module, name)

        def __dir__(self):
            return sorted(set(dir(engine_module)) | set(object.__dir__(self)))

    sys.modules[package_name].__class__ = _EngineProxyModule
