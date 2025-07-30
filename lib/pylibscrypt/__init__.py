# Copyright (c) 2014-2019, Jan Varho
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""Scrypt for Python"""

__version__ = '2.0.0-git'

# Prefer wallycore for scrypt as it performs about 20% faster than
# the pylibscrypt backend. If unavailable we fall back to pylibscrypt
# (via hashlib or libsodium as needed).
_done = False
try:
    import wallycore as _wallycore
    from . import mcf as mcf_mod
    from .common import (
        SCRYPT_N, SCRYPT_r, SCRYPT_p, SCRYPT_MCF_PREFIX_DEFAULT, check_args)

    def scrypt(password, salt, N=SCRYPT_N, r=SCRYPT_r, p=SCRYPT_p, olen=64):
        check_args(password, salt, N, r, p, olen)
        out = bytearray(olen)
        _wallycore.scrypt(password, salt, N, r, p, out)
        return bytes(out)

    def scrypt_mcf(password, salt=None, N=SCRYPT_N, r=SCRYPT_r, p=SCRYPT_p,
                   prefix=SCRYPT_MCF_PREFIX_DEFAULT):
        return mcf_mod.scrypt_mcf(scrypt, password, salt, N, r, p, prefix)

    def scrypt_mcf_check(mcf, password):
        return mcf_mod.scrypt_mcf_check(scrypt, mcf, password)
except ImportError:
    pass
else:
    _done = True

# First, try hashlib if wallycore isn't available
if not _done:
    try:
        from .hashlibscrypt import *
    except ImportError:
        pass
    else:
        _done = True

# If that didn't work, try loading libscrypt
if not _done:
    try:
        from .pylibscrypt import *
    except ImportError:
        pass
    else:
        _done = True

# Next: try the scrypt module
if not _done:
    try:
        from .pyscrypt import *
    except ImportError:
        pass
    else:
        _done = True

# Next: libsodium
if not _done:
    try:
        from .pylibsodium import *
    except ImportError:
        pass
    else:
        _done = True

# If that didn't work either, the inlined Python version
if not _done:
    from .pypyscrypt_inline import *

__all__ = ['scrypt', 'scrypt_mcf', 'scrypt_mcf_check']


