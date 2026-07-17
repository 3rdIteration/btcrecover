"""A small, structured library API over the recovery engines.

The command-line tools are argv-in / print-out and call ``sys.exit``. This
module wraps the existing engine seams (:func:`btcrpass.parse_arguments` +
:func:`btcrpass.main`, and :func:`btcrseed.main`) so that other Python code --
tests, the ``--json`` CLI mode, and the MCP server -- can run a recovery and get
a structured result object back instead of scraping stdout.

Nothing here changes CLI behaviour: it is a thin, additive layer.

Example
-------
    from btcrecover import api

    result = api.recover_password([
        "--wallet", "wallet.dat",
        "--passwordlist", "guesses.txt",
    ])
    if result.found:
        print("password is", result.password)
"""

import contextlib
import os
import sys
from dataclasses import asdict, dataclass
from typing import Optional, Sequence

__all__ = [
    "PasswordRecoveryResult",
    "SeedRecoveryResult",
    "recover_password",
    "recover_seed",
]


# Result status values (also used as the ``status`` field in ``to_dict()``).
STATUS_FOUND = "found"
STATUS_NOT_FOUND = "not_found"
STATUS_INTERRUPTED = "interrupted"
STATUS_ERROR = "error"


@dataclass
class PasswordRecoveryResult:
    """Outcome of a password recovery run."""

    status: str
    found: bool
    password: Optional[str] = None
    message: Optional[str] = None

    def to_dict(self) -> dict:
        return {"tool": "password", **asdict(self)}


@dataclass
class SeedRecoveryResult:
    """Outcome of a seed/mnemonic recovery run."""

    status: str
    found: bool
    mnemonic: Optional[str] = None
    path_coin: Optional[int] = None
    message: Optional[str] = None

    def to_dict(self) -> dict:
        return {"tool": "seed", **asdict(self)}


def _strip_json_flag(argv: Sequence[str]) -> list:
    """Drop the ``--json`` flag before handing argv to an engine.

    ``--json`` is handled entirely at the API / CLI boundary (this module runs
    quietly and returns a structured result). Some engine code paths re-parse
    argv with a strict secondary parser that does not know the flag, so it is
    removed here to avoid a spurious "unrecognized arguments" error.
    """
    return [a for a in argv if a != "--json"]


@contextlib.contextmanager
def _maybe_quiet(quiet: bool):
    """Redirect stdout chatter to stderr while *quiet* is true.

    The engines print progress banners and difficulty estimates to stdout, and
    the actual search runs in ``multiprocessing`` worker processes. To keep the
    real stdout clean (so a caller can emit a single JSON object there), the
    redirect is done at the file-descriptor level -- ``dup2`` of fd 1 onto fd 2 --
    so that child processes, which inherit fd 1, are covered too. A Python-level
    ``redirect_stdout`` would only affect the parent's ``print`` calls.
    """
    if not quiet:
        yield
        return

    sys.stdout.flush()
    try:
        saved_stdout_fd = os.dup(1)
    except (OSError, ValueError):
        # No real stdout fd (e.g. already redirected to a non-fd object under
        # some test runners) -- fall back to the Python-level redirect.
        with contextlib.redirect_stdout(sys.stderr):
            yield
        return

    try:
        os.dup2(2, 1)  # point fd 1 wherever stderr (fd 2) currently goes
        yield
    finally:
        sys.stdout.flush()
        os.dup2(saved_stdout_fd, 1)
        os.close(saved_stdout_fd)


def recover_password(
    argv: Sequence[str], quiet: bool = True
) -> PasswordRecoveryResult:
    """Run the password recovery engine and return a structured result.

    *argv* is the same argument list the ``btcrecover`` CLI accepts (without the
    program name), e.g. ``["--wallet", "w.dat", "--passwordlist", "g.txt"]``.
    """
    from btcrecover import btcrpass

    try:
        with _maybe_quiet(quiet):
            btcrpass.parse_arguments(_strip_json_flag(argv))
            password_found, not_found_msg = btcrpass.main()
    except SystemExit as e:
        # argparse (bad/--help args) and a few hard-stops call sys.exit(); at a
        # library boundary that should be a structured error, not a process kill.
        return PasswordRecoveryResult(
            STATUS_ERROR, False, message="exited with status {}".format(e.code)
        )

    if isinstance(password_found, str):
        return PasswordRecoveryResult(STATUS_FOUND, True, password=password_found)
    if password_found is False:
        return PasswordRecoveryResult(
            STATUS_NOT_FOUND, False, message=not_found_msg or None
        )
    # None -> interrupted (Ctrl-C) or a handled error inside main().
    return PasswordRecoveryResult(
        STATUS_INTERRUPTED, False, message=not_found_msg or None
    )


def recover_seed(argv: Sequence[str], quiet: bool = True) -> SeedRecoveryResult:
    """Run the seed/mnemonic recovery engine and return a structured result.

    *argv* is the same argument list the ``seedrecover`` CLI accepts.
    """
    from btcrecover import btcrseed

    try:
        with _maybe_quiet(quiet):
            btcrseed.register_autodetecting_wallets()
            mnemonic_sentence, path_coin = btcrseed.main(_strip_json_flag(argv))
    except SystemExit as e:
        return SeedRecoveryResult(
            STATUS_ERROR, False, message="exited with status {}".format(e.code)
        )

    if mnemonic_sentence:
        return SeedRecoveryResult(
            STATUS_FOUND,
            True,
            mnemonic=mnemonic_sentence,
            path_coin=path_coin,
        )
    if mnemonic_sentence is None:
        # An error occurred or Ctrl-C was pressed inside btcrseed.main().
        return SeedRecoveryResult(STATUS_INTERRUPTED, False)
    # Falsy-but-not-None -> the search completed without a match.
    return SeedRecoveryResult(STATUS_NOT_FOUND, False)
