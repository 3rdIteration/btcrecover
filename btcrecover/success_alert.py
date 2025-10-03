"""Helpers for emitting an audible alert when recovery succeeds."""

from __future__ import annotations

import sys
import threading
import time
from typing import Optional

_beep_enabled = False
_success_beep_stop_event: Optional[threading.Event] = None
_success_beep_thread: Optional[threading.Thread] = None


def _emit_beeps(count: int, spacing: float = 0.2) -> None:
    """Emit ``count`` terminal bell characters with ``spacing`` seconds between them."""

    for index in range(count):
        try:
            print("\a", end="", flush=True)
        except Exception:
            pass
        if index + 1 < count:
            time.sleep(spacing)


def set_beep_on_find(enabled: bool) -> None:
    """Enable or disable the background success beep."""

    global _beep_enabled
    _beep_enabled = bool(enabled)
    if not _beep_enabled:
        stop_success_beep()


def start_success_beep() -> None:
    """Begin a background thread that emits a terminal bell every five seconds."""

    global _success_beep_stop_event, _success_beep_thread

    if not _beep_enabled or _success_beep_thread is not None:
        return

    _success_beep_stop_event = threading.Event()

    def _beep_loop() -> None:
        while True:
            _emit_beeps(2)
            if _success_beep_stop_event.wait(5):
                break

    _success_beep_thread = threading.Thread(
        target=_beep_loop,
        name="success_beep",
        daemon=True,
    )
    _success_beep_thread.start()


def stop_success_beep() -> None:
    """Stop the background success beep thread if it is running."""

    global _success_beep_stop_event, _success_beep_thread

    if _success_beep_stop_event is not None:
        _success_beep_stop_event.set()
    if _success_beep_thread is not None:
        _success_beep_thread.join(timeout=0.1)

    _success_beep_stop_event = None
    _success_beep_thread = None


def wait_for_user_to_stop(prompt: str = "\nPress Enter to stop the success alert and exit...") -> None:
    """Wait for the user to press Enter before stopping the alert.

    The wait only occurs when the success beep is active and stdin is interactive.
    """

    if not _beep_enabled or _success_beep_thread is None:
        return

    stdin = getattr(sys, "stdin", None)
    if stdin is None:
        return

    try:
        is_interactive = stdin.isatty()
    except AttributeError:
        is_interactive = False

    if not is_interactive:
        return

    try:
        input(prompt)
    except EOFError:
        # Non-interactive consumers may close stdin unexpectedly; just stop beeping.
        pass


def beep_failure_once() -> None:
    """Emit a single terminal bell when a recovery attempt fails."""

    if not _beep_enabled:
        return

    _emit_beeps(1)
