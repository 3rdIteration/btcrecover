"""Helpers for emitting an audible alert when recovery succeeds."""

from __future__ import annotations

import threading
from typing import Optional

_beep_enabled = False
_success_beep_stop_event: Optional[threading.Event] = None
_success_beep_thread: Optional[threading.Thread] = None


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
            try:
                print("\a", end="", flush=True)
            except Exception:
                pass
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
