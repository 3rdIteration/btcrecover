"""Helpers for emitting an audible alert when recovery succeeds."""

from __future__ import annotations

import atexit
import os
import shutil
import subprocess
import sys
import threading
import time
from typing import Iterable, Optional, Sequence, TextIO

try:
    import fcntl  # type: ignore
except ImportError:  # pragma: no cover - not expected on Windows
    fcntl = None  # type: ignore

_KDMKTONE = 0x4B30
_PC_SPEAKER_FREQUENCY_HZ = 880
_PC_SPEAKER_DURATION_MS = 150

_beep_enabled = False
_success_beep_stop_event: Optional[threading.Event] = None
_success_beep_thread: Optional[threading.Thread] = None
_console_bell_stream: Optional[TextIO] = None
_console_open_attempted = False
_DEFAULT_CONSOLE_PATHS: tuple[str, ...] = ("/dev/console", "/dev/tty0", "/dev/vc/0")
PC_SPEAKER_DEFAULT_CONSOLE_PATHS: tuple[str, ...] = _DEFAULT_CONSOLE_PATHS
_ENV_CONSOLE_PATHS: tuple[str, ...] = tuple(
    path
    for path in os.environ.get("BTCRECOVER_CONSOLE_BELL", "").split(os.pathsep)
    if path
)

_console_bell_paths: tuple[str, ...] = _ENV_CONSOLE_PATHS or _DEFAULT_CONSOLE_PATHS
_initial_console_bell_paths: tuple[str, ...] = _console_bell_paths
_pcspeaker_available: Optional[bool] = None
_pcspeaker_forced = False
_write_lock = threading.Lock()
_beep_command_available: Optional[bool] = None
_beep_command_path: Optional[str] = None


def _console_bell_fd() -> Optional[int]:
    stream = _ensure_console_bell_stream()
    if stream is None:
        return None

    try:
        return stream.fileno()
    except Exception:
        return None


def _beep_command() -> Optional[str]:
    global _beep_command_path

    if _beep_command_path:
        return _beep_command_path

    path = shutil.which("beep")
    if path:
        _beep_command_path = path
    return _beep_command_path


def _emit_beep_command(duration_ms: int, frequency_hz: int) -> bool:
    """Fallback to the external ``beep`` utility when available."""

    global _beep_command_available

    if _beep_command_available is False:
        return False

    command_path = _beep_command()
    if not command_path:
        _beep_command_available = False
        return False

    try:
        subprocess.run(
            [command_path, "-f", str(frequency_hz), "-l", str(duration_ms)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError):
        _beep_command_available = False
        return False

    _beep_command_available = True
    return True


def _emit_pc_speaker_beep(duration_ms: int, frequency_hz: int) -> bool:
    """Attempt to ring the internal PC speaker directly."""

    global _pcspeaker_available

    if _pcspeaker_available is False and not _pcspeaker_forced:
        return False

    if fcntl is None:
        _pcspeaker_available = False
        if _pcspeaker_forced:
            return _emit_beep_command(duration_ms, frequency_hz)
        return False

    fd = _console_bell_fd()
    if fd is None:
        _pcspeaker_available = False
        if _pcspeaker_forced:
            return _emit_beep_command(duration_ms, frequency_hz)
        return False

    if duration_ms <= 0 or frequency_hz <= 0:
        return False

    try:
        fcntl.ioctl(fd, _KDMKTONE, (frequency_hz << 16) | duration_ms)
    except OSError:
        _pcspeaker_available = False
        if _pcspeaker_forced:
            return _emit_beep_command(duration_ms, frequency_hz)
        return False

    _pcspeaker_available = True
    return True


def configure_pc_speaker(
    enable: bool,
    *,
    console_paths: Optional[Sequence[str]] = None,
) -> bool:
    """Control whether the alert attempts to use the motherboard PC speaker.

    When ``enable`` is :data:`True`, the helper will try to drive the kernel PC
    speaker interface via ``KDMKTONE`` ioctls against one of the provided
    console device paths. The caller can provide ``console_paths`` to override
    the default search order. When disabled, the original console configuration
    (derived from ``BTCRECOVER_CONSOLE_BELL`` if set) is restored.

    The function returns :data:`True` if the configuration succeeded or
    :data:`False` when the PC speaker could not be prepared. Callers may still
    attempt playback even if ``False`` is returned as hardware support and
    privileges vary between systems.
    """

    global _console_bell_paths, _pcspeaker_available, _pcspeaker_forced, _console_open_attempted

    _pcspeaker_forced = bool(enable)

    if enable:
        if console_paths is not None:
            _console_bell_paths = tuple(path for path in console_paths if path)
        elif not _ENV_CONSOLE_PATHS:
            _console_bell_paths = _DEFAULT_CONSOLE_PATHS
    else:
        _console_bell_paths = _initial_console_bell_paths

    # Reset cached state so we re-open the console with the new configuration.
    _close_console_bell_stream()
    _console_open_attempted = False
    _pcspeaker_available = None

    global _beep_command_available

    if not enable:
        _beep_command_available = None
        return True

    # Try to open the console immediately to surface failures early.
    stream = _ensure_console_bell_stream()
    if stream is None:
        if _beep_command():
            _beep_command_available = None
            return True
        return False

    fd = _console_bell_fd()
    return fd is not None


def _close_console_bell_stream() -> None:
    global _console_bell_stream

    stream = _console_bell_stream
    _console_bell_stream = None
    if stream is not None:
        try:
            stream.close()
        except Exception:
            pass


def _ensure_console_bell_stream() -> Optional[TextIO]:
    """Return a handle that writes directly to the system console when possible."""

    global _console_bell_stream, _console_open_attempted

    if _console_bell_stream is not None or _console_open_attempted:
        return _console_bell_stream

    _console_open_attempted = True

    for console_path in _console_bell_paths:
        if not console_path:
            continue

        try:
            stream = open(console_path, "w", encoding="utf-8", errors="ignore")
        except OSError:
            continue

        _console_bell_stream = stream
        atexit.register(_close_console_bell_stream)
        return _console_bell_stream

    return None


def _bell_streams(skip_console: bool = False) -> Iterable[TextIO]:
    """Yield file-like objects that should receive BEL characters."""

    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        if stream is None:
            continue
        try:
            if stream.isatty():
                yield stream
        except Exception:
            continue

    if not skip_console:
        console_stream = _ensure_console_bell_stream()
        if console_stream is not None:
            yield console_stream


def _emit_beeps(count: int, spacing: float = 0.2) -> None:
    """Emit ``count`` terminal bell characters with ``spacing`` seconds between them."""

    for index in range(count):
        with _write_lock:
            pcspeaker = _emit_pc_speaker_beep(
                _PC_SPEAKER_DURATION_MS,
                _PC_SPEAKER_FREQUENCY_HZ,
            )
            emitted = False
            for stream in _bell_streams(skip_console=pcspeaker):
                try:
                    stream.write("\a")
                    stream.flush()
                    emitted = True
                except Exception:
                    continue

            if not emitted and not pcspeaker:
                # Fall back to the default stdout behaviour even if it is not a TTY.
                try:
                    sys.stdout.write("\a")
                    sys.stdout.flush()
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
    """Begin a background thread that emits a two-tone alert roughly every ten seconds."""

    global _success_beep_stop_event, _success_beep_thread

    if not _beep_enabled or _success_beep_thread is not None:
        return

    _success_beep_stop_event = threading.Event()

    def _beep_loop() -> None:
        while True:
            _emit_beeps(2, spacing=1.5)
            if _success_beep_stop_event.wait(10):
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
