"""Utility script to exercise the recovery alert beeps."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path


if "btcrecover" not in sys.modules:
    # Add the repository root to sys.path so local imports work when the
    # script is executed directly (e.g. ``python utilities/test_beeper.py``).
    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

from btcrecover import success_alert


def _run_success_demo() -> None:
    print("Starting success alert demo. The alert will double-beep every 5 seconds.")
    print("Press Enter when you've heard enough to stop the alert.\n")
    success_alert.set_beep_on_find(True)
    success_alert.start_success_beep()
    try:
        success_alert.wait_for_user_to_stop()
    finally:
        success_alert.stop_success_beep()
        success_alert.set_beep_on_find(False)


def _run_failure_demo() -> None:
    print("Emitting a single failure beep...")
    success_alert.set_beep_on_find(True)
    try:
        success_alert.beep_failure_once()
    finally:
        success_alert.set_beep_on_find(False)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Play the success and/or failure alert beeps exactly as the recovery "
            "tool would when --beep-on-find is enabled."
        )
    )
    parser.add_argument(
        "mode",
        choices=("success", "failure", "both"),
        default="both",
        nargs="?",
        help=(
            "Which alert to demonstrate. Default is 'both', which plays a single "
            "failure beep followed by the repeating success beep."
        ),
    )

    args = parser.parse_args(argv)

    if args.mode in {"failure", "both"}:
        _run_failure_demo()
        if args.mode == "both":
            # Give the failure beep time to finish on terminals that queue BEL.
            time.sleep(0.5)
            print()

    if args.mode in {"success", "both"}:
        _run_success_demo()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
