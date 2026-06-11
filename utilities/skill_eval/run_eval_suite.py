#!/usr/bin/env python3
"""Run one or more eval suite configs across all of their ``test_modes``.

The core harness (``skill_eval_harness.py``) runs a single runner mode per
invocation. This thin driver reads each suite config's ``shared.test_modes``
(default ``["docker", "chat"]`` order) and invokes the harness once per mode, so
a single config file is exercised in docker AND chat back-to-back.

Examples:
  # one system, docker then chat
  python utilities/skill_eval/run_eval_suite.py utilities/skill_eval/example_suite.json

  # several configs, each docker then chat (point at your own local configs)
  python utilities/skill_eval/run_eval_suite.py \
      my_configs/combined_5090.json \
      my_configs/combined_3070.json \
      my_configs/combined_deepseek.json

  # force a specific mode order / subset
  python utilities/skill_eval/run_eval_suite.py --modes chat,docker <config...>

  # show what would run without executing
  python utilities/skill_eval/run_eval_suite.py --dry-run <config...>
"""
from __future__ import annotations

import argparse
import json
import signal
import subprocess
import sys
from pathlib import Path


def _ignore_pause_signal() -> None:
    """Ignore the pause signal in the driver so Ctrl+Break (SIGBREAK) / Ctrl+\\ (SIGQUIT)
    pauses the harness child without terminating this wrapper. The child installs its
    own handler to toggle pause."""
    sig = getattr(signal, "SIGBREAK", None) or getattr(signal, "SIGQUIT", None)
    if sig is not None:
        try:
            signal.signal(sig, signal.SIG_IGN)
        except (ValueError, OSError):
            pass

# Lower sorts first -> docker runs before chat by default.
_MODE_ORDER = {"docker": 0, "chat": 1, "native": 2}


def _modes_for(shared: dict, forced: list[str] | None) -> list[str]:
    if forced:
        modes = list(forced)
    else:
        modes = shared.get("test_modes") or [shared.get("runner", "chat")]
    # de-duplicate while preserving the intended docker-before-chat ordering
    unique = list(dict.fromkeys(str(m).strip() for m in modes if str(m).strip()))
    return sorted(unique, key=lambda m: _MODE_ORDER.get(m, 99))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("configs", nargs="+", help="One or more suite-config JSON paths.")
    ap.add_argument(
        "--modes",
        default=None,
        help="Comma-separated runner modes to force (e.g. 'docker,chat'); overrides each config's test_modes.",
    )
    ap.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Keep going to the next mode/config if a run exits non-zero (default: stop).",
    )
    ap.add_argument("--dry-run", action="store_true", help="Print the harness commands without executing them.")
    ap.add_argument(
        "--harness-arg",
        action="append",
        default=[],
        dest="harness_args",
        metavar="ARG",
        help="Extra argument to forward to skill_eval_harness.py (repeatable). You can also "
             "just pass harness flags directly (e.g. --no-stream) — any flag this driver does "
             "not recognize is forwarded to the harness.",
    )
    # Unknown args (e.g. --no-stream, --no-judge-stream, --judge-max-tokens) are forwarded
    # straight to the harness so you don't have to wrap each one in --harness-arg.
    args, passthrough_args = ap.parse_known_args()
    args.harness_args = list(args.harness_args) + list(passthrough_args)
    _ignore_pause_signal()  # let Ctrl+Break pause the harness child, not kill this driver

    harness = Path(__file__).with_name("skill_eval_harness.py")
    if not harness.exists():
        print(f"[run_eval_suite] harness not found at {harness}", file=sys.stderr)
        return 2

    forced = [m.strip() for m in args.modes.split(",")] if args.modes else None

    plan: list[tuple[Path, str]] = []
    for cfg in args.configs:
        cfgp = Path(cfg)
        if not cfgp.exists():
            print(f"[run_eval_suite] config not found: {cfgp}", file=sys.stderr)
            return 2
        try:
            shared = json.loads(cfgp.read_text(encoding="utf-8")).get("shared", {})
        except (json.JSONDecodeError, OSError) as exc:
            print(f"[run_eval_suite] could not read {cfgp}: {exc}", file=sys.stderr)
            return 2
        for mode in _modes_for(shared, forced):
            plan.append((cfgp, mode))

    print(f"[run_eval_suite] {len(plan)} run(s) planned:")
    for cfgp, mode in plan:
        print(f"    - {cfgp.name}  ->  --runner {mode}")

    failures = 0
    for cfgp, mode in plan:
        cmd = [sys.executable, str(harness), "--suite-config", str(cfgp), "--runner", mode] + list(args.harness_args)
        print(f"\n===== {cfgp.name}  mode={mode} =====", flush=True)
        print("  " + " ".join(cmd), flush=True)
        if args.dry_run:
            continue
        rc = subprocess.run(cmd).returncode
        if rc != 0:
            failures += 1
            print(f"[run_eval_suite] {cfgp.name} mode={mode} exited {rc}", file=sys.stderr)
            if not args.continue_on_error:
                return rc

    if failures:
        print(f"\n[run_eval_suite] completed with {failures} failed run(s).", file=sys.stderr)
        return 1
    print("\n[run_eval_suite] all runs completed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
