#!/usr/bin/env python3
"""
Wrapper around skill_eval_harness.py that supports multiple test modes
(chat, docker, or both) from a single suite config.

In chat mode (no tools), OS filtering is disabled since the model can
give text advice for any OS. In docker mode, OS filtering is respected
since the tool environment is actual Linux.

Usage:
  python utilities/skill_eval/skill_eval_runner.py --suite-config utilities/skill_eval/example_suite.json

Suite config supports "test_modes" in "shared":
  "test_modes": ["docker"]           # docker only (with tools, OS-filtered)
  "test_modes": ["chat"]             # chat only (no tools, all OS)
  "test_modes": ["chat", "docker"]   # both modes
  Omit for original docker-only behavior.
"""

import argparse
import copy
import json
import os
import subprocess
import sys
import tempfile


def main() -> int:
    parser = argparse.ArgumentParser(description="Multi-mode skill evaluation runner")
    parser.add_argument("--suite-config", required=True, help="Path to suite config JSON")
    parser.add_argument("--skill-root", default=None, help="Override skill root directory")
    parser.add_argument("--scenario", action="append", default=None, help="Run specific scenario only")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    args, harness_args = parser.parse_known_args()

    # Load suite config
    config_path = os.path.abspath(args.suite_config)
    if not os.path.exists(config_path):
        print(f"Suite config not found: {config_path}", file=sys.stderr)
        return 1

    with open(config_path) as f:
        config = json.load(f)

    # Determine test modes
    shared = config.get("shared", {})
    test_modes = shared.pop("test_modes", ["docker"])

    # Resolve harness path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    harness = os.path.join(script_dir, "skill_eval_harness.py")
    if not os.path.exists(harness):
        harness = os.path.join(os.getcwd(), "utilities", "skill_eval", "skill_eval_harness.py")

    valid_modes = {"chat", "docker"}
    for mode in test_modes:
        if mode not in valid_modes:
            print(f"Invalid test_mode '{mode}'. Valid: {valid_modes}", file=sys.stderr)
            return 1

    total_runs = len(test_modes)
    exit_code = 0

    for idx, mode in enumerate(test_modes):
        # Patch a temporary config with the appropriate runner
        patched = copy.deepcopy(config)
        patched["shared"]["runner"] = mode
        patched["shared"].pop("skill_root", None)

        # Write temp config
        fd, tmp_path = tempfile.mkstemp(suffix=f"_{mode}.json", prefix="suite_")
        with os.fdopen(fd, "w") as f:
            json.dump(patched, f, indent=2)

        # Build command
        cmd = [sys.executable, harness, "--suite-config", tmp_path]
        if args.skill_root:
            cmd.extend(["--skill-root", args.skill_root])
        if args.scenario:
            for s in args.scenario:
                cmd.extend(["--scenario", s])

        # Chat mode: disable OS filtering since the model gives text advice for any OS
        if mode == "chat":
            cmd.append("--os-filter")
            cmd.append("all")
            # Also don't skip real-env scenarios in chat mode (it's just advice)
            cmd.append("--no-skip-real-env-scenarios")

        cmd.extend(harness_args)

        if args.verbose or total_runs > 1:
            label = f"[{idx+1}/{total_runs}] runner={mode}"
            print(f"\n{'='*70}")
            print(f"  {label}")
            print(f"{'='*70}")

        # Run harness
        result = subprocess.run(cmd, cwd=os.getcwd())
        if result.returncode != 0:
            exit_code = result.returncode

        # Cleanup temp config
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
