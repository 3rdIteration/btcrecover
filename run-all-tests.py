#!/usr/bin/env python

# run-all-tests.py -- runs *all* btcrecover tests
# Copyright (C) 2016, 2017 Christopher Gurnee
#
# This file is part of btcrecover.
#
# btcrecover is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version
# 2 of the License, or (at your option) any later version.
#
# btcrecover is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/

# If you find this program helpful, please consider a small
# donation to the developer at the following Bitcoin address:
#
#           3Au8ZodNHPei7MQiSVAWb7NB2yqsb48GW4
#
#                      Thank You!


import compatibility_check

# Use the green test runner if available
try:
    import green.config, green.suite, green.output, collections
    has_green = True

    # Adapter which uses green, but is similar in signature to unittest.main()
    def main(test_module, exit = None, buffer = None):
        import green.loader, green.runner
        if buffer:
            green_args.quiet_stdout = True
        try:
            suite = green.loader.GreenTestLoader().loadTestsFromModule(test_module)  # new API (v2.9+)
        except AttributeError:
            suite = green.loader.loadFromModule(test_module)                         # legacy API
        results = green.runner.run(suite, sys.stdout, green_args)
        # Return the results in an object with a "result" attribute, same as unittest.main()
        return collections.namedtuple("Tuple", "result")(results)

# If green isn't available, use the unittest test runner
except ImportError:
    from unittest import main
    has_green = False


if __name__ == "__main__":
    import argparse
    import atexit
    import multiprocessing
    import os
    import py_compile
    import subprocess
    import sys
    import time
    import timeit
    import tempfile
    from pathlib import Path

    from btcrecover.test import test_passwords

    is_coincurve_loadable = test_passwords.can_load_coincurve()
    if is_coincurve_loadable:
        from btcrecover.test     import test_seeds
        from btcrecover.btcrseed import full_version
    else:
        from btcrecover.btcrpass import full_version

    # Add two new arguments to those already provided by main()
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--no-buffer", action="store_true")
    parser.add_argument("--no-pause",  action="store_true")
    args, unparsed_args = parser.parse_known_args()
    sys.argv[1:] = unparsed_args

    # By default, pause before exiting
    if not args.no_pause:
        atexit.register(lambda: not multiprocessing.current_process().name.startswith("PoolWorker-") and
                                input("Press Enter to exit ..."))

    def verify_python_scripts() -> None:
        """Ensure CLI scripts compile and provide a basic execution path."""

        repo_root = Path(__file__).resolve().parent
        script_dirs = (
            repo_root,
            repo_root / "utilities",
            repo_root / "extract-scripts",
        )

        scripts = sorted(
            script
            for directory in script_dirs
            if directory.exists()
            for script in directory.iterdir()
            if script.is_file() and script.suffix == ".py"
        )

        this_file = Path(__file__).resolve()
        scripts = [script for script in scripts if script != this_file]

        env = os.environ.copy()
        pythonpath = env.get("PYTHONPATH")
        path_entries = [str(repo_root)]
        if pythonpath:
            path_entries.append(pythonpath)
        env["PYTHONPATH"] = os.pathsep.join(path_entries)

        temp_files = []

        try:
            for script in scripts:
                py_compile.compile(str(script), doraise=True)

            acceptable_return_codes = {0, 2}

            extra_args = {}
            skip_execution = {
                repo_root / "test_opencl_brute.py",
                repo_root / "utilities" / "generate_batch_seed_variations.py",
            }

            batch_script = repo_root / "seedrecover_batch.py"
            if batch_script in scripts:
                temp_batch = tempfile.NamedTemporaryFile(
                    "w", dir=str(repo_root), delete=False, encoding="utf-8"
                )
                temp_batch.write("# placeholder seed\n")
                temp_batch.close()
                temp_files.append(Path(temp_batch.name))
                extra_args[batch_script] = ("--batch-file", temp_batch.name)

            for script in scripts:
                if script in skip_execution:
                    continue

                help_flags = ("--help", "-h", None)
                last_result = None
                executed_successfully = False

                for flag in help_flags:
                    command = [sys.executable, str(script)]
                    if flag is not None:
                        command.append(flag)

                    if script in extra_args:
                        command.extend(extra_args[script])

                    last_result = subprocess.run(
                        command,
                        cwd=str(repo_root),
                        env=env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )

                    if last_result.returncode in acceptable_return_codes:
                        executed_successfully = True
                        break
                if executed_successfully:
                    continue

                stdout = last_result.stdout if last_result else ""
                stderr = last_result.stderr if last_result else ""
                code = last_result.returncode if last_result else "unknown"

                missing_dependency = "No module named" in stderr

                if missing_dependency:
                    print(
                        "Skipping {} verification due to missing optional dependency.".format(
                            script.name
                        ),
                        file=sys.stderr,
                    )
                    continue

                raise RuntimeError(
                    "Failed to execute {} with --help/-h for verification.\n"
                    "Exit code: {}\n"
                    "Stdout:\n{}\n"
                    "Stderr:\n{}".format(script, code, stdout, stderr)
                )
        finally:
            for temp_file in temp_files:
                try:
                    temp_file.unlink()
                except OSError:
                    pass

    print("Testing", full_version() + "\n")

    print("Verifying Python scripts for syntax and basic execution...\n")

    try:
        verify_python_scripts()
    except Exception as exc:
        print("Script verification failed:", file=sys.stderr)
        print(exc, file=sys.stderr)
        sys.exit(1)

    # Additional setup normally done by green.cmdline.main()
    if has_green:
        green_args = green.config.parseArguments()
        green_args = green.config.mergeConfig(green_args)
        if green_args.shouldExit:
            sys.exit(green_args.exitCode)
        green.suite.GreenTestSuite.args = green_args
        if green_args.debug:
            green.output.debug_level = green_args.debug

    total_tests = total_skipped = total_failures = total_errors = total_passing = 0
    def accumulate_results(r):
        global total_tests, total_skipped, total_failures, total_errors, total_passing
        total_tests    += r.testsRun
        total_skipped  += len(r.skipped)
        total_failures += len(r.failures)
        total_errors   += len(r.errors)
        if has_green:
            total_passing += len(r.passing)

    timer = timeit.default_timer
    start_time = time.time() if has_green else timer()

    print()
    if not has_green:
        print("** Testing in Unicode character mode **")
    os.environ["BTCR_CHAR_MODE"] = "unicode"
    results = main(test_passwords, exit=False, buffer= not args.no_buffer).result
    accumulate_results(results)

    if is_coincurve_loadable:
        print("\n** Testing seed recovery **")
        results = main(test_seeds, exit=False, buffer= not args.no_buffer).result
        accumulate_results(results)
    else:
        print("\nwarning: skipping seed recovery tests (can't find prerequisite coincurve)")

    print("\n\n*** Full Results ***")
    if has_green:
        # Print the results in color using green
        results.startTime  = start_time
        results.testsRun   = total_tests
        results.passing    = (None,) * total_passing
        results.skipped    = (None,) * total_skipped
        results.failures   = (None,) * total_failures
        results.errors     = (None,) * total_errors
        results.all_errors = ()
        green_args.no_skip_report = True
        results.stopTestRun()
    else:
        print("\nRan {} tests in {:.3f}s\n".format(total_tests, timer() - start_time))
        print("OK" if total_failures == total_errors == 0 else "FAILED")

        details = [
            name + "=" + str(val)
            for name,val in (("failures", total_failures), ("errors", total_errors), ("skipped", total_skipped))
                if val
        ]
        if details:
            print(" (" + ", ".join(details) + ")")
        print("\n")

    sys.exit(0 if total_failures == total_errors == 0 else 1)
