#!/usr/bin/env python3

# seedrecover.py -- Bitcoin mnemonic sentence recovery tool
# Copyright (C) 2014-2017 Christopher Gurnee
#
# This program is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version
# 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
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

# PYTHON_ARGCOMPLETE_OK - enables optional bash tab completion

import argparse
import datetime
import os
import shlex
import compatibility_check, copy

from btcrecover import btcrseed
from btcrecover import success_alert
import sys, multiprocessing


def _parse_batch_arguments(argv):
    """Extract batch specific arguments without disturbing btcrseed options."""

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "--batch-worker",
        metavar="ID(/ID2,...)/TOTAL",
        help="split batch processing across workers, similar to seedrecover --worker",
    )
    parser.add_argument(
        "--batch-file",
        default="batch_seeds.txt",
        metavar="FILE",
        help="batch seed file to process (default: %(default)s)",
    )
    parser.add_argument(
        "--batch-progress-file",
        metavar="FILE",
        help="file to append completed seeds and their status (default: BATCH_FILE.progress)",
    )
    parser.add_argument(
        "--batch-reverse",
        action="store_true",
        help="process the batch file in reverse order",
    )
    parser.add_argument(
        "--batch-skip-completed",
        action="store_true",
        help="skip seeds already marked as CHECKED or MATCHED in the progress file",
    )
    parser.add_argument(
        "--batch-progress-include-timestamp",
        action="store_true",
        help="include timestamps in progress log entries",
    )
    parser.add_argument(
        "--batch-progress-include-arguments",
        action="store_true",
        help="include command arguments in progress log entries",
    )

    parsed_args, remaining = parser.parse_known_args(argv[1:])
    sys.argv = [argv[0]] + remaining

    worker_ids = None
    workers_total = None
    progress_filename = parsed_args.batch_progress_file or f"{parsed_args.batch_file}.progress"

    if os.path.abspath(progress_filename) == os.path.abspath(parsed_args.batch_file):
        parser.error("progress file cannot be the same as the batch file")

    if parsed_args.batch_worker:
        try:
            worker_part, total_part = parsed_args.batch_worker.split("/")
            workers_total = int(total_part)
        except ValueError:  # pragma: no cover - defensive programming
            parser.error("--batch-worker must be formatted as ID(/ID2,...)/TOTAL")

        if workers_total < 2:
            parser.error("in --batch-worker ID#/TOTAL#, TOTAL# must be >= 2")

        try:
            worker_ids = [int(x) - 1 for x in worker_part.split(",")]
        except ValueError:
            parser.error("worker IDs must be integers")

        if min(worker_ids) < 0:
            parser.error("in --batch-worker ID#/TOTAL#, ID# must be >= 1")
        if max(worker_ids) >= workers_total:
            parser.error("in --batch-worker ID#/TOTAL#, ID# must be <= TOTAL#")

    return (
        parsed_args.batch_file,
        progress_filename,
        worker_ids,
        workers_total,
        parsed_args.batch_reverse,
        parsed_args.batch_skip_completed,
        parsed_args.batch_progress_include_timestamp,
        parsed_args.batch_progress_include_arguments,
    )


def _load_completed_seeds(progress_filename):
    completed_status = {}
    if not progress_filename:
        return set()

    success_statuses = {"MATCHED", "CHECKED"}

    try:
        with open(progress_filename, "r", encoding="utf-8") as progress_file:
            for line in progress_file:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 2:
                    continue

                status, seed_value = parts[0], parts[1]
                if not seed_value:
                    continue

                previous_status = completed_status.get(seed_value)

                if previous_status in success_statuses:
                    continue

                if status in success_statuses or previous_status is None:
                    completed_status[seed_value] = status
    except FileNotFoundError:
        return set()
    except OSError as exc:  # pragma: no cover - defensive programming
        print(
            f"Unable to read progress file '{progress_filename}' to skip completed seeds: {exc}",
            file=sys.stderr,
        )

    return {
        seed
        for seed, status in completed_status.items()
        if status in success_statuses
    }


def _progress_contains_match(progress_filename):
    if not progress_filename:
        return False

    try:
        with open(progress_filename, "r", encoding="utf-8") as progress_file:
            for line in progress_file:
                if line.startswith("MATCHED\t"):
                    return True
    except FileNotFoundError:
        return False
    except OSError as exc:  # pragma: no cover - defensive programming
        print(
            f"Unable to read progress file '{progress_filename}' while checking for matches: {exc}",
            file=sys.stderr,
        )

    return False


def _append_progress(
    progress_filename,
    seed,
    status,
    include_timestamp=False,
    arguments=None,
):
    if not progress_filename:
        return

    directory = os.path.dirname(progress_filename)
    if directory:
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError as exc:  # pragma: no cover - defensive programming
            print(
                f"Unable to create directories for progress file '{progress_filename}': {exc}",
                file=sys.stderr,
            )
            return

    try:
        with open(progress_filename, "a", encoding="utf-8") as progress_file:
            fields = [status, seed]
            if include_timestamp:
                fields.append(datetime.datetime.now().isoformat())
            if arguments:
                if isinstance(arguments, (list, tuple)):
                    argument_value = " ".join(shlex.quote(arg) for arg in arguments)
                else:
                    argument_value = str(arguments)
                fields.append(argument_value)
            progress_file.write("\t".join(fields) + "\n")
    except OSError as exc:  # pragma: no cover - defensive programming
        print(f"Unable to update progress file '{progress_filename}': {exc}", file=sys.stderr)

if __name__ == "__main__":
    (
        batch_filename,
        progress_filename,
        worker_ids,
        workers_total,
        process_reverse,
        skip_completed,
        include_timestamp,
        include_arguments,
    ) = _parse_batch_arguments(sys.argv)

    print()
    print("Starting", btcrseed.full_version())

    btcrseed.register_autodetecting_wallets()

    try:
        with open(batch_filename, "r", encoding="utf-8") as batch_seed_file:
            batch_seed_list = batch_seed_file.readlines()
    except OSError as exc:
        print(f"Unable to open batch file '{batch_filename}': {exc}", file=sys.stderr)
        sys.exit(1)

    if process_reverse:
        batch_seed_list = list(reversed(batch_seed_list))

    completed_seeds = (
        _load_completed_seeds(progress_filename) if skip_completed else set()
    )

    seed_index = 0
    retval = 0
    match_found = False

    for mnemonic in batch_seed_list:
        if _progress_contains_match(progress_filename):
            print("Stopping: matched seed already recorded in progress file")
            retval = 0
            break

        # Make a copy of the arguments
        temp_argv = copy.deepcopy(sys.argv)

        stripped_line = mnemonic.strip()
        if not stripped_line or stripped_line.startswith('#'):
            continue

        seed_to_try = mnemonic.split("#")[0].strip()

        if skip_completed and seed_to_try in completed_seeds:
            print("Skipping Seed (already completed):", seed_to_try)
            seed_index += 1
            continue

        if worker_ids is not None:
            if (seed_index % workers_total) not in worker_ids:
                seed_index += 1
                continue

        seed_index += 1

        # Split seeds from any comments
        temp_argv.append("--mnemonic")
        temp_argv.append(seed_to_try)

        print("Running Seed:", seed_to_try)

        try:
            mnemonic_sentence, path_coin = btcrseed.main(temp_argv[1:])
        except Exception:  # pragma: no cover - btcrseed failures are environment dependent
            print("Generated Exception...")
            _append_progress(
                progress_filename,
                seed_to_try,
                "ERROR",
                include_timestamp=include_timestamp,
                arguments=temp_argv[1:] if include_arguments else None,
            )
            continue

        if mnemonic_sentence:
            success_alert.start_success_beep()
            match_found = True
            _append_progress(
                progress_filename,
                seed_to_try,
                "MATCHED",
                include_timestamp=include_timestamp,
                arguments=temp_argv[1:] if include_arguments else None,
            )
            if skip_completed:
                completed_seeds.add(seed_to_try)
            if not btcrseed.tk_root:  # if the GUI is not being used
                print()
                print(
                    "If this tool helped you to recover funds, please consider donating 1% of what you recovered, in your crypto of choice to:")
                print("BTC: 37N7B7sdHahCXTcMJgEnHz7YmiR4bEqCrS ")
                print("BCH: qpvjee5vwwsv78xc28kwgd3m9mnn5adargxd94kmrt ")
                print("LTC: M966MQte7agAzdCZe5ssHo7g9VriwXgyqM ")
                print("ETH: 0x72343f2806428dbbc2C11a83A1844912184b4243 ")

                # Selective Donation Addressess depending on path being recovered... (To avoid spamming the dialogue with shitcoins...)
                # TODO: Implement this better with a dictionary mapping in seperate PY file with BTCRecover specific donation addys... (Seperate from YY Channel)
                if path_coin == 28:
                    print("VTC: vtc1qxauv20r2ux2vttrjmm9eylshl508q04uju936n ")

                if path_coin == 22:
                    print("MONA: mona1q504vpcuyrrgr87l4cjnal74a4qazes2g9qy8mv ")

                if path_coin == 5:
                    print("DASH: Xx2umk6tx25uCWp6XeaD5f7CyARkbemsZG ")

                if path_coin == 121:
                    print("ZEN: znUihTHfwm5UJS1ywo911mdNEzd9WY9vBP7 ")

                if path_coin == 3:
                    print("DOGE: DMQ6uuLAtNoe5y6DCpxk2Hy83nYSPDwb5T ")

                print()
                print("Find me on Reddit @ https://www.reddit.com/user/Crypto-Guide")
                print()
                print(
                    "You may also consider donating to Gurnec, who created and maintained this tool until late 2017 @ 3Au8ZodNHPei7MQiSVAWb7NB2yqsb48GW4")
                print()
                print("Seed found:", mnemonic_sentence)  # never dies from printing Unicode

            # print this if there's any chance of Unicode-related display issues
            if any(ord(c) > 126 for c in mnemonic_sentence):
                print("HTML Encoded Seed:", mnemonic_sentence.encode("ascii", "xmlcharrefreplace").decode())

            if not btcrseed.tk_root:
                success_alert.wait_for_user_to_stop()

            if btcrseed.tk_root:      # if the GUI is being used
                btcrseed.show_mnemonic_gui(mnemonic_sentence, path_coin)

            retval = 0
            break

        elif mnemonic_sentence is None:
            _append_progress(
                progress_filename,
                seed_to_try,
                "ERROR",
                include_timestamp=include_timestamp,
                arguments=temp_argv[1:] if include_arguments else None,
            )
            retval = 1  # An error occurred or Ctrl-C was pressed inside btcrseed.main()

        else:
            _append_progress(
                progress_filename,
                seed_to_try,
                "CHECKED",
                include_timestamp=include_timestamp,
                arguments=temp_argv[1:] if include_arguments else None,
            )
            if skip_completed:
                completed_seeds.add(seed_to_try)
            retval = 0  # "Seed not found" has already been printed to the console in btcrseed.main()

        # Wait for any remaining child processes to exit cleanly (to avoid error messages from gc)
        for process in multiprocessing.active_children():
            process.join(1.0)

    # Wait for any remaining child processes to exit cleanly (to avoid error messages from gc)
    for process in multiprocessing.active_children():
        process.join(1.0)

    if not match_found:
        success_alert.beep_failure_once()

    success_alert.stop_success_beep()

    sys.exit(retval)
