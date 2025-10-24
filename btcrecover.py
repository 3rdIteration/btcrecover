#!/usr/bin/env python

# btcrecover.py -- Bitcoin wallet password recovery tool
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

import compatibility_check

from btcrecover import btcrpass, success_alert
import itertools
import os
import re
import shlex
import subprocess
import sys
import multiprocessing


_SCAN_OPTION_MODES = {
    "--performance-scan": "flag",
    "--performance-scan-threads": "greedy",
    "--performance-scan-global-ws": "greedy",
    "--performance-scan-local-ws": "greedy",
    "--performance-scan-opencl-ws": "greedy",
    "--threads": "single",
    "--global-ws": "greedy",
    "--local-ws": "greedy",
    "--opencl-workgroup-size": "greedy",
    "--performance-runtime": "single",
}


def _strip_scan_related_args(argv):
    filtered = []
    i = 0
    length = len(argv)
    while i < length:
        token = argv[i]
        mode = _SCAN_OPTION_MODES.get(token)
        if not mode:
            filtered.append(token)
            i += 1
            continue
        i += 1
        if mode == "flag":
            continue
        if mode == "single":
            if i < length:
                i += 1
            continue
        if mode == "greedy":
            while i < length and not argv[i].startswith("--"):
                i += 1
            continue
    return filtered


def _format_local_ws(value):
    return "auto" if value is None else str(value)


def _format_opencl_workgroup(value):
    return "auto" if value is None else str(value)


def _derive_performance_scan_sets():
    runtime_limit = btcrpass.args.performance_runtime or 10.0
    if btcrpass.args.performance_runtime <= 0:
        print(
            "No --performance-runtime specified; defaulting to 10 seconds per benchmark.",
            file=sys.stderr,
        )

    threads_candidates = (
        sorted(
            {
                max(1, (btcrpass.args.threads or multiprocessing.cpu_count()) // 2),
                max(1, btcrpass.args.threads or multiprocessing.cpu_count()),
                min(64, (btcrpass.args.threads or multiprocessing.cpu_count()) * 2),
            }
        )
        if not btcrpass.args.performance_scan_threads
        else sorted(set(btcrpass.args.performance_scan_threads))
    )

    using_gpu = btcrpass.args.enable_gpu
    using_opencl = getattr(btcrpass.args, "enable_opencl", False)

    if using_gpu and using_opencl:
        return runtime_limit, {"mode": "conflict"}

    if using_gpu:
        base_global_ws = btcrpass.args.global_ws[0] if btcrpass.args.global_ws else 4096
        if btcrpass.args.performance_scan_global_ws:
            global_ws_candidates = sorted({value for value in btcrpass.args.performance_scan_global_ws})
        else:
            defaults = {
                base_global_ws,
                max(32, base_global_ws // 2) if base_global_ws // 2 else base_global_ws,
                base_global_ws * 2,
            }
            global_ws_candidates = sorted(value for value in defaults if value and value > 0)

        base_local_ws = btcrpass.args.local_ws[0] if btcrpass.args.local_ws else None
        if btcrpass.args.performance_scan_local_ws:
            local_ws_candidates = btcrpass.args.performance_scan_local_ws
        else:
            local_defaults = [None]
            if base_local_ws:
                local_defaults.extend(
                    [max(1, base_local_ws // 2), base_local_ws, base_local_ws * 2]
                )
            else:
                local_defaults.extend([32, 64, 128])
            local_ws_candidates = []
            for value in local_defaults:
                if value is None or value > 0:
                    if value not in local_ws_candidates:
                        local_ws_candidates.append(value)

        return (
            runtime_limit,
            {
                "mode": "gpu",
                "threads": threads_candidates,
                "global_ws": global_ws_candidates,
                "local_ws": local_ws_candidates,
            },
        )

    if using_opencl:
        if btcrpass.args.performance_scan_opencl_ws:
            workgroup_candidates = sorted(
                {value for value in btcrpass.args.performance_scan_opencl_ws if value > 0}
            )
        else:
            wallet = getattr(btcrpass, "loaded_wallet", None)
            base_workgroup = None
            if btcrpass.args.opencl_workgroup_size:
                base_workgroup = btcrpass.args.opencl_workgroup_size[0]
            elif wallet is not None:
                base_workgroup = getattr(wallet, "opencl_device_worksize", None)
            defaults = set()
            if base_workgroup:
                defaults.add(base_workgroup)
                defaults.add(max(1, base_workgroup // 2))
                defaults.add(base_workgroup * 2)
            else:
                defaults.update({4096, 8192, 16384})
            workgroup_candidates = sorted(value for value in defaults if value and value > 0)

        final_workgroups = []
        seen_workgroups = set()
        final_workgroups.append(None)
        seen_workgroups.add(None)
        for value in workgroup_candidates:
            if value not in seen_workgroups and value > 0:
                final_workgroups.append(value)
                seen_workgroups.add(value)

        return (
            runtime_limit,
            {
                "mode": "opencl",
                "threads": threads_candidates,
                "workgroups": final_workgroups,
            },
        )

    return runtime_limit, {"mode": None}


def _run_performance_scan():
    runtime_limit, scan_config = _derive_performance_scan_sets()

    mode = scan_config.get("mode") if scan_config else None

    if mode == "conflict":
        print(
            "Error: --performance-scan currently supports benchmarking a single accelerator configuration at a time.",
            file=sys.stderr,
        )
        return 1

    if mode == "gpu":
        if len(btcrpass.args.global_ws) > 1 or len(btcrpass.args.local_ws) > 1:
            print(
                "Error: --performance-scan currently supports benchmarking a single GPU configuration at a time.",
                file=sys.stderr,
            )
            return 1
    elif mode == "opencl":
        opencl_sizes = btcrpass.args.opencl_workgroup_size or []
        if len(opencl_sizes) > 1:
            print(
                "Error: --performance-scan currently supports benchmarking a single OpenCL configuration at a time.",
                file=sys.stderr,
            )
            return 1
    else:
        print(
            "Error: --performance-scan requires either --enable-gpu or --enable-opencl.",
            file=sys.stderr,
        )
        return 1

    combos = []
    seen = set()
    if mode == "gpu":
        for threads, global_ws, local_ws in itertools.product(
            scan_config["threads"],
            scan_config["global_ws"],
            scan_config["local_ws"],
        ):
            if local_ws and (global_ws % local_ws != 0 or local_ws > global_ws):
                continue
            key = (threads, global_ws, local_ws)
            if key in seen:
                continue
            combos.append({
                "threads": threads,
                "global_ws": global_ws,
                "local_ws": local_ws,
            })
            seen.add(key)
    else:  # mode == "opencl"
        for threads, workgroup in itertools.product(
            scan_config["threads"],
            scan_config["workgroups"],
        ):
            key = (threads, workgroup)
            if key in seen:
                continue
            combos.append({"threads": threads, "workgroup": workgroup})
            seen.add(key)

    if not combos:
        print("No valid performance scan combinations to test.", file=sys.stderr)
        return 1

    script_path = os.path.abspath(__file__)
    base_args = _strip_scan_related_args(sys.argv[1:])
    runtime_arg = ["--performance-runtime", f"{runtime_limit}"]
    total = len(combos)
    results = []
    failures = []
    summary_pattern = re.compile(
        r"Performance summary:\s*([0-9][0-9,\.]*?)\s*kP/s over ([0-9]*\.?[0-9]+) seconds \(([0-9][0-9,]*) passwords tried\)(.*)"
    )

    print(f"Running performance scan across {total} configuration(s)...")

    for index, combo in enumerate(combos, start=1):
        if mode == "gpu":
            descriptor = (
                f"threads={combo['threads']}, global-ws={combo['global_ws']}, "
                f"local-ws={_format_local_ws(combo['local_ws'])}"
            )
        else:
            descriptor = (
                f"threads={combo['threads']}, "
                f"opencl-workgroup={_format_opencl_workgroup(combo['workgroup'])}"
            )
        print(f"[{index}/{total}] {descriptor}")
        cmd = [sys.executable, script_path] + base_args + runtime_arg
        cmd.extend(["--threads", str(combo["threads"])])
        if mode == "gpu":
            cmd.extend(["--global-ws", str(combo["global_ws"])])
            if combo["local_ws"] is not None:
                cmd.extend(["--local-ws", str(combo["local_ws"])])
        else:
            if combo["workgroup"] is not None:
                cmd.extend(["--opencl-workgroup-size", str(combo["workgroup"])])
        result = subprocess.run(cmd, capture_output=True, text=True)
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        summary_line = None
        for line in stdout.splitlines():
            if line.startswith("Performance summary:"):
                summary_line = line.strip()
        if summary_line:
            match = summary_pattern.search(summary_line)
        else:
            match = None

        if match:
            rate = float(match.group(1).replace(",", ""))
            elapsed = float(match.group(2))
            passwords = int(match.group(3).replace(",", ""))
            note = match.group(4).strip()
            entry = {
                "threads": combo["threads"],
                "rate": rate,
                "elapsed": elapsed,
                "passwords": passwords,
                "note": note,
                "summary": summary_line,
                "exit_code": result.returncode,
            }
            if mode == "gpu":
                entry.update(
                    {
                        "global_ws": combo["global_ws"],
                        "local_ws": combo["local_ws"],
                    }
                )
            else:
                entry["workgroup"] = combo["workgroup"]
            results.append(entry)
            print(f"    {summary_line}")
        else:
            failure_info = {
                "threads": threads,
                "global_ws": global_ws,
                "local_ws": local_ws,
                "exit_code": result.returncode,
                "stdout": stdout,
                "stderr": stderr,
            }
            failures.append(failure_info)
            print("    Benchmark failed to produce a performance summary.")
            if stderr:
                print(f"    stderr: {stderr}")

    if results:
        sorted_results = sorted(results, key=lambda item: item["rate"], reverse=True)
        best_result = sorted_results[0]
        if mode == "gpu":
            best_label = (
                f"threads={best_result['threads']}, global-ws={best_result['global_ws']}, "
                f"local-ws={_format_local_ws(best_result['local_ws'])}"
            )
        else:
            best_label = (
                f"threads={best_result['threads']}, opencl-workgroup={_format_opencl_workgroup(best_result['workgroup'])}"
            )
        print("\nBest configuration by throughput:")
        print(
            f"  {best_label}: {best_result['rate']:,.2f} kP/s over {best_result['elapsed']:.2f} seconds"
            f" ({best_result['passwords']:,} passwords tried)"
        )
        if best_result["note"]:
            print(f"    {best_result['note']}")

        recommended_cmd = [sys.executable, script_path] + base_args
        if runtime_limit:
            recommended_cmd.extend(["--performance-runtime", f"{runtime_limit}"])
        recommended_cmd.extend(["--threads", str(best_result["threads"])])
        if mode == "gpu":
            recommended_cmd.extend(["--global-ws", str(best_result["global_ws"])])
            if best_result["local_ws"] is not None:
                recommended_cmd.extend(["--local-ws", str(best_result["local_ws"])])
        else:
            if best_result["workgroup"] is not None:
                recommended_cmd.extend(["--opencl-workgroup-size", str(best_result["workgroup"])])
        print("  Recommended command:")
        print(f"    {' '.join(shlex.quote(arg) for arg in recommended_cmd)}")

        print("\nFull performance scan summary (sorted by throughput):")
        for entry in sorted_results:
            note_suffix = f" {entry['note']}" if entry["note"] else ""
            if mode == "gpu":
                label = (
                    f"threads={entry['threads']}, global-ws={entry['global_ws']}, "
                    f"local-ws={_format_local_ws(entry['local_ws'])}"
                )
            else:
                label = (
                    f"threads={entry['threads']}, "
                    f"opencl-workgroup={_format_opencl_workgroup(entry['workgroup'])}"
                )
            print(
                f"  {label}: {entry['rate']:,.2f} kP/s over {entry['elapsed']:.2f} seconds"
                f" ({entry['passwords']:,} passwords tried){note_suffix}"
            )

    if failures:
        print("\nThe following configurations did not complete successfully:")
        for entry in failures:
            if mode == "gpu":
                label = (
                    f"threads={entry['threads']}, global-ws={entry['global_ws']}, "
                    f"local-ws={_format_local_ws(entry['local_ws'])}"
                )
            else:
                label = (
                    f"threads={entry['threads']}, "
                    f"opencl-workgroup={_format_opencl_workgroup(entry['workgroup'])}"
                )
            print(f"  {label}: exit code {entry['exit_code']}")

    return 0 if results else 1

if __name__ == "__main__":
    print()
    print(
        "Starting",
        btcrpass.full_version(),
        file=sys.stderr if any(a.startswith("--listp") for a in sys.argv[1:]) else sys.stdout,
    )  # --listpass

    btcrpass.parse_arguments(sys.argv[1:])

    if btcrpass.args.performance and getattr(btcrpass.args, "performance_scan", False):
        retval = _run_performance_scan()
        for process in multiprocessing.active_children():
            process.join(1.0)
        success_alert.stop_success_beep()
        sys.exit(retval)

    (password_found, not_found_msg) = btcrpass.main()

    if btcrpass.args.performance and btcrpass.performance_run_completed:
        retval = 0

    elif isinstance(password_found, str):
        success_alert.start_success_beep()
        print()
        print(
            "If this tool helped you to recover funds, please consider donating 1% of what you recovered, in your crypto of choice to:"
        )
        print("BTC: 37N7B7sdHahCXTcMJgEnHz7YmiR4bEqCrS ")
        print("BCH: qpvjee5vwwsv78xc28kwgd3m9mnn5adargxd94kmrt ")
        print("LTC: M966MQte7agAzdCZe5ssHo7g9VriwXgyqM ")
        print("ETH: 0x72343f2806428dbbc2C11a83A1844912184b4243 ")

        # print("VTC: vtc1qxauv20r2ux2vttrjmm9eylshl508q04uju936n ")
        # print("ZEN: znUihTHfwm5UJS1ywo911mdNEzd9WY9vBP7 ")
        # print("DASH: Xx2umk6tx25uCWp6XeaD5f7CyARkbemsZG ")
        # print("DOGE: DMQ6uuLAtNoe5y6DCpxk2Hy83nYSPDwb5T ")
        # print("XMR: 48wnuLYsPY7ewLQyF4RLAj3N8CHH4oBBcaoDjUQFiR4VfkgPNYBh1kSfLx94VoZSsGJnuUiibJuo7FySmqroAi6c1MLWHYF ")
        # print("MONA: mona1q504vpcuyrrgr87l4cjnal74a4qazes2g9qy8mv ")
        # print("XVG: DLZDT48wfuaHR47W4kU5PfW1JfJY25c9VJ")
        print()
        print("Find me on Reddit @ https://www.reddit.com/user/Crypto-Guide")
        print()
        print(
            "You may also consider donating to Gurnec, who created and maintained this tool until late 2017 @ 3Au8ZodNHPei7MQiSVAWb7NB2yqsb48GW4"
        )
        print()
        btcrpass.safe_print("Password found: '" + password_found + "'")
        if any(ord(c) < 32 or ord(c) > 126 for c in password_found):
            print(
                "HTML Encoded Password:   '"
                + password_found.encode("ascii", "xmlcharrefreplace").decode()
                + "'"
            )
        success_alert.wait_for_user_to_stop()
        retval = 0

    elif not_found_msg:
        print(not_found_msg, file=sys.stderr if btcrpass.args.listpass else sys.stdout)
        success_alert.beep_failure_once()
        retval = 0

    else:
        success_alert.beep_failure_once()
        retval = 1  # An error occurred or Ctrl-C was pressed

    # Wait for any remaining child processes to exit cleanly (to avoid error messages from gc)
    for process in multiprocessing.active_children():
        process.join(1.0)

    success_alert.stop_success_beep()

    sys.exit(retval)
