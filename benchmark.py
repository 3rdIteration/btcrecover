#!/usr/bin/env python3

# benchmark.py -- BTCRecover benchmarking tool
# Copyright (C) 2024 Stephen Rothery
#
# This file is part of btcrecover.
#
# btcrecover is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# btcrecover is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with btcrecover.  If not, see <http://www.gnu.org/licenses/>.

"""BTCRecover Benchmarking Tool

Runs performance benchmarks for various wallet types and seed recovery modes.
Tests CPU, GPU, and OpenCL acceleration. Results are saved as JSON files in
the benchmark-results/ directory for easy comparison across systems.

Usage:
    python benchmark.py                    # Run all CPU benchmarks
    python benchmark.py --gpu              # Also run GPU benchmarks
    python benchmark.py --opencl           # Also run OpenCL benchmarks
    python benchmark.py --duration 60      # Run each test for 60 seconds
    python benchmark.py --wallet-type all  # Test all wallet types (default)
    python benchmark.py --wallet-type seed # Test only seed recovery
"""

import argparse
import datetime
import json
import os
import platform
import re
import signal
import subprocess
import sys
import time


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WALLET_DIR = os.path.join(SCRIPT_DIR, "btcrecover", "test", "test-wallets")
RESULTS_DIR = os.path.join(SCRIPT_DIR, "benchmark-results")


def get_system_info():
    """Collect system information for the benchmark results."""
    info = {
        "hostname": platform.node(),
        "os": platform.system(),
        "os_version": platform.version(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "cpu_model": _get_cpu_model(),
        "cpu_cores_physical": _get_physical_cores(),
        "cpu_cores_logical": os.cpu_count(),
    }

    # Try to get GPU info
    gpu_info = _get_gpu_info()
    if gpu_info:
        info["gpu"] = gpu_info

    # Try to get OpenCL info
    opencl_info = _get_opencl_info()
    if opencl_info:
        info["opencl_devices"] = opencl_info

    return info


def _get_cpu_model():
    """Get the CPU model string."""
    try:
        if platform.system() == "Linux":
            with open("/proc/cpuinfo", "r") as f:
                for line in f:
                    if line.strip().startswith("model name"):
                        return line.split(":", 1)[1].strip()
        elif platform.system() == "Darwin":
            result = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip()
        elif platform.system() == "Windows":
            result = subprocess.run(
                ["wmic", "cpu", "get", "name"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                lines = [l.strip() for l in result.stdout.strip().split("\n") if l.strip() and l.strip() != "Name"]
                if lines:
                    return lines[0]
    except Exception:
        pass
    return platform.processor() or "Unknown"


def _get_physical_cores():
    """Get the number of physical CPU cores."""
    try:
        import multiprocessing
        # Try psutil first if available
        try:
            import psutil
            return psutil.cpu_count(logical=False)
        except ImportError:
            pass

        if platform.system() == "Linux":
            result = subprocess.run(
                ["lscpu"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                cores_per_socket = None
                sockets = None
                for line in result.stdout.split("\n"):
                    if "Core(s) per socket" in line:
                        cores_per_socket = int(line.split(":")[1].strip())
                    if "Socket(s)" in line:
                        sockets = int(line.split(":")[1].strip())
                if cores_per_socket is not None and sockets is not None:
                    return cores_per_socket * sockets
        elif platform.system() == "Darwin":
            result = subprocess.run(
                ["sysctl", "-n", "hw.physicalcpu"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                return int(result.stdout.strip())
    except Exception:
        pass
    return os.cpu_count()


def _get_gpu_info():
    """Try to detect GPU information."""
    gpus = []
    # Try nvidia-smi
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,memory.total,driver_version",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 3:
                    gpus.append({
                        "name": parts[0],
                        "memory_mb": parts[1],
                        "driver_version": parts[2],
                        "type": "NVIDIA"
                    })
    except FileNotFoundError:
        pass

    # Try lspci for other GPUs
    if not gpus:
        try:
            result = subprocess.run(
                ["lspci"], capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "VGA" in line or "3D controller" in line:
                        gpus.append({
                            "name": line.split(":", 2)[-1].strip() if ":" in line else line.strip(),
                            "type": "detected"
                        })
        except FileNotFoundError:
            pass

    return gpus if gpus else None


def _get_opencl_info():
    """Try to detect OpenCL devices."""
    try:
        result = subprocess.run(
            [sys.executable, "-c",
             "from lib.opencl_brute.opencl_information import opencl_information; "
             "info = opencl_information(); info.printfull()"],
            capture_output=True, text=True, timeout=10,
            cwd=SCRIPT_DIR
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass

    # Try pyopencl directly
    try:
        result = subprocess.run(
            [sys.executable, "-c",
             "import pyopencl as cl; "
             "platforms = cl.get_platforms(); "
             "[print(f'{d.name} ({cl.device_type.to_string(d.type)})') "
             "for p in platforms for d in p.get_devices()]"],
            capture_output=True, text=True, timeout=10,
            cwd=SCRIPT_DIR
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass

    return None


def run_benchmark(cmd, duration, label, cwd=None):
    """Run a single benchmark command and return the results.

    Runs the command as a subprocess for the specified duration, then sends
    SIGINT to stop it gracefully. Parses the output to extract the speed.

    To get a stabilised speed reading, we ignore the pre-start benchmark
    rate and instead compute the actual rate from the number of passwords
    tried and the wall-clock time spent in the search phase.

    Args:
        cmd: Command to run as a list of strings.
        duration: How many seconds to let the test run.
        label: Human-readable label for this benchmark.
        cwd: Working directory for the subprocess.

    Returns:
        dict with benchmark results, or None if the test failed.
    """
    if cwd is None:
        cwd = SCRIPT_DIR

    print(f"  Running: {label}...", end="", flush=True)

    # Add --pre-start-seconds 5 to keep the pre-start phase short
    # (we measure our own stabilised rate from the actual search phase)
    enhanced_cmd = list(cmd) + ["--pre-start-seconds", "5"]

    try:
        # Use unbuffered output via PYTHONUNBUFFERED env var
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"

        proc = subprocess.Popen(
            enhanced_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=cwd,
            env=env,
        )

        # Collect all output, watching for the "Searching for password" marker
        # to know when the actual search phase begins
        output_lines = []
        search_started = False
        search_start_time = None
        # Allow up to 120s for setup: some wallets (e.g. scrypt-based) have
        # a slow pre-start benchmark phase before the search begins.
        setup_deadline = time.monotonic() + 120

        import selectors
        sel = selectors.DefaultSelector()
        sel.register(proc.stdout, selectors.EVENT_READ)

        try:
            # Phase 1: Wait for setup to complete and search to start
            while time.monotonic() < setup_deadline:
                events = sel.select(timeout=1.0)
                if events:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    output_lines.append(line)
                    if "Searching for password" in line:
                        search_started = True
                        search_start_time = time.monotonic()
                        break

                # Check if process died
                if proc.poll() is not None:
                    break

            if not search_started:
                proc.kill()
                proc.wait()
                output = "".join(output_lines)
                print(f" FAILED (search phase never started)")
                if output.strip():
                    # Show last few meaningful lines
                    meaningful = [l.strip() for l in output.split("\n") if l.strip()]
                    for line in meaningful[-3:]:
                        print(f"    {line}")
                return None

            # Phase 2: Let the search run for the specified duration
            end_time = search_start_time + duration
            while time.monotonic() < end_time:
                remaining = end_time - time.monotonic()
                if remaining <= 0:
                    break
                events = sel.select(timeout=min(remaining, 1.0))
                if events:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    output_lines.append(line)
                if proc.poll() is not None:
                    break

        finally:
            sel.close()

        actual_search_duration = time.monotonic() - search_start_time

        # Send SIGINT to stop gracefully
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)
            try:
                remaining_output, _ = proc.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
                remaining_output, _ = proc.communicate(timeout=10)
        else:
            remaining_output = proc.stdout.read()

        output = "".join(output_lines) + (remaining_output or "")

        # Parse the number of passwords tried
        passwords_tried = _parse_passwords_tried(output)
        pre_start_rate = _parse_pre_start_rate(output)

        if passwords_tried and actual_search_duration > 0:
            actual_rate = passwords_tried / actual_search_duration
            print(f" {_format_rate(actual_rate)} ({passwords_tried:,} in {actual_search_duration:.1f}s)")
            return {
                "label": label,
                "passwords_per_second": round(actual_rate, 2),
                "passwords_tried": passwords_tried,
                "duration_seconds": round(actual_search_duration, 2),
                "pre_start_rate": round(pre_start_rate, 2) if pre_start_rate else None,
                "status": "ok",
            }
        elif pre_start_rate:
            print(f" {_format_rate(pre_start_rate)} (from pre-start benchmark)")
            return {
                "label": label,
                "passwords_per_second": round(pre_start_rate, 2),
                "passwords_tried": None,
                "duration_seconds": round(actual_search_duration, 2),
                "pre_start_rate": round(pre_start_rate, 2),
                "status": "pre_start_only",
            }
        else:
            print(f" FAILED (could not parse results)")
            meaningful = [l.strip() for l in output.split("\n") if l.strip()]
            for line in meaningful[-3:]:
                print(f"    {line}")
            return None

    except Exception as e:
        print(f" ERROR: {e}")
        try:
            proc.kill()
            proc.wait()
        except Exception:
            pass
        return None


def _parse_passwords_tried(output):
    """Extract the number of passwords tried from the output."""
    match = re.search(r"Interrupted after finishing password #\s*([\d,]+)", output)
    if match:
        return int(match.group(1).replace(",", ""))
    return None


def _parse_pre_start_rate(output):
    """Extract the pre-start benchmark rate from the output."""
    match = re.search(r"Pre-start benchmark completed in [\d.]+s \(([\d.]+) passwords/s\)", output)
    if match:
        return float(match.group(1))
    return None


def _format_rate(rate):
    """Format a rate value for display."""
    if rate >= 1_000_000:
        return f"{rate / 1_000_000:.2f} Mp/s"
    elif rate >= 1_000:
        return f"{rate / 1_000:.2f} Kp/s"
    else:
        return f"{rate:.2f} p/s"


# ──────────────────────────────────────────────────────────────────────
# Benchmark definitions
# ──────────────────────────────────────────────────────────────────────

def get_password_benchmarks():
    """Define password-recovery benchmarks using test wallet files."""
    benchmarks = []
    wallet_dir = WALLET_DIR

    # Each entry: (label, wallet_file, extra_args)
    wallet_tests = [
        ("Bitcoin Core (BDB)", "bitcoincore-wallet.dat", []),
        ("Bitcoin Core (SQLite)", "bitcoincore-0.21.1-wallet.dat", []),
        ("Electrum (Legacy)", "electrum-wallet", []),
        ("Electrum 2", "electrum2-wallet", []),
        ("Electrum 2.8+", "electrum28-wallet", []),
        ("Blockchain.com (v0)", "blockchain-v0.0-wallet.aes.json", []),
        ("Blockchain.com (v2)", "blockchain-v2.0-wallet.aes.json", []),
        ("Blockchain.com (v3)", "blockchain-v3.0-MAY2020-wallet.aes.json", []),
        ("MultiBit Classic", "multibit-wallet.key", []),
        ("MultiBit HD", "mbhd.wallet.aes", []),
        ("MetaMask (Chrome)", "metamask/nkbihfbeogaeaoehlefnkodbefgpgknn", []),
        ("Coinomi (Android)", "coinomi.wallet.android", []),
        ("Dogechain", "dogechain.wallet.aes.json", []),
        ("Bither", "bither-wallet.db", []),
        ("Ethereum Keystore (scrypt)", "utc-keystore-v3-scrypt-myetherwallet.json", []),
    ]

    for label, wallet_file, extra_args in wallet_tests:
        wallet_path = os.path.join(wallet_dir, wallet_file)
        if os.path.exists(wallet_path):
            benchmarks.append({
                "label": label,
                "category": "password",
                "cmd_builder": lambda wp=wallet_path, ea=extra_args: _build_password_cmd(wp, ea),
            })

    return benchmarks


def _build_password_cmd(wallet_path, extra_args):
    """Build the command for a password recovery benchmark."""
    threads = os.environ.get("BTCR_BENCHMARK_THREADS", str(os.cpu_count() or 1))
    cmd = [
        sys.executable, "btcrecover.py",
        "--performance",
        "--wallet", wallet_path,
        "--no-eta",
        "--no-dupchecks",
        "--dsw",
        "--threads", threads,
    ]
    cmd.extend(extra_args)
    return cmd


def get_seed_benchmarks():
    """Define seed-recovery benchmarks for BIP39 and Electrum."""
    benchmarks = []

    # BIP39 12-word seed
    benchmarks.append({
        "label": "BIP39 12-word Seed",
        "category": "seed",
        "cmd_builder": lambda: _build_seed_cmd(
            wallet_type="bip39",
            mnemonic_length=12,
            bip32_path="m/44'/0'/0'",
            address="17GR7xWtWrfYm6y3xoZy8cXioVqBbSYcpU",
        ),
    })

    # BIP39 24-word seed
    benchmarks.append({
        "label": "BIP39 24-word Seed",
        "category": "seed",
        "cmd_builder": lambda: _build_seed_cmd(
            wallet_type="bip39",
            mnemonic_length=24,
            bip32_path="m/44'/0'/0'",
            address="17GR7xWtWrfYm6y3xoZy8cXioVqBbSYcpU",
        ),
    })

    # Electrum 2 seed recovery
    benchmarks.append({
        "label": "Electrum Seed",
        "category": "seed",
        "cmd_builder": lambda: _build_seed_cmd(
            wallet_type="electrum2",
            mnemonic_length=12,
            bip32_path="m/0'",
            address="17GR7xWtWrfYm6y3xoZy8cXioVqBbSYcpU",
        ),
    })

    return benchmarks


def _build_seed_cmd(wallet_type, mnemonic_length, bip32_path, address):
    """Build the command for a seed recovery benchmark."""
    threads = os.environ.get("BTCR_BENCHMARK_THREADS", str(os.cpu_count() or 1))
    cmd = [
        sys.executable, "seedrecover.py",
        "--performance",
        "--wallet-type", wallet_type,
        "--mnemonic-length", str(mnemonic_length),
        "--language", "en",
        "--dsw",
        "--no-eta",
        "--no-dupchecks",
        "--addr-limit", "1",
        "--bip32-path", bip32_path,
        "--addrs", address,
        "--threads", threads,
    ]
    return cmd


def _append_gpu_args(cmd, gpu_args):
    """Append GPU acceleration arguments to a command list."""
    if gpu_args.get("global_ws"):
        cmd.extend(["--global-ws", str(gpu_args["global_ws"])])
    if gpu_args.get("local_ws"):
        cmd.extend(["--local-ws", str(gpu_args["local_ws"])])
    if gpu_args.get("gpu_names"):
        cmd.extend(["--gpu-names"] + gpu_args["gpu_names"])


def _append_opencl_args(cmd, opencl_args):
    """Append OpenCL acceleration arguments to a command list."""
    if opencl_args.get("workgroup_size"):
        cmd.extend(["--opencl-workgroup-size", str(opencl_args["workgroup_size"])])
    if opencl_args.get("platform"):
        cmd.extend(["--opencl-platform", str(opencl_args["platform"])])
    if opencl_args.get("devices"):
        cmd.extend(["--opencl-devices"] + [str(d) for d in opencl_args["devices"]])


# ──────────────────────────────────────────────────────────────────────
# Main benchmark runner
# ──────────────────────────────────────────────────────────────────────

def run_all_benchmarks(args):
    """Run all configured benchmarks and return results."""
    # Build GPU/OpenCL argument dicts from CLI args
    gpu_args = {}
    opencl_args = {}

    if args.global_ws is not None:
        gpu_args["global_ws"] = args.global_ws
    if args.local_ws is not None:
        gpu_args["local_ws"] = args.local_ws
    if args.gpu_names:
        gpu_args["gpu_names"] = args.gpu_names

    if args.opencl_workgroup_size is not None:
        opencl_args["workgroup_size"] = args.opencl_workgroup_size
    if args.opencl_platform is not None:
        opencl_args["platform"] = args.opencl_platform
    if args.opencl_devices:
        opencl_args["devices"] = args.opencl_devices

    threads = args.threads if args.threads else os.cpu_count() or 1

    results = {
        "metadata": {
            "benchmark_version": "1.0",
            "btcrecover_version": _get_btcrecover_version(),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "duration_per_test_seconds": args.duration,
            "threads": threads,
            "gpu_args": gpu_args if gpu_args else None,
            "opencl_args": opencl_args if opencl_args else None,
        },
        "system_info": get_system_info(),
        "benchmarks": [],
    }

    benchmarks = []

    if args.wallet_type in ("all", "password"):
        benchmarks.extend(get_password_benchmarks())
    if args.wallet_type in ("all", "seed"):
        benchmarks.extend(get_seed_benchmarks())

    if not benchmarks:
        print("No benchmarks to run.")
        return results

    total = len(benchmarks)
    modes = ["cpu"]
    if args.gpu:
        modes.append("gpu")
    if args.opencl:
        modes.append("opencl")

    for mode in modes:
        mode_label = mode.upper()
        print(f"\n{'=' * 60}")
        print(f" {mode_label} Benchmarks")
        print(f"{'=' * 60}")

        for i, bench in enumerate(benchmarks, 1):
            label = f"{bench['label']} ({mode_label})"
            print(f"\n[{i}/{total}] {label}")

            try:
                cmd = bench["cmd_builder"]()
            except Exception:
                print(f"  Skipping (failed to build command)")
                continue

            # Modify command for GPU/OpenCL mode
            if mode == "gpu" and bench["category"] == "password":
                cmd.append("--enable-gpu")
                _append_gpu_args(cmd, gpu_args)
            elif mode == "opencl" and bench["category"] == "seed":
                cmd.append("--enable-opencl")
                _append_opencl_args(cmd, opencl_args)
            elif mode == "gpu" and bench["category"] == "seed":
                # Seeds use --enable-opencl, not --enable-gpu
                cmd.append("--enable-opencl")
                _append_opencl_args(cmd, opencl_args)
            elif mode == "opencl" and bench["category"] == "password":
                cmd.append("--enable-gpu")
                _append_gpu_args(cmd, gpu_args)
            elif mode != "cpu":
                # Skip unsupported combinations
                print(f"  Skipping (not applicable for {mode_label})")
                continue

            result = run_benchmark(cmd, args.duration, label)
            if result:
                result["mode"] = mode
                result["category"] = bench["category"]
                results["benchmarks"].append(result)

    return results


def _get_btcrecover_version():
    """Get the btcrecover version string."""
    try:
        result = subprocess.run(
            [sys.executable, "btcrecover.py", "--version"],
            capture_output=True, text=True, timeout=10,
            cwd=SCRIPT_DIR,
        )
        version_match = re.search(r"btcrecover\s+([\d.]+\S*)", result.stdout + result.stderr)
        if version_match:
            return version_match.group(1)
    except Exception:
        pass
    return "unknown"


def save_results(results, output_file=None):
    """Save benchmark results to a JSON file."""
    os.makedirs(RESULTS_DIR, exist_ok=True)

    if output_file is None:
        # Generate filename from hostname and timestamp
        hostname = platform.node().replace(" ", "_").replace("/", "_") or "unknown"
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(RESULTS_DIR, f"benchmark_{hostname}_{timestamp}.json")

    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nResults saved to: {output_file}")
    return output_file


def print_summary(results):
    """Print a summary table of benchmark results."""
    benchmarks = results.get("benchmarks", [])
    if not benchmarks:
        print("\nNo benchmark results to display.")
        return

    print(f"\n{'=' * 70}")
    print(" Benchmark Summary")
    print(f"{'=' * 70}")
    print(f" System: {results['system_info'].get('cpu_model', 'Unknown CPU')}")
    print(f" Cores:  {results['system_info'].get('cpu_cores_physical', '?')} physical, "
          f"{results['system_info'].get('cpu_cores_logical', '?')} logical")
    gpu_info = results['system_info'].get('gpu')
    if gpu_info:
        for gpu in gpu_info:
            print(f" GPU:    {gpu.get('name', 'Unknown')}")
    print(f"{'=' * 70}")

    print(f"\n{'Test':<45} {'Mode':<8} {'Rate':<15}")
    print(f"{'-' * 45} {'-' * 8} {'-' * 15}")

    for bench in benchmarks:
        rate = bench.get("passwords_per_second", 0)
        print(f"{bench['label']:<45} {bench.get('mode', 'cpu'):<8} {_format_rate(rate):<15}")


def main():
    parser = argparse.ArgumentParser(
        description="BTCRecover Benchmarking Tool - Test recovery speed for various wallet types",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                         Run CPU benchmarks for all wallet types
  %(prog)s --gpu                   Also run GPU/OpenCL benchmarks
  %(prog)s --opencl                Also run OpenCL seed benchmarks
  %(prog)s --duration 60           Run each test for 60 seconds
  %(prog)s --wallet-type seed      Only test seed recovery
  %(prog)s --wallet-type password  Only test password recovery
  %(prog)s --threads 4             Use 4 worker threads
  %(prog)s --gpu --global-ws 8192  GPU benchmarks with custom work size
  %(prog)s --opencl --opencl-workgroup-size 1024  OpenCL with custom workgroup
  %(prog)s --output results.json   Save results to a specific file
        """
    )

    parser.add_argument(
        "--duration", type=int, default=30,
        help="Duration in seconds for each benchmark test (default: 30)"
    )
    parser.add_argument(
        "--gpu", action="store_true",
        help="Also run GPU-accelerated benchmarks (requires compatible GPU and drivers)"
    )
    parser.add_argument(
        "--opencl", action="store_true",
        help="Also run OpenCL-accelerated benchmarks (requires OpenCL runtime)"
    )
    parser.add_argument(
        "--wallet-type", choices=["all", "password", "seed"], default="all",
        help="Which wallet types to benchmark (default: all)"
    )
    parser.add_argument(
        "--output", metavar="FILE",
        help="Output file path for results (default: auto-generated in benchmark-results/)"
    )
    parser.add_argument(
        "--threads", type=int, default=None,
        help="Number of worker threads to use (default: number of CPU cores)"
    )

    # GPU acceleration arguments (password recovery)
    gpu_group = parser.add_argument_group("GPU acceleration (password recovery)")
    gpu_group.add_argument(
        "--global-ws", type=int, default=None, metavar="SIZE",
        help="OpenCL global work size for password recovery GPU mode (btcrecover default: 4096)"
    )
    gpu_group.add_argument(
        "--local-ws", type=int, default=None, metavar="SIZE",
        help="OpenCL local work size for password recovery GPU mode (btcrecover default: auto)"
    )
    gpu_group.add_argument(
        "--gpu-names", nargs="+", metavar="NAME",
        help="Choose GPU(s) on multi-GPU systems for password recovery"
    )

    # OpenCL acceleration arguments (seed recovery)
    opencl_group = parser.add_argument_group("OpenCL acceleration (seed recovery)")
    opencl_group.add_argument(
        "--opencl-workgroup-size", type=int, default=None, metavar="SIZE",
        help="OpenCL global work size / batch size for seed recovery"
    )
    opencl_group.add_argument(
        "--opencl-platform", type=int, default=None, metavar="ID",
        help="OpenCL platform ID to use (btcrecover default: auto)"
    )
    opencl_group.add_argument(
        "--opencl-devices", type=int, nargs="+", metavar="ID",
        help="OpenCL device IDs to use (btcrecover default: all)"
    )

    args = parser.parse_args()

    # Override thread count globally if specified
    if args.threads:
        os.environ["BTCR_BENCHMARK_THREADS"] = str(args.threads)

    print("BTCRecover Benchmarking Tool")
    print(f"{'=' * 60}")
    print(f"Duration per test: {args.duration} seconds")
    print(f"Wallet types:      {args.wallet_type}")
    print(f"Threads:           {args.threads if args.threads else 'auto (CPU cores)'}")
    print(f"GPU benchmarks:    {'Yes' if args.gpu else 'No'}")
    print(f"OpenCL benchmarks: {'Yes' if args.opencl else 'No'}")
    if args.gpu or args.opencl:
        if args.global_ws is not None:
            print(f"  Global work size:          {args.global_ws}")
        if args.local_ws is not None:
            print(f"  Local work size:           {args.local_ws}")
        if args.gpu_names:
            print(f"  GPU names:                 {', '.join(args.gpu_names)}")
        if args.opencl_workgroup_size is not None:
            print(f"  OpenCL workgroup size:     {args.opencl_workgroup_size}")
        if args.opencl_platform is not None:
            print(f"  OpenCL platform:           {args.opencl_platform}")
        if args.opencl_devices:
            print(f"  OpenCL devices:            {', '.join(str(d) for d in args.opencl_devices)}")

    # Collect system info
    print(f"\nCollecting system information...")
    sys_info = get_system_info()
    print(f"  CPU:    {sys_info.get('cpu_model', 'Unknown')}")
    print(f"  Cores:  {sys_info.get('cpu_cores_physical', '?')} physical, "
          f"{sys_info.get('cpu_cores_logical', '?')} logical")
    if sys_info.get("gpu"):
        for gpu in sys_info["gpu"]:
            print(f"  GPU:    {gpu.get('name', 'Unknown')}")
    if sys_info.get("opencl_devices"):
        print(f"  OpenCL: {sys_info['opencl_devices'][:100]}")

    # Run benchmarks
    results = run_all_benchmarks(args)

    # Print summary
    print_summary(results)

    # Save results
    output_file = save_results(results, args.output)

    print(f"\nBenchmark complete! Results saved to: {output_file}")
    print("To contribute your results, submit a PR adding the results file to the benchmark-results/ directory.")

    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
