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
    python benchmark.py                    # Run all benchmarks (CPU + GPU + OpenCL)
    python benchmark.py --no-gpu           # Skip GPU benchmarks
    python benchmark.py --no-opencl        # Skip OpenCL benchmarks
    python benchmark.py --duration 60      # Run each test for 60 seconds
    python benchmark.py --wallet-type all  # Test all wallet types (default)
    python benchmark.py --wallet-type seed # Test only seed recovery
"""

import argparse
import datetime
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import threading
import time


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WALLET_DIR = os.path.join(SCRIPT_DIR, "btcrecover", "test", "test-wallets")
RESULTS_DIR = os.path.join(SCRIPT_DIR, "benchmark-results")

# Maximum seconds to wait for the search phase to begin (some wallets like
# scrypt-based ones have slow pre-start benchmarks)
SEARCH_PHASE_TIMEOUT = 120


def _get_system_id():
    """Generate a privacy-preserving hashed system identifier.

    Combines several machine-specific values (hostname, CPU model, OS,
    architecture) and returns a truncated SHA-256 hex digest.  The same
    physical machine will always produce the same hash, making it possible
    to link benchmark runs from the same system without revealing the
    actual hostname or other identifiable information.
    """
    raw_parts = [
        platform.node(),          # hostname
        _get_cpu_model(),         # CPU brand string
        platform.machine(),       # architecture
        platform.system(),        # OS family
    ]
    # Try to include a hardware serial/UUID for even stronger uniqueness
    try:
        if platform.system() == "Linux":
            with open("/etc/machine-id", "r") as f:
                raw_parts.append(f.read().strip())
        elif platform.system() == "Windows":
            result = subprocess.run(
                ["wmic", "csproduct", "get", "UUID"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                lines = [l.strip() for l in result.stdout.strip().split("\n")
                         if l.strip() and l.strip() != "UUID"]
                if lines:
                    raw_parts.append(lines[0])
        elif platform.system() == "Darwin":
            result = subprocess.run(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "IOPlatformUUID" in line:
                        raw_parts.append(line.split("=", 1)[-1].strip().strip('"'))
                        break
    except Exception:
        pass

    raw = "|".join(raw_parts)
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]


def _get_windows_release():
    """Get the correct Windows release string.

    On systems upgraded from Windows 10 to Windows 11, platform.release()
    may still return '10' because the registry value it reads is stale.
    Use sys.getwindowsversion() to check the build number: builds >= 22000
    are Windows 11.
    """
    release = platform.release()
    try:
        ver = sys.getwindowsversion()
        if ver.build >= 22000 and release == "10":
            return "11"
    except Exception:
        pass
    return release


def get_system_info():
    """Collect system information for the benchmark results."""
    os_release = platform.release()
    if platform.system() == "Windows":
        os_release = _get_windows_release()

    info = {
        "system_id": _get_system_id(),
        "os": platform.system(),
        "os_version": platform.version(),
        "os_release": os_release,
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
    """Get the CPU model string.

    On Windows the most reliable source is the registry key
    ``HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0\\ProcessorNameString``
    which always contains the full human-readable brand string (e.g.
    "AMD Ryzen 9 7950X 16-Core Processor").  The older ``wmic`` approach and
    ``platform.processor()`` often return raw CPUID identifiers such as
    "AMD64 Family 25 Model 17 Stepping 1, AuthenticAMD" on AMD systems.
    """
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
            # Prefer the registry – it always has the full brand string and
            # does not depend on deprecated tools like wmic.
            try:
                import winreg
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
                )
                try:
                    value, _ = winreg.QueryValueEx(key, "ProcessorNameString")
                    if value and value.strip():
                        return value.strip()
                finally:
                    winreg.CloseKey(key)
            except Exception:
                pass
            # Fallback: wmic (deprecated but still present on many systems)
            try:
                result = subprocess.run(
                    ["wmic", "cpu", "get", "name"],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    lines = [l.strip() for l in result.stdout.strip().split("\n")
                             if l.strip() and l.strip() != "Name"]
                    if lines:
                        return lines[0]
            except Exception:
                pass
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
        elif platform.system() == "Windows":
            result = subprocess.run(
                ["wmic", "cpu", "get", "NumberOfCores"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                total = 0
                for line in result.stdout.strip().split("\n"):
                    line = line.strip()
                    if line and line != "NumberOfCores":
                        try:
                            total += int(line)
                        except ValueError:
                            pass
                if total > 0:
                    return total
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
    """Try to detect OpenCL devices and return structured info.

    Returns a list of dicts, one per device, with keys like name, type,
    driver_version, global_memory_mb, max_clock_mhz, compute_units, and
    max_work_group_size.  Falls back to a plain-text string if pyopencl
    is not available.
    """
    # Try the repo's own opencl_information helper first (plain text fallback)
    try:
        result = subprocess.run(
            [sys.executable, "-c",
             "import json, sys; "
             "import pyopencl as cl; "
             "devices = []; "
             "[devices.append({"
             "'platform_name': p.name, "
             "'platform_vendor': p.vendor, "
             "'platform_version': p.version, "
             "'name': d.name, "
             "'type': cl.device_type.to_string(d.type), "
             "'driver_version': d.driver_version, "
             "'global_memory_mb': round(d.global_mem_size / 1048576), "
             "'local_memory_kb': round(d.local_mem_size / 1024), "
             "'max_clock_mhz': d.max_clock_frequency, "
             "'compute_units': d.max_compute_units, "
             "'max_work_group_size': d.max_work_group_size, "
             "}) "
             "for p in cl.get_platforms() for d in p.get_devices()]; "
             "json.dump(devices, sys.stdout)"],
            capture_output=True, text=True, timeout=10,
            cwd=SCRIPT_DIR
        )
        if result.returncode == 0 and result.stdout.strip():
            devices = json.loads(result.stdout)
            if devices:
                return devices
    except Exception:
        pass

    return None


def run_benchmark(cmd, duration, label, cwd=None):
    """Run a single benchmark command and return the results.

    The command is expected to include ``--performance-duration`` so that the
    subprocess stops itself gracefully after the desired time.  This avoids
    the need to send SIGINT/CTRL_C_EVENT which causes BrokenPipeError on
    Windows.

    A background thread reads stdout line-by-line so that the approach
    works on every platform (the previous ``selectors`` strategy fails on
    Windows where pipes are not sockets).

    Args:
        cmd: Command to run as a list of strings.
        duration: Nominal duration for display/timeout purposes.
        label: Human-readable label for this benchmark.
        cwd: Working directory for the subprocess.

    Returns:
        dict with benchmark results, or None if the test failed.
    """
    if cwd is None:
        cwd = SCRIPT_DIR

    print(f"  Running: {label}...", end="", flush=True)

    try:
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=cwd,
            env=env,
        )

        # -- Reader thread: pumps stdout lines into a shared list ----------
        output_lines = []
        output_lock = threading.Lock()
        eof_event = threading.Event()

        def _reader():
            try:
                for line in proc.stdout:
                    with output_lock:
                        output_lines.append(line)
            except ValueError:
                pass
            finally:
                eof_event.set()

        reader = threading.Thread(target=_reader, daemon=True)
        reader.start()

        # Wait for the process to finish.  Allow generous extra time beyond
        # the nominal duration for the pre-start benchmark phase and setup.
        total_timeout = duration + SEARCH_PHASE_TIMEOUT
        try:
            proc.wait(timeout=total_timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)

        reader.join(timeout=10)

        with output_lock:
            output = "".join(output_lines)

        # Parse results -- prefer the summary line from --performance-duration
        perf_rate = _parse_performance_summary(output)
        progress_rate = _parse_progress_rate(output)
        passwords_tried = _parse_passwords_tried(output)
        wallet_difficulty = _parse_wallet_difficulty(output)

        actual_rate = perf_rate or progress_rate
        if actual_rate:
            source = "from summary" if perf_rate else "from progress output"
            print(f" {_format_rate(actual_rate)} ({source})")
        elif passwords_tried and duration > 0:
            actual_rate = passwords_tried / duration
            print(f" {_format_rate(actual_rate)} ({passwords_tried:,} in ~{duration}s)")
        else:
            print(f" FAILED (could not parse results)")
            meaningful = [l.strip() for l in output.split("\n") if l.strip()]
            for line in meaningful[-3:]:
                print(f"    {line}")
            return None

        return {
            "label": label,
            "passwords_per_second": round(actual_rate, 2),
            "passwords_tried": passwords_tried,
            "duration_seconds": duration,
            "wallet_difficulty": wallet_difficulty,
            "status": "ok",
        }

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
    # Try the --performance-duration summary line first
    match = re.search(
        r'Performance test completed:\s*([\d,]+)\s+passwords\s+in',
        output,
    )
    if match:
        return int(match.group(1).replace(",", ""))
    # Fall back to the interrupt message
    match = re.search(r"Interrupted after finishing password #\s*([\d,]+)", output)
    if match:
        return int(match.group(1).replace(",", ""))
    return None


def _parse_progress_rate(output):
    """Extract the last reported rate from the progress bar output.

    The progressbar widget outputs updates like:
        / 426510  elapsed: 0:00:11  rate:  37.28 kP/s

    Each update overwrites the previous one via carriage-return (\\r).
    We find ALL rate values in the captured output and return the last
    one, which is the most stabilised reading.
    """
    # Match "rate:" followed by a number and an optional SI prefix before P/s
    matches = re.findall(r'rate:\s*([\d.]+)\s*([kMGT]?)\s*P/s', output, re.IGNORECASE)
    if not matches:
        return None
    value_str, prefix = matches[-1]
    value = float(value_str)
    multipliers = {
        '': 1, 'k': 1_000, 'K': 1_000,
        'M': 1_000_000, 'G': 1_000_000_000, 'T': 1_000_000_000_000,
    }
    return value * multipliers.get(prefix, 1)


def _parse_performance_summary(output):
    """Extract rate from the --performance-duration summary line.

    The line looks like:
        Performance test completed: 1,234,567 passwords in 30.0s (41152.23 passwords/s)

    Returns the passwords/s rate as a float, or None if not found.
    """
    match = re.search(
        r'Performance test completed:\s*([\d,]+)\s+passwords\s+in\s+([\d.]+)s\s+'
        r'\(([\d.]+)\s+passwords/s\)',
        output,
    )
    if match:
        return float(match.group(3))
    return None


def _parse_wallet_difficulty(output):
    """Extract wallet difficulty information from the output."""
    match = re.search(r"Wallet difficulty:\s*(.+)", output)
    if match:
        return match.group(1).strip()
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
    # Each entry: (label, wallet_file, extra_args, supports_gpu)
    # supports_gpu indicates whether --enable-gpu is supported for this wallet type
    wallet_tests = [
        ("Bitcoin Core (BDB)", "bitcoincore-wallet.dat", [], True),
        ("Bitcoin Core (SQLite)", "bitcoincore-0.21.1-wallet.dat", [], True),
        ("Electrum 2.8+ Passphrase", "electrum28-wallet", [], False),
        ("Blockchain.com (v0)", "blockchain-v0.0-wallet.aes.json", [], False),
        ("Blockchain.com (v2)", "blockchain-v2.0-wallet.aes.json", [], False),
        ("Blockchain.com (v3)", "blockchain-v3.0-MAY2020-wallet.aes.json", [], False),
        ("MultiBit Classic", "multibit-wallet.key", [], False),
        ("MultiBit HD", "mbhd.wallet.aes", [], False),
        ("MetaMask (Chrome)", "metamask/nkbihfbeogaeaoehlefnkodbefgpgknn", [], False),
        ("Coinomi (Android)", "coinomi.wallet.android", [], False),
        ("Ethereum Keystore (scrypt)", "utc-keystore-v3-scrypt-myetherwallet.json", [], False),
    ]

    for label, wallet_file, extra_args, supports_gpu in wallet_tests:
        wallet_path = os.path.join(wallet_dir, wallet_file)
        if os.path.exists(wallet_path):
            benchmarks.append({
                "label": label,
                "category": "password",
                "supports_gpu": supports_gpu,
                "cmd_builder": lambda wp=wallet_path, ea=extra_args: _build_password_cmd(wp, ea),
            })

    # BIP39 Passphrase (searching for the BIP39 passphrase given a known mnemonic)
    benchmarks.append({
        "label": "BIP39 Passphrase",
        "category": "password",
        "supports_gpu": False,
        "supports_opencl": True,
        "cmd_builder": lambda: _build_bip39_passphrase_cmd(),
    })

    # SLIP39 Passphrase (searching for the SLIP39 passphrase given known shares)
    benchmarks.append({
        "label": "SLIP39 Passphrase",
        "category": "password",
        "supports_gpu": False,
        "supports_opencl": True,
        "cmd_builder": lambda: _build_slip39_passphrase_cmd(),
    })

    # BIP38 Encrypted Private Key
    benchmarks.append({
        "label": "BIP38 Encrypted Key",
        "category": "password",
        "supports_gpu": False,
        "supports_opencl": True,
        "cmd_builder": lambda: _build_bip38_cmd(),
    })

    # Raw Private Key (brute-force search for a private key given an address)
    benchmarks.append({
        "label": "Raw Private Key",
        "category": "password",
        "supports_gpu": False,
        "cmd_builder": lambda: _build_rawprivatekey_cmd(),
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


def _build_bip39_passphrase_cmd():
    """Build the command for a BIP39 passphrase recovery benchmark."""
    threads = os.environ.get("BTCR_BENCHMARK_THREADS", str(os.cpu_count() or 1))
    return [
        sys.executable, "btcrecover.py",
        "--performance",
        "--bip39",
        "--mpk", "xpub6D3uXJmdUg4xVnCUkNXJPCkk18gZAB8exGdQeb2rDwC5UJtraHHARSCc2Nz7rQ14godicjXiKxhUn39gbAw6Xb5eWb5srcbkhqPgAqoTMEY",
        "--mnemonic", "certain come keen collect slab gauge photo inside mechanic deny leader drop",
        "--no-eta",
        "--no-dupchecks",
        "--dsw",
        "--threads", threads,
    ]


def _build_slip39_passphrase_cmd():
    """Build the command for a SLIP39 passphrase recovery benchmark."""
    threads = os.environ.get("BTCR_BENCHMARK_THREADS", str(os.cpu_count() or 1))
    return [
        sys.executable, "btcrecover.py",
        "--performance",
        "--slip39",
        "--slip39-shares",
        "hearing echo academic acid deny bracelet playoff exact fancy various evidence standard adjust muscle parcel sled crucial amazing mansion losing",
        "hearing echo academic agency deliver join grant laden index depart deadline starting duration loud crystal bulge gasoline injury tofu together",
        "--addrs", "bc1q76szkxz4cta5p5s66muskvads0nhwe5m5w07pq",
        "--addr-limit", "2",
        "--no-eta",
        "--no-dupchecks",
        "--dsw",
        "--threads", threads,
    ]


def _build_bip38_cmd():
    """Build the command for a BIP38 encrypted private key benchmark."""
    threads = os.environ.get("BTCR_BENCHMARK_THREADS", str(os.cpu_count() or 1))
    return [
        sys.executable, "btcrecover.py",
        "--performance",
        "--bip38-enc-privkey", "6PnM7h9sBC9EMZxLVsKzpafvBN8zjKp8MZj6h9mfvYEQRMkKBTPTyWZHHx",
        "--no-eta",
        "--no-dupchecks",
        "--dsw",
        "--threads", threads,
    ]


def _build_rawprivatekey_cmd():
    """Build the command for a raw private key recovery benchmark."""
    threads = os.environ.get("BTCR_BENCHMARK_THREADS", str(os.cpu_count() or 1))
    return [
        sys.executable, "btcrecover.py",
        "--performance",
        "--rawprivatekey",
        "--addrs", "1EDrqbJMVwjQ2K5avN3627NcAXyWbkpGBL",
        "--no-eta",
        "--no-dupchecks",
        "--dsw",
        "--threads", threads,
    ]


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

    # Aezeed (LND) seed recovery
    benchmarks.append({
        "label": "Aezeed (LND) Seed",
        "category": "seed",
        "cmd_builder": lambda: _build_seed_cmd(
            wallet_type="aezeed",
            mnemonic_length=24,
            address="1Hp6UXuJjzt9eSBa9LhtW97KPb44bq4CAQ",
        ),
    })

    # SLIP39 Seed Share recovery
    benchmarks.append({
        "label": "SLIP39 Seed Share",
        "category": "seed",
        "cmd_builder": lambda: _build_slip39_seed_cmd(),
    })

    return benchmarks


def _build_seed_cmd(wallet_type, mnemonic_length, bip32_path=None, address=None):
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
        "--threads", threads,
    ]
    if address:
        cmd.extend(["--addr-limit", "1", "--addrs", address])
    if bip32_path:
        cmd.extend(["--bip32-path", bip32_path])
    return cmd


def _build_slip39_seed_cmd():
    """Build the command for a SLIP39 seed share recovery benchmark."""
    threads = os.environ.get("BTCR_BENCHMARK_THREADS", str(os.cpu_count() or 1))
    return [
        sys.executable, "seedrecover.py",
        "--performance",
        "--wallet-type", "slip39seed",
        "--mnemonic-length", "20",
        "--dsw",
        "--no-eta",
        "--no-dupchecks",
        "--threads", threads,
    ]


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
            "comment": args.comment,
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

            # Tell the subprocess to stop itself after the desired duration
            cmd.extend(["--performance-duration", str(args.duration)])

            # Modify command for GPU/OpenCL mode
            # --enable-gpu is only for password recovery (Bitcoin Core only)
            # --enable-opencl is for seed recovery AND some password types
            #   (BIP39 Passphrase, SLIP39 Passphrase, BIP38)
            if mode == "gpu" and bench["category"] == "password":
                if not bench.get("supports_gpu"):
                    print(f"  Skipping (GPU not supported for this wallet type)")
                    continue
                cmd.append("--enable-gpu")
                _append_gpu_args(cmd, gpu_args)
            elif mode == "opencl" and bench["category"] == "seed":
                cmd.append("--enable-opencl")
                _append_opencl_args(cmd, opencl_args)
            elif mode == "opencl" and bench.get("supports_opencl"):
                cmd.append("--enable-opencl")
                _append_opencl_args(cmd, opencl_args)
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
        # Generate filename from hashed system ID and timestamp
        system_id = results.get("system_info", {}).get("system_id", "unknown")
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(RESULTS_DIR, f"benchmark_{system_id}_{timestamp}.json")

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
    opencl_devs = results['system_info'].get('opencl_devices')
    if opencl_devs and isinstance(opencl_devs, list):
        for dev in opencl_devs:
            mem = dev.get("global_memory_mb", "?")
            print(f" OpenCL: {dev.get('name', 'Unknown')} "
                  f"({dev.get('type', '?')}, {mem} MB, "
                  f"driver {dev.get('driver_version', '?')})")
    print(f"{'=' * 70}")

    print(f"\n{'Test':<45} {'Mode':<8} {'Rate':<15} {'Difficulty'}")
    print(f"{'-' * 45} {'-' * 8} {'-' * 15} {'-' * 30}")

    for bench in benchmarks:
        rate = bench.get("passwords_per_second", 0)
        difficulty = bench.get("wallet_difficulty", "not reported")
        print(f"{bench['label']:<45} {bench.get('mode', 'cpu'):<8} {_format_rate(rate):<15} {difficulty}")


def main():
    parser = argparse.ArgumentParser(
        description="BTCRecover Benchmarking Tool - Test recovery speed for various wallet types",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                         Run CPU benchmarks for all wallet types
  %(prog)s                         Run all benchmarks (CPU + GPU + OpenCL)
  %(prog)s --no-gpu                Skip GPU benchmarks
  %(prog)s --no-opencl             Skip OpenCL benchmarks
  %(prog)s --duration 60           Run each test for 60 seconds
  %(prog)s --wallet-type seed      Only test seed recovery
  %(prog)s --wallet-type password  Only test password recovery
  %(prog)s --threads 4             Use 4 worker threads
  %(prog)s --global-ws 8192        GPU benchmarks with custom work size
  %(prog)s --opencl-workgroup-size 1024  OpenCL with custom workgroup
  %(prog)s --comment "GitHub actions run"  Add a free-form comment in metadata
  %(prog)s --output results.json   Save results to a specific file
        """
    )

    parser.add_argument(
        "--duration", type=int, default=30,
        help="Duration in seconds for each benchmark test (default: 30)"
    )
    parser.add_argument(
        "--gpu", action="store_true", default=True,
        help="Run GPU-accelerated benchmarks (default: enabled)"
    )
    parser.add_argument(
        "--no-gpu", action="store_false", dest="gpu",
        help="Skip GPU-accelerated benchmarks"
    )
    parser.add_argument(
        "--opencl", action="store_true", default=True,
        help="Run OpenCL-accelerated benchmarks (default: enabled)"
    )
    parser.add_argument(
        "--no-opencl", action="store_false", dest="opencl",
        help="Skip OpenCL-accelerated benchmarks"
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
    parser.add_argument(
        "--comment", type=str, default=None,
        help="Optional free-form note to include in benchmark metadata"
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
    if args.comment:
        print(f"Comment:           {args.comment}")
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
        opencl_devs = sys_info["opencl_devices"]
        if isinstance(opencl_devs, list):
            for dev in opencl_devs:
                mem = dev.get("global_memory_mb", "?")
                print(f"  OpenCL: {dev.get('name', 'Unknown')} "
                      f"({dev.get('type', '?')}, {mem} MB, "
                      f"driver {dev.get('driver_version', '?')})")
        else:
            print(f"  OpenCL: {str(opencl_devs)[:100]}")

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
