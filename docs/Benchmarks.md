# Performance Benchmarks

This page collects performance benchmarks from various systems running BTCRecover.
Benchmarks measure the password/seed recovery speed in passwords per second (p/s).

## Contributing Benchmarks

You can contribute your own benchmarks by running the benchmarking tool and
submitting a pull request:

```bash
# Run all CPU benchmarks (30 seconds each)
python benchmark.py

# Also include GPU/OpenCL benchmarks
python benchmark.py --gpu --opencl

# Adjust test duration (default: 30 seconds)
python benchmark.py --duration 60
```

Results are saved as JSON files in the `benchmark-results/` directory. Submit a
PR adding your results file to share your benchmarks with the community.

## Understanding the Results

- **p/s** = passwords per second (or seeds per second for seed recovery)
- **Kp/s** = thousands of passwords per second
- **Mp/s** = millions of passwords per second
- **CPU** = using CPU only (multi-threaded)
- **GPU/OpenCL** = using GPU acceleration via OpenCL

Speed varies significantly based on:

- **CPU model and core count** – more cores = faster for CPU tests
- **GPU model and memory** – more powerful GPU = faster for GPU tests
- **Wallet type** – some wallets use more expensive key derivation (e.g., scrypt vs PBKDF2)
- **Seed length** – 24-word seeds are slower than 12-word seeds due to the additional PBKDF2 rounds

## Benchmark Results

<!-- BENCHMARK_RESULTS_START -->

### Systems Tested

| # | CPU | Cores (Phys/Logical) | GPU | OpenCL Device | OS | Date |
|---|-----|----------------------|-----|---------------|----|----- |
| 1 | Apple M1 (Virtual) | 3/3 | None | None | Darwin 24.6.0 | 2026-04-11 |
| 2 | Intel(R) Xeon(R) Platinum 8370C CPU @ 2.80GHz | 2/4 | None | None | Linux 6.17.0-1010-azure | 2026-04-11 |
| 3 | Intel64 Family 6 Model 106 Stepping 6, GenuineIntel | 4/4 | None | None | Windows 2025Server | 2026-04-11 |

### Password Recovery Benchmarks

| Test | Difficulty | Mode | System 1 | System 2 | System 3 |
|------|------------|------|--------|--------|--------|
| Bitcoin Core (BDB) | 67,908 SHA-512 iterations | CPU | 106.58 p/s | 39.20 p/s | 16.95 p/s |
| Bitcoin Core (SQLite) | 267,488 SHA-512 iterations | CPU | 27.34 p/s | 9.59 p/s | 4.41 p/s |
| Bither | scrypt N, r, p = 16384, 8, 1 | CPU | 75.28 p/s | 60.80 p/s | 15.81 p/s |
| Blockchain.com (v0) | 10 PBKDF2-SHA1 iterations | CPU | 105.77 Kp/s | 41.45 Kp/s | 21.22 Kp/s |
| Blockchain.com (v2) | 10,000 PBKDF2-SHA1 iterations | CPU | 573.48 p/s | 316.39 p/s | 98.36 p/s |
| Blockchain.com (v3) | 5,000 PBKDF2-SHA1 iterations | CPU | 965.99 p/s | 634.39 p/s | 196.57 p/s |
| Coinomi (Android) | scrypt N, r, p = 16384, 8, 1 | CPU | 70.19 p/s | 60.00 p/s | 15.79 p/s |
| Dogechain | 5,000 PBKDF2-SHA256 iterations | CPU | 2.25 Kp/s | 1.16 Kp/s | 367.78 p/s |
| Electrum (Legacy) | 2 SHA-256 iterations | CPU | 306.77 Kp/s | 157.13 Kp/s | 99.42 Kp/s |
| Electrum 2 | 2 SHA-256 iterations | CPU | 295.38 Kp/s | 160.89 Kp/s | 97.86 Kp/s |
| Electrum 2.8+ | 1024 PBKDF2-SHA512 iterations + ECC | CPU | 6.69 Kp/s | 2.21 Kp/s | 957.77 p/s |
| Ethereum Keystore (scrypt) | Scrypt N=17 R=8 P=1 | CPU | 8.33 p/s | 8.80 p/s | 3.13 p/s |
| MetaMask (Chrome) | 10000 PBKDF2-SHA256 iterations | CPU | 1.25 Kp/s | 578.39 p/s | 178.09 p/s |
| MultiBit Classic | 3 MD5 iterations | CPU | 263.56 Kp/s | 138.59 Kp/s | 80.74 Kp/s |
| MultiBit HD | scrypt N, r, p = 16384, 8, 1 | CPU | 77.74 p/s | 60.00 p/s | 15.58 p/s |

### Seed Recovery Benchmarks

| Test | Mode | System 1 | System 2 | System 3 |
|------|------|--------|--------|--------|
| BIP39 12-word Seed | CPU | 50.45 Kp/s | 16.45 Kp/s | 7.34 Kp/s |
| BIP39 24-word Seed | CPU | 169.73 Kp/s | 94.72 Kp/s | 51.86 Kp/s |
| Electrum Seed | CPU | 220.82 Kp/s | 103.70 Kp/s | 44.65 Kp/s |


<!-- BENCHMARK_RESULTS_END -->

To view results locally, run the benchmark tool and then serve the docs:

```bash
# Generate benchmarks
python benchmark.py

# View results in docs (requires mkdocs and dependencies)
python generate_benchmark_docs.py
mkdocs serve
```
