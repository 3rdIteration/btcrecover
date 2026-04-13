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
| 1 | Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz | 16/16 | NVIDIA GeForce RTX 3070 | NVIDIA GeForce RTX 3070 (8192 MB) | Windows 10 | 2026-04-12 |
| 2 | Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz | 16/16 | NVIDIA GeForce RTX 3070 | NVIDIA GeForce RTX 3070 (8192 MB) | Windows 10 | 2026-04-12 |
| 3 | AMD64 Family 26 Model 68 Stepping 0, AuthenticAMD | 32/32 | NVIDIA GeForce RTX 5090 | NVIDIA GeForce RTX 5090 (32607 MB) | Windows 11 | 2026-04-12 |
| 4 | Apple M1 (Virtual) | 3/3 | None | None | Darwin 24.6.0 | 2026-04-12 |
| 5 | Apple M1 (Virtual) | 3/3 | None | None | Darwin 24.6.0 | 2026-04-12 |
| 6 | AMD EPYC 7763 64-Core Processor | 2/4 | None | None | Linux 6.17.0-1010-azure | 2026-04-12 |
| 7 | AMD EPYC 7763 64-Core Processor | 2/4 | None | None | Linux 6.17.0-1010-azure | 2026-04-12 |
| 8 | AMD64 Family 25 Model 17 Stepping 1, AuthenticAMD | 4/4 | None | None | Windows 2025Server | 2026-04-12 |
| 9 | AMD EPYC 9V74 80-Core Processor | 4/4 | None | None | Windows 2025Server | 2026-04-12 |

### Password Recovery Benchmarks

| System | Mode | Bitcoin Core (BDB) - 67,908 SHA-512 iterations | Bitcoin Core (SQLite) - 267,488 SHA-512 iterations | Electrum (Legacy) - 2 SHA-256 iterations | Electrum 2.8+ - 1024 PBKDF2-SHA512 iterations + ECC | Blockchain.com (v0) - 10 PBKDF2-SHA1 iterations | Blockchain.com (v2) - 10,000 PBKDF2-SHA1 iterations | Blockchain.com (v3) - 5,000 PBKDF2-SHA1 iterations | MultiBit Classic - 3 MD5 iterations | MultiBit HD - scrypt N, r, p = 16384, 8, 1 | MetaMask (Chrome) - 10000 PBKDF2-SHA256 iterations | Ethereum Keystore (scrypt) - Scrypt N=17 R=8 P=1 | Electrum 2.8+ Passphrase - 1024 PBKDF2-SHA512 iterations + ECC | BIP39 Passphrase - 2048 PBKDF2-SHA512 iterations + ECC | SLIP39 Passphrase - 40,000 PBKDF2-SHA256 iterations + ECC | BIP38 Encrypted Key - sCrypt N=14, r=8, p=8 | Raw Private Key - 1 SHA-256 iteration | Coinomi (Android) - scrypt N, r, p = 16384, 8, 1 |
|--------|------|--------|--------|--------|--------|--------|--------|--------|--------|--------|--------|--------|--------|--------|--------|--------|--------|--------|
| System 1: i7-10700K @ 3.80GHz | CPU | 95.50 p/s | 23.30 p/s | 207.48 Kp/s | 4.41 Kp/s | 61.48 Kp/s | 431.42 p/s | 772.70 p/s | 191.41 Kp/s | 131.29 p/s | 674.77 p/s | 16.77 p/s | — | — | — | — | — | — |
| System 1: NVIDIA GeForce RTX 3070 | GPU | 6.97 Kp/s | 2.09 Kp/s | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| System 2: i7-10700K @ 3.80GHz | CPU | 82.60 p/s | 22.87 p/s | — | — | 62.35 Kp/s | 431.40 p/s | 697.93 p/s | 181.25 Kp/s | 134.84 p/s | 689.70 p/s | 16.37 p/s | 4.67 Kp/s | 2.40 Kp/s | 365.89 p/s | 15.00 p/s | 73.45 Kp/s | — |
| System 2: NVIDIA GeForce RTX 3070 | GPU | 6.93 Kp/s | 2.09 Kp/s | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| System 2: NVIDIA GeForce RTX 3070 | OPENCL | — | — | — | — | — | — | — | — | — | — | — | — | 10.80 Kp/s | — | — | — | — |
| System 3: AMD64 Family 26 Model 68 Stepping 0, AuthenticAMD | CPU | 542.25 p/s | 137.85 p/s | 2.65 Mp/s | 33.74 Kp/s | 691.29 Kp/s | 3.25 Kp/s | 6.46 Kp/s | 2.00 Mp/s | 476.15 p/s | 6.33 Kp/s | — | — | — | — | — | — | — |
| System 3: NVIDIA GeForce RTX 5090 | GPU | 11.96 Kp/s | 3.21 Kp/s | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| System 4: Apple M1 (Virtual) | CPU | 98.17 p/s | 28.78 p/s | 301.99 Kp/s | 6.44 Kp/s | 73.60 Kp/s | 520.64 p/s | 1.10 Kp/s | 261.71 Kp/s | 69.20 p/s | 1.08 Kp/s | 8.97 p/s | — | — | — | — | — | 70.81 p/s |
| System 5: Apple M1 (Virtual) | CPU | 118.32 p/s | 30.40 p/s | — | — | 114.52 Kp/s | 625.97 p/s | 1.22 Kp/s | 301.89 Kp/s | 83.95 p/s | 1.34 Kp/s | 10.39 p/s | 7.38 Kp/s | 3.79 Kp/s | — | — | 76.00 Kp/s | 84.39 p/s |
| System 6: EPYC 7763 64-Core | CPU | 46.73 p/s | 11.40 p/s | 158.57 Kp/s | 2.67 Kp/s | 41.80 Kp/s | 394.67 p/s | 785.44 p/s | 140.33 Kp/s | 61.26 p/s | 700.40 p/s | 8.82 p/s | — | — | — | — | — | 61.79 p/s |
| System 7: EPYC 7763 64-Core | CPU | 46.81 p/s | 11.97 p/s | — | — | 42.59 Kp/s | 395.99 p/s | 787.66 p/s | 140.91 Kp/s | 62.02 p/s | 699.37 p/s | 9.32 p/s | 2.67 Kp/s | 1.36 Kp/s | — | — | 35.41 Kp/s | 62.37 p/s |
| System 8: AMD64 Family 25 Model 17 Stepping 1, AuthenticAMD | CPU | 29.00 p/s | 6.34 p/s | 158.42 Kp/s | 1.39 Kp/s | 33.26 Kp/s | 154.00 p/s | 146.36 p/s | 56.55 Kp/s | 21.00 p/s | 187.40 p/s | 5.46 p/s | — | — | — | — | — | 26.35 p/s |
| System 9: EPYC 9V74 80-Core | CPU | 35.95 p/s | 9.18 p/s | — | — | 46.21 Kp/s | 219.00 p/s | 433.67 p/s | 167.16 Kp/s | 35.82 p/s | 383.07 p/s | 7.33 p/s | 2.17 Kp/s | 1.15 Kp/s | — | — | 24.57 Kp/s | 35.30 p/s |

### Seed Recovery Benchmarks

| System | Mode | BIP39 12-word Seed | BIP39 24-word Seed | Electrum Seed | Aezeed (LND) Seed | SLIP39 Seed Share |
|--------|------|--------|--------|--------|--------|--------|
| System 1: i7-10700K @ 3.80GHz | CPU | 36.68 Kp/s | 147.63 Kp/s | 154.77 Kp/s | — | — |
| System 1: NVIDIA GeForce RTX 3070 | OPENCL | 129.10 Kp/s | 276.60 Kp/s | 396.32 Kp/s | — | — |
| System 2: i7-10700K @ 3.80GHz | CPU | 36.02 Kp/s | 155.32 Kp/s | 151.98 Kp/s | 284.50 Kp/s | 89.85 Kp/s |
| System 2: NVIDIA GeForce RTX 3070 | OPENCL | 127.20 Kp/s | 292.68 Kp/s | 390.90 Kp/s | 325.94 Kp/s | — |
| System 3: AMD64 Family 26 Model 68 Stepping 0, AuthenticAMD | CPU | 254.06 Kp/s | 841.75 Kp/s | 818.92 Kp/s | — | — |
| System 3: NVIDIA GeForce RTX 5090 | OPENCL | 132.77 Kp/s | 601.64 Kp/s | 147.17 Kp/s | — | — |
| System 4: Apple M1 (Virtual) | CPU | 40.45 Kp/s | 154.92 Kp/s | 211.87 Kp/s | — | — |
| System 5: Apple M1 (Virtual) | CPU | 53.18 Kp/s | 195.42 Kp/s | 249.63 Kp/s | 337.59 Kp/s | — |
| System 6: EPYC 7763 64-Core | CPU | 19.48 Kp/s | 106.14 Kp/s | 116.24 Kp/s | — | — |
| System 7: EPYC 7763 64-Core | CPU | 18.65 Kp/s | 106.56 Kp/s | 118.92 Kp/s | 230.10 Kp/s | — |
| System 8: AMD64 Family 25 Model 17 Stepping 1, AuthenticAMD | CPU | 16.15 Kp/s | 80.29 Kp/s | 90.91 Kp/s | — | — |
| System 9: EPYC 9V74 80-Core | CPU | 12.05 Kp/s | 90.66 Kp/s | 102.75 Kp/s | 215.30 Kp/s | — |


<!-- BENCHMARK_RESULTS_END -->

To view results locally, run the benchmark tool and then serve the docs:

```bash
# Generate benchmarks
python benchmark.py

# View results in docs (requires mkdocs and dependencies)
python generate_benchmark_docs.py
mkdocs serve
```
