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

!!! note "No benchmark results yet"
    No benchmark result files have been found in the `benchmark-results/` directory.
    Run `python benchmark.py` to generate your first benchmark, or see the
    contributing section above.


<!-- BENCHMARK_RESULTS_END -->

To view results locally, run the benchmark tool and then serve the docs:

```bash
# Generate benchmarks
python benchmark.py

# View results in docs (requires mkdocs and dependencies)
python generate_benchmark_docs.py
mkdocs serve
```
