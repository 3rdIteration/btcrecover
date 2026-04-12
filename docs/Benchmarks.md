# Performance Benchmarks

This page collects performance benchmarks from various systems running BTCRecover.
Benchmarks measure the password/seed recovery speed in passwords per second (p/s).

## Contributing Benchmarks

You can contribute your own benchmarks by running the benchmarking tool and
submitting a pull request:

```bash
# Run all benchmarks including CPU, GPU and OpenCL (30 seconds each)
python benchmark.py

# Skip GPU/OpenCL benchmarks (CPU only)
python benchmark.py --no-gpu --no-opencl

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

## Individual Test Commands

If you want to benchmark a specific wallet type or seed recovery mode on your system, you can
copy and paste any of the commands below. Each runs a `--performance` test that will execute
for a short time and report your system's recovery speed.

### Password Recovery

```bash
# Bitcoin Core (BDB)
python btcrecover.py --performance --wallet ./btcrecover/test/test-wallets/bitcoincore-wallet.dat --no-eta --no-dupchecks --dsw

# Bitcoin Core (SQLite)
python btcrecover.py --performance --wallet ./btcrecover/test/test-wallets/bitcoincore-0.21.1-wallet.dat --no-eta --no-dupchecks --dsw

# Bitcoin Core with GPU acceleration (the only wallet type that supports --enable-gpu)
python btcrecover.py --performance --wallet ./btcrecover/test/test-wallets/bitcoincore-wallet.dat --no-eta --no-dupchecks --dsw --enable-gpu

# Electrum (Legacy)
python btcrecover.py --performance --wallet ./btcrecover/test/test-wallets/electrum-wallet --no-eta --no-dupchecks --dsw

# Electrum 2.8+
python btcrecover.py --performance --wallet ./btcrecover/test/test-wallets/electrum28-wallet --no-eta --no-dupchecks --dsw

# Blockchain.com (v0)
python btcrecover.py --performance --wallet ./btcrecover/test/test-wallets/blockchain-v0.0-wallet.aes.json --no-eta --no-dupchecks --dsw

# Blockchain.com (v2)
python btcrecover.py --performance --wallet ./btcrecover/test/test-wallets/blockchain-v2.0-wallet.aes.json --no-eta --no-dupchecks --dsw

# Blockchain.com (v3)
python btcrecover.py --performance --wallet ./btcrecover/test/test-wallets/blockchain-v3.0-MAY2020-wallet.aes.json --no-eta --no-dupchecks --dsw

# MultiBit Classic
python btcrecover.py --performance --wallet ./btcrecover/test/test-wallets/multibit-wallet.key --no-eta --no-dupchecks --dsw

# MultiBit HD
python btcrecover.py --performance --wallet ./btcrecover/test/test-wallets/mbhd.wallet.aes --no-eta --no-dupchecks --dsw

# MetaMask (Chrome)
python btcrecover.py --performance --wallet ./btcrecover/test/test-wallets/metamask/nkbihfbeogaeaoehlefnkodbefgpgknn --no-eta --no-dupchecks --dsw

# Coinomi (Android)
python btcrecover.py --performance --wallet ./btcrecover/test/test-wallets/coinomi.wallet.android --no-eta --no-dupchecks --dsw

# Ethereum Keystore (scrypt)
python btcrecover.py --performance --wallet ./btcrecover/test/test-wallets/utc-keystore-v3-scrypt-myetherwallet.json --no-eta --no-dupchecks --dsw
```

### Seed Recovery

```bash
# BIP39 12-word Seed (CPU)
python seedrecover.py --performance --wallet-type bip39 --mnemonic-length 12 --language en --dsw --no-eta --no-dupchecks --addr-limit 1 --bip32-path "m/44'/0'/0'" --addrs 17GR7xWtWrfYm6y3xoZy8cXioVqBbSYcpU

# BIP39 24-word Seed (CPU)
python seedrecover.py --performance --wallet-type bip39 --mnemonic-length 24 --language en --dsw --no-eta --no-dupchecks --addr-limit 1 --bip32-path "m/44'/0'/0'" --addrs 17GR7xWtWrfYm6y3xoZy8cXioVqBbSYcpU

# BIP39 12-word Seed with OpenCL acceleration
python seedrecover.py --performance --wallet-type bip39 --mnemonic-length 12 --language en --dsw --no-eta --no-dupchecks --addr-limit 1 --bip32-path "m/44'/0'/0'" --addrs 17GR7xWtWrfYm6y3xoZy8cXioVqBbSYcpU --enable-opencl

# BIP39 24-word Seed with OpenCL acceleration
python seedrecover.py --performance --wallet-type bip39 --mnemonic-length 24 --language en --dsw --no-eta --no-dupchecks --addr-limit 1 --bip32-path "m/44'/0'/0'" --addrs 17GR7xWtWrfYm6y3xoZy8cXioVqBbSYcpU --enable-opencl

# Electrum Seed (CPU)
python seedrecover.py --performance --wallet-type electrum2 --mnemonic-length 12 --language en --dsw --no-eta --no-dupchecks --addr-limit 1 --bip32-path "m/0'" --addrs 17GR7xWtWrfYm6y3xoZy8cXioVqBbSYcpU

# Electrum Seed with OpenCL acceleration
python seedrecover.py --performance --wallet-type electrum2 --mnemonic-length 12 --language en --dsw --no-eta --no-dupchecks --addr-limit 1 --bip32-path "m/0'" --addrs 17GR7xWtWrfYm6y3xoZy8cXioVqBbSYcpU --enable-opencl
```
