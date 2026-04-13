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

- **CPU model and core count** â€“ more cores = faster for CPU tests
- **GPU model and memory** â€“ more powerful GPU = faster for GPU tests
- **Wallet type** â€“ some wallets use more expensive key derivation (e.g., scrypt vs PBKDF2)
- **Seed length** â€“ 24-word seeds are slower than 12-word seeds due to the additional PBKDF2 rounds

## Benchmark Results

<!-- BENCHMARK_RESULTS_START -->

### Systems Tested

| # | CPU | Cores (Phys/Logical) | GPU | OpenCL Device | OS | Date |
|---|-----|----------------------|-----|---------------|----|----- |
| 1 | i7-10700K @ 3.80GHz | 16/16 | NVIDIA GeForce RTX 3070 | NVIDIA GeForce RTX 3070 (8192 MB) | Windows 10 | 2026-04-12 |
| 2 | i7-10700K @ 3.80GHz | 16/16 | NVIDIA GeForce RTX 3070 | NVIDIA GeForce RTX 3070 (8192 MB) | Windows 10 | 2026-04-12 |
| 3 | AMD64 Family 26 Model 68 Stepping 0, AuthenticAMD | 32/32 | NVIDIA GeForce RTX 5090 | NVIDIA GeForce RTX 5090 (32607 MB) | Windows 11 | 2026-04-12 |
| 4 | Apple M1 (Virtual) | 3/3 | None | None | Darwin 24.6.0 | 2026-04-12 |
| 5 | Apple M1 (Virtual) | 3/3 | None | None | Darwin 24.6.0 | 2026-04-12 |
| 6 | EPYC 7763 64-Core | 2/4 | None | None | Linux 6.17.0-1010-azure | 2026-04-12 |
| 7 | EPYC 7763 64-Core | 2/4 | None | None | Linux 6.17.0-1010-azure | 2026-04-12 |
| 8 | AMD64 Family 25 Model 17 Stepping 1, AuthenticAMD | 4/4 | None | None | Windows 2025Server | 2026-04-12 |
| 9 | EPYC 9V74 80-Core | 4/4 | None | None | Windows 2025Server | 2026-04-12 |

### Password Benchmarks

| Test Type | Mode | BIP38 Encrypted Key - sCrypt N=14, r=8, p=8 | BIP39 Passphrase - 2048 PBKDF2-SHA512 iterations + ECC | BIP39 Passphrase - 2048 PBKDF2-SHA512 iterations + ECC | Bitcoin Core (BDB) - 67,908 SHA-512 iterations | Bitcoin Core (BDB) - 67,908 SHA-512 iterations | Bitcoin Core (SQLite) - 267,488 SHA-512 iterations | Bitcoin Core (SQLite) - 267,488 SHA-512 iterations | Blockchain.com (v0) - 10 PBKDF2-SHA1 iterations | Blockchain.com (v2) - 10,000 PBKDF2-SHA1 iterations | Blockchain.com (v3) - 5,000 PBKDF2-SHA1 iterations | Coinomi (Android) - scrypt N, r, p = 16384, 8, 1 | Electrum (Legacy) - 2 SHA-256 iterations | Electrum 2.8+ - 1024 PBKDF2-SHA512 iterations + ECC | Electrum 2.8+ Passphrase - 1024 PBKDF2-SHA512 iterations + ECC | Ethereum Keystore (scrypt) - Scrypt N=17 R=8 P=1 | MetaMask (Chrome) - 10000 PBKDF2-SHA256 iterations | MultiBit Classic - 3 MD5 iterations | MultiBit HD - scrypt N, r, p = 16384, 8, 1 | Raw Private Key - 1 SHA-256 iteration | SLIP39 Passphrase - 40,000 PBKDF2-SHA256 iterations + ECC |
|--------|------|--------|--------|--------|--------|--------|--------|--------|--------|--------|--------|--------|--------|--------|--------|--------|--------|--------|--------|--------|--------|
| Bitcoin Core (BDB) | CPU | 95.50 p/s | 82.60 p/s | 542.25 p/s | 98.17 p/s | 118.32 p/s | 46.73 p/s | 46.81 p/s | 29.00 p/s | 35.95 p/s |
| Bitcoin Core (SQLite) | CPU | 23.30 p/s | 22.87 p/s | 137.85 p/s | 28.78 p/s | 30.40 p/s | 11.40 p/s | 11.97 p/s | 6.34 p/s | 9.18 p/s |
| Electrum (Legacy) | CPU | 207.48 Kp/s | — | 2.65 Mp/s | 301.99 Kp/s | — | 158.57 Kp/s | — | 158.42 Kp/s | — |
| Electrum 2.8+ | CPU | 4.41 Kp/s | — | 33.74 Kp/s | 6.44 Kp/s | — | 2.67 Kp/s | — | 1.39 Kp/s | — |
| Blockchain.com (v0) | CPU | 61.48 Kp/s | 62.35 Kp/s | 691.29 Kp/s | 73.60 Kp/s | 114.52 Kp/s | 41.80 Kp/s | 42.59 Kp/s | 33.26 Kp/s | 46.21 Kp/s |
| Blockchain.com (v2) | CPU | 431.42 p/s | 431.40 p/s | 3.25 Kp/s | 520.64 p/s | 625.97 p/s | 394.67 p/s | 395.99 p/s | 154.00 p/s | 219.00 p/s |
| Blockchain.com (v3) | CPU | 772.70 p/s | 697.93 p/s | 6.46 Kp/s | 1.10 Kp/s | 1.22 Kp/s | 785.44 p/s | 787.66 p/s | 146.36 p/s | 433.67 p/s |
| MultiBit Classic | CPU | 191.41 Kp/s | 181.25 Kp/s | 2.00 Mp/s | 261.71 Kp/s | 301.89 Kp/s | 140.33 Kp/s | 140.91 Kp/s | 56.55 Kp/s | 167.16 Kp/s |
| MultiBit HD | CPU | 131.29 p/s | 134.84 p/s | 476.15 p/s | 69.20 p/s | 83.95 p/s | 61.26 p/s | 62.02 p/s | 21.00 p/s | 35.82 p/s |
| MetaMask (Chrome) | CPU | 674.77 p/s | 689.70 p/s | 6.33 Kp/s | 1.08 Kp/s | 1.34 Kp/s | 700.40 p/s | 699.37 p/s | 187.40 p/s | 383.07 p/s |
| Ethereum Keystore (scrypt) | CPU | 16.77 p/s | 16.37 p/s | — | 8.97 p/s | 10.39 p/s | 8.82 p/s | 9.32 p/s | 5.46 p/s | 7.33 p/s |
| Bitcoin Core (BDB) | GPU | 6.97 Kp/s | 6.93 Kp/s | 11.96 Kp/s | — | — | — | — | — | — |
| Bitcoin Core (SQLite) | GPU | 2.09 Kp/s | 2.09 Kp/s | 3.21 Kp/s | — | — | — | — | — | — |
| Electrum 2.8+ Passphrase | CPU | — | 4.67 Kp/s | — | — | 7.38 Kp/s | — | 2.67 Kp/s | — | 2.17 Kp/s |
| BIP39 Passphrase | CPU | — | 2.40 Kp/s | — | — | 3.79 Kp/s | — | 1.36 Kp/s | — | 1.15 Kp/s |
| SLIP39 Passphrase | CPU | — | 365.89 p/s | — | — | — | — | — | — | — |
| BIP38 Encrypted Key | CPU | — | 15.00 p/s | — | — | — | — | — | — | — |
| Raw Private Key | CPU | — | 73.45 Kp/s | — | — | 76.00 Kp/s | — | 35.41 Kp/s | — | 24.57 Kp/s |
| BIP39 Passphrase | OPENCL | — | 10.80 Kp/s | — | — | — | — | — | — | — |
| Coinomi (Android) | CPU | — | — | — | 70.81 p/s | 84.39 p/s | 61.79 p/s | 62.37 p/s | 26.35 p/s | 35.30 p/s |

### Seed Benchmarks

| Test Type | Mode | Aezeed (LND) Seed | Aezeed (LND) Seed | BIP39 12-word Seed | BIP39 12-word Seed | BIP39 24-word Seed | BIP39 24-word Seed | Electrum Seed | Electrum Seed | SLIP39 Seed Share |
|--------|------|--------|--------|--------|--------|--------|--------|--------|--------|--------|
| BIP39 12-word Seed | CPU | 36.68 Kp/s | 36.02 Kp/s | 254.06 Kp/s | 40.45 Kp/s | 53.18 Kp/s | 19.48 Kp/s | 18.65 Kp/s | 16.15 Kp/s | 12.05 Kp/s |
| BIP39 24-word Seed | CPU | 147.63 Kp/s | 155.32 Kp/s | 841.75 Kp/s | 154.92 Kp/s | 195.42 Kp/s | 106.14 Kp/s | 106.56 Kp/s | 80.29 Kp/s | 90.66 Kp/s |
| Electrum Seed | CPU | 154.77 Kp/s | 151.98 Kp/s | 818.92 Kp/s | 211.87 Kp/s | 249.63 Kp/s | 116.24 Kp/s | 118.92 Kp/s | 90.91 Kp/s | 102.75 Kp/s |
| BIP39 12-word Seed | OPENCL | 129.10 Kp/s | 127.20 Kp/s | 132.77 Kp/s | — | — | — | — | — | — |
| BIP39 24-word Seed | OPENCL | 276.60 Kp/s | 292.68 Kp/s | 601.64 Kp/s | — | — | — | — | — | — |
| Electrum Seed | OPENCL | 396.32 Kp/s | 390.90 Kp/s | 147.17 Kp/s | — | — | — | — | — | — |
| Aezeed (LND) Seed | CPU | — | 284.50 Kp/s | — | — | 337.59 Kp/s | — | 230.10 Kp/s | — | 215.30 Kp/s |
| SLIP39 Seed Share | CPU | — | 89.85 Kp/s | — | — | — | — | — | — | — |
| Aezeed (LND) Seed | OPENCL | — | 325.94 Kp/s | — | — | — | — | — | — | — |


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

# Electrum 2.8+ Passphrase
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

# BIP39 Passphrase (CPU)
python btcrecover.py --performance --bip39 --mpk xpub6D3uXJmdUg4xVnCUkNXJPCkk18gZAB8exGdQeb2rDwC5UJtraHHARSCc2Nz7rQ14godicjXiKxhUn39gbAw6Xb5eWb5srcbkhqPgAqoTMEY --mnemonic "certain come keen collect slab gauge photo inside mechanic deny leader drop" --no-eta --no-dupchecks --dsw

# BIP39 Passphrase with OpenCL acceleration
python btcrecover.py --performance --bip39 --mpk xpub6D3uXJmdUg4xVnCUkNXJPCkk18gZAB8exGdQeb2rDwC5UJtraHHARSCc2Nz7rQ14godicjXiKxhUn39gbAw6Xb5eWb5srcbkhqPgAqoTMEY --mnemonic "certain come keen collect slab gauge photo inside mechanic deny leader drop" --no-eta --no-dupchecks --dsw --enable-opencl

# SLIP39 Passphrase (CPU)
python btcrecover.py --performance --slip39 --slip39-shares "hearing echo academic acid deny bracelet playoff exact fancy various evidence standard adjust muscle parcel sled crucial amazing mansion losing" "hearing echo academic agency deliver join grant laden index depart deadline starting duration loud crystal bulge gasoline injury tofu together" --addrs bc1q76szkxz4cta5p5s66muskvads0nhwe5m5w07pq --addr-limit 2 --no-eta --no-dupchecks --dsw

# SLIP39 Passphrase with OpenCL acceleration
python btcrecover.py --performance --slip39 --slip39-shares "hearing echo academic acid deny bracelet playoff exact fancy various evidence standard adjust muscle parcel sled crucial amazing mansion losing" "hearing echo academic agency deliver join grant laden index depart deadline starting duration loud crystal bulge gasoline injury tofu together" --addrs bc1q76szkxz4cta5p5s66muskvads0nhwe5m5w07pq --addr-limit 2 --no-eta --no-dupchecks --dsw --enable-opencl

# BIP38 Encrypted Key (CPU)
python btcrecover.py --performance --bip38-enc-privkey 6PnM7h9sBC9EMZxLVsKzpafvBN8zjKp8MZj6h9mfvYEQRMkKBTPTyWZHHx --no-eta --no-dupchecks --dsw

# BIP38 Encrypted Key with OpenCL acceleration
python btcrecover.py --performance --bip38-enc-privkey 6PnM7h9sBC9EMZxLVsKzpafvBN8zjKp8MZj6h9mfvYEQRMkKBTPTyWZHHx --no-eta --no-dupchecks --dsw --enable-opencl

# Raw Private Key
python btcrecover.py --performance --rawprivatekey --addrs 1EDrqbJMVwjQ2K5avN3627NcAXyWbkpGBL --no-eta --no-dupchecks --dsw
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

# Aezeed (LND) Seed (CPU)
python seedrecover.py --performance --wallet-type aezeed --mnemonic-length 24 --language en --dsw --no-eta --no-dupchecks --addr-limit 1 --addrs 1Hp6UXuJjzt9eSBa9LhtW97KPb44bq4CAQ

# SLIP39 Seed Share (CPU)
python seedrecover.py --performance --wallet-type slip39seed --mnemonic-length 20 --dsw --no-eta --no-dupchecks
```
