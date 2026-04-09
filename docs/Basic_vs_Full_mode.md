# Requirements Reference

BTCRecover offers two installation options depending on which wallet types you need to recover.

## Quick Comparison

| Feature | Basic (`requirements.txt`) | Full (`requirements-full.txt`) |
|---------|---------------------------|-------------------------------|
| Image size | ~500MB | ~1.2GB |
| Build time | Fast | Slower (more packages to compile) |
| Bitcoin wallets | Yes | Yes |
| Ethereum wallets | Yes | Yes |
| Altcoin wallets | Limited | Full support |

## Basic Requirements

**Install with:** `pip3 install -r requirements.txt`

**Packages included:**
- `coincurve` - Elliptic curve cryptography for Bitcoin/Ethereum
- `protobuf` - Google Protocol Buffers (required for some wallet formats)
- `pycryptodome` - Cryptographic primitives (20x speed boost for many wallets)

**Supported wallet types:**
- Bitcoin Core
- Electrum (all versions)
- BIP-39 seed phrases (Bitcoin, Ethereum, and most BIP-39 compatible wallets)
- Blockchain.info
- MultiBit Classic/HD
- mSIGNA (CoinVault)
- Hive for OS X
- Bitcoin Wallet for Android/BlackBerry
- KnC Wallet for Android
- Bither
- Litecoin-Qt, Electrum-LTC, Litecoin Wallet for Android
- Dogecoin Core, MultiDoge, Dogecoin Wallet for Android

This covers the vast majority of recovery scenarios for Bitcoin, Ethereum, and their direct clones.

## Full Requirements

**Install with:** `pip3 install -r requirements-full.txt`

**Additional packages included:**
| Package | Purpose |
|---------|---------|
| `py_crypto_hd_wallet` | Multi-chain HD wallet support |
| `shamir-mnemonic` | SLIP39 Shamir secret sharing |
| `eth-keyfile` | Ethereum keystore file support |
| `staking-deposit` | Eth2 validator seed recovery |
| `pynacl` + `bitstring` | Helium wallet support |
| `groestlcoin_hash` | Groestlcoin support |
| `wallycore` | Optimized scrypt (20% faster BIP38) |
| `pylibscrypt` | Scrypt fallback |
| `ecdsa` | BIP38 encrypted private keys |
| `stellar_sdk` | Stellar wallet support |
| And many more... | Various chain-specific support |

**Additional wallet types supported:**

| Blockchain | Wallet Types |
|------------|--------------|
| **SLIP39** | Any wallet using Shamir's Secret Sharing |
| **Avalanche** | BIP39 wallets |
| **Cosmos (Atom)** | BIP39 wallets |
| **Polkadot** | BIP39 wallets |
| **Secret Network** | BIP39 wallets |
| **Solana** | BIP39 wallets |
| **Stellar** | BIP39 wallets |
| **Tezos** | BIP39 wallets |
| **Tron** | BIP39 wallets |
| **Helium** | BIP39 wallets |
| **Groestlcoin** | BIP39 wallets |
| **Ethereum 2.0** | Validator seed recovery |
| **BIP38** | Encrypted private keys |

## Which Should I Use?

**Use Basic if:**
- You're recovering a Bitcoin, Ethereum, or Litecoin wallet
- You're working with standard BIP-39 seed phrases for common cryptocurrencies
- You want faster installation and smaller disk usage
- You're running in a resource-constrained environment

**Use Full if:**
- You need to recover wallets for Solana, Polkadot, Cosmos, or other altcoins listed above
- You're working with SLIP39 (Shamir) seed phrases
- You need Eth2 validator seed recovery
- You're working with BIP38 encrypted private keys
- You're unsure which wallet type you have

## Docker Usage

When using Docker, you can choose between variants:

```bash
# Basic version
docker compose run --rm btcrecover python btcrecover.py --help

# Full version
docker compose run --rm btcrecover-full python btcrecover.py --help
```

Or build directly with the `REQUIREMENTS` build argument:

```bash
# Basic (default)
docker build -t btcrecover .

# Full
docker build --build-arg REQUIREMENTS=full -t btcrecover:full .
```

## Performance Notes

- **PyCryptoDome** (included in both): Provides up to 20x speed improvement for wallets that support it
- **wallycore** (full only): Provides ~20% faster scrypt operations for BIP38 and similar formats
- **RIPEMD160**: Both Docker images have OpenSSL configured to use native RIPEMD160 for optimal performance
