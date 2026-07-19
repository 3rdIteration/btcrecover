# btcrecover-rs

A Rust port of [btcrecover](https://github.com/3rdIteration/btcrecover) focusing on Bitcoin and Ethereum wallet recovery functionality.

## Features

### BIP39 Mnemonic Handling
- BIP39 English wordlist (2048 words)
- Mnemonic validation and checksum verification
- Entropy-to-mnemonic conversion
- PBKDF2-HMAC-SHA512 seed derivation (2048 iterations)

### BIP32 HD Key Derivation
- Master key generation from seed (HMAC-SHA512 with "Bitcoin seed")
- Hardened and normal child key derivation
- Full derivation path parsing (e.g., `m/44'/0'/0'/0/0`)
- Compressed and uncompressed public key generation (secp256k1)

### Bitcoin Address Generation
- **P2PKH** (Pay-to-Public-Key-Hash) — Legacy addresses starting with `1`
- **P2SH-P2WPKH** (Pay-to-Script-Hash wrapped SegWit) — Addresses starting with `3`
- **P2WPKH** (Pay-to-Witness-Public-Key-Hash) — Native SegWit/Bech32 addresses starting with `bc1q`
- Mainnet and Testnet support
- BIP44/49/84 default derivation paths

### Ethereum Address Generation
- Keccak-256 based address derivation
- EIP-55 mixed-case checksum encoding
- BIP44 derivation path support (`m/44'/60'/0'/0/0`)

### Wallet Password Recovery
- **Bitcoin Core** wallet.dat (SHA512 key derivation + AES-256-CBC)
- **MetaMask Desktop** vault (PBKDF2-SHA256 + AES-256-GCM)
- **MetaMask Mobile** vault (PBKDF2-SHA512 + AES-256-CBC)
- **Ethereum Keystore** V3 files (PBKDF2 KDF + Keccak-256 MAC verification)

### Seed Recovery
- Single-word replacement strategy (tests all 2048 words at each position)
- Multi-threaded parallel recovery using Rayon
- Bitcoin and Ethereum address matching
- Configurable derivation paths and address search depth

## Building

```bash
cd btcrecover-rs
cargo build --release
```

## Usage

### Generate an Address from a Mnemonic

```bash
# Bitcoin P2PKH (Legacy)
btcrecover-rs address --mnemonic "abandon abandon ... about" --blockchain bitcoin --address-type p2pkh

# Bitcoin P2WPKH (SegWit)
btcrecover-rs address --mnemonic "abandon abandon ... about" --blockchain bitcoin --address-type p2wpkh

# Ethereum
btcrecover-rs address --mnemonic "abandon abandon ... about" --blockchain ethereum
```

### Validate a Mnemonic

```bash
btcrecover-rs validate --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
```

### Seed Recovery

Recover a mnemonic with one incorrect word by matching against a known address:

```bash
# Ethereum seed recovery
btcrecover-rs seed-recover \
  --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon wrong" \
  --address "0x9858EfFD232B4033E47d90003D41EC34EcaEda94" \
  --blockchain ethereum

# Bitcoin seed recovery
btcrecover-rs seed-recover \
  --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon wrong" \
  --address "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA" \
  --blockchain bitcoin \
  --address-type p2pkh
```

### Password Recovery

```bash
# Bitcoin Core wallet
btcrecover-rs password-recover --wallet extract.txt --wallet-type bitcoin-core --passwords wordlist.txt

# MetaMask vault
btcrecover-rs password-recover --wallet vault.json --wallet-type metamask --passwords wordlist.txt
```

## Library Usage

```rust
use btcrecover_rs::{bip39, bip32, bitcoin, ethereum};

// Generate Bitcoin address from mnemonic
let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
let btc_addr = bitcoin::address_from_mnemonic(
    mnemonic, "", "m/84'/0'/0'/0/0",
    bitcoin::AddressType::P2wpkh, bitcoin::Network::Mainnet
).unwrap();

// Generate Ethereum address from mnemonic
let eth_addr = ethereum::address_from_mnemonic(
    mnemonic, "", "m/44'/60'/0'/0/0"
).unwrap();

// Validate a mnemonic
let is_valid = bip39::verify_checksum(mnemonic).unwrap();

// BIP32 key derivation
let seed = bip39::mnemonic_to_seed(mnemonic, "");
let key = bip32::derive_path_str(&seed, "m/44'/0'/0'/0/0").unwrap();
let pubkey = bip32::private_to_public_compressed(&key.private_key).unwrap();
```

## Running Tests

```bash
cargo test
```

## Architecture

```
btcrecover-rs/
├── src/
│   ├── lib.rs              # Library root with documentation
│   ├── main.rs             # CLI entry point (clap-based)
│   ├── bip39/
│   │   ├── mod.rs          # BIP39 mnemonic operations
│   │   └── wordlist.rs     # English wordlist (2048 words)
│   ├── bip32/
│   │   └── mod.rs          # BIP32 HD key derivation
│   ├── bitcoin/
│   │   ├── mod.rs          # Bitcoin address generation
│   │   └── wallet.rs       # Bitcoin Core password recovery
│   ├── ethereum/
│   │   ├── mod.rs          # Ethereum address generation
│   │   └── wallet.rs       # MetaMask/keystore password recovery
│   ├── recovery/
│   │   ├── mod.rs          # Recovery module root
│   │   ├── seed.rs         # Parallel seed recovery engine
│   │   └── password.rs     # Parallel password recovery engine
│   └── utils/
│       ├── mod.rs          # Utilities root
│       └── encoding.rs     # Base58Check, Bech32, HASH160, hex
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `secp256k1` | Elliptic curve operations (key generation, signing) |
| `sha2` | SHA-256, SHA-512 |
| `sha3` | Keccak-256 (Ethereum) |
| `hmac` | HMAC construction |
| `pbkdf2` | PBKDF2 key derivation |
| `ripemd` | RIPEMD-160 (Bitcoin HASH160) |
| `aes`, `cbc`, `aes-gcm` | AES encryption/decryption |
| `bs58` | Base58/Base58Check encoding |
| `bech32` | Bech32/Bech32m encoding (SegWit) |
| `clap` | CLI argument parsing |
| `rayon` | Data parallelism |
| `serde`, `serde_json` | JSON parsing |
| `thiserror` | Error types |

## License

GPL-2.0 (same as the original btcrecover)
