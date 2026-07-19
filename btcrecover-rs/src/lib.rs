//! # btcrecover-rs
//!
//! A Rust port of btcrecover - Bitcoin and Ethereum wallet password/seed recovery tool.
//!
//! This library provides:
//! - **BIP39**: Mnemonic generation, validation, and seed derivation
//! - **BIP32**: Hierarchical deterministic key derivation
//! - **Bitcoin**: Address generation (P2PKH, P2SH-P2WPKH, P2WPKH) and wallet password recovery
//! - **Ethereum**: Address generation (with EIP-55 checksums) and MetaMask vault recovery
//! - **Recovery**: Parallel seed and password recovery engines
//!
//! ## Example: Generate Bitcoin Address from Mnemonic
//!
//! ```rust
//! use btcrecover_rs::{bip39, bitcoin};
//!
//! let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
//! let address = bitcoin::address_from_mnemonic(
//!     mnemonic, "", "m/84'/0'/0'/0/0",
//!     bitcoin::AddressType::P2wpkh, bitcoin::Network::Mainnet
//! ).unwrap();
//! assert!(address.starts_with("bc1q"));
//! ```
//!
//! ## Example: Generate Ethereum Address from Mnemonic
//!
//! ```rust
//! use btcrecover_rs::{bip39, ethereum};
//!
//! let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
//! let address = ethereum::address_from_mnemonic(mnemonic, "", "m/44'/60'/0'/0/0").unwrap();
//! assert!(address.starts_with("0x"));
//! ```

pub mod bip32;
pub mod bip39;
pub mod bitcoin;
pub mod ethereum;
pub mod recovery;
pub mod utils;
