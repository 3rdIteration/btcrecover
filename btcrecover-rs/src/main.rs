use clap::{Parser, Subcommand};
use std::collections::HashSet;

use btcrecover_rs::{bip39, bitcoin, ethereum, recovery};

#[derive(Parser)]
#[command(name = "btcrecover-rs")]
#[command(about = "Bitcoin and Ethereum wallet password/seed recovery tool (Rust port)")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a Bitcoin or Ethereum address from a mnemonic
    Address {
        /// The mnemonic phrase (12 or 24 words)
        #[arg(short, long)]
        mnemonic: String,

        /// BIP39 passphrase
        #[arg(short, long, default_value = "")]
        passphrase: String,

        /// Blockchain type: bitcoin or ethereum
        #[arg(short, long, default_value = "bitcoin")]
        blockchain: String,

        /// Derivation path (e.g., m/44'/0'/0'/0/0)
        #[arg(short, long)]
        derivation_path: Option<String>,

        /// Bitcoin address type: p2pkh, p2sh, p2wpkh
        #[arg(long, default_value = "p2wpkh")]
        address_type: String,

        /// Network: mainnet or testnet
        #[arg(short, long, default_value = "mainnet")]
        network: String,
    },

    /// Validate a BIP39 mnemonic
    Validate {
        /// The mnemonic phrase to validate
        #[arg(short, long)]
        mnemonic: String,
    },

    /// Recover a seed by testing word replacements
    SeedRecover {
        /// The partial/incorrect mnemonic phrase
        #[arg(short, long)]
        mnemonic: String,

        /// Known address to match against
        #[arg(short, long)]
        address: String,

        /// Blockchain type: bitcoin or ethereum
        #[arg(short, long, default_value = "bitcoin")]
        blockchain: String,

        /// BIP39 passphrase
        #[arg(short, long, default_value = "")]
        passphrase: String,

        /// Derivation path
        #[arg(short, long)]
        derivation_path: Option<String>,

        /// Bitcoin address type: p2pkh, p2sh, p2wpkh
        #[arg(long, default_value = "p2wpkh")]
        address_type: String,

        /// Number of address indices to check
        #[arg(long, default_value = "1")]
        address_count: u32,
    },

    /// Recover a wallet password
    PasswordRecover {
        /// Path to the wallet extract file or MetaMask vault JSON
        #[arg(short, long)]
        wallet: String,

        /// Wallet type: bitcoin-core or metamask
        #[arg(short = 't', long)]
        wallet_type: String,

        /// Path to password list file
        #[arg(short, long)]
        passwords: String,
    },
}

fn parse_btc_address_type(s: &str) -> bitcoin::AddressType {
    match s.to_lowercase().as_str() {
        "p2pkh" | "legacy" => bitcoin::AddressType::P2pkh,
        "p2sh" | "wrapped-segwit" => bitcoin::AddressType::P2sh,
        "p2wpkh" | "segwit" | "bech32" => bitcoin::AddressType::P2wpkh,
        _ => bitcoin::AddressType::P2wpkh,
    }
}

fn parse_network(s: &str) -> bitcoin::Network {
    match s.to_lowercase().as_str() {
        "testnet" | "test" => bitcoin::Network::Testnet,
        _ => bitcoin::Network::Mainnet,
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Address {
            mnemonic,
            passphrase,
            blockchain,
            derivation_path,
            address_type,
            network,
        } => {
            // Validate mnemonic first
            match bip39::verify_checksum(&mnemonic) {
                Ok(true) => {}
                Ok(false) => {
                    eprintln!("Warning: mnemonic has invalid checksum");
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }

            match blockchain.to_lowercase().as_str() {
                "bitcoin" | "btc" => {
                    let addr_type = parse_btc_address_type(&address_type);
                    let net = parse_network(&network);
                    let path = derivation_path
                        .unwrap_or_else(|| bitcoin::default_derivation_path(addr_type).to_string());

                    match bitcoin::address_from_mnemonic(&mnemonic, &passphrase, &path, addr_type, net) {
                        Ok(addr) => {
                            println!("Bitcoin Address: {}", addr);
                            println!("Path: {}", path);
                        }
                        Err(e) => {
                            eprintln!("Error: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                "ethereum" | "eth" => {
                    let path = derivation_path
                        .unwrap_or_else(|| ethereum::DEFAULT_ETH_PATH.to_string());

                    match ethereum::address_from_mnemonic(&mnemonic, &passphrase, &path) {
                        Ok(addr) => {
                            println!("Ethereum Address: {}", addr);
                            println!("Path: {}", path);
                        }
                        Err(e) => {
                            eprintln!("Error: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                _ => {
                    eprintln!("Unsupported blockchain: {}", blockchain);
                    std::process::exit(1);
                }
            }
        }

        Commands::Validate { mnemonic } => match bip39::verify_checksum(&mnemonic) {
            Ok(true) => {
                println!("Valid BIP39 mnemonic ({} words)", mnemonic.split_whitespace().count());
            }
            Ok(false) => {
                println!("Invalid checksum");
                std::process::exit(1);
            }
            Err(e) => {
                println!("Error: {}", e);
                std::process::exit(1);
            }
        },

        Commands::SeedRecover {
            mnemonic,
            address,
            blockchain,
            passphrase,
            derivation_path,
            address_type,
            address_count,
        } => {
            let (blockchain_type, default_base_path) = match blockchain.to_lowercase().as_str() {
                "bitcoin" | "btc" => {
                    let addr_type = parse_btc_address_type(&address_type);
                    let full_path = bitcoin::default_derivation_path(addr_type);
                    // Strip last /index to get base path (e.g., m/44'/0'/0'/0)
                    let base = match full_path.rfind('/') {
                        Some(pos) => &full_path[..pos],
                        None => full_path,
                    };
                    (
                        recovery::seed::BlockchainType::Bitcoin,
                        base.to_string(),
                    )
                }
                "ethereum" | "eth" => (
                    recovery::seed::BlockchainType::Ethereum,
                    "m/44'/60'/0'/0".to_string(),
                ),
                _ => {
                    eprintln!("Unsupported blockchain: {}", blockchain);
                    std::process::exit(1);
                }
            };

            let base_path = derivation_path.unwrap_or(default_base_path);

            let config = recovery::seed::SeedRecoveryConfig {
                blockchain: blockchain_type,
                known_addresses: HashSet::from([address.to_lowercase()]),
                derivation_paths: vec![base_path],
                passphrase,
                btc_address_type: parse_btc_address_type(&address_type),
                btc_network: bitcoin::Network::Mainnet,
                address_search_count: address_count,
            };

            println!("Generating mnemonic candidates...");
            let candidates = recovery::seed::generate_all_single_word_candidates(&mnemonic);
            println!(
                "Testing {} candidates ({} positions × 2048 words)...",
                candidates.len(),
                mnemonic.split_whitespace().count()
            );

            let result = recovery::seed::recover_seed_parallel(&candidates, &config);

            match result.mnemonic {
                Some(found) => {
                    println!("\n*** FOUND ***");
                    println!("Mnemonic: {}", found);
                    if let Some(addr) = result.matched_address {
                        println!("Address: {}", addr);
                    }
                    if let Some(path) = result.matched_path {
                        println!("Path: {}", path);
                    }
                }
                None => {
                    println!("\nNo matching mnemonic found after {} checks.", result.checked_count);
                    std::process::exit(1);
                }
            }
        }

        Commands::PasswordRecover {
            wallet,
            wallet_type,
            passwords,
        } => {
            let wallet_data = match wallet_type.to_lowercase().as_str() {
                "bitcoin-core" | "btc-core" => {
                    let data = std::fs::read_to_string(&wallet)
                        .unwrap_or_else(|e| {
                            eprintln!("Error reading wallet file: {}", e);
                            std::process::exit(1);
                        });
                    let params = bitcoin::wallet::BitcoinCoreWalletParams::from_extract_string(
                        data.trim(),
                    )
                    .unwrap_or_else(|e| {
                        eprintln!("Error parsing wallet data: {}", e);
                        std::process::exit(1);
                    });
                    recovery::password::WalletType::BitcoinCore(params)
                }
                "metamask" => {
                    let json = std::fs::read_to_string(&wallet).unwrap_or_else(|e| {
                        eprintln!("Error reading vault file: {}", e);
                        std::process::exit(1);
                    });
                    let params =
                        ethereum::wallet::MetaMaskParams::from_json(&json).unwrap_or_else(|e| {
                            eprintln!("Error parsing vault: {}", e);
                            std::process::exit(1);
                        });
                    recovery::password::WalletType::MetaMask(params)
                }
                _ => {
                    eprintln!("Unsupported wallet type: {}", wallet_type);
                    std::process::exit(1);
                }
            };

            let password_list =
                recovery::password::read_password_list(&passwords).unwrap_or_else(|e| {
                    eprintln!("Error reading password list: {}", e);
                    std::process::exit(1);
                });

            println!("Testing {} passwords...", password_list.len());

            let result = recovery::password::recover_password_parallel(&password_list, &wallet_data);

            match result.password {
                Some(found) => {
                    println!("\n*** FOUND ***");
                    println!("Password: {}", found);
                }
                None => {
                    println!(
                        "\nNo matching password found after {} checks.",
                        result.checked_count
                    );
                    std::process::exit(1);
                }
            }
        }
    }
}
