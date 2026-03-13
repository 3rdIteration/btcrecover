use rayon::prelude::*;
use std::collections::HashSet;

use crate::bip39;
use crate::bitcoin::{self, AddressType, Network};
use crate::ethereum;

/// Blockchain type for seed recovery
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockchainType {
    Bitcoin,
    Ethereum,
}

/// Configuration for seed recovery
#[derive(Debug, Clone)]
pub struct SeedRecoveryConfig {
    /// Target blockchain
    pub blockchain: BlockchainType,
    /// Known addresses to check against (lowercase hex for ETH, base58/bech32 for BTC)
    pub known_addresses: HashSet<String>,
    /// Derivation path(s) to check
    pub derivation_paths: Vec<String>,
    /// BIP39 passphrase
    pub passphrase: String,
    /// Bitcoin address type (only used for Bitcoin)
    pub btc_address_type: AddressType,
    /// Bitcoin network (only used for Bitcoin)
    pub btc_network: Network,
    /// Number of address indices to check per path
    pub address_search_count: u32,
}

impl Default for SeedRecoveryConfig {
    fn default() -> Self {
        Self {
            blockchain: BlockchainType::Bitcoin,
            known_addresses: HashSet::new(),
            derivation_paths: vec!["m/44'/0'/0'/0".to_string()],
            passphrase: String::new(),
            btc_address_type: AddressType::P2wpkh,
            btc_network: Network::Mainnet,
            address_search_count: 1,
        }
    }
}

/// Result of a seed recovery attempt
#[derive(Debug, Clone)]
pub struct SeedRecoveryResult {
    /// The recovered mnemonic (if found)
    pub mnemonic: Option<String>,
    /// The matching address (if found)
    pub matched_address: Option<String>,
    /// The derivation path that matched
    pub matched_path: Option<String>,
    /// Number of mnemonics checked
    pub checked_count: u64,
}

/// Check if a mnemonic matches any known address
pub fn check_mnemonic(mnemonic: &str, config: &SeedRecoveryConfig) -> Option<(String, String)> {
    // Verify BIP39 checksum first (fast rejection)
    if bip39::verify_checksum(mnemonic).unwrap_or(false) == false {
        return None;
    }

    let seed = bip39::mnemonic_to_seed(mnemonic, &config.passphrase);

    for base_path in &config.derivation_paths {
        for idx in 0..config.address_search_count {
            let full_path = format!("{}/{}", base_path, idx);
            let address = match config.blockchain {
                BlockchainType::Bitcoin => {
                    match bitcoin::address_from_seed(
                        &seed,
                        &full_path,
                        config.btc_address_type,
                        config.btc_network,
                    ) {
                        Ok(addr) => addr,
                        Err(_) => continue,
                    }
                }
                BlockchainType::Ethereum => {
                    match ethereum::address_from_seed(&seed, &full_path) {
                        Ok(addr) => ethereum::format_address(&addr).to_lowercase(),
                        Err(_) => continue,
                    }
                }
            };

            let addr_lower = address.to_lowercase();
            if config.known_addresses.contains(&addr_lower) {
                return Some((address, full_path));
            }
        }
    }

    None
}

/// Try to recover a seed by testing multiple mnemonic candidates in parallel
/// Returns the first matching mnemonic or None
pub fn recover_seed_parallel(
    candidates: &[String],
    config: &SeedRecoveryConfig,
) -> SeedRecoveryResult {
    let result = candidates
        .par_iter()
        .find_map_any(|mnemonic| {
            check_mnemonic(mnemonic, config).map(|(addr, path)| (mnemonic.clone(), addr, path))
        });

    match result {
        Some((mnemonic, address, path)) => SeedRecoveryResult {
            mnemonic: Some(mnemonic),
            matched_address: Some(address),
            matched_path: Some(path),
            checked_count: candidates.len() as u64,
        },
        None => SeedRecoveryResult {
            mnemonic: None,
            matched_address: None,
            matched_path: None,
            checked_count: candidates.len() as u64,
        },
    }
}

/// Generate mnemonic candidates by replacing one word at a specific position
pub fn generate_single_word_candidates(mnemonic: &str, position: usize) -> Vec<String> {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    if position >= words.len() {
        return vec![];
    }

    let mut candidates = Vec::with_capacity(2048);
    for i in 0..2048 {
        if let Some(replacement) = bip39::word_at_index(i) {
            let mut new_words = words.clone();
            new_words[position] = replacement;
            candidates.push(new_words.join(" "));
        }
    }

    candidates
}

/// Generate mnemonic candidates by replacing one word at each position
pub fn generate_all_single_word_candidates(mnemonic: &str) -> Vec<String> {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    let mut candidates = Vec::new();

    for pos in 0..words.len() {
        candidates.extend(generate_single_word_candidates(mnemonic, pos));
    }

    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_mnemonic_bitcoin() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let mut config = SeedRecoveryConfig {
            blockchain: BlockchainType::Bitcoin,
            known_addresses: HashSet::new(),
            derivation_paths: vec!["m/44'/0'/0'/0".to_string()],
            passphrase: String::new(),
            btc_address_type: AddressType::P2pkh,
            btc_network: Network::Mainnet,
            address_search_count: 1,
        };

        // Get the actual address for this mnemonic
        let address = bitcoin::address_from_mnemonic(
            mnemonic,
            "",
            "m/44'/0'/0'/0/0",
            AddressType::P2pkh,
            Network::Mainnet,
        )
        .unwrap();

        config.known_addresses.insert(address.to_lowercase());

        let result = check_mnemonic(mnemonic, &config);
        assert!(result.is_some());
    }

    #[test]
    fn test_check_mnemonic_ethereum() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let mut config = SeedRecoveryConfig {
            blockchain: BlockchainType::Ethereum,
            known_addresses: HashSet::new(),
            derivation_paths: vec!["m/44'/60'/0'/0".to_string()],
            passphrase: String::new(),
            btc_address_type: AddressType::P2pkh,
            btc_network: Network::Mainnet,
            address_search_count: 1,
        };

        // Get the actual address
        let addr = ethereum::address_from_mnemonic(mnemonic, "", "m/44'/60'/0'/0/0").unwrap();
        config
            .known_addresses
            .insert(addr.to_lowercase());

        let result = check_mnemonic(mnemonic, &config);
        assert!(result.is_some());
    }

    #[test]
    fn test_check_mnemonic_wrong_address() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let config = SeedRecoveryConfig {
            blockchain: BlockchainType::Bitcoin,
            known_addresses: HashSet::from(["1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_lowercase()]),
            derivation_paths: vec!["m/44'/0'/0'/0".to_string()],
            passphrase: String::new(),
            btc_address_type: AddressType::P2pkh,
            btc_network: Network::Mainnet,
            address_search_count: 1,
        };

        let result = check_mnemonic(mnemonic, &config);
        assert!(result.is_none());
    }

    #[test]
    fn test_generate_single_word_candidates() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let candidates = generate_single_word_candidates(mnemonic, 0);
        assert_eq!(candidates.len(), 2048);

        // First candidate should start with "abandon"
        assert!(candidates[0].starts_with("abandon"));
        // Second candidate should start with "ability"
        assert!(candidates[1].starts_with("ability"));
    }

    #[test]
    fn test_parallel_recovery() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let mut config = SeedRecoveryConfig {
            blockchain: BlockchainType::Ethereum,
            known_addresses: HashSet::new(),
            derivation_paths: vec!["m/44'/60'/0'/0".to_string()],
            passphrase: String::new(),
            btc_address_type: AddressType::P2pkh,
            btc_network: Network::Mainnet,
            address_search_count: 1,
        };

        let addr = ethereum::address_from_mnemonic(mnemonic, "", "m/44'/60'/0'/0/0").unwrap();
        config.known_addresses.insert(addr.to_lowercase());

        let candidates = vec![
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong".to_string(),
            mnemonic.to_string(),
            "legal winner thank year wave sausage worth useful legal winner thank yellow".to_string(),
        ];

        let result = recover_seed_parallel(&candidates, &config);
        assert!(result.mnemonic.is_some());
        assert_eq!(result.mnemonic.unwrap(), mnemonic);
    }
}
