use rayon::prelude::*;

use crate::bitcoin::wallet::{self as btc_wallet, BitcoinCoreWalletParams};
use crate::ethereum::wallet::{self as eth_wallet, MetaMaskParams};

/// Wallet types supported for password recovery
#[derive(Debug, Clone)]
pub enum WalletType {
    /// Bitcoin Core wallet.dat
    BitcoinCore(BitcoinCoreWalletParams),
    /// MetaMask vault (Desktop or Mobile)
    MetaMask(MetaMaskParams),
}

/// Result of a password recovery attempt
#[derive(Debug, Clone)]
pub struct PasswordRecoveryResult {
    /// The recovered password (if found)
    pub password: Option<String>,
    /// Number of passwords checked
    pub checked_count: u64,
}

/// Check a single password against a wallet
pub fn check_password(wallet: &WalletType, password: &str) -> bool {
    match wallet {
        WalletType::BitcoinCore(params) => btc_wallet::check_password_bitcoin_core(params, password),
        WalletType::MetaMask(params) => eth_wallet::check_password_metamask(params, password),
    }
}

/// Try to recover a password by testing multiple candidates in parallel
pub fn recover_password_parallel(
    candidates: &[String],
    wallet: &WalletType,
) -> PasswordRecoveryResult {
    let result = candidates.par_iter().find_map_any(|password| {
        if check_password(wallet, password) {
            Some(password.clone())
        } else {
            None
        }
    });

    PasswordRecoveryResult {
        password: result,
        checked_count: candidates.len() as u64,
    }
}

/// Generate password candidates from a base password with common variations
pub fn generate_password_variations(base: &str) -> Vec<String> {
    let mut variations = Vec::new();

    // Original password
    variations.push(base.to_string());

    // Common number suffixes
    for i in 0..=99 {
        variations.push(format!("{}{}", base, i));
    }

    // Common symbol suffixes
    for suffix in &["!", "@", "#", "$", "%", "!!", "123", "1234"] {
        variations.push(format!("{}{}", base, suffix));
    }

    // Capitalize first letter
    if let Some(first) = base.chars().next() {
        let capitalized = format!("{}{}", first.to_uppercase(), &base[first.len_utf8()..]);
        if capitalized != base {
            variations.push(capitalized);
        }
    }

    // All uppercase
    let upper = base.to_uppercase();
    if upper != base {
        variations.push(upper);
    }

    // All lowercase
    let lower = base.to_lowercase();
    if lower != base {
        variations.push(lower);
    }

    variations
}

/// Read passwords from a wordlist file (one per line)
pub fn read_password_list(path: &str) -> Result<Vec<String>, std::io::Error> {
    use std::io::BufRead;
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    Ok(reader
        .lines()
        .collect::<Result<Vec<String>, _>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_variations() {
        let variations = generate_password_variations("test");
        assert!(variations.contains(&"test".to_string()));
        assert!(variations.contains(&"test1".to_string()));
        assert!(variations.contains(&"test!".to_string()));
        assert!(variations.contains(&"Test".to_string()));
        assert!(variations.contains(&"TEST".to_string()));
        assert!(variations.len() > 100);
    }

    #[test]
    fn test_parallel_recovery_not_found() {
        let params = BitcoinCoreWalletParams {
            encrypted_master_key: vec![0u8; 48],
            salt: vec![0u8; 8],
            derive_iterations: 10,
            derive_method: 0,
        };

        let wallet = WalletType::BitcoinCore(params);
        let candidates: Vec<String> = (0..10).map(|i| format!("wrong_{}", i)).collect();

        let result = recover_password_parallel(&candidates, &wallet);
        assert!(result.password.is_none());
        assert_eq!(result.checked_count, 10);
    }
}
