pub mod wallet;

use crate::bip32;
use sha3::{Digest, Keccak256};

/// Default Ethereum BIP44 derivation path
pub const DEFAULT_ETH_PATH: &str = "m/44'/60'/0'/0/0";

/// Generate an Ethereum address from a 64-byte uncompressed public key (without 0x04 prefix)
/// Ethereum address = last 20 bytes of Keccak-256(pubkey_x || pubkey_y)
pub fn pubkey_bytes_to_address(pubkey_bytes: &[u8; 64]) -> [u8; 20] {
    let hash = Keccak256::digest(pubkey_bytes);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..32]);
    address
}

/// Format an Ethereum address as a hex string with 0x prefix
pub fn format_address(address: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(address))
}

/// Format an Ethereum address with EIP-55 checksum encoding
pub fn format_address_checksum(address: &[u8; 20]) -> String {
    let addr_hex = hex::encode(address);
    let hash = Keccak256::digest(addr_hex.as_bytes());

    let mut checksummed = String::with_capacity(42);
    checksummed.push_str("0x");

    for (i, c) in addr_hex.chars().enumerate() {
        let hash_nibble = if i % 2 == 0 {
            (hash[i / 2] >> 4) & 0x0F
        } else {
            hash[i / 2] & 0x0F
        };

        if hash_nibble >= 8 {
            checksummed.push(c.to_ascii_uppercase());
        } else {
            checksummed.push(c);
        }
    }

    checksummed
}

/// Generate an Ethereum address from a private key
pub fn address_from_private_key(private_key: &[u8; 32]) -> Result<[u8; 20], String> {
    let pubkey_bytes =
        bip32::private_to_public_key_bytes(private_key).map_err(|e| e.to_string())?;
    Ok(pubkey_bytes_to_address(&pubkey_bytes))
}

/// Generate an Ethereum address from a BIP39 seed and derivation path
pub fn address_from_seed(seed: &[u8; 64], path: &str) -> Result<[u8; 20], String> {
    let key = bip32::derive_path_str(seed, path).map_err(|e| e.to_string())?;
    address_from_private_key(&key.private_key)
}

/// Generate a formatted Ethereum address from a mnemonic
pub fn address_from_mnemonic(
    mnemonic: &str,
    passphrase: &str,
    path: &str,
) -> Result<String, String> {
    let seed = crate::bip39::mnemonic_to_seed(mnemonic, passphrase);
    let address = address_from_seed(&seed, path)?;
    Ok(format_address_checksum(&address))
}

/// Validate an Ethereum address format (with or without checksum)
pub fn is_valid_address(address: &str) -> bool {
    let addr = if let Some(stripped) = address.strip_prefix("0x") {
        stripped
    } else if let Some(stripped) = address.strip_prefix("0X") {
        stripped
    } else {
        return false;
    };

    if addr.len() != 40 {
        return false;
    }

    addr.chars().all(|c| c.is_ascii_hexdigit())
}

/// Parse an Ethereum address string to bytes
pub fn parse_address(address: &str) -> Result<[u8; 20], String> {
    let addr = address
        .strip_prefix("0x")
        .or_else(|| address.strip_prefix("0X"))
        .unwrap_or(address);

    if addr.len() != 40 {
        return Err(format!("Invalid address length: {}", addr.len()));
    }

    let bytes = hex::decode(addr).map_err(|e| format!("Invalid hex: {}", e))?;
    let mut result = [0u8; 20];
    result.copy_from_slice(&bytes);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip39;

    #[test]
    fn test_ethereum_address_from_mnemonic() {
        // Well-known test vector for the "abandon" mnemonic
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let address = address_from_mnemonic(mnemonic, "", DEFAULT_ETH_PATH).unwrap();

        // This should be the known Ethereum address for this mnemonic
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42);
        // Known address: 0x9858EfFD232B4033E47d90003D41EC34EcaEda94
        assert_eq!(
            address.to_lowercase(),
            "0x9858effd232b4033e47d90003d41ec34ecaeda94"
        );
    }

    #[test]
    fn test_eip55_checksum() {
        let addr_bytes = hex::decode("9858effd232b4033e47d90003d41ec34ecaeda94").unwrap();
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&addr_bytes);

        let checksummed = format_address_checksum(&addr);
        assert_eq!(checksummed, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
    }

    #[test]
    fn test_validate_address() {
        assert!(is_valid_address(
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
        ));
        assert!(is_valid_address(
            "0x9858effd232b4033e47d90003d41ec34ecaeda94"
        ));
        assert!(!is_valid_address("9858effd232b4033e47d90003d41ec34ecaeda94")); // no prefix
        assert!(!is_valid_address("0x9858effd232b4033e47d90003d41ec34ecaeda9")); // too short
        assert!(!is_valid_address("0xGGGGeffd232b4033e47d90003d41ec34ecaeda94")); // invalid hex
    }

    #[test]
    fn test_parse_address() {
        let addr = parse_address("0x9858EfFD232B4033E47d90003D41EC34EcaEda94").unwrap();
        assert_eq!(
            hex::encode(addr),
            "9858effd232b4033e47d90003d41ec34ecaeda94"
        );
    }

    #[test]
    fn test_address_from_seed() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = bip39::mnemonic_to_seed(mnemonic, "");
        let addr = address_from_seed(&seed, DEFAULT_ETH_PATH).unwrap();
        assert_eq!(
            hex::encode(addr),
            "9858effd232b4033e47d90003d41ec34ecaeda94"
        );
    }

    #[test]
    fn test_multiple_derivation_indices() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = bip39::mnemonic_to_seed(mnemonic, "");

        // m/44'/60'/0'/0/0 and m/44'/60'/0'/0/1 should give different addresses
        let addr0 = address_from_seed(&seed, "m/44'/60'/0'/0/0").unwrap();
        let addr1 = address_from_seed(&seed, "m/44'/60'/0'/0/1").unwrap();
        assert_ne!(addr0, addr1);
    }
}
