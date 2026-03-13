pub mod wallet;

use crate::bip32;
use crate::utils::encoding;

/// Bitcoin network types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
}

/// Bitcoin address types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    /// Pay-to-Public-Key-Hash (1...)
    P2pkh,
    /// Pay-to-Script-Hash (3...)
    P2sh,
    /// Pay-to-Witness-Public-Key-Hash, native SegWit (bc1q...)
    P2wpkh,
    /// Pay-to-Witness-Script-Hash (bc1q... 32-byte program)
    P2wsh,
    /// Pay-to-Taproot (bc1p...)
    P2tr,
}

/// Version bytes for address encoding
impl AddressType {
    fn version_byte(self, network: Network) -> u8 {
        match (self, network) {
            (AddressType::P2pkh, Network::Mainnet) => 0x00,
            (AddressType::P2pkh, Network::Testnet) => 0x6f,
            (AddressType::P2sh, Network::Mainnet) => 0x05,
            (AddressType::P2sh, Network::Testnet) => 0xc4,
            _ => 0x00, // Bech32 addresses don't use version bytes
        }
    }
}

/// Generate a P2PKH Bitcoin address from a compressed public key
pub fn pubkey_to_p2pkh_address(pubkey: &[u8; 33], network: Network) -> String {
    let hash = encoding::hash160(pubkey);
    let version = AddressType::P2pkh.version_byte(network);
    encoding::base58check_encode(version, &hash)
}

/// Generate a P2SH-P2WPKH (wrapped SegWit) address from a compressed public key
pub fn pubkey_to_p2sh_p2wpkh_address(pubkey: &[u8; 33], network: Network) -> String {
    let keyhash = encoding::hash160(pubkey);
    // P2SH-P2WPKH witness script: OP_0 <20-byte-keyhash>
    let mut script = Vec::with_capacity(22);
    script.push(0x00); // OP_0
    script.push(0x14); // Push 20 bytes
    script.extend_from_slice(&keyhash);
    let script_hash = encoding::hash160(&script);
    let version = AddressType::P2sh.version_byte(network);
    encoding::base58check_encode(version, &script_hash)
}

/// Generate a native P2WPKH (Bech32) address from a compressed public key
pub fn pubkey_to_p2wpkh_address(pubkey: &[u8; 33], network: Network) -> Result<String, String> {
    let keyhash = encoding::hash160(pubkey);
    let hrp = match network {
        Network::Mainnet => "bc",
        Network::Testnet => "tb",
    };
    encoding::bech32_encode(hrp, 0, &keyhash)
}

/// Generate a Bitcoin address from a BIP39 seed and derivation path
pub fn address_from_seed(
    seed: &[u8; 64],
    path: &str,
    address_type: AddressType,
    network: Network,
) -> Result<String, String> {
    let key = bip32::derive_path_str(seed, path).map_err(|e| e.to_string())?;
    let pubkey = bip32::private_to_public_compressed(&key.private_key)
        .map_err(|e| e.to_string())?;

    match address_type {
        AddressType::P2pkh => Ok(pubkey_to_p2pkh_address(&pubkey, network)),
        AddressType::P2sh => Ok(pubkey_to_p2sh_p2wpkh_address(&pubkey, network)),
        AddressType::P2wpkh => pubkey_to_p2wpkh_address(&pubkey, network),
        _ => Err(format!("Unsupported address type: {:?}", address_type)),
    }
}

/// Generate a Bitcoin address from a mnemonic
pub fn address_from_mnemonic(
    mnemonic: &str,
    passphrase: &str,
    path: &str,
    address_type: AddressType,
    network: Network,
) -> Result<String, String> {
    let seed = crate::bip39::mnemonic_to_seed(mnemonic, passphrase);
    address_from_seed(&seed, path, address_type, network)
}

/// Get the default BIP44 derivation path for Bitcoin
pub fn default_derivation_path(address_type: AddressType) -> &'static str {
    match address_type {
        AddressType::P2pkh => "m/44'/0'/0'/0/0",
        AddressType::P2sh => "m/49'/0'/0'/0/0",
        AddressType::P2wpkh => "m/84'/0'/0'/0/0",
        AddressType::P2wsh => "m/84'/0'/0'/0/0",
        AddressType::P2tr => "m/86'/0'/0'/0/0",
    }
}

/// Derive the HASH160 of a public key at the given derivation path
pub fn pubkey_hash160_from_seed(
    seed: &[u8; 64],
    path: &str,
) -> Result<[u8; 20], String> {
    let key = bip32::derive_path_str(seed, path).map_err(|e| e.to_string())?;
    let pubkey = bip32::private_to_public_compressed(&key.private_key)
        .map_err(|e| e.to_string())?;
    Ok(encoding::hash160(&pubkey))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip39;

    #[test]
    fn test_p2pkh_address_from_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let address = address_from_mnemonic(
            mnemonic,
            "",
            "m/44'/0'/0'/0/0",
            AddressType::P2pkh,
            Network::Mainnet,
        )
        .unwrap();
        // Known address for this mnemonic/path combination
        assert!(address.starts_with('1'));
        assert_eq!(address, "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA");
    }

    #[test]
    fn test_p2wpkh_address_from_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let address = address_from_mnemonic(
            mnemonic,
            "",
            "m/84'/0'/0'/0/0",
            AddressType::P2wpkh,
            Network::Mainnet,
        )
        .unwrap();
        assert!(address.starts_with("bc1q"));
    }

    #[test]
    fn test_p2sh_p2wpkh_address_from_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let address = address_from_mnemonic(
            mnemonic,
            "",
            "m/49'/0'/0'/0/0",
            AddressType::P2sh,
            Network::Mainnet,
        )
        .unwrap();
        assert!(address.starts_with('3'));
    }

    #[test]
    fn test_default_paths() {
        assert_eq!(default_derivation_path(AddressType::P2pkh), "m/44'/0'/0'/0/0");
        assert_eq!(default_derivation_path(AddressType::P2sh), "m/49'/0'/0'/0/0");
        assert_eq!(default_derivation_path(AddressType::P2wpkh), "m/84'/0'/0'/0/0");
    }

    #[test]
    fn test_address_format_p2pkh() {
        // P2PKH addresses start with '1' on mainnet
        let seed = bip39::mnemonic_to_seed(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
        );
        let key = bip32::derive_path_str(&seed, "m/44'/0'/0'/0/0").unwrap();
        let pubkey = bip32::private_to_public_compressed(&key.private_key).unwrap();
        let addr = pubkey_to_p2pkh_address(&pubkey, Network::Mainnet);
        assert!(addr.starts_with('1'));
    }

    #[test]
    fn test_testnet_addresses() {
        let seed = bip39::mnemonic_to_seed(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
        );
        let key = bip32::derive_path_str(&seed, "m/44'/1'/0'/0/0").unwrap();
        let pubkey = bip32::private_to_public_compressed(&key.private_key).unwrap();

        let addr = pubkey_to_p2pkh_address(&pubkey, Network::Testnet);
        assert!(addr.starts_with('m') || addr.starts_with('n'));
    }
}
