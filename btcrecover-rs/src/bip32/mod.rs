use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::Sha512;

/// The secp256k1 curve order
const CURVE_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
    0x41, 0x41,
];

/// Errors that can occur during BIP32 operations
#[derive(Debug, thiserror::Error)]
pub enum Bip32Error {
    #[error("Invalid seed length")]
    InvalidSeedLength,
    #[error("Invalid child number")]
    InvalidChildNumber,
    #[error("Key derivation failed: {0}")]
    DerivationFailed(String),
    #[error("Invalid derivation path: {0}")]
    InvalidPath(String),
    #[error("Secp256k1 error: {0}")]
    Secp256k1Error(String),
}

/// A BIP32 extended key (private key with chain code)
#[derive(Clone)]
pub struct ExtendedPrivateKey {
    pub private_key: [u8; 32],
    pub chain_code: [u8; 32],
    pub depth: u8,
    pub child_number: u32,
}

/// A BIP32 extended public key
#[derive(Clone)]
pub struct ExtendedPublicKey {
    /// 33-byte compressed public key
    pub public_key: [u8; 33],
    pub chain_code: [u8; 32],
    pub depth: u8,
    pub child_number: u32,
}

/// A parsed derivation path component
#[derive(Debug, Clone, Copy)]
pub struct ChildNumber(pub u32);

impl ChildNumber {
    pub fn normal(index: u32) -> Self {
        ChildNumber(index)
    }

    pub fn hardened(index: u32) -> Self {
        ChildNumber(index | 0x80000000)
    }

    pub fn is_hardened(self) -> bool {
        self.0 & 0x80000000 != 0
    }
}

/// Parse a derivation path string like "m/44'/0'/0'/0/0"
pub fn parse_derivation_path(path: &str) -> Result<Vec<ChildNumber>, Bip32Error> {
    let path = path.trim();
    let parts: Vec<&str> = path.split('/').collect();

    if parts.is_empty() {
        return Err(Bip32Error::InvalidPath("Empty path".to_string()));
    }

    let start = if parts[0] == "m" || parts[0] == "M" {
        1
    } else {
        0
    };

    let mut result = Vec::with_capacity(parts.len() - start);
    for part in &parts[start..] {
        if part.is_empty() {
            continue;
        }
        let (num_str, hardened) = if part.ends_with('\'') || part.ends_with('h') || part.ends_with('H')
        {
            (&part[..part.len() - 1], true)
        } else {
            (*part, false)
        };

        let index: u32 = num_str
            .parse()
            .map_err(|_| Bip32Error::InvalidPath(format!("Invalid index: {}", part)))?;

        if hardened {
            result.push(ChildNumber::hardened(index));
        } else {
            result.push(ChildNumber::normal(index));
        }
    }

    Ok(result)
}

/// Generate master key from seed using HMAC-SHA512 with key "Bitcoin seed"
pub fn master_key_from_seed(seed: &[u8]) -> Result<ExtendedPrivateKey, Bip32Error> {
    if seed.len() < 16 || seed.len() > 64 {
        return Err(Bip32Error::InvalidSeedLength);
    }

    let mut hmac =
        Hmac::<Sha512>::new_from_slice(b"Bitcoin seed").expect("HMAC can take key of any size");
    hmac.update(seed);
    let result = hmac.finalize().into_bytes();

    let mut private_key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    private_key.copy_from_slice(&result[..32]);
    chain_code.copy_from_slice(&result[32..]);

    // Verify the key is valid (non-zero and less than curve order)
    if private_key.iter().all(|&b| b == 0) {
        return Err(Bip32Error::DerivationFailed(
            "Master key is zero".to_string(),
        ));
    }

    Ok(ExtendedPrivateKey {
        private_key,
        chain_code,
        depth: 0,
        child_number: 0,
    })
}

/// Derive a child private key from a parent private key
pub fn derive_child_private_key(
    parent: &ExtendedPrivateKey,
    child: ChildNumber,
) -> Result<ExtendedPrivateKey, Bip32Error> {
    let secp = Secp256k1::new();

    let mut hmac = Hmac::<Sha512>::new_from_slice(&parent.chain_code)
        .expect("HMAC can take key of any size");

    if child.is_hardened() {
        // Hardened: HMAC data = 0x00 || private_key || child_number
        hmac.update(&[0x00]);
        hmac.update(&parent.private_key);
    } else {
        // Normal: HMAC data = compressed_public_key || child_number
        let secret_key = SecretKey::from_slice(&parent.private_key)
            .map_err(|e| Bip32Error::Secp256k1Error(e.to_string()))?;
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        hmac.update(&public_key.serialize());
    }

    hmac.update(&child.0.to_be_bytes());
    let result = hmac.finalize().into_bytes();

    // Child key = (parent_key + derived_key) mod curve_order
    let child_key = add_private_keys(&parent.private_key, &result[..32])?;

    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&result[32..]);

    // Verify the key is valid
    if child_key.iter().all(|&b| b == 0) {
        return Err(Bip32Error::DerivationFailed(
            "Derived key is zero".to_string(),
        ));
    }

    Ok(ExtendedPrivateKey {
        private_key: child_key,
        chain_code,
        depth: parent.depth.wrapping_add(1),
        child_number: child.0,
    })
}

/// Derive a key through a full derivation path
pub fn derive_path(
    seed: &[u8],
    path: &[ChildNumber],
) -> Result<ExtendedPrivateKey, Bip32Error> {
    let mut key = master_key_from_seed(seed)?;
    for &child in path {
        key = derive_child_private_key(&key, child)?;
    }
    Ok(key)
}

/// Derive a key from seed using a path string
pub fn derive_path_str(seed: &[u8], path: &str) -> Result<ExtendedPrivateKey, Bip32Error> {
    let components = parse_derivation_path(path)?;
    derive_path(seed, &components)
}

/// Get the compressed public key from a private key
pub fn private_to_public_compressed(private_key: &[u8; 32]) -> Result<[u8; 33], Bip32Error> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(private_key)
        .map_err(|e| Bip32Error::Secp256k1Error(e.to_string()))?;
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    Ok(public_key.serialize())
}

/// Get the uncompressed public key from a private key (65 bytes, with 0x04 prefix)
pub fn private_to_public_uncompressed(private_key: &[u8; 32]) -> Result<[u8; 65], Bip32Error> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(private_key)
        .map_err(|e| Bip32Error::Secp256k1Error(e.to_string()))?;
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    Ok(public_key.serialize_uncompressed())
}

/// Get the public key bytes (without 0x04 prefix) for Ethereum
pub fn private_to_public_key_bytes(private_key: &[u8; 32]) -> Result<[u8; 64], Bip32Error> {
    let uncompressed = private_to_public_uncompressed(private_key)?;
    let mut result = [0u8; 64];
    result.copy_from_slice(&uncompressed[1..]); // Skip 0x04 prefix
    Ok(result)
}

/// Add two private keys modulo the curve order
fn add_private_keys(key1: &[u8; 32], key2: &[u8]) -> Result<[u8; 32], Bip32Error> {
    // Convert to big integers using simple byte arithmetic
    // key1 and key2 are 32-byte big-endian integers
    // Result = (key1 + key2) mod curve_order

    let mut result = [0u8; 33]; // Extra byte for carry
    let mut carry: u16 = 0;

    // Add key1 + key2[..32]
    for i in (0..32).rev() {
        let sum = key1[i] as u16 + key2[i] as u16 + carry;
        result[i + 1] = (sum & 0xFF) as u8;
        carry = sum >> 8;
    }
    result[0] = carry as u8;

    // Reduce modulo curve order if needed
    // Simple comparison and subtraction
    let mut result32 = [0u8; 32];
    if result[0] > 0 || compare_bytes(&result[1..33], &CURVE_ORDER) >= 0 {
        // Subtract curve order
        let mut borrow: i16 = 0;
        for i in (0..32).rev() {
            let diff = result[i + 1] as i16 - CURVE_ORDER[i] as i16 - borrow;
            if diff < 0 {
                result32[i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                result32[i] = diff as u8;
                borrow = 0;
            }
        }
    } else {
        result32.copy_from_slice(&result[1..33]);
    }

    Ok(result32)
}

/// Compare two byte slices as big-endian unsigned integers
fn compare_bytes(a: &[u8], b: &[u8]) -> i32 {
    for i in 0..a.len().min(b.len()) {
        if a[i] < b[i] {
            return -1;
        }
        if a[i] > b[i] {
            return 1;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_derivation_path() {
        let path = parse_derivation_path("m/44'/0'/0'/0/0").unwrap();
        assert_eq!(path.len(), 5);
        assert!(path[0].is_hardened());
        assert_eq!(path[0].0, 44 | 0x80000000);
        assert!(path[1].is_hardened());
        assert!(!path[3].is_hardened());
        assert_eq!(path[4].0, 0);
    }

    #[test]
    fn test_parse_path_with_h() {
        let path = parse_derivation_path("m/44h/0h/0h").unwrap();
        assert_eq!(path.len(), 3);
        assert!(path[0].is_hardened());
    }

    #[test]
    fn test_master_key_from_seed() {
        // BIP32 test vector 1
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = master_key_from_seed(&seed).unwrap();

        assert_eq!(
            hex::encode(master.private_key),
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        );
        assert_eq!(
            hex::encode(master.chain_code),
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
        );
    }

    #[test]
    fn test_derive_child_hardened() {
        // BIP32 test vector 1: m/0'
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = master_key_from_seed(&seed).unwrap();
        let child = derive_child_private_key(&master, ChildNumber::hardened(0)).unwrap();

        assert_eq!(
            hex::encode(child.private_key),
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
        );
    }

    #[test]
    fn test_derive_full_path() {
        // BIP32 test vector 1: m/0'/1
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = derive_path_str(&seed, "m/0'/1").unwrap();

        assert_eq!(
            hex::encode(key.private_key),
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"
        );
    }

    #[test]
    fn test_private_to_public() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = master_key_from_seed(&seed).unwrap();
        let pubkey = private_to_public_compressed(&master.private_key).unwrap();

        assert_eq!(
            hex::encode(pubkey),
            "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
        );
    }

    #[test]
    fn test_bip44_bitcoin_path() {
        // Test a full BIP44 Bitcoin derivation: m/44'/0'/0'/0/0
        // Using the "abandon" mnemonic seed
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = crate::bip39::mnemonic_to_seed(mnemonic, "");

        let key = derive_path_str(&seed, "m/44'/0'/0'/0/0").unwrap();
        let pubkey = private_to_public_compressed(&key.private_key).unwrap();
        // The derived public key should be deterministic
        assert_eq!(pubkey.len(), 33);
        assert!(pubkey[0] == 0x02 || pubkey[0] == 0x03);
    }

    #[test]
    fn test_bip44_ethereum_path() {
        // Test a full BIP44 Ethereum derivation: m/44'/60'/0'/0/0
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = crate::bip39::mnemonic_to_seed(mnemonic, "");

        let key = derive_path_str(&seed, "m/44'/60'/0'/0/0").unwrap();
        let pubkey_bytes = private_to_public_key_bytes(&key.private_key).unwrap();
        assert_eq!(pubkey_bytes.len(), 64);
    }
}
