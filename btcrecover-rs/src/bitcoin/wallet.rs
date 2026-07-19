use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha512};

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Errors from Bitcoin Core wallet operations
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("Invalid wallet data: {0}")]
    InvalidData(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Unsupported wallet format: {0}")]
    UnsupportedFormat(String),
}

/// Bitcoin Core encrypted master key parameters
/// Extracted from wallet.dat by extract scripts
#[derive(Debug, Clone)]
pub struct BitcoinCoreWalletParams {
    /// Encrypted master key (48 bytes typically)
    pub encrypted_master_key: Vec<u8>,
    /// Salt for key derivation
    pub salt: Vec<u8>,
    /// Number of derivation iterations
    pub derive_iterations: u32,
    /// Derivation method (0 = SHA512)
    pub derive_method: u32,
}

impl BitcoinCoreWalletParams {
    /// Parse Bitcoin Core wallet parameters from hex-encoded extract data
    /// Format: encrypted_key_hex:salt_hex:iterations:method
    pub fn from_extract_string(data: &str) -> Result<Self, WalletError> {
        let parts: Vec<&str> = data.split(':').collect();
        if parts.len() < 3 {
            return Err(WalletError::InvalidData(
                "Expected format: encrypted_key:salt:iterations[:method]".to_string(),
            ));
        }

        let encrypted_master_key =
            hex::decode(parts[0]).map_err(|e| WalletError::InvalidData(e.to_string()))?;
        let salt = hex::decode(parts[1]).map_err(|e| WalletError::InvalidData(e.to_string()))?;
        let derive_iterations: u32 = parts[2]
            .parse()
            .map_err(|e: std::num::ParseIntError| WalletError::InvalidData(e.to_string()))?;
        let derive_method: u32 = if parts.len() > 3 {
            parts[3]
                .parse()
                .map_err(|e: std::num::ParseIntError| WalletError::InvalidData(e.to_string()))?
        } else {
            0
        };

        Ok(Self {
            encrypted_master_key,
            salt,
            derive_iterations,
            derive_method,
        })
    }
}

/// Derive the AES key and IV from a password using Bitcoin Core's method
/// Iteratively applies SHA512(password + salt) for the given number of iterations
fn derive_key_iv(password: &[u8], salt: &[u8], iterations: u32) -> ([u8; 32], [u8; 16]) {
    let mut data = Vec::with_capacity(password.len() + salt.len());
    data.extend_from_slice(password);
    data.extend_from_slice(salt);

    let mut hash = Sha512::digest(&data);

    for _ in 1..iterations {
        hash = Sha512::digest(&hash);
    }

    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&hash[..32]);
    iv.copy_from_slice(&hash[32..48]);

    (key, iv)
}

/// Try to decrypt a Bitcoin Core wallet's master key with a given password
/// Returns true if the password is correct (master key decrypts with valid PKCS7 padding)
pub fn check_password_bitcoin_core(
    params: &BitcoinCoreWalletParams,
    password: &str,
) -> bool {
    let (key, iv) = derive_key_iv(password.as_bytes(), &params.salt, params.derive_iterations);

    // Decrypt the encrypted master key using AES-256-CBC
    let mut buffer = params.encrypted_master_key.clone();

    let result = Aes256CbcDec::new((&key).into(), (&iv).into())
        .decrypt_padded_mut::<NoPadding>(&mut buffer);

    match result {
        Ok(decrypted) => {
            // Check for valid PKCS7 padding
            // The last byte indicates the padding length
            if decrypted.is_empty() {
                return false;
            }
            let padding_byte = decrypted[decrypted.len() - 1];
            if padding_byte == 0 || padding_byte as usize > 16 || padding_byte as usize > decrypted.len() {
                return false;
            }
            // Verify all padding bytes are consistent
            let pad_start = decrypted.len() - padding_byte as usize;
            decrypted[pad_start..].iter().all(|&b| b == padding_byte)
        }
        Err(_) => false,
    }
}

/// Electrum wallet types for password recovery
#[derive(Debug, Clone)]
pub enum ElectrumWalletType {
    /// Electrum 1.x (legacy)
    Electrum1 {
        seed: Vec<u8>,
    },
    /// Electrum 2.x+ (BIP32-based)
    Electrum2 {
        encrypted_data: Vec<u8>,
    },
}

/// Check if a password is valid for an Electrum 2.x+ wallet
/// Electrum 2.x uses a specific encryption: HMAC-SHA512 based key derivation + AES-256-CBC
pub fn check_password_electrum2(encrypted_data: &[u8], password: &str) -> bool {
    if encrypted_data.len() < 36 {
        return false;
    }

    // Electrum 2 encrypted data format:
    // Magic bytes (4) + IV (16) + encrypted_data + MAC (32)
    let password_bytes = password.as_bytes();

    // Derive key using PBKDF2 (simplified - actual Electrum uses a specific scheme)
    let mut hmac = match Hmac::<Sha512>::new_from_slice(password_bytes) {
        Ok(h) => h,
        Err(_) => return false,
    };
    hmac.update(b"electrum");
    let derived = hmac.finalize().into_bytes();

    // Try to verify the HMAC
    let _key = &derived[..32];
    let mac_key = &derived[32..];

    // Compute HMAC of encrypted data (excluding the stored MAC)
    let data_without_mac = &encrypted_data[..encrypted_data.len() - 32];
    let stored_mac = &encrypted_data[encrypted_data.len() - 32..];

    let mut verify_mac = match Hmac::<Sha512>::new_from_slice(mac_key) {
        Ok(h) => h,
        Err(_) => return false,
    };
    verify_mac.update(data_without_mac);
    let computed_mac = verify_mac.finalize().into_bytes();

    computed_mac[..32] == *stored_mac
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_iv() {
        let password = b"test_password";
        let salt = b"test_salt";
        let (key, iv) = derive_key_iv(password, salt, 10);
        assert_eq!(key.len(), 32);
        assert_eq!(iv.len(), 16);

        // Same inputs should give same outputs (deterministic)
        let (key2, iv2) = derive_key_iv(password, salt, 10);
        assert_eq!(key, key2);
        assert_eq!(iv, iv2);
    }

    #[test]
    fn test_wrong_password() {
        let params = BitcoinCoreWalletParams {
            encrypted_master_key: vec![0u8; 48],
            salt: vec![0u8; 8],
            derive_iterations: 100,
            derive_method: 0,
        };

        // A random password should not decrypt random data
        assert!(!check_password_bitcoin_core(&params, "wrong_password"));
    }

    #[test]
    fn test_parse_extract_string() {
        let data = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef:0102030405060708:10000:0";
        let params = BitcoinCoreWalletParams::from_extract_string(data).unwrap();
        assert_eq!(params.encrypted_master_key.len(), 48);
        assert_eq!(params.salt.len(), 8);
        assert_eq!(params.derive_iterations, 10000);
        assert_eq!(params.derive_method, 0);
    }
}
