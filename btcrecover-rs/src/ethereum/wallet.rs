use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::{Sha256, Sha512};

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Errors from Ethereum wallet operations
#[derive(Debug, thiserror::Error)]
pub enum EthWalletError {
    #[error("Invalid wallet data: {0}")]
    InvalidData(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("JSON parse error: {0}")]
    JsonError(String),
}

/// MetaMask vault encryption type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetaMaskType {
    /// Desktop MetaMask (PBKDF2-SHA256 + AES-256-GCM)
    Desktop,
    /// Mobile MetaMask (PBKDF2-SHA512 + AES-256-CBC)
    Mobile,
}

/// MetaMask vault parameters
#[derive(Debug, Clone)]
pub struct MetaMaskParams {
    /// Type of MetaMask wallet
    pub wallet_type: MetaMaskType,
    /// Encrypted vault data
    pub data: Vec<u8>,
    /// Initialization vector
    pub iv: Vec<u8>,
    /// Salt for PBKDF2
    pub salt: Vec<u8>,
    /// Number of PBKDF2 iterations
    pub iterations: u32,
    /// GCM authentication tag (Desktop only)
    pub auth_tag: Option<Vec<u8>>,
}

impl MetaMaskParams {
    /// Parse MetaMask vault from JSON string
    pub fn from_json(json_str: &str) -> Result<Self, EthWalletError> {
        let v: serde_json::Value =
            serde_json::from_str(json_str).map_err(|e| EthWalletError::JsonError(e.to_string()))?;

        let data_str = v["data"]
            .as_str()
            .ok_or_else(|| EthWalletError::InvalidData("Missing 'data' field".to_string()))?;
        let iv_str = v["iv"]
            .as_str()
            .ok_or_else(|| EthWalletError::InvalidData("Missing 'iv' field".to_string()))?;
        let salt_str = v["salt"]
            .as_str()
            .ok_or_else(|| EthWalletError::InvalidData("Missing 'salt' field".to_string()))?;

        let data = base64_decode(data_str)
            .map_err(|e| EthWalletError::InvalidData(format!("Invalid data base64: {}", e)))?;
        let iv = hex::decode(iv_str)
            .or_else(|_| base64_decode(iv_str))
            .map_err(|e| EthWalletError::InvalidData(format!("Invalid IV: {}", e)))?;
        let salt = base64_decode(salt_str)
            .map_err(|e| EthWalletError::InvalidData(format!("Invalid salt base64: {}", e)))?;

        // Determine type based on presence of 'lib' field or data structure
        let wallet_type = if v.get("lib").is_some() {
            MetaMaskType::Mobile
        } else {
            MetaMaskType::Desktop
        };

        let iterations = v["iterations"]
            .as_u64()
            .unwrap_or(if wallet_type == MetaMaskType::Desktop {
                10000
            } else {
                5000
            }) as u32;

        // Note: For AES-GCM (desktop), the authentication tag is typically appended
        // to the ciphertext. The aes-gcm crate expects the tag to be part of the
        // ciphertext buffer and handles separation internally during decryption.
        let auth_tag = None;

        Ok(Self {
            wallet_type,
            data,
            iv,
            salt,
            iterations,
            auth_tag,
        })
    }
}

/// Simple base64 decoder (standard alphabet)
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    // Use a basic base64 implementation
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let input = input.trim();
    let input_bytes = input.as_bytes();
    let mut output = Vec::with_capacity(input.len() * 3 / 4);

    let mut buf: u32 = 0;
    let mut buf_len: u32 = 0;

    for &byte in input_bytes {
        if byte == b'=' {
            break;
        }
        let val = match TABLE.iter().position(|&b| b == byte) {
            Some(v) => v as u32,
            None => {
                if byte == b'\n' || byte == b'\r' || byte == b' ' {
                    continue;
                }
                return Err(format!("Invalid base64 character: {}", byte as char));
            }
        };
        buf = (buf << 6) | val;
        buf_len += 6;
        if buf_len >= 8 {
            buf_len -= 8;
            output.push((buf >> buf_len) as u8);
            buf &= (1 << buf_len) - 1;
        }
    }

    Ok(output)
}

/// Check a password against MetaMask desktop vault
/// Uses PBKDF2-HMAC-SHA256 + AES-256-GCM
pub fn check_password_metamask_desktop(params: &MetaMaskParams, password: &str) -> bool {
    // Derive key using PBKDF2-HMAC-SHA256
    let mut key = [0u8; 32];
    if pbkdf2::<Hmac<Sha256>>(
        password.as_bytes(),
        &params.salt,
        params.iterations,
        &mut key,
    )
    .is_err()
    {
        return false;
    }

    // Decrypt using AES-256-GCM
    let cipher = match Aes256Gcm::new_from_slice(&key) {
        Ok(c) => c,
        Err(_) => return false,
    };

    if params.iv.len() < 12 {
        return false;
    }
    let nonce = Nonce::from_slice(&params.iv[..12]);

    match cipher.decrypt(nonce, params.data.as_ref()) {
        Ok(plaintext) => {
            // Check if decrypted data looks like valid JSON
            if let Ok(text) = std::str::from_utf8(&plaintext) {
                text.contains("mnemonic") || text.contains("type") || text.contains("version")
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

/// Check a password against MetaMask mobile vault
/// Uses PBKDF2-HMAC-SHA512 + AES-256-CBC
pub fn check_password_metamask_mobile(params: &MetaMaskParams, password: &str) -> bool {
    // Derive key using PBKDF2-HMAC-SHA512
    let mut derived = [0u8; 64];
    if pbkdf2::<Hmac<Sha512>>(
        password.as_bytes(),
        &params.salt,
        params.iterations,
        &mut derived,
    )
    .is_err()
    {
        return false;
    }

    let key = &derived[..32];

    if params.iv.len() < 16 || params.data.len() < 16 {
        return false;
    }

    // Decrypt using AES-256-CBC
    let mut buffer = params.data.clone();
    let result = Aes256CbcDec::new(key.into(), params.iv[..16].into())
        .decrypt_padded_mut::<NoPadding>(&mut buffer);

    match result {
        Ok(decrypted) => {
            // Check if decrypted data looks like valid JSON
            if let Ok(text) = std::str::from_utf8(decrypted) {
                text.contains("mnemonic") || text.contains("type") || text.contains("version")
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

/// Check a password against a MetaMask vault (auto-detect type)
pub fn check_password_metamask(params: &MetaMaskParams, password: &str) -> bool {
    match params.wallet_type {
        MetaMaskType::Desktop => check_password_metamask_desktop(params, password),
        MetaMaskType::Mobile => check_password_metamask_mobile(params, password),
    }
}

/// Ethereum keystore (UTC/JSON) file parameters
/// V3 format with either scrypt or pbkdf2 KDF
#[derive(Debug, Clone)]
pub struct EthKeystoreParams {
    /// Encrypted private key (ciphertext)
    pub ciphertext: Vec<u8>,
    /// AES-128-CTR IV
    pub iv: Vec<u8>,
    /// MAC for verification
    pub mac: Vec<u8>,
    /// KDF type
    pub kdf: KeyDerivationFunction,
}

/// Key derivation function for Ethereum keystores
#[derive(Debug, Clone)]
pub enum KeyDerivationFunction {
    Scrypt {
        salt: Vec<u8>,
        n: u32,
        r: u32,
        p: u32,
        dklen: u32,
    },
    Pbkdf2 {
        salt: Vec<u8>,
        c: u32,
        dklen: u32,
    },
}

/// Verify an Ethereum keystore password by checking the MAC
/// The MAC = Keccak-256(derived_key[16..32] || ciphertext)
pub fn check_password_eth_keystore(params: &EthKeystoreParams, password: &str) -> bool {
    let derived_key = match &params.kdf {
        KeyDerivationFunction::Pbkdf2 { salt, c, dklen } => {
            let mut dk = vec![0u8; *dklen as usize];
            if pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, *c, &mut dk).is_err() {
                return false;
            }
            dk
        }
        KeyDerivationFunction::Scrypt { .. } => {
            // Scrypt would require an additional dependency
            // For now, return false for scrypt keystores
            return false;
        }
    };

    if derived_key.len() < 32 {
        return false;
    }

    // MAC = Keccak-256(derived_key[16..32] || ciphertext)
    use sha3::{Digest, Keccak256};
    let mut hasher = Keccak256::new();
    hasher.update(&derived_key[16..32]);
    hasher.update(&params.ciphertext);
    let computed_mac = hasher.finalize();

    computed_mac.as_slice() == params.mac.as_slice()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_decode() {
        let encoded = "SGVsbG8gV29ybGQ=";
        let decoded = base64_decode(encoded).unwrap();
        assert_eq!(decoded, b"Hello World");
    }

    #[test]
    fn test_metamask_wrong_password() {
        let params = MetaMaskParams {
            wallet_type: MetaMaskType::Desktop,
            data: vec![0u8; 64],
            iv: vec![0u8; 16],
            salt: vec![0u8; 32],
            iterations: 10,
            auth_tag: Some(vec![0u8; 16]),
        };

        assert!(!check_password_metamask(&params, "wrong_password"));
    }

    #[test]
    fn test_eth_keystore_pbkdf2_wrong_password() {
        let params = EthKeystoreParams {
            ciphertext: vec![0u8; 32],
            iv: vec![0u8; 16],
            mac: vec![0u8; 32],
            kdf: KeyDerivationFunction::Pbkdf2 {
                salt: vec![0u8; 32],
                c: 100,
                dklen: 32,
            },
        };

        assert!(!check_password_eth_keystore(&params, "wrong_password"));
    }
}
