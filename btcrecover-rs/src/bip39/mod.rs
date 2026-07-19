pub mod wordlist;

use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;

use wordlist::ENGLISH_WORDLIST;

/// Number of PBKDF2 iterations for BIP39 seed derivation
const BIP39_PBKDF2_ROUNDS: u32 = 2048;

/// Errors that can occur during BIP39 operations
#[derive(Debug, thiserror::Error)]
pub enum Bip39Error {
    #[error("Invalid word count: {0}. Must be 12, 15, 18, 21, or 24")]
    InvalidWordCount(usize),
    #[error("Unknown word: {0}")]
    UnknownWord(String),
    #[error("Invalid checksum")]
    InvalidChecksum,
    #[error("Invalid entropy length: {0}")]
    InvalidEntropyLength(usize),
}

/// Build a lookup map from word -> index for efficient lookups
fn build_word_map() -> HashMap<&'static str, u16> {
    let mut map = HashMap::with_capacity(2048);
    for (i, word) in ENGLISH_WORDLIST.iter().enumerate() {
        map.insert(*word, i as u16);
    }
    map
}

/// Convert a mnemonic phrase to word indices
pub fn mnemonic_to_indices(mnemonic: &str) -> Result<Vec<u16>, Bip39Error> {
    let word_map = build_word_map();
    let words: Vec<&str> = mnemonic.split_whitespace().collect();

    let valid_counts = [12, 15, 18, 21, 24];
    if !valid_counts.contains(&words.len()) {
        return Err(Bip39Error::InvalidWordCount(words.len()));
    }

    let mut indices = Vec::with_capacity(words.len());
    for word in &words {
        match word_map.get(word) {
            Some(&idx) => indices.push(idx),
            None => return Err(Bip39Error::UnknownWord(word.to_string())),
        }
    }
    Ok(indices)
}

/// Verify the BIP39 checksum of a mnemonic
/// Each word encodes 11 bits. For a 12-word mnemonic:
/// - 128 bits of entropy + 4 bits of checksum = 132 bits
/// The checksum is the first (entropy_bits/32) bits of SHA256(entropy)
pub fn verify_checksum(mnemonic: &str) -> Result<bool, Bip39Error> {
    let indices = mnemonic_to_indices(mnemonic)?;
    verify_checksum_from_indices(&indices)
}

/// Verify BIP39 checksum from word indices
pub fn verify_checksum_from_indices(indices: &[u16]) -> Result<bool, Bip39Error> {
    let num_words = indices.len();
    let total_bits = num_words * 11;
    let checksum_bits = num_words / 3; // CS = ENT/32, ENT = num_words*11 - CS
    let entropy_bits = total_bits - checksum_bits;

    // Convert indices to a bit string
    let mut bits = Vec::with_capacity(total_bits);
    for &idx in indices {
        for j in (0..11).rev() {
            bits.push((idx >> j) & 1);
        }
    }

    // Extract entropy bytes
    let entropy_bytes = entropy_bits / 8;
    let mut entropy = vec![0u8; entropy_bytes];
    for i in 0..entropy_bytes {
        let mut byte = 0u8;
        for j in 0..8 {
            byte = (byte << 1) | (bits[i * 8 + j] as u8);
        }
        entropy[i] = byte;
    }

    // Compute checksum
    let hash = Sha256::digest(&entropy);
    let mut expected_checksum_bits = Vec::with_capacity(checksum_bits);
    for i in 0..checksum_bits {
        expected_checksum_bits.push(((hash[i / 8] >> (7 - (i % 8))) & 1) as u16);
    }

    // Compare checksum bits
    let actual_checksum = &bits[entropy_bits..];
    Ok(actual_checksum == expected_checksum_bits.as_slice())
}

/// Derive a BIP39 seed from a mnemonic and optional passphrase
/// Uses PBKDF2-HMAC-SHA512 with 2048 iterations
/// Salt: "mnemonic" + passphrase
pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
    let mnemonic_bytes = mnemonic.as_bytes();
    let salt = format!("mnemonic{}", passphrase);
    let salt_bytes = salt.as_bytes();

    let mut seed = [0u8; 64];
    pbkdf2::<Hmac<Sha512>>(mnemonic_bytes, salt_bytes, BIP39_PBKDF2_ROUNDS, &mut seed)
        .expect("HMAC can be initialized with any key length");
    seed
}

/// Generate entropy and convert to mnemonic
pub fn entropy_to_mnemonic(entropy: &[u8]) -> Result<String, Bip39Error> {
    let ent_bits = entropy.len() * 8;
    let valid_lengths = [128, 160, 192, 224, 256];
    if !valid_lengths.contains(&ent_bits) {
        return Err(Bip39Error::InvalidEntropyLength(entropy.len()));
    }

    let checksum_bits = ent_bits / 32;
    let hash = Sha256::digest(entropy);

    // Convert entropy + checksum to bits
    let total_bits = ent_bits + checksum_bits;
    let mut bits = Vec::with_capacity(total_bits);

    for byte in entropy {
        for j in (0..8).rev() {
            bits.push((byte >> j) & 1);
        }
    }
    for i in 0..checksum_bits {
        bits.push((hash[i / 8] >> (7 - (i % 8))) & 1);
    }

    // Convert bits to word indices (11 bits each)
    let num_words = total_bits / 11;
    let mut words = Vec::with_capacity(num_words);
    for i in 0..num_words {
        let mut idx = 0u16;
        for j in 0..11 {
            idx = (idx << 1) | (bits[i * 11 + j] as u16);
        }
        words.push(ENGLISH_WORDLIST[idx as usize]);
    }

    Ok(words.join(" "))
}

/// Get the word at a given BIP39 index
pub fn word_at_index(index: u16) -> Option<&'static str> {
    ENGLISH_WORDLIST.get(index as usize).copied()
}

/// Get the index of a BIP39 word
pub fn index_of_word(word: &str) -> Option<u16> {
    ENGLISH_WORDLIST
        .iter()
        .position(|&w| w == word)
        .map(|i| i as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wordlist_length() {
        assert_eq!(ENGLISH_WORDLIST.len(), 2048);
    }

    #[test]
    fn test_first_last_words() {
        assert_eq!(ENGLISH_WORDLIST[0], "abandon");
        assert_eq!(ENGLISH_WORDLIST[2047], "zoo");
    }

    #[test]
    fn test_word_lookup() {
        assert_eq!(index_of_word("abandon"), Some(0));
        assert_eq!(index_of_word("zoo"), Some(2047));
        assert_eq!(index_of_word("notaword"), None);
    }

    #[test]
    fn test_mnemonic_to_indices() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let indices = mnemonic_to_indices(mnemonic).unwrap();
        assert_eq!(indices.len(), 12);
        assert_eq!(indices[0], 0);
        assert_eq!(indices[11], 3); // "about" is index 3
    }

    #[test]
    fn test_verify_checksum_valid() {
        // Standard BIP39 test vector: all-zero entropy
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert!(verify_checksum(mnemonic).unwrap());
    }

    #[test]
    fn test_verify_checksum_invalid() {
        // Change last word to make checksum invalid
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(!verify_checksum(mnemonic).unwrap());
    }

    #[test]
    fn test_mnemonic_to_seed() {
        // BIP39 test vector
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(mnemonic, "");
        let seed_hex = hex::encode(seed);
        // Known BIP39 test vector result
        assert_eq!(
            seed_hex,
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        );
    }

    #[test]
    fn test_mnemonic_to_seed_with_passphrase() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(mnemonic, "TREZOR");
        let seed_hex = hex::encode(seed);
        assert_eq!(
            seed_hex,
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
    }

    #[test]
    fn test_entropy_to_mnemonic() {
        // All-zero 128-bit entropy should give the known test vector
        let entropy = [0u8; 16];
        let mnemonic = entropy_to_mnemonic(&entropy).unwrap();
        assert_eq!(
            mnemonic,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
    }

    #[test]
    fn test_24_word_mnemonic() {
        // 256-bit entropy (all zeros)
        let entropy = [0u8; 32];
        let mnemonic = entropy_to_mnemonic(&entropy).unwrap();
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 24);
        assert!(verify_checksum(&mnemonic).unwrap());
    }

    #[test]
    fn test_invalid_word_count() {
        let mnemonic = "abandon abandon abandon";
        assert!(matches!(
            mnemonic_to_indices(mnemonic),
            Err(Bip39Error::InvalidWordCount(3))
        ));
    }

    #[test]
    fn test_unknown_word() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword";
        assert!(matches!(
            mnemonic_to_indices(mnemonic),
            Err(Bip39Error::UnknownWord(_))
        ));
    }
}
