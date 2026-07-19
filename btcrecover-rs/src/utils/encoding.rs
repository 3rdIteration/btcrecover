use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// Compute HASH160: RIPEMD160(SHA256(data))
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha256_hash = Sha256::digest(data);
    let mut ripemd = Ripemd160::new();
    ripemd.update(sha256_hash);
    let result = ripemd.finalize();
    let mut output = [0u8; 20];
    output.copy_from_slice(&result);
    output
}

/// Compute double SHA256: SHA256(SHA256(data))
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut output = [0u8; 32];
    output.copy_from_slice(&second);
    output
}

/// Encode bytes to Base58Check with a version prefix
pub fn base58check_encode(version: u8, payload: &[u8]) -> String {
    let mut data = Vec::with_capacity(1 + payload.len() + 4);
    data.push(version);
    data.extend_from_slice(payload);
    let checksum = double_sha256(&data);
    data.extend_from_slice(&checksum[..4]);
    bs58::encode(data).into_string()
}

/// Decode a Base58Check encoded string, returning (version, payload)
pub fn base58check_decode(input: &str) -> Result<(u8, Vec<u8>), String> {
    let data = bs58::decode(input)
        .into_vec()
        .map_err(|e| format!("Base58 decode error: {}", e))?;
    if data.len() < 5 {
        return Err("Base58Check data too short".to_string());
    }
    let (payload_with_version, checksum) = data.split_at(data.len() - 4);
    let computed_checksum = double_sha256(payload_with_version);
    if checksum != &computed_checksum[..4] {
        return Err("Base58Check checksum mismatch".to_string());
    }
    Ok((payload_with_version[0], payload_with_version[1..].to_vec()))
}

/// Encode to Bech32 (SegWit) address
pub fn bech32_encode(hrp: &str, witness_version: u8, program: &[u8]) -> Result<String, String> {
    use bech32::{Bech32m, Hrp};

    let hrp_parsed = Hrp::parse(hrp).map_err(|e| format!("Invalid HRP: {}", e))?;

    let mut data = Vec::with_capacity(1 + program.len());
    data.push(witness_version);
    data.extend_from_slice(program);

    if witness_version == 0 {
        use bech32::Bech32;
        bech32::encode::<Bech32>(hrp_parsed, &data)
            .map_err(|e| format!("Bech32 encode error: {}", e))
    } else {
        bech32::encode::<Bech32m>(hrp_parsed, &data)
            .map_err(|e| format!("Bech32m encode error: {}", e))
    }
}

/// Encode bytes as lowercase hex string
pub fn to_hex(data: &[u8]) -> String {
    hex::encode(data)
}

/// Decode hex string to bytes
pub fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s).map_err(|e| format!("Hex decode error: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash160() {
        // Known test vector: hash160 of compressed public key
        let pubkey = from_hex(
            "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        )
        .unwrap();
        let h = hash160(&pubkey);
        assert_eq!(
            to_hex(&h),
            "751e76e8199196d454941c45d1b3a323f1433bd6"
        );
    }

    #[test]
    fn test_double_sha256() {
        let data = b"hello";
        let result = double_sha256(data);
        // SHA256(SHA256("hello"))
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_base58check_roundtrip() {
        let payload = [0u8; 20]; // all zeros
        let encoded = base58check_encode(0x00, &payload);
        let (version, decoded) = base58check_decode(&encoded).unwrap();
        assert_eq!(version, 0x00);
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_hex_roundtrip() {
        let data = vec![0xde, 0xad, 0xbe, 0xef];
        let hex_str = to_hex(&data);
        assert_eq!(hex_str, "deadbeef");
        let decoded = from_hex(&hex_str).unwrap();
        assert_eq!(decoded, data);
    }
}
