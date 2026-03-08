use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::cipher::{CIPHER_PREFIX_SIZE, CipherVersion, NONCE_SIZE, TAG_SIZE};
use super::keys::{MasterKey, RecoveryKey};

/// Size of a wrapped key blob: prefix + nonce + ciphertext(32) + tag = 73 bytes.
pub const WRAPPED_KEY_SIZE: usize = CIPHER_PREFIX_SIZE + NONCE_SIZE + 32 + TAG_SIZE;

/// Legacy wrapped key size (without cipher prefix): 72 bytes.
const LEGACY_WRAPPED_KEY_SIZE: usize = NONCE_SIZE + 32 + TAG_SIZE;

/// Wrap (encrypt) a 32-byte vault key under a 32-byte wrapping key.
/// Returns a 73-byte blob: cipher_version (1) || nonce (24) || ciphertext+tag (48).
pub fn wrap_vault_key(vault_key: &MasterKey, wrapping_key: &[u8; 32]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(wrapping_key.into());

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, vault_key.as_bytes().as_ref())
        .expect("XChaCha20-Poly1305 encryption of 32 bytes cannot fail");

    let mut output = Vec::with_capacity(WRAPPED_KEY_SIZE);
    output.push(CipherVersion::XChaCha20Poly1305 as u8);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    output
}

/// Unwrap (decrypt) a wrapped key blob using a 32-byte wrapping key.
/// Accepts both new format (73 bytes with prefix) and legacy format (72 bytes without).
/// Returns the original 32-byte vault key, or an error if the wrapping key is wrong.
pub fn unwrap_vault_key(wrapped: &[u8], wrapping_key: &[u8; 32]) -> Result<MasterKey, &'static str> {
    let payload = if wrapped.len() == WRAPPED_KEY_SIZE && wrapped[0] == CipherVersion::XChaCha20Poly1305 as u8 {
        // New format with cipher prefix
        &wrapped[CIPHER_PREFIX_SIZE..]
    } else if wrapped.len() == LEGACY_WRAPPED_KEY_SIZE {
        // Legacy format without prefix
        wrapped
    } else {
        return Err("invalid wrapped key size");
    };

    let (nonce_bytes, ciphertext) = payload.split_at(NONCE_SIZE);
    let nonce = XNonce::from_slice(nonce_bytes);
    let cipher = XChaCha20Poly1305::new(wrapping_key.into());

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "unwrap failed: wrong key or corrupted data")?;

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&plaintext);
    Ok(MasterKey::from_bytes(key_bytes))
}

/// Generate a new random 32-byte recovery key.
pub fn generate_recovery_key() -> RecoveryKey {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    RecoveryKey::from_bytes(bytes)
}

/// Format a recovery key as a human-readable string of 8 groups of 4 hex chars,
/// e.g. "A1B2-C3D4-E5F6-7890-1234-5678-9ABC-DEF0".
pub fn format_recovery_key(key: &RecoveryKey) -> String {
    let hex = hex::encode_upper(key.as_bytes());
    let groups: Vec<&str> = (0..8).map(|i| &hex[i * 8..(i + 1) * 8]).collect();
    groups.join("-")
}

/// Parse a recovery key from the human-readable format.
/// Accepts with or without dashes, case-insensitive.
pub fn parse_recovery_key(input: &str) -> Result<RecoveryKey, &'static str> {
    let clean: String = input.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() != 64 {
        return Err("recovery key must be 64 hex characters");
    }
    let bytes = hex::decode(&clean).map_err(|_| "invalid hex in recovery key")?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(RecoveryKey::from_bytes(arr))
}

/// Compute SHA-256 of the recovery key for verification (stored in meta).
pub fn recovery_verification_hash(key: &RecoveryKey) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hasher.finalize().to_vec()
}

/// Verify a recovery key against its stored verification hash.
/// Uses constant-time comparison to prevent timing side-channel attacks.
pub fn verify_recovery_key(key: &RecoveryKey, stored_hash: &[u8]) -> bool {
    let computed = recovery_verification_hash(key);
    computed.ct_eq(stored_hash).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_vault_key() -> MasterKey {
        MasterKey::from_bytes([42u8; 32])
    }

    fn test_wrapping_key() -> [u8; 32] {
        [7u8; 32]
    }

    #[test]
    fn test_wrap_unwrap_roundtrip() {
        let vault_key = test_vault_key();
        let wrapping_key = test_wrapping_key();

        let wrapped = wrap_vault_key(&vault_key, &wrapping_key);
        assert_eq!(wrapped.len(), WRAPPED_KEY_SIZE);

        let unwrapped = unwrap_vault_key(&wrapped, &wrapping_key).unwrap();
        assert_eq!(unwrapped.as_bytes(), vault_key.as_bytes());
    }

    #[test]
    fn test_unwrap_wrong_key_fails() {
        let vault_key = test_vault_key();
        let wrapping_key = test_wrapping_key();
        let wrong_key = [99u8; 32];

        let wrapped = wrap_vault_key(&vault_key, &wrapping_key);
        let result = unwrap_vault_key(&wrapped, &wrong_key);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("wrong key"));
    }

    #[test]
    fn test_unwrap_invalid_size() {
        let result = unwrap_vault_key(&[0u8; 10], &test_wrapping_key());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("size"));
    }

    #[test]
    fn test_unwrap_tampered_data() {
        let vault_key = test_vault_key();
        let wrapping_key = test_wrapping_key();

        let mut wrapped = wrap_vault_key(&vault_key, &wrapping_key);
        wrapped[WRAPPED_KEY_SIZE - 1] ^= 0xFF;
        assert!(unwrap_vault_key(&wrapped, &wrapping_key).is_err());
    }

    #[test]
    fn test_wrap_produces_different_blobs() {
        let vault_key = test_vault_key();
        let wrapping_key = test_wrapping_key();

        let w1 = wrap_vault_key(&vault_key, &wrapping_key);
        let w2 = wrap_vault_key(&vault_key, &wrapping_key);
        assert_ne!(w1, w2); // Different nonces

        // Both unwrap to the same key
        let u1 = unwrap_vault_key(&w1, &wrapping_key).unwrap();
        let u2 = unwrap_vault_key(&w2, &wrapping_key).unwrap();
        assert_eq!(u1.as_bytes(), u2.as_bytes());
    }

    #[test]
    fn test_generate_recovery_key() {
        let k1 = generate_recovery_key();
        let k2 = generate_recovery_key();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn test_format_parse_roundtrip() {
        let key = generate_recovery_key();
        let formatted = format_recovery_key(&key);

        // Should be 8 groups of 8 hex chars separated by dashes
        assert_eq!(formatted.len(), 64 + 7); // 64 hex chars + 7 dashes
        assert_eq!(formatted.matches('-').count(), 7);

        let parsed = parse_recovery_key(&formatted).unwrap();
        assert_eq!(parsed.as_bytes(), key.as_bytes());
    }

    #[test]
    fn test_parse_without_dashes() {
        let key = RecoveryKey::from_bytes([0xAB; 32]);
        let hex_str = hex::encode_upper(key.as_bytes());
        let parsed = parse_recovery_key(&hex_str).unwrap();
        assert_eq!(parsed.as_bytes(), key.as_bytes());
    }

    #[test]
    fn test_parse_case_insensitive() {
        let key = RecoveryKey::from_bytes([0xAB; 32]);
        let formatted = format_recovery_key(&key);
        let lower = formatted.to_lowercase();
        let parsed = parse_recovery_key(&lower).unwrap();
        assert_eq!(parsed.as_bytes(), key.as_bytes());
    }

    #[test]
    fn test_parse_invalid_length() {
        assert!(parse_recovery_key("ABCD").is_err());
        assert!(parse_recovery_key("").is_err());
    }

    #[test]
    fn test_parse_invalid_hex() {
        // 64 chars but invalid hex
        let bad = "G".repeat(64);
        assert!(parse_recovery_key(&bad).is_err());
    }

    #[test]
    fn test_recovery_verification_hash() {
        let key = RecoveryKey::from_bytes([42u8; 32]);
        let hash = recovery_verification_hash(&key);
        assert_eq!(hash.len(), 32);

        // Same key → same hash
        let hash2 = recovery_verification_hash(&key);
        assert_eq!(hash, hash2);

        // Different key → different hash
        let other = RecoveryKey::from_bytes([99u8; 32]);
        let hash3 = recovery_verification_hash(&other);
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_verify_recovery_key() {
        let key = RecoveryKey::from_bytes([42u8; 32]);
        let hash = recovery_verification_hash(&key);
        assert!(verify_recovery_key(&key, &hash));

        let wrong = RecoveryKey::from_bytes([99u8; 32]);
        assert!(!verify_recovery_key(&wrong, &hash));
    }

    #[test]
    fn test_wrap_with_recovery_key() {
        let vault_key = test_vault_key();
        let recovery = generate_recovery_key();

        let wrapped = wrap_vault_key(&vault_key, recovery.as_bytes());
        let unwrapped = unwrap_vault_key(&wrapped, recovery.as_bytes()).unwrap();
        assert_eq!(unwrapped.as_bytes(), vault_key.as_bytes());
    }

    #[test]
    fn test_verify_recovery_key_constant_time() {
        // Verify constant-time comparison works correctly
        let key = RecoveryKey::from_bytes([42u8; 32]);
        let hash = recovery_verification_hash(&key);

        // Correct key verifies
        assert!(verify_recovery_key(&key, &hash));

        // Wrong key fails
        let wrong = RecoveryKey::from_bytes([99u8; 32]);
        assert!(!verify_recovery_key(&wrong, &hash));

        // Truncated hash fails
        assert!(!verify_recovery_key(&key, &hash[..16]));

        // Empty hash fails
        assert!(!verify_recovery_key(&key, &[]));
    }

    #[test]
    fn test_wrap_unwrap_legacy_format_compat() {
        // Verify that legacy 72-byte wrapped keys (without cipher prefix) still unwrap
        let vault_key = test_vault_key();
        let wrapping_key = test_wrapping_key();

        // Manually create a legacy wrapped key (no prefix)
        let cipher = XChaCha20Poly1305::new((&wrapping_key).into());
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, vault_key.as_bytes().as_ref()).unwrap();
        let mut legacy = Vec::new();
        legacy.extend_from_slice(&nonce_bytes);
        legacy.extend_from_slice(&ciphertext);
        assert_eq!(legacy.len(), 72); // Legacy size

        let unwrapped = unwrap_vault_key(&legacy, &wrapping_key).unwrap();
        assert_eq!(unwrapped.as_bytes(), vault_key.as_bytes());
    }

    #[test]
    fn test_cipher_prefix_in_wrapped_key() {
        let vault_key = test_vault_key();
        let wrapping_key = test_wrapping_key();

        let wrapped = wrap_vault_key(&vault_key, &wrapping_key);
        assert_eq!(wrapped.len(), WRAPPED_KEY_SIZE); // 73 bytes (1 prefix + 72)
        assert_eq!(wrapped[0], 0x01); // XChaCha20-Poly1305 prefix
    }
}
