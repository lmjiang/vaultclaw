use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use thiserror::Error;

use super::keys::{EntryKey, MasterKey};

/// Nonce size for XChaCha20-Poly1305: 24 bytes.
pub const NONCE_SIZE: usize = 24;
/// Authentication tag size: 16 bytes (appended to ciphertext by the AEAD).
pub const TAG_SIZE: usize = 16;
/// Size of the cipher version prefix: 1 byte.
pub const CIPHER_PREFIX_SIZE: usize = 1;

/// Cipher version identifiers for crypto agility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CipherVersion {
    /// XChaCha20-Poly1305 (current default).
    XChaCha20Poly1305 = 0x01,
}

impl CipherVersion {
    /// Parse a cipher version from its byte identifier.
    pub fn from_byte(byte: u8) -> Result<Self, CipherError> {
        match byte {
            0x01 => Ok(CipherVersion::XChaCha20Poly1305),
            _ => Err(CipherError::UnsupportedCipher(byte)),
        }
    }
}

#[derive(Debug, Error)]
pub enum CipherError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed: invalid key, corrupted data, or tampered ciphertext")]
    DecryptionFailed,
    #[error("Invalid nonce length: expected {NONCE_SIZE}, got {0}")]
    InvalidNonce(usize),
    #[error("Unsupported cipher version: 0x{0:02X}")]
    UnsupportedCipher(u8),
}

/// Encrypt plaintext using XChaCha20-Poly1305.
/// Returns: cipher_version (1 byte) || nonce (24 bytes) || ciphertext+tag.
pub fn encrypt(key: &MasterKey, plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CipherError::EncryptionFailed)?;

    let mut output = Vec::with_capacity(CIPHER_PREFIX_SIZE + NONCE_SIZE + ciphertext.len());
    output.push(CipherVersion::XChaCha20Poly1305 as u8);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt data produced by `encrypt`.
/// Input format: cipher_version (1 byte) || nonce (24 bytes) || ciphertext+tag.
/// Also accepts legacy format without prefix for backward compatibility.
pub fn decrypt(key: &MasterKey, data: &[u8]) -> Result<Vec<u8>, CipherError> {
    let payload = strip_cipher_prefix(data)?;

    if payload.len() < NONCE_SIZE + TAG_SIZE {
        return Err(CipherError::DecryptionFailed);
    }

    let (nonce_bytes, ciphertext) = payload.split_at(NONCE_SIZE);
    let nonce = XNonce::from_slice(nonce_bytes);
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CipherError::DecryptionFailed)
}

/// Encrypt plaintext using XChaCha20-Poly1305 with a per-entry key.
/// Returns: cipher_version (1 byte) || nonce (24 bytes) || ciphertext+tag.
pub fn encrypt_entry(key: &EntryKey, plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CipherError::EncryptionFailed)?;

    let mut output = Vec::with_capacity(CIPHER_PREFIX_SIZE + NONCE_SIZE + ciphertext.len());
    output.push(CipherVersion::XChaCha20Poly1305 as u8);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt data produced by `encrypt_entry`.
/// Input format: cipher_version (1 byte) || nonce (24 bytes) || ciphertext+tag.
/// Also accepts legacy format without prefix for backward compatibility.
pub fn decrypt_entry(key: &EntryKey, data: &[u8]) -> Result<Vec<u8>, CipherError> {
    let payload = strip_cipher_prefix(data)?;

    if payload.len() < NONCE_SIZE + TAG_SIZE {
        return Err(CipherError::DecryptionFailed);
    }

    let (nonce_bytes, ciphertext) = payload.split_at(NONCE_SIZE);
    let nonce = XNonce::from_slice(nonce_bytes);
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CipherError::DecryptionFailed)
}

/// Strip the cipher version prefix from encrypted data.
/// If the first byte is a known cipher version, validates and strips it.
/// If not, treats the data as legacy (pre-prefix) format for backward compatibility.
fn strip_cipher_prefix(data: &[u8]) -> Result<&[u8], CipherError> {
    if data.is_empty() {
        return Err(CipherError::DecryptionFailed);
    }

    match data[0] {
        0x01 => {
            // Known cipher version prefix — strip it
            Ok(&data[CIPHER_PREFIX_SIZE..])
        }
        _ => {
            // Legacy data without prefix — pass through as-is
            Ok(data)
        }
    }
}

/// Encrypt with a specific nonce (for deterministic testing only).
/// Returns: cipher_version (1 byte) || nonce (24 bytes) || ciphertext+tag.
#[cfg(test)]
pub fn encrypt_with_nonce(
    key: &MasterKey,
    plaintext: &[u8],
    nonce_bytes: &[u8; NONCE_SIZE],
) -> Result<Vec<u8>, CipherError> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = XNonce::from_slice(nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CipherError::EncryptionFailed)?;

    let mut output = Vec::with_capacity(CIPHER_PREFIX_SIZE + NONCE_SIZE + ciphertext.len());
    output.push(CipherVersion::XChaCha20Poly1305 as u8);
    output.extend_from_slice(nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::MasterKey;

    fn test_key() -> MasterKey {
        MasterKey::from_bytes([42u8; 32])
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = test_key();
        let plaintext = b"Hello, VaultClaw!";

        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_produces_different_ciphertext() {
        let key = test_key();
        let plaintext = b"same data";

        let enc1 = encrypt(&key, plaintext).unwrap();
        let enc2 = encrypt(&key, plaintext).unwrap();

        // Different nonces → different ciphertexts
        assert_ne!(enc1, enc2);

        // But both decrypt to the same plaintext
        assert_eq!(decrypt(&key, &enc1).unwrap(), plaintext);
        assert_eq!(decrypt(&key, &enc2).unwrap(), plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key1 = MasterKey::from_bytes([1u8; 32]);
        let key2 = MasterKey::from_bytes([2u8; 32]);

        let encrypted = encrypt(&key1, b"secret").unwrap();
        let result = decrypt(&key2, &encrypted);

        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_tampered_data_fails() {
        let key = test_key();
        let mut encrypted = encrypt(&key, b"important data").unwrap();

        // Tamper with a byte in the ciphertext portion
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;

        assert!(decrypt(&key, &encrypted).is_err());
    }

    #[test]
    fn test_decrypt_truncated_data_fails() {
        let key = test_key();
        assert!(decrypt(&key, &[0u8; 10]).is_err());
        assert!(decrypt(&key, &[]).is_err());
    }

    #[test]
    fn test_encrypt_empty_plaintext() {
        let key = test_key();
        let encrypted = encrypt(&key, b"").unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, b"");
    }

    #[test]
    fn test_encrypt_large_plaintext() {
        let key = test_key();
        let plaintext = vec![0xABu8; 1_000_000]; // 1MB

        let encrypted = encrypt(&key, &plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ciphertext_format() {
        let key = test_key();
        let plaintext = b"test";

        let encrypted = encrypt(&key, plaintext).unwrap();

        // Output = 1 (prefix) + 24 (nonce) + 4 (plaintext) + 16 (tag) = 45 bytes
        assert_eq!(encrypted.len(), CIPHER_PREFIX_SIZE + NONCE_SIZE + plaintext.len() + TAG_SIZE);
        // First byte is the cipher version
        assert_eq!(encrypted[0], CipherVersion::XChaCha20Poly1305 as u8);
    }

    #[test]
    fn test_deterministic_with_fixed_nonce() {
        let key = test_key();
        let nonce = [0u8; NONCE_SIZE];
        let plaintext = b"deterministic test";

        let enc1 = encrypt_with_nonce(&key, plaintext, &nonce).unwrap();
        let enc2 = encrypt_with_nonce(&key, plaintext, &nonce).unwrap();

        assert_eq!(enc1, enc2);
        assert_eq!(decrypt(&key, &enc1).unwrap(), plaintext);
    }

    #[test]
    fn test_decrypt_tampered_nonce_fails() {
        let key = test_key();
        let mut encrypted = encrypt(&key, b"nonce test").unwrap();

        // Tamper with the nonce
        encrypted[0] ^= 0xFF;

        assert!(decrypt(&key, &encrypted).is_err());
    }

    #[test]
    fn test_entry_encrypt_decrypt_roundtrip() {
        let key = crate::crypto::keys::EntryKey::from_bytes([7u8; 32]);
        let plaintext = b"entry secret data";
        let encrypted = encrypt_entry(&key, plaintext).unwrap();
        let decrypted = decrypt_entry(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_entry_decrypt_wrong_key_fails() {
        let k1 = crate::crypto::keys::EntryKey::from_bytes([1u8; 32]);
        let k2 = crate::crypto::keys::EntryKey::from_bytes([2u8; 32]);
        let encrypted = encrypt_entry(&k1, b"secret").unwrap();
        assert!(decrypt_entry(&k2, &encrypted).is_err());
    }

    #[test]
    fn test_entry_decrypt_truncated_fails() {
        let key = crate::crypto::keys::EntryKey::from_bytes([7u8; 32]);
        assert!(decrypt_entry(&key, &[0u8; 10]).is_err());
    }

    #[test]
    fn test_entry_encrypt_empty_plaintext() {
        let key = crate::crypto::keys::EntryKey::from_bytes([7u8; 32]);
        let encrypted = encrypt_entry(&key, b"").unwrap();
        let decrypted = decrypt_entry(&key, &encrypted).unwrap();
        assert_eq!(decrypted, b"");
    }

    #[test]
    fn test_cipher_version_prefix_present() {
        let key = test_key();
        let encrypted = encrypt(&key, b"test").unwrap();
        assert_eq!(encrypted[0], 0x01); // XChaCha20-Poly1305
    }

    #[test]
    fn test_cipher_version_from_byte() {
        assert_eq!(CipherVersion::from_byte(0x01).unwrap(), CipherVersion::XChaCha20Poly1305);
        assert!(CipherVersion::from_byte(0x00).is_err());
        assert!(CipherVersion::from_byte(0xFF).is_err());
    }

    #[test]
    fn test_entry_cipher_version_prefix() {
        let key = crate::crypto::keys::EntryKey::from_bytes([7u8; 32]);
        let encrypted = encrypt_entry(&key, b"secret").unwrap();
        assert_eq!(encrypted[0], 0x01); // XChaCha20-Poly1305
    }

    #[test]
    fn test_decrypt_legacy_format_without_prefix() {
        // Simulate legacy data: nonce || ciphertext+tag (no prefix byte)
        let key = test_key();
        let cipher = XChaCha20Poly1305::new(key.as_bytes().into());

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let plaintext = b"legacy data";
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

        // Build legacy format (no prefix)
        let mut legacy = Vec::new();
        legacy.extend_from_slice(&nonce_bytes);
        legacy.extend_from_slice(&ciphertext);

        // Should still decrypt successfully via backward compatibility
        let decrypted = decrypt(&key, &legacy).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_entry_legacy_format_without_prefix() {
        let key = crate::crypto::keys::EntryKey::from_bytes([7u8; 32]);
        let cipher = XChaCha20Poly1305::new(key.as_bytes().into());

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let plaintext = b"legacy entry";
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

        let mut legacy = Vec::new();
        legacy.extend_from_slice(&nonce_bytes);
        legacy.extend_from_slice(&ciphertext);

        let decrypted = decrypt_entry(&key, &legacy).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_unsupported_cipher_version_error() {
        let err = CipherVersion::from_byte(0x02);
        assert!(matches!(err, Err(CipherError::UnsupportedCipher(0x02))));
    }
}
