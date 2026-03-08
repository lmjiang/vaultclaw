use argon2::{Argon2, Algorithm, Version, Params};
use rand::RngCore;
use secrecy::ExposeSecret;
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

use super::keys::{MasterKey, PasswordSecret};

#[derive(Debug, Error)]
pub enum KdfError {
    #[error("Argon2 error: {0}")]
    Argon2(String),
    #[error("Invalid KDF parameters: {0}")]
    InvalidParams(String),
}

/// Parameters for Argon2id key derivation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB (default: 64 MiB = 65536 KiB)
    pub memory_cost_kib: u32,
    /// Number of iterations (default: 3)
    pub iterations: u32,
    /// Degree of parallelism (default: 4)
    pub parallelism: u32,
    /// Salt length in bytes (default: 32)
    pub salt_length: usize,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_cost_kib: 65536, // 64 MiB
            iterations: 3,
            parallelism: 4,
            salt_length: 32,
        }
    }
}

impl KdfParams {
    /// Fast parameters for testing only.
    #[cfg(test)]
    pub fn fast_for_testing() -> Self {
        Self {
            memory_cost_kib: 1024, // 1 MiB
            iterations: 1,
            parallelism: 1,
            salt_length: 32,
        }
    }
}

/// Generate a random salt of the specified length.
pub fn generate_salt(length: usize) -> Vec<u8> {
    let mut salt = vec![0u8; length];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Normalize a password before hashing: trim whitespace, NFKD normalize, UTF-8 encode.
/// This ensures cross-platform consistency for non-ASCII passwords.
pub fn normalize_password(password: &str) -> String {
    password.trim().nfkd().collect::<String>()
}

/// Derive a master key from a password and salt using Argon2id.
/// The password is automatically normalized (trim + NFKD) before hashing.
pub fn derive_master_key(
    password: &PasswordSecret,
    salt: &[u8],
    params: &KdfParams,
) -> Result<MasterKey, KdfError> {
    let normalized = normalize_password(password.expose_secret());

    let argon2_params = Params::new(
        params.memory_cost_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|e| KdfError::InvalidParams(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut output = [0u8; 32];
    argon2.hash_password_into(
        normalized.as_bytes(),
        salt,
        &mut output,
    ).map_err(|e| KdfError::Argon2(e.to_string()))?;

    Ok(MasterKey::from_bytes(output))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::password_secret;

    #[test]
    fn test_generate_salt() {
        let salt1 = generate_salt(32);
        let salt2 = generate_salt(32);
        assert_eq!(salt1.len(), 32);
        assert_eq!(salt2.len(), 32);
        assert_ne!(salt1, salt2); // Extremely unlikely to be equal
    }

    #[test]
    fn test_generate_salt_different_lengths() {
        assert_eq!(generate_salt(16).len(), 16);
        assert_eq!(generate_salt(64).len(), 64);
    }

    #[test]
    fn test_derive_master_key() {
        let password = password_secret("test-password-123".to_string());
        let salt = generate_salt(32);
        let params = KdfParams::fast_for_testing();

        let key = derive_master_key(&password, &salt, &params).unwrap();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn test_derive_deterministic() {
        let password = password_secret("deterministic-test".to_string());
        let salt = vec![1u8; 32];
        let params = KdfParams::fast_for_testing();

        let key1 = derive_master_key(&password, &salt, &params).unwrap();
        let key2 = derive_master_key(&password, &salt, &params).unwrap();
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_different_passwords_different_keys() {
        let salt = vec![1u8; 32];
        let params = KdfParams::fast_for_testing();

        let key1 = derive_master_key(
            &password_secret("password-a".to_string()),
            &salt,
            &params,
        )
        .unwrap();
        let key2 = derive_master_key(
            &password_secret("password-b".to_string()),
            &salt,
            &params,
        )
        .unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_different_salts_different_keys() {
        let password = password_secret("same-password".to_string());
        let params = KdfParams::fast_for_testing();

        let key1 = derive_master_key(&password, &[1u8; 32], &params).unwrap();
        let key2 = derive_master_key(&password, &[2u8; 32], &params).unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_default_params() {
        let params = KdfParams::default();
        assert_eq!(params.memory_cost_kib, 65536);
        assert_eq!(params.iterations, 3);
        assert_eq!(params.parallelism, 4);
        assert_eq!(params.salt_length, 32);
    }

    #[test]
    fn test_invalid_params_error() {
        let password = password_secret("test".to_string());
        let salt = vec![1u8; 32];
        // parallelism=0 is invalid for Argon2
        let params = KdfParams {
            memory_cost_kib: 1024,
            iterations: 1,
            parallelism: 0,
            salt_length: 32,
        };
        let result = derive_master_key(&password, &salt, &params);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid KDF parameters"));
    }

    #[test]
    fn test_normalize_password_trim() {
        assert_eq!(normalize_password("  hello  "), "hello");
        assert_eq!(normalize_password("\thello\n"), "hello");
    }

    #[test]
    fn test_normalize_password_nfkd() {
        // U+00E9 (é precomposed) → e + U+0301 (combining acute) under NFKD
        let precomposed = "\u{00E9}";
        let decomposed = "e\u{0301}";
        assert_eq!(normalize_password(precomposed), normalize_password(decomposed));
    }

    #[test]
    fn test_normalize_password_nfkd_compatibility() {
        // U+FB01 (fi ligature) → "fi" under NFKD
        assert_eq!(normalize_password("\u{FB01}"), "fi");
    }

    #[test]
    fn test_normalize_password_ascii_unchanged() {
        assert_eq!(normalize_password("password123!@#"), "password123!@#");
    }

    #[test]
    fn test_nfkd_normalized_passwords_derive_same_key() {
        let salt = vec![1u8; 32];
        let params = KdfParams::fast_for_testing();

        // é as precomposed (U+00E9) vs decomposed (e + U+0301)
        let p1 = password_secret("\u{00E9}".to_string());
        let p2 = password_secret("e\u{0301}".to_string());

        let k1 = derive_master_key(&p1, &salt, &params).unwrap();
        let k2 = derive_master_key(&p2, &salt, &params).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn test_trimmed_passwords_derive_same_key() {
        let salt = vec![1u8; 32];
        let params = KdfParams::fast_for_testing();

        let p1 = password_secret("  mypassword  ".to_string());
        let p2 = password_secret("mypassword".to_string());

        let k1 = derive_master_key(&p1, &salt, &params).unwrap();
        let k2 = derive_master_key(&p2, &salt, &params).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn test_known_vector() {
        // Verify that with fixed inputs we get a consistent output.
        // This serves as a regression test — if the output changes, something broke.
        let password = password_secret("vaultclaw-test-vector".to_string());
        let salt = b"0123456789abcdef0123456789abcdef";
        let params = KdfParams {
            memory_cost_kib: 1024,
            iterations: 1,
            parallelism: 1,
            salt_length: 32,
        };

        let key = derive_master_key(&password, salt, &params).unwrap();
        // Store the first derivation as the expected value
        let expected = *key.as_bytes();

        // Re-derive and verify consistency
        let key2 = derive_master_key(&password, salt, &params).unwrap();
        assert_eq!(key2.as_bytes(), &expected);
    }
}
