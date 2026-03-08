use hkdf::Hkdf;
use secrecy::Secret;
use sha2::Sha256;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A 32-byte master key derived from the user's password via Argon2id.
/// Automatically zeroed from memory on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; 32]);

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey([REDACTED])")
    }
}

impl MasterKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A 32-byte encryption key used for individual entry encryption.
/// Derived from the master key + entry-specific context.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EntryKey([u8; 32]);

impl EntryKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Derive a per-entry encryption key from the master key and entry ID.
/// Uses HKDF-SHA256 with a fixed salt and the entry UUID bytes as info.
pub fn derive_entry_key(master_key: &MasterKey, entry_id: &Uuid) -> EntryKey {
    let hk = Hkdf::<Sha256>::new(Some(b"vaultclaw-entry-key-v1"), master_key.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(entry_id.as_bytes(), &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    EntryKey::from_bytes(okm)
}

/// Derive an overview encryption key for an entry.
/// Uses a different HKDF context than the details key so they are independent.
pub fn derive_overview_key(master_key: &MasterKey, entry_id: &Uuid) -> EntryKey {
    let hk = Hkdf::<Sha256>::new(Some(b"vaultclaw-entry-overview-v1"), master_key.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(entry_id.as_bytes(), &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    EntryKey::from_bytes(okm)
}

/// Derive a details encryption key for an entry.
/// Uses a different HKDF context than the overview key so they are independent.
pub fn derive_details_key(master_key: &MasterKey, entry_id: &Uuid) -> EntryKey {
    let hk = Hkdf::<Sha256>::new(Some(b"vaultclaw-entry-details-v1"), master_key.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(entry_id.as_bytes(), &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    EntryKey::from_bytes(okm)
}

/// A 32-byte recovery key for emergency vault access.
/// Automatically zeroed from memory on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryKey([u8; 32]);

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryKey([REDACTED])")
    }
}

impl RecoveryKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Wraps a password string with automatic zeroization.
pub type PasswordSecret = Secret<String>;

/// Create a password secret from a string.
pub fn password_secret(password: String) -> PasswordSecret {
    Secret::new(password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_master_key_creation() {
        let bytes = [42u8; 32];
        let key = MasterKey::from_bytes(bytes);
        assert_eq!(key.as_bytes(), &[42u8; 32]);
    }

    #[test]
    fn test_entry_key_creation() {
        let bytes = [7u8; 32];
        let key = EntryKey::from_bytes(bytes);
        assert_eq!(key.as_bytes(), &[7u8; 32]);
    }

    #[test]
    fn test_master_key_zeroize_on_drop() {
        // We can't directly test zeroization after drop, but we verify
        // the derive macro compiles and the type implements ZeroizeOnDrop.
        let key = MasterKey::from_bytes([1u8; 32]);
        assert_eq!(key.as_bytes()[0], 1);
        // key is dropped here and memory should be zeroed
    }

    #[test]
    fn test_password_secret() {
        use secrecy::ExposeSecret;
        let secret = password_secret("hunter2".to_string());
        assert_eq!(secret.expose_secret(), "hunter2");
    }

    #[test]
    fn test_key_clone() {
        let key1 = MasterKey::from_bytes([99u8; 32]);
        let key2 = key1.clone();
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_master_key_debug_redacted() {
        let key = MasterKey::from_bytes([42u8; 32]);
        let debug_str = format!("{:?}", key);
        assert_eq!(debug_str, "MasterKey([REDACTED])");
        assert!(!debug_str.contains("42"));
    }

    #[test]
    fn test_derive_entry_key_deterministic() {
        let master = MasterKey::from_bytes([42u8; 32]);
        let id = Uuid::nil();
        let k1 = derive_entry_key(&master, &id);
        let k2 = derive_entry_key(&master, &id);
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn test_derive_entry_key_different_ids() {
        let master = MasterKey::from_bytes([42u8; 32]);
        let id1 = Uuid::from_bytes([1u8; 16]);
        let id2 = Uuid::from_bytes([2u8; 16]);
        let k1 = derive_entry_key(&master, &id1);
        let k2 = derive_entry_key(&master, &id2);
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn test_recovery_key_creation() {
        let bytes = [99u8; 32];
        let key = RecoveryKey::from_bytes(bytes);
        assert_eq!(key.as_bytes(), &[99u8; 32]);
    }

    #[test]
    fn test_recovery_key_debug_redacted() {
        let key = RecoveryKey::from_bytes([42u8; 32]);
        let debug_str = format!("{:?}", key);
        assert_eq!(debug_str, "RecoveryKey([REDACTED])");
        assert!(!debug_str.contains("42"));
    }

    #[test]
    fn test_recovery_key_clone() {
        let k1 = RecoveryKey::from_bytes([55u8; 32]);
        let k2 = k1.clone();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn test_derive_entry_key_different_masters() {
        let m1 = MasterKey::from_bytes([1u8; 32]);
        let m2 = MasterKey::from_bytes([2u8; 32]);
        let id = Uuid::nil();
        let k1 = derive_entry_key(&m1, &id);
        let k2 = derive_entry_key(&m2, &id);
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn test_overview_details_keys_are_different() {
        let master = MasterKey::from_bytes([42u8; 32]);
        let id = Uuid::from_bytes([1u8; 16]);
        let overview = derive_overview_key(&master, &id);
        let details = derive_details_key(&master, &id);
        assert_ne!(overview.as_bytes(), details.as_bytes());
    }

    #[test]
    fn test_overview_key_differs_from_entry_key() {
        let master = MasterKey::from_bytes([42u8; 32]);
        let id = Uuid::from_bytes([1u8; 16]);
        let entry = derive_entry_key(&master, &id);
        let overview = derive_overview_key(&master, &id);
        assert_ne!(entry.as_bytes(), overview.as_bytes());
    }

    #[test]
    fn test_overview_key_deterministic() {
        let master = MasterKey::from_bytes([42u8; 32]);
        let id = Uuid::from_bytes([1u8; 16]);
        let k1 = derive_overview_key(&master, &id);
        let k2 = derive_overview_key(&master, &id);
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn test_details_key_deterministic() {
        let master = MasterKey::from_bytes([42u8; 32]);
        let id = Uuid::from_bytes([1u8; 16]);
        let k1 = derive_details_key(&master, &id);
        let k2 = derive_details_key(&master, &id);
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn test_overview_key_different_ids() {
        let master = MasterKey::from_bytes([42u8; 32]);
        let id1 = Uuid::from_bytes([1u8; 16]);
        let id2 = Uuid::from_bytes([2u8; 16]);
        let k1 = derive_overview_key(&master, &id1);
        let k2 = derive_overview_key(&master, &id2);
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }
}
