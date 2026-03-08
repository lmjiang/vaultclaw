use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use rand::RngCore;
use thiserror::Error;

use crate::crypto::{cipher, kdf::{self, KdfParams}};
use crate::crypto::keys::{self, MasterKey, PasswordSecret, RecoveryKey};
use crate::crypto::recovery;
use super::entry::Entry;
use super::sqlite_store::SqliteBackend;
use super::store::VaultStore;

/// Magic bytes identifying a v1 VaultClaw file.
const V1_MAGIC: &[u8; 8] = b"VCLAW\x00\x01\x00";

/// Current vault format version (v2 = SQLite with per-entry encryption).
const FORMAT_VERSION: u32 = 2;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid vault file: {0}")]
    InvalidFormat(String),
    #[error("Wrong password or corrupted vault")]
    DecryptionFailed,
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Vault file is locked by another process")]
    Locked,
    #[error("Unsupported vault version: {0}")]
    UnsupportedVersion(u32),
    #[error("Database error: {0}")]
    Database(String),
}

impl From<rusqlite::Error> for VaultError {
    fn from(e: rusqlite::Error) -> Self {
        VaultError::Database(e.to_string())
    }
}

/// Maximum number of YubiKeys that can be enrolled on a single vault.
pub const MAX_YUBIKEYS: usize = 8;

/// Information about an enrolled YubiKey.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct YubiKeyInfo {
    pub credential_id: String,
    pub label: String,
    pub rpid: String,
    pub enrolled_at: String,
}

/// The on-disk vault header (unencrypted). Kept for v1 migration parsing.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VaultHeader {
    pub version: u32,
    pub kdf_params: KdfParams,
    pub salt: Vec<u8>,
}

/// Complete vault file representation.
/// V2 format: SQLite with per-entry encryption via HKDF-derived keys.
#[derive(Debug)]
pub struct VaultFile {
    pub header: VaultHeader,
    pub store: VaultStore,
    pub path: PathBuf,
    master_key: MasterKey,
    backend: SqliteBackend,
}

impl VaultFile {
    /// Create a new vault file at the given path.
    /// Uses v3 key wrapping: a random vault_key is wrapped under the password-derived key.
    pub fn create(
        path: impl Into<PathBuf>,
        password: &PasswordSecret,
        kdf_params: KdfParams,
    ) -> Result<Self, VaultError> {
        let path = path.into();
        let salt = kdf::generate_salt(kdf_params.salt_length);
        let password_key = kdf::derive_master_key(password, &salt, &kdf_params)
            .map_err(|e| VaultError::InvalidFormat(e.to_string()))?;

        // v3: generate random vault key, wrap under password-derived key
        let mut vault_key_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut vault_key_bytes);
        let master_key = MasterKey::from_bytes(vault_key_bytes);

        let wrapped = recovery::wrap_vault_key(&master_key, password_key.as_bytes());

        let backend = SqliteBackend::create(&path)?;

        // Store metadata
        backend.set_meta("version", &FORMAT_VERSION.to_le_bytes())?;
        backend.set_meta("kdf_params", &serde_json::to_vec(&kdf_params)
            .map_err(|e| VaultError::Serialization(e.to_string()))?)?;
        backend.set_meta("salt", &salt)?;
        backend.set_meta("wrapped_key_password", &wrapped)?;

        let header = VaultHeader {
            version: FORMAT_VERSION,
            kdf_params,
            salt,
        };

        Ok(Self {
            header,
            store: VaultStore::new(),
            path,
            master_key,
            backend,
        })
    }

    /// Open an existing vault file.
    pub fn open(
        path: impl Into<PathBuf>,
        password: &PasswordSecret,
    ) -> Result<Self, VaultError> {
        let path = path.into();

        // Read first bytes to detect format
        let data = fs::read(&path)?;
        if data.len() < 8 {
            return Err(VaultError::InvalidFormat("File too small".to_string()));
        }

        if &data[..V1_MAGIC.len()] == V1_MAGIC {
            // V1 format — migrate then open the resulting SQLite file
            migrate_v1_to_v2(&data, password, &path)?;
            return Self::open_v2(&path, password);
        }

        if data.len() >= 16 && &data[..16] == b"SQLite format 3\0" {
            return Self::open_v2(&path, password);
        }

        Err(VaultError::InvalidFormat("Invalid magic bytes".to_string()))
    }

    /// Open a v2/v3 (SQLite) vault file with a password.
    fn open_v2(path: &Path, password: &PasswordSecret) -> Result<Self, VaultError> {
        let backend = SqliteBackend::open(path)?;

        // Read metadata
        let version_bytes = backend.get_meta("version")?
            .ok_or_else(|| VaultError::InvalidFormat("Missing version metadata".to_string()))?;
        let version = u32::from_le_bytes(
            version_bytes.try_into()
                .map_err(|_| VaultError::InvalidFormat("Invalid version bytes".to_string()))?
        );

        if version > FORMAT_VERSION {
            return Err(VaultError::UnsupportedVersion(version));
        }

        let kdf_bytes = backend.get_meta("kdf_params")?
            .ok_or_else(|| VaultError::InvalidFormat("Missing KDF params".to_string()))?;
        let kdf_params: KdfParams = serde_json::from_slice(&kdf_bytes)
            .map_err(|e| VaultError::InvalidFormat(format!("KDF params: {}", e)))?;

        let salt = backend.get_meta("salt")?
            .ok_or_else(|| VaultError::InvalidFormat("Missing salt".to_string()))?;

        // Derive password key
        let password_key = kdf::derive_master_key(password, &salt, &kdf_params)
            .map_err(|e| VaultError::InvalidFormat(e.to_string()))?;

        // v3 detection: if wrapped_key_password exists, unwrap vault key
        let master_key = if let Some(wrapped) = backend.get_meta("wrapped_key_password")? {
            recovery::unwrap_vault_key(&wrapped, password_key.as_bytes())
                .map_err(|_| VaultError::DecryptionFailed)?
        } else {
            // Legacy v2: password-derived key IS the master key
            password_key
        };

        Self::load_entries(backend, path, version, kdf_params, salt, master_key)
    }

    /// Open a vault directly with a 32-byte master key (used by YubiKey and programmatic unlock).
    pub fn open_with_master_key(
        path: &Path,
        master_key: MasterKey,
    ) -> Result<Self, VaultError> {
        let backend = SqliteBackend::open(path)?;

        let version_bytes = backend.get_meta("version")?
            .ok_or_else(|| VaultError::InvalidFormat("Missing version metadata".to_string()))?;
        let version = u32::from_le_bytes(
            version_bytes.try_into()
                .map_err(|_| VaultError::InvalidFormat("Invalid version bytes".to_string()))?
        );

        if version > FORMAT_VERSION {
            return Err(VaultError::UnsupportedVersion(version));
        }

        let kdf_bytes = backend.get_meta("kdf_params")?
            .ok_or_else(|| VaultError::InvalidFormat("Missing KDF params".to_string()))?;
        let kdf_params: KdfParams = serde_json::from_slice(&kdf_bytes)
            .map_err(|e| VaultError::InvalidFormat(format!("KDF params: {}", e)))?;

        let salt = backend.get_meta("salt")?
            .ok_or_else(|| VaultError::InvalidFormat("Missing salt".to_string()))?;

        Self::load_entries(backend, path, version, kdf_params, salt, master_key)
    }

    /// Open a vault using a recovery key.
    pub fn open_with_recovery_key(
        path: &Path,
        recovery_key: &RecoveryKey,
    ) -> Result<Self, VaultError> {
        let backend = SqliteBackend::open(path)?;

        // Verify recovery key against stored hash
        if let Some(stored_hash) = backend.get_meta("recovery_verification")? {
            if !recovery::verify_recovery_key(recovery_key, &stored_hash) {
                return Err(VaultError::DecryptionFailed);
            }
        } else {
            return Err(VaultError::InvalidFormat("No recovery key configured".to_string()));
        }

        let wrapped = backend.get_meta("recovery_wrapped_key")?
            .ok_or_else(|| VaultError::InvalidFormat("No recovery wrapped key found".to_string()))?;

        let master_key = recovery::unwrap_vault_key(&wrapped, recovery_key.as_bytes())
            .map_err(|_| VaultError::DecryptionFailed)?;

        let version_bytes = backend.get_meta("version")?
            .ok_or_else(|| VaultError::InvalidFormat("Missing version metadata".to_string()))?;
        let version = u32::from_le_bytes(
            version_bytes.try_into()
                .map_err(|_| VaultError::InvalidFormat("Invalid version bytes".to_string()))?
        );

        let kdf_bytes = backend.get_meta("kdf_params")?
            .ok_or_else(|| VaultError::InvalidFormat("Missing KDF params".to_string()))?;
        let kdf_params: KdfParams = serde_json::from_slice(&kdf_bytes)
            .map_err(|e| VaultError::InvalidFormat(format!("KDF params: {}", e)))?;

        let salt = backend.get_meta("salt")?
            .ok_or_else(|| VaultError::InvalidFormat("Missing salt".to_string()))?;

        Self::load_entries(backend, path, version, kdf_params, salt, master_key)
    }

    /// Common entry-loading logic shared by all open methods.
    fn load_entries(
        backend: SqliteBackend,
        path: &Path,
        version: u32,
        kdf_params: KdfParams,
        salt: Vec<u8>,
        master_key: MasterKey,
    ) -> Result<Self, VaultError> {
        let raw_entries = backend.load_all_entries()?;
        let mut entries = Vec::with_capacity(raw_entries.len());

        for (id_str, blob) in &raw_entries {
            let entry_id: uuid::Uuid = id_str.parse()
                .map_err(|e| VaultError::InvalidFormat(format!("Invalid entry ID: {}", e)))?;
            let entry_key = keys::derive_entry_key(&master_key, &entry_id);
            let plaintext = cipher::decrypt_entry(&entry_key, blob)
                .map_err(|_| VaultError::DecryptionFailed)?;
            let entry: Entry = rmp_serde::from_slice(&plaintext)
                .map_err(|e| VaultError::Serialization(e.to_string()))?;
            entries.push(entry);
        }

        let header = VaultHeader { version, kdf_params, salt };

        Ok(Self {
            header,
            store: VaultStore::from_entries(entries),
            path: path.to_path_buf(),
            master_key,
            backend,
        })
    }

    /// Save the vault to disk. Re-encrypts all entries in a transaction.
    /// Writes both the legacy encrypted_blob (for backward compat) and split enc_overview/enc_details.
    pub fn save(&self) -> Result<(), VaultError> {
        let tx = self.backend.connection().unchecked_transaction()
            .map_err(|e| VaultError::Database(e.to_string()))?;

        // Get current DB entry IDs
        let db_ids: HashSet<String> = self.backend.list_entry_ids()?
            .into_iter().collect();

        // Upsert all current entries
        let mut live_ids = HashSet::new();
        for entry in self.store.entries() {
            let id_str = entry.id.to_string();
            live_ids.insert(id_str.clone());

            // Legacy full-entry blob (backward compatibility)
            let entry_key = keys::derive_entry_key(&self.master_key, &entry.id);
            let plaintext = rmp_serde::to_vec(&entry)
                .map_err(|e| VaultError::Serialization(e.to_string()))?;
            let blob = cipher::encrypt_entry(&entry_key, &plaintext)
                .map_err(|_| VaultError::Serialization("Encryption failed".to_string()))?;

            // Split encryption: overview and details with independent keys
            let overview_key = keys::derive_overview_key(&self.master_key, &entry.id);
            let overview_plaintext = rmp_serde::to_vec(&entry.to_overview())
                .map_err(|e| VaultError::Serialization(e.to_string()))?;
            let enc_overview = cipher::encrypt_entry(&overview_key, &overview_plaintext)
                .map_err(|_| VaultError::Serialization("Overview encryption failed".to_string()))?;

            let details_key = keys::derive_details_key(&self.master_key, &entry.id);
            let details_plaintext = rmp_serde::to_vec(&entry.to_details())
                .map_err(|e| VaultError::Serialization(e.to_string()))?;
            let enc_details = cipher::encrypt_entry(&details_key, &details_plaintext)
                .map_err(|_| VaultError::Serialization("Details encryption failed".to_string()))?;

            let updated_at = entry.updated_at.to_rfc3339();

            self.backend.upsert_entry_split(&id_str, &blob, &enc_overview, &enc_details, &updated_at)?;
        }

        // Delete entries that are no longer in the store
        for old_id in db_ids.difference(&live_ids) {
            self.backend.hard_delete_entry(old_id)?;
        }

        tx.commit().map_err(|e| VaultError::Database(e.to_string()))?;
        Ok(())
    }

    /// Get a reference to the store.
    pub fn store(&self) -> &VaultStore {
        &self.store
    }

    /// Get a mutable reference to the store.
    pub fn store_mut(&mut self) -> &mut VaultStore {
        &mut self.store
    }

    /// Load only the overview portions of all entries (without decrypting details).
    /// Falls back to the full encrypted_blob for entries stored before split encryption.
    pub fn load_overviews(&self) -> Result<Vec<super::entry::EntryOverview>, VaultError> {
        use super::entry::EntryOverview;
        let raw = self.backend.load_all_overviews()?;
        let mut overviews = Vec::with_capacity(raw.len());

        for (id_str, enc_overview_opt) in &raw {
            let entry_id: uuid::Uuid = id_str.parse()
                .map_err(|e| VaultError::InvalidFormat(format!("Invalid entry ID: {}", e)))?;

            if let Some(enc_overview) = enc_overview_opt {
                // Split encryption available — decrypt overview only
                let overview_key = keys::derive_overview_key(&self.master_key, &entry_id);
                let plaintext = cipher::decrypt_entry(&overview_key, enc_overview)
                    .map_err(|_| VaultError::DecryptionFailed)?;
                let overview: EntryOverview = rmp_serde::from_slice(&plaintext)
                    .map_err(|e| VaultError::Serialization(e.to_string()))?;
                overviews.push(overview);
            } else {
                // Legacy entry — fall back to full decryption
                let entry = self.store.get(&entry_id)
                    .ok_or_else(|| VaultError::InvalidFormat(format!("Entry {} not in store", entry_id)))?;
                overviews.push(entry.to_overview());
            }
        }

        Ok(overviews)
    }

    /// Load only the details for a specific entry (on-demand).
    pub fn load_entry_details(&self, entry_id: &uuid::Uuid) -> Result<super::entry::EntryDetails, VaultError> {
        use super::entry::EntryDetails;

        if let Some(enc_details) = self.backend.load_entry_details(&entry_id.to_string())? {
            let details_key = keys::derive_details_key(&self.master_key, entry_id);
            let plaintext = cipher::decrypt_entry(&details_key, &enc_details)
                .map_err(|_| VaultError::DecryptionFailed)?;
            let details: EntryDetails = rmp_serde::from_slice(&plaintext)
                .map_err(|e| VaultError::Serialization(e.to_string()))?;
            Ok(details)
        } else {
            // Legacy entry — extract details from the in-memory store
            let entry = self.store.get(entry_id)
                .ok_or_else(|| VaultError::InvalidFormat(format!("Entry {} not found", entry_id)))?;
            Ok(entry.to_details())
        }
    }

    /// Change the master password.
    /// v3: re-wraps the vault key under the new password-derived key (no entry re-encryption).
    /// v2 (legacy): re-encrypts all entries with new derived keys.
    pub fn change_password(
        &mut self,
        new_password: &PasswordSecret,
    ) -> Result<(), VaultError> {
        let new_salt = kdf::generate_salt(self.header.kdf_params.salt_length);
        let new_password_key = kdf::derive_master_key(new_password, &new_salt, &self.header.kdf_params)
            .map_err(|e| VaultError::InvalidFormat(e.to_string()))?;

        self.header.salt = new_salt.clone();
        self.backend.set_meta("salt", &new_salt)?;

        if self.is_v3() {
            // v3: re-wrap the existing vault key under the new password key
            let wrapped = recovery::wrap_vault_key(&self.master_key, new_password_key.as_bytes());
            self.backend.set_meta("wrapped_key_password", &wrapped)?;
            Ok(())
        } else {
            // Legacy v2: master_key changes, must re-encrypt all entries
            self.master_key = new_password_key;
            self.save()
        }
    }

    /// Check if this vault uses v3 key wrapping.
    pub fn is_v3(&self) -> bool {
        self.backend.get_meta("wrapped_key_password")
            .ok()
            .flatten()
            .is_some()
    }

    /// Migrate a v2 vault to v3 key wrapping format.
    /// The existing password-derived key becomes the wrapping key for a new random vault key.
    /// All entries are re-encrypted under the new vault key.
    pub fn migrate_to_v3(
        &mut self,
        _password: &PasswordSecret,
    ) -> Result<(), VaultError> {
        if self.is_v3() {
            return Err(VaultError::InvalidFormat("Vault is already v3 format".to_string()));
        }

        // The current master_key is the password-derived key
        let password_key_bytes = *self.master_key.as_bytes();

        // Generate new random vault key
        let mut vault_key_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut vault_key_bytes);
        let new_vault_key = MasterKey::from_bytes(vault_key_bytes);

        // Wrap vault key under password-derived key
        let wrapped = recovery::wrap_vault_key(&new_vault_key, &password_key_bytes);
        self.backend.set_meta("wrapped_key_password", &wrapped)?;

        // Update master key and re-encrypt all entries
        self.master_key = new_vault_key;
        self.save()
    }

    /// Enroll a YubiKey (or any 32-byte hardware secret) for vault unlock.
    /// The `secret` is the hmac-secret output from the FIDO2 authenticator.
    pub fn enroll_yubikey(
        &self,
        secret: &[u8; 32],
        info: &YubiKeyInfo,
    ) -> Result<usize, VaultError> {
        if !self.is_v3() {
            return Err(VaultError::InvalidFormat("Vault must be v3 format to enroll YubiKey".to_string()));
        }

        let count = self.yubikey_count()?;
        if count >= MAX_YUBIKEYS {
            return Err(VaultError::InvalidFormat(format!("Maximum {} YubiKeys already enrolled", MAX_YUBIKEYS)));
        }

        // Wrap vault key under the YubiKey secret
        let wrapped = recovery::wrap_vault_key(&self.master_key, secret);
        let slot = count;

        self.backend.set_meta(&format!("wrapped_key_yubikey_{}", slot), &wrapped)?;
        let info_json = serde_json::to_vec(info)
            .map_err(|e| VaultError::Serialization(e.to_string()))?;
        self.backend.set_meta(&format!("yubikey_cred_{}", slot), &info_json)?;
        self.backend.set_meta("yubikey_count", &[count as u8 + 1])?;

        Ok(slot)
    }

    /// Remove an enrolled YubiKey by slot index.
    /// Compacts remaining slots to maintain contiguous indexing.
    pub fn remove_yubikey(&self, slot: usize) -> Result<(), VaultError> {
        let count = self.yubikey_count()?;
        if slot >= count {
            return Err(VaultError::InvalidFormat(format!("YubiKey slot {} not found", slot)));
        }

        // Shift later slots down
        for i in slot..count - 1 {
            let next_wrapped = self.backend.get_meta(&format!("wrapped_key_yubikey_{}", i + 1))?
                .ok_or_else(|| VaultError::InvalidFormat("Missing wrapped key during compaction".to_string()))?;
            let next_cred = self.backend.get_meta(&format!("yubikey_cred_{}", i + 1))?
                .ok_or_else(|| VaultError::InvalidFormat("Missing credential during compaction".to_string()))?;
            self.backend.set_meta(&format!("wrapped_key_yubikey_{}", i), &next_wrapped)?;
            self.backend.set_meta(&format!("yubikey_cred_{}", i), &next_cred)?;
        }

        // Remove last slot
        let last = count - 1;
        self.backend.delete_meta(&format!("wrapped_key_yubikey_{}", last))?;
        self.backend.delete_meta(&format!("yubikey_cred_{}", last))?;

        if count == 1 {
            self.backend.delete_meta("yubikey_count")?;
        } else {
            self.backend.set_meta("yubikey_count", &[count as u8 - 1])?;
        }

        Ok(())
    }

    /// List all enrolled YubiKeys.
    pub fn list_yubikeys(&self) -> Result<Vec<(usize, YubiKeyInfo)>, VaultError> {
        let count = self.yubikey_count()?;
        let mut result = Vec::with_capacity(count);

        for i in 0..count {
            let cred_bytes = self.backend.get_meta(&format!("yubikey_cred_{}", i))?
                .ok_or_else(|| VaultError::InvalidFormat(format!("Missing yubikey_cred_{}", i)))?;
            let info: YubiKeyInfo = serde_json::from_slice(&cred_bytes)
                .map_err(|e| VaultError::Serialization(e.to_string()))?;
            result.push((i, info));
        }

        Ok(result)
    }

    /// Get the number of enrolled YubiKeys.
    fn yubikey_count(&self) -> Result<usize, VaultError> {
        match self.backend.get_meta("yubikey_count")? {
            Some(bytes) if !bytes.is_empty() => Ok(bytes[0] as usize),
            _ => Ok(0),
        }
    }

    /// Try to unwrap the vault key using a YubiKey secret.
    /// Tries all enrolled YubiKey slots until one succeeds.
    pub fn try_unwrap_with_yubikey_secret(
        path: &Path,
        secret: &[u8; 32],
    ) -> Result<MasterKey, VaultError> {
        let backend = SqliteBackend::open(path)?;
        let count = match backend.get_meta("yubikey_count")? {
            Some(bytes) if !bytes.is_empty() => bytes[0] as usize,
            _ => return Err(VaultError::InvalidFormat("No YubiKeys enrolled".to_string())),
        };

        for i in 0..count {
            if let Some(wrapped) = backend.get_meta(&format!("wrapped_key_yubikey_{}", i))? {
                if let Ok(key) = recovery::unwrap_vault_key(&wrapped, secret) {
                    return Ok(key);
                }
            }
        }

        Err(VaultError::DecryptionFailed)
    }

    /// Set up a recovery key for the vault. Returns the generated recovery key
    /// (which should be displayed once and stored offline by the user).
    pub fn setup_recovery_key(&self) -> Result<RecoveryKey, VaultError> {
        if !self.is_v3() {
            return Err(VaultError::InvalidFormat("Vault must be v3 format for recovery key".to_string()));
        }

        let recovery_key = recovery::generate_recovery_key();

        // Wrap vault key under recovery key
        let wrapped = recovery::wrap_vault_key(&self.master_key, recovery_key.as_bytes());
        self.backend.set_meta("recovery_wrapped_key", &wrapped)?;

        // Store verification hash
        let hash = recovery::recovery_verification_hash(&recovery_key);
        self.backend.set_meta("recovery_verification", &hash)?;

        Ok(recovery_key)
    }

    /// Check if the vault has a recovery key configured.
    pub fn has_recovery_key(&self) -> bool {
        self.backend.get_meta("recovery_wrapped_key")
            .ok()
            .flatten()
            .is_some()
    }

    /// Get the YubiKey salt (generates one if not present).
    pub fn yubikey_salt(&self) -> Result<Vec<u8>, VaultError> {
        if let Some(salt) = self.backend.get_meta("yubikey_salt")? {
            return Ok(salt);
        }
        let mut salt = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        self.backend.set_meta("yubikey_salt", &salt)?;
        Ok(salt)
    }

    /// Enroll Touch ID for this vault by wrapping the vault key and storing it
    /// in the macOS Keychain protected by biometry.
    #[cfg(target_os = "macos")]
    pub fn enroll_touchid(&self, vault_label: &str) -> Result<(), VaultError> {
        if !self.is_v3() {
            return Err(VaultError::InvalidFormat(
                "Vault must be v3 format to enroll Touch ID".to_string(),
            ));
        }

        // Wrap the vault key under a random 32-byte wrapping key
        let mut wrapping_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut wrapping_key);
        let wrapped_vault_key = recovery::wrap_vault_key(&self.master_key, &wrapping_key);

        // Store the wrapping key in Keychain (biometry-protected)
        crate::platform::touchid::store_wrapped_key(vault_label, &wrapping_key)
            .map_err(|e| VaultError::InvalidFormat(format!("Touch ID enrollment failed: {}", e)))?;

        // Store the wrapped vault key in the vault metadata
        self.backend.set_meta("touchid_wrapped_key", &wrapped_vault_key)?;
        self.backend.set_meta("touchid_vault_label", vault_label.as_bytes())?;

        Ok(())
    }

    /// Remove Touch ID enrollment from this vault.
    #[cfg(target_os = "macos")]
    pub fn remove_touchid(&self) -> Result<bool, VaultError> {
        let label = match self.backend.get_meta("touchid_vault_label")? {
            Some(bytes) => String::from_utf8(bytes)
                .map_err(|e| VaultError::InvalidFormat(format!("Invalid Touch ID label: {}", e)))?,
            None => return Ok(false),
        };

        // Remove from Keychain
        let _ = crate::platform::touchid::delete_wrapped_key(&label);

        // Remove from vault metadata
        self.backend.delete_meta("touchid_wrapped_key")?;
        self.backend.delete_meta("touchid_vault_label")?;

        Ok(true)
    }

    /// Check if Touch ID is enrolled for this vault.
    #[cfg(target_os = "macos")]
    pub fn has_touchid(&self) -> bool {
        self.backend
            .get_meta("touchid_wrapped_key")
            .ok()
            .flatten()
            .is_some()
    }

    /// Get the Touch ID vault label (for display purposes).
    #[cfg(target_os = "macos")]
    pub fn touchid_label(&self) -> Option<String> {
        self.backend
            .get_meta("touchid_vault_label")
            .ok()
            .flatten()
            .and_then(|b| String::from_utf8(b).ok())
    }

    /// Unlock the vault using Touch ID.
    /// Retrieves the wrapping key from Keychain (triggers biometric prompt),
    /// then unwraps the vault key from the stored metadata.
    #[cfg(target_os = "macos")]
    pub fn open_with_touchid(path: &Path) -> Result<Self, VaultError> {
        let backend = SqliteBackend::open(path)?;

        let vault_label = backend
            .get_meta("touchid_vault_label")?
            .and_then(|b| String::from_utf8(b).ok())
            .ok_or_else(|| VaultError::InvalidFormat("Touch ID not enrolled".to_string()))?;

        let wrapped_vault_key = backend
            .get_meta("touchid_wrapped_key")?
            .ok_or_else(|| VaultError::InvalidFormat("Touch ID wrapped key not found".to_string()))?;

        // Retrieve wrapping key from Keychain (triggers Touch ID prompt)
        let wrapping_key_bytes =
            crate::platform::touchid::retrieve_wrapped_key(&vault_label)
                .map_err(|_| VaultError::DecryptionFailed)?;

        if wrapping_key_bytes.len() != 32 {
            return Err(VaultError::InvalidFormat(
                "Invalid wrapping key size from Keychain".to_string(),
            ));
        }

        let mut wrapping_key = [0u8; 32];
        wrapping_key.copy_from_slice(&wrapping_key_bytes);

        let master_key = recovery::unwrap_vault_key(&wrapped_vault_key, &wrapping_key)
            .map_err(|_| VaultError::DecryptionFailed)?;

        let version_bytes = backend
            .get_meta("version")?
            .ok_or_else(|| VaultError::InvalidFormat("Missing version metadata".to_string()))?;
        let version = u32::from_le_bytes(
            version_bytes
                .try_into()
                .map_err(|_| VaultError::InvalidFormat("Invalid version bytes".to_string()))?,
        );

        let kdf_bytes = backend
            .get_meta("kdf_params")?
            .ok_or_else(|| VaultError::InvalidFormat("Missing KDF params".to_string()))?;
        let kdf_params: KdfParams = serde_json::from_slice(&kdf_bytes)
            .map_err(|e| VaultError::InvalidFormat(format!("KDF params: {}", e)))?;

        let salt = backend
            .get_meta("salt")?
            .ok_or_else(|| VaultError::InvalidFormat("Missing salt".to_string()))?;

        Self::load_entries(backend, path, version, kdf_params, salt, master_key)
    }

    /// Get the vault file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get a reference to the master key (for encrypting auxiliary files like agent state).
    pub fn master_key(&self) -> &MasterKey {
        &self.master_key
    }

    /// Get a reference to the SQLite backend (for agent storage access).
    pub fn backend(&self) -> &SqliteBackend {
        &self.backend
    }

    /// Force a WAL checkpoint (useful before file-copy sync).
    pub fn checkpoint(&self) -> Result<(), VaultError> {
        self.backend.checkpoint()?;
        Ok(())
    }
}

/// Migrate a v1 vault file to v2 (SQLite) format.
/// Creates a backup at `path.v1.backup` before overwriting.
fn migrate_v1_to_v2(data: &[u8], password: &PasswordSecret, path: &Path) -> Result<(), VaultError> {
    // Parse v1 format
    let (header, entries) = parse_v1(data, password)?;

    // Create backup
    let backup_path = path.with_extension("vclaw.v1.backup");
    fs::copy(path, &backup_path)?;

    // Remove original so SQLite can create fresh
    fs::remove_file(path)?;

    // Create new SQLite vault
    let backend = SqliteBackend::create(path)?;

    let kdf_params_json = serde_json::to_vec(&header.kdf_params)
        .map_err(|e| VaultError::Serialization(e.to_string()))?;

    backend.set_meta("version", &FORMAT_VERSION.to_le_bytes())?;
    backend.set_meta("kdf_params", &kdf_params_json)?;
    backend.set_meta("salt", &header.salt)?;

    // Derive master key and write entries with per-entry encryption
    let master_key = kdf::derive_master_key(password, &header.salt, &header.kdf_params)
        .map_err(|e| VaultError::InvalidFormat(e.to_string()))?;

    for entry in &entries {
        let entry_key = keys::derive_entry_key(&master_key, &entry.id);
        let plaintext = rmp_serde::to_vec(entry)
            .map_err(|e| VaultError::Serialization(e.to_string()))?;
        let blob = cipher::encrypt_entry(&entry_key, &plaintext)
            .map_err(|_| VaultError::Serialization("Encryption failed".to_string()))?;
        backend.upsert_entry(
            &entry.id.to_string(),
            &blob,
            &entry.updated_at.to_rfc3339(),
        )?;
    }

    Ok(())
}

/// Parse a v1 vault file, returning the header and decrypted entries.
fn parse_v1(data: &[u8], password: &PasswordSecret) -> Result<(VaultHeader, Vec<Entry>), VaultError> {
    if data.len() < V1_MAGIC.len() {
        return Err(VaultError::InvalidFormat("File too small".to_string()));
    }
    if &data[..V1_MAGIC.len()] != V1_MAGIC {
        return Err(VaultError::InvalidFormat("Invalid magic bytes".to_string()));
    }

    let rest = &data[V1_MAGIC.len()..];

    if rest.len() < 4 {
        return Err(VaultError::InvalidFormat("Missing header length".to_string()));
    }
    let header_len = u32::from_le_bytes(rest[..4].try_into().unwrap()) as usize;
    let rest = &rest[4..];

    if rest.len() < header_len {
        return Err(VaultError::InvalidFormat("Truncated header".to_string()));
    }

    let header: VaultHeader = rmp_serde::from_slice(&rest[..header_len])
        .map_err(|e| VaultError::InvalidFormat(format!("Header: {}", e)))?;

    if header.version > 1 {
        return Err(VaultError::UnsupportedVersion(header.version));
    }

    let master_key = kdf::derive_master_key(password, &header.salt, &header.kdf_params)
        .map_err(|e| VaultError::InvalidFormat(e.to_string()))?;

    let rest = &rest[header_len..];

    let entries = if rest.is_empty() {
        Vec::new()
    } else {
        let plaintext = crate::crypto::cipher::decrypt(&master_key, rest)
            .map_err(|_| VaultError::DecryptionFailed)?;
        rmp_serde::from_slice(&plaintext)
            .map_err(|e| VaultError::Serialization(e.to_string()))?
    };

    Ok((header, entries))
}

/// Create a v1-format vault file (for testing migration).
#[cfg(test)]
fn create_v1_bytes(header: &VaultHeader, entries: &[Entry], master_key: &MasterKey) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(V1_MAGIC);

    let header_bytes = rmp_serde::to_vec(header).unwrap();
    output.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    output.extend_from_slice(&header_bytes);

    if !entries.is_empty() {
        let entries_bytes = rmp_serde::to_vec(&entries.to_vec()).unwrap();
        let encrypted = crate::crypto::cipher::encrypt(master_key, &entries_bytes).unwrap();
        output.extend_from_slice(&encrypted);
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::password_secret;
    use crate::vault::entry::*;
    use tempfile::TempDir;

    fn test_params() -> KdfParams {
        KdfParams::fast_for_testing()
    }

    fn test_password() -> PasswordSecret {
        password_secret("test-master-password".to_string())
    }

    fn test_entry(title: &str) -> Entry {
        Entry::new(
            title.to_string(),
            Credential::Login(LoginCredential {
                url: format!("https://{}.com", title.to_lowercase()),
                username: "user".to_string(),
                password: "pass123".to_string(),
            }),
        )
    }

    #[test]
    fn test_create_new_vault() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
        assert!(path.exists());
        assert_eq!(vault.store().len(), 0);
        assert_eq!(vault.header.version, FORMAT_VERSION);
        // Verify it's a SQLite file
        assert!(SqliteBackend::is_sqlite_file(&path));
    }

    #[test]
    fn test_create_and_reopen() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        {
            let mut vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
            vault.store_mut().add(test_entry("GitHub"));
            vault.store_mut().add(test_entry("GitLab"));
            vault.save().unwrap();
        }

        let vault = VaultFile::open(&path, &test_password()).unwrap();
        assert_eq!(vault.store().len(), 2);
    }

    #[test]
    fn test_wrong_password() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        {
            let mut vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
            vault.store_mut().add(test_entry("Test"));
            vault.save().unwrap();
        }

        let wrong = password_secret("wrong-password".to_string());
        let result = VaultFile::open(&path, &wrong);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_vault_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        VaultFile::create(&path, &test_password(), test_params()).unwrap();
        let vault = VaultFile::open(&path, &test_password()).unwrap();
        assert_eq!(vault.store().len(), 0);
    }

    #[test]
    fn test_many_entries() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        {
            let mut vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
            for i in 0..100 {
                vault.store_mut().add(test_entry(&format!("Entry-{}", i)));
            }
            vault.save().unwrap();
        }

        let vault = VaultFile::open(&path, &test_password()).unwrap();
        assert_eq!(vault.store().len(), 100);
    }

    #[test]
    fn test_all_credential_types() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        {
            let mut vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();

            vault.store_mut().add(Entry::new(
                "Login".to_string(),
                Credential::Login(LoginCredential {
                    url: "https://example.com".to_string(),
                    username: "user".to_string(),
                    password: "pass".to_string(),
                }),
            ));

            vault.store_mut().add(Entry::new(
                "API".to_string(),
                Credential::ApiKey(ApiKeyCredential {
                    service: "AWS".to_string(),
                    key: "AKIA123".to_string(),
                    secret: "secret123".to_string(),
                }),
            ));

            vault.store_mut().add(Entry::new(
                "Note".to_string(),
                Credential::SecureNote(SecureNoteCredential {
                    content: "My secret note".to_string(),
                }),
            ));

            vault.store_mut().add(Entry::new(
                "SSH".to_string(),
                Credential::SshKey(SshKeyCredential {
                    private_key: "-----BEGIN KEY-----".to_string(),
                    public_key: "ssh-rsa AAAA".to_string(),
                    passphrase: "keypass".to_string(),
                }),
            ));

            vault.save().unwrap();
        }

        let vault = VaultFile::open(&path, &test_password()).unwrap();
        assert_eq!(vault.store().len(), 4);
    }

    #[test]
    fn test_change_password() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let new_password = password_secret("new-password-456".to_string());

        {
            let mut vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
            vault.store_mut().add(test_entry("Test"));
            vault.save().unwrap();
            vault.change_password(&new_password).unwrap();
        }

        // Old password should fail
        assert!(VaultFile::open(&path, &test_password()).is_err());

        // New password should work
        let vault = VaultFile::open(&path, &new_password).unwrap();
        assert_eq!(vault.store().len(), 1);
    }

    #[test]
    fn test_corrupted_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        // Write garbage that's not SQLite or v1
        fs::write(&path, b"not a vault file at all!!").unwrap();
        assert!(VaultFile::open(&path, &test_password()).is_err());
    }

    #[test]
    fn test_truncated_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        fs::write(&path, [0u8; 4]).unwrap();
        assert!(VaultFile::open(&path, &test_password()).is_err());
    }

    #[test]
    fn test_sqlite_file_persists() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let mut vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
        vault.store_mut().add(test_entry("Test"));
        vault.save().unwrap();

        assert!(path.exists());
        assert!(SqliteBackend::is_sqlite_file(&path));
    }

    #[test]
    fn test_entries_with_metadata() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let entry = test_entry("Test")
            .with_category("dev")
            .with_tags(vec!["important".into(), "work".into()])
            .with_favorite(true)
            .with_notes("Some notes")
            .with_totp("JBSWY3DPEHPK3PXP");

        {
            let mut vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
            let id = vault.store_mut().add(entry);
            vault.save().unwrap();

            let stored = vault.store().get(&id).unwrap();
            assert_eq!(stored.category.as_deref(), Some("dev"));
            assert_eq!(stored.tags, vec!["important", "work"]);
            assert!(stored.favorite);
            assert_eq!(stored.notes, "Some notes");
            assert_eq!(stored.totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        }

        // Verify persistence
        let vault = VaultFile::open(&path, &test_password()).unwrap();
        let entries = vault.store().list();
        assert_eq!(entries[0].category.as_deref(), Some("dev"));
        assert!(entries[0].favorite);
    }

    #[test]
    fn test_nonexistent_file() {
        let result = VaultFile::open("/nonexistent/path/test.vclaw", &test_password());
        assert!(result.is_err());
    }

    #[test]
    fn test_vault_path() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
        assert_eq!(vault.path(), path);
    }

    #[test]
    fn test_vault_error_display_variants() {
        let e = VaultError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "file not found"));
        assert!(e.to_string().contains("I/O error"));

        let e = VaultError::InvalidFormat("bad magic".to_string());
        assert!(e.to_string().contains("Invalid vault file"));
        assert!(e.to_string().contains("bad magic"));

        let e = VaultError::DecryptionFailed;
        assert!(e.to_string().contains("Wrong password"));

        let e = VaultError::Serialization("encode fail".to_string());
        assert!(e.to_string().contains("Serialization error"));

        let e = VaultError::Locked;
        assert!(e.to_string().contains("locked by another process"));

        let e = VaultError::UnsupportedVersion(42);
        assert!(e.to_string().contains("Unsupported vault version: 42"));

        let e = VaultError::Database("db broken".to_string());
        assert!(e.to_string().contains("Database error"));
        assert!(e.to_string().contains("db broken"));
    }

    #[test]
    fn test_empty_vault_wrong_password_detected_v3() {
        // v3 key wrapping detects wrong passwords even on empty vaults
        // (unlike v2 where there was no ciphertext to verify against).
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        VaultFile::create(&path, &test_password(), test_params()).unwrap();
        let wrong = password_secret("wrong".to_string());
        assert!(VaultFile::open(&path, &wrong).is_err());
    }

    #[test]
    fn test_save_to_nonexistent_directory() {
        let path = std::path::PathBuf::from("/nonexistent_dir_vaultclaw_test/subdir/test.vclaw");
        let result = VaultFile::create(&path, &test_password(), test_params());
        assert!(result.is_err());
    }

    #[test]
    fn test_create_with_invalid_kdf_params() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let bad_params = KdfParams {
            memory_cost_kib: 1024,
            iterations: 1,
            parallelism: 0,
            salt_length: 32,
        };

        let result = VaultFile::create(&path, &test_password(), bad_params);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid vault file"));
    }

    #[test]
    fn test_unsupported_version_in_sqlite() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        // Create a valid vault
        VaultFile::create(&path, &test_password(), test_params()).unwrap();

        // Tamper the version in the meta table
        let db = SqliteBackend::open(&path).unwrap();
        db.set_meta("version", &999u32.to_le_bytes()).unwrap();

        let err = VaultFile::open(&path, &test_password()).unwrap_err();
        assert!(err.to_string().contains("Unsupported vault version: 999"));
    }

    #[test]
    fn test_open_with_invalid_kdf_params_in_sqlite() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        VaultFile::create(&path, &test_password(), test_params()).unwrap();

        // Tamper kdf_params to have parallelism=0
        let mut params = test_params();
        params.parallelism = 0;
        let db = SqliteBackend::open(&path).unwrap();
        db.set_meta("kdf_params", &serde_json::to_vec(&params).unwrap()).unwrap();

        let err = VaultFile::open(&path, &test_password()).unwrap_err();
        assert!(err.to_string().contains("Invalid vault file"), "got: {}", err);
    }

    // ---- V1 migration tests ----

    #[test]
    fn test_v1_migration_empty_vault() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        // Create a v1 file
        let salt = kdf::generate_salt(32);
        let params = test_params();
        let master_key = kdf::derive_master_key(&test_password(), &salt, &params).unwrap();
        let header = VaultHeader { version: 1, kdf_params: params, salt };
        let v1_data = create_v1_bytes(&header, &[], &master_key);
        fs::write(&path, &v1_data).unwrap();

        // Open should auto-migrate
        let vault = VaultFile::open(&path, &test_password()).unwrap();
        assert_eq!(vault.store().len(), 0);
        assert_eq!(vault.header.version, FORMAT_VERSION);
        assert!(SqliteBackend::is_sqlite_file(&path));

        // Backup should exist
        let backup = path.with_extension("vclaw.v1.backup");
        assert!(backup.exists());
    }

    #[test]
    fn test_v1_migration_with_entries() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let salt = kdf::generate_salt(32);
        let params = test_params();
        let master_key = kdf::derive_master_key(&test_password(), &salt, &params).unwrap();
        let header = VaultHeader { version: 1, kdf_params: params, salt };
        let entries = vec![test_entry("GitHub"), test_entry("GitLab")];
        let v1_data = create_v1_bytes(&header, &entries, &master_key);
        fs::write(&path, &v1_data).unwrap();

        let vault = VaultFile::open(&path, &test_password()).unwrap();
        assert_eq!(vault.store().len(), 2);
        assert!(SqliteBackend::is_sqlite_file(&path));
    }

    #[test]
    fn test_v1_migration_wrong_password() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let salt = kdf::generate_salt(32);
        let params = test_params();
        let master_key = kdf::derive_master_key(&test_password(), &salt, &params).unwrap();
        let header = VaultHeader { version: 1, kdf_params: params, salt };
        let entries = vec![test_entry("Test")];
        let v1_data = create_v1_bytes(&header, &entries, &master_key);
        fs::write(&path, &v1_data).unwrap();

        let wrong = password_secret("wrong".to_string());
        assert!(VaultFile::open(&path, &wrong).is_err());
    }

    #[test]
    fn test_v1_parse_truncated() {
        // v1 magic but truncated
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        fs::write(&path, V1_MAGIC).unwrap();
        let err = VaultFile::open(&path, &test_password()).unwrap_err();
        assert!(err.to_string().contains("Missing header length"));
    }

    #[test]
    fn test_v1_parse_truncated_header() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let mut data = Vec::new();
        data.extend_from_slice(V1_MAGIC);
        data.extend_from_slice(&1000u32.to_le_bytes());
        data.extend_from_slice(b"short");
        fs::write(&path, &data).unwrap();
        let err = VaultFile::open(&path, &test_password()).unwrap_err();
        assert!(err.to_string().contains("Truncated header"));
    }

    #[test]
    fn test_v1_corrupt_header() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let garbage_header = b"this is not valid msgpack data!!";
        let mut data = Vec::new();
        data.extend_from_slice(V1_MAGIC);
        data.extend_from_slice(&(garbage_header.len() as u32).to_le_bytes());
        data.extend_from_slice(garbage_header);
        fs::write(&path, &data).unwrap();
        let err = VaultFile::open(&path, &test_password()).unwrap_err();
        assert!(err.to_string().contains("Header:"), "got: {}", err);
    }

    #[test]
    fn test_v1_corrupt_entries() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let salt = kdf::generate_salt(32);
        let params = test_params();
        let master_key = kdf::derive_master_key(&test_password(), &salt, &params).unwrap();
        let header = VaultHeader { version: 1, kdf_params: params, salt };

        // Build v1 file with corrupt encrypted section
        let header_bytes = rmp_serde::to_vec(&header).unwrap();
        let garbage = crate::crypto::cipher::encrypt(&master_key, b"not msgpack entries").unwrap();
        let mut data = Vec::new();
        data.extend_from_slice(V1_MAGIC);
        data.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(&header_bytes);
        data.extend_from_slice(&garbage);
        fs::write(&path, &data).unwrap();

        let err = VaultFile::open(&path, &test_password()).unwrap_err();
        assert!(err.to_string().contains("Serialization error"), "got: {}", err);
    }

    #[test]
    fn test_checkpoint() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
        vault.checkpoint().unwrap();
    }

    #[test]
    fn test_save_removes_deleted_entries() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let mut vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
        let id = vault.store_mut().add(test_entry("ToDelete"));
        vault.store_mut().add(test_entry("ToKeep"));
        vault.save().unwrap();

        vault.store_mut().remove(&id);
        vault.save().unwrap();

        let reopened = VaultFile::open(&path, &test_password()).unwrap();
        assert_eq!(reopened.store().len(), 1);
        assert!(reopened.store().get(&id).is_none());
    }

    #[test]
    fn test_from_rusqlite_error() {
        let e: VaultError = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(1),
            Some("test".to_string()),
        ).into();
        assert!(e.to_string().contains("Database error"));
    }

    // ---- V3 key wrapping tests ----

    #[test]
    fn test_v3_create_has_wrapped_key() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
        assert!(vault.is_v3());

        // wrapped_key_password should exist in meta
        let backend = SqliteBackend::open(&path).unwrap();
        let wrapped = backend.get_meta("wrapped_key_password").unwrap();
        assert!(wrapped.is_some());
        assert_eq!(wrapped.unwrap().len(), crate::crypto::recovery::WRAPPED_KEY_SIZE);
    }

    #[test]
    fn test_v3_create_and_reopen() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        {
            let mut vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
            vault.store_mut().add(test_entry("V3Test"));
            vault.save().unwrap();
        }

        let vault = VaultFile::open(&path, &test_password()).unwrap();
        assert_eq!(vault.store().len(), 1);
        assert_eq!(vault.store().list()[0].title, "V3Test");
    }

    #[test]
    fn test_v3_wrong_password() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        {
            let mut vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
            vault.store_mut().add(test_entry("Test"));
            vault.save().unwrap();
        }

        let wrong = password_secret("wrong-password".to_string());
        let result = VaultFile::open(&path, &wrong);
        assert!(result.is_err());
    }

    #[test]
    fn test_v3_change_password() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let new_password = password_secret("new-password-456".to_string());

        {
            let mut vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
            vault.store_mut().add(test_entry("Test"));
            vault.save().unwrap();
            vault.change_password(&new_password).unwrap();
        }

        // Old password should fail
        assert!(VaultFile::open(&path, &test_password()).is_err());

        // New password should work
        let vault = VaultFile::open(&path, &new_password).unwrap();
        assert_eq!(vault.store().len(), 1);
    }

    #[test]
    fn test_v3_change_password_no_reencrypt() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let new_password = password_secret("new-pw".to_string());

        let mut vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
        vault.store_mut().add(test_entry("Test"));
        vault.save().unwrap();

        // Get the master key bytes before change
        let key_before = *vault.master_key().as_bytes();
        vault.change_password(&new_password).unwrap();

        // Master key should NOT have changed (only re-wrapped)
        assert_eq!(vault.master_key().as_bytes(), &key_before);
    }

    #[test]
    fn test_open_with_master_key() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let master_key_bytes;
        {
            let mut vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
            vault.store_mut().add(test_entry("MasterKeyTest"));
            vault.save().unwrap();
            master_key_bytes = *vault.master_key().as_bytes();
        }

        let key = MasterKey::from_bytes(master_key_bytes);
        let vault = VaultFile::open_with_master_key(&path, key).unwrap();
        assert_eq!(vault.store().len(), 1);
        assert_eq!(vault.store().list()[0].title, "MasterKeyTest");
    }

    #[test]
    fn test_open_with_wrong_master_key() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        {
            let mut vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
            vault.store_mut().add(test_entry("Test"));
            vault.save().unwrap();
        }

        let wrong_key = MasterKey::from_bytes([99u8; 32]);
        let result = VaultFile::open_with_master_key(&path, wrong_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_open_with_master_key_unsupported_version() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
        let key_bytes = *vault.master_key().as_bytes();
        drop(vault);

        // Tamper the version
        let db = SqliteBackend::open(&path).unwrap();
        db.set_meta("version", &999u32.to_le_bytes()).unwrap();
        drop(db);

        let key = MasterKey::from_bytes(key_bytes);
        let err = VaultFile::open_with_master_key(&path, key).unwrap_err();
        assert!(err.to_string().contains("Unsupported vault version: 999"), "got: {}", err);
    }

    // ---- YubiKey enrollment tests ----

    fn test_yubikey_info(label: &str) -> YubiKeyInfo {
        YubiKeyInfo {
            credential_id: "cred-id-123".to_string(),
            label: label.to_string(),
            rpid: "vaultclaw.local".to_string(),
            enrolled_at: "2025-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn test_enroll_yubikey() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
        let secret = [42u8; 32];

        let slot = vault.enroll_yubikey(&secret, &test_yubikey_info("MyYubiKey")).unwrap();
        assert_eq!(slot, 0);

        let keys = vault.list_yubikeys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].0, 0);
        assert_eq!(keys[0].1.label, "MyYubiKey");
    }

    #[test]
    fn test_enroll_multiple_yubikeys() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let mut vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
        vault.store_mut().add(test_entry("Test"));
        vault.save().unwrap();

        for i in 0..3 {
            let mut secret = [0u8; 32];
            secret[0] = i as u8;
            vault.enroll_yubikey(&secret, &test_yubikey_info(&format!("Key{}", i))).unwrap();
        }

        let keys = vault.list_yubikeys().unwrap();
        assert_eq!(keys.len(), 3);
    }

    #[test]
    fn test_unlock_with_yubikey_secret() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let secret = [42u8; 32];
        {
            let mut vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
            vault.store_mut().add(test_entry("YKTest"));
            vault.save().unwrap();
            vault.enroll_yubikey(&secret, &test_yubikey_info("TestKey")).unwrap();
        }

        // Unlock with YubiKey secret
        let master_key = VaultFile::try_unwrap_with_yubikey_secret(&path, &secret).unwrap();
        let vault = VaultFile::open_with_master_key(&path, master_key).unwrap();
        assert_eq!(vault.store().len(), 1);
        assert_eq!(vault.store().list()[0].title, "YKTest");
    }

    #[test]
    fn test_unlock_with_wrong_yubikey_secret() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        {
            let vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
            vault.enroll_yubikey(&[42u8; 32], &test_yubikey_info("Key")).unwrap();
        }

        let wrong_secret = [99u8; 32];
        let result = VaultFile::try_unwrap_with_yubikey_secret(&path, &wrong_secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_yubikey() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();

        for i in 0..3u8 {
            vault.enroll_yubikey(&[i; 32], &test_yubikey_info(&format!("Key{}", i))).unwrap();
        }
        assert_eq!(vault.list_yubikeys().unwrap().len(), 3);

        // Remove middle one (slot 1)
        vault.remove_yubikey(1).unwrap();
        let keys = vault.list_yubikeys().unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].1.label, "Key0");
        assert_eq!(keys[1].1.label, "Key2");
    }

    #[test]
    fn test_remove_last_yubikey() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
        vault.enroll_yubikey(&[42u8; 32], &test_yubikey_info("Key")).unwrap();

        vault.remove_yubikey(0).unwrap();
        assert_eq!(vault.list_yubikeys().unwrap().len(), 0);
    }

    #[test]
    fn test_remove_yubikey_invalid_slot() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
        let result = vault.remove_yubikey(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_max_yubikeys() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();

        for i in 0..MAX_YUBIKEYS {
            vault.enroll_yubikey(&[i as u8; 32], &test_yubikey_info(&format!("Key{}", i))).unwrap();
        }

        // 9th should fail
        let result = vault.enroll_yubikey(&[99u8; 32], &test_yubikey_info("Overflow"));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Maximum"));
    }

    #[test]
    fn test_enroll_yubikey_requires_v3() {
        // Create a vault, remove wrapped_key_password to simulate v2
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
        // Remove the v3 marker
        vault.backend().delete_meta("wrapped_key_password").unwrap();

        let result = vault.enroll_yubikey(&[42u8; 32], &test_yubikey_info("Key"));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("v3"));
    }

    // ---- Recovery key tests ----

    #[test]
    fn test_setup_recovery_key() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let mut vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
        vault.store_mut().add(test_entry("RecoveryTest"));
        vault.save().unwrap();

        let recovery_key = vault.setup_recovery_key().unwrap();
        assert!(vault.has_recovery_key());

        // Format and parse roundtrip
        let formatted = crate::crypto::recovery::format_recovery_key(&recovery_key);
        let parsed = crate::crypto::recovery::parse_recovery_key(&formatted).unwrap();
        assert_eq!(parsed.as_bytes(), recovery_key.as_bytes());
    }

    #[test]
    fn test_open_with_recovery_key() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let recovery_key;
        {
            let mut vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
            vault.store_mut().add(test_entry("RecoveryTest"));
            vault.save().unwrap();
            recovery_key = vault.setup_recovery_key().unwrap();
        }

        let vault = VaultFile::open_with_recovery_key(&path, &recovery_key).unwrap();
        assert_eq!(vault.store().len(), 1);
        assert_eq!(vault.store().list()[0].title, "RecoveryTest");
    }

    #[test]
    fn test_open_with_wrong_recovery_key() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        {
            let vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
            vault.setup_recovery_key().unwrap();
        }

        let wrong_key = RecoveryKey::from_bytes([99u8; 32]);
        let result = VaultFile::open_with_recovery_key(&path, &wrong_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_open_with_recovery_no_recovery_configured() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        VaultFile::create(&path, &test_password(), test_params()).unwrap();

        let key = RecoveryKey::from_bytes([42u8; 32]);
        let result = VaultFile::open_with_recovery_key(&path, &key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No recovery key"));
    }

    #[test]
    fn test_setup_recovery_requires_v3() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
        vault.backend().delete_meta("wrapped_key_password").unwrap();

        let result = vault.setup_recovery_key();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("v3"));
    }

    // ---- v2 → v3 migration tests ----

    #[test]
    fn test_migrate_v2_to_v3() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        // Create a v3 vault and downgrade it to v2 by removing the wrapped key
        {
            let mut vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
            vault.store_mut().add(test_entry("MigrateTest1"));
            vault.store_mut().add(test_entry("MigrateTest2"));
            vault.save().unwrap();

            // Remove v3 marker to simulate v2
            vault.backend().delete_meta("wrapped_key_password").unwrap();
            assert!(!vault.is_v3());
        }

        // Re-open as v2 (password-derived key IS master key)
        // But we need a vault where the entries are encrypted with the password-derived key
        // Let's create a true v2-like vault manually
        let dir2 = TempDir::new().unwrap();
        let path2 = dir2.path().join("test.vclaw");
        {
            // Manually create a v2-style vault (no wrapped key)
            let salt = kdf::generate_salt(32);
            let params = test_params();
            let password_key = kdf::derive_master_key(&test_password(), &salt, &params).unwrap();

            let backend = SqliteBackend::create(&path2).unwrap();
            backend.set_meta("version", &FORMAT_VERSION.to_le_bytes()).unwrap();
            backend.set_meta("kdf_params", &serde_json::to_vec(&params).unwrap()).unwrap();
            backend.set_meta("salt", &salt).unwrap();
            // NO wrapped_key_password — this is v2

            // Write entries encrypted under the password-derived key
            let entry = test_entry("V2Entry");
            let entry_key = keys::derive_entry_key(&password_key, &entry.id);
            let plaintext = rmp_serde::to_vec(&entry).unwrap();
            let blob = cipher::encrypt_entry(&entry_key, &plaintext).unwrap();
            backend.upsert_entry(&entry.id.to_string(), &blob, &entry.updated_at.to_rfc3339()).unwrap();
        }

        // Open as v2
        let mut vault = VaultFile::open(&path2, &test_password()).unwrap();
        assert!(!vault.is_v3());
        assert_eq!(vault.store().len(), 1);

        // Migrate to v3
        vault.migrate_to_v3(&test_password()).unwrap();
        assert!(vault.is_v3());

        // Reopen with password should work
        let vault = VaultFile::open(&path2, &test_password()).unwrap();
        assert_eq!(vault.store().len(), 1);
        assert_eq!(vault.store().list()[0].title, "V2Entry");
    }

    #[test]
    fn test_migrate_already_v3_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let mut vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
        let result = vault.migrate_to_v3(&test_password());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already v3"));
    }

    #[test]
    fn test_yubikey_salt() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();

        let salt1 = vault.yubikey_salt().unwrap();
        assert_eq!(salt1.len(), 32);

        // Second call should return the same salt
        let salt2 = vault.yubikey_salt().unwrap();
        assert_eq!(salt1, salt2);
    }

    #[test]
    fn test_has_recovery_key() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
        assert!(!vault.has_recovery_key());

        vault.setup_recovery_key().unwrap();
        assert!(vault.has_recovery_key());
    }

    #[test]
    fn test_yubikey_info_serialization() {
        let info = YubiKeyInfo {
            credential_id: "cred-123".to_string(),
            label: "My Key".to_string(),
            rpid: "vaultclaw.local".to_string(),
            enrolled_at: "2025-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&info).unwrap();
        let parsed: YubiKeyInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.label, "My Key");
        assert_eq!(parsed.credential_id, "cred-123");
    }

    #[test]
    fn test_no_yubikeys_enrolled_unlock_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        VaultFile::create(&path, &test_password(), test_params()).unwrap();

        let result = VaultFile::try_unwrap_with_yubikey_secret(&path, &[42u8; 32]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No YubiKeys"));
    }

    #[test]
    fn test_multi_yubikey_unlock_any_works() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let secrets = [[1u8; 32], [2u8; 32], [3u8; 32]];
        {
            let mut vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
            vault.store_mut().add(test_entry("MultiYK"));
            vault.save().unwrap();
            for (i, secret) in secrets.iter().enumerate() {
                vault.enroll_yubikey(secret, &test_yubikey_info(&format!("Key{}", i))).unwrap();
            }
        }

        // Any of the 3 secrets should work
        for secret in &secrets {
            let key = VaultFile::try_unwrap_with_yubikey_secret(&path, secret).unwrap();
            let vault = VaultFile::open_with_master_key(&path, key).unwrap();
            assert_eq!(vault.store().len(), 1);
        }
    }

    #[test]
    fn test_v3_empty_vault_wrong_password_detected() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        VaultFile::create(&path, &test_password(), test_params()).unwrap();

        // v3 should detect wrong password even on empty vaults (wrapped key unwrap fails)
        let wrong = password_secret("wrong".to_string());
        let result = VaultFile::open(&path, &wrong);
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_yubikey_then_reindex_works() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let secrets: Vec<[u8; 32]> = (0..4u8).map(|i| [i; 32]).collect();
        let mut vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
        vault.store_mut().add(test_entry("Test"));
        vault.save().unwrap();

        for (i, secret) in secrets.iter().enumerate() {
            vault.enroll_yubikey(secret, &test_yubikey_info(&format!("Key{}", i))).unwrap();
        }

        // Remove slot 0
        vault.remove_yubikey(0).unwrap();

        // Remaining: Key1(now 0), Key2(now 1), Key3(now 2)
        let keys = vault.list_yubikeys().unwrap();
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].1.label, "Key1");
        assert_eq!(keys[1].1.label, "Key2");
        assert_eq!(keys[2].1.label, "Key3");

        // Secrets should still work for the remaining keys
        // Key1's secret is [1;32], now at slot 0
        let mk = VaultFile::try_unwrap_with_yubikey_secret(&path, &secrets[1]).unwrap();
        let v = VaultFile::open_with_master_key(&path, mk).unwrap();
        assert_eq!(v.store().len(), 1);
    }

    #[test]
    fn test_has_touchid_default_false() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test".to_string());
        let vault = VaultFile::create(&path, &password, test_params()).unwrap();
        assert!(!vault.has_touchid());
    }

    #[test]
    fn test_touchid_label_default_none() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test".to_string());
        let vault = VaultFile::create(&path, &password, test_params()).unwrap();
        assert!(vault.touchid_label().is_none());
    }

    #[test]
    fn test_remove_touchid_not_enrolled() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test".to_string());
        let vault = VaultFile::create(&path, &password, test_params()).unwrap();
        let result = vault.remove_touchid().unwrap();
        assert!(!result);
    }

    #[test]
    fn test_v1_unsupported_version_in_header() {
        // Create a v1 file with version > 1 in the header
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let salt = kdf::generate_salt(32);
        let params = test_params();
        let master_key = kdf::derive_master_key(&test_password(), &salt, &params).unwrap();
        // Set version=5 in the header to trigger UnsupportedVersion in parse_v1
        let header = VaultHeader { version: 5, kdf_params: params, salt };
        let v1_data = create_v1_bytes(&header, &[], &master_key);
        fs::write(&path, &v1_data).unwrap();

        let err = VaultFile::open(&path, &test_password()).unwrap_err();
        assert!(err.to_string().contains("Unsupported vault version: 5"), "got: {}", err);
    }

    #[test]
    fn test_legacy_v2_change_password() {
        // Create a vault, then remove wrapped_key_password to simulate v2 legacy
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let new_password = password_secret("new-pw-789".to_string());

        let mut vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
        vault.store_mut().add(test_entry("LegacyTest"));
        vault.save().unwrap();

        // Remove wrapped_key_password to make it a "v2 legacy" vault
        vault.backend.delete_meta("wrapped_key_password").unwrap();
        assert!(!vault.is_v3());

        // Change password on legacy vault — should re-encrypt all entries
        vault.change_password(&new_password).unwrap();

        // Now reopen — without wrapped_key_password, password_key IS master_key
        let reopened = VaultFile::open(&path, &new_password).unwrap();
        assert_eq!(reopened.store().len(), 1);
        assert_eq!(reopened.store().list()[0].title, "LegacyTest");

        // Old password should fail
        assert!(VaultFile::open(&path, &test_password()).is_err());
    }

    #[test]
    fn test_touchid_enroll_metadata_stored() {
        // Test that enroll_touchid stores metadata even though we can't
        // do the real biometric check. We mock the Keychain call failure.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test".to_string());
        let vault = VaultFile::create(&path, &password, test_params()).unwrap();

        // enroll_touchid will fail because the Keychain store will fail in CI,
        // but we can test the error path
        let result = vault.enroll_touchid("ci-test");
        // On a real Mac it might succeed; on CI it likely fails with Keychain error
        // Either way is valid — we're exercising the code path
        if result.is_ok() {
            assert!(vault.has_touchid());
            assert_eq!(vault.touchid_label().as_deref(), Some("ci-test"));
            // Clean up
            let _ = vault.remove_touchid();
        } else {
            // The error should mention Touch ID enrollment
            let err = result.unwrap_err().to_string();
            assert!(
                err.contains("Touch ID") || err.contains("Keychain") || err.contains("enrollment"),
                "unexpected error: {}",
                err
            );
        }
    }

    #[test]
    fn test_open_with_touchid_not_enrolled() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test".to_string());
        VaultFile::create(&path, &password, test_params()).unwrap();

        let err = VaultFile::open_with_touchid(&path).unwrap_err();
        assert!(err.to_string().contains("Touch ID not enrolled"), "got: {}", err);
    }

    #[test]
    fn test_open_with_touchid_missing_wrapped_key() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test".to_string());
        let vault = VaultFile::create(&path, &password, test_params()).unwrap();

        // Set the label but not the wrapped key
        vault.backend.set_meta("touchid_vault_label", b"test-vault").unwrap();

        let err = VaultFile::open_with_touchid(&path).unwrap_err();
        assert!(err.to_string().contains("Touch ID wrapped key not found"), "got: {}", err);
    }

    #[test]
    fn test_open_with_touchid_invalid_wrapping_key_size() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test".to_string());
        let vault = VaultFile::create(&path, &password, test_params()).unwrap();

        // Set label and wrapped key but simulate Keychain returning wrong-size key
        vault.backend.set_meta("touchid_vault_label", b"test-vault").unwrap();
        vault.backend.set_meta("touchid_wrapped_key", b"some-wrapped-data").unwrap();

        // This will fail at Keychain retrieval (DecryptionFailed) since there's
        // no real Touch ID key stored
        let err = VaultFile::open_with_touchid(&path).unwrap_err();
        assert!(
            err.to_string().contains("Wrong password") ||
            err.to_string().contains("wrapping key size") ||
            err.to_string().contains("Touch ID") ||
            err.to_string().contains("Decryption"),
            "got: {}", err
        );
    }

    #[test]
    fn test_remove_touchid_with_invalid_label_encoding() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test".to_string());
        let vault = VaultFile::create(&path, &password, test_params()).unwrap();

        // Store invalid UTF-8 as the label
        vault.backend.set_meta("touchid_vault_label", &[0xFF, 0xFE, 0xFD]).unwrap();

        let err = vault.remove_touchid().unwrap_err();
        assert!(err.to_string().contains("Invalid Touch ID label"), "got: {}", err);
    }

    // ---- parse_v1 direct tests ----

    #[test]
    fn test_parse_v1_empty_data() {
        // Trigger the "File too small" branch in parse_v1 (line 730)
        let password = test_password();
        let result = super::parse_v1(&[], &password);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("File too small"));
    }

    #[test]
    fn test_parse_v1_short_data() {
        // Data smaller than V1_MAGIC length
        let password = test_password();
        let result = super::parse_v1(b"VCLA", &password);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("File too small"));
    }

    #[test]
    fn test_parse_v1_wrong_magic() {
        // Trigger "Invalid magic bytes" branch in parse_v1 (line 733)
        let password = test_password();
        let result = super::parse_v1(b"NOTMAGIC", &password);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid magic bytes"));
    }

    #[test]
    fn test_parse_v1_valid_magic_wrong_magic() {
        // 8 bytes but not the right magic
        let password = test_password();
        let result = super::parse_v1(b"VCLAW\x00\x02\x00", &password);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid magic bytes"));
    }

    // ---- YubiKey missing slot data ----

    #[test]
    fn test_yubikey_unwrap_missing_wrapped_key_slot() {
        // Set yubikey_count=2 but only store wrapped_key_yubikey_0.
        // Slot 1 has no wrapped_key — triggers the None branch at line 497.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let secret_0 = [10u8; 32];
        let secret_1 = [20u8; 32];
        {
            let vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
            // Enroll slot 0
            vault.enroll_yubikey(&secret_0, &test_yubikey_info("Key0")).unwrap();
            // Enroll slot 1
            vault.enroll_yubikey(&secret_1, &test_yubikey_info("Key1")).unwrap();

            // Now delete wrapped_key_yubikey_0 to simulate a missing slot
            vault.backend().delete_meta("wrapped_key_yubikey_0").unwrap();
        }

        // Try to unwrap with secret_1 — should still succeed because slot 1 is intact
        let result = VaultFile::try_unwrap_with_yubikey_secret(&path, &secret_1);
        assert!(result.is_ok(), "should succeed with slot 1: {:?}", result.err());
    }

    #[test]
    fn test_yubikey_unwrap_all_slots_missing_wrapped_keys() {
        // Set yubikey_count=2 but delete all wrapped keys — should fail with DecryptionFailed
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        {
            let vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
            vault.enroll_yubikey(&[10u8; 32], &test_yubikey_info("Key0")).unwrap();
            vault.enroll_yubikey(&[20u8; 32], &test_yubikey_info("Key1")).unwrap();

            // Delete both wrapped keys
            vault.backend().delete_meta("wrapped_key_yubikey_0").unwrap();
            vault.backend().delete_meta("wrapped_key_yubikey_1").unwrap();
        }

        let result = VaultFile::try_unwrap_with_yubikey_secret(&path, &[10u8; 32]);
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Wrong password") || msg.contains("Decryption"),
            "expected DecryptionFailed, got: {}", msg
        );
    }

    #[test]
    fn test_yubikey_unwrap_first_slot_missing_falls_through() {
        // yubikey_count=3, but slot 0 wrapped key is missing.
        // The correct secret is for slot 2. Should iterate through all slots.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let secret_2 = [30u8; 32];
        {
            let vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
            vault.enroll_yubikey(&[10u8; 32], &test_yubikey_info("Key0")).unwrap();
            vault.enroll_yubikey(&[20u8; 32], &test_yubikey_info("Key1")).unwrap();
            vault.enroll_yubikey(&secret_2, &test_yubikey_info("Key2")).unwrap();

            // Delete slot 0's wrapped key
            vault.backend().delete_meta("wrapped_key_yubikey_0").unwrap();
        }

        // Secret for slot 2 should still work
        let result = VaultFile::try_unwrap_with_yubikey_secret(&path, &secret_2);
        assert!(result.is_ok(), "should succeed with slot 2: {:?}", result.err());
    }

    // ---- migrate_v1_to_v2 direct call with entries ----

    #[test]
    fn test_migrate_v1_to_v2_directly_with_entries() {
        // Call migrate_v1_to_v2 directly to cover line 721 (entry loop in migration)
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");

        let salt = kdf::generate_salt(32);
        let params = test_params();
        let master_key = kdf::derive_master_key(&test_password(), &salt, &params).unwrap();
        let header = VaultHeader { version: 1, kdf_params: params, salt };
        let entries = vec![test_entry("Direct1"), test_entry("Direct2"), test_entry("Direct3")];
        let v1_data = create_v1_bytes(&header, &entries, &master_key);
        fs::write(&path, &v1_data).unwrap();

        // Call migrate_v1_to_v2 directly
        super::migrate_v1_to_v2(&v1_data, &test_password(), &path).unwrap();

        // Verify the resulting SQLite file
        assert!(SqliteBackend::is_sqlite_file(&path));
        let vault = VaultFile::open(&path, &test_password()).unwrap();
        assert_eq!(vault.store().len(), 3);
    }

    // ---- VaultFile::open error paths for small / garbage files ----

    #[test]
    fn test_open_very_small_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        fs::write(&path, b"tiny").unwrap();
        let err = VaultFile::open(&path, &test_password()).unwrap_err();
        assert!(err.to_string().contains("File too small"), "got: {}", err);
    }

    #[test]
    fn test_open_non_v1_non_sqlite_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        // 16 bytes but not SQLite header and not V1 magic
        fs::write(&path, b"This is garbage!").unwrap();
        let err = VaultFile::open(&path, &test_password()).unwrap_err();
        assert!(err.to_string().contains("Invalid magic bytes"), "got: {}", err);
    }

    // ---- Touch ID: manually set up metadata and test open_with_touchid deeper paths ----

    #[cfg(target_os = "macos")]
    #[test]
    fn test_open_with_touchid_wrapping_key_wrong_size() {
        // Manually set up a vault with touchid metadata and a wrapping key
        // of the wrong size stored in the Keychain (simulated by storing directly)
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test".to_string());
        let vault = VaultFile::create(&path, &password, test_params()).unwrap();

        // Store touchid metadata pointing to a label
        vault.backend.set_meta("touchid_vault_label", b"wrong-size-test").unwrap();
        // Store a fake wrapped key (the real wrapping key from Keychain won't match)
        let fake_wrapped = crate::crypto::recovery::wrap_vault_key(
            &vault.master_key,
            &[42u8; 32],
        );
        vault.backend.set_meta("touchid_wrapped_key", &fake_wrapped).unwrap();

        // This will fail at Keychain retrieval step (no key stored in Keychain)
        let err = VaultFile::open_with_touchid(&path).unwrap_err();
        // Should fail with DecryptionFailed (Keychain retrieval fails)
        let msg = err.to_string();
        assert!(msg.contains("Wrong password") || msg.contains("Decryption") || msg.contains("wrapping key"), "got: {}", msg);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_enroll_touchid_requires_v3() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test".to_string());
        let vault = VaultFile::create(&path, &password, test_params()).unwrap();
        // Remove v3 marker to simulate v2
        vault.backend().delete_meta("wrapped_key_password").unwrap();

        let result = vault.enroll_touchid("test-label");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("v3"), "got non-v3 error");
    }

    // Interactive Touch ID tests — require biometric hardware:
    //   cargo test -- --ignored touchid_vault

    #[test]
    #[ignore]
    fn test_enroll_touchid_and_open() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test".to_string());
        let mut vault = VaultFile::create(&path, &password, test_params()).unwrap();

        // Add an entry
        vault.store_mut().add(Entry::new(
            "GitHub".to_string(),
            Credential::Login(LoginCredential {
                url: "https://github.com".to_string(),
                username: "user".to_string(),
                password: "pass".to_string(),
            }),
        ));
        vault.save().unwrap();

        // Enroll Touch ID
        vault.enroll_touchid("test-vault").unwrap();
        assert!(vault.has_touchid());
        assert_eq!(vault.touchid_label().as_deref(), Some("test-vault"));

        // Open with Touch ID (triggers biometric prompt)
        let reopened = VaultFile::open_with_touchid(&path).unwrap();
        assert_eq!(reopened.store().len(), 1);

        // Cleanup
        vault.remove_touchid().unwrap();
        assert!(!vault.has_touchid());
    }

    #[test]
    fn test_split_encryption_overview_details() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("split.vclaw");

        {
            let mut vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
            vault.store_mut().add(test_entry("GitHub"));
            vault.store_mut().add(test_entry("GitLab"));
            vault.save().unwrap();
        }

        // Reopen and verify overviews can be loaded independently
        let vault = VaultFile::open(&path, &test_password()).unwrap();
        let overviews = vault.load_overviews().unwrap();
        assert_eq!(overviews.len(), 2);

        let titles: Vec<&str> = overviews.iter().map(|o| o.title.as_str()).collect();
        assert!(titles.contains(&"GitHub"));
        assert!(titles.contains(&"GitLab"));

        // Verify overview has correct metadata
        let gh = overviews.iter().find(|o| o.title == "GitHub").unwrap();
        assert_eq!(gh.credential_type, "login");
        assert_eq!(gh.url.as_deref(), Some("https://github.com"));
        assert_eq!(gh.username.as_deref(), Some("user"));
    }

    #[test]
    fn test_split_encryption_load_details() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("details.vclaw");

        let entry_id;
        {
            let mut vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
            let entry = test_entry("GitHub");
            entry_id = entry.id;
            vault.store_mut().add(entry);
            vault.save().unwrap();
        }

        let vault = VaultFile::open(&path, &test_password()).unwrap();
        let details = vault.load_entry_details(&entry_id).unwrap();
        assert!(matches!(details.credential, Credential::Login(_)));
        if let Credential::Login(login) = &details.credential {
            assert_eq!(login.password, "pass123");
        }
    }

    #[test]
    fn test_split_encryption_roundtrip_preserves_data() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("roundtrip.vclaw");

        let original;
        {
            let mut vault = VaultFile::create(&path, &test_password(), test_params()).unwrap();
            let entry = test_entry("GitHub")
                .with_category("dev")
                .with_tags(vec!["vcs".to_string()])
                .with_notes("my notes")
                .with_sensitive(true);
            original = entry.clone();
            vault.store_mut().add(entry);
            vault.save().unwrap();
        }

        let vault = VaultFile::open(&path, &test_password()).unwrap();

        // Overview matches
        let overviews = vault.load_overviews().unwrap();
        let overview = &overviews[0];
        assert_eq!(overview.title, "GitHub");
        assert_eq!(overview.category.as_deref(), Some("dev"));
        assert_eq!(overview.tags, vec!["vcs"]);

        // Details match
        let details = vault.load_entry_details(&original.id).unwrap();
        assert_eq!(details.notes, "my notes");
        assert!(details.sensitive);
        assert_eq!(details.credential, original.credential);
    }
}
