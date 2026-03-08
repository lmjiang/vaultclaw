//! Vault backup and recovery system.
//!
//! Creates timestamped encrypted backups of the vault file, manages backup
//! rotation, and supports point-in-time recovery.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Metadata for a single backup file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupInfo {
    pub filename: String,
    pub path: PathBuf,
    pub created_at: DateTime<Utc>,
    pub size_bytes: u64,
    pub source_vault: String,
    pub vault_version: Option<u32>,
}

/// Configuration for the backup system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    pub backup_dir: PathBuf,
    pub max_backups: usize,
    pub auto_backup: bool,
}

impl Default for BackupConfig {
    fn default() -> Self {
        let dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("vaultclaw")
            .join("backups");
        Self {
            backup_dir: dir,
            max_backups: 10,
            auto_backup: true,
        }
    }
}

/// Resolve the default backup directory.
pub fn default_backup_dir() -> PathBuf {
    BackupConfig::default().backup_dir
}

/// Create a timestamped backup of the vault file.
///
/// Returns metadata about the created backup.
pub fn create_backup(vault_path: &Path, backup_dir: &Path) -> Result<BackupInfo, BackupError> {
    if !vault_path.exists() {
        return Err(BackupError::VaultNotFound(vault_path.display().to_string()));
    }

    std::fs::create_dir_all(backup_dir)?;

    // Checkpoint WAL to ensure all data is in the main file before copying
    checkpoint_wal(vault_path);

    let vault_name = vault_path
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy();
    let now = Utc::now();
    let timestamp = now.format("%Y%m%d-%H%M%S");
    let millis = now.timestamp_subsec_millis();
    let filename = format!("{}-{}-{:03}.vclaw.backup", vault_name, timestamp, millis);
    let backup_path = backup_dir.join(&filename);

    std::fs::copy(vault_path, &backup_path)?;

    let meta = std::fs::metadata(&backup_path)?;
    let version = read_vault_version(&backup_path);

    Ok(BackupInfo {
        filename,
        path: backup_path,
        created_at: Utc::now(),
        size_bytes: meta.len(),
        source_vault: vault_path.display().to_string(),
        vault_version: version,
    })
}

/// List available backups in a directory, sorted by creation time (newest first).
pub fn list_backups(backup_dir: &Path) -> Result<Vec<BackupInfo>, BackupError> {
    if !backup_dir.exists() {
        return Ok(Vec::new());
    }

    let mut backups = Vec::new();

    for entry in std::fs::read_dir(backup_dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();

        if !name.ends_with(".vclaw.backup") {
            continue;
        }

        let meta = std::fs::metadata(&path)?;
        let modified = meta.modified()
            .ok()
            .and_then(|t| {
                let dur = t.duration_since(std::time::UNIX_EPOCH).ok()?;
                DateTime::from_timestamp(dur.as_secs() as i64, 0)
            })
            .unwrap_or_else(Utc::now);

        backups.push(BackupInfo {
            filename: name,
            path: path.clone(),
            created_at: modified,
            size_bytes: meta.len(),
            source_vault: String::new(),
            vault_version: read_vault_version(&path),
        });
    }

    backups.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(backups)
}

/// Restore a backup to the vault path.
///
/// Creates a backup of the current vault before restoring (safety net).
pub fn restore_backup(backup_path: &Path, vault_path: &Path) -> Result<BackupInfo, BackupError> {
    if !backup_path.exists() {
        return Err(BackupError::BackupNotFound(backup_path.display().to_string()));
    }

    // Create safety backup of current vault if it exists
    if vault_path.exists() {
        let safety_dir = vault_path.parent().unwrap_or(Path::new("."));
        let safety_name = format!(
            "{}-pre-restore-{}.vclaw.backup",
            vault_path.file_stem().unwrap_or_default().to_string_lossy(),
            Utc::now().format("%Y%m%d-%H%M%S"),
        );
        let safety_path = safety_dir.join(&safety_name);
        std::fs::copy(vault_path, &safety_path)?;
    }

    std::fs::copy(backup_path, vault_path)?;

    let meta = std::fs::metadata(vault_path)?;
    Ok(BackupInfo {
        filename: vault_path.file_name().unwrap_or_default().to_string_lossy().to_string(),
        path: vault_path.to_path_buf(),
        created_at: Utc::now(),
        size_bytes: meta.len(),
        source_vault: backup_path.display().to_string(),
        vault_version: read_vault_version(vault_path),
    })
}

/// Verify a backup file's integrity without restoring.
///
/// Checks that the file is a valid SQLite database and has the expected vault tables.
pub fn verify_backup(backup_path: &Path) -> Result<VerifyResult, BackupError> {
    if !backup_path.exists() {
        return Err(BackupError::BackupNotFound(backup_path.display().to_string()));
    }

    let size = std::fs::metadata(backup_path)?.len();

    // Check SQLite magic bytes
    let header = std::fs::read(backup_path)?;
    if header.len() < 16 {
        return Ok(VerifyResult {
            valid: false,
            size_bytes: size,
            vault_version: None,
            entry_count: None,
            has_metadata: false,
            integrity_ok: false,
            error: Some("File too small".into()),
        });
    }

    let is_sqlite = &header[..16] == b"SQLite format 3\0";
    if !is_sqlite {
        // Could be v1 binary format
        let is_v1 = header.len() >= 8 && &header[..5] == b"VCLAW";
        return Ok(VerifyResult {
            valid: is_v1,
            size_bytes: size,
            vault_version: if is_v1 { Some(1) } else { None },
            entry_count: None,
            has_metadata: is_v1,
            integrity_ok: is_v1,
            error: if is_v1 { None } else { Some("Unknown file format".into()) },
        });
    }

    // Open SQLite and check tables
    match rusqlite::Connection::open_with_flags(
        backup_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ) {
        Ok(conn) => {
            let has_metadata = conn
                .prepare("SELECT COUNT(*) FROM meta")
                .and_then(|mut s| s.query_row([], |r| r.get::<_, i64>(0)))
                .unwrap_or(0) > 0;

            let entry_count = conn
                .prepare("SELECT COUNT(*) FROM entries")
                .and_then(|mut s| s.query_row([], |r| r.get::<_, i64>(0)))
                .ok()
                .map(|c| c as usize);

            let integrity = conn
                .pragma_query_value(None, "integrity_check", |row| row.get::<_, String>(0))
                .unwrap_or_else(|_| "error".into());

            let version = read_vault_version(backup_path);

            Ok(VerifyResult {
                valid: has_metadata && integrity == "ok",
                size_bytes: size,
                vault_version: version,
                entry_count,
                has_metadata,
                integrity_ok: integrity == "ok",
                error: if integrity != "ok" {
                    Some(format!("SQLite integrity: {}", integrity))
                } else {
                    None
                },
            })
        }
        Err(e) => Ok(VerifyResult {
            valid: false,
            size_bytes: size,
            vault_version: None,
            entry_count: None,
            has_metadata: false,
            integrity_ok: false,
            error: Some(format!("Cannot open SQLite: {}", e)),
        }),
    }
}

/// Result of backup verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResult {
    pub valid: bool,
    pub size_bytes: u64,
    pub vault_version: Option<u32>,
    pub entry_count: Option<usize>,
    pub has_metadata: bool,
    pub integrity_ok: bool,
    pub error: Option<String>,
}

/// Prune old backups, keeping only the most recent `max_keep`.
pub fn prune_backups(backup_dir: &Path, max_keep: usize) -> Result<Vec<String>, BackupError> {
    let backups = list_backups(backup_dir)?;
    let mut pruned = Vec::new();

    if backups.len() <= max_keep {
        return Ok(pruned);
    }

    for backup in backups.iter().skip(max_keep) {
        if std::fs::remove_file(&backup.path).is_ok() {
            pruned.push(backup.filename.clone());
        }
    }

    Ok(pruned)
}

/// Checkpoint WAL journal into the main database file.
/// This ensures file-copy backups contain all data.
fn checkpoint_wal(path: &Path) {
    if let Ok(conn) = rusqlite::Connection::open(path) {
        let _ = conn.pragma_update(None, "wal_checkpoint", "TRUNCATE");
    }
}

/// Read vault version from a vault/backup file without opening it.
fn read_vault_version(path: &Path) -> Option<u32> {
    let conn = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ).ok()?;

    let version_bytes: Vec<u8> = conn
        .prepare("SELECT value FROM meta WHERE key = 'version'")
        .and_then(|mut s| s.query_row([], |r| r.get(0)))
        .ok()?;

    if version_bytes.len() >= 4 {
        Some(u32::from_le_bytes([
            version_bytes[0], version_bytes[1], version_bytes[2], version_bytes[3],
        ]))
    } else {
        None
    }
}

/// Errors from backup operations.
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Vault file not found: {0}")]
    VaultNotFound(String),
    #[error("Backup file not found: {0}")]
    BackupNotFound(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::KdfParams;
    use crate::crypto::keys::password_secret;
    use crate::vault::format::VaultFile;
    use tempfile::TempDir;

    fn create_test_vault(dir: &Path) -> PathBuf {
        let path = dir.join("test.vclaw");
        let password = password_secret("testpass".to_string());
        VaultFile::create(&path, &password, KdfParams::fast_for_testing()).unwrap();
        path
    }

    #[test]
    fn test_create_backup() {
        let dir = TempDir::new().unwrap();
        let vault_path = create_test_vault(dir.path());
        let backup_dir = dir.path().join("backups");

        let info = create_backup(&vault_path, &backup_dir).unwrap();
        assert!(info.path.exists());
        assert!(info.filename.ends_with(".vclaw.backup"));
        assert!(info.filename.starts_with("test-"));
        assert!(info.size_bytes > 0);
    }

    #[test]
    fn test_create_backup_vault_not_found() {
        let dir = TempDir::new().unwrap();
        let result = create_backup(
            &dir.path().join("nonexistent.vclaw"),
            &dir.path().join("backups"),
        );
        assert!(matches!(result, Err(BackupError::VaultNotFound(_))));
    }

    #[test]
    fn test_list_backups_empty() {
        let dir = TempDir::new().unwrap();
        let backups = list_backups(&dir.path().join("nonexistent")).unwrap();
        assert!(backups.is_empty());
    }

    #[test]
    fn test_list_backups() {
        let dir = TempDir::new().unwrap();
        let vault_path = create_test_vault(dir.path());
        let backup_dir = dir.path().join("backups");

        create_backup(&vault_path, &backup_dir).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        create_backup(&vault_path, &backup_dir).unwrap();

        let backups = list_backups(&backup_dir).unwrap();
        assert_eq!(backups.len(), 2);
        // Newest first
        assert!(backups[0].created_at >= backups[1].created_at);
    }

    #[test]
    fn test_restore_backup() {
        let dir = TempDir::new().unwrap();
        let vault_path = create_test_vault(dir.path());
        let backup_dir = dir.path().join("backups");

        let backup = create_backup(&vault_path, &backup_dir).unwrap();

        // Delete the original
        std::fs::remove_file(&vault_path).unwrap();
        assert!(!vault_path.exists());

        // Restore
        let restored = restore_backup(&backup.path, &vault_path).unwrap();
        assert!(vault_path.exists());
        assert!(restored.size_bytes > 0);
    }

    #[test]
    fn test_restore_backup_creates_safety() {
        let dir = TempDir::new().unwrap();
        let vault_path = create_test_vault(dir.path());
        let backup_dir = dir.path().join("backups");

        let backup = create_backup(&vault_path, &backup_dir).unwrap();

        // Restore over existing vault — should create safety backup
        restore_backup(&backup.path, &vault_path).unwrap();

        // Check safety backup exists in the vault's directory
        let safety_files: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name().to_string_lossy().contains("pre-restore")
            })
            .collect();
        assert_eq!(safety_files.len(), 1);
    }

    #[test]
    fn test_restore_backup_not_found() {
        let dir = TempDir::new().unwrap();
        let result = restore_backup(
            &dir.path().join("nonexistent.vclaw.backup"),
            &dir.path().join("vault.vclaw"),
        );
        assert!(matches!(result, Err(BackupError::BackupNotFound(_))));
    }

    #[test]
    fn test_verify_backup_valid() {
        let dir = TempDir::new().unwrap();
        let vault_path = create_test_vault(dir.path());
        let backup_dir = dir.path().join("backups");

        let backup = create_backup(&vault_path, &backup_dir).unwrap();
        let result = verify_backup(&backup.path).unwrap();

        assert!(result.valid);
        assert!(result.integrity_ok);
        assert!(result.has_metadata);
        assert!(result.entry_count.is_some());
        assert!(result.error.is_none());
    }

    #[test]
    fn test_verify_backup_not_found() {
        let dir = TempDir::new().unwrap();
        let result = verify_backup(&dir.path().join("nonexistent.vclaw.backup"));
        assert!(matches!(result, Err(BackupError::BackupNotFound(_))));
    }

    #[test]
    fn test_verify_backup_invalid_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("invalid.vclaw.backup");
        std::fs::write(&path, b"not a vault file at all").unwrap();

        let result = verify_backup(&path).unwrap();
        assert!(!result.valid);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_verify_backup_too_small() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("tiny.vclaw.backup");
        std::fs::write(&path, b"tiny").unwrap();

        let result = verify_backup(&path).unwrap();
        assert!(!result.valid);
        assert_eq!(result.error.as_deref(), Some("File too small"));
    }

    #[test]
    fn test_prune_backups() {
        let dir = TempDir::new().unwrap();
        let vault_path = create_test_vault(dir.path());
        let backup_dir = dir.path().join("backups");

        for _ in 0..5 {
            create_backup(&vault_path, &backup_dir).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let before = list_backups(&backup_dir).unwrap();
        assert_eq!(before.len(), 5);

        let pruned = prune_backups(&backup_dir, 3).unwrap();
        assert_eq!(pruned.len(), 2);

        let after = list_backups(&backup_dir).unwrap();
        assert_eq!(after.len(), 3);
    }

    #[test]
    fn test_prune_backups_no_op() {
        let dir = TempDir::new().unwrap();
        let vault_path = create_test_vault(dir.path());
        let backup_dir = dir.path().join("backups");

        create_backup(&vault_path, &backup_dir).unwrap();

        let pruned = prune_backups(&backup_dir, 10).unwrap();
        assert!(pruned.is_empty());
    }

    #[test]
    fn test_prune_backups_empty_dir() {
        let dir = TempDir::new().unwrap();
        let pruned = prune_backups(&dir.path().join("nonexistent"), 5).unwrap();
        assert!(pruned.is_empty());
    }

    #[test]
    fn test_backup_config_default() {
        let config = BackupConfig::default();
        assert_eq!(config.max_backups, 10);
        assert!(config.auto_backup);
        assert!(config.backup_dir.to_str().unwrap().contains("vaultclaw"));
    }

    #[test]
    fn test_default_backup_dir() {
        let dir = default_backup_dir();
        assert!(dir.to_str().unwrap().contains("backups"));
    }

    #[test]
    fn test_backup_roundtrip() {
        let dir = TempDir::new().unwrap();
        let vault_path = create_test_vault(dir.path());
        let backup_dir = dir.path().join("backups");

        // Add an entry to the vault
        let password = password_secret("testpass".to_string());
        let mut vault = VaultFile::open(&vault_path, &password).unwrap();
        let entry = crate::vault::entry::Entry::new(
            "Test Entry".to_string(),
            crate::vault::entry::Credential::Login(crate::vault::entry::LoginCredential {
                url: "https://example.com".to_string(),
                username: "user".to_string(),
                password: "password123".to_string(),
            }),
        );
        vault.store_mut().add(entry);
        vault.save().unwrap();
        let original_count = vault.store().len();
        drop(vault);

        // Create backup
        let backup = create_backup(&vault_path, &backup_dir).unwrap();

        // Delete original, restore from backup
        std::fs::remove_file(&vault_path).unwrap();
        restore_backup(&backup.path, &vault_path).unwrap();

        // Open restored vault and verify
        let restored = VaultFile::open(&vault_path, &password).unwrap();
        assert_eq!(restored.store().len(), original_count);
    }

    #[test]
    fn test_backup_error_display() {
        let e = BackupError::VaultNotFound("/tmp/test.vclaw".into());
        assert!(e.to_string().contains("/tmp/test.vclaw"));

        let e = BackupError::BackupNotFound("/tmp/backup.vclaw.backup".into());
        assert!(e.to_string().contains("Backup file not found"));
    }

    #[test]
    fn test_backup_info_serialization() {
        let info = BackupInfo {
            filename: "test.vclaw.backup".into(),
            path: PathBuf::from("/tmp/test.vclaw.backup"),
            created_at: Utc::now(),
            size_bytes: 1024,
            source_vault: "/tmp/test.vclaw".into(),
            vault_version: Some(3),
        };
        let json = serde_json::to_string(&info).unwrap();
        let parsed: BackupInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.filename, "test.vclaw.backup");
        assert_eq!(parsed.size_bytes, 1024);
    }

    #[test]
    fn test_verify_result_serialization() {
        let result = VerifyResult {
            valid: true,
            size_bytes: 2048,
            vault_version: Some(3),
            entry_count: Some(5),
            has_metadata: true,
            integrity_ok: true,
            error: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: VerifyResult = serde_json::from_str(&json).unwrap();
        assert!(parsed.valid);
        assert_eq!(parsed.entry_count, Some(5));
    }

    #[test]
    fn test_list_backups_ignores_non_backup_files() {
        let dir = TempDir::new().unwrap();
        let backup_dir = dir.path().join("backups");
        std::fs::create_dir_all(&backup_dir).unwrap();

        // Create non-backup files
        std::fs::write(backup_dir.join("notes.txt"), "not a backup").unwrap();
        std::fs::write(backup_dir.join("other.vclaw"), "not a backup").unwrap();

        // Create a real backup
        let vault_path = create_test_vault(dir.path());
        create_backup(&vault_path, &backup_dir).unwrap();

        let backups = list_backups(&backup_dir).unwrap();
        assert_eq!(backups.len(), 1); // Only the real backup
    }

    #[test]
    fn test_backup_config_serialization() {
        let config = BackupConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: BackupConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.max_backups, 10);
        assert!(parsed.auto_backup);
    }
}
