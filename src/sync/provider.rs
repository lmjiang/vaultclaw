use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Conflict detected: local and remote have diverged")]
    Conflict {
        local_modified: u64,
        remote_modified: u64,
    },
    #[error("Remote not available: {0}")]
    Unavailable(String),
    #[error("HTTP error: {0}")]
    Http(String),
}

/// Metadata about a vault file for sync comparison.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VaultMetadata {
    pub path: String,
    pub size: u64,
    pub modified_timestamp: u64,
    pub checksum: String,
}

/// Sync direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncDirection {
    Push,
    Pull,
    Bidirectional,
}

/// Result of a sync operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResult {
    pub direction: SyncDirection,
    pub bytes_transferred: u64,
    pub success: bool,
    pub message: String,
}

/// Trait for vault sync providers.
/// Implementations handle different sync backends (file copy, WebDAV, etc.).
pub trait SyncProvider: Send + Sync {
    /// Name of this sync provider.
    fn name(&self) -> &str;

    /// Check if the remote is reachable.
    fn is_available(&self) -> Result<bool, SyncError>;

    /// Get metadata about the remote vault file.
    fn remote_metadata(&self) -> Result<Option<VaultMetadata>, SyncError>;

    /// Push local vault to remote.
    fn push(&self, local_path: &Path) -> Result<SyncResult, SyncError>;

    /// Pull remote vault to local.
    fn pull(&self, local_path: &Path) -> Result<SyncResult, SyncError>;
}

/// Compute a simple checksum (SHA-256) of a file.
pub fn file_checksum(path: &Path) -> Result<String, SyncError> {
    use sha2::{Sha256, Digest};
    let data = std::fs::read(path)?;
    let hash = Sha256::digest(&data);
    Ok(hex::encode(hash))
}

/// Get metadata for a local vault file.
pub fn local_metadata(path: &Path) -> Result<VaultMetadata, SyncError> {
    let metadata = std::fs::metadata(path)?;
    let modified = metadata
        .modified()?
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let checksum = file_checksum(path)?;

    Ok(VaultMetadata {
        path: path.display().to_string(),
        size: metadata.len(),
        modified_timestamp: modified,
        checksum,
    })
}

/// Determine sync direction based on metadata comparison.
pub fn determine_sync_direction(
    local: &VaultMetadata,
    remote: &VaultMetadata,
) -> Result<Option<SyncDirection>, SyncError> {
    if local.checksum == remote.checksum {
        return Ok(None); // Already in sync
    }

    if local.modified_timestamp > remote.modified_timestamp {
        Ok(Some(SyncDirection::Push))
    } else if remote.modified_timestamp > local.modified_timestamp {
        Ok(Some(SyncDirection::Pull))
    } else {
        // Same timestamp but different content — conflict
        Err(SyncError::Conflict {
            local_modified: local.modified_timestamp,
            remote_modified: remote.modified_timestamp,
        })
    }
}

/// Resolve the provider configuration path.
pub fn sync_config_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("vaultclaw")
        .join("sync.json")
}

/// Sync configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    pub provider: String,
    pub remote_path: String,
    pub auto_sync: bool,
    pub sync_interval_seconds: u64,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            provider: "file".to_string(),
            remote_path: String::new(),
            auto_sync: false,
            sync_interval_seconds: 300,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_file_checksum() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.bin");
        std::fs::write(&path, b"hello world").unwrap();

        let checksum = file_checksum(&path).unwrap();
        assert_eq!(checksum.len(), 64); // SHA-256 hex
        // Known SHA-256 of "hello world"
        assert_eq!(
            checksum,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_file_checksum_different_content() {
        let dir = TempDir::new().unwrap();
        let p1 = dir.path().join("a.bin");
        let p2 = dir.path().join("b.bin");
        std::fs::write(&p1, b"content a").unwrap();
        std::fs::write(&p2, b"content b").unwrap();

        assert_ne!(file_checksum(&p1).unwrap(), file_checksum(&p2).unwrap());
    }

    #[test]
    fn test_local_metadata() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.vclaw");
        std::fs::write(&path, b"vault data here").unwrap();

        let meta = local_metadata(&path).unwrap();
        assert_eq!(meta.size, 15);
        assert!(!meta.checksum.is_empty());
        assert!(meta.modified_timestamp > 0);
    }

    #[test]
    fn test_determine_sync_same() {
        let meta = VaultMetadata {
            path: "/vault.vclaw".to_string(),
            size: 100,
            modified_timestamp: 1000,
            checksum: "abc".to_string(),
        };
        let result = determine_sync_direction(&meta, &meta).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_determine_sync_push() {
        let local = VaultMetadata {
            path: "/local.vclaw".to_string(),
            size: 100,
            modified_timestamp: 2000,
            checksum: "newer".to_string(),
        };
        let remote = VaultMetadata {
            path: "/remote.vclaw".to_string(),
            size: 100,
            modified_timestamp: 1000,
            checksum: "older".to_string(),
        };
        let result = determine_sync_direction(&local, &remote).unwrap();
        assert_eq!(result, Some(SyncDirection::Push));
    }

    #[test]
    fn test_determine_sync_pull() {
        let local = VaultMetadata {
            path: "/local.vclaw".to_string(),
            size: 100,
            modified_timestamp: 1000,
            checksum: "older".to_string(),
        };
        let remote = VaultMetadata {
            path: "/remote.vclaw".to_string(),
            size: 100,
            modified_timestamp: 2000,
            checksum: "newer".to_string(),
        };
        let result = determine_sync_direction(&local, &remote).unwrap();
        assert_eq!(result, Some(SyncDirection::Pull));
    }

    #[test]
    fn test_determine_sync_conflict() {
        let local = VaultMetadata {
            path: "/local.vclaw".to_string(),
            size: 100,
            modified_timestamp: 1000,
            checksum: "different_a".to_string(),
        };
        let remote = VaultMetadata {
            path: "/remote.vclaw".to_string(),
            size: 100,
            modified_timestamp: 1000,
            checksum: "different_b".to_string(),
        };
        let result = determine_sync_direction(&local, &remote);
        assert!(matches!(result, Err(SyncError::Conflict { .. })));
    }

    #[test]
    fn test_sync_config_default() {
        let config = SyncConfig::default();
        assert_eq!(config.provider, "file");
        assert!(!config.auto_sync);
        assert_eq!(config.sync_interval_seconds, 300);
    }

    #[test]
    fn test_sync_config_serialization() {
        let config = SyncConfig {
            provider: "webdav".to_string(),
            remote_path: "https://dav.example.com/vault.vclaw".to_string(),
            auto_sync: true,
            sync_interval_seconds: 600,
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: SyncConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.provider, "webdav");
        assert!(parsed.auto_sync);
    }

    #[test]
    fn test_vault_metadata_serialization() {
        let meta = VaultMetadata {
            path: "/test.vclaw".to_string(),
            size: 1024,
            modified_timestamp: 1700000000,
            checksum: "abcdef".to_string(),
        };
        let json = serde_json::to_string(&meta).unwrap();
        let parsed: VaultMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, meta);
    }

    #[test]
    fn test_sync_result_serialization() {
        let result = SyncResult {
            direction: SyncDirection::Push,
            bytes_transferred: 4096,
            success: true,
            message: "Synced successfully".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: SyncResult = serde_json::from_str(&json).unwrap();
        assert!(parsed.success);
        assert_eq!(parsed.bytes_transferred, 4096);
    }

    #[test]
    fn test_sync_error_display() {
        let e = SyncError::Unavailable("server down".to_string());
        assert!(e.to_string().contains("server down"));

        let e = SyncError::Conflict {
            local_modified: 100,
            remote_modified: 200,
        };
        assert!(e.to_string().contains("Conflict"));
    }

    #[test]
    fn test_sync_error_display_http() {
        let e = SyncError::Http("connection refused".to_string());
        assert!(e.to_string().contains("HTTP error"));
        assert!(e.to_string().contains("connection refused"));
    }

    #[test]
    fn test_sync_error_display_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let e: SyncError = io_err.into();
        assert!(e.to_string().contains("IO error"));
    }

    #[test]
    fn test_sync_config_path() {
        let path = sync_config_path();
        assert!(path.to_str().unwrap().contains("vaultclaw"));
        assert!(path.to_str().unwrap().contains("sync.json"));
    }

    #[test]
    fn test_sync_direction_serialization() {
        let push = SyncDirection::Push;
        let json = serde_json::to_string(&push).unwrap();
        let parsed: SyncDirection = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, SyncDirection::Push);

        let pull = SyncDirection::Pull;
        let json = serde_json::to_string(&pull).unwrap();
        let parsed: SyncDirection = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, SyncDirection::Pull);

        let bidi = SyncDirection::Bidirectional;
        let json = serde_json::to_string(&bidi).unwrap();
        let parsed: SyncDirection = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, SyncDirection::Bidirectional);
    }

    // ---- Error-path tests for file_checksum() and local_metadata() ----

    #[test]
    fn test_file_checksum_nonexistent_file() {
        // L69: std::fs::read(path)? should return Io error
        let result = file_checksum(Path::new("/tmp/vaultclaw_nonexistent_checksum_test.bin"));
        assert!(matches!(result.unwrap_err(), SyncError::Io(ref e) if e.kind() == std::io::ErrorKind::NotFound));
    }

    #[test]
    fn test_local_metadata_nonexistent_file() {
        // L76: std::fs::metadata(path)? should return Io error
        let result = local_metadata(Path::new("/tmp/vaultclaw_nonexistent_meta_test.vclaw"));
        assert!(matches!(result.unwrap_err(), SyncError::Io(ref e) if e.kind() == std::io::ErrorKind::NotFound));
    }

    #[test]
    fn test_file_checksum_permission_denied() {
        // L69: std::fs::read(path)? should fail with permission denied
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("noperm.bin");
        std::fs::write(&path, b"secret").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();

        let result = file_checksum(&path);
        assert!(matches!(result.unwrap_err(), SyncError::Io(ref e) if e.kind() == std::io::ErrorKind::PermissionDenied));

        // Restore permissions for cleanup
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    #[test]
    fn test_local_metadata_unreadable_file() {
        // L76 + L82: metadata() may succeed but file_checksum() (L82) will fail
        // because the file can't be read.
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("noperm.vclaw");
        std::fs::write(&path, b"vault data").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();

        let result = local_metadata(&path);
        // On macOS, metadata() on a 0o000 file can still succeed (stat doesn't need read),
        // but file_checksum (which does fs::read) will fail.
        assert!(result.is_err());

        // Restore permissions for cleanup
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    #[test]
    fn test_determine_sync_direction_both_none_checksum_match() {
        // Ensure None is returned when checksums match despite different timestamps
        let local = VaultMetadata {
            path: "/local.vclaw".to_string(),
            size: 100,
            modified_timestamp: 1000,
            checksum: "same_hash".to_string(),
        };
        let remote = VaultMetadata {
            path: "/remote.vclaw".to_string(),
            size: 100,
            modified_timestamp: 2000,
            checksum: "same_hash".to_string(),
        };
        let result = determine_sync_direction(&local, &remote).unwrap();
        assert_eq!(result, None);
    }
}
