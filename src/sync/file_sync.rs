use std::path::{Path, PathBuf};

use super::provider::*;
use crate::vault::sqlite_store::SqliteBackend;

/// File-based sync provider.
/// Copies vault file to/from a directory (iCloud Drive, Syncthing folder, USB drive, etc.).
pub struct FileSyncProvider {
    remote_dir: PathBuf,
    vault_filename: String,
}

impl FileSyncProvider {
    pub fn new(remote_dir: PathBuf, vault_filename: String) -> Self {
        Self {
            remote_dir,
            vault_filename,
        }
    }

    fn remote_path(&self) -> PathBuf {
        self.remote_dir.join(&self.vault_filename)
    }
}

impl SyncProvider for FileSyncProvider {
    fn name(&self) -> &str {
        "file"
    }

    fn is_available(&self) -> Result<bool, SyncError> {
        Ok(self.remote_dir.exists() && self.remote_dir.is_dir())
    }

    fn remote_metadata(&self) -> Result<Option<VaultMetadata>, SyncError> {
        let path = self.remote_path();
        if !path.exists() {
            return Ok(None);
        }
        local_metadata(&path).map(Some)
    }

    fn push(&self, local_path: &Path) -> Result<SyncResult, SyncError> {
        if !self.remote_dir.exists() {
            std::fs::create_dir_all(&self.remote_dir)?;
        }

        // Checkpoint WAL before copying if this is a SQLite vault
        if SqliteBackend::is_sqlite_file(local_path) {
            if let Ok(db) = SqliteBackend::open(local_path) {
                let _ = db.checkpoint();
            }
        }

        let remote_path = self.remote_path();
        let local_meta = std::fs::metadata(local_path)?;
        let size = local_meta.len();

        // Atomic copy: write to temp file, then rename
        let tmp_path = remote_path.with_extension("vclaw.tmp");
        std::fs::copy(local_path, &tmp_path)?;
        std::fs::rename(&tmp_path, &remote_path)?;

        Ok(SyncResult {
            direction: SyncDirection::Push,
            bytes_transferred: size,
            success: true,
            message: format!("Pushed {} bytes to {}", size, remote_path.display()),
        })
    }

    fn pull(&self, local_path: &Path) -> Result<SyncResult, SyncError> {
        let remote_path = self.remote_path();
        if !remote_path.exists() {
            return Err(SyncError::Unavailable("Remote vault file not found".into()));
        }

        let remote_meta = std::fs::metadata(&remote_path)?;
        let size = remote_meta.len();

        // Atomic copy: write to temp file, then rename
        let tmp_path = local_path.with_extension("vclaw.tmp");
        std::fs::copy(&remote_path, &tmp_path)?;
        std::fs::rename(&tmp_path, local_path)?;

        Ok(SyncResult {
            direction: SyncDirection::Pull,
            bytes_transferred: size,
            success: true,
            message: format!("Pulled {} bytes from {}", size, remote_path.display()),
        })
    }
}

/// Convenience: sync a vault file to/from a remote directory.
pub fn sync_vault(
    local_path: &Path,
    remote_dir: &Path,
) -> Result<SyncResult, SyncError> {
    let filename = local_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let provider = FileSyncProvider::new(remote_dir.to_path_buf(), filename);

    if !provider.is_available()? {
        return Err(SyncError::Unavailable(
            format!("Remote directory not found: {}", remote_dir.display()),
        ));
    }

    let local_meta = local_metadata(local_path)?;

    match provider.remote_metadata()? {
        Some(remote_meta) => {
            match determine_sync_direction(&local_meta, &remote_meta)? {
                Some(SyncDirection::Push) => provider.push(local_path),
                Some(SyncDirection::Pull) => provider.pull(local_path),
                _ => Ok(SyncResult {
                    direction: SyncDirection::Bidirectional,
                    bytes_transferred: 0,
                    success: true,
                    message: "Already in sync".to_string(),
                }),
            }
        }
        None => {
            // Remote doesn't exist yet, push
            provider.push(local_path)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup() -> (TempDir, TempDir, PathBuf) {
        let local_dir = TempDir::new().unwrap();
        let remote_dir = TempDir::new().unwrap();
        let local_path = local_dir.path().join("test.vclaw");
        std::fs::write(&local_path, b"vault data version 1").unwrap();
        (local_dir, remote_dir, local_path)
    }

    #[test]
    fn test_file_sync_provider_name() {
        let provider = FileSyncProvider::new(PathBuf::from("/tmp"), "test.vclaw".to_string());
        assert_eq!(provider.name(), "file");
    }

    #[test]
    fn test_file_sync_available() {
        let dir = TempDir::new().unwrap();
        let provider = FileSyncProvider::new(dir.path().to_path_buf(), "test.vclaw".to_string());
        assert!(provider.is_available().unwrap());
    }

    #[test]
    fn test_file_sync_unavailable() {
        let provider = FileSyncProvider::new(
            PathBuf::from("/nonexistent/path/that/should/not/exist"),
            "test.vclaw".to_string(),
        );
        assert!(!provider.is_available().unwrap());
    }

    #[test]
    fn test_file_sync_remote_metadata_none() {
        let dir = TempDir::new().unwrap();
        let provider = FileSyncProvider::new(dir.path().to_path_buf(), "test.vclaw".to_string());
        assert!(provider.remote_metadata().unwrap().is_none());
    }

    #[test]
    fn test_file_sync_push() {
        let (_local_dir, remote_dir, local_path) = setup();
        let provider = FileSyncProvider::new(
            remote_dir.path().to_path_buf(),
            "test.vclaw".to_string(),
        );

        let result = provider.push(&local_path).unwrap();
        assert!(result.success);
        assert_eq!(result.direction, SyncDirection::Push);
        assert!(result.bytes_transferred > 0);

        // Verify remote file exists
        let remote_path = remote_dir.path().join("test.vclaw");
        assert!(remote_path.exists());
        assert_eq!(
            std::fs::read(&remote_path).unwrap(),
            b"vault data version 1"
        );
    }

    #[test]
    fn test_file_sync_pull() {
        let (local_dir, remote_dir, _) = setup();
        // Write file with the same name that the provider expects
        let remote_path = remote_dir.path().join("pulled.vclaw");
        std::fs::write(&remote_path, b"vault data from remote").unwrap();

        let local_path = local_dir.path().join("pulled.vclaw");
        // Create a placeholder local file
        std::fs::write(&local_path, b"old").unwrap();

        let provider = FileSyncProvider::new(
            remote_dir.path().to_path_buf(),
            "pulled.vclaw".to_string(),
        );

        let result = provider.pull(&local_path).unwrap();
        assert!(result.success);
        assert_eq!(result.direction, SyncDirection::Pull);
        assert_eq!(
            std::fs::read(&local_path).unwrap(),
            b"vault data from remote"
        );
    }

    #[test]
    fn test_file_sync_pull_no_remote() {
        let dir = TempDir::new().unwrap();
        let local_path = dir.path().join("local.vclaw");
        let provider = FileSyncProvider::new(dir.path().to_path_buf(), "remote.vclaw".to_string());

        let result = provider.pull(&local_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_sync_vault_first_push() {
        let (_local_dir, remote_dir, local_path) = setup();
        let result = sync_vault(&local_path, remote_dir.path()).unwrap();
        assert!(result.success);
        assert_eq!(result.direction, SyncDirection::Push);

        // Remote file should now exist
        let remote_path = remote_dir.path().join("test.vclaw");
        assert!(remote_path.exists());
    }

    #[test]
    fn test_sync_vault_already_synced() {
        let (_local_dir, remote_dir, local_path) = setup();

        // Push first
        sync_vault(&local_path, remote_dir.path()).unwrap();

        // Sync again — should be "already in sync"
        let result = sync_vault(&local_path, remote_dir.path()).unwrap();
        assert!(result.success);
        assert_eq!(result.bytes_transferred, 0);
        assert!(result.message.contains("sync"));
    }

    #[test]
    fn test_sync_vault_remote_newer() {
        let (_local_dir, remote_dir, local_path) = setup();

        // Push first
        sync_vault(&local_path, remote_dir.path()).unwrap();

        // Wait >1s to ensure filesystem timestamp changes (macOS has 1s granularity)
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let remote_path = remote_dir.path().join("test.vclaw");
        std::fs::write(&remote_path, b"vault data version 2 from remote").unwrap();

        // Sync should pull
        let result = sync_vault(&local_path, remote_dir.path()).unwrap();
        assert!(result.success);
        assert_eq!(result.direction, SyncDirection::Pull);
        assert_eq!(
            std::fs::read(&local_path).unwrap(),
            b"vault data version 2 from remote"
        );
    }

    #[test]
    fn test_sync_vault_local_newer() {
        let (_local_dir, remote_dir, local_path) = setup();

        // Write remote file first (older)
        let remote_path = remote_dir.path().join("test.vclaw");
        std::fs::write(&remote_path, b"old remote data").unwrap();

        // Wait >1s to ensure filesystem timestamp changes (macOS has 1s granularity)
        std::thread::sleep(std::time::Duration::from_millis(1100));
        std::fs::write(&local_path, b"newer local data").unwrap();

        // Sync should push
        let result = sync_vault(&local_path, remote_dir.path()).unwrap();
        assert!(result.success);
        assert_eq!(result.direction, SyncDirection::Push);
        assert_eq!(
            std::fs::read(&remote_path).unwrap(),
            b"newer local data"
        );
    }

    #[test]
    fn test_sync_vault_unavailable() {
        let dir = TempDir::new().unwrap();
        let local_path = dir.path().join("test.vclaw");
        std::fs::write(&local_path, b"data").unwrap();

        let result = sync_vault(&local_path, Path::new("/nonexistent/sync/dir"));
        assert!(result.is_err());
    }

    #[test]
    fn test_push_creates_remote_dir() {
        let local_dir = TempDir::new().unwrap();
        let local_path = local_dir.path().join("test.vclaw");
        std::fs::write(&local_path, b"data").unwrap();

        let remote_base = TempDir::new().unwrap();
        let nested_remote = remote_base.path().join("sub").join("dir");

        let provider = FileSyncProvider::new(nested_remote.clone(), "test.vclaw".to_string());
        let result = provider.push(&local_path).unwrap();
        assert!(result.success);
        assert!(nested_remote.join("test.vclaw").exists());
    }

    #[test]
    fn test_remote_metadata_after_push() {
        let (_local_dir, remote_dir, local_path) = setup();
        let provider = FileSyncProvider::new(
            remote_dir.path().to_path_buf(),
            "test.vclaw".to_string(),
        );

        assert!(provider.remote_metadata().unwrap().is_none());
        provider.push(&local_path).unwrap();

        let meta = provider.remote_metadata().unwrap().unwrap();
        assert!(meta.size > 0);
        assert!(!meta.checksum.is_empty());
    }

    // ---- Error-path tests for push() ----

    #[test]
    fn test_push_metadata_error_nonexistent_local_file() {
        // L48: std::fs::metadata(local_path)? should fail when local file doesn't exist
        let remote_dir = TempDir::new().unwrap();
        let provider = FileSyncProvider::new(
            remote_dir.path().to_path_buf(),
            "test.vclaw".to_string(),
        );
        let nonexistent = PathBuf::from("/tmp/vaultclaw_test_nonexistent_file.vclaw");
        let result = provider.push(&nonexistent);
        assert!(matches!(result.unwrap_err(), SyncError::Io(ref e) if e.kind() == std::io::ErrorKind::NotFound));
    }

    #[test]
    fn test_push_create_dir_all_error() {
        // L44: create_dir_all error when remote_dir is under an unwritable/impossible path.
        // On macOS/Linux, /proc or /sys are not writable.
        // Use a path nested under a file (not a directory) so create_dir_all fails.
        let tmp = TempDir::new().unwrap();
        let blocking_file = tmp.path().join("blocker");
        std::fs::write(&blocking_file, b"I am a file").unwrap();

        // remote_dir points *through* a regular file, so create_dir_all will fail
        let impossible_dir = blocking_file.join("subdir");
        let provider = FileSyncProvider::new(impossible_dir, "test.vclaw".to_string());

        let local_file = tmp.path().join("local.vclaw");
        std::fs::write(&local_file, b"data").unwrap();

        let result = provider.push(&local_file);
        assert!(result.is_err());
    }

    #[test]
    fn test_push_copy_error_source_vanishes() {
        // L53: copy error — create the source, get provider ready, delete source, then push.
        // The metadata call (L48) needs a real file, so we delete after creating
        // but before the copy happens. Since operations are sequential, we simulate
        // by pointing to a file that doesn't exist after metadata would be checked.
        // Actually, since push reads metadata then copies in sequence, the simplest
        // approach is to test with a file that disappears. But that's racy.
        // Instead, test copy error by making the destination directory read-only.
        let local_dir = TempDir::new().unwrap();
        let remote_dir = TempDir::new().unwrap();
        let local_path = local_dir.path().join("test.vclaw");
        std::fs::write(&local_path, b"vault data").unwrap();

        // Make remote_dir read-only so copy into it fails
        let mut perms = std::fs::metadata(remote_dir.path()).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        {
            perms.set_readonly(true);
        }
        std::fs::set_permissions(remote_dir.path(), perms.clone()).unwrap();

        let provider = FileSyncProvider::new(
            remote_dir.path().to_path_buf(),
            "test.vclaw".to_string(),
        );
        let result = provider.push(&local_path);
        assert!(result.is_err());

        // Restore permissions so TempDir cleanup works
        use std::os::unix::fs::PermissionsExt as _;
        perms.set_mode(0o755);
        std::fs::set_permissions(remote_dir.path(), perms).unwrap();
    }

    // ---- Error-path tests for pull() ----

    #[test]
    fn test_pull_metadata_error_unreadable_remote() {
        // L70: std::fs::metadata(&remote_path)? fails.
        // Create the remote file, then make it unreadable.
        let remote_dir = TempDir::new().unwrap();
        let remote_path = remote_dir.path().join("test.vclaw");
        std::fs::write(&remote_path, b"data").unwrap();

        // Remove all permissions from the remote file
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o000);
        std::fs::set_permissions(&remote_path, perms).unwrap();

        // Even though file exists (pull won't hit L67 early return),
        // metadata should still succeed on most Unix systems since metadata
        // only needs directory read. But copy will fail on the file.
        // So this tests L75 (copy error) more naturally.
        let local_dir = TempDir::new().unwrap();
        let local_path = local_dir.path().join("test.vclaw");
        let provider = FileSyncProvider::new(
            remote_dir.path().to_path_buf(),
            "test.vclaw".to_string(),
        );
        let result = provider.pull(&local_path);
        // On most systems, metadata() succeeds but copy fails due to no read permission
        assert!(result.is_err());

        // Restore permissions for cleanup
        let perms = std::fs::Permissions::from_mode(0o644);
        std::fs::set_permissions(&remote_path, perms).unwrap();
    }

    #[test]
    fn test_pull_copy_error_readonly_destination() {
        // L75: copy error when local destination directory is read-only
        let remote_dir = TempDir::new().unwrap();
        let remote_path = remote_dir.path().join("test.vclaw");
        std::fs::write(&remote_path, b"remote data").unwrap();

        let local_dir = TempDir::new().unwrap();
        let local_path = local_dir.path().join("test.vclaw");

        // Make local_dir read-only so writing the temp file fails
        let mut perms = std::fs::metadata(local_dir.path()).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(local_dir.path(), perms.clone()).unwrap();

        let provider = FileSyncProvider::new(
            remote_dir.path().to_path_buf(),
            "test.vclaw".to_string(),
        );
        let result = provider.pull(&local_path);
        assert!(result.is_err());

        // Restore permissions for cleanup
        use std::os::unix::fs::PermissionsExt as _;
        perms.set_mode(0o755);
        std::fs::set_permissions(local_dir.path(), perms).unwrap();
    }

    // ---- Error-path tests for sync_vault() ----

    #[test]
    fn test_sync_vault_local_metadata_error_nonexistent_local() {
        // L106: local_metadata(local_path)? fails when local file doesn't exist
        // but remote dir does exist (so is_available passes)
        let remote_dir = TempDir::new().unwrap();
        let nonexistent_local = PathBuf::from("/tmp/vaultclaw_does_not_exist_test.vclaw");

        let result = sync_vault(&nonexistent_local, remote_dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_sync_vault_determine_direction_conflict() {
        // L110: determine_sync_direction returns Err(Conflict)
        // This happens when checksums differ but timestamps are equal.
        // We need local and remote to have the same mtime but different content.
        let local_dir = TempDir::new().unwrap();
        let remote_dir = TempDir::new().unwrap();

        let local_path = local_dir.path().join("test.vclaw");
        let remote_path = remote_dir.path().join("test.vclaw");

        // Write different content
        std::fs::write(&local_path, b"local content AAA").unwrap();
        std::fs::write(&remote_path, b"remote content BBB").unwrap();

        // Set both files to the exact same modification time
        use std::time::{Duration, UNIX_EPOCH};
        let fixed_time = filetime::FileTime::from_system_time(
            UNIX_EPOCH + Duration::from_secs(1_700_000_000)
        );
        filetime::set_file_mtime(&local_path, fixed_time).unwrap();
        filetime::set_file_mtime(&remote_path, fixed_time).unwrap();

        let result = sync_vault(&local_path, remote_dir.path());
        assert!(matches!(result.unwrap_err(), SyncError::Conflict { .. }));
    }
}
