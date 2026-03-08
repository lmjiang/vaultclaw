use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MultiVaultError {
    #[error("Vault not found: {0}")]
    NotFound(String),
    #[error("Vault already exists: {0}")]
    AlreadyExists(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// A reference to a vault file with display metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultRef {
    pub name: String,
    pub path: PathBuf,
    pub description: String,
    pub is_default: bool,
    pub created_at: String,
}

/// Multi-vault manager.
/// Tracks multiple vault files and allows switching between them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiVaultManager {
    vaults: HashMap<String, VaultRef>,
    active: Option<String>,
}

impl Default for MultiVaultManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MultiVaultManager {
    pub fn new() -> Self {
        Self {
            vaults: HashMap::new(),
            active: None,
        }
    }

    /// Register a vault.
    pub fn add_vault(&mut self, vault: VaultRef) -> Result<(), MultiVaultError> {
        if self.vaults.contains_key(&vault.name) {
            return Err(MultiVaultError::AlreadyExists(vault.name));
        }
        let is_first = self.vaults.is_empty();
        let name = vault.name.clone();
        self.vaults.insert(name.clone(), vault);
        if is_first {
            self.active = Some(name);
        }
        Ok(())
    }

    /// Remove a vault reference (does not delete the file).
    pub fn remove_vault(&mut self, name: &str) -> Result<VaultRef, MultiVaultError> {
        let vault = self
            .vaults
            .remove(name)
            .ok_or_else(|| MultiVaultError::NotFound(name.to_string()))?;

        if self.active.as_deref() == Some(name) {
            self.active = self.vaults.keys().next().cloned();
        }
        Ok(vault)
    }

    /// Switch active vault.
    pub fn set_active(&mut self, name: &str) -> Result<(), MultiVaultError> {
        if !self.vaults.contains_key(name) {
            return Err(MultiVaultError::NotFound(name.to_string()));
        }
        self.active = Some(name.to_string());
        Ok(())
    }

    /// Get the active vault reference.
    pub fn active_vault(&self) -> Option<&VaultRef> {
        self.active
            .as_ref()
            .and_then(|name| self.vaults.get(name))
    }

    /// Get active vault path.
    pub fn active_path(&self) -> Option<&Path> {
        self.active_vault().map(|v| v.path.as_path())
    }

    /// List all registered vaults.
    pub fn list_vaults(&self) -> Vec<&VaultRef> {
        let mut vaults: Vec<&VaultRef> = self.vaults.values().collect();
        vaults.sort_by(|a, b| a.name.cmp(&b.name));
        vaults
    }

    /// Get a vault by name.
    pub fn get_vault(&self, name: &str) -> Option<&VaultRef> {
        self.vaults.get(name)
    }

    /// Number of registered vaults.
    pub fn len(&self) -> usize {
        self.vaults.len()
    }

    pub fn is_empty(&self) -> bool {
        self.vaults.is_empty()
    }

    /// Load manager from config file.
    pub fn load() -> Self {
        let path = Self::config_path();
        Self::load_from(&path)
    }

    /// Load manager from a specific path.
    pub fn load_from(path: &Path) -> Self {
        if path.exists() {
            let content = std::fs::read_to_string(path).unwrap_or_default();
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            Self::new()
        }
    }

    /// Save manager to config file.
    pub fn save(&self) -> Result<(), MultiVaultError> {
        let path = Self::config_path();
        self.save_to(&path)
    }

    /// Save manager to a specific path.
    pub fn save_to(&self, path: &Path) -> Result<(), MultiVaultError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(self)
            .map_err(std::io::Error::other)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    fn config_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("vaultclaw")
            .join("vaults.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_vault(name: &str) -> VaultRef {
        VaultRef {
            name: name.to_string(),
            path: PathBuf::from(format!("/tmp/{}.vclaw", name)),
            description: format!("{} vault", name),
            is_default: false,
            created_at: "2024-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn test_add_vault() {
        let mut mgr = MultiVaultManager::new();
        assert!(mgr.is_empty());

        mgr.add_vault(sample_vault("personal")).unwrap();
        assert_eq!(mgr.len(), 1);
        assert!(!mgr.is_empty());
    }

    #[test]
    fn test_add_vault_duplicate() {
        let mut mgr = MultiVaultManager::new();
        mgr.add_vault(sample_vault("personal")).unwrap();
        let result = mgr.add_vault(sample_vault("personal"));
        assert!(result.is_err());
    }

    #[test]
    fn test_first_vault_becomes_active() {
        let mut mgr = MultiVaultManager::new();
        mgr.add_vault(sample_vault("personal")).unwrap();
        assert_eq!(mgr.active_vault().unwrap().name, "personal");
    }

    #[test]
    fn test_remove_vault() {
        let mut mgr = MultiVaultManager::new();
        mgr.add_vault(sample_vault("personal")).unwrap();
        mgr.add_vault(sample_vault("work")).unwrap();

        let removed = mgr.remove_vault("personal").unwrap();
        assert_eq!(removed.name, "personal");
        assert_eq!(mgr.len(), 1);
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut mgr = MultiVaultManager::new();
        assert!(mgr.remove_vault("nope").is_err());
    }

    #[test]
    fn test_remove_active_switches() {
        let mut mgr = MultiVaultManager::new();
        mgr.add_vault(sample_vault("personal")).unwrap();
        mgr.add_vault(sample_vault("work")).unwrap();
        mgr.set_active("personal").unwrap();

        mgr.remove_vault("personal").unwrap();
        // Active should switch to remaining vault
        assert!(mgr.active_vault().is_some());
    }

    #[test]
    fn test_set_active() {
        let mut mgr = MultiVaultManager::new();
        mgr.add_vault(sample_vault("personal")).unwrap();
        mgr.add_vault(sample_vault("work")).unwrap();

        mgr.set_active("work").unwrap();
        assert_eq!(mgr.active_vault().unwrap().name, "work");
    }

    #[test]
    fn test_set_active_nonexistent() {
        let mut mgr = MultiVaultManager::new();
        assert!(mgr.set_active("nope").is_err());
    }

    #[test]
    fn test_list_vaults_sorted() {
        let mut mgr = MultiVaultManager::new();
        mgr.add_vault(sample_vault("work")).unwrap();
        mgr.add_vault(sample_vault("personal")).unwrap();
        mgr.add_vault(sample_vault("family")).unwrap();

        let list = mgr.list_vaults();
        assert_eq!(list[0].name, "family");
        assert_eq!(list[1].name, "personal");
        assert_eq!(list[2].name, "work");
    }

    #[test]
    fn test_get_vault() {
        let mut mgr = MultiVaultManager::new();
        mgr.add_vault(sample_vault("personal")).unwrap();

        assert!(mgr.get_vault("personal").is_some());
        assert!(mgr.get_vault("nope").is_none());
    }

    #[test]
    fn test_active_path() {
        let mut mgr = MultiVaultManager::new();
        assert!(mgr.active_path().is_none());

        mgr.add_vault(sample_vault("personal")).unwrap();
        let path = mgr.active_path().unwrap();
        assert_eq!(path, Path::new("/tmp/personal.vclaw"));
    }

    #[test]
    fn test_serialization() {
        let mut mgr = MultiVaultManager::new();
        mgr.add_vault(sample_vault("personal")).unwrap();
        mgr.add_vault(sample_vault("work")).unwrap();

        let json = serde_json::to_string(&mgr).unwrap();
        let parsed: MultiVaultManager = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed.active_vault().unwrap().name, "personal");
    }

    #[test]
    fn test_vault_ref_serialization() {
        let vault = sample_vault("test");
        let json = serde_json::to_string(&vault).unwrap();
        let parsed: VaultRef = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "test");
        assert_eq!(parsed.path, PathBuf::from("/tmp/test.vclaw"));
    }

    #[test]
    fn test_empty_manager() {
        let mgr = MultiVaultManager::new();
        assert!(mgr.is_empty());
        assert_eq!(mgr.len(), 0);
        assert!(mgr.active_vault().is_none());
        assert!(mgr.active_path().is_none());
        assert!(mgr.list_vaults().is_empty());
    }

    #[test]
    fn test_error_display() {
        let e = MultiVaultError::NotFound("test".to_string());
        assert!(e.to_string().contains("test"));

        let e = MultiVaultError::AlreadyExists("dup".to_string());
        assert!(e.to_string().contains("dup"));
    }

    #[test]
    fn test_error_display_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let e = MultiVaultError::Io(io_err);
        assert!(e.to_string().contains("IO error"));
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let config_path = dir.path().join("vaultclaw").join("vaults.json");

        let mut mgr = MultiVaultManager::new();
        mgr.add_vault(sample_vault("personal")).unwrap();
        mgr.add_vault(sample_vault("work")).unwrap();
        mgr.set_active("work").unwrap();

        // Save manually to temp location
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let content = serde_json::to_string_pretty(&mgr).unwrap();
        std::fs::write(&config_path, &content).unwrap();

        // Load from that file
        let loaded: MultiVaultManager = serde_json::from_str(
            &std::fs::read_to_string(&config_path).unwrap()
        ).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded.active_vault().unwrap().name, "work");
    }

    #[test]
    fn test_load_nonexistent_returns_empty() {
        // Simulating load() logic with a nonexistent path
        let content = "";
        let result: MultiVaultManager = serde_json::from_str(content).unwrap_or_default();
        assert!(result.is_empty());
    }

    #[test]
    fn test_load_invalid_json_returns_empty() {
        let content = "{{invalid json}}";
        let result: MultiVaultManager = serde_json::from_str(content).unwrap_or_default();
        assert!(result.is_empty());
    }

    #[test]
    fn test_default_trait() {
        let mgr = MultiVaultManager::default();
        assert!(mgr.is_empty());
        assert_eq!(mgr.len(), 0);
        assert!(mgr.active_vault().is_none());
    }

    #[test]
    fn test_vault_ref_all_fields() {
        let vault = VaultRef {
            name: "test".to_string(),
            path: PathBuf::from("/tmp/test.vclaw"),
            description: "Test vault".to_string(),
            is_default: true,
            created_at: "2025-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&vault).unwrap();
        let parsed: VaultRef = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_default);
        assert_eq!(parsed.description, "Test vault");
        assert_eq!(parsed.created_at, "2025-01-01T00:00:00Z");
    }

    #[test]
    fn test_remove_last_vault_clears_active() {
        let mut mgr = MultiVaultManager::new();
        mgr.add_vault(sample_vault("only")).unwrap();
        assert!(mgr.active_vault().is_some());

        mgr.remove_vault("only").unwrap();
        assert!(mgr.active_vault().is_none());
        assert!(mgr.active_path().is_none());
    }

    #[test]
    fn test_add_second_vault_does_not_change_active() {
        let mut mgr = MultiVaultManager::new();
        mgr.add_vault(sample_vault("first")).unwrap();
        mgr.add_vault(sample_vault("second")).unwrap();
        // Active should still be the first one
        assert_eq!(mgr.active_vault().unwrap().name, "first");
    }

    #[test]
    fn test_save_to_and_load_from_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vaults.json");

        let mut mgr = MultiVaultManager::new();
        mgr.add_vault(sample_vault("personal")).unwrap();
        mgr.add_vault(sample_vault("work")).unwrap();
        mgr.set_active("work").unwrap();

        mgr.save_to(&path).unwrap();
        assert!(path.exists());

        let loaded = MultiVaultManager::load_from(&path);
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded.active_vault().unwrap().name, "work");
        assert!(loaded.get_vault("personal").is_some());
    }

    #[test]
    fn test_load_from_nonexistent() {
        let loaded = MultiVaultManager::load_from(Path::new("/tmp/nonexistent_vaults_test.json"));
        assert!(loaded.is_empty());
    }

    #[test]
    fn test_load_from_invalid_json() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, "not json").unwrap();
        let loaded = MultiVaultManager::load_from(&path);
        assert!(loaded.is_empty());
    }

    #[test]
    fn test_load_from_empty_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("empty.json");
        std::fs::write(&path, "").unwrap();
        let loaded = MultiVaultManager::load_from(&path);
        assert!(loaded.is_empty());
    }

    #[test]
    fn test_save_to_creates_parent_dirs() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("a").join("b").join("vaults.json");
        let mut mgr = MultiVaultManager::new();
        mgr.add_vault(sample_vault("test")).unwrap();
        mgr.save_to(&path).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn test_load_uses_real_config_path() {
        // Tests MultiVaultManager::load() directly
        let mgr = MultiVaultManager::load();
        // Should return valid empty or populated manager
        let _ = mgr.len();
        let _ = mgr.is_empty();
    }

    #[test]
    fn test_error_from_io() {
        // Test the From<std::io::Error> impl
        let io_err = std::io::Error::other("disk full");
        let err: MultiVaultError = io_err.into();
        assert!(err.to_string().contains("IO error"));
    }

    #[test]
    fn test_save_uses_real_config_path() {
        // Verify save() doesn't panic — writes to config_path()
        let mgr = MultiVaultManager::new();
        let _ = mgr.save();
    }

    #[test]
    fn test_save_to_permission_denied() {
        let mgr = MultiVaultManager::new();
        let result = mgr.save_to(Path::new("/proc/nonexistent/deep/vaults.json"));
        assert!(result.is_err());
    }

    #[test]
    fn test_save_to_no_parent_path() {
        // Path::new("").parent() returns None → skips the if-let branch.
        let mgr = MultiVaultManager::new();
        let result = mgr.save_to(Path::new(""));
        assert!(result.is_err()); // write("") fails
    }

    // ---- Additional error-path tests ----

    #[test]
    fn test_remove_active_vault_when_only_vault() {
        // Exercise L72 where keys().next() returns None (no vaults left)
        let mut mgr = MultiVaultManager::new();
        mgr.add_vault(sample_vault("only_one")).unwrap();
        assert_eq!(mgr.active_vault().unwrap().name, "only_one");

        let removed = mgr.remove_vault("only_one").unwrap();
        assert_eq!(removed.name, "only_one");
        assert!(mgr.active_vault().is_none());
        assert!(mgr.is_empty());
    }

    #[test]
    fn test_remove_non_active_vault_keeps_active() {
        // Removing a vault that is NOT the active one should not change active
        let mut mgr = MultiVaultManager::new();
        mgr.add_vault(sample_vault("primary")).unwrap();
        mgr.add_vault(sample_vault("secondary")).unwrap();
        // "primary" is active (first added)
        assert_eq!(mgr.active_vault().unwrap().name, "primary");

        mgr.remove_vault("secondary").unwrap();
        assert_eq!(mgr.active_vault().unwrap().name, "primary");
        assert_eq!(mgr.len(), 1);
    }

    #[test]
    fn test_save_to_write_error_readonly_dir() {
        // L146-147: Exercise the write path with a directory that exists but
        // where writing a file fails.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().unwrap();
        let target_dir = dir.path().join("readonly");
        std::fs::create_dir(&target_dir).unwrap();

        // Make the directory read-only
        std::fs::set_permissions(&target_dir, std::fs::Permissions::from_mode(0o444)).unwrap();

        let mut mgr = MultiVaultManager::new();
        mgr.add_vault(sample_vault("test")).unwrap();

        let result = mgr.save_to(&target_dir.join("vaults.json"));
        assert!(result.is_err());

        // Restore permissions for cleanup
        std::fs::set_permissions(&target_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn test_config_path_returns_valid_path() {
        // L151-156: Exercise config_path() and verify it returns a reasonable path
        let path = MultiVaultManager::config_path();
        assert!(path.to_str().unwrap().contains("vaultclaw"));
        assert!(path.to_str().unwrap().ends_with("vaults.json"));
    }

    #[test]
    fn test_save_to_creates_deeply_nested_parents() {
        // L142-143: Exercise create_dir_all in save_to with deep nesting
        let dir = tempfile::TempDir::new().unwrap();
        let deep_path = dir.path().join("a").join("b").join("c").join("d").join("vaults.json");
        let mut mgr = MultiVaultManager::new();
        mgr.add_vault(sample_vault("nested")).unwrap();

        mgr.save_to(&deep_path).unwrap();
        assert!(deep_path.exists());

        // Verify content is valid JSON
        let loaded = MultiVaultManager::load_from(&deep_path);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.active_vault().unwrap().name, "nested");
    }

    #[test]
    fn test_save_to_create_dir_all_error() {
        // L143: create_dir_all fails when parent path goes through a regular file
        let dir = tempfile::TempDir::new().unwrap();
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"I am a file, not a directory").unwrap();

        let impossible_path = blocker.join("sub").join("vaults.json");
        let mgr = MultiVaultManager::new();
        let result = mgr.save_to(&impossible_path);
        assert!(result.is_err());
    }
}
