//! Auto-sync scheduler and sync history log.
//!
//! Manages periodic background sync operations and maintains a history of
//! sync events with timestamps, directions, and change counts.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use super::provider::{SyncConfig, SyncDirection, SyncResult};

/// A record of a completed sync operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncLogEntry {
    pub timestamp: DateTime<Utc>,
    pub direction: SyncDirection,
    pub bytes_transferred: u64,
    pub success: bool,
    pub message: String,
    pub provider: String,
    pub remote_path: String,
}

/// Sync status summary for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatus {
    pub configured: bool,
    pub auto_sync_enabled: bool,
    pub sync_interval_seconds: u64,
    pub last_sync: Option<SyncLogEntry>,
    pub last_sync_time: Option<String>,
    pub next_sync_time: Option<String>,
    pub pending_changes: bool,
    pub local_checksum: Option<String>,
    pub remote_checksum: Option<String>,
    pub config: Option<SyncConfig>,
}

/// Sync history: a log of recent sync operations.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SyncHistory {
    pub entries: Vec<SyncLogEntry>,
    pub max_entries: usize,
}

impl SyncHistory {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            max_entries: 100,
        }
    }

    /// Record a sync result in the history.
    pub fn record(
        &mut self,
        result: &SyncResult,
        provider: &str,
        remote_path: &str,
    ) {
        let entry = SyncLogEntry {
            timestamp: Utc::now(),
            direction: result.direction,
            bytes_transferred: result.bytes_transferred,
            success: result.success,
            message: result.message.clone(),
            provider: provider.to_string(),
            remote_path: remote_path.to_string(),
        };
        self.entries.push(entry);

        // Keep only the most recent entries
        if self.entries.len() > self.max_entries {
            self.entries.drain(..self.entries.len() - self.max_entries);
        }
    }

    /// Get the most recent sync entry.
    pub fn last_sync(&self) -> Option<&SyncLogEntry> {
        self.entries.last()
    }

    /// Get the last successful sync entry.
    pub fn last_successful_sync(&self) -> Option<&SyncLogEntry> {
        self.entries.iter().rev().find(|e| e.success)
    }

    /// Get entries since a given timestamp.
    pub fn entries_since(&self, since: DateTime<Utc>) -> Vec<&SyncLogEntry> {
        self.entries.iter().filter(|e| e.timestamp >= since).collect()
    }

    /// Count of successful/failed syncs.
    pub fn stats(&self) -> (usize, usize) {
        let success = self.entries.iter().filter(|e| e.success).count();
        let failed = self.entries.len() - success;
        (success, failed)
    }

    /// Load sync history from a file.
    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Save sync history to a file.
    pub fn save(&self, path: &Path) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(std::io::Error::other)?;
        std::fs::write(path, json)
    }
}

/// Resolve the path for the sync history file.
pub fn sync_history_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("vaultclaw")
        .join("sync_history.json")
}

/// Enhanced sync configuration with multi-target support.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncTarget {
    pub name: String,
    pub provider: String,
    pub remote_path: String,
    pub auto_sync: bool,
    pub sync_interval_seconds: u64,
    /// WebDAV-specific fields
    pub url: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Multi-target sync configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MultiSyncConfig {
    pub targets: Vec<SyncTarget>,
}

impl MultiSyncConfig {
    pub fn new() -> Self {
        Self {
            targets: Vec::new(),
        }
    }

    pub fn add_target(&mut self, target: SyncTarget) {
        // Replace existing target with same name
        self.targets.retain(|t| t.name != target.name);
        self.targets.push(target);
    }

    pub fn remove_target(&mut self, name: &str) -> bool {
        let before = self.targets.len();
        self.targets.retain(|t| t.name != name);
        self.targets.len() < before
    }

    pub fn get_target(&self, name: &str) -> Option<&SyncTarget> {
        self.targets.iter().find(|t| t.name == name)
    }

    pub fn auto_sync_targets(&self) -> Vec<&SyncTarget> {
        self.targets.iter().filter(|t| t.auto_sync).collect()
    }

    /// Load config from file.
    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Save config to file.
    pub fn save(&self, path: &Path) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(std::io::Error::other)?;
        std::fs::write(path, json)
    }
}

/// Resolve the path for the multi-sync config.
pub fn multi_sync_config_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("vaultclaw")
        .join("sync_targets.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_sync_history_new() {
        let history = SyncHistory::new();
        assert!(history.entries.is_empty());
        assert_eq!(history.max_entries, 100);
    }

    #[test]
    fn test_sync_history_record() {
        let mut history = SyncHistory::new();
        let result = SyncResult {
            direction: SyncDirection::Push,
            bytes_transferred: 1024,
            success: true,
            message: "OK".to_string(),
        };
        history.record(&result, "file", "/backup");
        assert_eq!(history.entries.len(), 1);
        assert_eq!(history.entries[0].provider, "file");
        assert_eq!(history.entries[0].bytes_transferred, 1024);
        assert!(history.entries[0].success);
    }

    #[test]
    fn test_sync_history_last_sync() {
        let mut history = SyncHistory::new();
        assert!(history.last_sync().is_none());

        let result = SyncResult {
            direction: SyncDirection::Push,
            bytes_transferred: 1024,
            success: true,
            message: "OK".to_string(),
        };
        history.record(&result, "file", "/backup");
        assert!(history.last_sync().is_some());
        assert_eq!(history.last_sync().unwrap().provider, "file");
    }

    #[test]
    fn test_sync_history_last_successful() {
        let mut history = SyncHistory::new();

        let ok = SyncResult {
            direction: SyncDirection::Push,
            bytes_transferred: 1024,
            success: true,
            message: "OK".to_string(),
        };
        let fail = SyncResult {
            direction: SyncDirection::Push,
            bytes_transferred: 0,
            success: false,
            message: "Failed".to_string(),
        };

        history.record(&ok, "file", "/backup");
        history.record(&fail, "file", "/backup");

        let last = history.last_successful_sync().unwrap();
        assert!(last.success);
        assert_eq!(last.bytes_transferred, 1024);
    }

    #[test]
    fn test_sync_history_stats() {
        let mut history = SyncHistory::new();
        let ok = SyncResult {
            direction: SyncDirection::Push,
            bytes_transferred: 100,
            success: true,
            message: "OK".to_string(),
        };
        let fail = SyncResult {
            direction: SyncDirection::Pull,
            bytes_transferred: 0,
            success: false,
            message: "Error".to_string(),
        };

        history.record(&ok, "file", "/a");
        history.record(&ok, "file", "/b");
        history.record(&fail, "webdav", "/c");

        let (success, failed) = history.stats();
        assert_eq!(success, 2);
        assert_eq!(failed, 1);
    }

    #[test]
    fn test_sync_history_max_entries() {
        let mut history = SyncHistory::new();
        history.max_entries = 3;

        let result = SyncResult {
            direction: SyncDirection::Push,
            bytes_transferred: 100,
            success: true,
            message: "OK".to_string(),
        };

        for _ in 0..5 {
            history.record(&result, "file", "/backup");
        }

        assert_eq!(history.entries.len(), 3);
    }

    #[test]
    fn test_sync_history_save_load() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("history.json");

        let mut history = SyncHistory::new();
        let result = SyncResult {
            direction: SyncDirection::Push,
            bytes_transferred: 2048,
            success: true,
            message: "Synced".to_string(),
        };
        history.record(&result, "webdav", "https://dav.example.com");
        history.save(&path).unwrap();

        let loaded = SyncHistory::load(&path);
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].provider, "webdav");
        assert_eq!(loaded.entries[0].bytes_transferred, 2048);
    }

    #[test]
    fn test_sync_history_load_nonexistent() {
        let history = SyncHistory::load(Path::new("/nonexistent/history.json"));
        assert!(history.entries.is_empty());
    }

    #[test]
    fn test_sync_history_serialization() {
        let mut history = SyncHistory::new();
        let result = SyncResult {
            direction: SyncDirection::Pull,
            bytes_transferred: 512,
            success: false,
            message: "timeout".to_string(),
        };
        history.record(&result, "webdav", "/remote");

        let json = serde_json::to_string(&history).unwrap();
        let parsed: SyncHistory = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.entries.len(), 1);
        assert!(!parsed.entries[0].success);
    }

    #[test]
    fn test_sync_log_entry_serialization() {
        let entry = SyncLogEntry {
            timestamp: Utc::now(),
            direction: SyncDirection::Push,
            bytes_transferred: 4096,
            success: true,
            message: "Done".to_string(),
            provider: "file".to_string(),
            remote_path: "/mnt/backup".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: SyncLogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.provider, "file");
        assert_eq!(parsed.bytes_transferred, 4096);
    }

    #[test]
    fn test_sync_status_serialization() {
        let status = SyncStatus {
            configured: true,
            auto_sync_enabled: true,
            sync_interval_seconds: 300,
            last_sync: None,
            last_sync_time: None,
            next_sync_time: None,
            pending_changes: false,
            local_checksum: Some("abc".to_string()),
            remote_checksum: Some("abc".to_string()),
            config: None,
        };
        let json = serde_json::to_string(&status).unwrap();
        let parsed: SyncStatus = serde_json::from_str(&json).unwrap();
        assert!(parsed.configured);
        assert!(parsed.auto_sync_enabled);
    }

    #[test]
    fn test_sync_history_path() {
        let path = sync_history_path();
        assert!(path.to_str().unwrap().contains("vaultclaw"));
        assert!(path.to_str().unwrap().contains("sync_history"));
    }

    // Multi-target sync config tests

    #[test]
    fn test_multi_sync_config_new() {
        let config = MultiSyncConfig::new();
        assert!(config.targets.is_empty());
    }

    #[test]
    fn test_multi_sync_config_add_target() {
        let mut config = MultiSyncConfig::new();
        config.add_target(SyncTarget {
            name: "backup".to_string(),
            provider: "file".to_string(),
            remote_path: "/mnt/backup".to_string(),
            auto_sync: true,
            sync_interval_seconds: 300,
            url: None,
            username: None,
            password: None,
        });
        assert_eq!(config.targets.len(), 1);
        assert_eq!(config.targets[0].name, "backup");
    }

    #[test]
    fn test_multi_sync_config_replace_target() {
        let mut config = MultiSyncConfig::new();
        config.add_target(SyncTarget {
            name: "backup".to_string(),
            provider: "file".to_string(),
            remote_path: "/old".to_string(),
            auto_sync: false,
            sync_interval_seconds: 300,
            url: None,
            username: None,
            password: None,
        });
        config.add_target(SyncTarget {
            name: "backup".to_string(),
            provider: "file".to_string(),
            remote_path: "/new".to_string(),
            auto_sync: true,
            sync_interval_seconds: 600,
            url: None,
            username: None,
            password: None,
        });
        assert_eq!(config.targets.len(), 1);
        assert_eq!(config.targets[0].remote_path, "/new");
        assert!(config.targets[0].auto_sync);
    }

    #[test]
    fn test_multi_sync_config_remove_target() {
        let mut config = MultiSyncConfig::new();
        config.add_target(SyncTarget {
            name: "backup".to_string(),
            provider: "file".to_string(),
            remote_path: "/mnt".to_string(),
            auto_sync: false,
            sync_interval_seconds: 300,
            url: None,
            username: None,
            password: None,
        });
        assert!(config.remove_target("backup"));
        assert!(config.targets.is_empty());
        assert!(!config.remove_target("nonexistent"));
    }

    #[test]
    fn test_multi_sync_config_get_target() {
        let mut config = MultiSyncConfig::new();
        config.add_target(SyncTarget {
            name: "primary".to_string(),
            provider: "webdav".to_string(),
            remote_path: "vault.vclaw".to_string(),
            auto_sync: true,
            sync_interval_seconds: 300,
            url: Some("https://dav.example.com".to_string()),
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
        });
        let target = config.get_target("primary").unwrap();
        assert_eq!(target.provider, "webdav");
        assert!(config.get_target("nonexistent").is_none());
    }

    #[test]
    fn test_multi_sync_config_auto_sync_targets() {
        let mut config = MultiSyncConfig::new();
        config.add_target(SyncTarget {
            name: "auto".to_string(),
            provider: "file".to_string(),
            remote_path: "/a".to_string(),
            auto_sync: true,
            sync_interval_seconds: 300,
            url: None, username: None, password: None,
        });
        config.add_target(SyncTarget {
            name: "manual".to_string(),
            provider: "file".to_string(),
            remote_path: "/b".to_string(),
            auto_sync: false,
            sync_interval_seconds: 300,
            url: None, username: None, password: None,
        });
        let auto = config.auto_sync_targets();
        assert_eq!(auto.len(), 1);
        assert_eq!(auto[0].name, "auto");
    }

    #[test]
    fn test_multi_sync_config_save_load() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("targets.json");

        let mut config = MultiSyncConfig::new();
        config.add_target(SyncTarget {
            name: "test".to_string(),
            provider: "file".to_string(),
            remote_path: "/mnt".to_string(),
            auto_sync: true,
            sync_interval_seconds: 600,
            url: None, username: None, password: None,
        });
        config.save(&path).unwrap();

        let loaded = MultiSyncConfig::load(&path);
        assert_eq!(loaded.targets.len(), 1);
        assert_eq!(loaded.targets[0].name, "test");
        assert!(loaded.targets[0].auto_sync);
    }

    #[test]
    fn test_multi_sync_config_load_nonexistent() {
        let config = MultiSyncConfig::load(Path::new("/nonexistent/targets.json"));
        assert!(config.targets.is_empty());
    }

    #[test]
    fn test_multi_sync_config_path() {
        let path = multi_sync_config_path();
        assert!(path.to_str().unwrap().contains("vaultclaw"));
        assert!(path.to_str().unwrap().contains("sync_targets"));
    }

    #[test]
    fn test_sync_target_serialization() {
        let target = SyncTarget {
            name: "webdav-primary".to_string(),
            provider: "webdav".to_string(),
            remote_path: "vault.vclaw".to_string(),
            auto_sync: true,
            sync_interval_seconds: 300,
            url: Some("https://dav.example.com".to_string()),
            username: Some("alice".to_string()),
            password: Some("secret".to_string()),
        };
        let json = serde_json::to_string(&target).unwrap();
        let parsed: SyncTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "webdav-primary");
        assert_eq!(parsed.url.as_deref(), Some("https://dav.example.com"));
    }

    #[test]
    fn test_sync_history_entries_since() {
        use chrono::Duration;

        let mut history = SyncHistory::new();

        // Manually create entries with controlled timestamps
        history.entries.push(SyncLogEntry {
            timestamp: Utc::now() - Duration::seconds(60),
            direction: SyncDirection::Push,
            bytes_transferred: 100,
            success: true,
            message: "OK".to_string(),
            provider: "file".to_string(),
            remote_path: "/a".to_string(),
        });

        let threshold = Utc::now() - Duration::seconds(30);

        history.entries.push(SyncLogEntry {
            timestamp: Utc::now(),
            direction: SyncDirection::Push,
            bytes_transferred: 100,
            success: true,
            message: "OK".to_string(),
            provider: "file".to_string(),
            remote_path: "/b".to_string(),
        });

        let recent = history.entries_since(threshold);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].remote_path, "/b");
    }
}
