use std::path::{Path, PathBuf};

use clap::Subcommand;

use crate::sync::file_sync::FileSyncProvider;
use crate::sync::provider::{local_metadata, SyncProvider};
use crate::sync::scheduler::{
    sync_history_path, multi_sync_config_path, MultiSyncConfig, SyncHistory, SyncTarget,
};
#[cfg(feature = "webdav")]
use crate::sync::webdav::{WebDavConfig, WebDavProvider};

#[derive(Subcommand)]
pub enum SyncCommands {
    /// Push local vault to remote
    Push {
        /// Sync provider (file or webdav)
        #[arg(long, default_value = "file")]
        provider: String,
        /// Remote path (directory for file, remote filename for webdav)
        #[arg(long)]
        remote_path: String,
        /// WebDAV server URL (required for webdav provider)
        #[arg(long)]
        url: Option<String>,
        /// WebDAV username
        #[arg(long)]
        username: Option<String>,
        /// WebDAV password
        #[arg(long)]
        password: Option<String>,
    },

    /// Pull remote vault to local
    Pull {
        /// Sync provider (file or webdav)
        #[arg(long, default_value = "file")]
        provider: String,
        /// Remote path (directory for file, remote filename for webdav)
        #[arg(long)]
        remote_path: String,
        /// WebDAV server URL (required for webdav provider)
        #[arg(long)]
        url: Option<String>,
        /// WebDAV username
        #[arg(long)]
        username: Option<String>,
        /// WebDAV password
        #[arg(long)]
        password: Option<String>,
    },

    /// Show sync status (vault metadata, last sync, configured targets)
    Status,

    /// Show sync history log
    History {
        /// Number of recent entries to show
        #[arg(short, long, default_value = "20")]
        last: usize,
    },

    /// Add a sync target
    AddTarget {
        /// Target name
        #[arg(long)]
        name: String,
        /// Sync provider (file or webdav)
        #[arg(long, default_value = "file")]
        provider: String,
        /// Remote path
        #[arg(long)]
        remote_path: String,
        /// Enable auto-sync for this target
        #[arg(long)]
        auto_sync: bool,
        /// Auto-sync interval in seconds (default 300)
        #[arg(long, default_value = "300")]
        interval: u64,
        /// WebDAV URL (required for webdav provider)
        #[arg(long)]
        url: Option<String>,
        /// WebDAV username
        #[arg(long)]
        username: Option<String>,
        /// WebDAV password
        #[arg(long)]
        password: Option<String>,
    },

    /// Remove a sync target
    RemoveTarget {
        /// Target name to remove
        name: String,
    },

    /// List configured sync targets
    Targets,
}

/// Handle a sync subcommand.
pub fn handle_sync_command(
    command: SyncCommands,
    vault_path: &Path,
    json_output: bool,
) -> anyhow::Result<()> {
    match command {
        SyncCommands::Push {
            provider,
            remote_path,
            url,
            username,
            password,
        } => {
            let provider_box = create_provider(&provider, &remote_path, vault_path, url, username, password)?;
            cmd_sync_push(vault_path, &provider, &remote_path, provider_box, json_output)
        }
        SyncCommands::Pull {
            provider,
            remote_path,
            url,
            username,
            password,
        } => {
            let provider_box = create_provider(&provider, &remote_path, vault_path, url, username, password)?;
            cmd_sync_pull(vault_path, &provider, &remote_path, provider_box, json_output)
        }
        SyncCommands::Status => cmd_sync_status(vault_path, json_output),
        SyncCommands::History { last } => cmd_sync_history(last, json_output),
        SyncCommands::AddTarget {
            name, provider, remote_path, auto_sync, interval,
            url, username, password,
        } => cmd_add_target(name, provider, remote_path, auto_sync, interval, url, username, password, json_output),
        SyncCommands::RemoveTarget { name } => cmd_remove_target(&name, json_output),
        SyncCommands::Targets => cmd_list_targets(json_output),
    }
}

fn vault_filename(vault_path: &Path) -> String {
    vault_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string()
}

fn create_provider(
    provider_name: &str,
    remote_path: &str,
    vault_path: &Path,
    url: Option<String>,
    username: Option<String>,
    password: Option<String>,
) -> anyhow::Result<Box<dyn SyncProvider>> {
    match provider_name {
        "file" => Ok(Box::new(FileSyncProvider::new(
            PathBuf::from(remote_path),
            vault_filename(vault_path),
        ))),
        "webdav" => {
            #[cfg(feature = "webdav")]
            {
                let url = url.ok_or_else(|| anyhow::anyhow!("WebDAV requires --url flag"))?;
                let config = WebDavConfig {
                    url,
                    username: username.unwrap_or_default(),
                    password: password.unwrap_or_default(),
                    remote_path: remote_path.to_string(),
                };
                Ok(Box::new(WebDavProvider::new(config)))
            }
            #[cfg(not(feature = "webdav"))]
            {
                let _ = (url, username, password);
                anyhow::bail!("WebDAV support not compiled. Rebuild with: cargo build --features webdav")
            }
        }
        other => anyhow::bail!(
            "Unsupported sync provider: '{}'. Supported: file, webdav",
            other
        ),
    }
}

fn cmd_sync_push(
    vault_path: &Path,
    provider_name: &str,
    remote_path: &str,
    provider: Box<dyn SyncProvider>,
    json_output: bool,
) -> anyhow::Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("Vault file not found: {}", vault_path.display());
    }

    if !provider.is_available()? {
        anyhow::bail!("Remote is not available");
    }

    let result = provider.push(vault_path)?;

    // Record in sync history
    let history_path = sync_history_path();
    let mut history = SyncHistory::load(&history_path);
    history.record(&result, provider_name, remote_path);
    let _ = history.save(&history_path);

    if json_output {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("{}", result.message);
    }
    Ok(())
}

fn cmd_sync_pull(
    vault_path: &Path,
    provider_name: &str,
    remote_path: &str,
    provider: Box<dyn SyncProvider>,
    json_output: bool,
) -> anyhow::Result<()> {
    if !provider.is_available()? {
        anyhow::bail!("Remote is not available");
    }

    let result = provider.pull(vault_path)?;

    // Record in sync history
    let history_path = sync_history_path();
    let mut history = SyncHistory::load(&history_path);
    history.record(&result, provider_name, remote_path);
    let _ = history.save(&history_path);

    if json_output {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("{}", result.message);
    }
    Ok(())
}

fn cmd_sync_status(vault_path: &Path, json_output: bool) -> anyhow::Result<()> {
    if !vault_path.exists() {
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "exists": false,
                    "path": vault_path.display().to_string(),
                }))?
            );
        } else {
            println!("Vault file not found: {}", vault_path.display());
        }
        return Ok(());
    }

    let meta = local_metadata(vault_path)?;
    let history = SyncHistory::load(&sync_history_path());
    let config = MultiSyncConfig::load(&multi_sync_config_path());
    let has_auto = config.targets.iter().any(|t| t.auto_sync);

    if json_output {
        let status = serde_json::json!({
            "vault": meta,
            "last_sync": history.last_sync(),
            "last_successful_sync": history.last_successful_sync(),
            "sync_count": history.entries.len(),
            "targets": config.targets,
            "auto_sync_enabled": has_auto,
        });
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!("=== Sync Status ===");
        println!("Vault:     {}", meta.path);
        println!("Size:      {} bytes", meta.size);
        println!("Modified:  {} (unix timestamp)", meta.modified_timestamp);
        println!("Checksum:  {}", &meta.checksum[..16]);

        if let Some(last) = history.last_sync() {
            println!("\nLast sync: {} ({} via {})",
                last.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                if last.success { "success" } else { "failed" },
                last.provider,
            );
        } else {
            println!("\nLast sync: never");
        }

        let (ok, fail) = history.stats();
        println!("History:   {} syncs ({} successful, {} failed)", ok + fail, ok, fail);
        println!("Targets:   {} configured ({} auto-sync)",
            config.targets.len(),
            config.auto_sync_targets().len(),
        );
    }
    Ok(())
}

fn cmd_sync_history(last: usize, json_output: bool) -> anyhow::Result<()> {
    let history = SyncHistory::load(&sync_history_path());

    let entries: Vec<_> = history.entries.iter().rev().take(last).collect();

    if json_output {
        println!("{}", serde_json::to_string_pretty(&entries)?);
    } else if entries.is_empty() {
        println!("No sync history.");
    } else {
        println!("=== Sync History (last {}) ===", entries.len());
        for entry in &entries {
            let status = if entry.success { "OK" } else { "FAIL" };
            println!("[{}] {:>4} {} {:?} → {} ({} bytes)",
                entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
                status,
                entry.provider,
                entry.direction,
                entry.remote_path,
                entry.bytes_transferred,
            );
            if !entry.success {
                println!("         Error: {}", entry.message);
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_add_target(
    name: String,
    provider: String,
    remote_path: String,
    auto_sync: bool,
    interval: u64,
    url: Option<String>,
    username: Option<String>,
    password: Option<String>,
    json_output: bool,
) -> anyhow::Result<()> {
    if provider == "webdav" && url.is_none() {
        anyhow::bail!("WebDAV targets require --url");
    }

    let target = SyncTarget {
        name: name.clone(),
        provider,
        remote_path,
        auto_sync,
        sync_interval_seconds: interval,
        url,
        username,
        password,
    };

    let config_path = multi_sync_config_path();
    let mut config = MultiSyncConfig::load(&config_path);
    config.add_target(target);
    config.save(&config_path)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&config)?);
    } else {
        println!("Sync target '{}' added.", name);
    }
    Ok(())
}

fn cmd_remove_target(name: &str, json_output: bool) -> anyhow::Result<()> {
    let config_path = multi_sync_config_path();
    let mut config = MultiSyncConfig::load(&config_path);

    if config.remove_target(name) {
        config.save(&config_path)?;
        if json_output {
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({"removed": name}))?);
        } else {
            println!("Sync target '{}' removed.", name);
        }
    } else if json_output {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({"error": "not found"}))?);
    } else {
        println!("Sync target '{}' not found.", name);
    }
    Ok(())
}

fn cmd_list_targets(json_output: bool) -> anyhow::Result<()> {
    let config = MultiSyncConfig::load(&multi_sync_config_path());

    if json_output {
        println!("{}", serde_json::to_string_pretty(&config.targets)?);
    } else if config.targets.is_empty() {
        println!("No sync targets configured.");
        println!("Add one with: vaultclaw sync add-target --name <name> --provider <file|webdav> --remote-path <path>");
    } else {
        println!("=== Sync Targets ===");
        for t in &config.targets {
            let auto = if t.auto_sync {
                format!("auto every {}s", t.sync_interval_seconds)
            } else {
                "manual".to_string()
            };
            println!("  {} ({}) → {} [{}]", t.name, t.provider, t.remote_path, auto);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::KdfParams;
    use crate::crypto::keys::password_secret;
    use crate::vault::format::VaultFile;

    fn create_test_vault_for_sync() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("testpass".to_string());
        VaultFile::create(&path, &password, KdfParams::fast_for_testing()).unwrap();
        (dir, path)
    }

    #[test]
    fn test_sync_status_no_vault() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("nonexistent.vclaw");
        let result = handle_sync_command(SyncCommands::Status, &path, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sync_status_no_vault_json() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("nonexistent.vclaw");
        let result = handle_sync_command(SyncCommands::Status, &path, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sync_status_with_vault() {
        let (_dir, path) = create_test_vault_for_sync();
        let result = handle_sync_command(SyncCommands::Status, &path, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sync_status_with_vault_json() {
        let (_dir, path) = create_test_vault_for_sync();
        let result = handle_sync_command(SyncCommands::Status, &path, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sync_push_file_provider() {
        let (_dir, path) = create_test_vault_for_sync();
        let remote_dir = tempfile::TempDir::new().unwrap();
        let result = handle_sync_command(
            SyncCommands::Push {
                provider: "file".to_string(),
                remote_path: remote_dir.path().display().to_string(),
                url: None, username: None, password: None,
            },
            &path,
            false,
        );
        assert!(result.is_ok());
        // Verify file was copied
        assert!(remote_dir.path().join("test.vclaw").exists());
    }

    #[test]
    fn test_sync_push_file_provider_json() {
        let (_dir, path) = create_test_vault_for_sync();
        let remote_dir = tempfile::TempDir::new().unwrap();
        let result = handle_sync_command(
            SyncCommands::Push {
                provider: "file".to_string(),
                remote_path: remote_dir.path().display().to_string(),
                url: None, username: None, password: None,
            },
            &path,
            true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_sync_pull_file_provider() {
        let (_dir, path) = create_test_vault_for_sync();
        let remote_dir = tempfile::TempDir::new().unwrap();

        // First push so there's something to pull
        handle_sync_command(
            SyncCommands::Push {
                provider: "file".to_string(),
                remote_path: remote_dir.path().display().to_string(),
                url: None, username: None, password: None,
            },
            &path,
            false,
        )
        .unwrap();

        // Now pull to a new location
        let pull_dir = tempfile::TempDir::new().unwrap();
        let pull_path = pull_dir.path().join("test.vclaw");
        let result = handle_sync_command(
            SyncCommands::Pull {
                provider: "file".to_string(),
                remote_path: remote_dir.path().display().to_string(),
                url: None, username: None, password: None,
            },
            &pull_path,
            false,
        );
        assert!(result.is_ok());
        assert!(pull_path.exists());
    }

    #[test]
    fn test_sync_push_no_vault() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("nonexistent.vclaw");
        let remote_dir = tempfile::TempDir::new().unwrap();
        let result = handle_sync_command(
            SyncCommands::Push {
                provider: "file".to_string(),
                remote_path: remote_dir.path().display().to_string(),
                url: None, username: None, password: None,
            },
            &path,
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_sync_unsupported_provider() {
        let (_dir, path) = create_test_vault_for_sync();
        let result = handle_sync_command(
            SyncCommands::Push {
                provider: "unsupported".to_string(),
                remote_path: "/tmp/test".to_string(),
                url: None, username: None, password: None,
            },
            &path,
            false,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported"));
    }

    #[test]
    fn test_vault_filename() {
        assert_eq!(vault_filename(Path::new("/tmp/my.vclaw")), "my.vclaw");
        assert_eq!(vault_filename(Path::new("vault.vclaw")), "vault.vclaw");
    }

    #[test]
    fn test_create_provider_file() {
        let provider = create_provider("file", "/tmp/remote", Path::new("/tmp/test.vclaw"), None, None, None);
        assert!(provider.is_ok());
        assert_eq!(provider.unwrap().name(), "file");
    }

    #[cfg(feature = "webdav")]
    #[test]
    fn test_create_provider_webdav() {
        let provider = create_provider(
            "webdav", "vault.vclaw", Path::new("/tmp/test.vclaw"),
            Some("https://dav.example.com".into()),
            Some("user".into()),
            Some("pass".into()),
        );
        assert!(provider.is_ok());
        assert_eq!(provider.unwrap().name(), "webdav");
    }

    #[test]
    fn test_create_provider_webdav_no_url() {
        let result = create_provider("webdav", "vault.vclaw", Path::new("/tmp/test.vclaw"), None, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_provider_unsupported() {
        let result = create_provider("ftp", "/tmp/remote", Path::new("/tmp/test.vclaw"), None, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_sync_pull_unavailable_remote() {
        let (_dir, path) = create_test_vault_for_sync();
        let result = handle_sync_command(
            SyncCommands::Pull {
                provider: "file".to_string(),
                remote_path: "/nonexistent/path/that/does/not/exist".to_string(),
                url: None, username: None, password: None,
            },
            &path,
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_sync_history_empty() {
        // History command should work even with no history file
        let result = cmd_sync_history(10, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sync_history_json() {
        let result = cmd_sync_history(10, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sync_list_targets_empty() {
        let result = cmd_list_targets(false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sync_list_targets_json() {
        let result = cmd_list_targets(true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sync_add_remove_target() {
        let dir = tempfile::TempDir::new().unwrap();
        let config_path = dir.path().join("targets.json");

        // Manually add a target to a temp config
        let mut config = MultiSyncConfig::new();
        config.add_target(SyncTarget {
            name: "test-target".to_string(),
            provider: "file".to_string(),
            remote_path: "/tmp/sync".to_string(),
            auto_sync: false,
            sync_interval_seconds: 300,
            url: None,
            username: None,
            password: None,
        });
        config.save(&config_path).unwrap();

        let loaded = MultiSyncConfig::load(&config_path);
        assert_eq!(loaded.targets.len(), 1);
        assert_eq!(loaded.targets[0].name, "test-target");
    }

    #[test]
    fn test_sync_add_target_webdav_requires_url() {
        let result = cmd_add_target(
            "test".into(), "webdav".into(), "vault.vclaw".into(),
            false, 300, None, None, None, false,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("--url"));
    }

    #[test]
    fn test_sync_remove_target_not_found() {
        let result = cmd_remove_target("nonexistent", false);
        assert!(result.is_ok()); // Not an error, just prints "not found"
    }

    #[test]
    fn test_sync_remove_target_json() {
        let result = cmd_remove_target("nonexistent", true);
        assert!(result.is_ok());
    }

    // --- Additional coverage tests ---

    #[test]
    fn test_handle_sync_command_history_dispatch() {
        // Covers line 129: dispatch to cmd_sync_history via handle_sync_command
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let result = handle_sync_command(SyncCommands::History { last: 5 }, &path, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_sync_command_add_target_dispatch() {
        // Covers lines 131-133, 346-355, 357-360, 364-365:
        // dispatch to cmd_add_target and successful text-mode add
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let result = handle_sync_command(
            SyncCommands::AddTarget {
                name: format!("test-add-dispatch-{}", std::process::id()),
                provider: "file".to_string(),
                remote_path: dir.path().display().to_string(),
                auto_sync: false,
                interval: 300,
                url: None,
                username: None,
                password: None,
            },
            &path,
            false,
        );
        assert!(result.is_ok());
        // Clean up
        let _ = cmd_remove_target(&format!("test-add-dispatch-{}", std::process::id()), false);
    }

    #[test]
    fn test_handle_sync_command_remove_target_dispatch() {
        // Covers line 134: dispatch to cmd_remove_target via handle_sync_command
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let result = handle_sync_command(
            SyncCommands::RemoveTarget {
                name: "nonexistent-dispatch-test".to_string(),
            },
            &path,
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_sync_command_targets_dispatch() {
        // Covers line 135: dispatch to cmd_list_targets via handle_sync_command
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let result = handle_sync_command(SyncCommands::Targets, &path, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sync_push_unavailable_remote() {
        // Covers line 197: "Remote is not available" in cmd_sync_push
        let (_dir, path) = create_test_vault_for_sync();
        let result = handle_sync_command(
            SyncCommands::Push {
                provider: "file".to_string(),
                remote_path: "/nonexistent/dir/that/does/not/exist".to_string(),
                url: None,
                username: None,
                password: None,
            },
            &path,
            false,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not available"));
    }

    #[test]
    fn test_sync_pull_json_output() {
        // Covers line 236: JSON output path in cmd_sync_pull
        let (_dir, path) = create_test_vault_for_sync();
        let remote_dir = tempfile::TempDir::new().unwrap();

        // Push first so there's something to pull
        handle_sync_command(
            SyncCommands::Push {
                provider: "file".to_string(),
                remote_path: remote_dir.path().display().to_string(),
                url: None,
                username: None,
                password: None,
            },
            &path,
            false,
        )
        .unwrap();

        // Pull with json_output=true
        let pull_dir = tempfile::TempDir::new().unwrap();
        let pull_path = pull_dir.path().join("test.vclaw");
        let result = handle_sync_command(
            SyncCommands::Pull {
                provider: "file".to_string(),
                remote_path: remote_dir.path().display().to_string(),
                url: None,
                username: None,
                password: None,
            },
            &pull_path,
            true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_sync_status_text_with_history() {
        // Covers lines 282-284: the last_sync Some branch in text output
        use crate::sync::provider::{SyncDirection, SyncResult};

        let (_dir, path) = create_test_vault_for_sync();

        // Pre-seed the global history file with an entry so status shows "Last sync: ..."
        let history_path = sync_history_path();
        let mut history = SyncHistory::new(); // new() sets max_entries=100
        let ok_result = SyncResult {
            direction: SyncDirection::Push,
            bytes_transferred: 4096,
            success: true,
            message: "OK".to_string(),
        };
        history.record(&ok_result, "file", "/tmp/test-status-hist");
        history.save(&history_path).unwrap();

        // Now check status in text mode — should print "Last sync: ..." with data
        let result = cmd_sync_status(&path, false);
        assert!(result.is_ok());

        // Clean up: remove the history file to restore pristine state
        let _ = std::fs::remove_file(&history_path);
    }

    #[test]
    fn test_sync_history_text_with_entries() {
        // Covers lines 311-315, 322-324: history text output with entries,
        // including the failed entry error line branch
        use crate::sync::provider::{SyncDirection, SyncResult};

        let history_path = sync_history_path();

        // Pre-seed with entries using new() which sets max_entries=100
        let mut history = SyncHistory::new();

        // Add a successful entry
        let ok_result = SyncResult {
            direction: SyncDirection::Push,
            bytes_transferred: 2048,
            success: true,
            message: "OK".to_string(),
        };
        history.record(&ok_result, "file", "/tmp/test-history-text");

        // Add a failed entry to cover lines 322-324
        let fail_result = SyncResult {
            direction: SyncDirection::Pull,
            bytes_transferred: 0,
            success: false,
            message: "Connection refused".to_string(),
        };
        history.record(&fail_result, "webdav", "https://example.com/vault");
        history.save(&history_path).unwrap();

        // Display history in text mode
        let result = cmd_sync_history(20, false);
        assert!(result.is_ok());

        // Clean up: remove the history file to restore pristine state
        let _ = std::fs::remove_file(&history_path);
    }

    #[test]
    fn test_cmd_add_target_file_text() {
        // Covers lines 346-355, 357-360, 364-365: successful file target add, text output
        let unique_name = format!("test-file-add-text-{}", std::process::id());
        let result = cmd_add_target(
            unique_name.clone(),
            "file".to_string(),
            "/tmp/sync-test".to_string(),
            false,
            300,
            None,
            None,
            None,
            false,
        );
        assert!(result.is_ok());
        // Clean up
        let _ = cmd_remove_target(&unique_name, false);
    }

    #[test]
    fn test_cmd_add_target_file_json() {
        // Covers lines 362-363: JSON output branch after successful add
        let unique_name = format!("test-file-add-json-{}", std::process::id());
        let result = cmd_add_target(
            unique_name.clone(),
            "file".to_string(),
            "/tmp/sync-test-json".to_string(),
            true,
            600,
            None,
            None,
            None,
            true,
        );
        assert!(result.is_ok());
        // Clean up
        let _ = cmd_remove_target(&unique_name, false);
    }

    #[test]
    fn test_cmd_remove_target_success_text() {
        // Covers lines 375-379: successful removal, text output
        let unique_name = format!("test-remove-ok-text-{}", std::process::id());
        // First add a target
        cmd_add_target(
            unique_name.clone(),
            "file".to_string(),
            "/tmp/remove-test".to_string(),
            false,
            300,
            None,
            None,
            None,
            false,
        )
        .unwrap();

        // Now remove it
        let result = cmd_remove_target(&unique_name, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_remove_target_success_json() {
        // Covers lines 376-377: successful removal, JSON output
        let unique_name = format!("test-remove-ok-json-{}", std::process::id());
        cmd_add_target(
            unique_name.clone(),
            "file".to_string(),
            "/tmp/remove-test-json".to_string(),
            false,
            300,
            None,
            None,
            None,
            false,
        )
        .unwrap();

        let result = cmd_remove_target(&unique_name, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_list_targets_with_entries_text() {
        // Covers lines 398-401, 403, 405: list targets text output with entries
        let unique_auto = format!("test-list-auto-{}", std::process::id());
        let unique_manual = format!("test-list-manual-{}", std::process::id());

        // Add an auto-sync target (covers line 400-401: auto format branch)
        cmd_add_target(
            unique_auto.clone(),
            "file".to_string(),
            "/tmp/list-test-auto".to_string(),
            true,
            600,
            None,
            None,
            None,
            false,
        )
        .unwrap();

        // Add a manual target (covers line 403: "manual" branch)
        cmd_add_target(
            unique_manual.clone(),
            "file".to_string(),
            "/tmp/list-test-manual".to_string(),
            false,
            300,
            None,
            None,
            None,
            false,
        )
        .unwrap();

        // List targets in text mode
        let result = cmd_list_targets(false);
        assert!(result.is_ok());

        // Clean up
        let _ = cmd_remove_target(&unique_auto, false);
        let _ = cmd_remove_target(&unique_manual, false);
    }
}
