use std::path::{Path, PathBuf};

use clap::Subcommand;

use crate::backup::{
    create_backup, default_backup_dir, list_backups, prune_backups, restore_backup,
    verify_backup, BackupConfig,
};

#[derive(Subcommand)]
pub enum BackupCommands {
    /// Create a timestamped backup of the vault
    Create {
        /// Backup directory (default: ~/.local/share/vaultclaw/backups/)
        #[arg(long)]
        path: Option<PathBuf>,
    },

    /// List available backups
    List {
        /// Backup directory
        #[arg(long)]
        path: Option<PathBuf>,
    },

    /// Restore vault from a backup file
    Restore {
        /// Path to the backup file
        file: PathBuf,
    },

    /// Verify backup integrity without restoring
    Verify {
        /// Path to the backup file
        file: PathBuf,
    },

    /// Remove old backups, keeping only the most recent N
    Prune {
        /// Maximum number of backups to keep (default: 10)
        #[arg(long, default_value = "10")]
        keep: usize,
        /// Backup directory
        #[arg(long)]
        path: Option<PathBuf>,
    },
}

pub fn handle_backup_command(
    command: BackupCommands,
    vault_path: &Path,
    json_output: bool,
) -> anyhow::Result<()> {
    match command {
        BackupCommands::Create { path } => {
            let backup_dir = path.unwrap_or_else(default_backup_dir);
            cmd_backup_create(vault_path, &backup_dir, json_output)
        }
        BackupCommands::List { path } => {
            let backup_dir = path.unwrap_or_else(default_backup_dir);
            cmd_backup_list(&backup_dir, json_output)
        }
        BackupCommands::Restore { file } => cmd_backup_restore(&file, vault_path, json_output),
        BackupCommands::Verify { file } => cmd_backup_verify(&file, json_output),
        BackupCommands::Prune { keep, path } => {
            let backup_dir = path.unwrap_or_else(default_backup_dir);
            cmd_backup_prune(&backup_dir, keep, json_output)
        }
    }
}

fn cmd_backup_create(
    vault_path: &Path,
    backup_dir: &Path,
    json_output: bool,
) -> anyhow::Result<()> {
    let info = create_backup(vault_path, backup_dir)?;

    // Auto-prune after creation
    let config = BackupConfig::default();
    let pruned = prune_backups(backup_dir, config.max_backups).unwrap_or_default();

    if json_output {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "backup": info,
            "pruned": pruned,
        }))?);
    } else {
        println!("Backup created: {}", info.filename);
        println!("  Path: {}", info.path.display());
        println!("  Size: {} bytes", info.size_bytes);
        if !pruned.is_empty() {
            println!("  Pruned {} old backup(s)", pruned.len());
        }
    }
    Ok(())
}

fn cmd_backup_list(backup_dir: &Path, json_output: bool) -> anyhow::Result<()> {
    let backups = list_backups(backup_dir)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&backups)?);
    } else if backups.is_empty() {
        println!("No backups found in {}", backup_dir.display());
    } else {
        println!("=== Backups ({}) ===", backups.len());
        for b in &backups {
            println!("  {} ({} bytes) [v{}] {}",
                b.filename,
                b.size_bytes,
                b.vault_version.unwrap_or(0),
                b.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
            );
        }
        println!("\nBackup directory: {}", backup_dir.display());
    }
    Ok(())
}

fn cmd_backup_restore(
    backup_file: &Path,
    vault_path: &Path,
    json_output: bool,
) -> anyhow::Result<()> {
    // Verify first
    let verify = verify_backup(backup_file)?;
    if !verify.valid {
        anyhow::bail!(
            "Backup verification failed: {}",
            verify.error.as_deref().unwrap_or("unknown error")
        );
    }

    let info = restore_backup(backup_file, vault_path)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "restored": info,
            "source": backup_file.display().to_string(),
        }))?);
    } else {
        println!("Vault restored from backup.");
        println!("  Source: {}", backup_file.display());
        println!("  Target: {}", vault_path.display());
        println!("  Size:   {} bytes", info.size_bytes);
        if vault_path.parent().is_some() {
            println!("  A safety backup was created in the vault directory.");
        }
    }
    Ok(())
}

fn cmd_backup_verify(backup_file: &Path, json_output: bool) -> anyhow::Result<()> {
    let result = verify_backup(backup_file)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("=== Backup Verification ===");
        println!("File:      {}", backup_file.display());
        println!("Valid:     {}", if result.valid { "YES" } else { "NO" });
        println!("Size:      {} bytes", result.size_bytes);
        if let Some(v) = result.vault_version {
            println!("Version:   {}", v);
        }
        if let Some(c) = result.entry_count {
            println!("Entries:   {}", c);
        }
        println!("Metadata:  {}", if result.has_metadata { "present" } else { "missing" });
        println!("Integrity: {}", if result.integrity_ok { "OK" } else { "FAILED" });
        if let Some(err) = &result.error {
            println!("Error:     {}", err);
        }
    }
    Ok(())
}

fn cmd_backup_prune(
    backup_dir: &Path,
    max_keep: usize,
    json_output: bool,
) -> anyhow::Result<()> {
    let pruned = prune_backups(backup_dir, max_keep)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "pruned": pruned,
            "kept": max_keep,
        }))?);
    } else if pruned.is_empty() {
        println!("No backups to prune (keeping last {}).", max_keep);
    } else {
        println!("Pruned {} backup(s):", pruned.len());
        for name in &pruned {
            println!("  - {}", name);
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
    use tempfile::TempDir;

    fn create_test_vault(dir: &Path) -> PathBuf {
        let path = dir.join("test.vclaw");
        let password = password_secret("testpass".to_string());
        VaultFile::create(&path, &password, KdfParams::fast_for_testing()).unwrap();
        path
    }

    #[test]
    fn test_backup_create_command() {
        let dir = TempDir::new().unwrap();
        let vault_path = create_test_vault(dir.path());
        let backup_dir = dir.path().join("backups");

        let result = handle_backup_command(
            BackupCommands::Create { path: Some(backup_dir.clone()) },
            &vault_path,
            false,
        );
        assert!(result.is_ok());

        let backups = list_backups(&backup_dir).unwrap();
        assert_eq!(backups.len(), 1);
    }

    #[test]
    fn test_backup_create_json() {
        let dir = TempDir::new().unwrap();
        let vault_path = create_test_vault(dir.path());
        let backup_dir = dir.path().join("backups");

        let result = handle_backup_command(
            BackupCommands::Create { path: Some(backup_dir) },
            &vault_path,
            true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_backup_list_command() {
        let dir = TempDir::new().unwrap();
        let vault_path = create_test_vault(dir.path());
        let backup_dir = dir.path().join("backups");

        create_backup(&vault_path, &backup_dir).unwrap();

        let result = handle_backup_command(
            BackupCommands::List { path: Some(backup_dir) },
            &vault_path,
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_backup_list_empty() {
        let dir = TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let result = handle_backup_command(
            BackupCommands::List { path: Some(dir.path().join("empty")) },
            &vault_path,
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_backup_list_json() {
        let dir = TempDir::new().unwrap();
        let vault_path = create_test_vault(dir.path());
        let backup_dir = dir.path().join("backups");
        create_backup(&vault_path, &backup_dir).unwrap();

        let result = handle_backup_command(
            BackupCommands::List { path: Some(backup_dir) },
            &vault_path,
            true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_backup_verify_command() {
        let dir = TempDir::new().unwrap();
        let vault_path = create_test_vault(dir.path());
        let backup_dir = dir.path().join("backups");

        let backup = create_backup(&vault_path, &backup_dir).unwrap();

        let result = handle_backup_command(
            BackupCommands::Verify { file: backup.path },
            &vault_path,
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_backup_verify_json() {
        let dir = TempDir::new().unwrap();
        let vault_path = create_test_vault(dir.path());
        let backup_dir = dir.path().join("backups");
        let backup = create_backup(&vault_path, &backup_dir).unwrap();

        let result = handle_backup_command(
            BackupCommands::Verify { file: backup.path },
            &vault_path,
            true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_backup_restore_command() {
        let dir = TempDir::new().unwrap();
        let vault_path = create_test_vault(dir.path());
        let backup_dir = dir.path().join("backups");
        let backup = create_backup(&vault_path, &backup_dir).unwrap();

        let result = handle_backup_command(
            BackupCommands::Restore { file: backup.path },
            &vault_path,
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_backup_restore_json() {
        let dir = TempDir::new().unwrap();
        let vault_path = create_test_vault(dir.path());
        let backup_dir = dir.path().join("backups");
        let backup = create_backup(&vault_path, &backup_dir).unwrap();

        let result = handle_backup_command(
            BackupCommands::Restore { file: backup.path },
            &vault_path,
            true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_backup_restore_invalid() {
        let dir = TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");
        let bad_backup = dir.path().join("bad.vclaw.backup");
        std::fs::write(&bad_backup, b"not a valid vault").unwrap();

        let result = handle_backup_command(
            BackupCommands::Restore { file: bad_backup },
            &vault_path,
            false,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("verification failed"));
    }

    #[test]
    fn test_backup_prune_command() {
        let dir = TempDir::new().unwrap();
        let vault_path = create_test_vault(dir.path());
        let backup_dir = dir.path().join("backups");

        for _ in 0..5 {
            create_backup(&vault_path, &backup_dir).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let result = handle_backup_command(
            BackupCommands::Prune { keep: 2, path: Some(backup_dir.clone()) },
            &vault_path,
            false,
        );
        assert!(result.is_ok());
        assert_eq!(list_backups(&backup_dir).unwrap().len(), 2);
    }

    #[test]
    fn test_backup_prune_json() {
        let dir = TempDir::new().unwrap();
        let vault_path = create_test_vault(dir.path());
        let backup_dir = dir.path().join("backups");

        for _ in 0..3 {
            create_backup(&vault_path, &backup_dir).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let result = handle_backup_command(
            BackupCommands::Prune { keep: 1, path: Some(backup_dir) },
            &vault_path,
            true,
        );
        assert!(result.is_ok());
    }
}
