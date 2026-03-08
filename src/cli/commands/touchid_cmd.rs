use clap::Subcommand;

use crate::vault::format::VaultFile;

#[derive(Subcommand)]
pub enum TouchIdCommands {
    /// Enroll Touch ID for vault unlock
    Enroll,

    /// Remove Touch ID enrollment
    Remove,

    /// Show Touch ID enrollment status
    Status,
}

pub fn handle_touchid_command(
    command: TouchIdCommands,
    vault: &VaultFile,
    json_output: bool,
) -> anyhow::Result<()> {
    match command {
        TouchIdCommands::Enroll => cmd_enroll(vault, json_output),
        TouchIdCommands::Remove => cmd_remove(vault, json_output),
        TouchIdCommands::Status => cmd_status(vault, json_output),
    }
}

fn cmd_enroll(vault: &VaultFile, json_output: bool) -> anyhow::Result<()> {
    if vault.has_touchid() {
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "already_enrolled",
                    "label": vault.touchid_label(),
                }))?
            );
        } else {
            println!("Touch ID is already enrolled for this vault.");
            println!("Run 'vaultclaw touchid remove' first to re-enroll.");
        }
        return Ok(());
    }

    // Use the vault filename (without extension) as the label
    let vault_label = vault
        .path()
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("default")
        .to_string();

    vault.enroll_touchid(&vault_label)?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": "enrolled",
                "label": vault_label,
            }))?
        );
    } else {
        println!("Touch ID enrolled successfully.");
        println!("You can now unlock your vault with 'vaultclaw unlock --touchid'.");
    }

    Ok(())
}

fn cmd_remove(vault: &VaultFile, json_output: bool) -> anyhow::Result<()> {
    let removed = vault.remove_touchid()?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": if removed { "removed" } else { "not_enrolled" },
            }))?
        );
    } else if removed {
        println!("Touch ID enrollment removed.");
    } else {
        println!("Touch ID was not enrolled for this vault.");
    }

    Ok(())
}

fn cmd_status(vault: &VaultFile, json_output: bool) -> anyhow::Result<()> {
    let enrolled = vault.has_touchid();
    let label = vault.touchid_label();

    // Also check if the Keychain item actually exists
    let keychain_present = label
        .as_deref()
        .map(crate::platform::touchid::is_enrolled)
        .unwrap_or(false);

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "enrolled": enrolled,
                "label": label,
                "keychain_present": keychain_present,
            }))?
        );
    } else if enrolled {
        println!("Touch ID: enrolled");
        if let Some(l) = &label {
            println!("  Label: {}", l);
        }
        if !keychain_present {
            println!("  WARNING: Keychain item missing. Re-enroll with 'vaultclaw touchid enroll'.");
        }
    } else {
        println!("Touch ID: not enrolled");
        println!("Enroll with 'vaultclaw touchid enroll'.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::KdfParams;
    use crate::crypto::keys::password_secret;
    use tempfile::TempDir;

    fn test_vault() -> (VaultFile, TempDir) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test".to_string());
        let vault = VaultFile::create(&path, &password, KdfParams::fast_for_testing()).unwrap();
        (vault, dir)
    }

    #[test]
    fn test_cmd_status_not_enrolled() {
        let (vault, _dir) = test_vault();
        cmd_status(&vault, false).unwrap();
    }

    #[test]
    fn test_cmd_status_not_enrolled_json() {
        let (vault, _dir) = test_vault();
        cmd_status(&vault, true).unwrap();
    }

    #[test]
    fn test_cmd_remove_not_enrolled() {
        let (vault, _dir) = test_vault();
        cmd_remove(&vault, false).unwrap();
    }

    #[test]
    fn test_cmd_remove_not_enrolled_json() {
        let (vault, _dir) = test_vault();
        cmd_remove(&vault, true).unwrap();
    }

    // Interactive tests requiring Touch ID hardware:
    //   cargo test -- --ignored touchid_cmd

    #[test]
    #[ignore]
    fn test_cmd_enroll_and_remove() {
        let (vault, _dir) = test_vault();
        cmd_enroll(&vault, false).unwrap();
        assert!(vault.has_touchid());

        cmd_remove(&vault, false).unwrap();
        assert!(!vault.has_touchid());
    }

    #[test]
    #[ignore]
    fn test_cmd_enroll_already_enrolled() {
        let (vault, _dir) = test_vault();
        cmd_enroll(&vault, false).unwrap();
        // Second enroll should report already enrolled
        cmd_enroll(&vault, false).unwrap();
        cmd_remove(&vault, false).unwrap();
    }
}
