use clap::Subcommand;

use crate::crypto::recovery;
use crate::vault::format::VaultFile;

#[derive(Subcommand)]
pub enum YubiKeyCommands {
    /// List enrolled YubiKeys
    List,

    /// Remove an enrolled YubiKey
    Remove {
        /// Slot index to remove
        slot: usize,
    },

    /// Set up a recovery key for emergency vault access
    Recovery,

    /// List connected FIDO2 devices
    #[cfg(feature = "yubikey")]
    Devices,

    /// Enroll a new YubiKey
    #[cfg(feature = "yubikey")]
    Enroll {
        /// Human-readable label for this key
        #[arg(short, long)]
        label: String,
    },
}

pub fn handle_yubikey_command(
    command: YubiKeyCommands,
    vault: &VaultFile,
    json_output: bool,
) -> anyhow::Result<()> {
    match command {
        YubiKeyCommands::List => cmd_list(vault, json_output),
        YubiKeyCommands::Remove { slot } => cmd_remove(vault, slot),
        YubiKeyCommands::Recovery => cmd_recovery(vault),
        #[cfg(feature = "yubikey")]
        YubiKeyCommands::Devices => cmd_devices(),
        #[cfg(feature = "yubikey")]
        YubiKeyCommands::Enroll { label } => cmd_enroll(vault, &label),
    }
}

fn cmd_list(vault: &VaultFile, json_output: bool) -> anyhow::Result<()> {
    let keys = vault.list_yubikeys()?;
    if keys.is_empty() {
        if json_output {
            println!("[]");
        } else {
            println!("No YubiKeys enrolled.");
        }
        return Ok(());
    }

    if json_output {
        let json_keys: Vec<_> = keys.iter().map(|(slot, info)| {
            serde_json::json!({
                "slot": slot,
                "label": info.label,
                "credential_id": info.credential_id,
                "rpid": info.rpid,
                "enrolled_at": info.enrolled_at,
            })
        }).collect();
        println!("{}", serde_json::to_string_pretty(&json_keys)?);
    } else {
        println!("Enrolled YubiKeys:");
        for (slot, info) in &keys {
            println!("  [{}] {} ({})", slot, info.label, info.rpid);
        }
    }
    Ok(())
}

fn cmd_remove(vault: &VaultFile, slot: usize) -> anyhow::Result<()> {
    vault.remove_yubikey(slot)?;
    println!("YubiKey at slot {} removed.", slot);
    Ok(())
}

fn cmd_recovery(vault: &VaultFile) -> anyhow::Result<()> {
    if vault.has_recovery_key() {
        println!("WARNING: A recovery key already exists. Setting up a new one will replace it.");
    }

    let key = vault.setup_recovery_key()?;
    let formatted = recovery::format_recovery_key(&key);

    println!("Recovery key generated. Store this OFFLINE in a safe place.");
    println!("If you lose your master password AND all enrolled YubiKeys,");
    println!("this is the ONLY way to recover your vault.");
    println!();
    println!("  {}", formatted);
    println!();
    println!("This key will NOT be shown again.");

    Ok(())
}

#[cfg(feature = "yubikey")]
fn cmd_devices() -> anyhow::Result<()> {
    let devices = crate::platform::yubikey::list_devices()
        .map_err(|e| anyhow::anyhow!(e))?;

    if devices.is_empty() {
        println!("No FIDO2 devices found. Insert a YubiKey and try again.");
        return Ok(());
    }

    println!("Connected FIDO2 devices:");
    for (i, d) in devices.iter().enumerate() {
        println!("  [{}] {} ({})", i, d.product_name, d.manufacturer);
    }
    Ok(())
}

#[cfg(feature = "yubikey")]
fn cmd_enroll(vault: &VaultFile, label: &str) -> anyhow::Result<()> {
    use crate::platform::yubikey;

    let salt = vault.yubikey_salt()?;
    let mut salt_arr = [0u8; 32];
    salt_arr.copy_from_slice(&salt);

    println!("Touch your YubiKey to enroll...");

    let devices = ctap_hid_fido2::FidoKeyHidFactory::create(&ctap_hid_fido2::Cfg::init())
        .map_err(|e| anyhow::anyhow!("No FIDO2 device found: {}", e))?;

    let device = devices.first()
        .ok_or_else(|| anyhow::anyhow!("No FIDO2 device found"))?;

    let user_id = uuid::Uuid::new_v4();
    let (cred_id, secret) = yubikey::enroll(
        device,
        "vaultclaw.local",
        user_id.as_bytes(),
        label,
        &salt_arr,
    ).map_err(|e| anyhow::anyhow!(e))?;

    let info = YubiKeyInfo {
        credential_id: hex::encode(&cred_id),
        label: label.to_string(),
        rpid: "vaultclaw.local".to_string(),
        enrolled_at: chrono::Utc::now().to_rfc3339(),
    };

    let slot = vault.enroll_yubikey(&secret, &info)?;
    println!("YubiKey enrolled at slot {}.", slot);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::KdfParams;
    use crate::crypto::keys::password_secret;
    use crate::vault::format::YubiKeyInfo;
    use tempfile::TempDir;

    fn test_vault() -> (VaultFile, TempDir) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test".to_string());
        let vault = VaultFile::create(&path, &password, KdfParams::fast_for_testing()).unwrap();
        (vault, dir)
    }

    #[test]
    fn test_cmd_list_empty() {
        let (vault, _dir) = test_vault();
        cmd_list(&vault, false).unwrap();
    }

    #[test]
    fn test_cmd_list_json_empty() {
        let (vault, _dir) = test_vault();
        cmd_list(&vault, true).unwrap();
    }

    #[test]
    fn test_cmd_list_with_keys() {
        let (vault, _dir) = test_vault();

        let info = YubiKeyInfo {
            credential_id: "cred-123".to_string(),
            label: "TestKey".to_string(),
            rpid: "vaultclaw.local".to_string(),
            enrolled_at: "2025-01-01T00:00:00Z".to_string(),
        };
        vault.enroll_yubikey(&[42u8; 32], &info).unwrap();

        cmd_list(&vault, false).unwrap();
        cmd_list(&vault, true).unwrap();
    }

    #[test]
    fn test_cmd_remove() {
        let (vault, _dir) = test_vault();

        let info = YubiKeyInfo {
            credential_id: "cred-123".to_string(),
            label: "TestKey".to_string(),
            rpid: "vaultclaw.local".to_string(),
            enrolled_at: "2025-01-01T00:00:00Z".to_string(),
        };
        vault.enroll_yubikey(&[42u8; 32], &info).unwrap();

        cmd_remove(&vault, 0).unwrap();
        assert_eq!(vault.list_yubikeys().unwrap().len(), 0);
    }

    #[test]
    fn test_cmd_recovery() {
        let (vault, _dir) = test_vault();
        cmd_recovery(&vault).unwrap();
        assert!(vault.has_recovery_key());
    }

    #[test]
    fn test_cmd_recovery_replaces_existing() {
        let (vault, _dir) = test_vault();
        cmd_recovery(&vault).unwrap();
        assert!(vault.has_recovery_key());
        // Calling again should still succeed (replaces)
        cmd_recovery(&vault).unwrap();
    }
}
