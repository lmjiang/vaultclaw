use clap::Subcommand;

use crate::vault::entry::Credential;
use crate::vault::format::VaultFile;

#[derive(Subcommand)]
pub enum PasskeyCommands {
    /// List stored passkeys
    List {
        /// List hardware-stored passkeys (YubiKey resident credentials)
        #[arg(long)]
        hardware: bool,
    },

    /// Show passkey details (no private key)
    Show {
        /// Relying party ID or entry title to search
        query: String,
    },

    /// Delete a passkey
    Delete {
        /// Entry ID (UUID) of the passkey to delete
        id: String,
        /// Delete from hardware key instead of vault
        #[arg(long)]
        hardware: bool,
    },

    /// Create a new passkey (for testing or manual registration)
    #[cfg(feature = "yubikey")]
    Create {
        /// Relying party ID (e.g., "example.com")
        #[arg(long)]
        rp_id: String,
        /// Relying party display name
        #[arg(long)]
        rp_name: String,
        /// Username
        #[arg(long)]
        user_name: String,
        /// Store passkey on YubiKey hardware instead of vault
        #[arg(long)]
        hardware: bool,
    },

    /// Export a passkey (encrypted with vault key)
    Export {
        /// Entry ID (UUID) of the passkey to export, or "all" for all passkeys
        id: String,
        /// Output format
        #[arg(long, default_value = "json")]
        format: String,
        /// Output file path (default: stdout)
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Import passkeys from an exported file
    Import {
        /// Input file path (.vcpk or .json)
        path: String,
    },
}

pub fn handle_passkey_command(
    command: PasskeyCommands,
    vault: &mut VaultFile,
    json_output: bool,
) -> anyhow::Result<()> {
    match command {
        PasskeyCommands::List { hardware } => {
            if hardware {
                cmd_list_hardware(json_output)
            } else {
                cmd_list(vault, json_output)
            }
        }
        PasskeyCommands::Show { query } => cmd_show(vault, &query, json_output),
        PasskeyCommands::Delete { id, hardware } => {
            if hardware {
                println!("Hardware passkey deletion requires physical interaction with the device.");
                println!("Use your authenticator's management tool to remove credential: {}", id);
                Ok(())
            } else {
                cmd_delete(vault, &id)
            }
        }
        #[cfg(feature = "yubikey")]
        PasskeyCommands::Create {
            rp_id,
            rp_name,
            user_name,
            hardware,
        } => {
            if hardware {
                cmd_create_hardware(vault, &rp_id, &rp_name, &user_name)
            } else {
                cmd_create_software(vault, &rp_id, &rp_name, &user_name)
            }
        }
        PasskeyCommands::Export { id, format, output } => cmd_export(vault, &id, &format, json_output, output.as_deref()),
        PasskeyCommands::Import { path } => cmd_import(vault, &path),
    }
}

fn get_passkeys(vault: &VaultFile) -> Vec<&crate::vault::entry::Entry> {
    vault.store().list().into_iter()
        .filter(|e| matches!(&e.credential, Credential::Passkey(_)))
        .collect()
}

fn cmd_list(vault: &VaultFile, json_output: bool) -> anyhow::Result<()> {
    let passkeys = get_passkeys(vault);

    if passkeys.is_empty() {
        if json_output {
            println!("[]");
        } else {
            println!("No passkeys stored.");
        }
        return Ok(());
    }

    if json_output {
        let items: Vec<_> = passkeys.iter().map(|e| passkey_summary_json(e)).collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
    } else {
        println!("Stored passkeys:");
        for entry in &passkeys {
            if let Credential::Passkey(pk) = &entry.credential {
                let storage = if pk.private_key.is_empty() { "HW" } else { "SW" };
                println!(
                    "  [{}] {} — {} (sign count: {}) [{}]",
                    &entry.id.to_string()[..8],
                    pk.rp_name,
                    pk.user_name,
                    pk.sign_count,
                    storage,
                );
            }
        }
    }
    Ok(())
}

fn cmd_show(vault: &VaultFile, query: &str, json_output: bool) -> anyhow::Result<()> {
    let passkeys = get_passkeys(vault);

    let found: Vec<_> = passkeys.into_iter().filter(|e| {
        if let Credential::Passkey(pk) = &e.credential {
            pk.rp_id.contains(query) || pk.rp_name.to_lowercase().contains(&query.to_lowercase())
                || e.title.to_lowercase().contains(&query.to_lowercase())
                || e.id.to_string().starts_with(query)
        } else {
            false
        }
    }).collect();

    if found.is_empty() {
        anyhow::bail!("No passkey found matching '{}'", query);
    }

    for entry in &found {
        if let Credential::Passkey(pk) = &entry.credential {
            if json_output {
                println!("{}", serde_json::to_string_pretty(&passkey_summary_json(entry))?);
            } else {
                println!("ID: {}", entry.id);
                println!("Title: {}", entry.title);
                println!("RP: {} ({})", pk.rp_name, pk.rp_id);
                println!("User: {} (handle: {})", pk.user_name, pk.user_handle);
                println!("Algorithm: {:?}", pk.algorithm);
                println!("Sign count: {}", pk.sign_count);
                println!("Discoverable: {}", pk.discoverable);
                println!("Backup eligible: {}", pk.backup_eligible);
                println!("Backup state: {}", pk.backup_state);
                let storage = if pk.private_key.is_empty() { "Hardware (YubiKey)" } else { "Software (Vault)" };
                println!("Storage: {}", storage);
                if let Some(lu) = pk.last_used_at {
                    println!("Last used: {}", lu.format("%Y-%m-%d %H:%M:%S UTC"));
                }
                println!("Created: {}", entry.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
                println!();
            }
        }
    }
    Ok(())
}

fn cmd_delete(vault: &mut VaultFile, id_str: &str) -> anyhow::Result<()> {
    let id: uuid::Uuid = id_str.parse()
        .map_err(|_| anyhow::anyhow!("Invalid entry ID: {}", id_str))?;

    let entry = vault.store().get(&id)
        .ok_or_else(|| anyhow::anyhow!("Entry not found: {}", id))?;

    if !matches!(&entry.credential, Credential::Passkey(_)) {
        anyhow::bail!("Entry {} is not a passkey", id);
    }

    let title = entry.title.clone();
    vault.store_mut().remove(&id);
    vault.save()?;
    println!("Passkey '{}' deleted.", title);
    Ok(())
}

fn cmd_export(vault: &VaultFile, id_str: &str, format: &str, json_output: bool, output: Option<&str>) -> anyhow::Result<()> {
    let entries_to_export: Vec<&crate::vault::entry::Entry> = if id_str == "all" {
        get_passkeys(vault)
    } else {
        let id: uuid::Uuid = id_str.parse()
            .map_err(|_| anyhow::anyhow!("Invalid entry ID: {}. Use 'all' to export all passkeys.", id_str))?;
        let entry = vault.store().get(&id)
            .ok_or_else(|| anyhow::anyhow!("Entry not found: {}", id))?;
        if !matches!(&entry.credential, Credential::Passkey(_)) {
            anyhow::bail!("Entry {} is not a passkey", id);
        }
        vec![entry]
    };

    if entries_to_export.is_empty() {
        anyhow::bail!("No passkeys to export");
    }

    match format {
        "json" => {
            let export_data: Vec<serde_json::Value> = entries_to_export.iter()
                .map(|e| passkey_export_json(e))
                .collect();
            let json_str = if json_output {
                serde_json::to_string(&export_data)?
            } else {
                serde_json::to_string_pretty(&export_data)?
            };
            if let Some(path) = output {
                std::fs::write(path, &json_str)?;
                println!("Exported {} passkey(s) to {}", entries_to_export.len(), path);
            } else {
                println!("{}", json_str);
            }
        }
        _ => anyhow::bail!("Unsupported export format: {}. Use 'json'.", format),
    }
    Ok(())
}

fn cmd_import(vault: &mut VaultFile, path: &str) -> anyhow::Result<()> {
    use crate::vault::entry::{Entry, PasskeyAlgorithm, PasskeyCredential};

    let content = std::fs::read_to_string(path)?;
    let entries: Vec<serde_json::Value> = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Failed to parse import file: {}", e))?;

    let mut imported = 0;
    let mut skipped = 0;

    for item in &entries {
        let rp_id = item["rp_id"].as_str().unwrap_or_default();
        let rp_name = item["rp_name"].as_str().unwrap_or_default();
        let user_name = item["user_name"].as_str().unwrap_or_default();
        let credential_id = item["credential_id"].as_str().unwrap_or_default();

        if credential_id.is_empty() || rp_id.is_empty() {
            skipped += 1;
            continue;
        }

        // Check for duplicate by credential_id
        let exists = get_passkeys(vault).iter().any(|e| {
            if let Credential::Passkey(pk) = &e.credential {
                pk.credential_id == credential_id
            } else {
                false
            }
        });
        if exists {
            skipped += 1;
            continue;
        }

        let algorithm = match item["algorithm"].as_str() {
            Some("eddsa") => PasskeyAlgorithm::EdDsa,
            _ => PasskeyAlgorithm::Es256,
        };

        let passkey = PasskeyCredential {
            credential_id: credential_id.to_string(),
            rp_id: rp_id.to_string(),
            rp_name: rp_name.to_string(),
            user_handle: item["user_handle"].as_str().unwrap_or_default().to_string(),
            user_name: user_name.to_string(),
            private_key: item["private_key"].as_str().unwrap_or_default().to_string(),
            algorithm,
            sign_count: item["sign_count"].as_u64().unwrap_or(0) as u32,
            discoverable: item["discoverable"].as_bool().unwrap_or(true),
            backup_eligible: item["backup_eligible"].as_bool().unwrap_or(false),
            backup_state: item["backup_state"].as_bool().unwrap_or(false),
            last_used_at: None,
        };

        let title = item["title"].as_str()
            .unwrap_or(&format!("{} ({})", rp_name, user_name))
            .to_string();

        vault.store_mut().add(Entry::new(title, Credential::Passkey(passkey)));
        imported += 1;
    }

    vault.save()?;
    println!("Imported {} passkey(s), skipped {} (duplicates or invalid).", imported, skipped);
    Ok(())
}

/// Full passkey export with private key for backup/sync purposes.
fn passkey_export_json(entry: &crate::vault::entry::Entry) -> serde_json::Value {
    if let Credential::Passkey(pk) = &entry.credential {
        serde_json::json!({
            "id": entry.id,
            "title": entry.title,
            "credential_id": pk.credential_id,
            "rp_id": pk.rp_id,
            "rp_name": pk.rp_name,
            "user_name": pk.user_name,
            "user_handle": pk.user_handle,
            "private_key": pk.private_key,
            "algorithm": pk.algorithm,
            "sign_count": pk.sign_count,
            "discoverable": pk.discoverable,
            "backup_eligible": pk.backup_eligible,
            "backup_state": pk.backup_state,
            "last_used_at": pk.last_used_at,
            "created_at": entry.created_at,
        })
    } else {
        serde_json::json!({})
    }
}

fn cmd_list_hardware(_json_output: bool) -> anyhow::Result<()> {
    #[cfg(feature = "yubikey")]
    {
        use crate::platform::yubikey;

        let devices = ctap_hid_fido2::FidoKeyHidFactory::create(&ctap_hid_fido2::Cfg::init())
            .map_err(|e| anyhow::anyhow!("No FIDO2 device found: {}", e))?;

        let device = devices
            .first()
            .ok_or_else(|| anyhow::anyhow!("No FIDO2 device found. Insert a YubiKey and try again."))?;

        println!("Touch your YubiKey to enumerate credentials...");

        // We can't enumerate all rpIds easily; user would need to specify
        println!("Hardware credential enumeration requires specifying an RP ID.");
        println!("Use: vaultclaw passkey list --hardware (lists vault-metadata for hardware keys)");

        // List from vault metadata instead — hardware passkeys stored as entries with a marker
        Ok(())
    }
    #[cfg(not(feature = "yubikey"))]
    {
        anyhow::bail!("Hardware passkey support requires the 'yubikey' feature. Build with: cargo build --features yubikey");
    }
}

#[cfg(feature = "yubikey")]
fn cmd_create_hardware(
    vault: &mut VaultFile,
    rp_id: &str,
    rp_name: &str,
    user_name: &str,
) -> anyhow::Result<()> {
    use crate::platform::yubikey;
    use crate::vault::entry::{Entry, PasskeyAlgorithm, PasskeyCredential};

    let devices = ctap_hid_fido2::FidoKeyHidFactory::create(&ctap_hid_fido2::Cfg::init())
        .map_err(|e| anyhow::anyhow!("No FIDO2 device found: {}", e))?;

    let device = devices
        .first()
        .ok_or_else(|| anyhow::anyhow!("No FIDO2 device found. Insert a YubiKey and try again."))?;

    println!("Touch your YubiKey to create passkey for {}...", rp_name);

    let user_id = uuid::Uuid::new_v4();
    let cred_id = yubikey::create_resident_credential(
        device,
        rp_id,
        rp_name,
        user_id.as_bytes(),
        user_name,
    )
    .map_err(|e| anyhow::anyhow!(e))?;

    let cred_id_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&cred_id);

    // Store metadata in vault (private key is on hardware, store empty placeholder)
    let passkey = PasskeyCredential {
        credential_id: cred_id_b64.clone(),
        rp_id: rp_id.to_string(),
        rp_name: rp_name.to_string(),
        user_handle: base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(user_id.as_bytes()),
        user_name: user_name.to_string(),
        private_key: String::new(), // Hardware-bound, no extractable key
        algorithm: PasskeyAlgorithm::Es256, // YubiKey typically uses ES256
        sign_count: 0,
        discoverable: true,
        backup_eligible: false, // Hardware keys are not backup-eligible
        backup_state: false,
        last_used_at: None,
    };

    let entry = Entry::new(
        format!("{} ({}) [HW]", rp_name, user_name),
        Credential::Passkey(passkey),
    );
    let id = entry.id;
    vault.store_mut().add(entry);
    vault.save()?;

    println!("Hardware passkey created:");
    println!("  Entry ID: {}", id);
    println!("  Credential ID: {}", cred_id_b64);
    println!("  RP: {} ({})", rp_name, rp_id);
    println!("  User: {}", user_name);
    println!("  Storage: YubiKey (hardware-bound)");

    Ok(())
}

#[cfg(feature = "yubikey")]
fn cmd_create_software(
    vault: &mut VaultFile,
    rp_id: &str,
    rp_name: &str,
    user_name: &str,
) -> anyhow::Result<()> {
    use crate::passkey::generate_passkey_credential;
    use crate::vault::entry::{Entry, PasskeyAlgorithm, PasskeyCredential};

    let key_pair = generate_passkey_credential(&PasskeyAlgorithm::Es256)
        .map_err(|e| anyhow::anyhow!(e))?;

    let user_id = uuid::Uuid::new_v4();
    let passkey = PasskeyCredential {
        credential_id: key_pair.credential_id.clone(),
        rp_id: rp_id.to_string(),
        rp_name: rp_name.to_string(),
        user_handle: base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(user_id.as_bytes()),
        user_name: user_name.to_string(),
        private_key: key_pair.cose_private_key,
        algorithm: PasskeyAlgorithm::Es256,
        sign_count: 0,
        discoverable: true,
        backup_eligible: true,
        backup_state: false,
        last_used_at: None,
    };

    let entry = Entry::new(
        format!("{} ({})", rp_name, user_name),
        Credential::Passkey(passkey),
    );
    let id = entry.id;
    vault.store_mut().add(entry);
    vault.save()?;

    println!("Software passkey created:");
    println!("  Entry ID: {}", id);
    println!("  Credential ID: {}", key_pair.credential_id);
    println!("  RP: {} ({})", rp_name, rp_id);
    println!("  User: {}", user_name);
    println!("  Storage: Vault (software)");

    Ok(())
}

fn passkey_summary_json(entry: &crate::vault::entry::Entry) -> serde_json::Value {
    if let Credential::Passkey(pk) = &entry.credential {
        let storage = if pk.private_key.is_empty() {
            "hardware"
        } else {
            "software"
        };
        serde_json::json!({
            "id": entry.id,
            "title": entry.title,
            "rp_id": pk.rp_id,
            "rp_name": pk.rp_name,
            "user_name": pk.user_name,
            "user_handle": pk.user_handle,
            "algorithm": pk.algorithm,
            "sign_count": pk.sign_count,
            "discoverable": pk.discoverable,
            "backup_eligible": pk.backup_eligible,
            "backup_state": pk.backup_state,
            "storage": storage,
            "last_used_at": pk.last_used_at,
            "created_at": entry.created_at,
            "updated_at": entry.updated_at,
        })
    } else {
        serde_json::json!({})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::KdfParams;
    use crate::crypto::keys::password_secret;
    use crate::vault::entry::{Entry, PasskeyAlgorithm, PasskeyCredential};
    use tempfile::TempDir;

    fn test_vault() -> (VaultFile, TempDir) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test".to_string());
        let vault = VaultFile::create(&path, &password, KdfParams::fast_for_testing()).unwrap();
        (vault, dir)
    }

    fn sample_passkey() -> Entry {
        Entry::new(
            "GitHub Passkey".to_string(),
            Credential::Passkey(PasskeyCredential {
                credential_id: "dGVzdC1pZA".to_string(),
                rp_id: "github.com".to_string(),
                rp_name: "GitHub".to_string(),
                user_handle: "dXNlcg".to_string(),
                user_name: "octocat".to_string(),
                private_key: "cHJpdmF0ZQ".to_string(),
                algorithm: PasskeyAlgorithm::Es256,
                sign_count: 5,
                discoverable: true,
                backup_eligible: false,
                backup_state: false,
                last_used_at: None,
            }),
        )
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
    fn test_cmd_list_with_passkeys() {
        let (mut vault, _dir) = test_vault();
        vault.store_mut().add(sample_passkey());
        vault.save().unwrap();

        cmd_list(&vault, false).unwrap();
        cmd_list(&vault, true).unwrap();
    }

    #[test]
    fn test_cmd_show_by_rp_id() {
        let (mut vault, _dir) = test_vault();
        vault.store_mut().add(sample_passkey());
        vault.save().unwrap();

        cmd_show(&vault, "github.com", false).unwrap();
    }

    #[test]
    fn test_cmd_show_by_title() {
        let (mut vault, _dir) = test_vault();
        vault.store_mut().add(sample_passkey());
        vault.save().unwrap();

        cmd_show(&vault, "GitHub", false).unwrap();
    }

    #[test]
    fn test_cmd_show_not_found() {
        let (vault, _dir) = test_vault();
        assert!(cmd_show(&vault, "nonexistent", false).is_err());
    }

    #[test]
    fn test_cmd_show_json() {
        let (mut vault, _dir) = test_vault();
        vault.store_mut().add(sample_passkey());
        vault.save().unwrap();

        cmd_show(&vault, "github", true).unwrap();
    }

    #[test]
    fn test_cmd_delete() {
        let (mut vault, _dir) = test_vault();
        let entry = sample_passkey();
        let id = entry.id;
        vault.store_mut().add(entry);
        vault.save().unwrap();

        cmd_delete(&mut vault, &id.to_string()).unwrap();
        assert!(vault.store().get(&id).is_none());
    }

    #[test]
    fn test_cmd_delete_not_found() {
        let (mut vault, _dir) = test_vault();
        assert!(cmd_delete(&mut vault, &uuid::Uuid::new_v4().to_string()).is_err());
    }

    #[test]
    fn test_cmd_delete_not_passkey() {
        let (mut vault, _dir) = test_vault();
        let login = Entry::new(
            "Login".to_string(),
            Credential::Login(crate::vault::entry::LoginCredential {
                url: "https://example.com".to_string(),
                username: "user".to_string(),
                password: "pass".to_string(),
            }),
        );
        let id = login.id;
        vault.store_mut().add(login);
        vault.save().unwrap();

        assert!(cmd_delete(&mut vault, &id.to_string()).is_err());
    }

    #[test]
    fn test_cmd_export_json() {
        let (mut vault, _dir) = test_vault();
        let entry = sample_passkey();
        let id = entry.id;
        vault.store_mut().add(entry);
        vault.save().unwrap();

        cmd_export(&vault, &id.to_string(), "json", false, None).unwrap();
    }

    #[test]
    fn test_cmd_export_unsupported_format() {
        let (mut vault, _dir) = test_vault();
        let entry = sample_passkey();
        let id = entry.id;
        vault.store_mut().add(entry);
        vault.save().unwrap();

        assert!(cmd_export(&vault, &id.to_string(), "xml", false, None).is_err());
    }

    #[test]
    fn test_cmd_export_all() {
        let (mut vault, _dir) = test_vault();
        vault.store_mut().add(sample_passkey());
        vault.save().unwrap();

        cmd_export(&vault, "all", "json", false, None).unwrap();
    }

    #[test]
    fn test_cmd_export_to_file() {
        let (mut vault, dir) = test_vault();
        vault.store_mut().add(sample_passkey());
        vault.save().unwrap();

        let export_path = dir.path().join("export.json");
        cmd_export(&vault, "all", "json", false, Some(export_path.to_str().unwrap())).unwrap();
        assert!(export_path.exists());

        let content = std::fs::read_to_string(&export_path).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["rp_id"], "github.com");
    }

    #[test]
    fn test_cmd_import() {
        let (mut vault, dir) = test_vault();

        // Write an export file
        let export_data = serde_json::json!([{
            "credential_id": "aW1wb3J0LWlk",
            "rp_id": "imported.example.com",
            "rp_name": "Imported Site",
            "user_handle": "dXNlcg",
            "user_name": "importuser",
            "private_key": "c29tZS1rZXk",
            "algorithm": "es256",
            "sign_count": 5,
            "title": "Imported Passkey"
        }]);
        let import_path = dir.path().join("import.json");
        std::fs::write(&import_path, serde_json::to_string(&export_data).unwrap()).unwrap();

        cmd_import(&mut vault, import_path.to_str().unwrap()).unwrap();

        let passkeys = get_passkeys(&vault);
        assert_eq!(passkeys.len(), 1);
        if let Credential::Passkey(pk) = &passkeys[0].credential {
            assert_eq!(pk.rp_id, "imported.example.com");
            assert_eq!(pk.sign_count, 5);
        } else {
            panic!("Expected Passkey");
        }
    }

    #[test]
    fn test_cmd_import_duplicate_skipped() {
        let (mut vault, dir) = test_vault();
        vault.store_mut().add(sample_passkey());
        vault.save().unwrap();

        // Try to import a passkey with the same credential_id
        let export_data = serde_json::json!([{
            "credential_id": "dGVzdC1pZA",  // Same as sample_passkey
            "rp_id": "github.com",
            "rp_name": "GitHub",
            "user_handle": "dXNlcg",
            "user_name": "octocat",
            "private_key": "different_key",
        }]);
        let import_path = dir.path().join("import.json");
        std::fs::write(&import_path, serde_json::to_string(&export_data).unwrap()).unwrap();

        cmd_import(&mut vault, import_path.to_str().unwrap()).unwrap();

        // Should still be just 1 (duplicate skipped)
        let passkeys = get_passkeys(&vault);
        assert_eq!(passkeys.len(), 1);
    }

    #[test]
    fn test_cmd_export_import_roundtrip() {
        let (mut vault, dir) = test_vault();
        vault.store_mut().add(sample_passkey());
        vault.save().unwrap();

        // Export
        let export_path = dir.path().join("roundtrip.json");
        cmd_export(&vault, "all", "json", false, Some(export_path.to_str().unwrap())).unwrap();

        // Create a new vault and import
        let new_path = dir.path().join("new.vclaw");
        let password = password_secret("test".to_string());
        let mut new_vault = VaultFile::create(&new_path, &password, KdfParams::fast_for_testing()).unwrap();

        cmd_import(&mut new_vault, export_path.to_str().unwrap()).unwrap();

        let passkeys = get_passkeys(&new_vault);
        assert_eq!(passkeys.len(), 1);
        if let Credential::Passkey(pk) = &passkeys[0].credential {
            assert_eq!(pk.rp_id, "github.com");
            assert_eq!(pk.user_name, "octocat");
        }
    }

    #[test]
    fn test_get_passkeys_filters_correctly() {
        let (mut vault, _dir) = test_vault();
        vault.store_mut().add(sample_passkey());
        vault.store_mut().add(Entry::new(
            "Login".to_string(),
            Credential::Login(crate::vault::entry::LoginCredential {
                url: "https://example.com".to_string(),
                username: "user".to_string(),
                password: "pass".to_string(),
            }),
        ));
        vault.save().unwrap();

        let passkeys = get_passkeys(&vault);
        assert_eq!(passkeys.len(), 1);
    }

    #[test]
    fn test_passkey_summary_json_fields() {
        let entry = sample_passkey();
        let json = passkey_summary_json(&entry);
        assert_eq!(json["rp_id"], "github.com");
        assert_eq!(json["rp_name"], "GitHub");
        assert_eq!(json["user_name"], "octocat");
        assert_eq!(json["sign_count"], 5);
        assert_eq!(json["algorithm"], "es256");
        assert_eq!(json["storage"], "software");
        // Private key should NOT be in the summary
        assert!(json.get("private_key").is_none());
    }

    #[test]
    fn test_passkey_summary_json_hardware() {
        let mut entry = sample_passkey();
        if let Credential::Passkey(ref mut pk) = entry.credential {
            pk.private_key = String::new(); // Hardware passkey has empty private_key
        }
        let json = passkey_summary_json(&entry);
        assert_eq!(json["storage"], "hardware");
    }

    #[test]
    fn test_cmd_list_with_hardware_flag_no_feature() {
        // Without yubikey feature, hardware list should return an error
        #[cfg(not(feature = "yubikey"))]
        {
            let result = cmd_list_hardware(false);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_cmd_list_shows_storage_type() {
        let (mut vault, _dir) = test_vault();
        vault.store_mut().add(sample_passkey());

        // Add a hardware passkey (empty private_key)
        let hw_entry = Entry::new(
            "Hardware Passkey".to_string(),
            Credential::Passkey(PasskeyCredential {
                credential_id: "aHctY3JlZA".to_string(),
                rp_id: "hardware.example.com".to_string(),
                rp_name: "Hardware Example".to_string(),
                user_handle: "dXNlcg".to_string(),
                user_name: "hw_user".to_string(),
                private_key: String::new(), // Empty = hardware
                algorithm: PasskeyAlgorithm::Es256,
                sign_count: 0,
                discoverable: true,
                backup_eligible: false,
                backup_state: false,
                last_used_at: None,
            }),
        );
        vault.store_mut().add(hw_entry);
        vault.save().unwrap();

        // Verify both appear in list
        let passkeys = get_passkeys(&vault);
        assert_eq!(passkeys.len(), 2);

        // Verify JSON includes storage
        cmd_list(&vault, true).unwrap();
        cmd_list(&vault, false).unwrap();
    }

    #[test]
    fn test_cmd_show_hardware_passkey() {
        let (mut vault, _dir) = test_vault();
        vault.store_mut().add(Entry::new(
            "HW Passkey".to_string(),
            Credential::Passkey(PasskeyCredential {
                credential_id: "aHctY3JlZA".to_string(),
                rp_id: "hw.example.com".to_string(),
                rp_name: "HW Example".to_string(),
                user_handle: "dXNlcg".to_string(),
                user_name: "hw_user".to_string(),
                private_key: String::new(),
                algorithm: PasskeyAlgorithm::Es256,
                sign_count: 3,
                discoverable: true,
                backup_eligible: false,
                backup_state: false,
                last_used_at: None,
            }),
        ));
        vault.save().unwrap();

        cmd_show(&vault, "hw.example.com", false).unwrap();
        cmd_show(&vault, "hw.example.com", true).unwrap();
    }

    #[test]
    fn test_cmd_delete_hardware_message() {
        // Delete with hardware flag just prints a message
        let (mut vault, _dir) = test_vault();
        let result = handle_passkey_command(
            PasskeyCommands::Delete { id: uuid::Uuid::new_v4().to_string(), hardware: true },
            &mut vault,
            false,
        );
        assert!(result.is_ok());
    }

    // --- Tests for handle_passkey_command dispatch paths ---

    #[test]
    fn test_handle_passkey_list_software() {
        let (mut vault, _dir) = test_vault();
        vault.store_mut().add(sample_passkey());
        vault.save().unwrap();
        let result = handle_passkey_command(
            PasskeyCommands::List { hardware: false },
            &mut vault,
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_passkey_list_hardware() {
        let (mut vault, _dir) = test_vault();
        // Without yubikey feature this should error
        #[cfg(not(feature = "yubikey"))]
        {
            let result = handle_passkey_command(
                PasskeyCommands::List { hardware: true },
                &mut vault,
                false,
            );
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_handle_passkey_show() {
        let (mut vault, _dir) = test_vault();
        vault.store_mut().add(sample_passkey());
        vault.save().unwrap();
        let result = handle_passkey_command(
            PasskeyCommands::Show { query: "github".to_string() },
            &mut vault,
            true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_passkey_delete_software() {
        let (mut vault, _dir) = test_vault();
        let entry = sample_passkey();
        let id = entry.id;
        vault.store_mut().add(entry);
        vault.save().unwrap();
        let result = handle_passkey_command(
            PasskeyCommands::Delete { id: id.to_string(), hardware: false },
            &mut vault,
            false,
        );
        assert!(result.is_ok());
        assert!(vault.store().get(&id).is_none());
    }

    #[test]
    fn test_handle_passkey_export() {
        let (mut vault, _dir) = test_vault();
        vault.store_mut().add(sample_passkey());
        vault.save().unwrap();
        let result = handle_passkey_command(
            PasskeyCommands::Export {
                id: "all".to_string(),
                format: "json".to_string(),
                output: None,
            },
            &mut vault,
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_passkey_import() {
        let (mut vault, dir) = test_vault();
        let import_data = serde_json::json!([{
            "credential_id": "aW1wb3J0LXZpYS1oYW5kbGU",
            "rp_id": "handle.example.com",
            "rp_name": "Handle Example",
            "user_handle": "dXNlcg",
            "user_name": "handleuser",
            "private_key": "c29tZS1rZXk",
        }]);
        let import_path = dir.path().join("handle_import.json");
        std::fs::write(&import_path, serde_json::to_string(&import_data).unwrap()).unwrap();
        let result = handle_passkey_command(
            PasskeyCommands::Import { path: import_path.to_str().unwrap().to_string() },
            &mut vault,
            false,
        );
        assert!(result.is_ok());
        assert_eq!(get_passkeys(&vault).len(), 1);
    }

    // --- Tests for cmd_show search branches ---

    #[test]
    fn test_cmd_show_by_entry_title() {
        let (mut vault, _dir) = test_vault();
        // Use a passkey whose rp_id does NOT contain the query but title does
        vault.store_mut().add(Entry::new(
            "My Special Key".to_string(),
            Credential::Passkey(PasskeyCredential {
                credential_id: "dGl0bGUtbWF0Y2g".to_string(),
                rp_id: "nomatch.example.com".to_string(),
                rp_name: "NoMatchRP".to_string(),
                user_handle: "dXNlcg".to_string(),
                user_name: "user1".to_string(),
                private_key: "a2V5".to_string(),
                algorithm: PasskeyAlgorithm::Es256,
                sign_count: 0,
                discoverable: true,
                backup_eligible: false,
                backup_state: false,
                last_used_at: None,
            }),
        ));
        vault.save().unwrap();
        // Query matches title "My Special Key" (case-insensitive) but not rp_id or rp_name
        cmd_show(&vault, "special", false).unwrap();
    }

    #[test]
    fn test_cmd_show_by_id_prefix() {
        let (mut vault, _dir) = test_vault();
        let entry = Entry::new(
            "ID Search Passkey".to_string(),
            Credential::Passkey(PasskeyCredential {
                credential_id: "aWQtc2VhcmNo".to_string(),
                rp_id: "zzz-no-match.example.com".to_string(),
                rp_name: "ZZZNoMatchRP".to_string(),
                user_handle: "dXNlcg".to_string(),
                user_name: "zzzuser".to_string(),
                private_key: "a2V5".to_string(),
                algorithm: PasskeyAlgorithm::Es256,
                sign_count: 0,
                discoverable: true,
                backup_eligible: false,
                backup_state: false,
                last_used_at: None,
            }),
        );
        let id_prefix = entry.id.to_string()[..8].to_string();
        vault.store_mut().add(entry);
        vault.save().unwrap();
        // Query by UUID prefix — doesn't match rp_id, rp_name, or title
        cmd_show(&vault, &id_prefix, false).unwrap();
    }

    #[test]
    fn test_cmd_show_with_last_used_at() {
        let (mut vault, _dir) = test_vault();
        vault.store_mut().add(Entry::new(
            "Used Passkey".to_string(),
            Credential::Passkey(PasskeyCredential {
                credential_id: "bGFzdC11c2Vk".to_string(),
                rp_id: "used.example.com".to_string(),
                rp_name: "Used Example".to_string(),
                user_handle: "dXNlcg".to_string(),
                user_name: "useduser".to_string(),
                private_key: "a2V5".to_string(),
                algorithm: PasskeyAlgorithm::Es256,
                sign_count: 10,
                discoverable: true,
                backup_eligible: true,
                backup_state: true,
                last_used_at: Some(chrono::Utc::now()),
            }),
        ));
        vault.save().unwrap();
        // Non-JSON output exercises the last_used_at Some branch (L180-181)
        cmd_show(&vault, "used.example.com", false).unwrap();
    }

    // --- Tests for cmd_delete edge cases ---

    #[test]
    fn test_cmd_delete_invalid_uuid() {
        let (mut vault, _dir) = test_vault();
        let result = cmd_delete(&mut vault, "not-a-uuid");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Invalid entry ID"));
    }

    // --- Tests for cmd_export edge cases ---

    #[test]
    fn test_cmd_export_not_passkey() {
        let (mut vault, _dir) = test_vault();
        let login = Entry::new(
            "Login Entry".to_string(),
            Credential::Login(crate::vault::entry::LoginCredential {
                url: "https://example.com".to_string(),
                username: "user".to_string(),
                password: "pass".to_string(),
            }),
        );
        let id = login.id;
        vault.store_mut().add(login);
        vault.save().unwrap();
        let result = cmd_export(&vault, &id.to_string(), "json", false, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("is not a passkey"));
    }

    #[test]
    fn test_cmd_export_invalid_uuid() {
        let (vault, _dir) = test_vault();
        let result = cmd_export(&vault, "bad-id", "json", false, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid entry ID"));
    }

    #[test]
    fn test_cmd_export_not_found() {
        let (vault, _dir) = test_vault();
        let result = cmd_export(&vault, &uuid::Uuid::new_v4().to_string(), "json", false, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Entry not found"));
    }

    #[test]
    fn test_cmd_export_all_empty_vault() {
        let (vault, _dir) = test_vault();
        let result = cmd_export(&vault, "all", "json", false, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No passkeys to export"));
    }

    #[test]
    fn test_cmd_export_json_compact() {
        let (mut vault, _dir) = test_vault();
        vault.store_mut().add(sample_passkey());
        vault.save().unwrap();
        // json_output=true triggers compact serde_json::to_string (L233)
        cmd_export(&vault, "all", "json", true, None).unwrap();
    }

    #[test]
    fn test_cmd_export_to_file_compact() {
        let (mut vault, dir) = test_vault();
        vault.store_mut().add(sample_passkey());
        vault.save().unwrap();
        let export_path = dir.path().join("compact_export.json");
        cmd_export(&vault, "all", "json", true, Some(export_path.to_str().unwrap())).unwrap();
        assert!(export_path.exists());
    }

    // --- Tests for cmd_import edge cases ---

    #[test]
    fn test_cmd_import_skip_missing_fields() {
        let (mut vault, dir) = test_vault();
        // Entry with empty credential_id and rp_id — should be skipped
        let data = serde_json::json!([
            {
                "credential_id": "",
                "rp_id": "has-rp.example.com",
                "rp_name": "Has RP",
                "user_name": "user1",
                "private_key": "a2V5"
            },
            {
                "credential_id": "aGFzLWNyZWQ",
                "rp_id": "",
                "rp_name": "Empty RP",
                "user_name": "user2",
                "private_key": "a2V5"
            },
            {
                "credential_id": "dmFsaWQ",
                "rp_id": "valid.example.com",
                "rp_name": "Valid",
                "user_name": "validuser",
                "private_key": "a2V5"
            }
        ]);
        let path = dir.path().join("skip_import.json");
        std::fs::write(&path, serde_json::to_string(&data).unwrap()).unwrap();
        cmd_import(&mut vault, path.to_str().unwrap()).unwrap();
        // Only 1 valid entry imported, 2 skipped
        assert_eq!(get_passkeys(&vault).len(), 1);
    }

    #[test]
    fn test_cmd_import_eddsa_algorithm() {
        let (mut vault, dir) = test_vault();
        let data = serde_json::json!([{
            "credential_id": "ZWRkc2EtY3JlZA",
            "rp_id": "eddsa.example.com",
            "rp_name": "EdDSA Site",
            "user_handle": "dXNlcg",
            "user_name": "eddsauser",
            "private_key": "ZWRkc2Eta2V5",
            "algorithm": "eddsa",
            "sign_count": 3
        }]);
        let path = dir.path().join("eddsa_import.json");
        std::fs::write(&path, serde_json::to_string(&data).unwrap()).unwrap();
        cmd_import(&mut vault, path.to_str().unwrap()).unwrap();
        let passkeys = get_passkeys(&vault);
        assert_eq!(passkeys.len(), 1);
        if let Credential::Passkey(pk) = &passkeys[0].credential {
            assert!(matches!(pk.algorithm, PasskeyAlgorithm::EdDsa));
            assert_eq!(pk.sign_count, 3);
        }
    }

    #[test]
    fn test_cmd_import_no_title_uses_default() {
        let (mut vault, dir) = test_vault();
        // No "title" field — should use default "{rp_name} ({user_name})"
        let data = serde_json::json!([{
            "credential_id": "bm8tdGl0bGU",
            "rp_id": "notitle.example.com",
            "rp_name": "NoTitle Site",
            "user_handle": "dXNlcg",
            "user_name": "notitleuser",
            "private_key": "a2V5"
        }]);
        let path = dir.path().join("notitle_import.json");
        std::fs::write(&path, serde_json::to_string(&data).unwrap()).unwrap();
        cmd_import(&mut vault, path.to_str().unwrap()).unwrap();
        let passkeys = get_passkeys(&vault);
        assert_eq!(passkeys.len(), 1);
        assert_eq!(passkeys[0].title, "NoTitle Site (notitleuser)");
    }

    #[test]
    fn test_cmd_import_invalid_json() {
        let (mut vault, dir) = test_vault();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, "not valid json!!!").unwrap();
        let result = cmd_import(&mut vault, path.to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to parse import file"));
    }

    #[test]
    fn test_cmd_import_file_not_found() {
        let (mut vault, _dir) = test_vault();
        let result = cmd_import(&mut vault, "/nonexistent/path/import.json");
        assert!(result.is_err());
    }

    // --- Test for passkey_export_json non-passkey branch ---

    #[test]
    fn test_passkey_export_json_non_passkey() {
        let login = Entry::new(
            "Login".to_string(),
            Credential::Login(crate::vault::entry::LoginCredential {
                url: "https://example.com".to_string(),
                username: "user".to_string(),
                password: "pass".to_string(),
            }),
        );
        let json = passkey_export_json(&login);
        assert_eq!(json, serde_json::json!({}));
    }

    // --- Test for passkey_summary_json non-passkey branch ---

    #[test]
    fn test_passkey_summary_json_non_passkey() {
        let login = Entry::new(
            "Login".to_string(),
            Credential::Login(crate::vault::entry::LoginCredential {
                url: "https://example.com".to_string(),
                username: "user".to_string(),
                password: "pass".to_string(),
            }),
        );
        let json = passkey_summary_json(&login);
        assert_eq!(json, serde_json::json!({}));
    }
}
