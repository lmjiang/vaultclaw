use std::path::PathBuf;

use clap::Subcommand;

use crate::sync::multi_vault::{MultiVaultManager, VaultRef};

/// Subcommands for `vaultclaw vault`.
#[derive(Subcommand, Debug, Clone)]
pub enum VaultCommands {
    /// List all registered vaults
    List,
    /// Register a vault
    Register {
        /// Vault name
        name: String,
        /// Path to vault file
        path: PathBuf,
        /// Description
        #[arg(short, long, default_value = "")]
        description: String,
    },
    /// Remove a vault registration (does not delete the file)
    Remove {
        /// Vault name
        name: String,
    },
    /// Switch the active vault
    Switch {
        /// Vault name to activate
        name: String,
    },
    /// Show the active vault
    Active,
}

/// Handle `vaultclaw vault <subcommand>`.
pub fn handle_vault_command(command: VaultCommands, json_output: bool) -> anyhow::Result<()> {
    let mut mgr = MultiVaultManager::load();
    handle_vault_command_with_mgr(command, &mut mgr, json_output)?;
    mgr.save().map_err(|e| anyhow::anyhow!("{}", e))?;
    Ok(())
}

fn handle_vault_command_with_mgr(
    command: VaultCommands,
    mgr: &mut MultiVaultManager,
    json_output: bool,
) -> anyhow::Result<()> {
    match command {
        VaultCommands::List => cmd_vault_list(mgr, json_output),
        VaultCommands::Register { name, path, description } => {
            cmd_vault_register(mgr, &name, path, &description, json_output)
        }
        VaultCommands::Remove { name } => cmd_vault_remove(mgr, &name, json_output),
        VaultCommands::Switch { name } => cmd_vault_switch(mgr, &name, json_output),
        VaultCommands::Active => cmd_vault_active(mgr, json_output),
    }
}

fn cmd_vault_list(mgr: &MultiVaultManager, json_output: bool) -> anyhow::Result<()> {
    let vaults = mgr.list_vaults();

    if json_output {
        println!("{}", serde_json::to_string_pretty(&vaults)?);
    } else if vaults.is_empty() {
        println!("No vaults registered. Use `vaultclaw vault register` to add one.");
    } else {
        let active_name = mgr.active_vault().map(|v| v.name.as_str());
        for vault in &vaults {
            let marker = if Some(vault.name.as_str()) == active_name { "*" } else { " " };
            let desc = if vault.description.is_empty() {
                String::new()
            } else {
                format!(" — {}", vault.description)
            };
            println!("{} {}{} ({})", marker, vault.name, desc, vault.path.display());
        }
        println!("\n{} vault(s) registered", vaults.len());
    }
    Ok(())
}

fn cmd_vault_register(
    mgr: &mut MultiVaultManager,
    name: &str,
    path: PathBuf,
    description: &str,
    json_output: bool,
) -> anyhow::Result<()> {
    let vault = VaultRef {
        name: name.to_string(),
        path: path.clone(),
        description: description.to_string(),
        is_default: mgr.is_empty(),
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    mgr.add_vault(vault).map_err(|e| anyhow::anyhow!("{}", e))?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "registered": name,
            "path": path.display().to_string(),
        }))?);
    } else {
        println!("Registered vault '{}' at {}", name, path.display());
    }
    Ok(())
}

fn cmd_vault_remove(mgr: &mut MultiVaultManager, name: &str, json_output: bool) -> anyhow::Result<()> {
    let removed = mgr.remove_vault(name).map_err(|e| anyhow::anyhow!("{}", e))?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "removed": name,
            "path": removed.path.display().to_string(),
        }))?);
    } else {
        println!("Removed vault '{}' (file at {} was not deleted)", name, removed.path.display());
    }
    Ok(())
}

fn cmd_vault_switch(mgr: &mut MultiVaultManager, name: &str, json_output: bool) -> anyhow::Result<()> {
    mgr.set_active(name).map_err(|e| anyhow::anyhow!("{}", e))?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "active": name,
        }))?);
    } else {
        println!("Switched to vault '{}'", name);
    }
    Ok(())
}

fn cmd_vault_active(mgr: &MultiVaultManager, json_output: bool) -> anyhow::Result<()> {
    if let Some(vault) = mgr.active_vault() {
        if json_output {
            println!("{}", serde_json::to_string_pretty(&vault)?);
        } else {
            println!("Active vault: {} ({})", vault.name, vault.path.display());
            if !vault.description.is_empty() {
                println!("Description: {}", vault.description);
            }
        }
    } else if json_output {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "active": null,
        }))?);
    } else {
        println!("No active vault. Use `vaultclaw vault register` to add one.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vault(name: &str, desc: &str, is_default: bool) -> VaultRef {
        VaultRef {
            name: name.into(),
            path: PathBuf::from(format!("/tmp/{}.vclaw", name)),
            description: desc.into(),
            is_default,
            created_at: "2024-01-01T00:00:00Z".into(),
        }
    }

    // ---- Tests via handle_vault_command_with_mgr (covers all dispatch + handlers) ----

    #[test]
    fn test_list_empty() {
        let mut mgr = MultiVaultManager::new();
        handle_vault_command_with_mgr(VaultCommands::List, &mut mgr, false).unwrap();
    }

    #[test]
    fn test_list_empty_json() {
        let mut mgr = MultiVaultManager::new();
        handle_vault_command_with_mgr(VaultCommands::List, &mut mgr, true).unwrap();
    }

    #[test]
    fn test_list_with_vaults() {
        let mut mgr = MultiVaultManager::new();
        mgr.add_vault(make_vault("alpha", "First vault", true)).unwrap();
        mgr.add_vault(make_vault("bravo", "", false)).unwrap();
        handle_vault_command_with_mgr(VaultCommands::List, &mut mgr, false).unwrap();
    }

    #[test]
    fn test_list_with_vaults_json() {
        let mut mgr = MultiVaultManager::new();
        mgr.add_vault(make_vault("alpha", "", true)).unwrap();
        handle_vault_command_with_mgr(VaultCommands::List, &mut mgr, true).unwrap();
    }

    #[test]
    fn test_register_first_vault() {
        let mut mgr = MultiVaultManager::new();
        handle_vault_command_with_mgr(
            VaultCommands::Register {
                name: "myvault".into(),
                path: PathBuf::from("/tmp/my.vclaw"),
                description: "My vault".into(),
            },
            &mut mgr,
            false,
        ).unwrap();
        assert_eq!(mgr.list_vaults().len(), 1);
        assert_eq!(mgr.list_vaults()[0].name, "myvault");
        // First vault gets is_default = true
        assert!(mgr.list_vaults()[0].is_default);
    }

    #[test]
    fn test_register_json() {
        let mut mgr = MultiVaultManager::new();
        handle_vault_command_with_mgr(
            VaultCommands::Register {
                name: "myvault".into(),
                path: PathBuf::from("/tmp/my.vclaw"),
                description: "".into(),
            },
            &mut mgr,
            true,
        ).unwrap();
        assert_eq!(mgr.list_vaults().len(), 1);
    }

    #[test]
    fn test_register_duplicate_error() {
        let mut mgr = MultiVaultManager::new();
        mgr.add_vault(make_vault("dup", "", false)).unwrap();
        let result = handle_vault_command_with_mgr(
            VaultCommands::Register {
                name: "dup".into(),
                path: PathBuf::from("/tmp/dup2.vclaw"),
                description: "".into(),
            },
            &mut mgr,
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_existing() {
        let mut mgr = MultiVaultManager::new();
        mgr.add_vault(make_vault("removable", "", false)).unwrap();
        handle_vault_command_with_mgr(
            VaultCommands::Remove { name: "removable".into() },
            &mut mgr,
            false,
        ).unwrap();
        assert!(mgr.is_empty());
    }

    #[test]
    fn test_remove_json() {
        let mut mgr = MultiVaultManager::new();
        mgr.add_vault(make_vault("removable", "", false)).unwrap();
        handle_vault_command_with_mgr(
            VaultCommands::Remove { name: "removable".into() },
            &mut mgr,
            true,
        ).unwrap();
        assert!(mgr.is_empty());
    }

    #[test]
    fn test_remove_not_found() {
        let mut mgr = MultiVaultManager::new();
        let result = handle_vault_command_with_mgr(
            VaultCommands::Remove { name: "nonexistent".into() },
            &mut mgr,
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_switch() {
        let mut mgr = MultiVaultManager::new();
        mgr.add_vault(make_vault("v1", "", false)).unwrap();
        mgr.add_vault(make_vault("v2", "", false)).unwrap();
        handle_vault_command_with_mgr(
            VaultCommands::Switch { name: "v2".into() },
            &mut mgr,
            false,
        ).unwrap();
        assert_eq!(mgr.active_vault().unwrap().name, "v2");
    }

    #[test]
    fn test_switch_json() {
        let mut mgr = MultiVaultManager::new();
        mgr.add_vault(make_vault("v1", "", false)).unwrap();
        handle_vault_command_with_mgr(
            VaultCommands::Switch { name: "v1".into() },
            &mut mgr,
            true,
        ).unwrap();
    }

    #[test]
    fn test_switch_not_found() {
        let mut mgr = MultiVaultManager::new();
        let result = handle_vault_command_with_mgr(
            VaultCommands::Switch { name: "nonexistent".into() },
            &mut mgr,
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_active_no_vault() {
        let mut mgr = MultiVaultManager::new();
        handle_vault_command_with_mgr(VaultCommands::Active, &mut mgr, false).unwrap();
    }

    #[test]
    fn test_active_no_vault_json() {
        let mut mgr = MultiVaultManager::new();
        handle_vault_command_with_mgr(VaultCommands::Active, &mut mgr, true).unwrap();
    }

    #[test]
    fn test_active_with_vault() {
        let mut mgr = MultiVaultManager::new();
        mgr.add_vault(make_vault("primary", "Main vault", true)).unwrap();
        mgr.set_active("primary").unwrap();
        handle_vault_command_with_mgr(VaultCommands::Active, &mut mgr, false).unwrap();
    }

    #[test]
    fn test_active_with_vault_json() {
        let mut mgr = MultiVaultManager::new();
        mgr.add_vault(make_vault("primary", "", true)).unwrap();
        mgr.set_active("primary").unwrap();
        handle_vault_command_with_mgr(VaultCommands::Active, &mut mgr, true).unwrap();
    }

    #[test]
    fn test_active_with_description() {
        let mut mgr = MultiVaultManager::new();
        mgr.add_vault(make_vault("primary", "Has description", true)).unwrap();
        mgr.set_active("primary").unwrap();
        handle_vault_command_with_mgr(VaultCommands::Active, &mut mgr, false).unwrap();
    }

    #[test]
    fn test_active_without_description() {
        let mut mgr = MultiVaultManager::new();
        mgr.add_vault(make_vault("primary", "", true)).unwrap();
        mgr.set_active("primary").unwrap();
        handle_vault_command_with_mgr(VaultCommands::Active, &mut mgr, false).unwrap();
    }

    #[test]
    fn test_list_active_marker() {
        let mut mgr = MultiVaultManager::new();
        mgr.add_vault(make_vault("a", "", false)).unwrap();
        mgr.add_vault(make_vault("b", "with desc", false)).unwrap();
        mgr.set_active("b").unwrap();
        // This exercises the active marker "*" vs " " and description formatting
        handle_vault_command_with_mgr(VaultCommands::List, &mut mgr, false).unwrap();
    }

    #[test]
    fn test_vault_ref_serialization() {
        let vault = make_vault("test", "A test vault", true);
        let json = serde_json::to_string(&vault).unwrap();
        let parsed: VaultRef = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "test");
        assert!(parsed.is_default);
    }

    #[test]
    fn test_full_workflow() {
        let mut mgr = MultiVaultManager::new();
        // Register two vaults
        handle_vault_command_with_mgr(
            VaultCommands::Register {
                name: "work".into(),
                path: PathBuf::from("/tmp/work.vclaw"),
                description: "Work passwords".into(),
            },
            &mut mgr,
            false,
        ).unwrap();
        handle_vault_command_with_mgr(
            VaultCommands::Register {
                name: "personal".into(),
                path: PathBuf::from("/tmp/personal.vclaw"),
                description: "".into(),
            },
            &mut mgr,
            false,
        ).unwrap();
        assert_eq!(mgr.list_vaults().len(), 2);

        // Switch to personal
        handle_vault_command_with_mgr(
            VaultCommands::Switch { name: "personal".into() },
            &mut mgr,
            false,
        ).unwrap();
        assert_eq!(mgr.active_vault().unwrap().name, "personal");

        // List
        handle_vault_command_with_mgr(VaultCommands::List, &mut mgr, false).unwrap();

        // Active
        handle_vault_command_with_mgr(VaultCommands::Active, &mut mgr, false).unwrap();

        // Remove work
        handle_vault_command_with_mgr(
            VaultCommands::Remove { name: "work".into() },
            &mut mgr,
            false,
        ).unwrap();
        assert_eq!(mgr.list_vaults().len(), 1);
    }
}
