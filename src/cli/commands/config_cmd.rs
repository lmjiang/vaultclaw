use clap::Subcommand;
use crate::config::AppConfig;

#[derive(Subcommand)]
pub enum ConfigCommands {
    /// Show current configuration
    Show,
    /// Get a specific configuration value
    Get {
        /// Configuration key (vault_path, auto_lock_seconds, clipboard_clear_seconds, default_password_length, socket_path, http_port, http_enabled)
        key: String,
    },
    /// Set a configuration value
    Set {
        /// Configuration key
        key: String,
        /// New value
        value: String,
    },
    /// Show the path to the configuration file
    Path,
    /// Reset configuration to defaults
    Reset,
}

pub fn handle_config_command(command: ConfigCommands, json_output: bool) -> anyhow::Result<()> {
    match command {
        ConfigCommands::Show => cmd_config_show(json_output),
        ConfigCommands::Get { key } => cmd_config_get(&key, json_output),
        ConfigCommands::Set { key, value } => cmd_config_set(&key, &value, json_output),
        ConfigCommands::Path => cmd_config_path(json_output),
        ConfigCommands::Reset => cmd_config_reset(json_output),
    }
}

fn cmd_config_show(json_output: bool) -> anyhow::Result<()> {
    let config = AppConfig::load();
    if json_output {
        println!("{}", serde_json::to_string_pretty(&config)?);
    } else {
        println!("vault_path             = {}", config.vault_path.display());
        println!("auto_lock_seconds      = {}", config.auto_lock_seconds);
        println!("clipboard_clear_seconds = {}", config.clipboard_clear_seconds);
        println!("default_password_length = {}", config.default_password_length);
        println!("socket_path            = {}", config.socket_path.display());
        println!("http_port              = {}", config.http_port);
        println!("http_enabled           = {}", config.http_enabled);
    }
    Ok(())
}

fn config_get_value(config: &AppConfig, key: &str) -> anyhow::Result<String> {
    match key {
        "vault_path" => Ok(config.vault_path.display().to_string()),
        "auto_lock_seconds" => Ok(config.auto_lock_seconds.to_string()),
        "clipboard_clear_seconds" => Ok(config.clipboard_clear_seconds.to_string()),
        "default_password_length" => Ok(config.default_password_length.to_string()),
        "socket_path" => Ok(config.socket_path.display().to_string()),
        "http_port" => Ok(config.http_port.to_string()),
        "http_enabled" => Ok(config.http_enabled.to_string()),
        _ => anyhow::bail!(
            "Unknown config key: '{}'. Valid keys: vault_path, auto_lock_seconds, clipboard_clear_seconds, default_password_length, socket_path, http_port, http_enabled",
            key
        ),
    }
}

fn cmd_config_get(key: &str, json_output: bool) -> anyhow::Result<()> {
    let config = AppConfig::load();
    let value = config_get_value(&config, key)?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "key": key,
            "value": value,
        }))?);
    } else {
        println!("{}", value);
    }
    Ok(())
}

fn cmd_config_set(key: &str, value: &str, json_output: bool) -> anyhow::Result<()> {
    let mut config = AppConfig::load();
    apply_config_value(&mut config, key, value)?;
    config.save().map_err(|e| anyhow::anyhow!("Failed to save config: {}", e))?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "key": key,
            "value": value,
            "saved": true,
        }))?);
    } else {
        println!("Set {} = {}", key, value);
    }
    Ok(())
}

fn apply_config_value(config: &mut AppConfig, key: &str, value: &str) -> anyhow::Result<()> {
    match key {
        "vault_path" => config.vault_path = value.into(),
        "auto_lock_seconds" => {
            config.auto_lock_seconds = value.parse()
                .map_err(|_| anyhow::anyhow!("Invalid value for auto_lock_seconds: expected integer"))?;
        }
        "clipboard_clear_seconds" => {
            config.clipboard_clear_seconds = value.parse()
                .map_err(|_| anyhow::anyhow!("Invalid value for clipboard_clear_seconds: expected integer"))?;
        }
        "default_password_length" => {
            config.default_password_length = value.parse()
                .map_err(|_| anyhow::anyhow!("Invalid value for default_password_length: expected integer"))?;
        }
        "socket_path" => config.socket_path = value.into(),
        "http_port" => {
            config.http_port = value.parse()
                .map_err(|_| anyhow::anyhow!("Invalid value for http_port: expected integer 1-65535"))?;
        }
        "http_enabled" => {
            config.http_enabled = match value {
                "true" | "1" | "yes" => true,
                "false" | "0" | "no" => false,
                _ => anyhow::bail!("Invalid value for http_enabled: expected true/false"),
            };
        }
        _ => anyhow::bail!(
            "Unknown config key: '{}'. Valid keys: vault_path, auto_lock_seconds, clipboard_clear_seconds, default_password_length, socket_path, http_port, http_enabled",
            key
        ),
    }
    Ok(())
}

fn cmd_config_path(json_output: bool) -> anyhow::Result<()> {
    let path = dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("vaultclaw")
        .join("config.json");
    if json_output {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "path": path.display().to_string(),
        }))?);
    } else {
        println!("{}", path.display());
    }
    Ok(())
}

fn cmd_config_reset(json_output: bool) -> anyhow::Result<()> {
    let config = AppConfig::default();
    config.save().map_err(|e| anyhow::anyhow!("Failed to save config: {}", e))?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(&config)?);
    } else {
        println!("Configuration reset to defaults.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_config_get_value_all_keys() {
        let config = AppConfig::default();
        assert!(config_get_value(&config, "vault_path").is_ok());
        assert!(config_get_value(&config, "auto_lock_seconds").is_ok());
        assert!(config_get_value(&config, "clipboard_clear_seconds").is_ok());
        assert!(config_get_value(&config, "default_password_length").is_ok());
        assert!(config_get_value(&config, "socket_path").is_ok());
        assert!(config_get_value(&config, "http_port").is_ok());
        assert!(config_get_value(&config, "http_enabled").is_ok());
    }

    #[test]
    fn test_config_get_value_unknown_key() {
        let config = AppConfig::default();
        let result = config_get_value(&config, "nonexistent");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown config key"));
    }

    #[test]
    fn test_apply_config_value_vault_path() {
        let mut config = AppConfig::default();
        apply_config_value(&mut config, "vault_path", "/tmp/test.vclaw").unwrap();
        assert_eq!(config.vault_path, PathBuf::from("/tmp/test.vclaw"));
    }

    #[test]
    fn test_apply_config_value_auto_lock_seconds() {
        let mut config = AppConfig::default();
        apply_config_value(&mut config, "auto_lock_seconds", "600").unwrap();
        assert_eq!(config.auto_lock_seconds, 600);
    }

    #[test]
    fn test_apply_config_value_clipboard_clear_seconds() {
        let mut config = AppConfig::default();
        apply_config_value(&mut config, "clipboard_clear_seconds", "15").unwrap();
        assert_eq!(config.clipboard_clear_seconds, 15);
    }

    #[test]
    fn test_apply_config_value_default_password_length() {
        let mut config = AppConfig::default();
        apply_config_value(&mut config, "default_password_length", "32").unwrap();
        assert_eq!(config.default_password_length, 32);
    }

    #[test]
    fn test_apply_config_value_socket_path() {
        let mut config = AppConfig::default();
        apply_config_value(&mut config, "socket_path", "/tmp/vc.sock").unwrap();
        assert_eq!(config.socket_path, PathBuf::from("/tmp/vc.sock"));
    }

    #[test]
    fn test_apply_config_value_http_port() {
        let mut config = AppConfig::default();
        apply_config_value(&mut config, "http_port", "8080").unwrap();
        assert_eq!(config.http_port, 8080);
    }

    #[test]
    fn test_apply_config_value_http_enabled_true() {
        let mut config = AppConfig::default();
        apply_config_value(&mut config, "http_enabled", "true").unwrap();
        assert!(config.http_enabled);
        apply_config_value(&mut config, "http_enabled", "1").unwrap();
        assert!(config.http_enabled);
        apply_config_value(&mut config, "http_enabled", "yes").unwrap();
        assert!(config.http_enabled);
    }

    #[test]
    fn test_apply_config_value_http_enabled_false() {
        let mut config = AppConfig::default();
        apply_config_value(&mut config, "http_enabled", "false").unwrap();
        assert!(!config.http_enabled);
        apply_config_value(&mut config, "http_enabled", "0").unwrap();
        assert!(!config.http_enabled);
        apply_config_value(&mut config, "http_enabled", "no").unwrap();
        assert!(!config.http_enabled);
    }

    #[test]
    fn test_apply_config_value_invalid_integer() {
        let mut config = AppConfig::default();
        assert!(apply_config_value(&mut config, "auto_lock_seconds", "abc").is_err());
        assert!(apply_config_value(&mut config, "clipboard_clear_seconds", "abc").is_err());
        assert!(apply_config_value(&mut config, "default_password_length", "abc").is_err());
        assert!(apply_config_value(&mut config, "http_port", "abc").is_err());
    }

    #[test]
    fn test_apply_config_value_invalid_bool() {
        let mut config = AppConfig::default();
        assert!(apply_config_value(&mut config, "http_enabled", "maybe").is_err());
    }

    #[test]
    fn test_apply_config_value_unknown_key() {
        let mut config = AppConfig::default();
        assert!(apply_config_value(&mut config, "unknown_key", "value").is_err());
    }

    #[test]
    fn test_config_get_value_returns_correct_values() {
        let config = AppConfig {
            vault_path: PathBuf::from("/data/my.vclaw"),
            auto_lock_seconds: 600,
            clipboard_clear_seconds: 15,
            default_password_length: 32,
            socket_path: PathBuf::from("/tmp/vc.sock"),
            http_port: 8080,
            http_enabled: false,
        };
        assert_eq!(config_get_value(&config, "vault_path").unwrap(), "/data/my.vclaw");
        assert_eq!(config_get_value(&config, "auto_lock_seconds").unwrap(), "600");
        assert_eq!(config_get_value(&config, "clipboard_clear_seconds").unwrap(), "15");
        assert_eq!(config_get_value(&config, "default_password_length").unwrap(), "32");
        assert_eq!(config_get_value(&config, "socket_path").unwrap(), "/tmp/vc.sock");
        assert_eq!(config_get_value(&config, "http_port").unwrap(), "8080");
        assert_eq!(config_get_value(&config, "http_enabled").unwrap(), "false");
    }

    #[test]
    fn test_cmd_config_show_json() {
        // Just verify it doesn't panic
        let _ = cmd_config_show(true);
    }

    #[test]
    fn test_cmd_config_show_text() {
        let _ = cmd_config_show(false);
    }

    #[test]
    fn test_cmd_config_path_json() {
        let _ = cmd_config_path(true);
    }

    #[test]
    fn test_cmd_config_path_text() {
        let _ = cmd_config_path(false);
    }

    #[test]
    fn test_cmd_config_get_valid() {
        // Uses real config, just verify no panic
        let _ = cmd_config_get("vault_path", false);
        let _ = cmd_config_get("vault_path", true);
    }

    #[test]
    fn test_cmd_config_get_invalid() {
        assert!(cmd_config_get("nonexistent", false).is_err());
    }

    #[test]
    fn test_handle_config_command_show() {
        // Exercises the Show arm of handle_config_command (lines 26-28, 34)
        assert!(handle_config_command(ConfigCommands::Show, false).is_ok());
        assert!(handle_config_command(ConfigCommands::Show, true).is_ok());
    }

    #[test]
    fn test_handle_config_command_get() {
        // Exercises the Get arm (line 29)
        assert!(handle_config_command(ConfigCommands::Get { key: "vault_path".to_string() }, false).is_ok());
        assert!(handle_config_command(ConfigCommands::Get { key: "invalid_key".to_string() }, false).is_err());
    }

    #[test]
    fn test_handle_config_command_set() {
        // Exercises the Set arm (line 30) and cmd_config_set (lines 82-96)
        // Set vault_path since it doesn't require parsing and save() writes to real config path
        assert!(handle_config_command(
            ConfigCommands::Set { key: "vault_path".to_string(), value: "/tmp/test_handle.vclaw".to_string() },
            false,
        ).is_ok());
        assert!(handle_config_command(
            ConfigCommands::Set { key: "vault_path".to_string(), value: "/tmp/test_handle.vclaw".to_string() },
            true,
        ).is_ok());
    }

    #[test]
    fn test_handle_config_command_set_invalid_key() {
        // Exercises the Set arm error path through apply_config_value
        assert!(handle_config_command(
            ConfigCommands::Set { key: "nonexistent".to_string(), value: "x".to_string() },
            false,
        ).is_err());
    }

    #[test]
    fn test_handle_config_command_path() {
        // Exercises the Path arm (line 31)
        assert!(handle_config_command(ConfigCommands::Path, false).is_ok());
        assert!(handle_config_command(ConfigCommands::Path, true).is_ok());
    }

    #[test]
    fn test_handle_config_command_reset() {
        // Exercises the Reset arm (line 32) and cmd_config_reset (lines 148-157)
        assert!(handle_config_command(ConfigCommands::Reset, false).is_ok());
        assert!(handle_config_command(ConfigCommands::Reset, true).is_ok());
    }

    #[test]
    fn test_cmd_config_set_text_output() {
        // Directly tests cmd_config_set with text output (lines 82-96, text branch)
        assert!(cmd_config_set("vault_path", "/tmp/test_set.vclaw", false).is_ok());
    }

    #[test]
    fn test_cmd_config_set_json_output() {
        // Directly tests cmd_config_set with JSON output (lines 86-91)
        assert!(cmd_config_set("vault_path", "/tmp/test_set.vclaw", true).is_ok());
    }

    #[test]
    fn test_cmd_config_set_invalid_key() {
        // Tests the error path in cmd_config_set via apply_config_value
        assert!(cmd_config_set("bad_key", "value", false).is_err());
    }

    #[test]
    fn test_cmd_config_reset_text_output() {
        // Directly tests cmd_config_reset text path (lines 148-155)
        assert!(cmd_config_reset(false).is_ok());
    }

    #[test]
    fn test_cmd_config_reset_json_output() {
        // Directly tests cmd_config_reset JSON path (lines 148-153, 157)
        assert!(cmd_config_reset(true).is_ok());
    }
}
