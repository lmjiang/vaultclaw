pub mod vault_ref;

use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

/// Application configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Path to the default vault file.
    pub vault_path: PathBuf,
    /// Auto-lock timeout in seconds (0 = never).
    pub auto_lock_seconds: u64,
    /// Clipboard clear timeout in seconds (0 = never).
    pub clipboard_clear_seconds: u64,
    /// Default password generator length.
    pub default_password_length: usize,
    /// Unix socket path for daemon communication.
    pub socket_path: PathBuf,
    /// HTTP API port for agent access (default 6274).
    #[serde(default = "default_http_port")]
    pub http_port: u16,
    /// Whether the HTTP API server is enabled.
    #[serde(default = "default_http_enabled")]
    pub http_enabled: bool,
}

fn default_http_port() -> u16 { 6274 }
fn default_http_enabled() -> bool { true }

impl Default for AppConfig {
    fn default() -> Self {
        let data_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("vaultclaw");

        let runtime_dir = dirs::runtime_dir()
            .or_else(dirs::cache_dir)
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("vaultclaw");

        Self {
            vault_path: data_dir.join("default.vclaw"),
            auto_lock_seconds: 300, // 5 minutes
            clipboard_clear_seconds: 30,
            default_password_length: 24,
            socket_path: runtime_dir.join("vaultclaw.sock"),
            http_port: 6274,
            http_enabled: true,
        }
    }
}

impl AppConfig {
    /// Load config, using defaults if no config file exists.
    pub fn load() -> Self {
        let config_path = Self::config_path();
        Self::load_from(&config_path)
    }

    /// Load config from a specific path.
    pub fn load_from(path: &Path) -> Self {
        if path.exists() {
            let content = std::fs::read_to_string(path).unwrap_or_default();
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            Self::default()
        }
    }

    /// Save config to disk.
    pub fn save(&self) -> std::io::Result<()> {
        let config_path = Self::config_path();
        self.save_to(&config_path)
    }

    /// Save config to a specific path.
    pub fn save_to(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(self)
            .map_err(std::io::Error::other)?;
        std::fs::write(path, content)
    }

    fn config_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("vaultclaw")
            .join("config.json")
    }
}

/// Generate a random password with the specified length.
pub fn generate_password(length: usize) -> String {
    use rand::Rng;

    const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const DIGITS: &[u8] = b"0123456789";
    const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}|;:,.<>?";

    let all_chars: Vec<u8> = [LOWERCASE, UPPERCASE, DIGITS, SYMBOLS].concat();

    if length < 4 {
        // For very short passwords, just use all chars
        let mut rng = rand::thread_rng();
        return (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..all_chars.len());
                all_chars[idx] as char
            })
            .collect();
    }

    let mut rng = rand::thread_rng();
    let mut password: Vec<u8> = Vec::with_capacity(length);

    // Ensure at least one of each category
    password.push(LOWERCASE[rng.gen_range(0..LOWERCASE.len())]);
    password.push(UPPERCASE[rng.gen_range(0..UPPERCASE.len())]);
    password.push(DIGITS[rng.gen_range(0..DIGITS.len())]);
    password.push(SYMBOLS[rng.gen_range(0..SYMBOLS.len())]);

    // Fill the rest randomly
    for _ in 4..length {
        let idx = rng.gen_range(0..all_chars.len());
        password.push(all_chars[idx]);
    }

    // Shuffle to avoid predictable positions
    for i in (1..password.len()).rev() {
        let j = rng.gen_range(0..=i);
        password.swap(i, j);
    }

    String::from_utf8(password).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AppConfig::default();
        assert_eq!(config.auto_lock_seconds, 300);
        assert_eq!(config.clipboard_clear_seconds, 30);
        assert_eq!(config.default_password_length, 24);
    }

    #[test]
    fn test_generate_password_length() {
        for len in [8, 16, 24, 32, 64] {
            let pw = generate_password(len);
            assert_eq!(pw.len(), len, "Password length should be {}", len);
        }
    }

    #[test]
    fn test_generate_password_has_all_categories() {
        // Generate a bunch of passwords and check they contain all char types
        for _ in 0..10 {
            let pw = generate_password(24);
            assert!(pw.chars().any(|c| c.is_ascii_lowercase()), "Should have lowercase");
            assert!(pw.chars().any(|c| c.is_ascii_uppercase()), "Should have uppercase");
            assert!(pw.chars().any(|c| c.is_ascii_digit()), "Should have digit");
            assert!(
                pw.chars().any(|c| !c.is_ascii_alphanumeric()),
                "Should have symbol"
            );
        }
    }

    #[test]
    fn test_generate_password_uniqueness() {
        let pw1 = generate_password(32);
        let pw2 = generate_password(32);
        assert_ne!(pw1, pw2);
    }

    #[test]
    fn test_generate_password_short() {
        let pw = generate_password(1);
        assert_eq!(pw.len(), 1);

        let pw = generate_password(0);
        assert_eq!(pw.len(), 0);
    }

    #[test]
    fn test_config_serialization() {
        let config = AppConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: AppConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.auto_lock_seconds, config.auto_lock_seconds);
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let config_path = dir.path().join("vaultclaw").join("config.json");

        let config = AppConfig {
            vault_path: PathBuf::from("/tmp/test.vclaw"),
            auto_lock_seconds: 600,
            clipboard_clear_seconds: 15,
            default_password_length: 32,
            socket_path: PathBuf::from("/tmp/vc.sock"),
            http_port: 6274,
            http_enabled: true,
        };

        // Save manually to temp location
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let content = serde_json::to_string_pretty(&config).unwrap();
        std::fs::write(&config_path, &content).unwrap();

        // Load from that file
        let loaded: AppConfig = serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(loaded.auto_lock_seconds, 600);
        assert_eq!(loaded.clipboard_clear_seconds, 15);
        assert_eq!(loaded.default_password_length, 32);
        assert_eq!(loaded.vault_path, PathBuf::from("/tmp/test.vclaw"));
        assert_eq!(loaded.socket_path, PathBuf::from("/tmp/vc.sock"));
    }

    #[test]
    fn test_load_nonexistent_returns_default() {
        // AppConfig::load() falls back to default when no config file exists
        // We can't control config_path(), but we can test the fallback logic
        let content = "";
        let result: AppConfig = serde_json::from_str(content).unwrap_or_default();
        assert_eq!(result.auto_lock_seconds, 300);
        assert_eq!(result.clipboard_clear_seconds, 30);
    }

    #[test]
    fn test_load_invalid_json_returns_default() {
        let content = "not valid json {{{";
        let result: AppConfig = serde_json::from_str(content).unwrap_or_default();
        assert_eq!(result.auto_lock_seconds, 300);
    }

    #[test]
    fn test_config_all_fields_serialize() {
        let config = AppConfig {
            vault_path: PathBuf::from("/data/my.vclaw"),
            auto_lock_seconds: 0,
            clipboard_clear_seconds: 0,
            default_password_length: 8,
            socket_path: PathBuf::from("/run/vc.sock"),
            http_port: 6274,
            http_enabled: true,
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("/data/my.vclaw"));
        assert!(json.contains("/run/vc.sock"));
        let parsed: AppConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.auto_lock_seconds, 0);
        assert_eq!(parsed.clipboard_clear_seconds, 0);
        assert_eq!(parsed.default_password_length, 8);
    }

    #[test]
    fn test_save_creates_parent_dirs() {
        let dir = tempfile::TempDir::new().unwrap();
        let nested = dir.path().join("a").join("b").join("config.json");
        // Simulate save logic
        if let Some(parent) = nested.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let config = AppConfig::default();
        let content = serde_json::to_string_pretty(&config).unwrap();
        std::fs::write(&nested, &content).unwrap();
        assert!(nested.exists());
    }

    #[test]
    fn test_generate_password_length_2() {
        let pw = generate_password(2);
        assert_eq!(pw.len(), 2);
    }

    #[test]
    fn test_generate_password_length_3() {
        let pw = generate_password(3);
        assert_eq!(pw.len(), 3);
    }

    #[test]
    fn test_config_default_vault_path_contains_vaultclaw() {
        let config = AppConfig::default();
        assert!(config.vault_path.to_str().unwrap().contains("vaultclaw"));
        assert!(config.vault_path.to_str().unwrap().contains("default.vclaw"));
    }

    #[test]
    fn test_config_default_socket_path_contains_vaultclaw() {
        let config = AppConfig::default();
        assert!(config.socket_path.to_str().unwrap().contains("vaultclaw"));
    }

    #[test]
    fn test_save_to_and_load_from_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("config.json");

        let config = AppConfig {
            vault_path: PathBuf::from("/tmp/test.vclaw"),
            auto_lock_seconds: 600,
            clipboard_clear_seconds: 15,
            default_password_length: 32,
            socket_path: PathBuf::from("/tmp/vc.sock"),
            http_port: 6274,
            http_enabled: true,
        };

        config.save_to(&path).unwrap();
        assert!(path.exists());

        let loaded = AppConfig::load_from(&path);
        assert_eq!(loaded.auto_lock_seconds, 600);
        assert_eq!(loaded.clipboard_clear_seconds, 15);
        assert_eq!(loaded.default_password_length, 32);
        assert_eq!(loaded.vault_path, PathBuf::from("/tmp/test.vclaw"));
        assert_eq!(loaded.socket_path, PathBuf::from("/tmp/vc.sock"));
    }

    #[test]
    fn test_load_from_nonexistent() {
        let loaded = AppConfig::load_from(std::path::Path::new("/tmp/nonexistent_config_test.json"));
        assert_eq!(loaded.auto_lock_seconds, 300);
        assert_eq!(loaded.clipboard_clear_seconds, 30);
    }

    #[test]
    fn test_load_from_invalid_json() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, "not json {{").unwrap();
        let loaded = AppConfig::load_from(&path);
        assert_eq!(loaded.auto_lock_seconds, 300); // defaults
    }

    #[test]
    fn test_save_to_creates_parent_dirs() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("nested").join("deep").join("config.json");
        let config = AppConfig::default();
        config.save_to(&path).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn test_load_from_empty_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("empty.json");
        std::fs::write(&path, "").unwrap();
        let loaded = AppConfig::load_from(&path);
        assert_eq!(loaded.auto_lock_seconds, 300); // defaults
    }

    #[test]
    fn test_load_uses_real_config_path() {
        // Tests AppConfig::load() directly, exercising config_path()
        let config = AppConfig::load();
        // Should return valid defaults regardless of whether config file exists
        let _ = config.auto_lock_seconds; // u64 is always valid; just verify load doesn't panic
        assert!(config.default_password_length > 0);
    }

    #[test]
    fn test_generate_password_length_4() {
        // Exactly 4 chars: one of each category guaranteed
        let pw = generate_password(4);
        assert_eq!(pw.len(), 4);
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pw.chars().any(|c| c.is_ascii_digit()));
        assert!(pw.chars().any(|c| !c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_save_uses_real_config_path() {
        // Just verify save() doesn't panic — we can't control the real config path
        // but we verify the method exists and runs
        let config = AppConfig::default();
        // save() writes to config_path(), which may or may not succeed depending on permissions
        let _ = config.save();
    }

    #[test]
    fn test_save_to_permission_denied() {
        // Try to save to a path where create_dir_all will fail
        let config = AppConfig::default();
        let result = config.save_to(std::path::Path::new("/proc/nonexistent/deep/config.json"));
        assert!(result.is_err());
    }

    #[test]
    fn test_save_to_no_parent_path() {
        // Path::new("").parent() returns None, so the if-let branch is skipped.
        let config = AppConfig::default();
        let result = config.save_to(Path::new(""));
        assert!(result.is_err()); // write("") fails
    }
}
