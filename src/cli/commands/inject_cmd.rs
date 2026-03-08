use std::collections::HashMap;
use std::fs;
use std::path::Path;

use regex::Regex;

use crate::config::vault_ref::{parse_vault_ref, resolve_ref, ResolveResult};
use crate::daemon::client::DaemonClient;
use crate::vault::entry::Entry;

use super::run_cmd;

/// Find all `vault://` references in a string.
fn find_vault_refs(text: &str) -> Vec<String> {
    let re = Regex::new(r"vault://[a-zA-Z0-9_./ -]+").unwrap();
    re.find_iter(text)
        .map(|m| m.as_str().trim_end_matches('/').trim().to_string())
        .collect()
}

/// Resolve a list of vault:// URI strings against vault entries.
fn resolve_vault_batch(
    refs: &[String],
    entries: &[&Entry],
) -> anyhow::Result<HashMap<String, String>> {
    let mut resolved = HashMap::new();
    let mut errors = Vec::new();

    for ref_str in refs {
        match parse_vault_ref(ref_str) {
            Some(vref) => match resolve_ref(&vref, entries) {
                ResolveResult::Resolved(val) => {
                    resolved.insert(ref_str.clone(), val);
                }
                ResolveResult::NotFound(title) => {
                    errors.push(format!("  {}: Entry '{}' not found", ref_str, title));
                }
                ResolveResult::InvalidField {
                    field,
                    credential_type,
                    ..
                } => {
                    errors.push(format!(
                        "  {}: Invalid field '{}' for {} credential",
                        ref_str, field, credential_type
                    ));
                }
            },
            None => {
                errors.push(format!("  {}: Invalid vault:// URI", ref_str));
            }
        }
    }

    if !errors.is_empty() {
        anyhow::bail!(
            "Failed to resolve {} vault:// reference(s):\n{}",
            errors.len(),
            errors.join("\n")
        );
    }

    Ok(resolved)
}

/// Replace all `vault://` references in text with resolved values.
fn replace_vault_refs(text: &str, resolved: &HashMap<String, String>) -> String {
    let re = Regex::new(r"vault://[a-zA-Z0-9_./ -]+").unwrap();
    re.replace_all(text, |caps: &regex::Captures| {
        let uri = caps.get(0).unwrap().as_str().trim_end_matches('/').trim();
        resolved
            .get(uri)
            .cloned()
            .unwrap_or_else(|| uri.to_string())
    })
    .into_owned()
}

/// Execute the `vaultclaw inject` command.
///
/// Reads a config file, resolves all `vclaw://` and `vault://` references,
/// and outputs the resolved content to stdout. Never writes secrets to disk.
pub fn handle_inject_command(
    daemon: Option<DaemonClient>,
    vault_path: &Path,
    get_pw: impl Fn(&str) -> String,
    file: &Path,
) -> anyhow::Result<()> {
    let content = fs::read_to_string(file)
        .map_err(|e| anyhow::anyhow!("Failed to read '{}': {}", file.display(), e))?;

    // Collect both vclaw:// and vault:// references
    let vclaw_refs = run_cmd::find_vclaw_refs(&content);
    let vault_refs = find_vault_refs(&content);

    if vclaw_refs.is_empty() && vault_refs.is_empty() {
        // No references found — output content as-is
        print!("{}", content);
        return Ok(());
    }

    // Resolve all references
    let mut daemon = daemon;
    let entries = run_cmd::get_entries(daemon.as_mut(), vault_path, &get_pw)?;
    let entry_refs: Vec<&Entry> = entries.iter().collect();

    let mut result = content;

    if !vclaw_refs.is_empty() {
        let resolved = run_cmd::resolve_batch(&vclaw_refs, &entry_refs)?;
        result = run_cmd::replace_vclaw_refs(&result, &resolved);
        eprintln!(
            "vaultclaw inject: resolved {} vclaw:// reference(s)",
            resolved.len()
        );
    }

    if !vault_refs.is_empty() {
        let resolved = resolve_vault_batch(&vault_refs, &entry_refs)?;
        result = replace_vault_refs(&result, &resolved);
        eprintln!(
            "vaultclaw inject: resolved {} vault:// reference(s)",
            resolved.len()
        );
    }

    print!("{}", result);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::KdfParams;
    use crate::crypto::keys::password_secret;
    use crate::vault::entry::*;
    use crate::vault::format::VaultFile;
    use std::fs;

    // ── find_vault_refs ──

    #[test]
    fn test_find_vault_refs_simple() {
        let refs = find_vault_refs("vault://github");
        assert_eq!(refs, vec!["vault://github"]);
    }

    #[test]
    fn test_find_vault_refs_with_field() {
        let refs = find_vault_refs("vault://github/password");
        assert_eq!(refs, vec!["vault://github/password"]);
    }

    #[test]
    fn test_find_vault_refs_in_json() {
        let config = r#"{
            "apiKey": "vault://aws/key",
            "secret": "vault://aws/secret",
            "normal": "not-a-ref"
        }"#;
        let refs = find_vault_refs(config);
        assert_eq!(refs.len(), 2);
        assert!(refs.contains(&"vault://aws/key".to_string()));
        assert!(refs.contains(&"vault://aws/secret".to_string()));
    }

    #[test]
    fn test_find_vault_refs_none() {
        let refs = find_vault_refs("no references here");
        assert!(refs.is_empty());
    }

    #[test]
    fn test_find_vault_refs_in_env() {
        let content = "API_KEY=vault://my-api\nDB_PASS=vault://db/password\n";
        let refs = find_vault_refs(content);
        assert_eq!(refs.len(), 2);
    }

    #[test]
    fn test_find_vault_refs_trailing_slash() {
        let refs = find_vault_refs("vault://github/");
        assert_eq!(refs, vec!["vault://github"]);
    }

    #[test]
    fn test_find_vault_refs_in_toml() {
        let content = r#"
[database]
password = "vault://db-creds/password"
host = "localhost"
"#;
        let refs = find_vault_refs(content);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0], "vault://db-creds/password");
    }

    #[test]
    fn test_find_vault_refs_in_yaml() {
        let content = r#"
apiKey: "vault://anthropic/key"
botToken: vault://telegram
port: 8080
"#;
        let refs = find_vault_refs(content);
        assert_eq!(refs.len(), 2);
    }

    // ── resolve_vault_batch ──

    fn make_entries() -> Vec<Entry> {
        vec![
            Entry::new(
                "GitHub".into(),
                Credential::Login(LoginCredential {
                    url: "https://github.com".into(),
                    username: "user".into(),
                    password: "gh_token_123".into(),
                }),
            ),
            Entry::new(
                "AWS".into(),
                Credential::ApiKey(ApiKeyCredential {
                    service: "aws".into(),
                    key: "AKIAIOSFODNN7EXAMPLE".into(),
                    secret: "wJalrXUtnFEMI/K7MDENG".into(),
                }),
            ),
            Entry::new(
                "Deploy Note".into(),
                Credential::SecureNote(SecureNoteCredential {
                    content: "secret deploy instructions".into(),
                }),
            ),
        ]
    }

    #[test]
    fn test_resolve_vault_batch_success() {
        let entries = make_entries();
        let entry_refs: Vec<&Entry> = entries.iter().collect();
        let refs = vec![
            "vault://github".to_string(),
            "vault://aws/key".to_string(),
        ];
        let resolved = resolve_vault_batch(&refs, &entry_refs).unwrap();
        assert_eq!(resolved["vault://github"], "gh_token_123");
        assert_eq!(resolved["vault://aws/key"], "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn test_resolve_vault_batch_not_found() {
        let entries = make_entries();
        let entry_refs: Vec<&Entry> = entries.iter().collect();
        let refs = vec!["vault://nonexistent".to_string()];
        let err = resolve_vault_batch(&refs, &entry_refs).unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_resolve_vault_batch_invalid_field() {
        let entries = make_entries();
        let entry_refs: Vec<&Entry> = entries.iter().collect();
        let refs = vec!["vault://github/bad_field".to_string()];
        let err = resolve_vault_batch(&refs, &entry_refs).unwrap_err();
        assert!(err.to_string().contains("Invalid field"));
    }

    #[test]
    fn test_resolve_vault_batch_empty() {
        let entries = make_entries();
        let entry_refs: Vec<&Entry> = entries.iter().collect();
        let resolved = resolve_vault_batch(&[], &entry_refs).unwrap();
        assert!(resolved.is_empty());
    }

    // ── replace_vault_refs ──

    #[test]
    fn test_replace_vault_refs_json() {
        let config = r#"{"key": "vault://aws/key", "other": "plain"}"#;
        let mut resolved = HashMap::new();
        resolved.insert(
            "vault://aws/key".to_string(),
            "AKIAIOSFODNN7EXAMPLE".to_string(),
        );
        let result = replace_vault_refs(config, &resolved);
        assert_eq!(
            result,
            r#"{"key": "AKIAIOSFODNN7EXAMPLE", "other": "plain"}"#
        );
    }

    #[test]
    fn test_replace_vault_refs_env() {
        let content = "API_KEY=vault://aws/key\nNORMAL=hello\n";
        let mut resolved = HashMap::new();
        resolved.insert("vault://aws/key".to_string(), "secret-val".to_string());
        let result = replace_vault_refs(content, &resolved);
        assert_eq!(result, "API_KEY=secret-val\nNORMAL=hello\n");
    }

    #[test]
    fn test_replace_vault_refs_unresolved_passthrough() {
        let text = "vault://unknown";
        let resolved = HashMap::new();
        let result = replace_vault_refs(text, &resolved);
        assert_eq!(result, "vault://unknown");
    }

    // ── handle_inject_command (integration) ──

    #[test]
    fn test_inject_no_refs() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");
        let config_path = dir.path().join("config.json");
        fs::write(&config_path, r#"{"key": "plain-value"}"#).unwrap();

        // No refs → should succeed without needing vault
        let result = handle_inject_command(
            None,
            &vault_path,
            |_| panic!("should not prompt"),
            &config_path,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_inject_file_not_found() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let result = handle_inject_command(
            None,
            &vault_path,
            |_| panic!("should not prompt"),
            Path::new("/nonexistent/config.json"),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read"));
    }

    #[test]
    fn test_inject_vclaw_refs() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let password = password_secret("test".to_string());
        let kdf = KdfParams::fast_for_testing();
        let mut vault = VaultFile::create(&vault_path, &password, kdf).unwrap();
        vault.store_mut().add(Entry::new(
            "my-api-key".into(),
            Credential::ApiKey(ApiKeyCredential {
                service: "test".into(),
                key: "resolved-key-value".into(),
                secret: "".into(),
            }),
        ));
        vault.save().unwrap();

        let config_path = dir.path().join("config.json");
        fs::write(
            &config_path,
            r#"{"apiKey": "vclaw://default/my-api-key"}"#,
        )
        .unwrap();

        // Capture would go to stdout but we can verify the function succeeds
        let result = handle_inject_command(None, &vault_path, |_| "test".into(), &config_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_inject_vault_refs() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let password = password_secret("test".to_string());
        let kdf = KdfParams::fast_for_testing();
        let mut vault = VaultFile::create(&vault_path, &password, kdf).unwrap();
        vault.store_mut().add(Entry::new(
            "github".into(),
            Credential::Login(LoginCredential {
                url: "https://github.com".into(),
                username: "user".into(),
                password: "gh_pat_12345".into(),
            }),
        ));
        vault.save().unwrap();

        let config_path = dir.path().join("app.env");
        fs::write(&config_path, "TOKEN=vault://github\nPORT=8080\n").unwrap();

        let result = handle_inject_command(None, &vault_path, |_| "test".into(), &config_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_inject_mixed_refs() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let password = password_secret("test".to_string());
        let kdf = KdfParams::fast_for_testing();
        let mut vault = VaultFile::create(&vault_path, &password, kdf).unwrap();
        vault.store_mut().add(Entry::new(
            "api-key".into(),
            Credential::ApiKey(ApiKeyCredential {
                service: "test".into(),
                key: "secret-key-123".into(),
                secret: "secret-secret-456".into(),
            }),
        ));
        vault.save().unwrap();

        let config_path = dir.path().join("config.json");
        fs::write(
            &config_path,
            r#"{"vclaw_key": "vclaw://default/api-key", "vault_key": "vault://api-key/secret"}"#,
        )
        .unwrap();

        let result = handle_inject_command(None, &vault_path, |_| "test".into(), &config_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_inject_unresolvable_vclaw_ref() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let password = password_secret("test".to_string());
        let kdf = KdfParams::fast_for_testing();
        VaultFile::create(&vault_path, &password, kdf).unwrap();

        let config_path = dir.path().join("config.json");
        fs::write(
            &config_path,
            r#"{"key": "vclaw://default/nonexistent"}"#,
        )
        .unwrap();

        let result = handle_inject_command(None, &vault_path, |_| "test".into(), &config_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_inject_unresolvable_vault_ref() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let password = password_secret("test".to_string());
        let kdf = KdfParams::fast_for_testing();
        VaultFile::create(&vault_path, &password, kdf).unwrap();

        let config_path = dir.path().join("config.json");
        fs::write(&config_path, r#"{"key": "vault://nonexistent"}"#).unwrap();

        let result = handle_inject_command(None, &vault_path, |_| "test".into(), &config_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_inject_toml_format() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let password = password_secret("test".to_string());
        let kdf = KdfParams::fast_for_testing();
        let mut vault = VaultFile::create(&vault_path, &password, kdf).unwrap();
        vault.store_mut().add(Entry::new(
            "db-creds".into(),
            Credential::Login(LoginCredential {
                url: "postgres://localhost".into(),
                username: "admin".into(),
                password: "super-secret-pw".into(),
            }),
        ));
        vault.save().unwrap();

        let config_path = dir.path().join("config.toml");
        fs::write(
            &config_path,
            r#"[database]
password = "vault://db-creds"
host = "localhost"
"#,
        )
        .unwrap();

        let result = handle_inject_command(None, &vault_path, |_| "test".into(), &config_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_inject_yaml_format() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let password = password_secret("test".to_string());
        let kdf = KdfParams::fast_for_testing();
        let mut vault = VaultFile::create(&vault_path, &password, kdf).unwrap();
        vault.store_mut().add(Entry::new(
            "telegram".into(),
            Credential::ApiKey(ApiKeyCredential {
                service: "telegram".into(),
                key: "bot-token-xyz".into(),
                secret: "".into(),
            }),
        ));
        vault.save().unwrap();

        let config_path = dir.path().join("config.yaml");
        fs::write(
            &config_path,
            "apiKey: \"vault://telegram\"\nport: 8080\n",
        )
        .unwrap();

        let result = handle_inject_command(None, &vault_path, |_| "test".into(), &config_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_inject_env_format() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let password = password_secret("test".to_string());
        let kdf = KdfParams::fast_for_testing();
        let mut vault = VaultFile::create(&vault_path, &password, kdf).unwrap();
        vault.store_mut().add(Entry::new(
            "my-secret".into(),
            Credential::ApiKey(ApiKeyCredential {
                service: "test".into(),
                key: "secret-val".into(),
                secret: "".into(),
            }),
        ));
        vault.save().unwrap();

        let config_path = dir.path().join(".env");
        fs::write(
            &config_path,
            "SECRET=vclaw://default/my-secret\nPLAIN=hello\n",
        )
        .unwrap();

        let result = handle_inject_command(None, &vault_path, |_| "test".into(), &config_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_inject_with_field_selectors() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let password = password_secret("test".to_string());
        let kdf = KdfParams::fast_for_testing();
        let mut vault = VaultFile::create(&vault_path, &password, kdf).unwrap();
        vault.store_mut().add(Entry::new(
            "github".into(),
            Credential::Login(LoginCredential {
                url: "https://github.com".into(),
                username: "myuser".into(),
                password: "mypass".into(),
            }),
        ));
        vault.save().unwrap();

        let config_path = dir.path().join("config.json");
        fs::write(
            &config_path,
            r#"{"user": "vault://github/username", "pass": "vault://github/password"}"#,
        )
        .unwrap();

        let result = handle_inject_command(None, &vault_path, |_| "test".into(), &config_path);
        assert!(result.is_ok());
    }
}
