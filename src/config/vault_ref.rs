//! Vault reference resolver: parse and resolve `vault://service/key-name` references
//! in configuration files.
//!
//! References use the format: `vault://title[/field]`
//! - `vault://github` — resolves to the password of the entry titled "github"
//! - `vault://aws/key` — resolves to the API key of the entry titled "aws"
//! - `vault://aws/secret` — resolves to the API secret
//! - `vault://ssh-prod/private_key` — resolves to the SSH private key
//! - `vault://notes/content` — resolves to the secure note content

use std::collections::HashMap;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::vault::entry::{Credential, Entry};

/// A parsed vault reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultRef {
    /// The credential title to look up.
    pub title: String,
    /// Optional field selector (e.g., "key", "secret", "password", "private_key", "content").
    /// If None, defaults to the primary secret field for the credential type.
    pub field: Option<String>,
}

/// Result of resolving a vault reference.
#[derive(Debug, Clone)]
pub enum ResolveResult {
    /// Successfully resolved to a value.
    Resolved(String),
    /// Entry not found in vault.
    NotFound(String),
    /// Entry found but requested field doesn't exist for this credential type.
    InvalidField { title: String, field: String, credential_type: String },
}

/// Parse a vault reference string.
/// Returns `Some(VaultRef)` if the string is a valid `vault://...` reference.
pub fn parse_vault_ref(value: &str) -> Option<VaultRef> {
    let trimmed = value.trim();
    let rest = trimmed.strip_prefix("vault://")?;
    if rest.is_empty() {
        return None;
    }

    let parts: Vec<&str> = rest.splitn(2, '/').collect();
    let title = parts[0].to_string();
    if title.is_empty() {
        return None;
    }
    let field = parts.get(1).filter(|s| !s.is_empty()).map(|s| s.to_string());

    Some(VaultRef { title, field })
}

/// Resolve a vault reference against a list of entries.
pub fn resolve_ref(vref: &VaultRef, entries: &[&Entry]) -> ResolveResult {
    // Find entry by case-insensitive title match
    let entry = entries.iter().find(|e| e.title.eq_ignore_ascii_case(&vref.title));
    let entry = match entry {
        Some(e) => e,
        None => return ResolveResult::NotFound(vref.title.clone()),
    };

    let field = vref.field.as_deref();
    extract_field(entry, field)
}

/// Extract a specific field from a credential entry.
pub(crate) fn extract_field(entry: &Entry, field: Option<&str>) -> ResolveResult {
    match (&entry.credential, field) {
        // Login: default = password
        (Credential::Login(c), None | Some("password")) => ResolveResult::Resolved(c.password.clone()),
        (Credential::Login(c), Some("username")) => ResolveResult::Resolved(c.username.clone()),
        (Credential::Login(c), Some("url")) => ResolveResult::Resolved(c.url.clone()),

        // ApiKey: default = key
        (Credential::ApiKey(c), None | Some("key")) => ResolveResult::Resolved(c.key.clone()),
        (Credential::ApiKey(c), Some("secret")) => ResolveResult::Resolved(c.secret.clone()),
        (Credential::ApiKey(c), Some("service")) => ResolveResult::Resolved(c.service.clone()),

        // SecureNote: default = content
        (Credential::SecureNote(c), None | Some("content")) => ResolveResult::Resolved(c.content.clone()),

        // SshKey: default = private_key
        (Credential::SshKey(c), None | Some("private_key")) => ResolveResult::Resolved(c.private_key.clone()),
        (Credential::SshKey(c), Some("public_key")) => ResolveResult::Resolved(c.public_key.clone()),
        (Credential::SshKey(c), Some("passphrase")) => ResolveResult::Resolved(c.passphrase.clone()),

        // Passkey: default = credential_id
        (Credential::Passkey(c), None | Some("credential_id")) => ResolveResult::Resolved(c.credential_id.clone()),
        (Credential::Passkey(c), Some("rp_id")) => ResolveResult::Resolved(c.rp_id.clone()),
        (Credential::Passkey(c), Some("user_name")) => ResolveResult::Resolved(c.user_name.clone()),
        (Credential::Passkey(c), Some("user_handle")) => ResolveResult::Resolved(c.user_handle.clone()),

        // Invalid field for credential type
        (cred, Some(f)) => {
            let cred_type = match cred {
                Credential::Login(_) => "Login",
                Credential::ApiKey(_) => "ApiKey",
                Credential::SecureNote(_) => "SecureNote",
                Credential::SshKey(_) => "SshKey",
                Credential::Passkey(_) => "Passkey",
            };
            ResolveResult::InvalidField {
                title: entry.title.clone(),
                field: f.to_string(),
                credential_type: cred_type.to_string(),
            }
        }
    }
}

/// Scan a JSON configuration string and resolve all vault:// references.
/// Returns a new string with references replaced by their resolved values.
/// Unresolvable references are left unchanged.
pub fn resolve_config(config: &str, entries: &[&Entry]) -> String {
    let re = Regex::new(r#""(vault://[^"]+)""#).unwrap();
    re.replace_all(config, |caps: &regex::Captures| {
        let full = &caps[1];
        if let Some(vref) = parse_vault_ref(full) {
            match resolve_ref(&vref, entries) {
                ResolveResult::Resolved(val) => {
                    // Escape the value for JSON string context
                    format!("\"{}\"", val.replace('\\', "\\\\").replace('"', "\\\""))
                }
                _ => format!("\"{}\"", full),
            }
        } else {
            format!("\"{}\"", full)
        }
    })
    .to_string()
}

/// Scan a HashMap of config values and resolve vault:// references.
/// Returns a new map with resolved values.
pub fn resolve_map(map: &HashMap<String, String>, entries: &[&Entry]) -> HashMap<String, String> {
    map.iter()
        .map(|(k, v)| {
            let resolved = if let Some(vref) = parse_vault_ref(v) {
                match resolve_ref(&vref, entries) {
                    ResolveResult::Resolved(val) => val,
                    _ => v.clone(),
                }
            } else {
                v.clone()
            };
            (k.clone(), resolved)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::entry::*;

    fn make_entries() -> Vec<Entry> {
        vec![
            Entry::new("GitHub".into(), Credential::Login(LoginCredential {
                url: "https://github.com".into(),
                username: "user".into(),
                password: "gh_token_123".into(),
            })),
            Entry::new("AWS".into(), Credential::ApiKey(ApiKeyCredential {
                service: "aws".into(),
                key: "AKIAIOSFODNN7EXAMPLE".into(),
                secret: "wJalrXUtnFEMI/K7MDENG".into(),
            })),
            Entry::new("Deploy Note".into(), Credential::SecureNote(SecureNoteCredential {
                content: "secret deploy instructions".into(),
            })),
            Entry::new("prod-ssh".into(), Credential::SshKey(SshKeyCredential {
                private_key: "-----BEGIN RSA-----".into(),
                public_key: "ssh-rsa AAAA".into(),
                passphrase: "keypass".into(),
            })),
        ]
    }

    #[test]
    fn test_parse_vault_ref_simple() {
        let vref = parse_vault_ref("vault://github").unwrap();
        assert_eq!(vref.title, "github");
        assert_eq!(vref.field, None);
    }

    #[test]
    fn test_parse_vault_ref_with_field() {
        let vref = parse_vault_ref("vault://aws/secret").unwrap();
        assert_eq!(vref.title, "aws");
        assert_eq!(vref.field, Some("secret".into()));
    }

    #[test]
    fn test_parse_vault_ref_invalid() {
        assert!(parse_vault_ref("not-a-ref").is_none());
        assert!(parse_vault_ref("vault://").is_none());
        assert!(parse_vault_ref("vault:///field").is_none());
        assert!(parse_vault_ref("http://example.com").is_none());
    }

    #[test]
    fn test_parse_vault_ref_with_whitespace() {
        let vref = parse_vault_ref("  vault://github  ").unwrap();
        assert_eq!(vref.title, "github");
    }

    #[test]
    fn test_parse_vault_ref_trailing_slash() {
        let vref = parse_vault_ref("vault://github/").unwrap();
        assert_eq!(vref.title, "github");
        assert_eq!(vref.field, None);
    }

    #[test]
    fn test_resolve_login_default() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();
        let vref = VaultRef { title: "GitHub".into(), field: None };
        assert!(matches!(resolve_ref(&vref, &refs), ResolveResult::Resolved(v) if v == "gh_token_123"));
    }

    #[test]
    fn test_resolve_login_username() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();
        let vref = VaultRef { title: "GitHub".into(), field: Some("username".into()) };
        assert!(matches!(resolve_ref(&vref, &refs), ResolveResult::Resolved(v) if v == "user"));
    }

    #[test]
    fn test_resolve_login_url() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();
        let vref = VaultRef { title: "GitHub".into(), field: Some("url".into()) };
        assert!(matches!(resolve_ref(&vref, &refs), ResolveResult::Resolved(v) if v == "https://github.com"));
    }

    #[test]
    fn test_resolve_api_key_default() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();
        let vref = VaultRef { title: "aws".into(), field: None };
        assert!(matches!(resolve_ref(&vref, &refs), ResolveResult::Resolved(v) if v == "AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_resolve_api_key_secret() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();
        let vref = VaultRef { title: "AWS".into(), field: Some("secret".into()) };
        assert!(matches!(resolve_ref(&vref, &refs), ResolveResult::Resolved(v) if v.contains("wJalr")));
    }

    #[test]
    fn test_resolve_api_key_service() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();
        let vref = VaultRef { title: "AWS".into(), field: Some("service".into()) };
        assert!(matches!(resolve_ref(&vref, &refs), ResolveResult::Resolved(v) if v == "aws"));
    }

    #[test]
    fn test_resolve_note_default() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();
        let vref = VaultRef { title: "Deploy Note".into(), field: None };
        assert!(matches!(resolve_ref(&vref, &refs), ResolveResult::Resolved(v) if v.contains("deploy")));
    }

    #[test]
    fn test_resolve_ssh_default() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();
        let vref = VaultRef { title: "prod-ssh".into(), field: None };
        assert!(matches!(resolve_ref(&vref, &refs), ResolveResult::Resolved(v) if v.contains("RSA")));
    }

    #[test]
    fn test_resolve_ssh_public_key() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();
        let vref = VaultRef { title: "prod-ssh".into(), field: Some("public_key".into()) };
        assert!(matches!(resolve_ref(&vref, &refs), ResolveResult::Resolved(v) if v.contains("ssh-rsa")));
    }

    #[test]
    fn test_resolve_ssh_passphrase() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();
        let vref = VaultRef { title: "prod-ssh".into(), field: Some("passphrase".into()) };
        assert!(matches!(resolve_ref(&vref, &refs), ResolveResult::Resolved(v) if v == "keypass"));
    }

    #[test]
    fn test_resolve_not_found() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();
        let vref = VaultRef { title: "nonexistent".into(), field: None };
        assert!(matches!(resolve_ref(&vref, &refs), ResolveResult::NotFound(_)));
    }

    #[test]
    fn test_resolve_invalid_field() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();
        let vref = VaultRef { title: "GitHub".into(), field: Some("nonexistent_field".into()) };
        assert!(matches!(resolve_ref(&vref, &refs), ResolveResult::InvalidField { .. }));
    }

    #[test]
    fn test_resolve_case_insensitive() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();
        let vref = VaultRef { title: "github".into(), field: None };
        assert!(matches!(resolve_ref(&vref, &refs), ResolveResult::Resolved(_)));
    }

    #[test]
    fn test_resolve_config_json() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();

        let config = r#"{
            "botToken": "vault://github",
            "awsKey": "vault://aws/key",
            "awsSecret": "vault://aws/secret",
            "normalValue": "hello"
        }"#;

        let resolved = resolve_config(config, &refs);
        assert!(resolved.contains("gh_token_123"));
        assert!(resolved.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(resolved.contains("wJalr"));
        assert!(resolved.contains("hello")); // non-ref values unchanged
        assert!(!resolved.contains("vault://")); // all refs resolved
    }

    #[test]
    fn test_resolve_config_unresolvable_left_unchanged() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();

        let config = r#"{"key": "vault://nonexistent"}"#;
        let resolved = resolve_config(config, &refs);
        assert!(resolved.contains("vault://nonexistent"));
    }

    #[test]
    fn test_resolve_map() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();

        let mut map = HashMap::new();
        map.insert("token".into(), "vault://github".into());
        map.insert("key".into(), "vault://aws/key".into());
        map.insert("plain".into(), "just a string".into());

        let resolved = resolve_map(&map, &refs);
        assert_eq!(resolved["token"], "gh_token_123");
        assert_eq!(resolved["key"], "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(resolved["plain"], "just a string");
    }

    #[test]
    fn test_resolve_map_unresolvable() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();

        let mut map = HashMap::new();
        map.insert("missing".into(), "vault://nonexistent".into());

        let resolved = resolve_map(&map, &refs);
        assert_eq!(resolved["missing"], "vault://nonexistent");
    }

    #[test]
    fn test_vault_ref_serialization() {
        let vref = VaultRef { title: "test".into(), field: Some("password".into()) };
        let json = serde_json::to_string(&vref).unwrap();
        let parsed: VaultRef = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, vref);
    }

    #[test]
    fn test_resolve_login_password_explicit() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();
        let vref = VaultRef { title: "GitHub".into(), field: Some("password".into()) };
        assert!(matches!(resolve_ref(&vref, &refs), ResolveResult::Resolved(v) if v == "gh_token_123"));
    }

    #[test]
    fn test_resolve_note_content_explicit() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();
        let vref = VaultRef { title: "Deploy Note".into(), field: Some("content".into()) };
        assert!(matches!(resolve_ref(&vref, &refs), ResolveResult::Resolved(v) if v.contains("deploy")));
    }

    #[test]
    fn test_resolve_ssh_private_key_explicit() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();
        let vref = VaultRef { title: "prod-ssh".into(), field: Some("private_key".into()) };
        assert!(matches!(resolve_ref(&vref, &refs), ResolveResult::Resolved(v) if v.contains("RSA")));
    }

    #[test]
    fn test_resolve_invalid_field_note() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();
        let vref = VaultRef { title: "Deploy Note".into(), field: Some("bad_field".into()) };
        assert!(matches!(resolve_ref(&vref, &refs), ResolveResult::InvalidField { credential_type, .. } if credential_type == "SecureNote"));
    }

    #[test]
    fn test_resolve_invalid_field_ssh() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();
        let vref = VaultRef { title: "prod-ssh".into(), field: Some("bad".into()) };
        assert!(matches!(resolve_ref(&vref, &refs), ResolveResult::InvalidField { credential_type, .. } if credential_type == "SshKey"));
    }

    #[test]
    fn test_resolve_invalid_field_api() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();
        let vref = VaultRef { title: "AWS".into(), field: Some("bad".into()) };
        assert!(matches!(resolve_ref(&vref, &refs), ResolveResult::InvalidField { credential_type, .. } if credential_type == "ApiKey"));
    }
}
