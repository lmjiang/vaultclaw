use serde::{Deserialize, Serialize};

use crate::config::vault_ref::{extract_field, ResolveResult};
use crate::vault::entry::Entry;

/// Parsed `vclaw://` URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VclawUri {
    pub vault: String,
    pub entry: String,
    pub field: Option<String>,
}

/// Result of resolving a single vclaw:// reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveResponse {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parse a `vclaw://` URI string.
///
/// Format: `vclaw://vault_name/entry_title[/field]`
/// Example: `vclaw://default/github/password`
pub fn parse_vclaw_uri(s: &str) -> Option<VclawUri> {
    let rest = s.trim().strip_prefix("vclaw://")?;
    if rest.is_empty() {
        return None;
    }

    let mut parts = rest.splitn(3, '/');
    let vault = parts.next()?.to_string();
    if vault.is_empty() {
        return None;
    }

    let entry = parts.next().unwrap_or("").to_string();
    if entry.is_empty() {
        return None;
    }

    let field = parts.next().filter(|s| !s.is_empty()).map(|s| s.to_string());

    Some(VclawUri { vault, entry, field })
}

/// Resolve a single vclaw:// URI against vault entries.
///
/// Looks up by title (case-insensitive) or by UUID string.
pub fn resolve_vclaw_uri(uri: &VclawUri, entries: &[&Entry]) -> ResolveResponse {
    let uri_str = format_uri(uri);

    // Try UUID match first
    let entry = if let Ok(uuid) = uri.entry.parse::<uuid::Uuid>() {
        entries.iter().find(|e| e.id == uuid).copied()
    } else {
        None
    };

    // Fall back to title match
    let entry = entry.or_else(|| {
        entries
            .iter()
            .find(|e| e.title.eq_ignore_ascii_case(&uri.entry))
            .copied()
    });

    let entry = match entry {
        Some(e) => e,
        None => {
            return ResolveResponse {
                uri: uri_str,
                value: None,
                error: Some(format!("Entry '{}' not found", uri.entry)),
            };
        }
    };

    match extract_field(entry, uri.field.as_deref()) {
        ResolveResult::Resolved(val) => ResolveResponse {
            uri: uri_str,
            value: Some(val),
            error: None,
        },
        ResolveResult::NotFound(title) => ResolveResponse {
            uri: uri_str,
            value: None,
            error: Some(format!("Entry '{}' not found", title)),
        },
        ResolveResult::InvalidField {
            field,
            credential_type,
            ..
        } => ResolveResponse {
            uri: uri_str,
            value: None,
            error: Some(format!(
                "Invalid field '{}' for {} credential",
                field, credential_type
            )),
        },
    }
}

/// Batch resolve multiple vclaw:// references.
pub fn resolve_vclaw_refs(refs: &[String], entries: &[&Entry]) -> Vec<ResolveResponse> {
    refs.iter()
        .map(|r| {
            match parse_vclaw_uri(r) {
                Some(uri) => resolve_vclaw_uri(&uri, entries),
                None => ResolveResponse {
                    uri: r.clone(),
                    value: None,
                    error: Some(format!("Invalid vclaw:// URI: {}", r)),
                },
            }
        })
        .collect()
}

fn format_uri(uri: &VclawUri) -> String {
    match &uri.field {
        Some(f) => format!("vclaw://{}/{}/{}", uri.vault, uri.entry, f),
        None => format!("vclaw://{}/{}", uri.vault, uri.entry),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::entry::*;

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
            Entry::new(
                "prod-ssh".into(),
                Credential::SshKey(SshKeyCredential {
                    private_key: "-----BEGIN RSA-----".into(),
                    public_key: "ssh-rsa AAAA".into(),
                    passphrase: "keypass".into(),
                }),
            ),
        ]
    }

    #[test]
    fn test_parse_valid_uri() {
        let uri = parse_vclaw_uri("vclaw://default/github").unwrap();
        assert_eq!(uri.vault, "default");
        assert_eq!(uri.entry, "github");
        assert!(uri.field.is_none());
    }

    #[test]
    fn test_parse_with_field() {
        let uri = parse_vclaw_uri("vclaw://default/github/password").unwrap();
        assert_eq!(uri.vault, "default");
        assert_eq!(uri.entry, "github");
        assert_eq!(uri.field.as_deref(), Some("password"));
    }

    #[test]
    fn test_parse_with_whitespace() {
        let uri = parse_vclaw_uri("  vclaw://default/github  ").unwrap();
        assert_eq!(uri.vault, "default");
        assert_eq!(uri.entry, "github");
    }

    #[test]
    fn test_parse_invalid_no_prefix() {
        assert!(parse_vclaw_uri("vault://github").is_none());
    }

    #[test]
    fn test_parse_empty() {
        assert!(parse_vclaw_uri("vclaw://").is_none());
    }

    #[test]
    fn test_parse_no_entry() {
        assert!(parse_vclaw_uri("vclaw://default").is_none());
        assert!(parse_vclaw_uri("vclaw://default/").is_none());
    }

    #[test]
    fn test_parse_empty_vault() {
        assert!(parse_vclaw_uri("vclaw:///entry").is_none());
    }

    #[test]
    fn test_parse_trailing_slash() {
        let uri = parse_vclaw_uri("vclaw://default/github/").unwrap();
        assert_eq!(uri.entry, "github");
        assert!(uri.field.is_none());
    }

    #[test]
    fn test_resolve_by_title() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();
        let uri = parse_vclaw_uri("vclaw://default/github").unwrap();
        let result = resolve_vclaw_uri(&uri, &refs);
        assert_eq!(result.value.as_deref(), Some("gh_token_123"));
        assert!(result.error.is_none());
    }

    #[test]
    fn test_resolve_case_insensitive() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();
        let uri = parse_vclaw_uri("vclaw://default/GITHUB").unwrap();
        let result = resolve_vclaw_uri(&uri, &refs);
        assert_eq!(result.value.as_deref(), Some("gh_token_123"));
    }

    #[test]
    fn test_resolve_by_uuid() {
        let entries = make_entries();
        let id = entries[0].id.to_string();
        let refs: Vec<&Entry> = entries.iter().collect();
        let uri = VclawUri {
            vault: "default".into(),
            entry: id,
            field: None,
        };
        let result = resolve_vclaw_uri(&uri, &refs);
        assert_eq!(result.value.as_deref(), Some("gh_token_123"));
    }

    #[test]
    fn test_resolve_with_field() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();
        let uri = parse_vclaw_uri("vclaw://default/github/username").unwrap();
        let result = resolve_vclaw_uri(&uri, &refs);
        assert_eq!(result.value.as_deref(), Some("user"));
    }

    #[test]
    fn test_resolve_api_key() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();
        let uri = parse_vclaw_uri("vclaw://default/aws/secret").unwrap();
        let result = resolve_vclaw_uri(&uri, &refs);
        assert!(result.value.as_deref().unwrap().contains("wJalr"));
    }

    #[test]
    fn test_resolve_not_found() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();
        let uri = parse_vclaw_uri("vclaw://default/nonexistent").unwrap();
        let result = resolve_vclaw_uri(&uri, &refs);
        assert!(result.value.is_none());
        assert!(result.error.as_ref().unwrap().contains("not found"));
    }

    #[test]
    fn test_resolve_invalid_field() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();
        let uri = parse_vclaw_uri("vclaw://default/github/bad_field").unwrap();
        let result = resolve_vclaw_uri(&uri, &refs);
        assert!(result.value.is_none());
        assert!(result.error.as_ref().unwrap().contains("Invalid field"));
    }

    #[test]
    fn test_batch_resolve() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();
        let uris = vec![
            "vclaw://default/github".to_string(),
            "vclaw://default/aws/key".to_string(),
            "vclaw://default/nonexistent".to_string(),
            "not-a-uri".to_string(),
        ];
        let results = resolve_vclaw_refs(&uris, &refs);
        assert_eq!(results.len(), 4);
        assert_eq!(results[0].value.as_deref(), Some("gh_token_123"));
        assert_eq!(results[1].value.as_deref(), Some("AKIAIOSFODNN7EXAMPLE"));
        assert!(results[2].error.is_some());
        assert!(results[3].error.as_ref().unwrap().contains("Invalid vclaw://"));
    }

    #[test]
    fn test_batch_resolve_empty() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();
        let results = resolve_vclaw_refs(&[], &refs);
        assert!(results.is_empty());
    }

    #[test]
    fn test_resolve_response_serialization() {
        let resp = ResolveResponse {
            uri: "vclaw://default/github".into(),
            value: Some("secret".into()),
            error: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("error")); // skip_serializing_if
        let parsed: ResolveResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.value.as_deref(), Some("secret"));
    }

    #[test]
    fn test_resolve_response_error_serialization() {
        let resp = ResolveResponse {
            uri: "vclaw://default/missing".into(),
            value: None,
            error: Some("not found".into()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("\"value\"")); // skip_serializing_if
        let parsed: ResolveResponse = serde_json::from_str(&json).unwrap();
        assert!(parsed.error.is_some());
    }

    #[test]
    fn test_format_uri_without_field() {
        let uri = VclawUri {
            vault: "default".into(),
            entry: "github".into(),
            field: None,
        };
        assert_eq!(format_uri(&uri), "vclaw://default/github");
    }

    #[test]
    fn test_format_uri_with_field() {
        let uri = VclawUri {
            vault: "default".into(),
            entry: "github".into(),
            field: Some("password".into()),
        };
        assert_eq!(format_uri(&uri), "vclaw://default/github/password");
    }

    #[test]
    fn test_resolve_ssh_key() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();
        let uri = parse_vclaw_uri("vclaw://default/prod-ssh/public_key").unwrap();
        let result = resolve_vclaw_uri(&uri, &refs);
        assert!(result.value.as_deref().unwrap().contains("ssh-rsa"));
    }

    #[test]
    fn test_resolve_note() {
        let entries = make_entries();
        let refs: Vec<&Entry> = entries.iter().collect();
        let uri = parse_vclaw_uri("vclaw://default/deploy note").unwrap();
        let result = resolve_vclaw_uri(&uri, &refs);
        assert!(result.value.as_deref().unwrap().contains("deploy"));
    }
}
