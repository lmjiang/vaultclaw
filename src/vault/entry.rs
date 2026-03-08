use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a credential entry.
pub type EntryId = Uuid;

/// A credential entry in the vault.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    pub id: EntryId,
    pub title: String,
    pub credential: Credential,
    pub category: Option<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub notes: String,
    pub totp_secret: Option<String>,
    /// Whether this credential is marked as sensitive (requires manual approval for agent access).
    #[serde(default)]
    pub sensitive: bool,
    /// Timestamp of the last HIBP breach check for this entry.
    #[serde(default)]
    pub last_breach_check: Option<DateTime<Utc>>,
    /// Number of times this password was found in known breaches (0 = clean).
    #[serde(default)]
    pub breach_count: Option<u64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// The different credential types supported by VaultClaw.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum Credential {
    Login(LoginCredential),
    ApiKey(ApiKeyCredential),
    SecureNote(SecureNoteCredential),
    SshKey(SshKeyCredential),
    Passkey(PasskeyCredential),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LoginCredential {
    pub url: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiKeyCredential {
    pub service: String,
    pub key: String,
    pub secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecureNoteCredential {
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SshKeyCredential {
    pub private_key: String,
    pub public_key: String,
    pub passphrase: String,
}

/// Algorithm used for the passkey's key pair.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PasskeyAlgorithm {
    /// ECDSA with P-256 curve (COSE algorithm -7)
    #[serde(rename = "es256")]
    Es256,
    /// EdDSA with Ed25519 (COSE algorithm -8)
    #[serde(rename = "eddsa")]
    EdDsa,
}

/// A WebAuthn discoverable credential (passkey) stored in the vault.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PasskeyCredential {
    /// Unique credential identifier assigned during registration (base64url-encoded).
    pub credential_id: String,
    /// Relying party identifier (e.g., "google.com").
    pub rp_id: String,
    /// Human-readable relying party name.
    pub rp_name: String,
    /// Relying party's user ID (base64url-encoded).
    pub user_handle: String,
    /// User display name.
    pub user_name: String,
    /// Private key in COSE key format (base64url-encoded CBOR).
    pub private_key: String,
    /// Algorithm used for the key pair.
    pub algorithm: PasskeyAlgorithm,
    /// Signature counter, incremented on each assertion.
    pub sign_count: u32,
    /// Whether this is a discoverable (resident) credential.
    #[serde(default = "default_true")]
    pub discoverable: bool,
    /// Whether this credential is eligible for backup.
    #[serde(default)]
    pub backup_eligible: bool,
    /// Whether this credential has been backed up.
    #[serde(default)]
    pub backup_state: bool,
    /// Timestamp of last use for authentication.
    #[serde(default)]
    pub last_used_at: Option<DateTime<Utc>>,
}

fn default_true() -> bool { true }

/// Overview metadata for an entry (non-sensitive, used for listing/searching).
/// Encrypted with the overview key (HKDF context: vaultclaw-entry-overview-v1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EntryOverview {
    pub id: EntryId,
    pub title: String,
    pub credential_type: String,
    pub category: Option<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    /// URL for login entries, service name for API keys, rp_id for passkeys.
    pub url: Option<String>,
    /// Username for login entries, user_name for passkeys.
    pub username: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Sensitive details for an entry (passwords, keys, secrets).
/// Encrypted with the details key (HKDF context: vaultclaw-entry-details-v1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EntryDetails {
    pub credential: Credential,
    pub notes: String,
    pub totp_secret: Option<String>,
    #[serde(default)]
    pub sensitive: bool,
    #[serde(default)]
    pub last_breach_check: Option<DateTime<Utc>>,
    #[serde(default)]
    pub breach_count: Option<u64>,
}

impl Entry {
    /// Extract the overview portion of this entry.
    pub fn to_overview(&self) -> EntryOverview {
        let (url, username) = match &self.credential {
            Credential::Login(c) => (Some(c.url.clone()), Some(c.username.clone())),
            Credential::ApiKey(c) => (Some(c.service.clone()), None),
            Credential::Passkey(c) => (Some(c.rp_id.clone()), Some(c.user_name.clone())),
            _ => (None, None),
        };
        EntryOverview {
            id: self.id,
            title: self.title.clone(),
            credential_type: self.credential_type().to_string(),
            category: self.category.clone(),
            tags: self.tags.clone(),
            favorite: self.favorite,
            url,
            username,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }

    /// Extract the details portion of this entry.
    pub fn to_details(&self) -> EntryDetails {
        EntryDetails {
            credential: self.credential.clone(),
            notes: self.notes.clone(),
            totp_secret: self.totp_secret.clone(),
            sensitive: self.sensitive,
            last_breach_check: self.last_breach_check,
            breach_count: self.breach_count,
        }
    }

    /// Reconstruct an entry from its overview and details.
    pub fn from_overview_and_details(overview: EntryOverview, details: EntryDetails) -> Self {
        Self {
            id: overview.id,
            title: overview.title,
            credential: details.credential,
            category: overview.category,
            tags: overview.tags,
            favorite: overview.favorite,
            notes: details.notes,
            totp_secret: details.totp_secret,
            sensitive: details.sensitive,
            last_breach_check: details.last_breach_check,
            breach_count: details.breach_count,
            created_at: overview.created_at,
            updated_at: overview.updated_at,
        }
    }

    pub fn new(title: String, credential: Credential) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            title,
            credential,
            category: None,
            tags: Vec::new(),
            favorite: false,
            notes: String::new(),
            totp_secret: None,
            sensitive: false,
            last_breach_check: None,
            breach_count: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        self.category = Some(category.into());
        self
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    pub fn with_favorite(mut self, favorite: bool) -> Self {
        self.favorite = favorite;
        self
    }

    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = notes.into();
        self
    }

    pub fn with_totp(mut self, totp_secret: impl Into<String>) -> Self {
        self.totp_secret = Some(totp_secret.into());
        self
    }

    pub fn with_sensitive(mut self, sensitive: bool) -> Self {
        self.sensitive = sensitive;
        self
    }

    /// Get the credential type as a string.
    pub fn credential_type(&self) -> &str {
        match &self.credential {
            Credential::Login(_) => "login",
            Credential::ApiKey(_) => "api_key",
            Credential::SecureNote(_) => "secure_note",
            Credential::SshKey(_) => "ssh_key",
            Credential::Passkey(_) => "passkey",
        }
    }

    /// Check if this entry matches a search query (case-insensitive).
    pub fn matches(&self, query: &str) -> bool {
        let q = query.to_lowercase();
        if self.title.to_lowercase().contains(&q) {
            return true;
        }
        if self.tags.iter().any(|t| t.to_lowercase().contains(&q)) {
            return true;
        }
        if let Some(cat) = &self.category {
            if cat.to_lowercase().contains(&q) {
                return true;
            }
        }
        match &self.credential {
            Credential::Login(login) => {
                login.url.to_lowercase().contains(&q)
                    || login.username.to_lowercase().contains(&q)
            }
            Credential::ApiKey(api) => api.service.to_lowercase().contains(&q),
            Credential::SecureNote(note) => note.content.to_lowercase().contains(&q),
            Credential::SshKey(_) => false,
            Credential::Passkey(pk) => {
                pk.rp_id.to_lowercase().contains(&q)
                    || pk.rp_name.to_lowercase().contains(&q)
                    || pk.user_name.to_lowercase().contains(&q)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_login() -> Entry {
        Entry::new(
            "GitHub".to_string(),
            Credential::Login(LoginCredential {
                url: "https://github.com".to_string(),
                username: "octocat".to_string(),
                password: "s3cret".to_string(),
            }),
        )
    }

    #[test]
    fn test_entry_creation() {
        let entry = sample_login();
        assert_eq!(entry.title, "GitHub");
        assert_eq!(entry.credential_type(), "login");
        assert!(!entry.favorite);
        assert!(entry.tags.is_empty());
        assert!(entry.category.is_none());
    }

    #[test]
    fn test_entry_builder() {
        let entry = sample_login()
            .with_category("development")
            .with_tags(vec!["vcs".to_string(), "code".to_string()])
            .with_favorite(true)
            .with_notes("My personal GitHub account")
            .with_totp("JBSWY3DPEHPK3PXP");

        assert_eq!(entry.category.as_deref(), Some("development"));
        assert_eq!(entry.tags, vec!["vcs", "code"]);
        assert!(entry.favorite);
        assert_eq!(entry.notes, "My personal GitHub account");
        assert_eq!(entry.totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn test_matches_title() {
        let entry = sample_login();
        assert!(entry.matches("git"));
        assert!(entry.matches("GitHub"));
        assert!(entry.matches("GITHUB"));
        assert!(!entry.matches("gitlab"));
    }

    #[test]
    fn test_matches_url() {
        let entry = sample_login();
        assert!(entry.matches("github.com"));
    }

    #[test]
    fn test_matches_username() {
        let entry = sample_login();
        assert!(entry.matches("octocat"));
    }

    #[test]
    fn test_matches_tag() {
        let entry = sample_login().with_tags(vec!["work".to_string()]);
        assert!(entry.matches("work"));
    }

    #[test]
    fn test_matches_category() {
        let entry = sample_login().with_category("social");
        assert!(entry.matches("social"));
    }

    #[test]
    fn test_matches_api_key() {
        let entry = Entry::new(
            "AWS".to_string(),
            Credential::ApiKey(ApiKeyCredential {
                service: "Amazon Web Services".to_string(),
                key: "AKIA123".to_string(),
                secret: "secret".to_string(),
            }),
        );
        assert!(entry.matches("amazon"));
        assert_eq!(entry.credential_type(), "api_key");
    }

    #[test]
    fn test_matches_secure_note() {
        let entry = Entry::new(
            "Recovery codes".to_string(),
            Credential::SecureNote(SecureNoteCredential {
                content: "code1 code2 code3".to_string(),
            }),
        );
        assert!(entry.matches("code2"));
        assert_eq!(entry.credential_type(), "secure_note");
    }

    #[test]
    fn test_ssh_key_type() {
        let entry = Entry::new(
            "Server key".to_string(),
            Credential::SshKey(SshKeyCredential {
                private_key: "-----BEGIN OPENSSH PRIVATE KEY-----".to_string(),
                public_key: "ssh-ed25519 AAAA...".to_string(),
                passphrase: "pass".to_string(),
            }),
        );
        assert_eq!(entry.credential_type(), "ssh_key");
    }

    #[test]
    fn test_serialization_roundtrip() {
        let entry = sample_login()
            .with_category("dev")
            .with_tags(vec!["vcs".to_string()])
            .with_totp("JBSWY3DPEHPK3PXP");

        let serialized = rmp_serde::to_vec(&entry).unwrap();
        let deserialized: Entry = rmp_serde::from_slice(&serialized).unwrap();
        assert_eq!(entry, deserialized);
    }

    #[test]
    fn test_json_serialization_roundtrip() {
        let entry = sample_login();
        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: Entry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, deserialized);
    }

    #[test]
    fn test_unique_ids() {
        let e1 = sample_login();
        let e2 = sample_login();
        assert_ne!(e1.id, e2.id);
    }

    #[test]
    fn test_ssh_key_matches_returns_false() {
        let entry = Entry::new(
            "Server Key".to_string(),
            Credential::SshKey(SshKeyCredential {
                private_key: "key-data".to_string(),
                public_key: "pubkey".to_string(),
                passphrase: "pass".to_string(),
            }),
        );
        // SshKey credential type always returns false for credential-specific matching
        assert!(!entry.matches("key-data"));
        assert!(!entry.matches("pubkey"));
        // But title match still works
        assert!(entry.matches("Server"));
    }

    #[test]
    fn test_matches_no_category() {
        let entry = sample_login();
        assert!(entry.category.is_none());
        // Should not panic even without a category
        assert!(!entry.matches("nonexistent"));
    }

    #[test]
    fn test_sensitive_default_false() {
        let entry = sample_login();
        assert!(!entry.sensitive);
    }

    #[test]
    fn test_with_sensitive() {
        let entry = sample_login().with_sensitive(true);
        assert!(entry.sensitive);
    }

    #[test]
    fn test_sensitive_serialization_roundtrip() {
        let entry = sample_login().with_sensitive(true);
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: Entry = serde_json::from_str(&json).unwrap();
        assert!(parsed.sensitive);
    }

    #[test]
    fn test_sensitive_default_deserialization() {
        // Simulate a JSON without the "sensitive" field (backwards compatibility)
        let entry = sample_login();
        let mut json: serde_json::Value = serde_json::to_value(&entry).unwrap();
        json.as_object_mut().unwrap().remove("sensitive");
        let parsed: Entry = serde_json::from_value(json).unwrap();
        assert!(!parsed.sensitive);
    }

    #[test]
    fn test_overview_extraction() {
        let entry = sample_login()
            .with_category("dev")
            .with_tags(vec!["vcs".to_string()])
            .with_favorite(true);

        let overview = entry.to_overview();
        assert_eq!(overview.id, entry.id);
        assert_eq!(overview.title, "GitHub");
        assert_eq!(overview.credential_type, "login");
        assert_eq!(overview.category.as_deref(), Some("dev"));
        assert_eq!(overview.tags, vec!["vcs"]);
        assert!(overview.favorite);
        assert_eq!(overview.url.as_deref(), Some("https://github.com"));
        assert_eq!(overview.username.as_deref(), Some("octocat"));
    }

    #[test]
    fn test_details_extraction() {
        let entry = sample_login()
            .with_notes("my notes")
            .with_totp("JBSWY3DPEHPK3PXP")
            .with_sensitive(true);

        let details = entry.to_details();
        assert_eq!(details.credential, entry.credential);
        assert_eq!(details.notes, "my notes");
        assert_eq!(details.totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert!(details.sensitive);
    }

    #[test]
    fn test_overview_details_roundtrip() {
        let entry = sample_login()
            .with_category("dev")
            .with_tags(vec!["vcs".to_string()])
            .with_notes("notes")
            .with_totp("TOTP")
            .with_sensitive(true);

        let overview = entry.to_overview();
        let details = entry.to_details();
        let reconstructed = Entry::from_overview_and_details(overview, details);

        assert_eq!(reconstructed.id, entry.id);
        assert_eq!(reconstructed.title, entry.title);
        assert_eq!(reconstructed.credential, entry.credential);
        assert_eq!(reconstructed.category, entry.category);
        assert_eq!(reconstructed.tags, entry.tags);
        assert_eq!(reconstructed.favorite, entry.favorite);
        assert_eq!(reconstructed.notes, entry.notes);
        assert_eq!(reconstructed.totp_secret, entry.totp_secret);
        assert_eq!(reconstructed.sensitive, entry.sensitive);
    }

    #[test]
    fn test_overview_serialization_roundtrip() {
        let entry = sample_login().with_category("dev");
        let overview = entry.to_overview();
        let bytes = rmp_serde::to_vec(&overview).unwrap();
        let parsed: EntryOverview = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(parsed, overview);
    }

    #[test]
    fn test_details_serialization_roundtrip() {
        let entry = sample_login().with_notes("secret notes");
        let details = entry.to_details();
        let bytes = rmp_serde::to_vec(&details).unwrap();
        let parsed: EntryDetails = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(parsed, details);
    }

    #[test]
    fn test_overview_api_key() {
        let entry = Entry::new(
            "AWS".to_string(),
            Credential::ApiKey(ApiKeyCredential {
                service: "Amazon Web Services".to_string(),
                key: "AKIA123".to_string(),
                secret: "secret".to_string(),
            }),
        );
        let overview = entry.to_overview();
        assert_eq!(overview.credential_type, "api_key");
        assert_eq!(overview.url.as_deref(), Some("Amazon Web Services"));
        assert!(overview.username.is_none());
    }

    #[test]
    fn test_overview_secure_note() {
        let entry = Entry::new(
            "Note".to_string(),
            Credential::SecureNote(SecureNoteCredential { content: "secret".to_string() }),
        );
        let overview = entry.to_overview();
        assert_eq!(overview.credential_type, "secure_note");
        assert!(overview.url.is_none());
        assert!(overview.username.is_none());
    }
}
