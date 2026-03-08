use std::collections::HashMap;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::vault::entry::{Credential, Entry, EntryId};

/// Password strength score (0-4, matching zxcvbn).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Strength {
    VeryWeak = 0,
    Weak = 1,
    Fair = 2,
    Strong = 3,
    VeryStrong = 4,
}

impl From<u8> for Strength {
    fn from(score: u8) -> Self {
        match score {
            0 => Strength::VeryWeak,
            1 => Strength::Weak,
            2 => Strength::Fair,
            3 => Strength::Strong,
            _ => Strength::VeryStrong,
        }
    }
}

impl Strength {
    pub fn label(&self) -> &'static str {
        match self {
            Strength::VeryWeak => "Very Weak",
            Strength::Weak => "Weak",
            Strength::Fair => "Fair",
            Strength::Strong => "Strong",
            Strength::VeryStrong => "Very Strong",
        }
    }

    pub fn is_acceptable(&self) -> bool {
        *self >= Strength::Strong
    }
}

/// Health assessment for a single password entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordHealth {
    pub entry_id: EntryId,
    pub title: String,
    pub strength: Strength,
    pub reused: bool,
    pub age_days: i64,
    pub is_old: bool,
    pub issues: Vec<String>,
}

/// Overall vault health report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultHealthReport {
    pub total_entries: usize,
    pub login_entries: usize,
    pub weak_passwords: usize,
    pub reused_passwords: usize,
    pub old_passwords: usize,
    pub entries_without_totp: usize,
    pub health_score: u8,
    pub details: Vec<PasswordHealth>,
}

/// Score a single password using zxcvbn.
pub fn score_password(password: &str) -> Strength {
    let estimate = zxcvbn::zxcvbn(password, &[]);
    let score: u8 = estimate.score().into();
    Strength::from(score)
}

/// Extract the password string from an entry, if it has one.
pub fn extract_password(entry: &Entry) -> Option<&str> {
    match &entry.credential {
        Credential::Login(login) => Some(&login.password),
        Credential::ApiKey(api) => Some(&api.secret),
        Credential::SshKey(ssh) => {
            if ssh.passphrase.is_empty() {
                None
            } else {
                Some(&ssh.passphrase)
            }
        }
        Credential::SecureNote(_) | Credential::Passkey(_) => None,
    }
}

/// Find reused passwords across entries. Returns a map of password hash -> entry IDs.
fn find_reused_passwords(entries: &[&Entry]) -> HashMap<String, Vec<EntryId>> {
    let mut password_map: HashMap<String, Vec<EntryId>> = HashMap::new();

    for entry in entries {
        if let Some(password) = extract_password(entry) {
            // Use the password itself as key (we're in-memory, not storing to disk)
            password_map
                .entry(password.to_string())
                .or_default()
                .push(entry.id);
        }
    }

    // Only keep entries with duplicates
    password_map.retain(|_, ids| ids.len() > 1);
    password_map
}

/// Maximum age in days before a password is considered "old".
const MAX_PASSWORD_AGE_DAYS: i64 = 365;

/// Analyze the health of all entries in the vault.
pub fn analyze_vault_health(entries: &[&Entry]) -> VaultHealthReport {
    let now = Utc::now();
    let login_entries: Vec<&&Entry> = entries
        .iter()
        .filter(|e| matches!(e.credential, Credential::Login(_) | Credential::ApiKey(_)))
        .collect();

    let reused = find_reused_passwords(entries);
    let reused_ids: std::collections::HashSet<EntryId> = reused
        .values()
        .flat_map(|ids| ids.iter().copied())
        .collect();

    let mut details = Vec::new();
    let mut weak_count = 0;
    let mut old_count = 0;
    let mut no_totp_count = 0;

    for entry in entries {
        let password = extract_password(entry);
        let strength = password
            .map(score_password)
            .unwrap_or(Strength::VeryStrong); // Secure notes don't have passwords

        let age_days = (now - entry.updated_at).num_days();
        let is_old = password.is_some() && age_days > MAX_PASSWORD_AGE_DAYS;
        let is_reused = reused_ids.contains(&entry.id);

        let mut issues = Vec::new();
        if !strength.is_acceptable() && password.is_some() {
            issues.push(format!("Password strength: {}", strength.label()));
            weak_count += 1;
        }
        if is_reused {
            issues.push("Password is reused across multiple entries".to_string());
        }
        if is_old {
            issues.push(format!("Password is {} days old", age_days));
            old_count += 1;
        }
        if entry.totp_secret.is_none() && matches!(entry.credential, Credential::Login(_)) {
            issues.push("No TOTP/2FA configured".to_string());
            no_totp_count += 1;
        }

        details.push(PasswordHealth {
            entry_id: entry.id,
            title: entry.title.clone(),
            strength,
            reused: is_reused,
            age_days,
            is_old,
            issues,
        });
    }

    let reused_count = reused_ids.len();

    // Calculate overall health score (0-100)
    let total_logins = login_entries.len().max(1);
    let weak_penalty = (weak_count * 100 / total_logins).min(40) as u8;
    let reused_penalty = (reused_count * 100 / total_logins).min(30) as u8;
    let old_penalty = (old_count * 100 / total_logins).min(20) as u8;
    let totp_penalty = (no_totp_count * 100 / total_logins).min(10) as u8;
    let health_score = 100u8.saturating_sub(weak_penalty + reused_penalty + old_penalty + totp_penalty);

    VaultHealthReport {
        total_entries: entries.len(),
        login_entries: login_entries.len(),
        weak_passwords: weak_count,
        reused_passwords: reused_count,
        old_passwords: old_count,
        entries_without_totp: no_totp_count,
        health_score,
        details,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::entry::*;

    fn login(title: &str, password: &str) -> Entry {
        Entry::new(
            title.to_string(),
            Credential::Login(LoginCredential {
                url: format!("https://{}.com", title.to_lowercase()),
                username: "user".to_string(),
                password: password.to_string(),
            }),
        )
    }

    #[test]
    fn test_score_password_weak() {
        let s = score_password("password");
        assert!(s <= Strength::Weak);
    }

    #[test]
    fn test_score_password_strong() {
        let s = score_password("X9#kL!mP@2qR&vZ8wN$");
        assert!(s >= Strength::Strong);
    }

    #[test]
    fn test_score_password_empty() {
        let s = score_password("");
        assert_eq!(s, Strength::VeryWeak);
    }

    #[test]
    fn test_strength_labels() {
        assert_eq!(Strength::VeryWeak.label(), "Very Weak");
        assert_eq!(Strength::Weak.label(), "Weak");
        assert_eq!(Strength::Fair.label(), "Fair");
        assert_eq!(Strength::Strong.label(), "Strong");
        assert_eq!(Strength::VeryStrong.label(), "Very Strong");
    }

    #[test]
    fn test_strength_acceptable() {
        assert!(!Strength::VeryWeak.is_acceptable());
        assert!(!Strength::Weak.is_acceptable());
        assert!(!Strength::Fair.is_acceptable());
        assert!(Strength::Strong.is_acceptable());
        assert!(Strength::VeryStrong.is_acceptable());
    }

    #[test]
    fn test_strength_from_u8() {
        assert_eq!(Strength::from(0), Strength::VeryWeak);
        assert_eq!(Strength::from(1), Strength::Weak);
        assert_eq!(Strength::from(2), Strength::Fair);
        assert_eq!(Strength::from(3), Strength::Strong);
        assert_eq!(Strength::from(4), Strength::VeryStrong);
        assert_eq!(Strength::from(5), Strength::VeryStrong);
    }

    #[test]
    fn test_find_reused_passwords() {
        let e1 = login("GitHub", "same_password_123!");
        let e2 = login("GitLab", "same_password_123!");
        let e3 = login("Twitter", "different_password!");
        let entries: Vec<&Entry> = vec![&e1, &e2, &e3];

        let reused = find_reused_passwords(&entries);
        assert_eq!(reused.len(), 1);
        let ids = reused.values().next().unwrap();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn test_find_no_reused() {
        let e1 = login("A", "unique_pass_1!");
        let e2 = login("B", "unique_pass_2!");
        let entries: Vec<&Entry> = vec![&e1, &e2];

        let reused = find_reused_passwords(&entries);
        assert!(reused.is_empty());
    }

    #[test]
    fn test_extract_password_login() {
        let e = login("Test", "mypass");
        assert_eq!(extract_password(&e), Some("mypass"));
    }

    #[test]
    fn test_extract_password_api_key() {
        let e = Entry::new(
            "AWS".to_string(),
            Credential::ApiKey(ApiKeyCredential {
                service: "AWS".to_string(),
                key: "AKIA".to_string(),
                secret: "secret123".to_string(),
            }),
        );
        assert_eq!(extract_password(&e), Some("secret123"));
    }

    #[test]
    fn test_extract_password_secure_note() {
        let e = Entry::new(
            "Note".to_string(),
            Credential::SecureNote(SecureNoteCredential {
                content: "secret notes".to_string(),
            }),
        );
        assert_eq!(extract_password(&e), None);
    }

    #[test]
    fn test_extract_password_ssh_key_empty() {
        let e = Entry::new(
            "Key".to_string(),
            Credential::SshKey(SshKeyCredential {
                private_key: "-----BEGIN-----".to_string(),
                public_key: "ssh-ed25519".to_string(),
                passphrase: "".to_string(),
            }),
        );
        assert_eq!(extract_password(&e), None);
    }

    #[test]
    fn test_extract_password_ssh_key_with_passphrase() {
        let e = Entry::new(
            "Key".to_string(),
            Credential::SshKey(SshKeyCredential {
                private_key: "-----BEGIN-----".to_string(),
                public_key: "ssh-ed25519".to_string(),
                passphrase: "my-passphrase".to_string(),
            }),
        );
        assert_eq!(extract_password(&e), Some("my-passphrase"));
    }

    #[test]
    fn test_analyze_vault_health_empty() {
        let entries: Vec<&Entry> = vec![];
        let report = analyze_vault_health(&entries);
        assert_eq!(report.total_entries, 0);
        assert_eq!(report.health_score, 100);
    }

    #[test]
    fn test_analyze_vault_health_all_strong() {
        let e1 = login("GitHub", "X9#kL!mP@2qR&vZ8wN$").with_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        let e2 = login("GitLab", "Y8@jK!nO#3pQ&uW7xM$").with_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        let entries: Vec<&Entry> = vec![&e1, &e2];

        let report = analyze_vault_health(&entries);
        assert_eq!(report.total_entries, 2);
        assert_eq!(report.weak_passwords, 0);
        assert_eq!(report.reused_passwords, 0);
        assert!(report.health_score >= 80);
    }

    #[test]
    fn test_analyze_vault_health_weak_passwords() {
        let e1 = login("Site1", "password");
        let e2 = login("Site2", "123456");
        let entries: Vec<&Entry> = vec![&e1, &e2];

        let report = analyze_vault_health(&entries);
        assert!(report.weak_passwords > 0);
        assert!(report.health_score < 80);
    }

    #[test]
    fn test_analyze_vault_health_reused() {
        let e1 = login("Site1", "X9#kL!mP@2qR&vZ8wN$");
        let e2 = login("Site2", "X9#kL!mP@2qR&vZ8wN$");
        let entries: Vec<&Entry> = vec![&e1, &e2];

        let report = analyze_vault_health(&entries);
        assert_eq!(report.reused_passwords, 2);
        assert!(report.details.iter().all(|d| d.reused));
    }

    #[test]
    fn test_analyze_vault_health_no_totp() {
        let e1 = login("Site1", "X9#kL!mP@2qR&vZ8wN$");
        let entries: Vec<&Entry> = vec![&e1];

        let report = analyze_vault_health(&entries);
        assert_eq!(report.entries_without_totp, 1);
    }

    #[test]
    fn test_password_health_serialization() {
        let e = login("Test", "password");
        let health = PasswordHealth {
            entry_id: e.id,
            title: "Test".to_string(),
            strength: Strength::Weak,
            reused: false,
            age_days: 10,
            is_old: false,
            issues: vec!["Weak password".to_string()],
        };
        let json = serde_json::to_string(&health).unwrap();
        let parsed: PasswordHealth = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.title, "Test");
        assert_eq!(parsed.strength, Strength::Weak);
    }

    #[test]
    fn test_vault_health_report_serialization() {
        let report = VaultHealthReport {
            total_entries: 5,
            login_entries: 4,
            weak_passwords: 1,
            reused_passwords: 2,
            old_passwords: 0,
            entries_without_totp: 3,
            health_score: 75,
            details: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: VaultHealthReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.health_score, 75);
        assert_eq!(parsed.total_entries, 5);
    }

    #[test]
    fn test_strength_ordering() {
        assert!(Strength::VeryWeak < Strength::Weak);
        assert!(Strength::Weak < Strength::Fair);
        assert!(Strength::Fair < Strength::Strong);
        assert!(Strength::Strong < Strength::VeryStrong);
    }

    #[test]
    fn test_find_reused_passwords_mixed_credential_types() {
        let e1 = login("GitHub", "same_pass_123!");
        let e2 = login("GitLab", "same_pass_123!");
        let e3 = Entry::new(
            "Note".to_string(),
            Credential::SecureNote(SecureNoteCredential {
                content: "just a note".to_string(),
            }),
        );
        let entries: Vec<&Entry> = vec![&e1, &e2, &e3];
        let reused = find_reused_passwords(&entries);
        assert_eq!(reused.len(), 1);
    }

    #[test]
    fn test_analyze_vault_health_with_totp() {
        let e1 = login("Site1", "X9#kL!mP@2qR&vZ8wN$").with_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        let e2 = login("Site2", "Y8@jK!nO#3pQ&uW7xM$");
        let entries: Vec<&Entry> = vec![&e1, &e2];
        let report = analyze_vault_health(&entries);
        // e1 has TOTP, e2 does not
        assert_eq!(report.entries_without_totp, 1);
    }
}
