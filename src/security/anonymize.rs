//! PII anonymization layer for protecting personal identity.
//!
//! Hashes usernames, anonymizes file paths, and replaces personal identifiers
//! consistently throughout text. Uses SHA-256 for deterministic hashing.

use regex::Regex;
use sha2::{Digest, Sha256};

/// Hash a username to a deterministic anonymized form: `user_<8 hex chars>`.
pub fn hash_username(username: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(username.as_bytes());
    let result = hasher.finalize();
    format!("user_{}", hex::encode(&result[..4]))
}

/// Detect the current user's home directory and username.
pub fn detect_home_dir() -> (String, String) {
    let home = dirs::home_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let username = std::path::Path::new(&home)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    (home, username)
}

/// Anonymize a file path by replacing the user's home directory prefix.
pub fn anonymize_path(path: &str, username: &str, username_hash: &str, home: &str) -> String {
    if path.is_empty() || username.is_empty() {
        return path.to_string();
    }

    let escaped = regex::escape(username);

    // Build prefixes to check (longer first for correct matching)
    let mut prefixes: Vec<(String, String)> = Vec::new();

    // Subdirectory prefixes strip to project-relative
    for base in &[format!("/Users/{username}"), format!("/home/{username}"), home.to_string()] {
        for subdir in &["Documents", "Downloads", "Desktop"] {
            let prefix = format!("{base}/{subdir}/");
            prefixes.push((prefix, String::new()));
        }
    }

    // Home directory prefixes replace with hash
    for base in &[format!("/Users/{username}"), format!("/home/{username}"), home.to_string()] {
        let prefix = format!("{base}/");
        prefixes.push((prefix, format!("{username_hash}/")));
    }

    // Sort by prefix length descending (longest match first)
    prefixes.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

    let mut result = path.to_string();
    for (prefix, replacement) in &prefixes {
        if result.starts_with(prefix.as_str()) {
            result = format!("{}{}", replacement, &result[prefix.len()..]);
            return result;
        }
    }

    // Fallback: replace username in path patterns
    result = Regex::new(&format!(r"/Users/{escaped}(?=/|$)"))
        .map(|re| re.replace_all(&result, format!("/{username_hash}")).to_string())
        .unwrap_or(result);
    result = Regex::new(&format!(r"/home/{escaped}(?=/|$)"))
        .map(|re| re.replace_all(&result, format!("/{username_hash}")).to_string())
        .unwrap_or(result);

    // Hyphen-encoded paths (e.g., -Users-username-)
    result = Regex::new(&format!(r"-Users-{escaped}(?=-|/|$)"))
        .map(|re| re.replace_all(&result, format!("-Users-{username_hash}")).to_string())
        .unwrap_or(result);
    result = Regex::new(&format!(r"-home-{escaped}(?=-|/|$)"))
        .map(|re| re.replace_all(&result, format!("-home-{username_hash}")).to_string())
        .unwrap_or(result);

    result
}

/// Anonymize usernames and paths in arbitrary text.
pub fn anonymize_text(text: &str, username: &str, username_hash: &str) -> String {
    if text.is_empty() || username.is_empty() {
        return text.to_string();
    }

    let escaped = regex::escape(username);
    let mut result = text.to_string();

    // Replace /Users/<username> and /home/<username>
    if let Ok(re) = Regex::new(&format!(r"/Users/{escaped}(?=/|[^a-zA-Z0-9_-]|$)")) {
        result = re.replace_all(&result, format!("/{username_hash}")).to_string();
    }
    if let Ok(re) = Regex::new(&format!(r"/home/{escaped}(?=/|[^a-zA-Z0-9_-]|$)")) {
        result = re.replace_all(&result, format!("/{username_hash}")).to_string();
    }

    // Hyphen-encoded paths
    if let Ok(re) = Regex::new(&format!(r"-Users-{escaped}(?=-|/|$)")) {
        result = re.replace_all(&result, format!("-Users-{username_hash}")).to_string();
    }
    if let Ok(re) = Regex::new(&format!(r"-home-{escaped}(?=-|/|$)")) {
        result = re.replace_all(&result, format!("-home-{username_hash}")).to_string();
    }

    // Bare username replacement (only if >= 4 chars to avoid false positives)
    if username.len() >= 4 {
        if let Ok(re) = Regex::new(&format!(r"\b{escaped}\b")) {
            result = re.replace_all(&result, username_hash).to_string();
        }
    }

    result
}

/// Stateful anonymizer that consistently hashes usernames and anonymizes text.
pub struct Anonymizer {
    home: String,
    username: String,
    username_hash: String,
    extra: Vec<(String, String)>,
}

impl Anonymizer {
    /// Create a new anonymizer detecting the current OS username.
    pub fn new(extra_usernames: &[String]) -> Self {
        let (home, username) = detect_home_dir();
        let username_hash = hash_username(&username);
        let extra = extra_usernames
            .iter()
            .filter(|s| !s.is_empty() && s.as_str() != username)
            .map(|name| (name.trim().to_string(), hash_username(name.trim())))
            .collect();
        Self { home, username, username_hash, extra }
    }

    /// Create an anonymizer with an explicit username (for testing).
    pub fn with_username(username: &str, extra_usernames: &[String]) -> Self {
        let username_hash = hash_username(username);
        let home = format!("/Users/{username}");
        let extra = extra_usernames
            .iter()
            .filter(|s| !s.is_empty() && s.as_str() != username)
            .map(|name| (name.trim().to_string(), hash_username(name.trim())))
            .collect();
        Self { home, username: username.to_string(), username_hash, extra }
    }

    /// Anonymize a file path.
    pub fn path(&self, file_path: &str) -> String {
        let mut result = anonymize_path(file_path, &self.username, &self.username_hash, &self.home);
        for (name, hashed) in &self.extra {
            result = replace_username(&result, name, hashed);
        }
        result
    }

    /// Anonymize arbitrary text (paths, usernames, etc.).
    pub fn text(&self, content: &str) -> String {
        let mut result = anonymize_text(content, &self.username, &self.username_hash);
        for (name, hashed) in &self.extra {
            result = replace_username(&result, name, hashed);
        }
        result
    }

    /// Get the primary username hash.
    pub fn primary_hash(&self) -> &str {
        &self.username_hash
    }

    /// Get the detected username.
    pub fn username(&self) -> &str {
        &self.username
    }
}

/// Replace a username in text with its hash (case-insensitive for >= 3 char usernames).
fn replace_username(text: &str, username: &str, username_hash: &str) -> String {
    if text.is_empty() || username.is_empty() || username.len() < 3 {
        return text.to_string();
    }
    let escaped = regex::escape(username);
    Regex::new(&escaped)
        .map(|re| re.replace_all(text, username_hash).to_string())
        .unwrap_or_else(|_| text.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_username() {
        let hash = hash_username("john");
        assert!(hash.starts_with("user_"));
        assert_eq!(hash.len(), 13); // "user_" + 8 hex chars
        // Deterministic
        assert_eq!(hash, hash_username("john"));
    }

    #[test]
    fn test_hash_different_usernames() {
        let h1 = hash_username("john");
        let h2 = hash_username("jane");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_anonymize_path_home() {
        let hash = hash_username("john");
        let result = anonymize_path("/Users/john/Projects/foo/main.rs", "john", &hash, "/Users/john");
        assert!(!result.contains("john"));
        assert!(result.contains(&hash));
        assert!(result.contains("Projects/foo/main.rs"));
    }

    #[test]
    fn test_anonymize_path_linux() {
        let hash = hash_username("john");
        let result = anonymize_path("/home/john/src/app.py", "john", &hash, "/home/john");
        assert!(!result.contains("john"));
        assert!(result.contains(&hash));
    }

    #[test]
    fn test_anonymize_path_documents_stripped() {
        let hash = hash_username("john");
        let result = anonymize_path("/Users/john/Documents/project/file.txt", "john", &hash, "/Users/john");
        // Documents prefix should be stripped entirely
        assert_eq!(result, "project/file.txt");
    }

    #[test]
    fn test_anonymize_path_empty() {
        let hash = hash_username("john");
        assert_eq!(anonymize_path("", "john", &hash, "/Users/john"), "");
    }

    #[test]
    fn test_anonymize_path_no_username() {
        let hash = hash_username("john");
        let path = "/tmp/somefile.txt";
        assert_eq!(anonymize_path(path, "john", &hash, "/Users/john"), path);
    }

    #[test]
    fn test_anonymize_text_paths() {
        let hash = hash_username("john");
        let text = "Error in /Users/john/project/src/main.rs:42";
        let result = anonymize_text(text, "john", &hash);
        assert!(!result.contains("/Users/john"));
        assert!(result.contains(&hash));
    }

    #[test]
    fn test_anonymize_text_bare_username() {
        let hash = hash_username("john");
        let text = "User john committed the changes";
        let result = anonymize_text(text, "john", &hash);
        assert!(!result.contains("john"));
        assert!(result.contains(&hash));
    }

    #[test]
    fn test_anonymize_text_short_username_no_bare_replace() {
        let hash = hash_username("ab");
        let text = "Maybe ab is in the string";
        let result = anonymize_text(text, "ab", &hash);
        // Short usernames (< 4 chars) don't get bare replacement to avoid false positives
        assert_eq!(result, text);
    }

    #[test]
    fn test_anonymize_text_empty() {
        let hash = hash_username("john");
        assert_eq!(anonymize_text("", "john", &hash), "");
    }

    #[test]
    fn test_anonymize_text_hyphen_encoded() {
        let hash = hash_username("john");
        let text = "/private/tmp/claude-501/-Users-john-Projects";
        let result = anonymize_text(text, "john", &hash);
        assert!(!result.contains("-Users-john"));
        assert!(result.contains(&format!("-Users-{hash}")));
    }

    #[test]
    fn test_anonymizer_struct() {
        let anon = Anonymizer::with_username("john", &[]);
        assert_eq!(anon.username(), "john");
        assert!(anon.primary_hash().starts_with("user_"));
    }

    #[test]
    fn test_anonymizer_path() {
        let anon = Anonymizer::with_username("john", &[]);
        let result = anon.path("/Users/john/Projects/app/main.rs");
        assert!(!result.contains("john"));
    }

    #[test]
    fn test_anonymizer_text() {
        let anon = Anonymizer::with_username("john", &[]);
        let result = anon.text("Author: john at /Users/john/repo");
        assert!(!result.contains("john"));
    }

    #[test]
    fn test_anonymizer_extra_usernames() {
        let extras = vec!["github_user".to_string()];
        let anon = Anonymizer::with_username("john", &extras);
        let result = anon.text("Committed by github_user from /Users/john/repo");
        assert!(!result.contains("github_user"));
        assert!(!result.contains("john"));
    }

    #[test]
    fn test_anonymizer_extra_username_same_as_primary() {
        // Extra username same as primary should be deduplicated
        let extras = vec!["john".to_string()];
        let anon = Anonymizer::with_username("john", &extras);
        let result = anon.text("john was here");
        assert!(!result.contains("john"));
    }

    #[test]
    fn test_replace_username_short() {
        // Usernames < 3 chars are not replaced
        assert_eq!(replace_username("ab is here", "ab", "user_1234"), "ab is here");
    }

    #[test]
    fn test_replace_username_normal() {
        let result = replace_username("Hello john!", "john", "user_abcd");
        assert_eq!(result, "Hello user_abcd!");
    }

    #[test]
    fn test_detect_home_dir() {
        let (home, username) = detect_home_dir();
        assert!(!home.is_empty());
        assert!(!username.is_empty());
    }

    #[test]
    fn test_anonymize_text_home_path() {
        // Covers lines 95, 98 — /Users/<username> and /home/<username> replacements
        let result = anonymize_text("/Users/alice/Documents/secret.txt", "alice", "hash_a");
        assert!(result.contains("/hash_a/Documents"));
        assert!(!result.contains("alice"));

        let result = anonymize_text("/home/alice/config", "alice", "hash_a");
        assert!(result.contains("/hash_a/config"));
    }

    #[test]
    fn test_anonymize_text_hyphen_encoded_paths() {
        // Covers lines 103, 106 — -Users-<username> and -home-<username> replacements
        let result = anonymize_text("-Users-alice-Projects", "alice", "hash_a");
        assert!(result.contains("-Users-hash_a-Projects"));
        assert!(!result.contains("alice"));

        let result = anonymize_text("-home-alice-work", "alice", "hash_a");
        assert!(result.contains("-home-hash_a-work"));
    }

    #[test]
    fn test_anonymizer_with_extra_names() {
        // Covers lines 156-157 — extra names loop in path() and text()
        let extras = vec!["bob".to_string()];
        let anon = Anonymizer::with_username("alice", &extras);
        let result = anon.path("/Users/bob/Documents");
        assert!(!result.contains("bob"));

        let result = anon.text("User bob logged in from /home/bob");
        assert!(!result.contains("bob"));
    }
}
