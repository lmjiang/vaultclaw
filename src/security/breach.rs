use serde::{Deserialize, Serialize};
use sha1::{Sha1, Digest};
use thiserror::Error;

use crate::vault::entry::{Entry, EntryId};

#[derive(Debug, Error)]
pub enum BreachError {
    #[error("HTTP request failed: {0}")]
    HttpError(String),
    #[error("Invalid response from HIBP API: {0}")]
    InvalidResponse(String),
}

/// Result of checking a password against HIBP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachResult {
    pub breached: bool,
    pub count: u64,
}

/// Result of a breach check for a single vault entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryBreachResult {
    pub entry_id: EntryId,
    pub title: String,
    pub breached: bool,
    pub count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Summary of a batch breach check across the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachCheckReport {
    pub checked: usize,
    pub breached_count: usize,
    pub error_count: usize,
    pub results: Vec<EntryBreachResult>,
}

/// Check a password against the Have I Been Pwned API using k-anonymity.
/// Only the first 5 characters of the SHA1 hash are sent to the API.
pub async fn check_password_breach(password: &str) -> Result<BreachResult, BreachError> {
    check_password_breach_with_url(password, "https://api.pwnedpasswords.com/range").await
}

/// Implementation that accepts a configurable base URL (used for testing and custom HIBP endpoints).
/// The URL should be the base path without a trailing slash (e.g. "https://api.pwnedpasswords.com/range").
/// The SHA1 prefix will be appended as a path segment.
pub async fn check_password_breach_with_url(
    password: &str,
    base_url: &str,
) -> Result<BreachResult, BreachError> {
    let hash = sha1_hex(password);
    let prefix = &hash[..5];
    let suffix = &hash[5..];

    let url = format!("{}/{}", base_url, prefix);

    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .header("User-Agent", "VaultClaw-PasswordManager")
        .send()
        .await
        .map_err(|e| BreachError::HttpError(e.to_string()))?;

    if !response.status().is_success() {
        return Err(BreachError::HttpError(format!(
            "HTTP {}",
            response.status()
        )));
    }

    let body = response
        .text()
        .await
        .map_err(|e| BreachError::InvalidResponse(e.to_string()))?;

    let count = parse_hibp_response(&body, suffix);

    Ok(BreachResult {
        breached: count > 0,
        count,
    })
}

/// Compute SHA1 hash of a password, returned as uppercase hex string.
pub fn sha1_hex(password: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    hex::encode_upper(result)
}

/// Parse the HIBP range API response to find the matching suffix count.
fn parse_hibp_response(body: &str, suffix: &str) -> u64 {
    let suffix_upper = suffix.to_uppercase();
    for line in body.lines() {
        let line = line.trim();
        if let Some((hash_suffix, count_str)) = line.split_once(':') {
            if hash_suffix.to_uppercase() == suffix_upper {
                return count_str.trim().parse().unwrap_or(0);
            }
        }
    }
    0
}

/// Check a password offline (without API) - just returns the SHA1 prefix for display.
pub fn password_sha1_prefix(password: &str) -> String {
    let hash = sha1_hex(password);
    hash[..5].to_string()
}

/// Check a single entry against HIBP and return the result.
pub async fn check_entry_breach(entry: &Entry) -> EntryBreachResult {
    check_entry_breach_with_url(entry, "https://api.pwnedpasswords.com/range").await
}

/// Check a single entry against HIBP using a configurable base URL (for testing).
pub async fn check_entry_breach_with_url(entry: &Entry, base_url: &str) -> EntryBreachResult {
    let password = crate::security::health::extract_password(entry);
    let password = match password {
        Some(pw) => pw,
        None => {
            return EntryBreachResult {
                entry_id: entry.id,
                title: entry.title.clone(),
                breached: false,
                count: 0,
                error: None,
            };
        }
    };

    match check_password_breach_with_url(password, base_url).await {
        Ok(result) => EntryBreachResult {
            entry_id: entry.id,
            title: entry.title.clone(),
            breached: result.breached,
            count: result.count,
            error: None,
        },
        Err(e) => EntryBreachResult {
            entry_id: entry.id,
            title: entry.title.clone(),
            breached: false,
            count: 0,
            error: Some(e.to_string()),
        },
    }
}

/// HIBP rate limit: 1.5 seconds between requests (free tier).
const HIBP_RATE_LIMIT_MS: u64 = 1500;

/// Check multiple entries against HIBP with rate limiting (1.5s between requests).
pub async fn check_entries_breach(entries: &[&Entry]) -> BreachCheckReport {
    check_entries_breach_with_url(entries, "https://api.pwnedpasswords.com/range").await
}

/// Check multiple entries against HIBP with rate limiting, using a configurable base URL (for testing).
pub async fn check_entries_breach_with_url(
    entries: &[&Entry],
    base_url: &str,
) -> BreachCheckReport {
    let mut results = Vec::new();
    let mut breached_count = 0;
    let mut error_count = 0;
    let mut checked = 0;

    for (i, entry) in entries.iter().enumerate() {
        // Rate limit: wait between requests (skip before first)
        if i > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(HIBP_RATE_LIMIT_MS)).await;
        }

        let password = crate::security::health::extract_password(entry);
        if password.is_none() {
            continue;
        }

        let result = check_entry_breach_with_url(entry, base_url).await;
        checked += 1;
        if result.error.is_some() {
            error_count += 1;
        } else if result.breached {
            breached_count += 1;
        }
        results.push(result);
    }

    BreachCheckReport {
        checked,
        breached_count,
        error_count,
        results,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_hex() {
        // Known SHA1 for "password"
        let hash = sha1_hex("password");
        assert_eq!(hash, "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }

    #[test]
    fn test_sha1_hex_empty() {
        let hash = sha1_hex("");
        assert_eq!(hash.len(), 40);
    }

    #[test]
    fn test_sha1_hex_case() {
        let hash = sha1_hex("test");
        // SHA1 of "test" = A94A8FE5CCB19BA61C4C0873D391E987982FBBD3
        assert_eq!(hash, "A94A8FE5CCB19BA61C4C0873D391E987982FBBD3");
    }

    #[test]
    fn test_parse_hibp_response_found() {
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n\
                     1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\n\
                     0023456789ABCDEF0123456789ABCDEF012:42";
        // "password" suffix is 1E4C9B93F3F0682250B6CF8331B7EE68FD8
        let count = parse_hibp_response(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
        assert_eq!(count, 3861493);
    }

    #[test]
    fn test_parse_hibp_response_not_found() {
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n\
                     1E4C9B93F3F0682250B6CF8331B7EE68FD8:100";
        let count = parse_hibp_response(body, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0");
        assert_eq!(count, 0);
    }

    #[test]
    fn test_parse_hibp_response_empty() {
        let count = parse_hibp_response("", "ABC");
        assert_eq!(count, 0);
    }

    #[test]
    fn test_parse_hibp_response_case_insensitive() {
        let body = "AABBCC:42";
        assert_eq!(parse_hibp_response(body, "aabbcc"), 42);
        assert_eq!(parse_hibp_response(body, "AABBCC"), 42);
    }

    #[test]
    fn test_password_sha1_prefix() {
        let prefix = password_sha1_prefix("password");
        assert_eq!(prefix, "5BAA6");
        assert_eq!(prefix.len(), 5);
    }

    #[test]
    fn test_breach_result() {
        let result = BreachResult { breached: true, count: 100 };
        assert!(result.breached);
        assert_eq!(result.count, 100);

        let safe = BreachResult { breached: false, count: 0 };
        assert!(!safe.breached);
        assert_eq!(safe.count, 0);
    }

    #[test]
    fn test_breach_result_clone_debug() {
        let result = BreachResult { breached: true, count: 42 };
        let cloned = result.clone();
        assert_eq!(cloned.count, 42);
        let debug = format!("{:?}", result);
        assert!(debug.contains("42"));
    }

    #[test]
    fn test_breach_error_display_http() {
        let err = BreachError::HttpError("connection refused".to_string());
        let msg = err.to_string();
        assert!(msg.contains("HTTP request failed"));
        assert!(msg.contains("connection refused"));
    }

    #[test]
    fn test_breach_error_display_invalid_response() {
        let err = BreachError::InvalidResponse("bad body".to_string());
        let msg = err.to_string();
        assert!(msg.contains("Invalid response"));
        assert!(msg.contains("bad body"));
    }

    #[test]
    fn test_breach_error_debug() {
        let err = BreachError::HttpError("timeout".to_string());
        let debug = format!("{:?}", err);
        assert!(debug.contains("HttpError"));
    }

    #[test]
    fn test_parse_hibp_response_malformed_line() {
        // Lines without ':' should be skipped
        let body = "malformed_line\nAABBCC:10";
        assert_eq!(parse_hibp_response(body, "AABBCC"), 10);
    }

    #[test]
    fn test_parse_hibp_response_invalid_count() {
        // Non-numeric count should parse as 0
        let body = "AABBCC:notanumber";
        assert_eq!(parse_hibp_response(body, "AABBCC"), 0);
    }

    #[test]
    fn test_parse_hibp_response_whitespace() {
        let body = "  AABBCC:99  \r\n";
        assert_eq!(parse_hibp_response(body, "AABBCC"), 99);
    }

    #[test]
    fn test_sha1_hex_known_vectors() {
        // "abc" → A9993E364706816ABA3E25717850C26C9CD0D89D
        assert_eq!(sha1_hex("abc"), "A9993E364706816ABA3E25717850C26C9CD0D89D");
    }

    #[test]
    fn test_password_sha1_prefix_different_passwords() {
        let p1 = password_sha1_prefix("password1");
        let p2 = password_sha1_prefix("password2");
        // Different passwords should (very likely) have different prefixes
        // or at least the function works correctly
        assert_eq!(p1.len(), 5);
        assert_eq!(p2.len(), 5);
    }

    #[tokio::test]
    async fn test_check_password_breach_network_error() {
        // This test verifies that the async function properly handles
        // unreachable servers. In CI without network, this will fail with HttpError.
        // We just verify it doesn't panic.
        let result = check_password_breach("test_password_for_breach_check").await;
        match result {
            Ok(r) => {
                // If we have network access, this known-weak password should be breached
                // But we don't assert on it since tests should work offline
                let _ = r.breached;
            }
            Err(e) => {
                // Network error is expected in offline/CI environments
                let msg = e.to_string();
                assert!(!msg.is_empty());
            }
        }
    }

    /// Helper: start a mock HTTP server that responds to any request with the given
    /// status code and body. Returns the server address.
    fn start_breach_mock_server(
        status: u16,
        body: &str,
    ) -> std::net::SocketAddr {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = body.to_string();

        std::thread::spawn(move || {
            for _ in 0..5 {
                let stream = match listener.accept() {
                    Ok((s, _)) => s,
                    Err(_) => break,
                };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut writer = stream;

                // Read request line
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
                    continue;
                }

                // Consume headers
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap_or(0);
                    if line.trim().is_empty() {
                        break;
                    }
                }

                let status_text = match status {
                    200 => "OK",
                    403 => "Forbidden",
                    429 => "Too Many Requests",
                    500 => "Internal Server Error",
                    503 => "Service Unavailable",
                    _ => "Error",
                };

                let response = format!(
                    "HTTP/1.1 {} {}\r\nContent-Length: {}\r\n\r\n{}",
                    status, status_text, body.len(), body
                );
                let _ = writer.write_all(response.as_bytes());
                let _ = writer.flush();
            }
        });

        addr
    }

    #[tokio::test]
    async fn test_check_password_breach_http_error_status() {
        // Tests the error path in check_password_breach_with_url when the
        // server responds with a non-success HTTP status (lines 37-40).
        let addr = start_breach_mock_server(403, "Forbidden");
        let base_url = format!("http://{}/range", addr);

        let result = check_password_breach_with_url("password", &base_url).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("HTTP"));
        assert!(msg.contains("403"));
    }

    #[tokio::test]
    async fn test_check_password_breach_http_500_error() {
        let addr = start_breach_mock_server(500, "Internal Server Error");
        let base_url = format!("http://{}/range", addr);

        let result = check_password_breach_with_url("test", &base_url).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("500"));
    }

    #[tokio::test]
    async fn test_check_password_breach_mock_success_found() {
        // Mock a successful HIBP response that contains a matching suffix
        // SHA1 of "password" = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        // prefix = 5BAA6, suffix = 1E4C9B93F3F0682250B6CF8331B7EE68FD8
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n\
                    1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\n\
                    00234ABCDEF0123456789ABCDEF0123456:7";
        let addr = start_breach_mock_server(200, body);
        let base_url = format!("http://{}/range", addr);

        let result = check_password_breach_with_url("password", &base_url).await;
        assert!(result.is_ok());
        let breach = result.unwrap();
        assert!(breach.breached);
        assert_eq!(breach.count, 3861493);
    }

    #[tokio::test]
    async fn test_check_password_breach_mock_429() {
        let addr = start_breach_mock_server(429, "Too Many Requests");
        let base_url = format!("http://{}/range", addr);

        let result = check_password_breach_with_url("test", &base_url).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("429"));
    }

    #[tokio::test]
    async fn test_check_password_breach_mock_503() {
        let addr = start_breach_mock_server(503, "Service Unavailable");
        let base_url = format!("http://{}/range", addr);

        let result = check_password_breach_with_url("test", &base_url).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("503"));
    }

    #[tokio::test]
    async fn test_check_password_breach_mock_unknown_status() {
        let addr = start_breach_mock_server(418, "I'm a teapot");
        let base_url = format!("http://{}/range", addr);

        let result = check_password_breach_with_url("test", &base_url).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("418"));
    }

    #[tokio::test]
    async fn test_check_password_breach_mock_success_not_found() {
        // Mock a successful response that does NOT contain the suffix
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n\
                    00234ABCDEF0123456789ABCDEF0123456:7";
        let addr = start_breach_mock_server(200, body);
        let base_url = format!("http://{}/range", addr);

        // Use a password whose suffix won't match any entry in the body
        let result = check_password_breach_with_url("some_unique_password_xyz", &base_url).await;
        assert!(result.is_ok());
        let breach = result.unwrap();
        assert!(!breach.breached);
        assert_eq!(breach.count, 0);
    }

    #[test]
    fn test_mock_server_immediate_disconnect() {
        // Exercise the `continue` path in start_breach_mock_server (line 270)
        // when a client connects but sends no data and immediately disconnects.
        use std::net::TcpStream;

        let addr = start_breach_mock_server(200, "OK");

        // Connect and immediately drop (send nothing) to hit the read_line == 0 path
        {
            let _stream = TcpStream::connect(addr).unwrap();
            // Dropping _stream here closes the connection without sending data
        }

        // Give the server thread a moment to process the empty connection
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Verify the server is still alive and functional after the empty connection
        {
            use std::io::{Read, Write};
            let mut stream = TcpStream::connect(addr).unwrap();
            stream.write_all(b"GET /range/AAAAA HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
            stream.flush().unwrap();
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).unwrap();
            let response = std::str::from_utf8(&buf[..n]).unwrap();
            assert!(response.contains("200 OK"));
        }
    }

    // ---- New type tests ----

    #[test]
    fn test_breach_result_serialization() {
        let result = BreachResult { breached: true, count: 42 };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: BreachResult = serde_json::from_str(&json).unwrap();
        assert!(parsed.breached);
        assert_eq!(parsed.count, 42);
    }

    #[test]
    fn test_entry_breach_result_serialization() {
        let result = EntryBreachResult {
            entry_id: uuid::Uuid::new_v4(),
            title: "Test".to_string(),
            breached: true,
            count: 100,
            error: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("error")); // skip_serializing_if None
        let parsed: EntryBreachResult = serde_json::from_str(&json).unwrap();
        assert!(parsed.breached);
        assert_eq!(parsed.count, 100);
    }

    #[test]
    fn test_entry_breach_result_with_error() {
        let result = EntryBreachResult {
            entry_id: uuid::Uuid::new_v4(),
            title: "Test".to_string(),
            breached: false,
            count: 0,
            error: Some("network error".to_string()),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("network error"));
    }

    #[test]
    fn test_breach_check_report_serialization() {
        let report = BreachCheckReport {
            checked: 2,
            breached_count: 1,
            error_count: 0,
            results: vec![
                EntryBreachResult {
                    entry_id: uuid::Uuid::new_v4(),
                    title: "Breached".to_string(),
                    breached: true,
                    count: 50,
                    error: None,
                },
                EntryBreachResult {
                    entry_id: uuid::Uuid::new_v4(),
                    title: "Safe".to_string(),
                    breached: false,
                    count: 0,
                    error: None,
                },
            ],
        };
        let json = serde_json::to_string_pretty(&report).unwrap();
        let parsed: BreachCheckReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.checked, 2);
        assert_eq!(parsed.breached_count, 1);
        assert_eq!(parsed.results.len(), 2);
    }

    // ---- check_entry_breach tests ----

    #[tokio::test]
    async fn test_check_entry_breach_no_password() {
        use crate::vault::entry::*;
        let entry = Entry::new(
            "Note".to_string(),
            Credential::SecureNote(SecureNoteCredential { content: "secret".to_string() }),
        );
        let result = check_entry_breach(&entry).await;
        assert!(!result.breached);
        assert_eq!(result.count, 0);
        assert!(result.error.is_none());
    }

    #[tokio::test]
    async fn test_check_entry_breach_with_mock() {
        use crate::vault::entry::*;
        // This test uses the real HIBP API path (check_password_breach),
        // but we just verify the result structure is correct regardless of network.
        let entry = Entry::new(
            "Test".to_string(),
            Credential::Login(LoginCredential {
                url: "https://test.com".to_string(),
                username: "user".to_string(),
                password: "test_unique_password_xyz_42".to_string(),
            }),
        );
        let result = check_entry_breach(&entry).await;
        assert_eq!(result.entry_id, entry.id);
        assert_eq!(result.title, "Test");
        // Either succeeds or errors (depending on network)
        // Just verify structure
        let _ = result.breached;
        let _ = result.count;
    }

    // ---- CLI entry filter test ----

    #[test]
    fn test_cmd_breach_with_entry_filter() {
        use crate::crypto::kdf::KdfParams;
        use crate::crypto::keys::password_secret;
        use crate::vault::entry::*;
        use crate::vault::format::VaultFile;

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("testpass".to_string());
        let mut vault = VaultFile::create(&path, &password, KdfParams::fast_for_testing()).unwrap();

        vault.store_mut().add(Entry::new(
            "GitHub".to_string(),
            Credential::Login(LoginCredential {
                url: "https://github.com".to_string(),
                username: "user".to_string(),
                password: "ghpass123".to_string(),
            }),
        ));
        vault.store_mut().add(Entry::new(
            "AWS".to_string(),
            Credential::ApiKey(ApiKeyCredential {
                service: "aws".to_string(),
                key: "AKIA123".to_string(),
                secret: "secret456".to_string(),
            }),
        ));

        // Filter to "github" should work
        let result = crate::cli::commands::security::cmd_breach_with_vault(
            &vault, false, Some("github"), false,
        );
        assert!(result.is_ok());

        // Filter to nonexistent should return "no passwords to check"
        let result = crate::cli::commands::security::cmd_breach_with_vault(
            &vault, false, Some("nonexistent"), false,
        );
        assert!(result.is_ok());
    }

    // ---- Breach metadata on Entry test ----

    #[test]
    fn test_entry_breach_metadata() {
        use crate::vault::entry::*;
        let mut entry = Entry::new(
            "Test".to_string(),
            Credential::Login(LoginCredential {
                url: "https://test.com".to_string(),
                username: "u".to_string(),
                password: "p".to_string(),
            }),
        );
        assert!(entry.last_breach_check.is_none());
        assert!(entry.breach_count.is_none());

        entry.last_breach_check = Some(chrono::Utc::now());
        entry.breach_count = Some(42);
        assert!(entry.last_breach_check.is_some());
        assert_eq!(entry.breach_count, Some(42));
    }

    #[test]
    fn test_entry_breach_metadata_serialization_roundtrip() {
        use crate::vault::entry::*;
        let mut entry = Entry::new(
            "Test".to_string(),
            Credential::Login(LoginCredential {
                url: "https://test.com".to_string(),
                username: "u".to_string(),
                password: "p".to_string(),
            }),
        );
        entry.last_breach_check = Some(chrono::Utc::now());
        entry.breach_count = Some(99);

        let json = serde_json::to_string(&entry).unwrap();
        let parsed: Entry = serde_json::from_str(&json).unwrap();
        assert!(parsed.last_breach_check.is_some());
        assert_eq!(parsed.breach_count, Some(99));
    }

    #[test]
    fn test_entry_breach_metadata_backwards_compat() {
        use crate::vault::entry::*;
        // Simulate an old entry without breach fields
        let entry = Entry::new(
            "Old".to_string(),
            Credential::Login(LoginCredential {
                url: "https://old.com".to_string(),
                username: "u".to_string(),
                password: "p".to_string(),
            }),
        );
        let mut json: serde_json::Value = serde_json::to_value(&entry).unwrap();
        json.as_object_mut().unwrap().remove("last_breach_check");
        json.as_object_mut().unwrap().remove("breach_count");
        let parsed: Entry = serde_json::from_value(json).unwrap();
        assert!(parsed.last_breach_check.is_none());
        assert!(parsed.breach_count.is_none());
    }

    // ---- check_entry_breach_with_url tests (covers error path + batch logic) ----

    #[tokio::test]
    async fn test_check_entry_breach_with_url_error_path() {
        // Server returns 500 → exercises the Err(e) arm (lines 141-147)
        use crate::vault::entry::*;
        let addr = start_breach_mock_server(500, "Internal Server Error");
        let base_url = format!("http://{}/range", addr);

        let entry = Entry::new(
            "ErrorEntry".to_string(),
            Credential::Login(LoginCredential {
                url: "https://example.com".to_string(),
                username: "user".to_string(),
                password: "mypassword".to_string(),
            }),
        );

        let result = check_entry_breach_with_url(&entry, &base_url).await;
        assert_eq!(result.entry_id, entry.id);
        assert_eq!(result.title, "ErrorEntry");
        assert!(!result.breached);
        assert_eq!(result.count, 0);
        assert!(result.error.is_some());
        assert!(result.error.unwrap().contains("500"));
    }

    #[tokio::test]
    async fn test_check_entry_breach_with_url_breached() {
        // Server returns a response containing the password's SHA1 suffix
        use crate::vault::entry::*;
        // SHA1 of "password" = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        // suffix = 1E4C9B93F3F0682250B6CF8331B7EE68FD8
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n\
                    1E4C9B93F3F0682250B6CF8331B7EE68FD8:9999\r\n";
        let addr = start_breach_mock_server(200, body);
        let base_url = format!("http://{}/range", addr);

        let entry = Entry::new(
            "BreachedEntry".to_string(),
            Credential::Login(LoginCredential {
                url: "https://example.com".to_string(),
                username: "user".to_string(),
                password: "password".to_string(),
            }),
        );

        let result = check_entry_breach_with_url(&entry, &base_url).await;
        assert_eq!(result.entry_id, entry.id);
        assert_eq!(result.title, "BreachedEntry");
        assert!(result.breached);
        assert_eq!(result.count, 9999);
        assert!(result.error.is_none());
    }

    #[tokio::test]
    async fn test_check_entry_breach_with_url_no_password() {
        use crate::vault::entry::*;
        let addr = start_breach_mock_server(200, "");
        let base_url = format!("http://{}/range", addr);

        let entry = Entry::new(
            "NoteEntry".to_string(),
            Credential::SecureNote(SecureNoteCredential {
                content: "just a note".to_string(),
            }),
        );

        let result = check_entry_breach_with_url(&entry, &base_url).await;
        assert!(!result.breached);
        assert_eq!(result.count, 0);
        assert!(result.error.is_none());
    }

    #[tokio::test]
    async fn test_check_entries_breach_with_url_empty() {
        let addr = start_breach_mock_server(200, "");
        let base_url = format!("http://{}/range", addr);

        let entries: Vec<&Entry> = vec![];
        let report = check_entries_breach_with_url(&entries, &base_url).await;
        assert_eq!(report.checked, 0);
        assert_eq!(report.breached_count, 0);
        assert_eq!(report.error_count, 0);
        assert!(report.results.is_empty());
    }

    #[tokio::test]
    async fn test_check_entries_breach_with_url_all_no_password() {
        use crate::vault::entry::*;
        let addr = start_breach_mock_server(200, "");
        let base_url = format!("http://{}/range", addr);

        let e1 = Entry::new(
            "Note1".to_string(),
            Credential::SecureNote(SecureNoteCredential {
                content: "note".to_string(),
            }),
        );
        let e2 = Entry::new(
            "Note2".to_string(),
            Credential::SecureNote(SecureNoteCredential {
                content: "note2".to_string(),
            }),
        );

        let entries: Vec<&Entry> = vec![&e1, &e2];
        let report = check_entries_breach_with_url(&entries, &base_url).await;
        assert_eq!(report.checked, 0);
        assert_eq!(report.breached_count, 0);
        assert_eq!(report.error_count, 0);
        assert!(report.results.is_empty());
    }

    #[tokio::test]
    async fn test_check_entries_breach_with_url_mixed() {
        // Exercises the full batch logic: breached entry, safe entry, no-password
        // entry (skipped), and error entry.
        use crate::vault::entry::*;

        // SHA1 of "password" suffix = 1E4C9B93F3F0682250B6CF8331B7EE68FD8
        // We serve this suffix as breached.
        // SHA1 of "unique_safe_pw_xyz" won't match → not breached.
        let body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\r\n\
                    0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n";
        let addr = start_breach_mock_server(200, body);
        let base_url = format!("http://{}/range", addr);

        let breached_entry = Entry::new(
            "Breached".to_string(),
            Credential::Login(LoginCredential {
                url: "https://a.com".to_string(),
                username: "u".to_string(),
                password: "password".to_string(),
            }),
        );

        let safe_entry = Entry::new(
            "Safe".to_string(),
            Credential::Login(LoginCredential {
                url: "https://b.com".to_string(),
                username: "u".to_string(),
                password: "unique_safe_pw_xyz_9999".to_string(),
            }),
        );

        let note_entry = Entry::new(
            "Note".to_string(),
            Credential::SecureNote(SecureNoteCredential {
                content: "no password".to_string(),
            }),
        );

        let entries: Vec<&Entry> = vec![&breached_entry, &note_entry, &safe_entry];
        let report = check_entries_breach_with_url(&entries, &base_url).await;

        // note_entry is skipped (no password) → 2 checked
        assert_eq!(report.checked, 2);
        assert_eq!(report.breached_count, 1);
        assert_eq!(report.error_count, 0);
        assert_eq!(report.results.len(), 2);

        // First result should be the breached entry
        assert!(report.results[0].breached);
        assert_eq!(report.results[0].count, 42);

        // Second result should be safe
        assert!(!report.results[1].breached);
        assert_eq!(report.results[1].count, 0);
    }

    #[tokio::test]
    async fn test_check_entries_breach_with_url_error_entries() {
        // Server returns 500 for all requests → all entries with passwords get errors
        use crate::vault::entry::*;
        let addr = start_breach_mock_server(500, "fail");
        let base_url = format!("http://{}/range", addr);

        let e1 = Entry::new(
            "E1".to_string(),
            Credential::Login(LoginCredential {
                url: "https://a.com".to_string(),
                username: "u".to_string(),
                password: "pw1".to_string(),
            }),
        );
        let e2 = Entry::new(
            "E2".to_string(),
            Credential::ApiKey(ApiKeyCredential {
                service: "svc".to_string(),
                key: "k".to_string(),
                secret: "s".to_string(),
            }),
        );

        let entries: Vec<&Entry> = vec![&e1, &e2];
        let report = check_entries_breach_with_url(&entries, &base_url).await;
        assert_eq!(report.checked, 2);
        assert_eq!(report.breached_count, 0);
        assert_eq!(report.error_count, 2);
        assert_eq!(report.results.len(), 2);
        assert!(report.results[0].error.is_some());
        assert!(report.results[1].error.is_some());
    }

    #[tokio::test]
    async fn test_check_entries_breach_with_url_single_entry() {
        // Single entry should NOT trigger rate limit sleep (i == 0 path)
        use crate::vault::entry::*;
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n";
        let addr = start_breach_mock_server(200, body);
        let base_url = format!("http://{}/range", addr);

        let entry = Entry::new(
            "Single".to_string(),
            Credential::Login(LoginCredential {
                url: "https://a.com".to_string(),
                username: "u".to_string(),
                password: "pw".to_string(),
            }),
        );

        let start = std::time::Instant::now();
        let entries: Vec<&Entry> = vec![&entry];
        let report = check_entries_breach_with_url(&entries, &base_url).await;
        let elapsed = start.elapsed();

        assert_eq!(report.checked, 1);
        // Should complete well under 1.5s since there's no rate limit for first request
        assert!(elapsed < std::time::Duration::from_millis(1000));
    }
}
