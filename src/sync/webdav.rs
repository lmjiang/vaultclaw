use std::path::Path;

use serde::{Deserialize, Serialize};

use super::provider::*;

/// WebDAV sync configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebDavConfig {
    pub url: String,
    pub username: String,
    pub password: String,
    pub remote_path: String,
}

/// WebDAV sync provider for syncing vault files over HTTP/WebDAV.
pub struct WebDavProvider {
    config: WebDavConfig,
}

impl WebDavProvider {
    pub fn new(config: WebDavConfig) -> Self {
        Self { config }
    }

    fn full_url(&self) -> String {
        format!("{}/{}", self.config.url.trim_end_matches('/'), self.config.remote_path)
    }
}

impl SyncProvider for WebDavProvider {
    fn name(&self) -> &str {
        "webdav"
    }

    fn is_available(&self) -> Result<bool, SyncError> {
        // Try a HEAD/PROPFIND to check server availability.
        // For now, we do a blocking reqwest call.
        let client = reqwest::blocking::Client::new();
        let resp = client
            .request(reqwest::Method::OPTIONS, &self.config.url)
            .basic_auth(&self.config.username, Some(&self.config.password))
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .map_err(|e| SyncError::Http(e.to_string()))?;

        Ok(resp.status().is_success() || resp.status().as_u16() == 207)
    }

    fn remote_metadata(&self) -> Result<Option<VaultMetadata>, SyncError> {
        let client = reqwest::blocking::Client::new();
        let url = self.full_url();

        let resp = client
            .head(&url)
            .basic_auth(&self.config.username, Some(&self.config.password))
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .map_err(|e| SyncError::Http(e.to_string()))?;

        if resp.status().as_u16() == 404 {
            return Ok(None);
        }

        if !resp.status().is_success() {
            return Err(SyncError::Http(format!("HTTP {}", resp.status())));
        }

        let size = resp
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);

        // Use ETag as a pseudo-checksum if available
        let checksum = resp
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        Ok(Some(VaultMetadata {
            path: url,
            size,
            modified_timestamp: 0, // WebDAV doesn't always provide this in HEAD
            checksum,
        }))
    }

    fn push(&self, local_path: &Path) -> Result<SyncResult, SyncError> {
        let data = std::fs::read(local_path)?;
        let size = data.len() as u64;

        let client = reqwest::blocking::Client::new();
        let url = self.full_url();

        let resp = client
            .put(&url)
            .basic_auth(&self.config.username, Some(&self.config.password))
            .header("Content-Type", "application/octet-stream")
            .body(data)
            .timeout(std::time::Duration::from_secs(60))
            .send()
            .map_err(|e| SyncError::Http(e.to_string()))?;

        if !resp.status().is_success() && resp.status().as_u16() != 201 && resp.status().as_u16() != 204 {
            return Err(SyncError::Http(format!("PUT failed: HTTP {}", resp.status())));
        }

        Ok(SyncResult {
            direction: SyncDirection::Push,
            bytes_transferred: size,
            success: true,
            message: format!("Pushed {} bytes to {}", size, url),
        })
    }

    fn pull(&self, local_path: &Path) -> Result<SyncResult, SyncError> {
        let client = reqwest::blocking::Client::new();
        let url = self.full_url();

        let resp = client
            .get(&url)
            .basic_auth(&self.config.username, Some(&self.config.password))
            .timeout(std::time::Duration::from_secs(60))
            .send()
            .map_err(|e| SyncError::Http(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(SyncError::Http(format!("GET failed: HTTP {}", resp.status())));
        }

        let data = resp.bytes().map_err(|e| SyncError::Http(e.to_string()))?;
        let size = data.len() as u64;

        // Atomic write: temp file then rename
        let tmp_path = local_path.with_extension("vclaw.tmp");
        std::fs::write(&tmp_path, &data)?;
        std::fs::rename(&tmp_path, local_path)?;

        Ok(SyncResult {
            direction: SyncDirection::Pull,
            bytes_transferred: size,
            success: true,
            message: format!("Pulled {} bytes from {}", size, url),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> WebDavConfig {
        WebDavConfig {
            url: "https://dav.example.com".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault/default.vclaw".to_string(),
        }
    }

    #[test]
    fn test_webdav_provider_name() {
        let provider = WebDavProvider::new(test_config());
        assert_eq!(provider.name(), "webdav");
    }

    #[test]
    fn test_webdav_full_url() {
        let provider = WebDavProvider::new(test_config());
        assert_eq!(
            provider.full_url(),
            "https://dav.example.com/vault/default.vclaw"
        );
    }

    #[test]
    fn test_webdav_full_url_trailing_slash() {
        let config = WebDavConfig {
            url: "https://dav.example.com/".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);
        assert_eq!(
            provider.full_url(),
            "https://dav.example.com/vault.vclaw"
        );
    }

    #[test]
    fn test_webdav_config_serialization() {
        let config = test_config();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: WebDavConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.url, "https://dav.example.com");
        assert_eq!(parsed.remote_path, "vault/default.vclaw");
    }

    #[test]
    fn test_webdav_push_unreachable() {
        let config = WebDavConfig {
            url: "http://127.0.0.1:19999".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("local.vclaw");
        std::fs::write(&path, b"test data").unwrap();
        let result = provider.push(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_webdav_pull_unreachable() {
        let config = WebDavConfig {
            url: "http://127.0.0.1:19999".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("local.vclaw");
        let result = provider.pull(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_webdav_new() {
        let config = test_config();
        let provider = WebDavProvider::new(config);
        assert_eq!(provider.name(), "webdav");
        assert_eq!(
            provider.full_url(),
            "https://dav.example.com/vault/default.vclaw"
        );
    }

    #[test]
    fn test_webdav_config_all_fields() {
        let config = WebDavConfig {
            url: "https://my.server.com:8443".to_string(),
            username: "admin".to_string(),
            password: "s3cret!".to_string(),
            remote_path: "data/vault.vclaw".to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: WebDavConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.url, "https://my.server.com:8443");
        assert_eq!(parsed.username, "admin");
        assert_eq!(parsed.password, "s3cret!");
        assert_eq!(parsed.remote_path, "data/vault.vclaw");
    }

    #[test]
    fn test_webdav_is_available_unreachable() {
        let config = WebDavConfig {
            url: "http://127.0.0.1:19999".to_string(), // Unlikely to be running
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);
        // Should return error (connection refused) or Ok(false), not panic
        let _ = provider.is_available();
    }

    #[test]
    fn test_webdav_remote_metadata_unreachable() {
        let config = WebDavConfig {
            url: "http://127.0.0.1:19999".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);
        let result = provider.remote_metadata();
        assert!(result.is_err());
    }

    /// Helper: start a minimal HTTP server on a random port, returning (addr, handle).
    fn start_mock_server(
        response_fn: impl Fn(&str, &str) -> (u16, Vec<(String, String)>, Vec<u8>) + Send + 'static,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = std::thread::spawn(move || {
            // Accept up to 10 connections for testing
            for _ in 0..10 {
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

                // Parse method and path
                let parts: Vec<&str> = request_line.split_whitespace().collect();
                let method = parts.first().unwrap_or(&"GET").to_string();
                let path = parts.get(1).unwrap_or(&"/").to_string();

                // Read headers (we mostly skip them, but consume them)
                let mut content_length = 0usize;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap_or(0);
                    if line.trim().is_empty() {
                        break;
                    }
                    if line.to_lowercase().starts_with("content-length:") {
                        content_length = line.split(':').nth(1).unwrap_or("0").trim().parse().unwrap_or(0);
                    }
                }

                // Read body if present
                if content_length > 0 {
                    let mut body = vec![0u8; content_length];
                    use std::io::Read;
                    let _ = reader.read_exact(&mut body);
                }

                let (status, headers, body) = response_fn(&method, &path);
                let status_text = match status {
                    200 => "OK",
                    201 => "Created",
                    204 => "No Content",
                    207 => "Multi-Status",
                    404 => "Not Found",
                    _ => "OK",
                };

                let mut response = format!("HTTP/1.1 {} {}\r\n", status, status_text);
                for (k, v) in &headers {
                    response.push_str(&format!("{}: {}\r\n", k, v));
                }
                response.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
                let _ = writer.write_all(response.as_bytes());
                let _ = writer.write_all(&body);
                let _ = writer.flush();
            }
        });

        (addr, handle)
    }

    #[test]
    fn test_webdav_is_available_success() {
        let (addr, _handle) = start_mock_server(|_method, _path| {
            (200, vec![], vec![])
        });

        let config = WebDavConfig {
            url: format!("http://{}", addr),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);
        let result = provider.is_available().unwrap();
        assert!(result);
    }

    #[test]
    fn test_webdav_is_available_207() {
        let (addr, _handle) = start_mock_server(|_method, _path| {
            (207, vec![], vec![])
        });

        let config = WebDavConfig {
            url: format!("http://{}", addr),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);
        let result = provider.is_available().unwrap();
        assert!(result);
    }

    #[test]
    fn test_webdav_remote_metadata_success() {
        let (addr, _handle) = start_mock_server(|_method, _path| {
            (
                200,
                vec![
                    ("Content-Length".to_string(), "1024".to_string()),
                    ("ETag".to_string(), "\"abc123\"".to_string()),
                ],
                vec![],
            )
        });

        let config = WebDavConfig {
            url: format!("http://{}", addr),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);
        let meta = provider.remote_metadata().unwrap().unwrap();
        assert_eq!(meta.size, 1024);
        assert_eq!(meta.checksum, "\"abc123\"");
    }

    #[test]
    fn test_webdav_remote_metadata_404() {
        let (addr, _handle) = start_mock_server(|_method, _path| {
            (404, vec![], vec![])
        });

        let config = WebDavConfig {
            url: format!("http://{}", addr),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);
        let result = provider.remote_metadata().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_webdav_remote_metadata_error_status() {
        let (addr, _handle) = start_mock_server(|_method, _path| {
            (500, vec![], b"Internal Server Error".to_vec())
        });

        let config = WebDavConfig {
            url: format!("http://{}", addr),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);
        let result = provider.remote_metadata();
        assert!(result.is_err());
    }

    #[test]
    fn test_webdav_push_success() {
        let (addr, _handle) = start_mock_server(|_method, _path| {
            (201, vec![], vec![])
        });

        let config = WebDavConfig {
            url: format!("http://{}", addr),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("local.vclaw");
        std::fs::write(&path, b"vault data here").unwrap();

        let result = provider.push(&path).unwrap();
        assert!(result.success);
        assert_eq!(result.bytes_transferred, 15);
        assert!(matches!(result.direction, super::SyncDirection::Push));
    }

    #[test]
    fn test_webdav_push_failure_status() {
        let (addr, _handle) = start_mock_server(|_method, _path| {
            (500, vec![], b"Server Error".to_vec())
        });

        let config = WebDavConfig {
            url: format!("http://{}", addr),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("local.vclaw");
        std::fs::write(&path, b"data").unwrap();

        let result = provider.push(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_webdav_pull_success() {
        let (addr, _handle) = start_mock_server(|_method, _path| {
            (200, vec![], b"remote vault data".to_vec())
        });

        let config = WebDavConfig {
            url: format!("http://{}", addr),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("local.vclaw");

        let result = provider.pull(&path).unwrap();
        assert!(result.success);
        assert_eq!(result.bytes_transferred, 17); // "remote vault data".len()
        assert!(matches!(result.direction, super::SyncDirection::Pull));

        // Verify data was written
        let data = std::fs::read(&path).unwrap();
        assert_eq!(data, b"remote vault data");
    }

    #[test]
    fn test_webdav_pull_failure_status() {
        let (addr, _handle) = start_mock_server(|_method, _path| {
            (403, vec![], b"Forbidden".to_vec())
        });

        let config = WebDavConfig {
            url: format!("http://{}", addr),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("local.vclaw");

        let result = provider.pull(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_webdav_push_nonexistent_local_file() {
        let config = WebDavConfig {
            url: "http://127.0.0.1:19999".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);
        let result = provider.push(std::path::Path::new("/nonexistent/file.vclaw"));
        assert!(result.is_err());
    }

    #[test]
    fn test_webdav_is_available_returns_false_on_non_success() {
        // When the server returns a non-success, non-207 status,
        // is_available should return Ok(false).
        let (addr, _handle) = start_mock_server(|_method, _path| {
            (403, vec![], b"Forbidden".to_vec())
        });

        let config = WebDavConfig {
            url: format!("http://{}", addr),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);
        let result = provider.is_available().unwrap();
        assert!(!result);
    }

    #[test]
    fn test_webdav_push_success_204() {
        // Some WebDAV servers return 204 No Content on PUT (overwrite).
        let (addr, _handle) = start_mock_server(|_method, _path| {
            (204, vec![], vec![])
        });

        let config = WebDavConfig {
            url: format!("http://{}", addr),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("local.vclaw");
        std::fs::write(&path, b"updated vault data").unwrap();

        let result = provider.push(&path).unwrap();
        assert!(result.success);
        assert_eq!(result.bytes_transferred, 18);
        assert!(matches!(result.direction, super::SyncDirection::Push));
    }

    #[test]
    fn test_webdav_push_success_200() {
        // Some servers return 200 OK on PUT.
        let (addr, _handle) = start_mock_server(|_method, _path| {
            (200, vec![], vec![])
        });

        let config = WebDavConfig {
            url: format!("http://{}", addr),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("local.vclaw");
        std::fs::write(&path, b"data").unwrap();

        let result = provider.push(&path).unwrap();
        assert!(result.success);
        assert_eq!(result.bytes_transferred, 4);
    }

    #[test]
    fn test_webdav_remote_metadata_no_headers() {
        // Server returns 200 but without Content-Length or ETag headers.
        // size should default to 0, checksum to empty string.
        let (addr, _handle) = start_mock_server(|_method, _path| {
            (200, vec![], vec![])
        });

        let config = WebDavConfig {
            url: format!("http://{}", addr),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);
        let meta = provider.remote_metadata().unwrap().unwrap();
        // Without Content-Length header, size defaults to 0
        assert_eq!(meta.size, 0);
        // Without ETag header, checksum defaults to empty string
        assert_eq!(meta.checksum, "");
    }

    #[test]
    fn test_webdav_remote_metadata_non_numeric_content_length() {
        // Server returns Content-Length with a non-numeric value.
        // The code should parse it as 0 via unwrap_or(0).
        let (addr, _handle) = start_mock_server(|_method, _path| {
            (
                200,
                vec![
                    ("Content-Length".to_string(), "not_a_number".to_string()),
                ],
                vec![],
            )
        });

        let config = WebDavConfig {
            url: format!("http://{}", addr),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);
        let meta = provider.remote_metadata().unwrap().unwrap();
        // Non-numeric content-length should default to 0
        assert_eq!(meta.size, 0);
    }

    #[test]
    fn test_webdav_pull_writes_atomically() {
        // Verify that pull uses atomic write (temp file then rename)
        // by checking that the final file exists and temp file does not.
        let (addr, _handle) = start_mock_server(|_method, _path| {
            (200, vec![], b"atomic write test".to_vec())
        });

        let config = WebDavConfig {
            url: format!("http://{}", addr),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("local.vclaw");

        let result = provider.pull(&path).unwrap();
        assert!(result.success);

        // Final file should exist
        assert!(path.exists());
        // Temp file should NOT exist (it was renamed)
        let tmp_path = path.with_extension("vclaw.tmp");
        assert!(!tmp_path.exists());

        // Verify content
        let data = std::fs::read(&path).unwrap();
        assert_eq!(data, b"atomic write test");
    }

    #[test]
    fn test_webdav_push_message_contains_url() {
        let (addr, _handle) = start_mock_server(|_method, _path| {
            (201, vec![], vec![])
        });

        let config = WebDavConfig {
            url: format!("http://{}", addr),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("local.vclaw");
        std::fs::write(&path, b"data").unwrap();

        let result = provider.push(&path).unwrap();
        // The message should contain the URL
        assert!(result.message.contains("vault.vclaw"));
        assert!(result.message.contains("Pushed"));
    }

    #[test]
    fn test_webdav_pull_message_contains_url() {
        let (addr, _handle) = start_mock_server(|_method, _path| {
            (200, vec![], b"data".to_vec())
        });

        let config = WebDavConfig {
            url: format!("http://{}", addr),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("local.vclaw");

        let result = provider.pull(&path).unwrap();
        assert!(result.message.contains("vault.vclaw"));
        assert!(result.message.contains("Pulled"));
    }

    #[test]
    fn test_mock_server_handles_immediate_disconnect() {
        // Connect to the mock server and immediately close the connection
        // without sending any data. This exercises the `continue` branch
        // in start_mock_server when read_line returns 0.
        use std::net::TcpStream;

        let (addr, _handle) = start_mock_server(|_method, _path| {
            (200, vec![], vec![])
        });

        // Connect and immediately drop (close) the connection
        let stream = TcpStream::connect(addr).unwrap();
        drop(stream);

        // Now send a real request to verify the server still works after
        // handling the empty connection
        let config = WebDavConfig {
            url: format!("http://{}", addr),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);
        let result = provider.is_available().unwrap();
        assert!(result);
    }

    // ---- Additional error-path tests for webdav.rs ----

    #[test]
    fn test_webdav_pull_write_error_readonly_dir() {
        // L140: std::fs::write(&tmp_path, &data)? fails when destination dir is read-only
        let (addr, _handle) = start_mock_server(|_method, _path| {
            (200, vec![], b"pulled data".to_vec())
        });

        let config = WebDavConfig {
            url: format!("http://{}", addr),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);

        let dir = tempfile::TempDir::new().unwrap();
        let local_path = dir.path().join("local.vclaw");

        // Make the directory read-only so write fails
        let mut perms = std::fs::metadata(dir.path()).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(dir.path(), perms.clone()).unwrap();

        let result = provider.pull(&local_path);
        assert!(matches!(result.unwrap_err(), SyncError::Io(ref e) if e.kind() == std::io::ErrorKind::PermissionDenied));

        // Restore permissions for cleanup
        use std::os::unix::fs::PermissionsExt as _;
        perms.set_mode(0o755);
        std::fs::set_permissions(dir.path(), perms).unwrap();
    }

    #[test]
    fn test_webdav_pull_rename_error_cross_path() {
        // L141: std::fs::rename(&tmp_path, local_path)? fails.
        // This is hard to trigger in isolation since rename usually works
        // within the same filesystem. But if we make local_path point to
        // a location where the parent doesn't exist, rename will fail.
        // However, the write (L140) creates the tmp file at local_path.with_extension("vclaw.tmp"),
        // so the parent must exist for write to succeed. We can't easily test rename in isolation
        // without the write succeeding first.
        //
        // Instead, test by pointing local_path to a path whose parent is a file (not a dir).
        // The tmp file writes successfully (it's next to local_path), but the rename target
        // is inside a non-directory path.
        //
        // Actually, the tmp_path and local_path share the same parent, so if write works,
        // rename to the same directory generally works too. On Unix, rename can fail if
        // local_path is a directory that exists and is non-empty. Let's test that.
        let (addr, _handle) = start_mock_server(|_method, _path| {
            (200, vec![], b"data for rename test".to_vec())
        });

        let config = WebDavConfig {
            url: format!("http://{}", addr),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);

        let dir = tempfile::TempDir::new().unwrap();
        // Create local_path as a non-empty directory — rename(file, dir) fails on Unix
        let local_path = dir.path().join("local.vclaw");
        std::fs::create_dir(&local_path).unwrap();
        std::fs::write(local_path.join("child.txt"), b"block rename").unwrap();

        let result = provider.pull(&local_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_webdav_is_available_error_is_sync_error_http() {
        // L45: Verify the error from is_available is specifically SyncError::Http
        let config = WebDavConfig {
            url: "http://127.0.0.1:19999".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);
        let result = provider.is_available();
        assert!(result.is_ok() || matches!(result, Err(SyncError::Http(ref msg)) if !msg.is_empty()));
    }

    #[test]
    fn test_webdav_remote_metadata_error_is_sync_error_http() {
        // L59: Verify the error type from remote_metadata
        let config = WebDavConfig {
            url: "http://127.0.0.1:19999".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);
        let result = provider.remote_metadata();
        assert!(matches!(result, Err(SyncError::Http(ref msg)) if !msg.is_empty()));
    }

    #[test]
    fn test_webdav_push_error_is_sync_error_http() {
        // L106: Verify push network error returns SyncError::Http
        let config = WebDavConfig {
            url: "http://127.0.0.1:19999".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("local.vclaw");
        std::fs::write(&path, b"data").unwrap();

        let result = provider.push(&path);
        assert!(matches!(result, Err(SyncError::Http(ref msg)) if !msg.is_empty()));
    }

    #[test]
    fn test_webdav_pull_error_is_sync_error_http() {
        // L129: Verify pull network error returns SyncError::Http
        let config = WebDavConfig {
            url: "http://127.0.0.1:19999".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("local.vclaw");

        let result = provider.pull(&path);
        assert!(matches!(result, Err(SyncError::Http(ref msg)) if !msg.is_empty()));
    }

    #[test]
    fn test_webdav_push_io_error_nonexistent_local() {
        // L93: std::fs::read(local_path)? fails with IO error before any HTTP call
        let config = WebDavConfig {
            url: "http://127.0.0.1:19999".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);

        let result = provider.push(std::path::Path::new("/tmp/vaultclaw_definitely_not_here.vclaw"));
        assert!(matches!(result.unwrap_err(), SyncError::Io(ref e) if e.kind() == std::io::ErrorKind::NotFound));
    }

    #[test]
    fn test_webdav_push_status_403() {
        // Verify that a 403 Forbidden response causes an error (not 200/201/204)
        let (addr, _handle) = start_mock_server(|_method, _path| {
            (403, vec![], b"Forbidden".to_vec())
        });

        let config = WebDavConfig {
            url: format!("http://{}", addr),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("local.vclaw");
        std::fs::write(&path, b"data").unwrap();

        let result = provider.push(&path);
        assert!(matches!(result.unwrap_err(), SyncError::Http(ref msg) if msg.contains("PUT failed") && msg.contains("403")));
    }

    #[test]
    fn test_webdav_pull_status_500() {
        // Verify that a 500 status in pull returns the right error message
        let (addr, _handle) = start_mock_server(|_method, _path| {
            (500, vec![], b"Internal Server Error".to_vec())
        });

        let config = WebDavConfig {
            url: format!("http://{}", addr),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("local.vclaw");

        let result = provider.pull(&path);
        assert!(matches!(result.unwrap_err(), SyncError::Http(ref msg) if msg.contains("GET failed") && msg.contains("500")));
    }

    #[test]
    fn test_webdav_remote_metadata_500_error_message() {
        // Verify the error message format for non-success, non-404 status
        let (addr, _handle) = start_mock_server(|_method, _path| {
            (500, vec![], b"Server Error".to_vec())
        });

        let config = WebDavConfig {
            url: format!("http://{}", addr),
            username: "user".to_string(),
            password: "pass".to_string(),
            remote_path: "vault.vclaw".to_string(),
        };
        let provider = WebDavProvider::new(config);

        let result = provider.remote_metadata();
        assert!(matches!(result, Err(SyncError::Http(ref msg)) if msg.contains("HTTP") && msg.contains("500")));
    }
}
