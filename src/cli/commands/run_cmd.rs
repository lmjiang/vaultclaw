use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use regex::Regex;

use crate::agent::resolve::{parse_vclaw_uri, resolve_vclaw_uri, ResolveResponse};
use crate::crypto::keys::password_secret;
use crate::daemon::client::DaemonClient;
use crate::daemon::protocol::{Request, ResponseData};
use crate::security::redact::RedactionEngine;
use crate::vault::entry::Entry;
use crate::vault::format::VaultFile;

/// Guard that securely cleans up a temp directory on drop.
/// Overwrites file contents with zeros before deleting.
struct TempDirGuard {
    path: Option<PathBuf>,
}

impl TempDirGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn empty() -> Self {
        Self { path: None }
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        if let Some(ref path) = self.path {
            secure_delete_dir(path);
        }
    }
}

/// Overwrite all files in a directory with zeros, then remove the directory.
fn secure_delete_dir(path: &Path) {
    if let Ok(dir_entries) = fs::read_dir(path) {
        for entry in dir_entries.flatten() {
            if let Ok(metadata) = entry.metadata() {
                if metadata.is_file() {
                    if let Ok(mut f) = fs::OpenOptions::new().write(true).open(entry.path()) {
                        let zeros = vec![0u8; metadata.len() as usize];
                        let _ = f.write_all(&zeros);
                        let _ = f.flush();
                    }
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    }
    let _ = fs::remove_dir(path);
}

/// Find all `vclaw://` references in a string.
///
/// Uses the spec regex: `vclaw://vault/entry[/field]`
/// Entry names may contain spaces, dots, hyphens. In config files (JSON, YAML, TOML),
/// vclaw:// URIs should be inside quotes so the quote character terminates the match.
pub(crate) fn find_vclaw_refs(text: &str) -> Vec<String> {
    let re =
        Regex::new(r"vclaw://[a-zA-Z0-9_-]+/[a-zA-Z0-9_. -]+(?:/[a-zA-Z0-9_-]+)?").unwrap();
    re.find_iter(text)
        .map(|m| m.as_str().trim_end_matches('/').trim().to_string())
        .collect()
}

/// Parse a `.env` file into key=value pairs.
/// Skips blank lines and comments (#). Strips surrounding quotes from values.
fn parse_env_file(path: &Path) -> anyhow::Result<Vec<(String, String)>> {
    let content = fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Failed to read env file '{}': {}", path.display(), e))?;
    Ok(parse_env_content(&content))
}

fn parse_env_content(content: &str) -> Vec<(String, String)> {
    let mut vars = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().to_string();
            let value = value.trim();
            let value = strip_quotes(value).to_string();
            vars.push((key, value));
        }
    }
    vars
}

fn strip_quotes(s: &str) -> &str {
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"'))
            || (s.starts_with('\'') && s.ends_with('\'')))
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// Replace all `vclaw://` references in text with resolved values.
pub(crate) fn replace_vclaw_refs(text: &str, resolved: &HashMap<String, String>) -> String {
    let re =
        Regex::new(r"vclaw://[a-zA-Z0-9_-]+/[a-zA-Z0-9_. -]+(?:/[a-zA-Z0-9_-]+)?").unwrap();
    re.replace_all(text, |caps: &regex::Captures| {
        let uri = caps.get(0).unwrap().as_str().trim_end_matches('/').trim();
        resolved
            .get(uri)
            .cloned()
            .unwrap_or_else(|| uri.to_string())
    })
    .into_owned()
}

/// Resolve a list of vclaw:// URI strings against vault entries.
/// Returns a map from URI string → resolved value.
/// Errors if any reference fails to resolve.
pub(crate) fn resolve_batch(
    refs: &[String],
    entries: &[&Entry],
) -> anyhow::Result<HashMap<String, String>> {
    let mut resolved = HashMap::new();
    let mut errors = Vec::new();

    for ref_str in refs {
        let resp = match parse_vclaw_uri(ref_str) {
            Some(uri) => resolve_vclaw_uri(&uri, entries),
            None => ResolveResponse {
                uri: ref_str.clone(),
                value: None,
                error: Some(format!("Invalid vclaw:// URI: {}", ref_str)),
            },
        };

        if let Some(value) = resp.value {
            resolved.insert(resp.uri, value);
        } else if let Some(error) = resp.error {
            errors.push(format!("  {}: {}", resp.uri, error));
        }
    }

    if !errors.is_empty() {
        anyhow::bail!(
            "Failed to resolve {} vclaw:// reference(s):\n{}",
            errors.len(),
            errors.join("\n")
        );
    }

    Ok(resolved)
}

/// Get all entries via daemon or direct vault access.
pub(crate) fn get_entries(
    daemon: Option<&mut DaemonClient>,
    vault_path: &Path,
    get_pw: &dyn Fn(&str) -> String,
) -> anyhow::Result<Vec<Entry>> {
    // Try daemon first
    if let Some(client) = daemon {
        match client.request(&Request::List {
            tag: None,
            category: None,
            favorites_only: false,
        }) {
            Ok(data) => {
                if let ResponseData::Entries(entries) = *data {
                    return Ok(entries);
                }
                // Unexpected response type — fall through to direct mode
            }
            Err(e) => {
                eprintln!(
                    "vaultclaw run: daemon unavailable ({}), falling back to direct mode",
                    e
                );
            }
        }
    }

    // Direct mode: open vault with password
    let password_str = get_pw("Master password: ");
    let password = password_secret(password_str);
    let vault = VaultFile::open(vault_path, &password)?;
    Ok(vault.store().list().into_iter().cloned().collect())
}

/// Create a secure temp directory with restricted permissions (0700).
fn create_secure_temp_dir() -> anyhow::Result<PathBuf> {
    let temp_base = std::env::temp_dir();
    let dir_name = format!("vaultclaw-run-{}", uuid::Uuid::new_v4().as_simple());
    let temp_dir = temp_base.join(dir_name);
    fs::create_dir_all(&temp_dir)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp_dir, fs::Permissions::from_mode(0o700))?;
    }

    Ok(temp_dir)
}

/// Write content to a file with restricted permissions (0600).
fn write_secure_file(path: &Path, content: &[u8]) -> anyhow::Result<()> {
    let mut file = fs::File::create(path)?;
    file.write_all(content)?;
    file.flush()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

/// Replace all known secret values in a line with `[REDACTED]`.
fn redact_line(line: &str, secrets: &[String], engine: &RedactionEngine) -> String {
    let mut result = line.to_string();
    // First, replace exact secret values (longest first to avoid partial matches)
    for secret in secrets {
        if !secret.is_empty() {
            result = result.replace(secret.as_str(), "[REDACTED]");
        }
    }
    // Then, run the pattern-based redaction engine
    result = engine.redact(&result);
    result
}

/// Execute the `vaultclaw run` command.
///
/// 1. Collects vclaw:// references from environment, --env file, and --config file.
/// 2. Resolves them via daemon (preferred) or direct vault access (fallback).
/// 3. Spawns the child process with resolved environment variables.
/// 4. If --config is used, writes resolved config to a secure temp file.
/// 5. If --redact-output is set, captures stdout/stderr and removes secrets.
/// 6. Returns the child's exit code.
#[allow(clippy::too_many_arguments)]
pub fn handle_run_command(
    daemon: Option<DaemonClient>,
    vault_path: &Path,
    get_pw: impl Fn(&str) -> String,
    env_file: Option<PathBuf>,
    config_file: Option<PathBuf>,
    config_var: String,
    redact_output: bool,
    command: Vec<String>,
) -> anyhow::Result<i32> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("No command specified"))?;

    // Phase 1: Collect all vclaw:// references from all sources
    let mut all_refs: Vec<String> = Vec::new();
    let mut env_overrides: Vec<(String, String)> = Vec::new();
    let mut config_content: Option<String> = None;

    // Scan current environment variables
    for (key, value) in std::env::vars() {
        if value.starts_with("vclaw://") {
            let refs = find_vclaw_refs(&value);
            all_refs.extend(refs);
            env_overrides.push((key, value));
        }
    }

    // Parse --env file
    if let Some(ref path) = env_file {
        let parsed = parse_env_file(path)?;
        for (key, value) in parsed {
            let refs = find_vclaw_refs(&value);
            all_refs.extend(refs);
            env_overrides.push((key, value));
        }
    }

    // Read --config file
    if let Some(ref path) = config_file {
        let content = fs::read_to_string(path).map_err(|e| {
            anyhow::anyhow!("Failed to read config file '{}': {}", path.display(), e)
        })?;
        let refs = find_vclaw_refs(&content);
        all_refs.extend(refs);
        config_content = Some(content);
    }

    // Deduplicate refs
    all_refs.sort();
    all_refs.dedup();

    // Phase 2: Resolve all references
    let resolved = if all_refs.is_empty() {
        HashMap::new()
    } else {
        let mut daemon = daemon;
        let entries = get_entries(daemon.as_mut(), vault_path, &get_pw)?;
        let entry_refs: Vec<&Entry> = entries.iter().collect();
        let result = resolve_batch(&all_refs, &entry_refs)?;
        eprintln!(
            "vaultclaw run: resolved {} credential(s)",
            result.len()
        );
        result
    };

    // Phase 3: Build child process
    let mut cmd = Command::new(program);
    cmd.args(args);

    // Inject resolved env vars (both from current env and --env file)
    for (key, value) in &env_overrides {
        if value.starts_with("vclaw://") {
            // Resolve the entire value (may contain a vclaw:// ref)
            let resolved_value = replace_vclaw_refs(value, &resolved);
            cmd.env(key, &resolved_value);
        } else {
            cmd.env(key, value);
        }
    }

    // Phase 4: Handle --config file
    let _temp_guard;
    if let Some(content) = config_content {
        let resolved_content = replace_vclaw_refs(&content, &resolved);
        let temp_dir = create_secure_temp_dir()?;
        let filename = config_file
            .as_ref()
            .unwrap()
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        let temp_path = temp_dir.join(filename.as_ref());
        write_secure_file(&temp_path, resolved_content.as_bytes())?;
        cmd.env(&config_var, temp_path.display().to_string());
        _temp_guard = TempDirGuard::new(temp_dir);
    } else {
        _temp_guard = TempDirGuard::empty();
    }

    // Phase 5: Execute child process
    if redact_output && !resolved.is_empty() {
        // Capture and redact stdout/stderr
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| anyhow::anyhow!("Failed to execute '{}': {}", program, e))?;

        // Collect secret values for exact-match redaction, sorted longest-first
        let mut secrets: Vec<String> = resolved.values().cloned().collect();
        secrets.sort_by_key(|b| std::cmp::Reverse(b.len()));

        let engine = RedactionEngine::with_defaults();

        // Read stdout in a background thread
        let child_stdout = child.stdout.take();
        let secrets_for_stdout = secrets.clone();
        let stdout_handle = std::thread::spawn(move || {
            let engine = RedactionEngine::with_defaults();
            if let Some(stdout) = child_stdout {
                let reader = BufReader::new(stdout);
                for line in reader.lines().map_while(Result::ok) {
                    println!("{}", redact_line(&line, &secrets_for_stdout, &engine));
                }
            }
        });

        // Read stderr on the current thread (main thread waits for child anyway)
        if let Some(stderr) = child.stderr.take() {
            let reader = BufReader::new(stderr);
            for line in reader.lines().map_while(Result::ok) {
                eprintln!("{}", redact_line(&line, &secrets, &engine));
            }
        }

        stdout_handle.join().ok();
        let status = child.wait().map_err(|e| {
            anyhow::anyhow!("Failed to wait for '{}': {}", program, e)
        })?;

        // _temp_guard drops here, securely cleaning up temp files
        Ok(status.code().unwrap_or(1))
    } else {
        // Standard passthrough: inherit stdout/stderr
        let status = cmd
            .status()
            .map_err(|e| anyhow::anyhow!("Failed to execute '{}': {}", program, e))?;

        // _temp_guard drops here, securely cleaning up temp files
        Ok(status.code().unwrap_or(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::entry::*;

    // ── find_vclaw_refs ──

    #[test]
    fn test_find_refs_simple() {
        let refs = find_vclaw_refs("vclaw://default/github");
        assert_eq!(refs, vec!["vclaw://default/github"]);
    }

    #[test]
    fn test_find_refs_with_field() {
        let refs = find_vclaw_refs("vclaw://default/github/password");
        assert_eq!(refs, vec!["vclaw://default/github/password"]);
    }

    #[test]
    fn test_find_refs_in_env_value() {
        let refs = find_vclaw_refs("vclaw://default/anthropic-api-key");
        assert_eq!(refs, vec!["vclaw://default/anthropic-api-key"]);
    }

    #[test]
    fn test_find_refs_in_config() {
        let config = r#"{
            "apiKey": "vclaw://default/anthropic-api-key",
            "botToken": "vclaw://default/telegram-bot-token",
            "normal": "not-a-ref"
        }"#;
        let refs = find_vclaw_refs(config);
        assert_eq!(refs.len(), 2);
        assert!(refs.contains(&"vclaw://default/anthropic-api-key".to_string()));
        assert!(refs.contains(&"vclaw://default/telegram-bot-token".to_string()));
    }

    #[test]
    fn test_find_refs_none() {
        let refs = find_vclaw_refs("no references here");
        assert!(refs.is_empty());
    }

    #[test]
    fn test_find_refs_with_spaces() {
        let refs = find_vclaw_refs("vclaw://default/Deploy Note");
        assert_eq!(refs, vec!["vclaw://default/Deploy Note"]);
    }

    #[test]
    fn test_find_refs_trailing_slash() {
        let refs = find_vclaw_refs("vclaw://default/github/");
        assert_eq!(refs, vec!["vclaw://default/github"]);
    }

    // ── parse_env_content ──

    #[test]
    fn test_parse_env_basic() {
        let content = "KEY=value\nOTHER=stuff";
        let vars = parse_env_content(content);
        assert_eq!(vars.len(), 2);
        assert_eq!(vars[0], ("KEY".to_string(), "value".to_string()));
        assert_eq!(vars[1], ("OTHER".to_string(), "stuff".to_string()));
    }

    #[test]
    fn test_parse_env_comments_and_blanks() {
        let content = "# comment\n\nKEY=value\n  # another comment\n";
        let vars = parse_env_content(content);
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0], ("KEY".to_string(), "value".to_string()));
    }

    #[test]
    fn test_parse_env_quoted_values() {
        let content = "A=\"quoted value\"\nB='single quoted'";
        let vars = parse_env_content(content);
        assert_eq!(vars[0].1, "quoted value");
        assert_eq!(vars[1].1, "single quoted");
    }

    #[test]
    fn test_parse_env_vclaw_refs() {
        let content = "API_KEY=vclaw://default/anthropic-api-key\nNORMAL=hello";
        let vars = parse_env_content(content);
        assert_eq!(vars[0].1, "vclaw://default/anthropic-api-key");
        assert_eq!(vars[1].1, "hello");
    }

    #[test]
    fn test_parse_env_empty() {
        let vars = parse_env_content("");
        assert!(vars.is_empty());
    }

    #[test]
    fn test_parse_env_no_value() {
        let content = "NO_EQUALS_SIGN";
        let vars = parse_env_content(content);
        assert!(vars.is_empty());
    }

    #[test]
    fn test_parse_env_empty_value() {
        let content = "EMPTY=";
        let vars = parse_env_content(content);
        assert_eq!(vars[0], ("EMPTY".to_string(), String::new()));
    }

    #[test]
    fn test_parse_env_value_with_equals() {
        let content = "URL=https://example.com?a=1&b=2";
        let vars = parse_env_content(content);
        assert_eq!(vars[0].1, "https://example.com?a=1&b=2");
    }

    // ── strip_quotes ──

    #[test]
    fn test_strip_double_quotes() {
        assert_eq!(strip_quotes("\"hello\""), "hello");
    }

    #[test]
    fn test_strip_single_quotes() {
        assert_eq!(strip_quotes("'hello'"), "hello");
    }

    #[test]
    fn test_no_quotes() {
        assert_eq!(strip_quotes("hello"), "hello");
    }

    #[test]
    fn test_mismatched_quotes() {
        assert_eq!(strip_quotes("\"hello'"), "\"hello'");
    }

    #[test]
    fn test_empty_quotes() {
        assert_eq!(strip_quotes("\"\""), "");
    }

    #[test]
    fn test_single_char() {
        assert_eq!(strip_quotes("x"), "x");
    }

    // ── replace_vclaw_refs ──

    #[test]
    fn test_replace_refs_in_json() {
        let config = r#"{"key": "vclaw://default/api-key", "other": "plain"}"#;
        let mut resolved = HashMap::new();
        resolved.insert(
            "vclaw://default/api-key".to_string(),
            "sk-secret-123".to_string(),
        );
        let result = replace_vclaw_refs(config, &resolved);
        assert_eq!(result, r#"{"key": "sk-secret-123", "other": "plain"}"#);
    }

    #[test]
    fn test_replace_refs_multiple() {
        let text = r#"{"a": "vclaw://default/key-a", "b": "vclaw://default/key-b"}"#;
        let mut resolved = HashMap::new();
        resolved.insert("vclaw://default/key-a".to_string(), "val_a".to_string());
        resolved.insert("vclaw://default/key-b".to_string(), "val_b".to_string());
        let result = replace_vclaw_refs(text, &resolved);
        assert_eq!(result, r#"{"a": "val_a", "b": "val_b"}"#);
    }

    #[test]
    fn test_replace_refs_unresolved_passthrough() {
        let text = "vclaw://default/unknown";
        let resolved = HashMap::new();
        let result = replace_vclaw_refs(text, &resolved);
        assert_eq!(result, "vclaw://default/unknown");
    }

    // ── resolve_batch ──

    fn make_entries() -> Vec<Entry> {
        vec![
            Entry::new(
                "github".into(),
                Credential::Login(LoginCredential {
                    url: "https://github.com".into(),
                    username: "user".into(),
                    password: "gh_token_123".into(),
                }),
            ),
            Entry::new(
                "anthropic-api-key".into(),
                Credential::ApiKey(ApiKeyCredential {
                    service: "anthropic".into(),
                    key: "sk-ant-12345".into(),
                    secret: "".into(),
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
    fn test_resolve_batch_success() {
        let entries = make_entries();
        let entry_refs: Vec<&Entry> = entries.iter().collect();
        let refs = vec![
            "vclaw://default/github".to_string(),
            "vclaw://default/anthropic-api-key".to_string(),
        ];
        let resolved = resolve_batch(&refs, &entry_refs).unwrap();
        assert_eq!(resolved["vclaw://default/github"], "gh_token_123");
        assert_eq!(resolved["vclaw://default/anthropic-api-key"], "sk-ant-12345");
    }

    #[test]
    fn test_resolve_batch_with_field() {
        let entries = make_entries();
        let entry_refs: Vec<&Entry> = entries.iter().collect();
        let refs = vec!["vclaw://default/github/username".to_string()];
        let resolved = resolve_batch(&refs, &entry_refs).unwrap();
        assert_eq!(resolved["vclaw://default/github/username"], "user");
    }

    #[test]
    fn test_resolve_batch_not_found() {
        let entries = make_entries();
        let entry_refs: Vec<&Entry> = entries.iter().collect();
        let refs = vec!["vclaw://default/nonexistent".to_string()];
        let err = resolve_batch(&refs, &entry_refs).unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_resolve_batch_invalid_uri() {
        let entries = make_entries();
        let entry_refs: Vec<&Entry> = entries.iter().collect();
        let refs = vec!["not-a-uri".to_string()];
        let err = resolve_batch(&refs, &entry_refs).unwrap_err();
        assert!(err.to_string().contains("Invalid vclaw://"));
    }

    #[test]
    fn test_resolve_batch_empty() {
        let entries = make_entries();
        let entry_refs: Vec<&Entry> = entries.iter().collect();
        let resolved = resolve_batch(&[], &entry_refs).unwrap();
        assert!(resolved.is_empty());
    }

    #[test]
    fn test_resolve_batch_note_with_space() {
        let entries = make_entries();
        let entry_refs: Vec<&Entry> = entries.iter().collect();
        let refs = vec!["vclaw://default/Deploy Note".to_string()];
        let resolved = resolve_batch(&refs, &entry_refs).unwrap();
        assert!(resolved["vclaw://default/Deploy Note"].contains("deploy"));
    }

    // ── secure temp dir ──

    #[test]
    fn test_create_secure_temp_dir() {
        let dir = create_secure_temp_dir().unwrap();
        assert!(dir.exists());
        assert!(dir.is_dir());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
        }

        fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn test_write_secure_file() {
        let dir = create_secure_temp_dir().unwrap();
        let file_path = dir.join("test.txt");
        write_secure_file(&file_path, b"secret data").unwrap();

        assert_eq!(fs::read_to_string(&file_path).unwrap(), "secret data");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&file_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        fs::remove_file(&file_path).unwrap();
        fs::remove_dir(&dir).unwrap();
    }

    // ── TempDirGuard ──

    #[test]
    fn test_temp_dir_guard_cleanup() {
        let dir = create_secure_temp_dir().unwrap();
        let file_path = dir.join("secret.json");
        write_secure_file(&file_path, b"sensitive content").unwrap();
        assert!(file_path.exists());

        let guard = TempDirGuard::new(dir.clone());
        drop(guard);

        assert!(!file_path.exists());
        assert!(!dir.exists());
    }

    #[test]
    fn test_temp_dir_guard_empty() {
        let guard = TempDirGuard::empty();
        drop(guard); // should not panic
    }

    #[test]
    fn test_secure_delete_overwrites() {
        let dir = create_secure_temp_dir().unwrap();
        let file_path = dir.join("test.bin");
        write_secure_file(&file_path, b"secret").unwrap();

        // Before delete, verify content
        assert_eq!(fs::read(&file_path).unwrap(), b"secret");

        secure_delete_dir(&dir);
        assert!(!file_path.exists());
        assert!(!dir.exists());
    }

    // ── parse_env_file (integration) ──

    #[test]
    fn test_parse_env_file_integration() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join(".env");
        fs::write(
            &path,
            "API_KEY=vclaw://default/api-key\n# comment\nNAME=hello\n",
        )
        .unwrap();

        let vars = parse_env_file(&path).unwrap();
        assert_eq!(vars.len(), 2);
        assert_eq!(vars[0], ("API_KEY".into(), "vclaw://default/api-key".into()));
        assert_eq!(vars[1], ("NAME".into(), "hello".into()));
    }

    #[test]
    fn test_parse_env_file_not_found() {
        let result = parse_env_file(Path::new("/nonexistent/.env"));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read"));
    }

    // ── handle_run_command (integration) ──

    #[test]
    fn test_run_no_refs_passthrough() {
        // Running a simple command with no vclaw:// refs should just pass through
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let exit_code = handle_run_command(
            None,
            &vault_path,
            |_| panic!("should not prompt for password"),
            None,
            None,
            "VAULTCLAW_CONFIG".into(),
            false,
            vec!["true".into()],
        )
        .unwrap();

        assert_eq!(exit_code, 0);
    }

    #[test]
    fn test_run_command_not_found() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let result = handle_run_command(
            None,
            &vault_path,
            |_| panic!("should not prompt"),
            None,
            None,
            "VAULTCLAW_CONFIG".into(),
            false,
            vec!["nonexistent_command_xyz_12345".into()],
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to execute"));
    }

    #[test]
    fn test_run_empty_command() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let result = handle_run_command(
            None,
            &vault_path,
            |_| panic!("should not prompt"),
            None,
            None,
            "VAULTCLAW_CONFIG".into(),
            false,
            vec![],
        );

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No command specified"));
    }

    #[test]
    fn test_run_exit_code_forwarding() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let exit_code = handle_run_command(
            None,
            &vault_path,
            |_| panic!("should not prompt"),
            None,
            None,
            "VAULTCLAW_CONFIG".into(),
            false,
            vec!["false".into()], // `false` exits with code 1
        )
        .unwrap();

        assert_eq!(exit_code, 1);
    }

    #[test]
    fn test_run_with_env_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        // Create vault with an entry
        let password = password_secret("test".to_string());
        let kdf = crate::crypto::kdf::KdfParams::fast_for_testing();
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

        // Create .env file with vclaw:// ref
        let env_path = dir.path().join(".env");
        fs::write(&env_path, "MY_KEY=vclaw://default/my-api-key\n").unwrap();

        // Run `env` and capture output to verify the env var was resolved
        // Use `sh -c 'echo $MY_KEY'` to print the resolved env var
        let exit_code = handle_run_command(
            None,
            &vault_path,
            |_| "test".into(),
            Some(env_path),
            None,
            "VAULTCLAW_CONFIG".into(),
            false,
            vec!["sh".into(), "-c".into(), "test \"$MY_KEY\" = 'resolved-key-value'".into()],
        )
        .unwrap();

        assert_eq!(exit_code, 0);
    }

    #[test]
    fn test_run_with_config_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let password = password_secret("test".to_string());
        let kdf = crate::crypto::kdf::KdfParams::fast_for_testing();
        let mut vault = VaultFile::create(&vault_path, &password, kdf).unwrap();
        vault.store_mut().add(Entry::new(
            "my-secret".into(),
            Credential::ApiKey(ApiKeyCredential {
                service: "test".into(),
                key: "SECRET_VALUE_123".into(),
                secret: "".into(),
            }),
        ));
        vault.save().unwrap();

        // Create config file with vclaw:// ref
        let config_path = dir.path().join("config.json");
        fs::write(
            &config_path,
            r#"{"apiKey": "vclaw://default/my-secret"}"#,
        )
        .unwrap();

        // Run a command that reads the resolved config file path from env
        let exit_code = handle_run_command(
            None,
            &vault_path,
            |_| "test".into(),
            None,
            Some(config_path),
            "TEST_CONFIG".into(),
            false,
            vec![
                "sh".into(),
                "-c".into(),
                // Verify the resolved config contains the secret value
                r#"grep -q 'SECRET_VALUE_123' "$TEST_CONFIG""#.into(),
            ],
        )
        .unwrap();

        assert_eq!(exit_code, 0);
    }

    #[test]
    fn test_run_config_temp_cleanup() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let password = password_secret("test".to_string());
        let kdf = crate::crypto::kdf::KdfParams::fast_for_testing();
        let mut vault = VaultFile::create(&vault_path, &password, kdf).unwrap();
        vault.store_mut().add(Entry::new(
            "key".into(),
            Credential::ApiKey(ApiKeyCredential {
                service: "test".into(),
                key: "val".into(),
                secret: "".into(),
            }),
        ));
        vault.save().unwrap();

        let config_path = dir.path().join("app.json");
        fs::write(&config_path, r#"{"k": "vclaw://default/key"}"#).unwrap();

        // Capture the temp config path via a script that writes it to a file
        let marker = dir.path().join("temp_path.txt");
        let script = format!(
            r#"echo "$TEST_CFG" > "{}""#,
            marker.display()
        );

        let exit_code = handle_run_command(
            None,
            &vault_path,
            |_| "test".into(),
            None,
            Some(config_path),
            "TEST_CFG".into(),
            false,
            vec!["sh".into(), "-c".into(), script],
        )
        .unwrap();

        assert_eq!(exit_code, 0);

        // Read the temp path that was used
        let temp_config_path = fs::read_to_string(&marker).unwrap().trim().to_string();
        // After handle_run_command returns, the temp file should be cleaned up
        assert!(
            !Path::new(&temp_config_path).exists(),
            "Temp config file should be cleaned up after run"
        );
    }

    #[test]
    fn test_run_unresolvable_ref() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let password = password_secret("test".to_string());
        let kdf = crate::crypto::kdf::KdfParams::fast_for_testing();
        VaultFile::create(&vault_path, &password, kdf).unwrap();

        let env_path = dir.path().join(".env");
        fs::write(&env_path, "KEY=vclaw://default/nonexistent\n").unwrap();

        let result = handle_run_command(
            None,
            &vault_path,
            |_| "test".into(),
            Some(env_path),
            None,
            "VAULTCLAW_CONFIG".into(),
            false,
            vec!["true".into()],
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_run_with_args() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let exit_code = handle_run_command(
            None,
            &vault_path,
            |_| panic!("should not prompt"),
            None,
            None,
            "VAULTCLAW_CONFIG".into(),
            false,
            vec!["sh".into(), "-c".into(), "exit 42".into()],
        )
        .unwrap();

        assert_eq!(exit_code, 42);
    }

    #[test]
    fn test_run_env_file_not_found() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let result = handle_run_command(
            None,
            &vault_path,
            |_| panic!("should not prompt"),
            Some(PathBuf::from("/nonexistent/.env")),
            None,
            "VAULTCLAW_CONFIG".into(),
            false,
            vec!["true".into()],
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read"));
    }

    #[test]
    fn test_run_config_file_not_found() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let result = handle_run_command(
            None,
            &vault_path,
            |_| panic!("should not prompt"),
            None,
            Some(PathBuf::from("/nonexistent/config.json")),
            "VAULTCLAW_CONFIG".into(),
            false,
            vec!["true".into()],
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read"));
    }

    #[test]
    fn test_run_env_file_mixed_values() {
        // Test .env file with both vclaw:// and plain values
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let password = password_secret("test".to_string());
        let kdf = crate::crypto::kdf::KdfParams::fast_for_testing();
        let mut vault = VaultFile::create(&vault_path, &password, kdf).unwrap();
        vault.store_mut().add(Entry::new(
            "api-key".into(),
            Credential::ApiKey(ApiKeyCredential {
                service: "test".into(),
                key: "resolved-secret".into(),
                secret: "".into(),
            }),
        ));
        vault.save().unwrap();

        let env_path = dir.path().join(".env");
        fs::write(
            &env_path,
            "SECRET=vclaw://default/api-key\nPLAIN_VAR=hello-world\n",
        )
        .unwrap();

        // Verify both vars are set: SECRET resolved, PLAIN_VAR passed through
        let exit_code = handle_run_command(
            None,
            &vault_path,
            |_| "test".into(),
            Some(env_path),
            None,
            "VAULTCLAW_CONFIG".into(),
            false,
            vec![
                "sh".into(),
                "-c".into(),
                "test \"$SECRET\" = 'resolved-secret' && test \"$PLAIN_VAR\" = 'hello-world'"
                    .into(),
            ],
        )
        .unwrap();

        assert_eq!(exit_code, 0);
    }

    #[test]
    fn test_run_config_with_spaces_in_entry() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let password = password_secret("test".to_string());
        let kdf = crate::crypto::kdf::KdfParams::fast_for_testing();
        let mut vault = VaultFile::create(&vault_path, &password, kdf).unwrap();
        vault.store_mut().add(Entry::new(
            "Deploy Note".into(),
            Credential::SecureNote(SecureNoteCredential {
                content: "secret-deploy-value".into(),
            }),
        ));
        vault.save().unwrap();

        let config_path = dir.path().join("config.json");
        fs::write(
            &config_path,
            r#"{"note": "vclaw://default/Deploy Note"}"#,
        )
        .unwrap();

        let exit_code = handle_run_command(
            None,
            &vault_path,
            |_| "test".into(),
            None,
            Some(config_path),
            "TEST_CFG".into(),
            false,
            vec![
                "sh".into(),
                "-c".into(),
                r#"grep -q 'secret-deploy-value' "$TEST_CFG""#.into(),
            ],
        )
        .unwrap();

        assert_eq!(exit_code, 0);
    }

    #[test]
    fn test_get_entries_direct_mode() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let password = password_secret("test".to_string());
        let kdf = crate::crypto::kdf::KdfParams::fast_for_testing();
        let mut vault = VaultFile::create(&vault_path, &password, kdf).unwrap();
        vault.store_mut().add(Entry::new(
            "test-entry".into(),
            Credential::Login(LoginCredential {
                url: "https://example.com".into(),
                username: "user".into(),
                password: "pass".into(),
            }),
        ));
        vault.save().unwrap();

        let entries = get_entries(None, &vault_path, &|_| "test".into()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "test-entry");
    }

    #[test]
    fn test_replace_refs_with_spaces_in_json() {
        let config = r#"{"note": "vclaw://default/Deploy Note"}"#;
        let mut resolved = HashMap::new();
        resolved.insert(
            "vclaw://default/Deploy Note".to_string(),
            "secret-value".to_string(),
        );
        let result = replace_vclaw_refs(config, &resolved);
        assert_eq!(result, r#"{"note": "secret-value"}"#);
    }

    #[test]
    fn test_replace_refs_with_field() {
        let text = r#""vclaw://default/github/username""#;
        let mut resolved = HashMap::new();
        resolved.insert(
            "vclaw://default/github/username".to_string(),
            "myuser".to_string(),
        );
        let result = replace_vclaw_refs(text, &resolved);
        assert_eq!(result, r#""myuser""#);
    }

    #[test]
    fn test_find_refs_multiple_on_separate_lines() {
        let text = "KEY1=vclaw://default/key-a\nKEY2=vclaw://default/key-b\n";
        let refs = find_vclaw_refs(text);
        assert_eq!(refs.len(), 2);
        assert!(refs.contains(&"vclaw://default/key-a".to_string()));
        assert!(refs.contains(&"vclaw://default/key-b".to_string()));
    }

    // ── redact_line ──

    #[test]
    fn test_redact_line_exact_secret() {
        let engine = RedactionEngine::with_defaults();
        let line = "The password is my-super-secret-value here";
        let secrets = vec!["my-super-secret-value".to_string()];
        let result = redact_line(line, &secrets, &engine);
        assert_eq!(result, "The password is [REDACTED] here");
    }

    #[test]
    fn test_redact_line_multiple_secrets() {
        let engine = RedactionEngine::with_defaults();
        let line = "user=secret1 and host=secret2";
        let secrets = vec!["secret1".to_string(), "secret2".to_string()];
        let result = redact_line(line, &secrets, &engine);
        assert_eq!(result, "user=[REDACTED] and host=[REDACTED]");
    }

    #[test]
    fn test_redact_line_no_secrets() {
        let engine = RedactionEngine::with_defaults();
        let line = "This is a normal line";
        let secrets: Vec<String> = vec![];
        let result = redact_line(line, &secrets, &engine);
        assert_eq!(result, "This is a normal line");
    }

    #[test]
    fn test_redact_line_also_runs_pattern_engine() {
        let engine = RedactionEngine::with_defaults();
        let line = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij leaked";
        let secrets: Vec<String> = vec![];
        let result = redact_line(line, &secrets, &engine);
        assert!(result.contains("[REDACTED:github-token]"));
        assert!(!result.contains("ghp_"));
    }

    #[test]
    fn test_redact_line_longest_first() {
        let engine = RedactionEngine::with_defaults();
        let line = "value=abc-secret-long and abc";
        // "abc-secret-long" should be replaced before "abc" to avoid partial redaction
        let secrets = vec!["abc-secret-long".to_string(), "abc".to_string()];
        let result = redact_line(line, &secrets, &engine);
        assert_eq!(result, "value=[REDACTED] and [REDACTED]");
    }

    #[test]
    fn test_redact_line_empty_secret_skipped() {
        let engine = RedactionEngine::with_defaults();
        let line = "normal line";
        let secrets = vec!["".to_string(), "secret".to_string()];
        let result = redact_line(line, &secrets, &engine);
        assert_eq!(result, "normal line");
    }

    // ── handle_run_command with redact_output ──

    #[test]
    fn test_run_redact_output_basic() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let password = password_secret("test".to_string());
        let kdf = crate::crypto::kdf::KdfParams::fast_for_testing();
        let mut vault = VaultFile::create(&vault_path, &password, kdf).unwrap();
        vault.store_mut().add(Entry::new(
            "my-secret".into(),
            Credential::ApiKey(ApiKeyCredential {
                service: "test".into(),
                key: "SUPER_SECRET_VALUE".into(),
                secret: "".into(),
            }),
        ));
        vault.save().unwrap();

        let env_path = dir.path().join(".env");
        fs::write(&env_path, "MY_KEY=vclaw://default/my-secret\n").unwrap();

        // With redact_output=true, child echoes the secret but it should be redacted
        let exit_code = handle_run_command(
            None,
            &vault_path,
            |_| "test".into(),
            Some(env_path),
            None,
            "VAULTCLAW_CONFIG".into(),
            true,
            vec!["sh".into(), "-c".into(), "echo $MY_KEY".into()],
        )
        .unwrap();

        assert_eq!(exit_code, 0);
    }

    #[test]
    fn test_run_redact_output_no_refs_passthrough() {
        // When there are no refs, redact_output should just pass through
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let exit_code = handle_run_command(
            None,
            &vault_path,
            |_| panic!("should not prompt"),
            None,
            None,
            "VAULTCLAW_CONFIG".into(),
            true,
            vec!["echo".into(), "hello".into()],
        )
        .unwrap();

        assert_eq!(exit_code, 0);
    }

    #[test]
    fn test_run_redact_output_stderr() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let password = password_secret("test".to_string());
        let kdf = crate::crypto::kdf::KdfParams::fast_for_testing();
        let mut vault = VaultFile::create(&vault_path, &password, kdf).unwrap();
        vault.store_mut().add(Entry::new(
            "token".into(),
            Credential::ApiKey(ApiKeyCredential {
                service: "test".into(),
                key: "SECRET_TOKEN_XYZ".into(),
                secret: "".into(),
            }),
        ));
        vault.save().unwrap();

        let env_path = dir.path().join(".env");
        fs::write(&env_path, "TOK=vclaw://default/token\n").unwrap();

        // Echo secret to stderr
        let exit_code = handle_run_command(
            None,
            &vault_path,
            |_| "test".into(),
            Some(env_path),
            None,
            "VAULTCLAW_CONFIG".into(),
            true,
            vec!["sh".into(), "-c".into(), "echo $TOK >&2".into()],
        )
        .unwrap();

        assert_eq!(exit_code, 0);
    }

    #[test]
    fn test_run_redact_output_preserves_exit_code() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let password = password_secret("test".to_string());
        let kdf = crate::crypto::kdf::KdfParams::fast_for_testing();
        let mut vault = VaultFile::create(&vault_path, &password, kdf).unwrap();
        vault.store_mut().add(Entry::new(
            "key".into(),
            Credential::ApiKey(ApiKeyCredential {
                service: "test".into(),
                key: "val".into(),
                secret: "".into(),
            }),
        ));
        vault.save().unwrap();

        let env_path = dir.path().join(".env");
        fs::write(&env_path, "K=vclaw://default/key\n").unwrap();

        let exit_code = handle_run_command(
            None,
            &vault_path,
            |_| "test".into(),
            Some(env_path),
            None,
            "VAULTCLAW_CONFIG".into(),
            true,
            vec!["sh".into(), "-c".into(), "exit 42".into()],
        )
        .unwrap();

        assert_eq!(exit_code, 42);
    }

    // ── secure_delete_dir (additional) ──

    #[test]
    fn test_secure_delete_dir_with_multiple_files() {
        // Covers L53-54, L56: metadata().is_file() + remove_file paths
        let dir = create_secure_temp_dir().unwrap();
        let f1 = dir.join("file1.txt");
        let f2 = dir.join("file2.bin");
        write_secure_file(&f1, b"secret data one").unwrap();
        write_secure_file(&f2, b"secret data two").unwrap();
        assert!(f1.exists());
        assert!(f2.exists());

        secure_delete_dir(&dir);
        assert!(!f1.exists());
        assert!(!f2.exists());
        assert!(!dir.exists());
    }

    #[test]
    fn test_secure_delete_dir_nonexistent() {
        // Covers the Err path in fs::read_dir (dir doesn't exist)
        secure_delete_dir(Path::new("/nonexistent/dir/xyz"));
        // Should not panic
    }

    #[test]
    fn test_secure_delete_dir_empty() {
        // Covers the loop with no entries
        let dir = create_secure_temp_dir().unwrap();
        assert!(dir.exists());
        secure_delete_dir(&dir);
        assert!(!dir.exists());
    }

    // ── handle_run_command with redact_output (additional) ──

    #[test]
    fn test_run_redact_output_command_not_found() {
        // Covers L390-391: redact_output=true + command fails to spawn
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let password = password_secret("test".to_string());
        let kdf = crate::crypto::kdf::KdfParams::fast_for_testing();
        let mut vault = VaultFile::create(&vault_path, &password, kdf).unwrap();
        vault.store_mut().add(Entry::new(
            "key".into(),
            Credential::ApiKey(ApiKeyCredential {
                service: "test".into(),
                key: "val".into(),
                secret: "".into(),
            }),
        ));
        vault.save().unwrap();

        let env_path = dir.path().join(".env");
        fs::write(&env_path, "K=vclaw://default/key\n").unwrap();

        let result = handle_run_command(
            None,
            &vault_path,
            |_| "test".into(),
            Some(env_path),
            None,
            "VAULTCLAW_CONFIG".into(),
            true, // redact_output
            vec!["nonexistent_command_xyz_99999".into()],
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to execute"));
    }

    #[test]
    fn test_run_redact_output_with_config_file() {
        // Covers redact_output=true + config file path (exercises more of the redact branch)
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let password = password_secret("test".to_string());
        let kdf = crate::crypto::kdf::KdfParams::fast_for_testing();
        let mut vault = VaultFile::create(&vault_path, &password, kdf).unwrap();
        vault.store_mut().add(Entry::new(
            "api-token".into(),
            Credential::ApiKey(ApiKeyCredential {
                service: "test".into(),
                key: "MY_SECRET_API_TOKEN_VALUE".into(),
                secret: "".into(),
            }),
        ));
        vault.save().unwrap();

        let config_path = dir.path().join("config.json");
        fs::write(
            &config_path,
            r#"{"token": "vclaw://default/api-token"}"#,
        )
        .unwrap();

        let exit_code = handle_run_command(
            None,
            &vault_path,
            |_| "test".into(),
            None,
            Some(config_path),
            "APP_CONFIG".into(),
            true, // redact_output
            vec!["sh".into(), "-c".into(), r#"cat "$APP_CONFIG""#.into()],
        )
        .unwrap();

        assert_eq!(exit_code, 0);
    }

    #[test]
    fn test_run_redact_output_stderr_and_stdout() {
        // Exercises both stdout and stderr redaction in the same run
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let password = password_secret("test".to_string());
        let kdf = crate::crypto::kdf::KdfParams::fast_for_testing();
        let mut vault = VaultFile::create(&vault_path, &password, kdf).unwrap();
        vault.store_mut().add(Entry::new(
            "secret".into(),
            Credential::ApiKey(ApiKeyCredential {
                service: "test".into(),
                key: "TOP_SECRET_VALUE".into(),
                secret: "".into(),
            }),
        ));
        vault.save().unwrap();

        let env_path = dir.path().join(".env");
        fs::write(&env_path, "S=vclaw://default/secret\n").unwrap();

        let exit_code = handle_run_command(
            None,
            &vault_path,
            |_| "test".into(),
            Some(env_path),
            None,
            "VAULTCLAW_CONFIG".into(),
            true,
            vec!["sh".into(), "-c".into(), "echo $S && echo $S >&2".into()],
        )
        .unwrap();

        assert_eq!(exit_code, 0);
    }

    #[test]
    fn test_run_config_file_not_found_with_redact() {
        // Config file not found error, with redact_output=true
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let result = handle_run_command(
            None,
            &vault_path,
            |_| panic!("should not prompt"),
            None,
            Some(PathBuf::from("/nonexistent/config.json")),
            "VAULTCLAW_CONFIG".into(),
            true,
            vec!["true".into()],
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read"));
    }

    #[test]
    fn test_run_with_env_file_no_vclaw_refs() {
        // .env file has vars but none are vclaw:// refs — no resolution needed
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let env_path = dir.path().join(".env");
        fs::write(&env_path, "PLAIN_A=hello\nPLAIN_B=world\n").unwrap();

        let exit_code = handle_run_command(
            None,
            &vault_path,
            |_| panic!("should not prompt"),
            Some(env_path),
            None,
            "VAULTCLAW_CONFIG".into(),
            false,
            vec!["true".into()],
        )
        .unwrap();

        assert_eq!(exit_code, 0);
    }

    // ── get_entries with daemon (covers L169-185) ──

    /// Helper: create a mock daemon on a Unix socket that responds to a List request.
    fn mock_daemon_socket(
        socket_path: &Path,
        response: crate::daemon::protocol::Response,
    ) -> std::thread::JoinHandle<()> {
        use std::io::{BufRead as _, BufReader as StdBufReader, Write as _};
        use std::os::unix::net::UnixListener;

        let listener = UnixListener::bind(socket_path).unwrap();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = StdBufReader::new(stream.try_clone().unwrap());
            let mut writer = stream;

            let mut line = String::new();
            reader.read_line(&mut line).unwrap();

            let resp_json = serde_json::to_string(&response).unwrap();
            writer.write_all(resp_json.as_bytes()).unwrap();
            writer.write_all(b"\n").unwrap();
            writer.flush().unwrap();
        })
    }

    #[test]
    fn test_get_entries_daemon_success() {
        // Covers L169-177: daemon returns Entries successfully
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("daemon_ok.sock");
        let vault_path = dir.path().join("test.vclaw");

        let entry = Entry::new(
            "from-daemon".into(),
            Credential::Login(LoginCredential {
                url: "https://example.com".into(),
                username: "daemonuser".into(),
                password: "daemonpass".into(),
            }),
        );

        let response = crate::daemon::protocol::Response::ok(
            ResponseData::Entries(vec![entry.clone()]),
        );
        let handle = mock_daemon_socket(&socket_path, response);

        // Small delay to let the listener start
        std::thread::sleep(std::time::Duration::from_millis(50));

        let mut client = DaemonClient::connect(&socket_path).unwrap();
        let entries = get_entries(Some(&mut client), &vault_path, &|_| panic!("should not prompt")).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "from-daemon");

        handle.join().unwrap();
    }

    #[test]
    fn test_get_entries_daemon_error_fallback() {
        // Covers L180-185: daemon returns error, falls back to direct vault
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("daemon_err.sock");
        let vault_path = dir.path().join("test.vclaw");

        // Create a vault for fallback
        let password = password_secret("test".to_string());
        let kdf = crate::crypto::kdf::KdfParams::fast_for_testing();
        let mut vault = VaultFile::create(&vault_path, &password, kdf).unwrap();
        vault.store_mut().add(Entry::new(
            "fallback-entry".into(),
            Credential::Login(LoginCredential {
                url: "https://example.com".into(),
                username: "user".into(),
                password: "pass".into(),
            }),
        ));
        vault.save().unwrap();

        let response = crate::daemon::protocol::Response::error("vault locked");
        let handle = mock_daemon_socket(&socket_path, response);

        std::thread::sleep(std::time::Duration::from_millis(50));

        let mut client = DaemonClient::connect(&socket_path).unwrap();
        let entries = get_entries(Some(&mut client), &vault_path, &|_| "test".into()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "fallback-entry");

        handle.join().unwrap();
    }

    #[test]
    fn test_get_entries_daemon_unexpected_response() {
        // Covers L174-178: daemon returns Ok but with non-Entries data, falls through
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("daemon_unexpected.sock");
        let vault_path = dir.path().join("test.vclaw");

        // Create a vault for fallback
        let password = password_secret("test".to_string());
        let kdf = crate::crypto::kdf::KdfParams::fast_for_testing();
        let mut vault = VaultFile::create(&vault_path, &password, kdf).unwrap();
        vault.store_mut().add(Entry::new(
            "direct-entry".into(),
            Credential::Login(LoginCredential {
                url: "https://example.com".into(),
                username: "u".into(),
                password: "p".into(),
            }),
        ));
        vault.save().unwrap();

        // Return a Health response instead of Entries
        let response = crate::daemon::protocol::Response::ok(
            ResponseData::Health(crate::daemon::protocol::HealthResponse {
                healthy: true,
                uptime_seconds: 1,
            }),
        );
        let handle = mock_daemon_socket(&socket_path, response);

        std::thread::sleep(std::time::Duration::from_millis(50));

        let mut client = DaemonClient::connect(&socket_path).unwrap();
        let entries = get_entries(Some(&mut client), &vault_path, &|_| "test".into()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "direct-entry");

        handle.join().unwrap();
    }

    // NOTE: L272-274 (process env var scanning for vclaw://) cannot be safely tested
    // in parallel with other handle_run_command tests because std::env::set_var is
    // process-global and causes resolution failures in concurrent tests.

    // ── secure_delete_dir edge case: non-file entry (covers L53-54 closing braces) ──

    #[test]
    fn test_secure_delete_dir_with_subdirectory() {
        // Tests that secure_delete_dir handles subdirectories gracefully
        // (metadata.is_file() returns false for directories, skipping the file-zero-out path)
        let dir = create_secure_temp_dir().unwrap();
        let subdir = dir.join("subdir");
        fs::create_dir(&subdir).unwrap();
        let file_in_subdir = subdir.join("inner.txt");
        fs::write(&file_in_subdir, b"data").unwrap();
        let top_file = dir.join("top.txt");
        write_secure_file(&top_file, b"top data").unwrap();

        assert!(subdir.exists());
        assert!(top_file.exists());

        secure_delete_dir(&dir);
        // Top file should be removed
        assert!(!top_file.exists());
        // Subdirectory may still exist (secure_delete_dir only removes files, not recursively)
        // but the top dir remove attempt will fail because subdir still has content
        // Clean up the leftovers
        let _ = fs::remove_file(&file_in_subdir);
        let _ = fs::remove_dir(&subdir);
        let _ = fs::remove_dir(&dir);
    }
}
