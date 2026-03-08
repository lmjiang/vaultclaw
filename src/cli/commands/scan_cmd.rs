use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde::Serialize;

// ---- Secret pattern definitions ----

/// A named pattern for detecting secrets.
#[derive(Debug, Clone)]
pub struct SecretPattern {
    pub name: &'static str,
    pub regex: Regex,
}

/// Build the list of built-in secret detection patterns.
pub fn builtin_patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "Anthropic API Key",
            regex: Regex::new(r"sk-ant-[a-zA-Z0-9\-_]{20,}").unwrap(),
        },
        SecretPattern {
            name: "OpenAI API Key",
            regex: Regex::new(r"sk-[a-zA-Z0-9]{20,}").unwrap(),
        },
        SecretPattern {
            name: "Google API Key",
            regex: Regex::new(r"AIzaSy[a-zA-Z0-9\-_]{33}").unwrap(),
        },
        SecretPattern {
            name: "Telegram Bot Token",
            regex: Regex::new(r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}").unwrap(),
        },
        SecretPattern {
            name: "GitHub PAT",
            regex: Regex::new(r"ghp_[a-zA-Z0-9]{36}").unwrap(),
        },
        SecretPattern {
            name: "AWS Access Key",
            regex: Regex::new(r"AKIA[A-Z0-9]{16}").unwrap(),
        },
        SecretPattern {
            name: "GitHub Fine-grained PAT",
            regex: Regex::new(r"github_pat_[a-zA-Z0-9_]{82}").unwrap(),
        },
        SecretPattern {
            name: "Slack Token",
            regex: Regex::new(r"xox[bpras]-[a-zA-Z0-9\-]{10,}").unwrap(),
        },
    ]
}

/// File extensions to scan.
const SCAN_EXTENSIONS: &[&str] = &[
    "json", "yaml", "yml", "toml", "env", "sh", "bash", "zsh", "config", "cfg", "ini",
];

/// Directory names to skip.
const SKIP_DIRS: &[&str] = &[".git", "node_modules", "target", ".venv", "__pycache__", "dist"];

// ---- Finding representation ----

/// A detected secret finding.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub file: String,
    pub line: usize,
    pub secret_type: String,
    pub masked: String,
    pub raw_value: String,
}

/// Mask a secret for display: show first 4 and last 2 chars, rest as *.
fn mask_secret(s: &str) -> String {
    if s.len() <= 8 {
        return "*".repeat(s.len());
    }
    let prefix = &s[..4];
    let suffix = &s[s.len() - 2..];
    format!("{}{}{}",  prefix, "*".repeat(s.len() - 6), suffix)
}

/// Compute Shannon entropy of a string.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }
    let len = s.len() as f64;
    freq.values()
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Extract quoted string values from a line for entropy checking.
fn extract_quoted_values(line: &str) -> Vec<String> {
    let re = Regex::new(r#"["']([^"']{12,})["']"#).unwrap();
    re.captures_iter(line)
        .map(|c| c[1].to_string())
        .collect()
}

// ---- File scanning ----

/// Check if a file extension is scannable.
fn is_scannable(path: &Path) -> bool {
    let name = path.file_name().unwrap_or_default().to_string_lossy();

    // .env and .env.* files
    if name == ".env" || name.starts_with(".env.") {
        return true;
    }

    // Check extension
    if let Some(ext) = path.extension() {
        let ext = ext.to_string_lossy().to_lowercase();
        return SCAN_EXTENSIONS.contains(&ext.as_str());
    }

    false
}

/// Check if a path should be skipped (hidden dirs, node_modules, etc.).
fn should_skip_dir(name: &str) -> bool {
    SKIP_DIRS.contains(&name)
}

/// Recursively collect all scannable files under a path.
pub fn collect_files(path: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();

    if path.is_file() {
        if is_scannable(path) {
            files.push(path.to_path_buf());
        }
        return files;
    }

    if !path.is_dir() {
        return files;
    }

    let entries = match fs::read_dir(path) {
        Ok(e) => e,
        Err(_) => return files,
    };

    for entry in entries.flatten() {
        let entry_path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();

        if entry_path.is_dir() {
            if !should_skip_dir(&name) {
                files.extend(collect_files(&entry_path));
            }
        } else if is_scannable(&entry_path) {
            // Skip binary files (quick heuristic: check first 512 bytes for null bytes)
            if let Ok(bytes) = fs::read(&entry_path) {
                let check_len = bytes.len().min(512);
                if !bytes[..check_len].contains(&0) {
                    files.push(entry_path);
                }
            }
        }
    }

    files
}

/// Scan a single file for secrets using the given patterns.
pub fn scan_file(
    path: &Path,
    patterns: &[SecretPattern],
    entropy_threshold: f64,
) -> Vec<Finding> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let file_str = path.display().to_string();
    let mut findings = Vec::new();
    let mut seen: std::collections::HashSet<(usize, String)> = std::collections::HashSet::new();

    for (line_num, line) in content.lines().enumerate() {
        // Check named patterns
        for pattern in patterns {
            for m in pattern.regex.find_iter(line) {
                let raw = m.as_str().to_string();
                let key = (line_num + 1, raw.clone());
                if seen.contains(&key) {
                    continue;
                }
                seen.insert(key);
                findings.push(Finding {
                    file: file_str.clone(),
                    line: line_num + 1,
                    secret_type: pattern.name.to_string(),
                    masked: mask_secret(&raw),
                    raw_value: raw,
                });
            }
        }

        // Check high-entropy quoted strings
        for value in extract_quoted_values(line) {
            let entropy = shannon_entropy(&value);
            if entropy > entropy_threshold {
                let key = (line_num + 1, value.clone());
                if seen.contains(&key) {
                    continue;
                }
                // Skip if already matched by a named pattern
                if findings.iter().any(|f| f.line == line_num + 1 && value.contains(&f.raw_value)) {
                    continue;
                }
                seen.insert(key);
                findings.push(Finding {
                    file: file_str.clone(),
                    line: line_num + 1,
                    secret_type: format!("High-entropy string (entropy: {:.2})", entropy),
                    masked: mask_secret(&value),
                    raw_value: value,
                });
            }
        }
    }

    findings
}

/// Generate a vault slug from a secret type and file context.
pub fn generate_slug(finding: &Finding) -> String {
    let base = finding
        .file
        .rsplit('/')
        .next()
        .unwrap_or("unknown")
        .replace('.', "-");

    let type_hint = finding
        .secret_type
        .to_lowercase()
        .replace(' ', "-")
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-')
        .collect::<String>();

    let slug = format!("{}-{}-L{}", base, type_hint, finding.line);
    // Truncate to reasonable length
    if slug.len() > 64 {
        slug[..64].to_string()
    } else {
        slug
    }
}

// ---- Output formatting ----

/// Print findings in human-readable format.
pub fn print_findings(findings: &[Finding]) {
    if findings.is_empty() {
        println!("No secrets found.");
        return;
    }

    println!("Found {} potential secret(s):\n", findings.len());
    for f in findings {
        println!("  {}:{}", f.file, f.line);
        println!("    Type: {}", f.secret_type);
        println!("    Value: {}", f.masked);
        println!();
    }
}

/// Print findings as JSON.
pub fn print_findings_json(findings: &[Finding]) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(findings)?;
    println!("{}", json);
    Ok(())
}

/// Print what --fix would do.
pub fn print_dry_run(findings: &[Finding]) {
    if findings.is_empty() {
        println!("No secrets found. Nothing to fix.");
        return;
    }

    println!("Dry run — would perform {} replacement(s):\n", findings.len());
    for f in findings {
        let slug = generate_slug(f);
        println!("  {}:{}", f.file, f.line);
        println!("    {} → vclaw://default/{}", f.masked, slug);
        println!();
    }
}

// ---- Fix mode ----

/// Result of a fix operation.
pub struct FixResult {
    pub replaced: usize,
    pub backed_up: Vec<PathBuf>,
}

/// Apply fixes: import secrets to vault and replace with vclaw:// references.
/// Returns the number of replacements and list of backed-up files.
pub fn apply_fixes(
    findings: &[Finding],
    vault_path: &Path,
    password: &str,
) -> anyhow::Result<FixResult> {
    use crate::crypto::keys::password_secret;
    use crate::vault::entry::*;
    use crate::vault::format::VaultFile;

    if findings.is_empty() {
        return Ok(FixResult {
            replaced: 0,
            backed_up: Vec::new(),
        });
    }

    // Open vault
    let password_sec = password_secret(password.to_string());
    let mut vault = VaultFile::open(vault_path, &password_sec)?;

    // Create backup directory
    let backup_dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".vaultclaw")
        .join("scan-backups")
        .join(chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string());
    fs::create_dir_all(&backup_dir)?;

    // Group findings by file
    let mut by_file: HashMap<String, Vec<&Finding>> = HashMap::new();
    for f in findings {
        by_file.entry(f.file.clone()).or_default().push(f);
    }

    let mut replaced = 0;
    let mut backed_up = Vec::new();

    for (file_path, file_findings) in &by_file {
        let path = Path::new(file_path);
        let content = fs::read_to_string(path)?;

        // Back up original
        let backup_name = file_path.replace('/', "__");
        let backup_path = backup_dir.join(&backup_name);
        fs::write(&backup_path, &content)?;
        backed_up.push(backup_path);

        // Replace each secret
        let mut new_content = content.clone();
        for finding in file_findings {
            let slug = generate_slug(finding);
            let vclaw_ref = format!("vclaw://default/{}", slug);

            // Import to vault as ApiKey
            let entry = Entry::new(
                slug.clone(),
                Credential::ApiKey(ApiKeyCredential {
                    service: finding.secret_type.clone(),
                    key: finding.raw_value.clone(),
                    secret: String::new(),
                }),
            );
            vault.store_mut().add(entry);

            new_content = new_content.replace(&finding.raw_value, &vclaw_ref);
            replaced += 1;
        }

        fs::write(path, &new_content)?;
    }

    vault.save()?;

    Ok(FixResult {
        replaced,
        backed_up,
    })
}

// ---- Main entry point ----

/// Execute the `vaultclaw scan` command.
pub fn handle_scan_command(
    path: PathBuf,
    json_output: bool,
    dry_run: bool,
    fix: bool,
    custom_patterns: Vec<String>,
    vault_path: &Path,
    get_pw: impl Fn(&str) -> String,
) -> anyhow::Result<()> {
    // Build pattern list
    let mut patterns = builtin_patterns();
    for custom in &custom_patterns {
        let re = Regex::new(custom)
            .map_err(|e| anyhow::anyhow!("Invalid custom pattern '{}': {}", custom, e))?;
        patterns.push(SecretPattern {
            name: "Custom pattern",
            regex: re,
        });
    }

    // Collect files
    let files = collect_files(&path);
    if files.is_empty() {
        if json_output {
            println!("[]");
        } else {
            println!("No scannable files found in {}", path.display());
        }
        return Ok(());
    }

    // Scan all files
    let mut all_findings = Vec::new();
    for file in &files {
        let findings = scan_file(file, &patterns, 4.5);
        all_findings.extend(findings);
    }

    // Output results
    if dry_run {
        if json_output {
            print_findings_json(&all_findings)?;
        } else {
            print_dry_run(&all_findings);
        }
        return Ok(());
    }

    if fix {
        if all_findings.is_empty() {
            println!("No secrets found. Nothing to fix.");
            return Ok(());
        }

        let password = get_pw("Master password: ");
        let result = apply_fixes(&all_findings, vault_path, &password)?;
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "replaced": result.replaced,
                    "backed_up": result.backed_up.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                }))?
            );
        } else {
            println!("Fixed {} secret(s).", result.replaced);
            println!("Backups saved to:");
            for p in &result.backed_up {
                println!("  {}", p.display());
            }
            println!("\nSecrets imported to vault. Use 'vaultclaw run' to resolve vclaw:// refs.");
        }
        return Ok(());
    }

    // Default: just report
    if json_output {
        print_findings_json(&all_findings)?;
    } else {
        print_findings(&all_findings);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── mask_secret ──

    #[test]
    fn test_mask_long_secret() {
        let masked = mask_secret("sk-ant-abc123def456xyz");
        assert!(masked.starts_with("sk-a"));
        assert!(masked.ends_with("yz"));
        assert!(masked.contains('*'));
    }

    #[test]
    fn test_mask_short_secret() {
        assert_eq!(mask_secret("short"), "*****");
    }

    #[test]
    fn test_mask_exactly_8() {
        assert_eq!(mask_secret("12345678"), "********");
    }

    #[test]
    fn test_mask_9_chars() {
        assert_eq!(mask_secret("123456789"), "1234***89");
    }

    #[test]
    fn test_mask_empty() {
        assert_eq!(mask_secret(""), "");
    }

    // ── shannon_entropy ──

    #[test]
    fn test_entropy_zero() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn test_entropy_single_char() {
        assert_eq!(shannon_entropy("aaaa"), 0.0);
    }

    #[test]
    fn test_entropy_two_chars() {
        let e = shannon_entropy("ab");
        assert!((e - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_entropy_high() {
        let e = shannon_entropy("aB3$xY9!qW2@pL5#");
        assert!(e > 3.5);
    }

    #[test]
    fn test_entropy_low() {
        let e = shannon_entropy("aaaaaabbbb");
        assert!(e < 1.5);
    }

    // ── extract_quoted_values ──

    #[test]
    fn test_extract_double_quoted() {
        let vals = extract_quoted_values(r#""sk-ant-abc123def456ghi789""#);
        assert_eq!(vals.len(), 1);
        assert_eq!(vals[0], "sk-ant-abc123def456ghi789");
    }

    #[test]
    fn test_extract_single_quoted() {
        let vals = extract_quoted_values("'AKIAIOSFODNN7EXAMPLE'");
        assert_eq!(vals.len(), 1);
    }

    #[test]
    fn test_extract_short_values_skipped() {
        let vals = extract_quoted_values(r#""short""#);
        assert!(vals.is_empty());
    }

    #[test]
    fn test_extract_multiple() {
        let vals = extract_quoted_values(r#""long_value_12345" "other_value_67890""#);
        assert_eq!(vals.len(), 2);
    }

    // ── builtin_patterns ──

    #[test]
    fn test_builtin_patterns_count() {
        let patterns = builtin_patterns();
        assert!(patterns.len() >= 6);
    }

    #[test]
    fn test_anthropic_pattern() {
        let patterns = builtin_patterns();
        let pat = patterns.iter().find(|p| p.name == "Anthropic API Key").unwrap();
        assert!(pat.regex.is_match("sk-ant-api03-abc123def456ghi789jkl"));
        assert!(!pat.regex.is_match("sk-ant-short"));
    }

    #[test]
    fn test_openai_pattern() {
        let patterns = builtin_patterns();
        let pat = patterns.iter().find(|p| p.name == "OpenAI API Key").unwrap();
        assert!(pat.regex.is_match("sk-abcdefghijklmnopqrstuvwx"));
        assert!(!pat.regex.is_match("sk-short"));
    }

    #[test]
    fn test_github_pat_pattern() {
        let patterns = builtin_patterns();
        let pat = patterns.iter().find(|p| p.name == "GitHub PAT").unwrap();
        assert!(pat.regex.is_match("ghp_abcdefghijklmnopqrstuvwxyz0123456789"));
        assert!(!pat.regex.is_match("ghp_short"));
    }

    #[test]
    fn test_aws_pattern() {
        let patterns = builtin_patterns();
        let pat = patterns.iter().find(|p| p.name == "AWS Access Key").unwrap();
        assert!(pat.regex.is_match("AKIAIOSFODNN7EXAMPLE"));
        assert!(!pat.regex.is_match("AKIA_too_short"));
    }

    #[test]
    fn test_google_pattern() {
        let patterns = builtin_patterns();
        let pat = patterns.iter().find(|p| p.name == "Google API Key").unwrap();
        assert!(pat.regex.is_match("AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q"));
        assert!(!pat.regex.is_match("AIzaSyShort"));
    }

    #[test]
    fn test_telegram_pattern() {
        let patterns = builtin_patterns();
        let pat = patterns.iter().find(|p| p.name == "Telegram Bot Token").unwrap();
        // 10 digits + colon + exactly 35 alphanumeric/dash/underscore chars
        assert!(pat.regex.is_match("1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefgh"));
        assert!(!pat.regex.is_match("12345:short"));
    }

    #[test]
    fn test_slack_pattern() {
        let patterns = builtin_patterns();
        let pat = patterns.iter().find(|p| p.name == "Slack Token").unwrap();
        assert!(pat.regex.is_match("xoxb-1234567890-abcdef"));
    }

    // ── is_scannable ──

    #[test]
    fn test_scannable_json() {
        assert!(is_scannable(Path::new("config.json")));
    }

    #[test]
    fn test_scannable_env() {
        assert!(is_scannable(Path::new(".env")));
    }

    #[test]
    fn test_scannable_env_local() {
        assert!(is_scannable(Path::new(".env.local")));
    }

    #[test]
    fn test_scannable_yaml() {
        assert!(is_scannable(Path::new("config.yaml")));
    }

    #[test]
    fn test_scannable_toml() {
        assert!(is_scannable(Path::new("Cargo.toml")));
    }

    #[test]
    fn test_scannable_sh() {
        assert!(is_scannable(Path::new("setup.sh")));
    }

    #[test]
    fn test_not_scannable_rs() {
        assert!(!is_scannable(Path::new("main.rs")));
    }

    #[test]
    fn test_not_scannable_binary() {
        assert!(!is_scannable(Path::new("image.png")));
    }

    // ── should_skip_dir ──

    #[test]
    fn test_skip_git() {
        assert!(should_skip_dir(".git"));
    }

    #[test]
    fn test_skip_node_modules() {
        assert!(should_skip_dir("node_modules"));
    }

    #[test]
    fn test_skip_target() {
        assert!(should_skip_dir("target"));
    }

    #[test]
    fn test_dont_skip_src() {
        assert!(!should_skip_dir("src"));
    }

    // ── scan_file ──

    #[test]
    fn test_scan_file_with_secrets() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("config.json");
        fs::write(
            &file,
            r#"{"key": "sk-ant-api03-abc123def456ghi789jklmnopqrstuv"}"#,
        )
        .unwrap();

        let patterns = builtin_patterns();
        let findings = scan_file(&file, &patterns, 4.5);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].secret_type, "Anthropic API Key");
        assert_eq!(findings[0].line, 1);
    }

    #[test]
    fn test_scan_file_no_secrets() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("config.json");
        fs::write(&file, r#"{"key": "vclaw://default/my-key"}"#).unwrap();

        let patterns = builtin_patterns();
        let findings = scan_file(&file, &patterns, 4.5);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_scan_file_multiple_secrets() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join(".env");
        fs::write(
            &file,
            "API_KEY=sk-ant-api03-abc123def456ghi789jklmnopqrstuv\n\
             AWS_KEY=AKIAIOSFODNN7EXAMPLE\n\
             NORMAL=hello\n",
        )
        .unwrap();

        let patterns = builtin_patterns();
        let findings = scan_file(&file, &patterns, 4.5);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn test_scan_file_github_pat() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("config.sh");
        fs::write(
            &file,
            "export GH_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n",
        )
        .unwrap();

        let patterns = builtin_patterns();
        let findings = scan_file(&file, &patterns, 4.5);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].secret_type, "GitHub PAT");
    }

    #[test]
    fn test_scan_file_high_entropy() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("config.json");
        // High-entropy random string that doesn't match named patterns
        fs::write(
            &file,
            r#"{"token": "xR7$kL9#mQ2!pW4&bN6^jY8*cF0"}"#,
        )
        .unwrap();

        let patterns = builtin_patterns();
        let findings = scan_file(&file, &patterns, 4.0);
        assert!(!findings.is_empty());
        assert!(findings[0].secret_type.contains("entropy"));
    }

    #[test]
    fn test_scan_file_dedup() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("config.json");
        // Same secret appearing in different contexts on same line
        fs::write(
            &file,
            r#"{"a": "AKIAIOSFODNN7EXAMPLE", "b": "different"}"#,
        )
        .unwrap();

        let patterns = builtin_patterns();
        let findings = scan_file(&file, &patterns, 4.5);
        // Should only report once per line+value
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_scan_nonexistent_file() {
        let findings = scan_file(Path::new("/nonexistent/file.json"), &builtin_patterns(), 4.5);
        assert!(findings.is_empty());
    }

    // ── collect_files ──

    #[test]
    fn test_collect_files_directory() {
        let dir = tempfile::TempDir::new().unwrap();
        fs::write(dir.path().join("config.json"), "{}").unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();
        fs::write(dir.path().join(".env"), "KEY=val").unwrap();

        let files = collect_files(dir.path());
        assert_eq!(files.len(), 2); // config.json and .env
    }

    #[test]
    fn test_collect_files_skips_dirs() {
        let dir = tempfile::TempDir::new().unwrap();
        let git_dir = dir.path().join(".git");
        fs::create_dir(&git_dir).unwrap();
        fs::write(git_dir.join("config"), "secret").unwrap();
        fs::write(dir.path().join("config.json"), "{}").unwrap();

        let files = collect_files(dir.path());
        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("config.json"));
    }

    #[test]
    fn test_collect_files_recursive() {
        let dir = tempfile::TempDir::new().unwrap();
        let sub = dir.path().join("subdir");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("app.yaml"), "key: val").unwrap();
        fs::write(dir.path().join("config.toml"), "[section]").unwrap();

        let files = collect_files(dir.path());
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_collect_files_single_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("test.env");
        fs::write(&file, "KEY=val").unwrap();

        let files = collect_files(&file);
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn test_collect_files_nonexistent() {
        let files = collect_files(Path::new("/nonexistent/path"));
        assert!(files.is_empty());
    }

    // ── generate_slug ──

    #[test]
    fn test_generate_slug() {
        let finding = Finding {
            file: "configs/app.json".into(),
            line: 5,
            secret_type: "AWS Access Key".into(),
            masked: "AKIA***LE".into(),
            raw_value: "AKIAIOSFODNN7EXAMPLE".into(),
        };
        let slug = generate_slug(&finding);
        assert!(slug.contains("app-json"));
        assert!(slug.contains("aws-access-key"));
        assert!(slug.contains("L5"));
    }

    #[test]
    fn test_generate_slug_truncation() {
        let finding = Finding {
            file: "very/long/path/to/some/deeply/nested/configuration/file.json".into(),
            line: 999,
            secret_type: "Some Very Long Pattern Name That Should Be Truncated".into(),
            masked: "****".into(),
            raw_value: "secret".into(),
        };
        let slug = generate_slug(&finding);
        assert!(slug.len() <= 64);
    }

    // ── print_findings ──

    #[test]
    fn test_print_findings_empty() {
        // Should not panic
        print_findings(&[]);
    }

    #[test]
    fn test_print_findings_json_empty() {
        print_findings_json(&[]).unwrap();
    }

    #[test]
    fn test_print_findings_json_with_data() {
        let findings = vec![Finding {
            file: "test.json".into(),
            line: 1,
            secret_type: "Test".into(),
            masked: "****".into(),
            raw_value: "secret".into(),
        }];
        print_findings_json(&findings).unwrap();
    }

    #[test]
    fn test_print_dry_run_empty() {
        print_dry_run(&[]);
    }

    #[test]
    fn test_print_dry_run_with_data() {
        let findings = vec![Finding {
            file: "test.json".into(),
            line: 1,
            secret_type: "Test".into(),
            masked: "****".into(),
            raw_value: "secret".into(),
        }];
        print_dry_run(&findings);
    }

    // ── apply_fixes ──

    #[test]
    fn test_apply_fixes_empty() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");
        let password = crate::crypto::keys::password_secret("test".to_string());
        let kdf = crate::crypto::kdf::KdfParams::fast_for_testing();
        crate::vault::format::VaultFile::create(&vault_path, &password, kdf).unwrap();

        let result = apply_fixes(&[], &vault_path, "test").unwrap();
        assert_eq!(result.replaced, 0);
        assert!(result.backed_up.is_empty());
    }

    #[test]
    fn test_apply_fixes_replaces_secret() {
        let dir = tempfile::TempDir::new().unwrap();

        // Create vault
        let vault_path = dir.path().join("test.vclaw");
        let password = crate::crypto::keys::password_secret("test".to_string());
        let kdf = crate::crypto::kdf::KdfParams::fast_for_testing();
        crate::vault::format::VaultFile::create(&vault_path, &password, kdf).unwrap();

        // Create file with secret
        let config_path = dir.path().join("config.json");
        fs::write(&config_path, r#"{"key": "AKIAIOSFODNN7EXAMPLE"}"#).unwrap();

        let findings = vec![Finding {
            file: config_path.display().to_string(),
            line: 1,
            secret_type: "AWS Access Key".into(),
            masked: "AKIA***LE".into(),
            raw_value: "AKIAIOSFODNN7EXAMPLE".into(),
        }];

        let result = apply_fixes(&findings, &vault_path, "test").unwrap();
        assert_eq!(result.replaced, 1);
        assert_eq!(result.backed_up.len(), 1);

        // Verify the file was modified
        let content = fs::read_to_string(&config_path).unwrap();
        assert!(content.contains("vclaw://default/"));
        assert!(!content.contains("AKIAIOSFODNN7EXAMPLE"));

        // Verify the backup contains the original
        let backup_content = fs::read_to_string(&result.backed_up[0]).unwrap();
        assert!(backup_content.contains("AKIAIOSFODNN7EXAMPLE"));

        // Verify vault has the imported entry
        let vault = crate::vault::format::VaultFile::open(&vault_path, &password).unwrap();
        let entries = vault.store().list();
        assert!(entries.iter().any(|e| {
            if let crate::vault::entry::Credential::ApiKey(ref ak) = e.credential {
                ak.key == "AKIAIOSFODNN7EXAMPLE"
            } else {
                false
            }
        }));
    }

    // ── handle_scan_command ──

    #[test]
    fn test_scan_command_no_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        handle_scan_command(
            dir.path().to_path_buf(),
            false,
            false,
            false,
            vec![],
            &vault_path,
            |_| panic!("should not prompt"),
        )
        .unwrap();
    }

    #[test]
    fn test_scan_command_json_output() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");
        fs::write(
            dir.path().join("config.json"),
            r#"{"key": "AKIAIOSFODNN7EXAMPLE"}"#,
        )
        .unwrap();

        handle_scan_command(
            dir.path().to_path_buf(),
            true,
            false,
            false,
            vec![],
            &vault_path,
            |_| panic!("should not prompt"),
        )
        .unwrap();
    }

    #[test]
    fn test_scan_command_dry_run() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");
        fs::write(
            dir.path().join("config.json"),
            r#"{"key": "AKIAIOSFODNN7EXAMPLE"}"#,
        )
        .unwrap();

        handle_scan_command(
            dir.path().to_path_buf(),
            false,
            true,
            false,
            vec![],
            &vault_path,
            |_| panic!("should not prompt"),
        )
        .unwrap();
    }

    #[test]
    fn test_scan_command_custom_pattern() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");
        fs::write(
            dir.path().join("config.json"),
            r#"{"key": "CUSTOM_SECRET_12345678"}"#,
        )
        .unwrap();

        handle_scan_command(
            dir.path().to_path_buf(),
            true,
            false,
            false,
            vec!["CUSTOM_SECRET_[0-9]+".to_string()],
            &vault_path,
            |_| panic!("should not prompt"),
        )
        .unwrap();
    }

    #[test]
    fn test_scan_command_invalid_pattern() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        let result = handle_scan_command(
            dir.path().to_path_buf(),
            false,
            false,
            false,
            vec!["[invalid".to_string()],
            &vault_path,
            |_| panic!("should not prompt"),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid custom pattern"));
    }

    #[test]
    fn test_scan_command_fix_mode() {
        let dir = tempfile::TempDir::new().unwrap();

        // Create vault
        let vault_path = dir.path().join("test.vclaw");
        let password = crate::crypto::keys::password_secret("test".to_string());
        let kdf = crate::crypto::kdf::KdfParams::fast_for_testing();
        crate::vault::format::VaultFile::create(&vault_path, &password, kdf).unwrap();

        // Create file with secret
        fs::write(
            dir.path().join("config.json"),
            r#"{"key": "AKIAIOSFODNN7EXAMPLE"}"#,
        )
        .unwrap();

        handle_scan_command(
            dir.path().to_path_buf(),
            false,
            false,
            true,
            vec![],
            &vault_path,
            |_| "test".to_string(),
        )
        .unwrap();

        // Verify replacement
        let content = fs::read_to_string(dir.path().join("config.json")).unwrap();
        assert!(content.contains("vclaw://default/"));
        assert!(!content.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_scan_command_no_files_json() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        // Empty dir with no scannable files
        handle_scan_command(
            dir.path().to_path_buf(),
            true,
            false,
            false,
            vec![],
            &vault_path,
            |_| panic!("should not prompt"),
        )
        .unwrap();
    }

    // ── is_scannable (additional) ──

    #[test]
    fn test_not_scannable_no_extension() {
        // A file with no extension that is not .env should return false (covers L126, L128)
        assert!(!is_scannable(Path::new("Makefile")));
        assert!(!is_scannable(Path::new("Dockerfile")));
        assert!(!is_scannable(Path::new("README")));
    }

    // ── collect_files (additional) ──

    #[test]
    fn test_collect_files_unreadable_dir() {
        // Passing a nonexistent directory hits the Err(_) path in read_dir (L153)
        let files = collect_files(Path::new("/nonexistent/dir/that/does/not/exist"));
        assert!(files.is_empty());
    }

    #[test]
    fn test_collect_files_single_nonscannable_file() {
        // Single non-scannable file returns empty
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("main.rs");
        fs::write(&file, "fn main() {}").unwrap();

        let files = collect_files(&file);
        assert!(files.is_empty());
    }

    // ── scan_file (additional) ──

    #[test]
    fn test_scan_file_dedup_same_value_via_pattern_overlap() {
        // When two patterns match the same value on the same line, only one finding
        // should be reported (covers L200: seen.contains check).
        // Create a string that matches both "OpenAI API Key" (sk-...) and could appear
        // again via the same pattern (find_iter only yields each non-overlapping match once),
        // so we construct a line where the same secret literally appears twice.
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("config.json");
        // Put the exact same secret twice on the same line
        fs::write(
            &file,
            r#"{"a": "AKIAIOSFODNN7EXAMPLE", "b": "AKIAIOSFODNN7EXAMPLE"}"#,
        )
        .unwrap();

        let patterns = builtin_patterns();
        let findings = scan_file(&file, &patterns, 4.5);
        // The first match is recorded, the second is skipped by seen.contains
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].secret_type, "AWS Access Key");
    }

    #[test]
    fn test_scan_file_entropy_skipped_when_named_pattern_matches() {
        // High-entropy quoted string that contains a value already found by a named pattern
        // should be skipped (covers L223).
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("config.json");
        // The AWS key AKIAIOSFODNN7EXAMPLE is matched by the AWS pattern.
        // Wrap it in a quoted string that is high-entropy and contains the raw_value.
        fs::write(
            &file,
            r#"{"key": "xAKIAIOSFODNN7EXAMPLEz9!$#"}"#,
        )
        .unwrap();

        let patterns = builtin_patterns();
        // Use a low threshold so the entropy check triggers
        let findings = scan_file(&file, &patterns, 2.0);
        // Should have the AWS pattern finding, but not a separate entropy finding
        // for the quoted value that contains the AWS key
        let aws_count = findings.iter().filter(|f| f.secret_type == "AWS Access Key").count();
        let entropy_count = findings.iter().filter(|f| f.secret_type.contains("entropy")).count();
        assert_eq!(aws_count, 1);
        // The entropy finding for the quoted string containing the AWS key is skipped (L223)
        assert_eq!(entropy_count, 0);
    }

    // ── print_findings (additional) ──

    #[test]
    fn test_print_findings_with_data() {
        // Covers L275-281: non-empty findings printed in human-readable format
        let findings = vec![
            Finding {
                file: "test.json".into(),
                line: 1,
                secret_type: "AWS Access Key".into(),
                masked: "AKIA***LE".into(),
                raw_value: "AKIAIOSFODNN7EXAMPLE".into(),
            },
            Finding {
                file: "config.yaml".into(),
                line: 10,
                secret_type: "GitHub PAT".into(),
                masked: "ghp_***ij".into(),
                raw_value: "ghp_abcdefghij".into(),
            },
        ];
        // Should not panic; exercises the println! branches
        print_findings(&findings);
    }

    // ── handle_scan_command (additional) ──

    #[test]
    fn test_scan_command_dry_run_json() {
        // Covers L440: dry_run=true + json_output=true
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");
        fs::write(
            dir.path().join("config.json"),
            r#"{"key": "AKIAIOSFODNN7EXAMPLE"}"#,
        )
        .unwrap();

        handle_scan_command(
            dir.path().to_path_buf(),
            true,  // json_output
            true,  // dry_run
            false,
            vec![],
            &vault_path,
            |_| panic!("should not prompt"),
        )
        .unwrap();
    }

    #[test]
    fn test_scan_command_fix_json_output() {
        // Covers L456, L458-461: fix=true + json_output=true with findings
        let dir = tempfile::TempDir::new().unwrap();

        // Create vault
        let vault_path = dir.path().join("test.vclaw");
        let password = crate::crypto::keys::password_secret("test".to_string());
        let kdf = crate::crypto::kdf::KdfParams::fast_for_testing();
        crate::vault::format::VaultFile::create(&vault_path, &password, kdf).unwrap();

        // Create file with secret
        fs::write(
            dir.path().join("config.json"),
            r#"{"key": "AKIAIOSFODNN7EXAMPLE"}"#,
        )
        .unwrap();

        handle_scan_command(
            dir.path().to_path_buf(),
            true,  // json_output
            false,
            true,  // fix
            vec![],
            &vault_path,
            |_| "test".to_string(),
        )
        .unwrap();

        // Verify replacement happened
        let content = fs::read_to_string(dir.path().join("config.json")).unwrap();
        assert!(content.contains("vclaw://default/"));
        assert!(!content.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_scan_command_default_text_report_with_findings() {
        // Covers L477-479: default report mode (not json, not dry_run, not fix)
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");
        fs::write(
            dir.path().join("config.json"),
            r#"{"key": "AKIAIOSFODNN7EXAMPLE"}"#,
        )
        .unwrap();

        handle_scan_command(
            dir.path().to_path_buf(),
            false, // json_output=false
            false, // dry_run=false
            false, // fix=false
            vec![],
            &vault_path,
            |_| panic!("should not prompt"),
        )
        .unwrap();
    }

    #[test]
    fn test_scan_command_fix_no_findings() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");

        // File with no secrets
        fs::write(dir.path().join("config.json"), r#"{"key": "normal"}"#).unwrap();

        handle_scan_command(
            dir.path().to_path_buf(),
            false,
            false,
            true,
            vec![],
            &vault_path,
            |_| panic!("should not prompt"),
        )
        .unwrap();
    }

    // ── collect_files: binary file skipping ──

    #[test]
    fn test_collect_files_skips_binary_files() {
        // A file with null bytes in the first 512 bytes should be skipped
        // even if it has a scannable extension (covers the contains(&0) branch).
        let dir = tempfile::TempDir::new().unwrap();
        let bin_file = dir.path().join("data.json");
        let mut content = b"{ \"key\": \"value\" }".to_vec();
        content.push(0u8); // null byte makes it "binary"
        fs::write(&bin_file, &content).unwrap();

        // Also add a normal text file to ensure it IS collected
        fs::write(dir.path().join("config.json"), r#"{"ok": true}"#).unwrap();

        let files = collect_files(dir.path());
        // Only config.json should be collected; data.json is treated as binary
        assert_eq!(files.len(), 1);
        assert!(files[0].to_string_lossy().contains("config.json"));
    }

    #[test]
    fn test_collect_files_unreadable_subdir() {
        // Create a subdirectory, then remove read permissions so read_dir fails.
        // This covers line 153: Err(_) => return files.
        let dir = tempfile::TempDir::new().unwrap();
        let unreadable = dir.path().join("secret");
        fs::create_dir(&unreadable).unwrap();
        fs::write(unreadable.join("config.json"), "{}").unwrap();

        // Remove read+execute permissions on the directory
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).unwrap();
        }

        // Collect from parent; the unreadable subdir's read_dir should fail
        let files = collect_files(dir.path());

        // Restore permissions so TempDir cleanup works
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o755)).unwrap();
        }

        // On Unix, the unreadable dir's contents won't be found
        #[cfg(unix)]
        assert!(files.is_empty());
    }

    // ── scan_file: entropy dedup via seen set ──

    #[test]
    fn test_scan_file_entropy_dedup_via_seen() {
        // When the same high-entropy quoted string appears twice on the same line,
        // the second occurrence should be skipped by the seen set (covers L218-219).
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("config.json");
        // Two identical high-entropy strings on same line; neither matches named patterns
        let high_entropy = "xR7kL9mQ2pW4bN6jY8cF0";
        let content = format!(r#"{{"a": "{}", "b": "{}"}}"#, high_entropy, high_entropy);
        fs::write(&file, &content).unwrap();

        let patterns = builtin_patterns();
        let findings = scan_file(&file, &patterns, 3.0);
        // Should have at most one entropy finding for this value on this line
        let entropy_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.secret_type.contains("entropy") && f.raw_value == high_entropy)
            .collect();
        assert!(entropy_findings.len() <= 1);
    }

    // ── generate_slug: no slash in path ──

    #[test]
    fn test_generate_slug_no_slash() {
        // When file path has no '/', rsplit('/').next() returns the whole string
        let finding = Finding {
            file: "standalone.json".into(),
            line: 1,
            secret_type: "Test".into(),
            masked: "****".into(),
            raw_value: "secret".into(),
        };
        let slug = generate_slug(&finding);
        assert!(slug.contains("standalone-json"));
        assert!(slug.contains("L1"));
    }

    // ── handle_scan_command: dry_run with no findings ──

    #[test]
    fn test_scan_command_dry_run_no_findings_text() {
        // dry_run=true with no findings should print "No secrets found"
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");
        fs::write(dir.path().join("config.json"), r#"{"safe": "value"}"#).unwrap();

        handle_scan_command(
            dir.path().to_path_buf(),
            false,
            true, // dry_run
            false,
            vec![],
            &vault_path,
            |_| panic!("should not prompt"),
        )
        .unwrap();
    }

    #[test]
    fn test_scan_command_dry_run_no_findings_json() {
        // dry_run=true + json_output=true with no findings
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");
        fs::write(dir.path().join("config.json"), r#"{"safe": "value"}"#).unwrap();

        handle_scan_command(
            dir.path().to_path_buf(),
            true,  // json_output
            true,  // dry_run
            false,
            vec![],
            &vault_path,
            |_| panic!("should not prompt"),
        )
        .unwrap();
    }

    // ── handle_scan_command: default JSON report with findings ──

    #[test]
    fn test_scan_command_default_json_report_with_findings() {
        // Covers L475-476: json_output=true, not dry_run, not fix
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");
        fs::write(
            dir.path().join("config.json"),
            r#"{"key": "AKIAIOSFODNN7EXAMPLE"}"#,
        )
        .unwrap();

        handle_scan_command(
            dir.path().to_path_buf(),
            true,  // json_output
            false, // dry_run=false
            false, // fix=false
            vec![],
            &vault_path,
            |_| panic!("should not prompt"),
        )
        .unwrap();
    }

    // ── apply_fixes: multiple findings in same file ──

    #[test]
    fn test_apply_fixes_multiple_secrets_same_file() {
        let dir = tempfile::TempDir::new().unwrap();

        // Create vault
        let vault_path = dir.path().join("test.vclaw");
        let password = crate::crypto::keys::password_secret("test".to_string());
        let kdf = crate::crypto::kdf::KdfParams::fast_for_testing();
        crate::vault::format::VaultFile::create(&vault_path, &password, kdf).unwrap();

        // Create file with two secrets
        let config_path = dir.path().join("config.json");
        fs::write(
            &config_path,
            r#"{"aws": "AKIAIOSFODNN7EXAMPLE", "gh": "ghp_abcdefghijklmnopqrstuvwxyz0123456789"}"#,
        )
        .unwrap();

        let findings = vec![
            Finding {
                file: config_path.display().to_string(),
                line: 1,
                secret_type: "AWS Access Key".into(),
                masked: "AKIA***LE".into(),
                raw_value: "AKIAIOSFODNN7EXAMPLE".into(),
            },
            Finding {
                file: config_path.display().to_string(),
                line: 1,
                secret_type: "GitHub PAT".into(),
                masked: "ghp_***89".into(),
                raw_value: "ghp_abcdefghijklmnopqrstuvwxyz0123456789".into(),
            },
        ];

        let result = apply_fixes(&findings, &vault_path, "test").unwrap();
        assert_eq!(result.replaced, 2);
        assert_eq!(result.backed_up.len(), 1); // Same file backed up once

        let content = fs::read_to_string(&config_path).unwrap();
        assert!(!content.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!content.contains("ghp_abcdefghijklmnopqrstuvwxyz0123456789"));
        // Should have two vclaw:// references
        assert_eq!(content.matches("vclaw://default/").count(), 2);
    }

    // ── apply_fixes: findings across multiple files ──

    #[test]
    fn test_apply_fixes_multiple_files() {
        let dir = tempfile::TempDir::new().unwrap();

        // Create vault
        let vault_path = dir.path().join("test.vclaw");
        let password = crate::crypto::keys::password_secret("test".to_string());
        let kdf = crate::crypto::kdf::KdfParams::fast_for_testing();
        crate::vault::format::VaultFile::create(&vault_path, &password, kdf).unwrap();

        // Create two files with secrets
        let file_a = dir.path().join("a.json");
        let file_b = dir.path().join("b.json");
        fs::write(&file_a, r#"{"key": "AKIAIOSFODNN7EXAMPLE"}"#).unwrap();
        fs::write(
            &file_b,
            r#"{"token": "ghp_abcdefghijklmnopqrstuvwxyz0123456789"}"#,
        )
        .unwrap();

        let findings = vec![
            Finding {
                file: file_a.display().to_string(),
                line: 1,
                secret_type: "AWS Access Key".into(),
                masked: "AKIA***LE".into(),
                raw_value: "AKIAIOSFODNN7EXAMPLE".into(),
            },
            Finding {
                file: file_b.display().to_string(),
                line: 1,
                secret_type: "GitHub PAT".into(),
                masked: "ghp_***89".into(),
                raw_value: "ghp_abcdefghijklmnopqrstuvwxyz0123456789".into(),
            },
        ];

        let result = apply_fixes(&findings, &vault_path, "test").unwrap();
        assert_eq!(result.replaced, 2);
        assert_eq!(result.backed_up.len(), 2); // Two separate files backed up

        let content_a = fs::read_to_string(&file_a).unwrap();
        assert!(content_a.contains("vclaw://default/"));
        assert!(!content_a.contains("AKIAIOSFODNN7EXAMPLE"));

        let content_b = fs::read_to_string(&file_b).unwrap();
        assert!(content_b.contains("vclaw://default/"));
        assert!(!content_b.contains("ghp_abcdefghijklmnopqrstuvwxyz0123456789"));
    }

    // ── handle_scan_command: fix mode with multiple findings + text output ──

    #[test]
    fn test_scan_command_fix_multiple_findings_text() {
        // Covers L464-469: fix=true, json_output=false, multiple findings
        let dir = tempfile::TempDir::new().unwrap();

        let vault_path = dir.path().join("test.vclaw");
        let password = crate::crypto::keys::password_secret("test".to_string());
        let kdf = crate::crypto::kdf::KdfParams::fast_for_testing();
        crate::vault::format::VaultFile::create(&vault_path, &password, kdf).unwrap();

        // File with two secrets to exercise the backup listing loop
        fs::write(
            dir.path().join("config.json"),
            "AWS=AKIAIOSFODNN7EXAMPLE\nGH=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n",
        )
        .unwrap();

        handle_scan_command(
            dir.path().to_path_buf(),
            false, // json_output=false to hit text output branch
            false,
            true, // fix
            vec![],
            &vault_path,
            |_| "test".to_string(),
        )
        .unwrap();
    }

    // ── GitHub Fine-grained PAT pattern ──

    #[test]
    fn test_github_fine_grained_pat_pattern() {
        let patterns = builtin_patterns();
        let pat = patterns
            .iter()
            .find(|p| p.name == "GitHub Fine-grained PAT")
            .unwrap();
        // 82-char alphanumeric+underscore suffix
        let token = format!("github_pat_{}", "a".repeat(82));
        assert!(pat.regex.is_match(&token));
        assert!(!pat.regex.is_match("github_pat_short"));
    }

    // ── is_scannable: additional extensions ──

    #[test]
    fn test_scannable_bash() {
        assert!(is_scannable(Path::new("script.bash")));
    }

    #[test]
    fn test_scannable_zsh() {
        assert!(is_scannable(Path::new("script.zsh")));
    }

    #[test]
    fn test_scannable_config() {
        assert!(is_scannable(Path::new("app.config")));
    }

    #[test]
    fn test_scannable_cfg() {
        assert!(is_scannable(Path::new("setup.cfg")));
    }

    #[test]
    fn test_scannable_ini() {
        assert!(is_scannable(Path::new("settings.ini")));
    }

    #[test]
    fn test_scannable_yml() {
        assert!(is_scannable(Path::new("docker-compose.yml")));
    }

    // ── should_skip_dir: additional ──

    #[test]
    fn test_skip_venv() {
        assert!(should_skip_dir(".venv"));
    }

    #[test]
    fn test_skip_pycache() {
        assert!(should_skip_dir("__pycache__"));
    }

    #[test]
    fn test_skip_dist() {
        assert!(should_skip_dir("dist"));
    }
}
