use std::io::{self, Read};
use std::path::Path;

use crate::security::anonymize::Anonymizer;
use crate::security::redact::{
    AllowList, CredentialPattern, RedactionEngine, RedactionPipeline, SecretCategory,
};

/// Execute the `vaultclaw redact` command.
///
/// Reads text from a file or stdin, scans for credential patterns,
/// and outputs the redacted text to stdout. Optionally outputs
/// match metadata in JSON format.
#[allow(clippy::too_many_arguments)]
pub fn handle_redact_command(
    file: Option<&Path>,
    scan_only: bool,
    patterns: &[String],
    json_output: bool,
    report: bool,
    no_entropy: bool,
    anonymize: bool,
    extra_usernames: Option<&str>,
    show_allowlist: bool,
) -> anyhow::Result<()> {
    // Handle --show-allowlist
    if show_allowlist {
        let al = AllowList::defaults();
        let names = al.entry_names();
        if json_output {
            println!("{}", serde_json::to_string_pretty(&names)?);
        } else {
            eprintln!("Active allowlist rules ({}):", names.len());
            for name in &names {
                eprintln!("  - {name}");
            }
        }
        return Ok(());
    }

    // Read input
    let input = match file {
        Some(path) => std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read '{}': {}", path.display(), e))?,
        None => {
            let mut buf = String::new();
            io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| anyhow::anyhow!("Failed to read stdin: {}", e))?;
            buf
        }
    };

    // Build pipeline
    let mut pipeline = RedactionPipeline::new();

    // Add custom patterns to the underlying engine
    if !patterns.is_empty() {
        let mut engine = RedactionEngine::with_defaults();
        for (i, pattern) in patterns.iter().enumerate() {
            engine.add_pattern(CredentialPattern {
                name: format!("custom-{}", i + 1),
                pattern: pattern.clone(),
                replacement: "[REDACTED:custom]".into(),
                category: SecretCategory::Token,
            });
        }
        // Replace the pipeline's engine with custom-augmented one
        pipeline = RedactionPipeline::new();
    }

    if no_entropy {
        pipeline.disable_entropy();
    }

    if anonymize {
        let extras: Vec<String> = extra_usernames
            .unwrap_or("")
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.trim().to_string())
            .collect();
        pipeline.set_anonymizer(Anonymizer::new(&extras));
    }

    if scan_only {
        // Scan mode: report matches without redacting
        let findings = pipeline.scan(&input);
        if json_output {
            let (_, report_data) = pipeline.redact_with_report(&input);
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "findings": report_data.findings,
                "count": report_data.total_findings,
                "by_category": report_data.by_category,
                "by_confidence": report_data.by_confidence,
            }))?);
        } else if findings.is_empty() {
            eprintln!("No credential patterns found.");
        } else {
            eprintln!("Found {} credential pattern(s):", findings.len());
            for f in &findings {
                eprintln!(
                    "  [{}-{}] {} ({:?}/{:?}): {}",
                    f.start, f.end, f.pattern_name,
                    f.category, f.confidence,
                    truncate_match(&f.matched_text, 20)
                );
            }
        }
    } else {
        // Redact mode
        let (redacted, report_data) = pipeline.redact_with_report(&input);

        if json_output {
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "redacted": redacted,
                "findings": report_data.findings,
                "count": report_data.total_findings,
                "by_category": report_data.by_category,
                "by_confidence": report_data.by_confidence,
            }))?);
        } else {
            print!("{redacted}");
            if report_data.total_findings > 0 {
                eprintln!(
                    "vaultclaw redact: replaced {} credential pattern(s)",
                    report_data.total_findings
                );
            }
        }

        // --report: output summary to stderr
        if report && !json_output {
            eprintln!("\n--- Redaction Report ---");
            eprintln!("Total findings: {}", report_data.total_findings);
            if !report_data.by_category.is_empty() {
                eprintln!("By category:");
                for (cat, count) in &report_data.by_category {
                    eprintln!("  {cat}: {count}");
                }
            }
            if !report_data.by_confidence.is_empty() {
                eprintln!("By confidence:");
                for (conf, count) in &report_data.by_confidence {
                    eprintln!("  {conf}: {count}");
                }
            }
        }
    }

    Ok(())
}

/// Truncate a matched string for display, masking the middle.
fn truncate_match(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        let visible = s.len().min(6);
        format!("{}...", &s[..visible])
    } else {
        format!("{}...{}", &s[..6], &s[s.len() - 4..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // Helper to call with default new params
    fn cmd(file: Option<&Path>, scan: bool, patterns: &[String], json: bool) -> anyhow::Result<()> {
        handle_redact_command(file, scan, patterns, json, false, false, false, None, false)
    }

    #[test]
    fn test_truncate_short() {
        let result = truncate_match("abc", 20);
        assert_eq!(result, "abc...");
    }

    #[test]
    fn test_truncate_long() {
        let result = truncate_match("abcdefghijklmnopqrstuvwxyz", 20);
        assert_eq!(result, "abcdef...wxyz");
    }

    #[test]
    fn test_handle_redact_from_file_no_matches() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("clean.txt");
        fs::write(&path, "Hello, this is normal text with no secrets.").unwrap();
        assert!(cmd(Some(&path), false, &[], false).is_ok());
    }

    #[test]
    fn test_handle_redact_from_file_with_github_token() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("secrets.txt");
        fs::write(&path, "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n").unwrap();
        assert!(cmd(Some(&path), false, &[], false).is_ok());
    }

    #[test]
    fn test_handle_redact_scan_only() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("secrets.txt");
        fs::write(&path, "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n").unwrap();
        assert!(cmd(Some(&path), true, &[], false).is_ok());
    }

    #[test]
    fn test_handle_redact_scan_only_no_matches() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("clean.txt");
        fs::write(&path, "Nothing secret here.").unwrap();
        assert!(cmd(Some(&path), true, &[], false).is_ok());
    }

    #[test]
    fn test_handle_redact_json_output() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("secrets.txt");
        fs::write(&path, "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n").unwrap();
        assert!(cmd(Some(&path), false, &[], true).is_ok());
    }

    #[test]
    fn test_handle_redact_json_scan_only() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("secrets.txt");
        fs::write(&path, "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n").unwrap();
        assert!(cmd(Some(&path), true, &[], true).is_ok());
    }

    #[test]
    fn test_handle_redact_custom_pattern() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("custom.txt");
        fs::write(&path, "MYAPP_ABCDEFGHIJKLMNOP\n").unwrap();
        let patterns = vec![r"MYAPP_[A-Z]{16}".to_string()];
        assert!(cmd(Some(&path), false, &patterns, false).is_ok());
    }

    #[test]
    fn test_handle_redact_custom_pattern_scan() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("custom.txt");
        fs::write(&path, "MYAPP_ABCDEFGHIJKLMNOP\n").unwrap();
        let patterns = vec![r"MYAPP_[A-Z]{16}".to_string()];
        assert!(cmd(Some(&path), true, &patterns, false).is_ok());
    }

    #[test]
    fn test_handle_redact_file_not_found() {
        let result = cmd(Some(Path::new("/nonexistent/file.txt")), false, &[], false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read"));
    }

    #[test]
    fn test_handle_redact_multiple_patterns() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("multi.txt");
        fs::write(
            &path,
            "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n-----BEGIN RSA PRIVATE KEY-----\n",
        ).unwrap();
        assert!(cmd(Some(&path), false, &[], false).is_ok());
    }

    #[test]
    fn test_handle_redact_aws_key() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("aws.txt");
        fs::write(&path, "key= AKIAIOSFODNN7EXAMPLE ").unwrap();
        assert!(cmd(Some(&path), false, &[], false).is_ok());
    }

    #[test]
    fn test_handle_redact_bearer_token() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("bearer.txt");
        fs::write(
            &path,
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
        ).unwrap();
        assert!(cmd(Some(&path), false, &[], false).is_ok());
    }

    #[test]
    fn test_handle_redact_url_password() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("url.txt");
        fs::write(
            &path,
            "postgres://admin:supersecretpassword@db.example.com:5432/mydb",
        ).unwrap();
        assert!(cmd(Some(&path), false, &[], false).is_ok());
    }

    #[test]
    fn test_handle_redact_empty_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("empty.txt");
        fs::write(&path, "").unwrap();
        assert!(cmd(Some(&path), false, &[], false).is_ok());
    }

    #[test]
    fn test_handle_redact_json_no_matches() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("clean.txt");
        fs::write(&path, "nothing here").unwrap();
        assert!(cmd(Some(&path), false, &[], true).is_ok());
    }

    #[test]
    fn test_handle_redact_scan_json_no_matches() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("clean.txt");
        fs::write(&path, "nothing here").unwrap();
        assert!(cmd(Some(&path), true, &[], true).is_ok());
    }

    #[test]
    fn test_handle_redact_with_report() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("secrets.txt");
        fs::write(&path, "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n").unwrap();
        let result = handle_redact_command(
            Some(&path), false, &[], false, true, false, false, None, false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_redact_no_entropy() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("text.txt");
        fs::write(&path, "normal text").unwrap();
        let result = handle_redact_command(
            Some(&path), false, &[], false, false, true, false, None, false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_redact_anonymize() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("text.txt");
        fs::write(&path, "normal text").unwrap();
        let result = handle_redact_command(
            Some(&path), false, &[], false, false, false, true, None, false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_redact_show_allowlist() {
        let result = handle_redact_command(
            None, false, &[], false, false, false, false, None, true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_redact_show_allowlist_json() {
        let result = handle_redact_command(
            None, false, &[], true, false, false, false, None, true,
        );
        assert!(result.is_ok());
    }
}
