//! Credential pattern registry and redaction engine.
//!
//! Scans text for known credential patterns (API keys, tokens, passwords)
//! and replaces them with redaction markers. Used for:
//! - Pre-context injection filtering (P0 item #2 from ADR-000)
//! - Exec output redaction (P0 item #3 from ADR-000)
//! - Compaction scrubbing

use std::collections::HashMap;

use aho_corasick::AhoCorasick;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Category of secret detected by a credential pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretCategory {
    /// Specific API key (AWS, GitHub, Anthropic, OpenAI, etc.)
    ApiKey,
    /// Authentication token (JWT, Bearer, Slack, Discord, etc.)
    Token,
    /// Database connection string containing credentials
    DatabaseUrl,
    /// Private key material (RSA, EC, DSA, OPENSSH)
    PrivateKey,
    /// Personally identifiable information (email, IP address)
    Pii,
    /// High-entropy string detected heuristically
    HighEntropy,
}

/// A known credential pattern that can be detected in text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialPattern {
    /// Human-readable name for this pattern (e.g., "AWS Access Key").
    pub name: String,
    /// Regex pattern to match.
    pub pattern: String,
    /// What to replace matches with. Use `$name` for dynamic replacement.
    pub replacement: String,
    /// Category of secret this pattern detects.
    #[serde(default = "default_category")]
    pub category: SecretCategory,
}

fn default_category() -> SecretCategory {
    SecretCategory::Token
}

/// Allowlist for suppressing known false positives.
///
/// After a pattern match is found, the matched text is checked against all
/// allowlist entries. If any entry matches, the finding is suppressed.
pub struct AllowList {
    entries: Vec<(String, Regex)>,
}

impl AllowList {
    /// Create an allowlist from regex pattern strings.
    pub fn new(patterns: Vec<(String, String)>) -> Self {
        let entries = patterns
            .into_iter()
            .filter_map(|(name, pat)| Regex::new(&pat).ok().map(|r| (name, r)))
            .collect();
        Self { entries }
    }

    /// Create the default built-in allowlist.
    pub fn defaults() -> Self {
        Self::new(default_allowlist())
    }

    /// Check if a matched text should be suppressed by the allowlist.
    pub fn is_allowed(&self, matched_text: &str) -> bool {
        self.entries.iter().any(|(_, regex)| regex.is_match(matched_text))
    }

    /// Get the number of allowlist entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Get the names of all allowlist entries.
    pub fn entry_names(&self) -> Vec<&str> {
        self.entries.iter().map(|(name, _)| name.as_str()).collect()
    }

    /// Load additional allowlist entries from a TOML file.
    ///
    /// Expected format:
    /// ```toml
    /// [[rules]]
    /// name = "My custom rule"
    /// pattern = "my_pattern"
    /// ```
    pub fn load_from_file(&mut self, path: &std::path::Path) -> anyhow::Result<()> {
        let content = std::fs::read_to_string(path)?;
        let table: toml::Value = content.parse()?;
        if let Some(rules) = table.get("rules").and_then(|v| v.as_array()) {
            for rule in rules {
                let name = rule.get("name").and_then(|v| v.as_str()).unwrap_or("custom");
                let pattern = rule.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
                if let Ok(regex) = Regex::new(pattern) {
                    self.entries.push((name.to_string(), regex));
                }
            }
        }
        Ok(())
    }
}

/// Default allowlist entries for suppressing known false positives.
pub fn default_allowlist() -> Vec<(String, String)> {
    vec![
        // Email false positives
        ("noreply emails".into(), r"noreply@".into()),
        ("example.com emails".into(), r"@example\.com".into()),
        ("localhost emails".into(), r"@localhost".into()),
        ("GitHub noreply".into(), r"@users\.noreply\.github\.com".into()),
        // Decorator/annotation false positives
        ("Python @pytest".into(), r"@pytest".into()),
        ("Python @app".into(), r"@app\.".into()),
        ("Python @router".into(), r"@router\.".into()),
        ("Python @tasks".into(), r"@tasks\.".into()),
        ("Python @server".into(), r"@server\.".into()),
        ("Python @mcp".into(), r"@mcp\.".into()),
        ("Rust #[test]".into(), r"#\[test\]".into()),
        ("Rust #[derive]".into(), r"#\[derive".into()),
        // Example/documentation URLs
        ("example postgres URL".into(), r"postgres://user:pass@".into()),
        ("example postgres URL 2".into(), r"postgres://username:password@".into()),
        ("example mysql URL".into(), r"mysql://user:pass@".into()),
        ("example mongodb URL".into(), r"mongodb://user:pass@".into()),
        // Private/reserved IPs (low risk)
        ("private IP 192.168.x".into(), r"192\.168\.".into()),
        ("private IP 10.x".into(), r"10\.\d+\.\d+\.\d+".into()),
        ("private IP 172.16-31.x".into(), r"172\.(?:1[6-9]|2\d|3[01])\.".into()),
        ("loopback".into(), r"127\.0\.0\.".into()),
        ("zero address".into(), r"0\.0\.0\.0".into()),
        // Well-known public DNS
        ("Google DNS".into(), r"8\.8\.8\.8".into()),
        ("Google DNS 2".into(), r"8\.8\.4\.4".into()),
        ("Cloudflare DNS".into(), r"1\.1\.1\.1".into()),
        // Regex pattern strings in source code (discussing patterns, not actual secrets)
        ("AWS key regex".into(), r"AKIA\[".into()),
        ("API key regex".into(), r"sk-ant-\.\*".into()),
    ]
}

/// Compute Shannon entropy of a string. Higher values indicate more random-looking strings.
pub fn shannon_entropy(s: &str) -> f64 {
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

/// Check if a string has mixed character types (uppercase + lowercase + digits).
pub fn has_mixed_char_types(s: &str) -> bool {
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = s.chars().any(|c| c.is_ascii_digit());
    has_upper && has_lower && has_digit
}

/// Check if a string looks like a high-entropy secret (not a version string, domain, etc.).
fn is_high_entropy_secret(s: &str) -> bool {
    // Strip quotes if present
    let inner = s.trim_matches(|c| c == '\'' || c == '"');
    if inner.len() < 40 {
        return false;
    }
    // Must have mixed character types
    if !has_mixed_char_types(inner) {
        return false;
    }
    // Must have high entropy
    if shannon_entropy(inner) < 3.5 {
        return false;
    }
    // Skip strings with too many dots (likely domain names or version strings)
    if inner.chars().filter(|&c| c == '.').count() > 2 {
        return false;
    }
    true
}

/// The redaction engine: scans text and replaces credential patterns.
pub struct RedactionEngine {
    patterns: Vec<(CredentialPattern, Regex)>,
    allowlist: Option<AllowList>,
    entropy_enabled: bool,
}

impl RedactionEngine {
    /// Create a new engine with the given patterns (no allowlist, entropy enabled).
    pub fn new(patterns: Vec<CredentialPattern>) -> Self {
        let compiled: Vec<(CredentialPattern, Regex)> = patterns
            .into_iter()
            .filter_map(|p| {
                Regex::new(&p.pattern).ok().map(|r| (p, r))
            })
            .collect();
        Self { patterns: compiled, allowlist: None, entropy_enabled: true }
    }

    /// Create an engine with the default built-in patterns, allowlist, and entropy checking.
    pub fn with_defaults() -> Self {
        let mut engine = Self::new(default_patterns());
        engine.allowlist = Some(AllowList::defaults());
        engine
    }

    /// Set the allowlist for this engine.
    pub fn set_allowlist(&mut self, allowlist: AllowList) {
        self.allowlist = Some(allowlist);
    }

    /// Enable or disable entropy-based validation for high-entropy matches.
    pub fn set_entropy_enabled(&mut self, enabled: bool) {
        self.entropy_enabled = enabled;
    }

    /// Add a custom pattern to the engine.
    pub fn add_pattern(&mut self, pattern: CredentialPattern) {
        if let Ok(regex) = Regex::new(&pattern.pattern) {
            self.patterns.push((pattern, regex));
        }
    }

    /// Get the number of registered patterns.
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Get the registered pattern names.
    pub fn pattern_names(&self) -> Vec<&str> {
        self.patterns.iter().map(|(p, _)| p.name.as_str()).collect()
    }

    /// Scan text and return all matches found (filtered by allowlist and entropy checks).
    pub fn scan(&self, text: &str) -> Vec<RedactionMatch> {
        let mut matches = Vec::new();
        for (pattern, regex) in &self.patterns {
            for m in regex.find_iter(text) {
                let matched_text = m.as_str().to_string();
                // Check allowlist — skip if any allowlist entry matches
                if let Some(ref al) = self.allowlist {
                    if al.is_allowed(&matched_text) {
                        continue;
                    }
                }
                // For high-entropy patterns, validate with entropy check
                if pattern.category == SecretCategory::HighEntropy
                    && self.entropy_enabled
                    && !is_high_entropy_secret(&matched_text)
                {
                    continue;
                }
                matches.push(RedactionMatch {
                    pattern_name: pattern.name.clone(),
                    category: pattern.category,
                    start: m.start(),
                    end: m.end(),
                    matched_text,
                });
            }
        }
        // Sort by position for consistent output
        matches.sort_by_key(|m| m.start);
        matches
    }

    /// Redact all credential patterns in text, replacing with markers.
    /// Respects the allowlist: matched text that passes an allowlist rule is not redacted.
    pub fn redact(&self, text: &str) -> String {
        // Collect all matches with their replacements, filtered by allowlist + entropy
        let mut replacements: Vec<(usize, usize, String)> = Vec::new();
        for (pattern, regex) in &self.patterns {
            for m in regex.find_iter(text) {
                let matched_text = m.as_str();
                if let Some(ref al) = self.allowlist {
                    if al.is_allowed(matched_text) {
                        continue;
                    }
                }
                if pattern.category == SecretCategory::HighEntropy
                    && self.entropy_enabled
                    && !is_high_entropy_secret(matched_text)
                {
                    continue;
                }
                replacements.push((m.start(), m.end(), pattern.replacement.clone()));
            }
        }

        if replacements.is_empty() {
            return text.to_string();
        }

        // Sort by start position ascending, then by length descending (longest match wins)
        replacements.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| (b.1 - b.0).cmp(&(a.1 - a.0))));

        // Deduplicate overlapping ranges: keep the first (earliest start, longest) match
        let mut deduped: Vec<(usize, usize, String)> = Vec::new();
        for r in replacements {
            if let Some(last) = deduped.last() {
                if r.0 < last.1 {
                    // Overlaps with previous — skip
                    continue;
                }
            }
            deduped.push(r);
        }

        // Replace from end to start to preserve indices
        let mut result = text.to_string();
        for (start, end, replacement) in deduped.into_iter().rev() {
            result.replace_range(start..end, &replacement);
        }
        result
    }

    /// Redact text, returning both the redacted text and the matches found.
    pub fn redact_with_matches(&self, text: &str) -> (String, Vec<RedactionMatch>) {
        let matches = self.scan(text);
        let redacted = self.redact(text);
        (redacted, matches)
    }
}

/// A secret value from the vault, paired with its entry title for informative redaction.
#[derive(Debug, Clone)]
pub struct VaultSecret {
    /// The actual secret value (password, API key, etc.)
    pub value: String,
    /// Title of the vault entry this secret belongs to.
    pub entry_title: String,
}

/// Vault-aware redactor using Aho-Corasick for O(n) multi-pattern matching.
///
/// Instead of only regex pattern matching, this does exact-match against every
/// credential value stored in the vault. This catches secrets in ANY format,
/// even ones no regex would detect.
pub struct VaultAwareRedactor {
    automaton: AhoCorasick,
    /// Parallel array: automaton pattern index → (entry_title, secret_value_len)
    labels: Vec<(String, usize)>,
}

impl VaultAwareRedactor {
    /// Build a vault-aware redactor from vault secrets.
    ///
    /// Filters out secrets shorter than `min_length` to avoid false positives.
    /// Uses longest-match-first semantics.
    pub fn new(secrets: Vec<VaultSecret>, min_length: usize) -> Option<Self> {
        let filtered: Vec<VaultSecret> = secrets
            .into_iter()
            .filter(|s| s.value.len() >= min_length && !s.value.trim().is_empty())
            .collect();

        if filtered.is_empty() {
            return None;
        }

        // Deduplicate by value, keeping the first entry title
        let mut seen = HashMap::new();
        let mut deduped: Vec<VaultSecret> = Vec::new();
        for s in filtered {
            if !seen.contains_key(&s.value) {
                seen.insert(s.value.clone(), true);
                deduped.push(s);
            }
        }

        let patterns: Vec<&str> = deduped.iter().map(|s| s.value.as_str()).collect();
        let labels: Vec<(String, usize)> = deduped
            .iter()
            .map(|s| (s.entry_title.clone(), s.value.len()))
            .collect();

        // Build Aho-Corasick with longest-match-first semantics
        let automaton = AhoCorasick::builder()
            .match_kind(aho_corasick::MatchKind::LeftmostLongest)
            .build(&patterns)
            .ok()?;

        Some(Self { automaton, labels })
    }

    /// Scan text for vault secret matches.
    pub fn scan(&self, text: &str) -> Vec<RedactionMatch> {
        self.automaton
            .find_iter(text)
            .map(|m| {
                let (ref title, _) = self.labels[m.pattern().as_usize()];
                RedactionMatch {
                    pattern_name: format!("vault:{title}"),
                    category: SecretCategory::ApiKey, // vault secrets are high-confidence
                    start: m.start(),
                    end: m.end(),
                    matched_text: text[m.start()..m.end()].to_string(),
                }
            })
            .collect()
    }

    /// Redact vault secrets in text, replacing with `[VAULT:entry_title]`.
    pub fn redact(&self, text: &str) -> String {
        let mut result = String::with_capacity(text.len());
        let mut last_end = 0;
        for m in self.automaton.find_iter(text) {
            let (ref title, _) = self.labels[m.pattern().as_usize()];
            result.push_str(&text[last_end..m.start()]);
            result.push_str(&format!("[VAULT:{title}]"));
            last_end = m.end();
        }
        result.push_str(&text[last_end..]);
        result
    }

    /// Number of secrets loaded into the automaton.
    pub fn secret_count(&self) -> usize {
        self.labels.len()
    }
}

/// A credential pattern match found in text.
#[derive(Debug, Clone)]
pub struct RedactionMatch {
    pub pattern_name: String,
    pub category: SecretCategory,
    pub start: usize,
    pub end: usize,
    pub matched_text: String,
}

/// Built-in credential patterns covering common services.
/// Ordered from most specific to least specific to avoid partial matches.
pub fn default_patterns() -> Vec<CredentialPattern> {
    vec![
        // ── Most specific patterns first ──

        // JWT tokens — full 3-segment form (before generic base64)
        CredentialPattern {
            name: "JWT Token".into(),
            pattern: r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}".into(),
            replacement: "[REDACTED:jwt]".into(),
            category: SecretCategory::Token,
        },
        // JWT tokens — partial (header only or truncated)
        CredentialPattern {
            name: "JWT Partial".into(),
            pattern: r"eyJ[A-Za-z0-9_-]{15,}".into(),
            replacement: "[REDACTED:jwt-partial]".into(),
            category: SecretCategory::Token,
        },
        // Database connection strings with passwords (postgres, mysql, mongodb)
        CredentialPattern {
            name: "Database URL".into(),
            pattern: "(?:postgres(?:ql)?|mysql|mongodb(?:\\+srv)?)://[^:@\\s]+:[^@\\s]+@[^\\s\"'`]+".into(),
            replacement: "[REDACTED:database-url]".into(),
            category: SecretCategory::DatabaseUrl,
        },
        // Anthropic API key
        CredentialPattern {
            name: "Anthropic API Key".into(),
            pattern: r"sk-ant-[A-Za-z0-9_-]{20,}".into(),
            replacement: "[REDACTED:anthropic-key]".into(),
            category: SecretCategory::ApiKey,
        },
        // OpenAI API key
        CredentialPattern {
            name: "OpenAI API Key".into(),
            pattern: r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}".into(),
            replacement: "[REDACTED:openai-key]".into(),
            category: SecretCategory::ApiKey,
        },
        // Hugging Face tokens
        CredentialPattern {
            name: "HuggingFace Token".into(),
            pattern: r"hf_[A-Za-z0-9]{20,}".into(),
            replacement: "[REDACTED:hf-token]".into(),
            category: SecretCategory::ApiKey,
        },
        // GitHub tokens
        CredentialPattern {
            name: "GitHub Token".into(),
            pattern: r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}".into(),
            replacement: "[REDACTED:github-token]".into(),
            category: SecretCategory::ApiKey,
        },
        // PyPI tokens
        CredentialPattern {
            name: "PyPI Token".into(),
            pattern: r"pypi-[A-Za-z0-9_-]{50,}".into(),
            replacement: "[REDACTED:pypi-token]".into(),
            category: SecretCategory::ApiKey,
        },
        // NPM tokens
        CredentialPattern {
            name: "NPM Token".into(),
            pattern: r"npm_[A-Za-z0-9]{30,}".into(),
            replacement: "[REDACTED:npm-token]".into(),
            category: SecretCategory::ApiKey,
        },
        // AWS Access Key
        CredentialPattern {
            name: "AWS Access Key".into(),
            pattern: r"(?:^|[^A-Z0-9\[])(?P<key>AKIA[0-9A-Z]{16})(?:[^A-Z0-9\]{}]|$)".into(),
            replacement: " [REDACTED:aws-key] ".into(),
            category: SecretCategory::ApiKey,
        },
        // AWS Secret Key (key=value form)
        CredentialPattern {
            name: "AWS Secret Key".into(),
            pattern: r#"(?i)(?:aws_secret_access_key|secret_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"#.into(),
            replacement: "[REDACTED:aws-secret]".into(),
            category: SecretCategory::ApiKey,
        },
        // Slack tokens
        CredentialPattern {
            name: "Slack Token".into(),
            pattern: r"xox[bpars]-[A-Za-z0-9-]{20,}".into(),
            replacement: "[REDACTED:slack-token]".into(),
            category: SecretCategory::Token,
        },
        // Discord webhook URLs
        CredentialPattern {
            name: "Discord Webhook".into(),
            pattern: r"https?://(?:discord\.com|discordapp\.com)/api/webhooks/\d+/[A-Za-z0-9_-]{20,}".into(),
            replacement: "[REDACTED:discord-webhook]".into(),
            category: SecretCategory::Token,
        },
        // Private key blocks (BEGIN to END markers)
        CredentialPattern {
            name: "Private Key".into(),
            pattern: r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----".into(),
            replacement: "[REDACTED:private-key-header]".into(),
            category: SecretCategory::PrivateKey,
        },
        // CLI flags that pass tokens/secrets: --token VALUE, --api-key VALUE, etc.
        CredentialPattern {
            name: "CLI Token Flag".into(),
            pattern: r"(?i)(?:--|-)(?:access[_-]?token|auth[_-]?token|api[_-]?key|secret|password|token)[\s=]+([A-Za-z0-9_/+=.\-]{8,})".into(),
            replacement: "[REDACTED:cli-token]".into(),
            category: SecretCategory::Token,
        },
        // Environment variable assignments with secret-like names
        CredentialPattern {
            name: "Env Secret".into(),
            pattern: r#"(?i)(?:SECRET|PASSWORD|TOKEN|API_KEY|AUTH_KEY|ACCESS_KEY|SERVICE_KEY|DB_PASSWORD|SUPABASE_KEY|SUPABASE_SERVICE|ANON_KEY|SERVICE_ROLE)\s*=\s*['"]?([^\s'"]{6,})['"]?"#.into(),
            replacement: "[REDACTED:env-secret]".into(),
            category: SecretCategory::Token,
        },
        // Generic secret assignments in code: api_key: "value", secret_key = "value"
        CredentialPattern {
            name: "Generic Secret Assignment".into(),
            pattern: r#"(?i)(?:secret[_-]?key|api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|service[_-]?role[_-]?key|private[_-]?key)\s*[=:]\s*['"]([A-Za-z0-9_/+=.\-]{20,})['"]"#.into(),
            replacement: "[REDACTED:secret-assignment]".into(),
            category: SecretCategory::Token,
        },
        // Bearer tokens in headers
        CredentialPattern {
            name: "Bearer Token".into(),
            pattern: r"Bearer\s+[A-Za-z0-9_.\-/+=]{20,}".into(),
            replacement: "Bearer [REDACTED:token]".into(),
            category: SecretCategory::Token,
        },
        // URL query parameters with secrets: ?key=VALUE, &token=VALUE
        CredentialPattern {
            name: "URL Secret Param".into(),
            pattern: r"(?i)[?&](?:key|token|secret|password|apikey|api_key|access_token|auth)=([A-Za-z0-9_/+=.\-]{8,})".into(),
            replacement: "[REDACTED:url-param]".into(),
            category: SecretCategory::Token,
        },
        // Generic long hex secrets (32+ hex chars, common in API keys)
        CredentialPattern {
            name: "Hex Secret".into(),
            pattern: r#"(?:secret|token|key|password|api_key|apikey|auth)[\s:=]+['"]?([0-9a-f]{32,})['"]?"#.into(),
            replacement: "[REDACTED:hex-secret]".into(),
            category: SecretCategory::Token,
        },
        // Generic password in URLs
        CredentialPattern {
            name: "URL Password".into(),
            pattern: r"://[^:@\s]+:([^@\s]{8,})@".into(),
            replacement: "://[user]:[REDACTED:url-password]@".into(),
            category: SecretCategory::DatabaseUrl,
        },
        // Email addresses (PII)
        CredentialPattern {
            name: "Email Address".into(),
            pattern: r"\b[A-Za-z0-9._%+-]{2,}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b".into(),
            replacement: "[REDACTED:email]".into(),
            category: SecretCategory::Pii,
        },
        // Public IP addresses (matches all IPv4; allowlist filters private/loopback)
        CredentialPattern {
            name: "Public IP".into(),
            pattern: r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b".into(),
            replacement: "[REDACTED:ip]".into(),
            category: SecretCategory::Pii,
        },
        // High-entropy quoted strings (catch-all, checked last)
        CredentialPattern {
            name: "High Entropy String".into(),
            pattern: r#"['"][A-Za-z0-9_/+=.\-]{40,}['"]"#.into(),
            replacement: "[REDACTED:high-entropy]".into(),
            category: SecretCategory::HighEntropy,
        },
    ]
}

/// Convenience function: redact text with default patterns.
pub fn redact_text(text: &str) -> String {
    let engine = RedactionEngine::with_defaults();
    engine.redact(text)
}

/// Convenience function: scan text for credentials with default patterns.
pub fn scan_text(text: &str) -> Vec<RedactionMatch> {
    let engine = RedactionEngine::with_defaults();
    engine.scan(text)
}

/// Confidence level for a redaction finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Confidence {
    /// Vault-aware exact match or specific pattern match
    High,
    /// Generic pattern match (hex secret, generic assignment)
    Medium,
    /// Entropy-based heuristic detection
    Low,
}

/// A finding from the unified redaction pipeline, with confidence level.
#[derive(Debug, Clone, Serialize)]
pub struct PipelineFinding {
    pub pattern_name: String,
    pub category: SecretCategory,
    pub confidence: Confidence,
    pub start: usize,
    pub end: usize,
    #[serde(skip_serializing)]
    pub matched_text: String,
}

/// Summary report from the redaction pipeline.
#[derive(Debug, Clone, Serialize)]
pub struct RedactionReport {
    pub total_findings: usize,
    pub by_category: HashMap<String, usize>,
    pub by_confidence: HashMap<String, usize>,
    pub findings: Vec<PipelineFinding>,
}

impl RedactionReport {
    fn from_findings(findings: &[PipelineFinding]) -> Self {
        let mut by_category: HashMap<String, usize> = HashMap::new();
        let mut by_confidence: HashMap<String, usize> = HashMap::new();
        for f in findings {
            *by_category.entry(format!("{:?}", f.category)).or_insert(0) += 1;
            *by_confidence.entry(format!("{:?}", f.confidence)).or_insert(0) += 1;
        }
        Self {
            total_findings: findings.len(),
            by_category,
            by_confidence,
            findings: findings.to_vec(),
        }
    }
}

/// Unified redaction pipeline combining all detection layers.
///
/// Pipeline order:
/// 1. Vault-aware exact match (highest confidence)
/// 2. Specific pattern match (JWT, API keys, etc.)
/// 3. Entropy-based detection (catch-all)
/// 4. PII anonymization (usernames, paths, emails)
/// 5. Allowlist suppression (applied at steps 1-3)
/// 6. Custom string redaction (user-configured)
pub struct RedactionPipeline {
    engine: RedactionEngine,
    vault_redactor: Option<VaultAwareRedactor>,
    anonymizer: Option<super::anonymize::Anonymizer>,
    custom_strings: Vec<String>,
}

impl RedactionPipeline {
    /// Create a new pipeline with default patterns and allowlist.
    pub fn new() -> Self {
        Self {
            engine: RedactionEngine::with_defaults(),
            vault_redactor: None,
            anonymizer: None,
            custom_strings: Vec::new(),
        }
    }

    /// Set the vault-aware redactor (requires unlocked vault).
    pub fn set_vault_redactor(&mut self, redactor: VaultAwareRedactor) {
        self.vault_redactor = Some(redactor);
    }

    /// Set the PII anonymizer.
    pub fn set_anonymizer(&mut self, anonymizer: super::anonymize::Anonymizer) {
        self.anonymizer = Some(anonymizer);
    }

    /// Add custom string(s) to redact.
    pub fn add_custom_strings(&mut self, strings: Vec<String>) {
        self.custom_strings.extend(strings);
    }

    /// Disable entropy-based detection.
    pub fn disable_entropy(&mut self) {
        self.engine.set_entropy_enabled(false);
    }

    /// Scan text and return all findings with confidence levels.
    pub fn scan(&self, text: &str) -> Vec<PipelineFinding> {
        let mut findings = Vec::new();

        // Step 1: Vault-aware exact match (highest confidence)
        if let Some(ref vr) = self.vault_redactor {
            for m in vr.scan(text) {
                findings.push(PipelineFinding {
                    pattern_name: m.pattern_name,
                    category: m.category,
                    confidence: Confidence::High,
                    start: m.start,
                    end: m.end,
                    matched_text: m.matched_text,
                });
            }
        }

        // Step 2+3: Pattern match + entropy (filtered by allowlist)
        for m in self.engine.scan(text) {
            // Skip if overlapping with a vault match
            if findings.iter().any(|f| m.start < f.end && m.end > f.start) {
                continue;
            }
            let confidence = match m.category {
                SecretCategory::HighEntropy => Confidence::Low,
                SecretCategory::Pii => Confidence::Medium,
                _ => Confidence::High,
            };
            findings.push(PipelineFinding {
                pattern_name: m.pattern_name,
                category: m.category,
                confidence,
                start: m.start,
                end: m.end,
                matched_text: m.matched_text,
            });
        }

        findings.sort_by_key(|f| f.start);
        findings
    }

    /// Redact text through the full pipeline, returning redacted text.
    pub fn redact(&self, text: &str) -> String {
        let mut result = text.to_string();

        // Step 1: Vault-aware exact match
        if let Some(ref vr) = self.vault_redactor {
            result = vr.redact(&result);
        }

        // Step 2+3: Pattern-based + entropy redaction
        result = self.engine.redact(&result);

        // Step 4: PII anonymization
        if let Some(ref anon) = self.anonymizer {
            result = anon.text(&result);
        }

        // Step 6: Custom string redaction
        for custom in &self.custom_strings {
            if custom.len() >= 3 {
                result = result.replace(custom, "[REDACTED:custom]");
            }
        }

        result
    }

    /// Redact text and generate a detailed report.
    pub fn redact_with_report(&self, text: &str) -> (String, RedactionReport) {
        let findings = self.scan(text);
        let redacted = self.redact(text);
        let report = RedactionReport::from_findings(&findings);
        (redacted, report)
    }
}

impl Default for RedactionPipeline {
    fn default() -> Self {
        Self::new()
    }
}

/// Redact sensitive environment variables from a key-value map.
/// Returns a new map with sensitive values replaced.
pub fn redact_env_vars(env: &[(String, String)]) -> Vec<(String, String)> {
    let sensitive_keys = [
        "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN",
        "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
        "DATABASE_URL", "DB_PASSWORD",
        "SECRET_KEY", "API_KEY", "API_SECRET",
        "PRIVATE_KEY", "SSH_PRIVATE_KEY",
        "SLACK_TOKEN", "SLACK_BOT_TOKEN",
        "TELEGRAM_BOT_TOKEN",
    ];

    let engine = RedactionEngine::with_defaults();

    env.iter()
        .map(|(k, v)| {
            let upper_key = k.to_uppercase();
            let redacted = if sensitive_keys.iter().any(|sk| upper_key == *sk)
                || upper_key.contains("SECRET")
                || upper_key.contains("PASSWORD")
                || upper_key.contains("TOKEN")
                || upper_key.contains("PRIVATE_KEY")
            {
                "[REDACTED]".to_string()
            } else {
                // Also scan the value for credential patterns
                engine.redact(v)
            };
            (k.clone(), redacted)
        })
        .collect()
}

/// List of filesystem paths that commonly contain credentials.
/// These should be blocked from exec output.
pub fn sensitive_paths() -> Vec<&'static str> {
    vec![
        "~/.ssh/id_rsa",
        "~/.ssh/id_ed25519",
        "~/.ssh/id_ecdsa",
        "~/.ssh/id_dsa",
        "~/.aws/credentials",
        "~/.aws/config",
        "~/.netrc",
        "~/.npmrc",
        "~/.pypirc",
        "~/.docker/config.json",
        "~/.kube/config",
        "~/.gnupg/",
        "~/.config/gh/hosts.yml",
        ".env",
        ".env.local",
        ".env.production",
    ]
}

/// Check if a command's output might contain sensitive data based on the command.
pub fn is_sensitive_command(cmd: &str) -> bool {
    let sensitive = ["env", "printenv", "set", "export", "cat ~/.ssh", "cat ~/.aws",
        "cat .env", "cat ~/.netrc", "echo $", "echo ${"];
    sensitive.iter().any(|s| cmd.contains(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_patterns_compile() {
        let engine = RedactionEngine::with_defaults();
        assert!(engine.pattern_count() > 0);
    }

    #[test]
    fn test_pattern_count_expanded() {
        let engine = RedactionEngine::with_defaults();
        assert!(engine.pattern_count() >= 20, "Expected 20+ patterns, got {}", engine.pattern_count());
    }

    #[test]
    fn test_secret_category_on_match() {
        let engine = RedactionEngine::with_defaults();
        let text = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let matches = engine.scan(text);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].category, SecretCategory::ApiKey);
    }

    // ── Existing patterns (preserved) ──

    #[test]
    fn test_redact_github_token() {
        let engine = RedactionEngine::with_defaults();
        let text = "My token is ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij and more";
        let redacted = engine.redact(text);
        assert!(!redacted.contains("ghp_"));
        assert!(redacted.contains("[REDACTED:github-token]"));
    }

    #[test]
    fn test_redact_aws_key() {
        let engine = RedactionEngine::with_defaults();
        let text = "key= AKIAIOSFODNN7EXAMPLE ";
        let redacted = engine.redact(text);
        assert!(!redacted.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(redacted.contains("[REDACTED:aws-key]"));
    }

    #[test]
    fn test_redact_bearer_token() {
        let engine = RedactionEngine::with_defaults();
        let text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWI";
        let redacted = engine.redact(text);
        assert!(!redacted.contains("eyJhbGciOi"));
        assert!(redacted.contains("[REDACTED"));
    }

    #[test]
    fn test_redact_private_key_header() {
        let engine = RedactionEngine::with_defaults();
        let text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAI...";
        let redacted = engine.redact(text);
        assert!(!redacted.contains("BEGIN RSA PRIVATE KEY"));
        assert!(redacted.contains("[REDACTED:private-key-header]"));
    }

    #[test]
    fn test_redact_url_password() {
        let engine = RedactionEngine::with_defaults();
        let text = "postgres://admin:supersecretpassword@db.example.com:5432/mydb";
        let redacted = engine.redact(text);
        assert!(!redacted.contains("supersecretpassword"));
        assert!(redacted.contains("[REDACTED"));
    }

    #[test]
    fn test_no_false_positives_on_normal_text() {
        let engine = RedactionEngine::with_defaults();
        let text = "Hello world, this is a normal message with no secrets.";
        let redacted = engine.redact(text);
        assert_eq!(redacted, text);
    }

    #[test]
    fn test_scan_returns_matches() {
        let engine = RedactionEngine::with_defaults();
        let text = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let matches = engine.scan(text);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern_name, "GitHub Token");
    }

    #[test]
    fn test_redact_with_matches() {
        let engine = RedactionEngine::with_defaults();
        let text = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let (redacted, matches) = engine.redact_with_matches(text);
        assert!(!matches.is_empty());
        assert!(redacted.contains("[REDACTED"));
    }

    #[test]
    fn test_custom_pattern() {
        let mut engine = RedactionEngine::new(vec![]);
        engine.add_pattern(CredentialPattern {
            name: "Custom Token".into(),
            pattern: r"MYAPP_[A-Z0-9]{16}".into(),
            replacement: "[REDACTED:myapp]".into(),
            category: SecretCategory::Token,
        });

        let text = "token=MYAPP_ABCDEFGHIJKLMNOP";
        let redacted = engine.redact(text);
        assert!(redacted.contains("[REDACTED:myapp]"));
    }

    #[test]
    fn test_invalid_regex_pattern_skipped() {
        let engine = RedactionEngine::new(vec![CredentialPattern {
            name: "Bad Pattern".into(),
            pattern: r"[invalid regex".into(),
            replacement: "[REDACTED]".into(),
            category: SecretCategory::Token,
        }]);
        assert_eq!(engine.pattern_count(), 0);
    }

    #[test]
    fn test_pattern_names() {
        let engine = RedactionEngine::with_defaults();
        let names = engine.pattern_names();
        assert!(names.contains(&"GitHub Token"));
        assert!(names.contains(&"AWS Access Key"));
    }

    #[test]
    fn test_redact_text_convenience() {
        let text = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let redacted = redact_text(text);
        assert!(redacted.contains("[REDACTED"));
    }

    #[test]
    fn test_scan_text_convenience() {
        let text = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let matches = scan_text(text);
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_redact_env_vars() {
        let env = vec![
            ("PATH".into(), "/usr/bin".into()),
            ("GITHUB_TOKEN".into(), "ghp_secret123".into()),
            ("AWS_SECRET_ACCESS_KEY".into(), "myawssecret".into()),
            ("HOME".into(), "/home/user".into()),
            ("MY_SECRET".into(), "hidden".into()),
            ("DB_PASSWORD".into(), "pass123".into()),
        ];

        let redacted = redact_env_vars(&env);
        assert_eq!(redacted.iter().find(|(k, _)| k == "PATH").unwrap().1, "/usr/bin");
        assert_eq!(redacted.iter().find(|(k, _)| k == "GITHUB_TOKEN").unwrap().1, "[REDACTED]");
        assert_eq!(redacted.iter().find(|(k, _)| k == "AWS_SECRET_ACCESS_KEY").unwrap().1, "[REDACTED]");
        assert_eq!(redacted.iter().find(|(k, _)| k == "HOME").unwrap().1, "/home/user");
        assert_eq!(redacted.iter().find(|(k, _)| k == "MY_SECRET").unwrap().1, "[REDACTED]");
        assert_eq!(redacted.iter().find(|(k, _)| k == "DB_PASSWORD").unwrap().1, "[REDACTED]");
    }

    #[test]
    fn test_redact_env_vars_value_scanning() {
        let env = vec![
            ("SOME_VAR".into(), "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij".into()),
        ];
        let redacted = redact_env_vars(&env);
        assert!(redacted[0].1.contains("[REDACTED"));
    }

    #[test]
    fn test_sensitive_paths() {
        let paths = sensitive_paths();
        assert!(paths.contains(&"~/.ssh/id_rsa"));
        assert!(paths.contains(&".env"));
        assert!(paths.contains(&"~/.aws/credentials"));
    }

    #[test]
    fn test_is_sensitive_command() {
        assert!(is_sensitive_command("env"));
        assert!(is_sensitive_command("printenv"));
        assert!(is_sensitive_command("cat ~/.ssh/id_rsa"));
        assert!(is_sensitive_command("cat .env"));
        assert!(is_sensitive_command("echo $SECRET"));
        assert!(!is_sensitive_command("ls -la"));
        assert!(!is_sensitive_command("git status"));
    }

    #[test]
    fn test_redact_slack_token() {
        let engine = RedactionEngine::with_defaults();
        let text = "token: xoxb-1234567890123-1234567890123-abcDEFghiJKL";
        let redacted = engine.redact(text);
        assert!(redacted.contains("[REDACTED:slack-token]"));
    }

    #[test]
    fn test_redact_hex_secret() {
        let engine = RedactionEngine::with_defaults();
        // Use a key name that triggers hex-secret specifically
        let text = "auth= deadbeef0123456789abcdef0123456789abcdef";
        let redacted = engine.redact(text);
        assert!(redacted.contains("[REDACTED"),
            "Hex secret not redacted: {}", redacted);
    }

    #[test]
    fn test_redact_ec_private_key() {
        let engine = RedactionEngine::with_defaults();
        let text = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQ...";
        let redacted = engine.redact(text);
        assert!(redacted.contains("[REDACTED:private-key-header]"));
    }

    #[test]
    fn test_redact_openssh_private_key() {
        let engine = RedactionEngine::with_defaults();
        let text = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn...";
        let redacted = engine.redact(text);
        assert!(redacted.contains("[REDACTED:private-key-header]"));
    }

    #[test]
    fn test_multiple_matches_in_same_text() {
        let engine = RedactionEngine::with_defaults();
        let text = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij and also -----BEGIN RSA PRIVATE KEY-----";
        let matches = engine.scan(text);
        assert!(matches.len() >= 2);
    }

    #[test]
    fn test_credential_pattern_serialization() {
        let pattern = CredentialPattern {
            name: "Test".into(),
            pattern: r"\d+".into(),
            replacement: "[REDACTED]".into(),
            category: SecretCategory::Token,
        };
        let json = serde_json::to_string(&pattern).unwrap();
        let parsed: CredentialPattern = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "Test");
        assert_eq!(parsed.category, SecretCategory::Token);
    }

    #[test]
    fn test_scan_empty_text() {
        let engine = RedactionEngine::with_defaults();
        let matches = engine.scan("");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_redact_empty_text() {
        let engine = RedactionEngine::with_defaults();
        assert_eq!(engine.redact(""), "");
    }

    // ── New pattern tests (2 per new pattern) ──

    #[test]
    fn test_redact_jwt_full() {
        let engine = RedactionEngine::with_defaults();
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let redacted = engine.redact(jwt);
        assert!(redacted.contains("[REDACTED:jwt]"), "JWT not redacted: {}", redacted);
        assert!(!redacted.contains("eyJhbGciOi"));
    }

    #[test]
    fn test_jwt_no_false_positive() {
        let engine = RedactionEngine::with_defaults();
        let text = "The function returns eyJ which is not a JWT";
        let matches = engine.scan(text);
        assert!(matches.is_empty() || !matches.iter().any(|m| m.pattern_name.contains("JWT")));
    }

    #[test]
    fn test_redact_jwt_partial() {
        let engine = RedactionEngine::with_defaults();
        let text = "truncated token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let redacted = engine.redact(text);
        assert!(redacted.contains("[REDACTED:jwt"), "JWT partial not redacted: {}", redacted);
    }

    #[test]
    fn test_redact_database_url_postgres() {
        let engine = RedactionEngine::with_defaults();
        let text = "DATABASE_URL=postgres://user:s3cretP4ss@db.host.com:5432/mydb";
        let redacted = engine.redact(text);
        assert!(!redacted.contains("s3cretP4ss"), "DB password not redacted: {}", redacted);
    }

    #[test]
    fn test_redact_database_url_mysql() {
        let engine = RedactionEngine::with_defaults();
        let text = "mysql://root:hunter2@db.prod.example.com:3306/app";
        let redacted = engine.redact(text);
        assert!(!redacted.contains("hunter2"), "MySQL password not redacted: {}", redacted);
    }

    #[test]
    fn test_redact_database_url_mongodb() {
        let engine = RedactionEngine::with_defaults();
        let text = "mongodb+srv://admin:p4ssw0rd@cluster.mongodb.net/test";
        let redacted = engine.redact(text);
        assert!(!redacted.contains("p4ssw0rd"), "MongoDB password not redacted: {}", redacted);
    }

    #[test]
    fn test_redact_anthropic_key() {
        let engine = RedactionEngine::with_defaults();
        let text = "ANTHROPIC_API_KEY=sk-ant-abc123XYZ_defghijklmnop-0123456789";
        let redacted = engine.redact(text);
        assert!(redacted.contains("[REDACTED:anthropic-key]") || redacted.contains("[REDACTED:env-secret]"));
        assert!(!redacted.contains("sk-ant-abc123"));
    }

    #[test]
    fn test_redact_huggingface_token() {
        let engine = RedactionEngine::with_defaults();
        let text = "export HF_TOKEN=hf_ABCDEFghijklmnopQRSTUVwxyz1234567890";
        let redacted = engine.redact(text);
        assert!(!redacted.contains("hf_ABCDEF"), "HF token not redacted: {}", redacted);
    }

    #[test]
    fn test_huggingface_no_false_positive() {
        let engine = RedactionEngine::with_defaults();
        // Short "hf_" prefix shouldn't trigger
        let text = "This file is hf_ab";
        let matches = engine.scan(text);
        assert!(!matches.iter().any(|m| m.pattern_name == "HuggingFace Token"));
    }

    #[test]
    fn test_redact_pypi_token() {
        let engine = RedactionEngine::with_defaults();
        let token = format!("pypi-{}", "A".repeat(60));
        let redacted = engine.redact(&token);
        assert!(redacted.contains("[REDACTED:pypi-token]"), "PyPI token not redacted: {}", redacted);
    }

    #[test]
    fn test_pypi_no_false_positive() {
        let engine = RedactionEngine::with_defaults();
        let text = "pypi-short";
        let matches = engine.scan(text);
        assert!(!matches.iter().any(|m| m.pattern_name == "PyPI Token"));
    }

    #[test]
    fn test_redact_npm_token() {
        let engine = RedactionEngine::with_defaults();
        let token = format!("npm_{}", "A".repeat(36));
        let redacted = engine.redact(&token);
        assert!(redacted.contains("[REDACTED:npm-token]"), "NPM token not redacted: {}", redacted);
    }

    #[test]
    fn test_npm_no_false_positive() {
        let engine = RedactionEngine::with_defaults();
        let text = "npm_short";
        let matches = engine.scan(text);
        assert!(!matches.iter().any(|m| m.pattern_name == "NPM Token"));
    }

    #[test]
    fn test_redact_discord_webhook() {
        let engine = RedactionEngine::with_defaults();
        let text = "https://discord.com/api/webhooks/123456789/ABCDEFGHIJKLMNOPQRSTuvwxyz1234567890";
        let redacted = engine.redact(text);
        assert!(redacted.contains("[REDACTED:discord-webhook]"), "Discord webhook not redacted: {}", redacted);
    }

    #[test]
    fn test_discord_webhook_no_false_positive() {
        let engine = RedactionEngine::with_defaults();
        let text = "https://discord.com/api/channels/123456789";
        let matches = engine.scan(text);
        assert!(!matches.iter().any(|m| m.pattern_name == "Discord Webhook"));
    }

    #[test]
    fn test_redact_cli_token_flag() {
        let engine = RedactionEngine::with_defaults();
        let text = "curl --token abcDEF123456789_secret --url http://example.com";
        let redacted = engine.redact(text);
        assert!(redacted.contains("[REDACTED:cli-token]"), "CLI token not redacted: {}", redacted);
    }

    #[test]
    fn test_cli_flag_with_equals() {
        let engine = RedactionEngine::with_defaults();
        let text = "--api-key=sk_live_ABCDef123456ghij";
        let redacted = engine.redact(text);
        assert!(redacted.contains("[REDACTED:cli-token]"), "CLI flag not redacted: {}", redacted);
    }

    #[test]
    fn test_redact_env_secret_assignment() {
        let engine = RedactionEngine::with_defaults();
        let text = "SECRET=myVeryLongSecretValue123";
        let redacted = engine.redact(text);
        assert!(redacted.contains("[REDACTED:env-secret]"), "Env secret not redacted: {}", redacted);
    }

    #[test]
    fn test_env_secret_quoted() {
        let engine = RedactionEngine::with_defaults();
        let text = r#"API_KEY="ABCdef_1234567890_ghijkl""#;
        let redacted = engine.redact(text);
        assert!(redacted.contains("[REDACTED"), "Env secret quoted not redacted: {}", redacted);
    }

    #[test]
    fn test_redact_generic_secret_assignment() {
        let engine = RedactionEngine::with_defaults();
        let text = r#"api_key: "dGhpcyBpcyBhIHNlY3JldCBrZXkgdmFsdWUhISE""#;
        let redacted = engine.redact(text);
        assert!(redacted.contains("[REDACTED"), "Generic secret not redacted: {}", redacted);
    }

    #[test]
    fn test_generic_secret_no_false_positive() {
        let engine = RedactionEngine::with_defaults();
        let text = r#"description: "short""#;
        let matches = engine.scan(text);
        assert!(!matches.iter().any(|m| m.pattern_name == "Generic Secret Assignment"));
    }

    #[test]
    fn test_redact_url_secret_param() {
        let engine = RedactionEngine::with_defaults();
        let text = "https://api.example.com/v1?key=aBcDeFgHiJkLmNoPqRsTuVwXyZ123456";
        let redacted = engine.redact(text);
        assert!(redacted.contains("[REDACTED:url-param]"), "URL param not redacted: {}", redacted);
    }

    #[test]
    fn test_url_param_no_false_positive() {
        let engine = RedactionEngine::with_defaults();
        let text = "https://example.com?page=2&sort=name";
        let matches = engine.scan(text);
        assert!(!matches.iter().any(|m| m.pattern_name == "URL Secret Param"));
    }

    #[test]
    fn test_redact_email() {
        let engine = RedactionEngine::with_defaults();
        let text = "Contact us at user@company.com for info";
        let redacted = engine.redact(text);
        assert!(redacted.contains("[REDACTED:email]"), "Email not redacted: {}", redacted);
    }

    #[test]
    fn test_email_no_false_positive() {
        let engine = RedactionEngine::with_defaults();
        let text = "x@y is not a real email";
        let matches = engine.scan(text);
        assert!(!matches.iter().any(|m| m.pattern_name == "Email Address"));
    }

    #[test]
    fn test_redact_public_ip() {
        let engine = RedactionEngine::with_defaults();
        let text = "Server is at 203.0.113.42 on port 443";
        let redacted = engine.redact(text);
        assert!(redacted.contains("[REDACTED:ip]"), "Public IP not redacted: {}", redacted);
    }

    #[test]
    fn test_ip_loopback_suppressed_by_allowlist() {
        let engine = RedactionEngine::with_defaults();
        let text = "localhost is 127.0.0.1";
        let matches = engine.scan(text);
        assert!(!matches.iter().any(|m| m.pattern_name == "Public IP"),
            "Loopback should be suppressed by allowlist");
    }

    #[test]
    fn test_ip_private_suppressed_by_allowlist() {
        let engine = RedactionEngine::with_defaults();
        let text = "Router at 192.168.1.1";
        let matches = engine.scan(text);
        assert!(!matches.iter().any(|m| m.pattern_name == "Public IP"),
            "Private IP should be suppressed by allowlist");
    }

    #[test]
    fn test_redact_high_entropy_string() {
        let engine = RedactionEngine::with_defaults();
        let text = r#"config = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7bC9dE1fG3hI5""#;
        let redacted = engine.redact(text);
        assert!(redacted.contains("[REDACTED"), "High entropy not redacted: {}", redacted);
    }

    #[test]
    fn test_high_entropy_short_not_matched() {
        let engine = RedactionEngine::with_defaults();
        let text = r#"msg = "hello world""#;
        let matches = engine.scan(text);
        assert!(!matches.iter().any(|m| m.pattern_name == "High Entropy String"));
    }

    #[test]
    fn test_redact_aws_secret_key() {
        let engine = RedactionEngine::with_defaults();
        let text = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let redacted = engine.redact(text);
        // May be caught by aws-secret or env-secret pattern depending on match position
        assert!(redacted.contains("[REDACTED"), "AWS secret not redacted: {}", redacted);
        assert!(!redacted.contains("wJalrXUtnFEMI"));
    }

    #[test]
    fn test_aws_secret_key_no_false_positive() {
        let engine = RedactionEngine::with_defaults();
        let text = "some_other_key = short";
        let matches = engine.scan(text);
        assert!(!matches.iter().any(|m| m.pattern_name == "AWS Secret Key"));
    }

    #[test]
    fn test_category_database_url() {
        let engine = RedactionEngine::with_defaults();
        let text = "postgres://user:password123@host:5432/db";
        let matches = engine.scan(text);
        let db_match = matches.iter().find(|m| m.pattern_name == "Database URL");
        assert!(db_match.is_some(), "Should find Database URL match");
        assert_eq!(db_match.unwrap().category, SecretCategory::DatabaseUrl);
    }

    #[test]
    fn test_category_private_key() {
        let engine = RedactionEngine::with_defaults();
        let text = "-----BEGIN RSA PRIVATE KEY-----";
        let matches = engine.scan(text);
        assert!(!matches.is_empty());
        let pk_match = matches.iter().find(|m| m.pattern_name == "Private Key");
        assert!(pk_match.is_some());
        assert_eq!(pk_match.unwrap().category, SecretCategory::PrivateKey);
    }

    #[test]
    fn test_category_pii_email() {
        let engine = RedactionEngine::with_defaults();
        let text = "user@company.com";
        let matches = engine.scan(text);
        let email_match = matches.iter().find(|m| m.pattern_name == "Email Address");
        assert!(email_match.is_some());
        assert_eq!(email_match.unwrap().category, SecretCategory::Pii);
    }

    #[test]
    fn test_secret_category_serialization() {
        let cat = SecretCategory::ApiKey;
        let json = serde_json::to_string(&cat).unwrap();
        let parsed: SecretCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, SecretCategory::ApiKey);
    }

    // ── Allowlist tests ──

    #[test]
    fn test_allowlist_defaults_created() {
        let al = AllowList::defaults();
        assert!(al.entry_count() > 0);
    }

    #[test]
    fn test_allowlist_suppresses_noreply_email() {
        let engine = RedactionEngine::with_defaults();
        let text = "bot@users.noreply.github.com";
        let matches = engine.scan(text);
        assert!(!matches.iter().any(|m| m.pattern_name == "Email Address"),
            "noreply email should be suppressed by allowlist");
    }

    #[test]
    fn test_allowlist_suppresses_example_email() {
        let engine = RedactionEngine::with_defaults();
        let text = "test@example.com";
        let matches = engine.scan(text);
        assert!(!matches.iter().any(|m| m.pattern_name == "Email Address"),
            "@example.com should be suppressed by allowlist");
    }

    #[test]
    fn test_allowlist_suppresses_google_dns() {
        let engine = RedactionEngine::with_defaults();
        let text = "DNS server at 8.8.8.8";
        let matches = engine.scan(text);
        assert!(!matches.iter().any(|m| m.pattern_name == "Public IP"),
            "8.8.8.8 should be suppressed by allowlist");
    }

    #[test]
    fn test_allowlist_suppresses_cloudflare_dns() {
        let engine = RedactionEngine::with_defaults();
        let text = "DNS server at 1.1.1.1";
        let matches = engine.scan(text);
        assert!(!matches.iter().any(|m| m.pattern_name == "Public IP"),
            "1.1.1.1 should be suppressed by allowlist");
    }

    #[test]
    fn test_allowlist_suppresses_private_10_ip() {
        let engine = RedactionEngine::with_defaults();
        let text = "internal at 10.0.0.1";
        let matches = engine.scan(text);
        assert!(!matches.iter().any(|m| m.pattern_name == "Public IP"),
            "10.x.x.x should be suppressed by allowlist");
    }

    #[test]
    fn test_allowlist_suppresses_example_db_url() {
        let engine = RedactionEngine::with_defaults();
        let text = "Example: postgres://user:pass@localhost/mydb";
        let matches = engine.scan(text);
        assert!(!matches.iter().any(|m| m.pattern_name == "Database URL"),
            "Example DB URL should be suppressed by allowlist");
    }

    #[test]
    fn test_allowlist_does_not_suppress_real_secret() {
        let engine = RedactionEngine::with_defaults();
        let text = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let matches = engine.scan(text);
        assert!(matches.iter().any(|m| m.pattern_name == "GitHub Token"),
            "Real secret should not be suppressed");
    }

    #[test]
    fn test_allowlist_custom_entry() {
        let mut al = AllowList::defaults();
        al.entries.push(("custom".into(), Regex::new(r"SAFE_TOKEN").unwrap()));
        let mut engine = RedactionEngine::new(default_patterns());
        engine.set_allowlist(al);
        let text = "token: SAFE_TOKEN_ABCDEFGHIJKLMNOPQRSTUVWXYZab";
        let matches = engine.scan(text);
        // The custom allowlist entry suppresses this
        assert!(matches.is_empty() || !matches.iter().any(|m| m.matched_text.contains("SAFE_TOKEN")));
    }

    #[test]
    fn test_allowlist_entry_names() {
        let al = AllowList::defaults();
        let names = al.entry_names();
        assert!(names.contains(&"loopback"));
        assert!(names.contains(&"Google DNS"));
        assert!(names.contains(&"noreply emails"));
    }

    #[test]
    fn test_allowlist_load_from_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("allowlist.toml");
        std::fs::write(&path, r#"
[[rules]]
name = "my rule"
pattern = "SAFE_.*"
"#).unwrap();

        let mut al = AllowList::defaults();
        let before = al.entry_count();
        al.load_from_file(&path).unwrap();
        assert_eq!(al.entry_count(), before + 1);
        assert!(al.is_allowed("SAFE_thing"));
    }

    #[test]
    fn test_redact_respects_allowlist() {
        let engine = RedactionEngine::with_defaults();
        // noreply email should not be redacted
        let text = "From noreply@service.com to user@company.com";
        let redacted = engine.redact(text);
        // noreply@ should be preserved, real email should be redacted
        assert!(redacted.contains("noreply@service.com"), "noreply should be preserved: {}", redacted);
        assert!(redacted.contains("[REDACTED:email]"), "real email should be redacted: {}", redacted);
    }

    // ── Entropy detection tests ──

    #[test]
    fn test_shannon_entropy_empty() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn test_shannon_entropy_uniform() {
        // All same character — entropy = 0
        assert_eq!(shannon_entropy("aaaaaaa"), 0.0);
    }

    #[test]
    fn test_shannon_entropy_high() {
        // Random-looking string should have high entropy
        let s = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z";
        let e = shannon_entropy(s);
        assert!(e > 4.0, "Expected high entropy, got {}", e);
    }

    #[test]
    fn test_shannon_entropy_english() {
        // English text has moderate entropy; the key insight is that it doesn't
        // also pass has_mixed_char_types, so it won't be flagged as a secret
        let s = "the quick brown fox jumps over the lazy dog";
        let e = shannon_entropy(s);
        assert!(e > 0.0 && e < 5.0, "English text entropy should be moderate, got {}", e);
        // English text lacks mixed char types (no uppercase, no digits)
        assert!(!has_mixed_char_types(s), "English text should not have mixed char types");
    }

    #[test]
    fn test_has_mixed_char_types_true() {
        assert!(has_mixed_char_types("aB3"));
    }

    #[test]
    fn test_has_mixed_char_types_missing_digit() {
        assert!(!has_mixed_char_types("aBcDeFg"));
    }

    #[test]
    fn test_has_mixed_char_types_missing_upper() {
        assert!(!has_mixed_char_types("abc123"));
    }

    #[test]
    fn test_high_entropy_validated() {
        let engine = RedactionEngine::with_defaults();
        // High-entropy secret: mixed chars, >40 chars, high entropy
        let secret = r#"config = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7bC9dE1fG3hI5""#;
        let matches = engine.scan(secret);
        assert!(matches.iter().any(|m| m.category == SecretCategory::HighEntropy),
            "Should detect high entropy string");
    }

    #[test]
    fn test_low_entropy_not_matched() {
        let engine = RedactionEngine::with_defaults();
        // Repeated characters — low entropy, should NOT be flagged
        let text = r#"padding = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA""#;
        let matches = engine.scan(text);
        assert!(!matches.iter().any(|m| m.category == SecretCategory::HighEntropy),
            "Low-entropy string should not be flagged");
    }

    #[test]
    fn test_version_string_not_high_entropy() {
        let engine = RedactionEngine::with_defaults();
        // Version string with dots — should be skipped by entropy check
        let text = r#"ver = "1.2.3.4.5.6.7.8.9.0.1.2.3.4.5.6.7.8.9.0.1.2.3.4.5.6.7.8.9.0.1.2.3.4""#;
        let matches = engine.scan(text);
        assert!(!matches.iter().any(|m| m.category == SecretCategory::HighEntropy),
            "Version string should not be flagged as high entropy");
    }

    #[test]
    fn test_entropy_disabled() {
        let mut engine = RedactionEngine::with_defaults();
        engine.set_entropy_enabled(false);
        // With entropy disabled, high-entropy patterns match without validation
        let text = r#"pad = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA""#;
        let matches = engine.scan(text);
        // Without entropy check, the pattern regex still matches, but since entropy is disabled
        // the validation is skipped — all regex matches pass through
        assert!(matches.iter().any(|m| m.pattern_name == "High Entropy String"),
            "With entropy disabled, all regex matches should pass through");
    }

    #[test]
    fn test_is_high_entropy_secret_function() {
        // Positive: actual secret-looking string
        assert!(is_high_entropy_secret(r#""aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7bC9""#));
        // Negative: too short
        assert!(!is_high_entropy_secret(r#""short""#));
        // Negative: no mixed chars
        assert!(!is_high_entropy_secret(&format!(r#""{}""#, "A".repeat(50))));
    }

    // ── Vault-aware redaction tests ──

    #[test]
    fn test_vault_redactor_basic() {
        let secrets = vec![
            VaultSecret { value: "MyS3cretP@ss!".into(), entry_title: "GitHub".into() },
            VaultSecret { value: "sk-ant-api03-longkey123".into(), entry_title: "Anthropic".into() },
        ];
        let redactor = VaultAwareRedactor::new(secrets, 6).unwrap();
        assert_eq!(redactor.secret_count(), 2);

        let text = "Password is MyS3cretP@ss! and key is sk-ant-api03-longkey123";
        let redacted = redactor.redact(text);
        assert!(redacted.contains("[VAULT:GitHub]"), "Should contain vault label: {}", redacted);
        assert!(redacted.contains("[VAULT:Anthropic]"), "Should contain vault label: {}", redacted);
        assert!(!redacted.contains("MyS3cretP@ss!"));
        assert!(!redacted.contains("sk-ant-api03-longkey123"));
    }

    #[test]
    fn test_vault_redactor_short_secrets_filtered() {
        let secrets = vec![
            VaultSecret { value: "ab".into(), entry_title: "Short".into() },
            VaultSecret { value: "longer_secret_value".into(), entry_title: "Long".into() },
        ];
        let redactor = VaultAwareRedactor::new(secrets, 6).unwrap();
        assert_eq!(redactor.secret_count(), 1); // Only the long one
    }

    #[test]
    fn test_vault_redactor_empty() {
        let secrets: Vec<VaultSecret> = vec![];
        assert!(VaultAwareRedactor::new(secrets, 6).is_none());
    }

    #[test]
    fn test_vault_redactor_scan() {
        let secrets = vec![
            VaultSecret { value: "hunter2_secret".into(), entry_title: "MyService".into() },
        ];
        let redactor = VaultAwareRedactor::new(secrets, 6).unwrap();
        let text = "The password is hunter2_secret in the config";
        let matches = redactor.scan(text);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern_name, "vault:MyService");
        assert_eq!(matches[0].matched_text, "hunter2_secret");
    }

    #[test]
    fn test_vault_redactor_multiple_occurrences() {
        let secrets = vec![
            VaultSecret { value: "my_api_key_value".into(), entry_title: "API Key".into() },
        ];
        let redactor = VaultAwareRedactor::new(secrets, 6).unwrap();
        let text = "key1=my_api_key_value key2=my_api_key_value";
        let redacted = redactor.redact(text);
        assert_eq!(redacted, "key1=[VAULT:API Key] key2=[VAULT:API Key]");
    }

    #[test]
    fn test_vault_redactor_longest_match() {
        let secrets = vec![
            VaultSecret { value: "secret".into(), entry_title: "Short".into() },
            VaultSecret { value: "secret_extended_value".into(), entry_title: "Long".into() },
        ];
        let redactor = VaultAwareRedactor::new(secrets, 6).unwrap();
        let text = "pw=secret_extended_value here";
        let redacted = redactor.redact(text);
        assert!(redacted.contains("[VAULT:Long]"), "Should match longest: {}", redacted);
    }

    #[test]
    fn test_vault_redactor_no_match() {
        let secrets = vec![
            VaultSecret { value: "specific_secret".into(), entry_title: "Test".into() },
        ];
        let redactor = VaultAwareRedactor::new(secrets, 6).unwrap();
        let text = "This text has no secrets at all";
        let redacted = redactor.redact(text);
        assert_eq!(redacted, text);
    }

    #[test]
    fn test_vault_redactor_deduplicates() {
        let secrets = vec![
            VaultSecret { value: "same_password".into(), entry_title: "Service A".into() },
            VaultSecret { value: "same_password".into(), entry_title: "Service B".into() },
        ];
        let redactor = VaultAwareRedactor::new(secrets, 6).unwrap();
        assert_eq!(redactor.secret_count(), 1); // Deduplicated
    }

    #[test]
    fn test_vault_redactor_performance() {
        // Test with many secrets — should still be O(n)
        let secrets: Vec<VaultSecret> = (0..1000)
            .map(|i| VaultSecret {
                value: format!("secret_value_{i:04}_padding_for_length"),
                entry_title: format!("Entry {i}"),
            })
            .collect();
        let redactor = VaultAwareRedactor::new(secrets, 6).unwrap();
        assert_eq!(redactor.secret_count(), 1000);

        let text = "normal text with secret_value_0042_padding_for_length embedded";
        let redacted = redactor.redact(text);
        assert!(redacted.contains("[VAULT:Entry 42]"), "Should find secret 42: {}", redacted);
    }

    // ── Pipeline tests ──

    #[test]
    fn test_pipeline_basic() {
        let pipeline = RedactionPipeline::new();
        let text = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let redacted = pipeline.redact(text);
        assert!(redacted.contains("[REDACTED:github-token]"));
    }

    #[test]
    fn test_pipeline_with_vault_redactor() {
        let mut pipeline = RedactionPipeline::new();
        let secrets = vec![
            VaultSecret { value: "MyVaultPassword123!".into(), entry_title: "MyService".into() },
        ];
        pipeline.set_vault_redactor(VaultAwareRedactor::new(secrets, 6).unwrap());

        let text = "Login with MyVaultPassword123! for the service";
        let redacted = pipeline.redact(text);
        assert!(redacted.contains("[VAULT:MyService]"), "Should vault-redact: {}", redacted);
    }

    #[test]
    fn test_pipeline_with_custom_strings() {
        let mut pipeline = RedactionPipeline::new();
        pipeline.add_custom_strings(vec!["COMPANY_INTERNAL".into()]);

        let text = "This is a COMPANY_INTERNAL document";
        let redacted = pipeline.redact(text);
        assert!(redacted.contains("[REDACTED:custom]"));
    }

    #[test]
    fn test_pipeline_scan_with_confidence() {
        let pipeline = RedactionPipeline::new();
        let text = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij at 203.0.113.1";
        let findings = pipeline.scan(text);
        assert!(!findings.is_empty());
        // GitHub token should be high confidence
        let gh = findings.iter().find(|f| f.pattern_name == "GitHub Token");
        assert!(gh.is_some());
        assert_eq!(gh.unwrap().confidence, Confidence::High);
    }

    #[test]
    fn test_pipeline_report() {
        let pipeline = RedactionPipeline::new();
        let text = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij and -----BEGIN RSA PRIVATE KEY-----";
        let (redacted, report) = pipeline.redact_with_report(text);
        assert!(report.total_findings >= 2);
        assert!(!report.by_category.is_empty());
        assert!(!report.by_confidence.is_empty());
        assert!(redacted.contains("[REDACTED"));
    }

    #[test]
    fn test_pipeline_default() {
        let pipeline = RedactionPipeline::default();
        assert_eq!(pipeline.redact("hello"), "hello");
    }

    #[test]
    fn test_pipeline_vault_takes_priority() {
        // Vault-aware match should prevent pattern match on same region
        let mut pipeline = RedactionPipeline::new();
        let secrets = vec![
            VaultSecret {
                value: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij".into(),
                entry_title: "GitHub Token".into(),
            },
        ];
        pipeline.set_vault_redactor(VaultAwareRedactor::new(secrets, 6).unwrap());

        let findings = pipeline.scan("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
        // Should find it via vault, not pattern
        assert_eq!(findings.len(), 1);
        assert!(findings[0].pattern_name.starts_with("vault:"));
    }

    #[test]
    fn test_pipeline_disable_entropy() {
        let mut pipeline = RedactionPipeline::new();
        pipeline.disable_entropy();
        // Low-entropy string that would be filtered by entropy check
        let text = r#"pad = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA""#;
        let findings = pipeline.scan(text);
        // With entropy disabled, the regex matches but no entropy validation
        assert!(findings.iter().any(|f| f.pattern_name == "High Entropy String"));
    }

    #[test]
    fn test_report_serialization() {
        let pipeline = RedactionPipeline::new();
        let (_, report) = pipeline.redact_with_report("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("total_findings"));
        assert!(json.contains("by_category"));
    }

    #[test]
    fn test_confidence_serialization() {
        let c = Confidence::High;
        let json = serde_json::to_string(&c).unwrap();
        let parsed: Confidence = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, Confidence::High);
    }
}
