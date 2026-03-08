use serde::{Deserialize, Serialize};

use super::report::SecurityReport;
use super::rotation::RotationSummary;

/// Trait for LLM backends that generate security insights.
pub trait LlmClient: Send + Sync {
    /// Generate a security narrative from a report.
    fn generate_report_narrative(&self, context: &LlmReportContext) -> Result<String, LlmError>;

    /// Generate rotation recommendations.
    fn generate_rotation_advice(&self, context: &LlmRotationContext) -> Result<String, LlmError>;
}

/// Context passed to the LLM for report generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmReportContext {
    pub grade: String,
    pub health_score: u8,
    pub total_entries: usize,
    pub weak_passwords: usize,
    pub reused_passwords: usize,
    pub old_passwords: usize,
    pub entries_without_totp: usize,
    pub recommendation_count: usize,
    pub critical_issues: usize,
}

impl LlmReportContext {
    pub fn from_report(report: &SecurityReport) -> Self {
        Self {
            grade: format!("{:?}", report.summary.grade),
            health_score: report.health.health_score,
            total_entries: report.health.total_entries,
            weak_passwords: report.health.weak_passwords,
            reused_passwords: report.health.reused_passwords,
            old_passwords: report.health.old_passwords,
            entries_without_totp: report.health.entries_without_totp,
            recommendation_count: report.recommendations.len(),
            critical_issues: report.summary.critical_issues,
        }
    }
}

/// Context passed to the LLM for rotation advice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmRotationContext {
    pub pending_rotations: usize,
    pub completed_rotations: usize,
    pub failed_rotations: usize,
    pub entry_titles: Vec<String>,
    pub triggers: Vec<String>,
}

impl LlmRotationContext {
    pub fn from_summary(summary: &RotationSummary, entry_titles: Vec<String>, triggers: Vec<String>) -> Self {
        Self {
            pending_rotations: summary.pending,
            completed_rotations: summary.completed,
            failed_rotations: summary.failed,
            entry_titles,
            triggers,
        }
    }
}

/// Errors from LLM operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LlmError {
    /// The LLM service is unavailable.
    Unavailable(String),
    /// Rate limit exceeded.
    RateLimited,
    /// Invalid response from LLM.
    InvalidResponse(String),
    /// No LLM backend configured.
    NotConfigured,
}

impl std::fmt::Display for LlmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LlmError::Unavailable(msg) => write!(f, "LLM unavailable: {}", msg),
            LlmError::RateLimited => write!(f, "LLM rate limited"),
            LlmError::InvalidResponse(msg) => write!(f, "Invalid LLM response: {}", msg),
            LlmError::NotConfigured => write!(f, "No LLM backend configured"),
        }
    }
}

/// Prompt templates for security analysis.
pub struct PromptTemplates;

impl PromptTemplates {
    /// Build a prompt for generating a security report narrative.
    pub fn report_narrative(context: &LlmReportContext) -> String {
        format!(
            "You are a cybersecurity advisor analyzing a password vault.\n\
             \n\
             Vault Statistics:\n\
             - Security Grade: {}\n\
             - Health Score: {}/100\n\
             - Total entries: {}\n\
             - Weak passwords: {}\n\
             - Reused passwords: {}\n\
             - Old passwords (>1 year): {}\n\
             - Without 2FA: {}\n\
             - Critical issues: {}\n\
             - Total recommendations: {}\n\
             \n\
             Provide a brief (3-5 sentences) security assessment. Be specific about the \
             most important action the user should take. Do not mention specific entry names.",
            context.grade,
            context.health_score,
            context.total_entries,
            context.weak_passwords,
            context.reused_passwords,
            context.old_passwords,
            context.entries_without_totp,
            context.critical_issues,
            context.recommendation_count,
        )
    }

    /// Build a prompt for rotation advice.
    pub fn rotation_advice(context: &LlmRotationContext) -> String {
        let titles = if context.entry_titles.is_empty() {
            "none".to_string()
        } else {
            context.entry_titles.join(", ")
        };
        let triggers = if context.triggers.is_empty() {
            "none".to_string()
        } else {
            context.triggers.join(", ")
        };

        format!(
            "You are a cybersecurity advisor helping with password rotation.\n\
             \n\
             Rotation Status:\n\
             - Pending rotations: {}\n\
             - Completed rotations: {}\n\
             - Failed rotations: {}\n\
             - Entries needing rotation: {}\n\
             - Triggers: {}\n\
             \n\
             Provide brief (2-3 sentences) prioritization advice for which passwords \
             to rotate first and why. Focus on practical security impact.",
            context.pending_rotations,
            context.completed_rotations,
            context.failed_rotations,
            titles,
            triggers,
        )
    }
}

/// An LLM-enhanced security report combining static analysis with AI insights.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedReport {
    /// The base security report.
    pub report: SecurityReport,
    /// AI-generated narrative summary (if available).
    pub narrative: Option<String>,
    /// Whether the narrative was generated by an LLM or is a fallback.
    pub llm_generated: bool,
}

impl EnhancedReport {
    /// Create an enhanced report without LLM (static fallback).
    pub fn without_llm(report: SecurityReport) -> Self {
        let narrative = generate_static_narrative(&report);
        Self {
            report,
            narrative: Some(narrative),
            llm_generated: false,
        }
    }

    /// Create an enhanced report with LLM narrative.
    pub fn with_llm(report: SecurityReport, client: &dyn LlmClient) -> Self {
        let context = LlmReportContext::from_report(&report);
        match client.generate_report_narrative(&context) {
            Ok(narrative) => Self {
                report,
                narrative: Some(narrative),
                llm_generated: true,
            },
            Err(_) => Self::without_llm(report),
        }
    }
}

/// Generate a static (non-LLM) narrative from a security report.
pub fn generate_static_narrative(report: &SecurityReport) -> String {
    let mut parts = Vec::new();

    parts.push(format!(
        "Your vault has a {} security grade (score: {}/100) across {} entries.",
        report.summary.grade.label(),
        report.health.health_score,
        report.health.total_entries,
    ));

    if report.summary.critical_issues > 0 {
        parts.push(format!(
            "There are {} critical issue(s) that need immediate attention.",
            report.summary.critical_issues
        ));
    }

    if report.health.weak_passwords > 0 {
        parts.push(format!(
            "You have {} weak password(s) that should be strengthened.",
            report.health.weak_passwords
        ));
    }

    if report.health.reused_passwords > 0 {
        parts.push(format!(
            "{} entries share reused passwords — each should have a unique password.",
            report.health.reused_passwords
        ));
    }

    if report.health.old_passwords > 0 {
        parts.push(format!(
            "{} password(s) haven't been changed in over a year.",
            report.health.old_passwords
        ));
    }

    if report.health.entries_without_totp > 0 {
        parts.push(format!(
            "Consider enabling 2FA on {} login(s) that lack it.",
            report.health.entries_without_totp
        ));
    }

    if report.summary.critical_issues == 0
        && report.health.weak_passwords == 0
        && report.health.reused_passwords == 0
    {
        parts.push("Your passwords are in good shape. Keep it up!".to_string());
    }

    parts.join(" ")
}

/// Format an enhanced report as human-readable text.
pub fn format_enhanced_report(enhanced: &EnhancedReport) -> String {
    let mut output = super::report::format_report_text(&enhanced.report);

    if let Some(narrative) = &enhanced.narrative {
        output.push_str("--- AI Insights ---\n");
        if enhanced.llm_generated {
            output.push_str("[Generated by LLM]\n");
        }
        output.push_str(narrative);
        output.push('\n');
    }

    output
}

/// A mock LLM client for testing.
#[derive(Debug)]
pub struct MockLlmClient {
    pub response: Result<String, LlmError>,
}

impl MockLlmClient {
    pub fn success(response: impl Into<String>) -> Self {
        Self {
            response: Ok(response.into()),
        }
    }

    pub fn error(error: LlmError) -> Self {
        Self {
            response: Err(error),
        }
    }
}

impl LlmClient for MockLlmClient {
    fn generate_report_narrative(&self, _context: &LlmReportContext) -> Result<String, LlmError> {
        self.response.clone()
    }

    fn generate_rotation_advice(&self, _context: &LlmRotationContext) -> Result<String, LlmError> {
        self.response.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::report::generate_report;
    use crate::security::rotation::RotationSummary;
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

    fn empty_report() -> SecurityReport {
        generate_report(&[])
    }

    fn weak_report() -> SecurityReport {
        let e1 = login("Weak", "123");
        let e2 = login("Reused1", "same_pass");
        let e3 = login("Reused2", "same_pass");
        generate_report(&[&e1, &e2, &e3])
    }

    // ---- LlmReportContext tests ----

    #[test]
    fn test_llm_report_context_from_empty_report() {
        let report = empty_report();
        let ctx = LlmReportContext::from_report(&report);
        assert_eq!(ctx.health_score, 100);
        assert_eq!(ctx.total_entries, 0);
        assert_eq!(ctx.critical_issues, 0);
    }

    #[test]
    fn test_llm_report_context_from_weak_report() {
        let report = weak_report();
        let ctx = LlmReportContext::from_report(&report);
        assert!(ctx.weak_passwords > 0);
        assert!(ctx.critical_issues > 0);
    }

    #[test]
    fn test_llm_report_context_serialization() {
        let ctx = LlmReportContext {
            grade: "A".into(),
            health_score: 95,
            total_entries: 10,
            weak_passwords: 0,
            reused_passwords: 0,
            old_passwords: 0,
            entries_without_totp: 2,
            recommendation_count: 1,
            critical_issues: 0,
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let parsed: LlmReportContext = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.health_score, 95);
    }

    // ---- LlmRotationContext tests ----

    #[test]
    fn test_llm_rotation_context_from_summary() {
        let summary = RotationSummary {
            total_plans: 3,
            pending: 2,
            approved: 0,
            rotating: 0,
            completed: 1,
            failed: 0,
            dismissed: 0,
        };
        let ctx = LlmRotationContext::from_summary(
            &summary,
            vec!["GitHub".into(), "AWS".into()],
            vec!["weak".into(), "old".into()],
        );
        assert_eq!(ctx.pending_rotations, 2);
        assert_eq!(ctx.entry_titles.len(), 2);
    }

    #[test]
    fn test_llm_rotation_context_serialization() {
        let ctx = LlmRotationContext {
            pending_rotations: 1,
            completed_rotations: 0,
            failed_rotations: 0,
            entry_titles: vec!["Test".into()],
            triggers: vec!["weak".into()],
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let parsed: LlmRotationContext = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.pending_rotations, 1);
    }

    // ---- LlmError tests ----

    #[test]
    fn test_llm_error_display() {
        assert!(LlmError::Unavailable("down".into()).to_string().contains("unavailable"));
        assert!(LlmError::RateLimited.to_string().contains("rate limited"));
        assert!(LlmError::InvalidResponse("bad".into()).to_string().contains("Invalid"));
        assert!(LlmError::NotConfigured.to_string().contains("No LLM backend configured"));
    }

    #[test]
    fn test_llm_error_serialization() {
        let errors = vec![
            LlmError::Unavailable("down".into()),
            LlmError::RateLimited,
            LlmError::InvalidResponse("bad".into()),
            LlmError::NotConfigured,
        ];
        for err in errors {
            let json = serde_json::to_string(&err).unwrap();
            let parsed: LlmError = serde_json::from_str(&json).unwrap();
            assert_eq!(format!("{}", parsed), format!("{}", err));
        }
    }

    // ---- PromptTemplates tests ----

    #[test]
    fn test_report_narrative_prompt() {
        let ctx = LlmReportContext::from_report(&empty_report());
        let prompt = PromptTemplates::report_narrative(&ctx);
        assert!(prompt.contains("cybersecurity advisor"));
        assert!(prompt.contains("Health Score: 100"));
        assert!(prompt.contains("3-5 sentences"));
    }

    #[test]
    fn test_rotation_advice_prompt() {
        let ctx = LlmRotationContext {
            pending_rotations: 2,
            completed_rotations: 1,
            failed_rotations: 0,
            entry_titles: vec!["GitHub".into()],
            triggers: vec!["weak".into()],
        };
        let prompt = PromptTemplates::rotation_advice(&ctx);
        assert!(prompt.contains("password rotation"));
        assert!(prompt.contains("GitHub"));
        assert!(prompt.contains("weak"));
    }

    #[test]
    fn test_rotation_advice_prompt_empty() {
        let ctx = LlmRotationContext {
            pending_rotations: 0,
            completed_rotations: 0,
            failed_rotations: 0,
            entry_titles: vec![],
            triggers: vec![],
        };
        let prompt = PromptTemplates::rotation_advice(&ctx);
        assert!(prompt.contains("none"));
    }

    // ---- MockLlmClient tests ----

    #[test]
    fn test_mock_llm_success() {
        let client = MockLlmClient::success("Great security!");
        let ctx = LlmReportContext::from_report(&empty_report());
        let result = client.generate_report_narrative(&ctx);
        assert_eq!(result.unwrap(), "Great security!");
    }

    #[test]
    fn test_mock_llm_error() {
        let client = MockLlmClient::error(LlmError::NotConfigured);
        let ctx = LlmReportContext::from_report(&empty_report());
        let result = client.generate_report_narrative(&ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_mock_llm_rotation_advice() {
        let client = MockLlmClient::success("Rotate GitHub first.");
        let ctx = LlmRotationContext {
            pending_rotations: 1,
            completed_rotations: 0,
            failed_rotations: 0,
            entry_titles: vec!["GitHub".into()],
            triggers: vec!["weak".into()],
        };
        let result = client.generate_rotation_advice(&ctx);
        assert_eq!(result.unwrap(), "Rotate GitHub first.");
    }

    // ---- EnhancedReport tests ----

    #[test]
    fn test_enhanced_report_without_llm() {
        let report = empty_report();
        let enhanced = EnhancedReport::without_llm(report);
        assert!(!enhanced.llm_generated);
        assert!(enhanced.narrative.is_some());
    }

    #[test]
    fn test_enhanced_report_with_llm_success() {
        let report = empty_report();
        let client = MockLlmClient::success("AI says: all good!");
        let enhanced = EnhancedReport::with_llm(report, &client);
        assert!(enhanced.llm_generated);
        assert_eq!(enhanced.narrative.as_deref(), Some("AI says: all good!"));
    }

    #[test]
    fn test_enhanced_report_with_llm_fallback() {
        let report = empty_report();
        let client = MockLlmClient::error(LlmError::Unavailable("down".into()));
        let enhanced = EnhancedReport::with_llm(report, &client);
        assert!(!enhanced.llm_generated); // Falls back to static
        assert!(enhanced.narrative.is_some());
    }

    #[test]
    fn test_enhanced_report_serialization() {
        let enhanced = EnhancedReport::without_llm(empty_report());
        let json = serde_json::to_string(&enhanced).unwrap();
        let parsed: EnhancedReport = serde_json::from_str(&json).unwrap();
        assert!(!parsed.llm_generated);
    }

    // ---- Static narrative tests ----

    #[test]
    fn test_static_narrative_empty() {
        let report = empty_report();
        let narrative = generate_static_narrative(&report);
        assert!(narrative.contains("Excellent"));
        assert!(narrative.contains("100/100"));
        assert!(narrative.contains("good shape"));
    }

    #[test]
    fn test_static_narrative_weak() {
        let report = weak_report();
        let narrative = generate_static_narrative(&report);
        assert!(narrative.contains("weak password"));
    }

    #[test]
    fn test_static_narrative_reused() {
        let e1 = login("A", "X9#kL!mP@2qR&vZ8wN$");
        let e2 = login("B", "X9#kL!mP@2qR&vZ8wN$");
        let report = generate_report(&[&e1, &e2]);
        let narrative = generate_static_narrative(&report);
        assert!(narrative.contains("reused"));
    }

    #[test]
    fn test_static_narrative_old() {
        let mut e1 = login("Old", "X9#kL!mP@2qR&vZ8wN$unique99");
        e1.updated_at = chrono::Utc::now() - chrono::Duration::days(400);
        e1 = e1.with_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        let report = generate_report(&[&e1]);
        let narrative = generate_static_narrative(&report);
        assert!(narrative.contains("year"));
    }

    #[test]
    fn test_static_narrative_no_totp() {
        let e1 = login("NoTOTP", "X9#kL!mP@2qR&vZ8wN$unique");
        let report = generate_report(&[&e1]);
        let narrative = generate_static_narrative(&report);
        assert!(narrative.contains("2FA"));
    }

    // ---- Format tests ----

    #[test]
    fn test_format_enhanced_report_without_llm() {
        let enhanced = EnhancedReport::without_llm(empty_report());
        let text = format_enhanced_report(&enhanced);
        assert!(text.contains("VaultClaw Security Report"));
        assert!(text.contains("AI Insights"));
        assert!(!text.contains("[Generated by LLM]"));
    }

    #[test]
    fn test_format_enhanced_report_with_llm() {
        let report = empty_report();
        let client = MockLlmClient::success("LLM generated insight.");
        let enhanced = EnhancedReport::with_llm(report, &client);
        let text = format_enhanced_report(&enhanced);
        assert!(text.contains("[Generated by LLM]"));
        assert!(text.contains("LLM generated insight."));
    }

    #[test]
    fn test_format_enhanced_report_no_narrative() {
        let enhanced = EnhancedReport {
            report: empty_report(),
            narrative: None,
            llm_generated: false,
        };
        let text = format_enhanced_report(&enhanced);
        assert!(!text.contains("AI Insights"));
    }
}
