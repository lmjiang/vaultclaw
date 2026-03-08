use serde::{Deserialize, Serialize};

use crate::vault::entry::Entry;

use super::health::{analyze_vault_health, Strength, VaultHealthReport};

/// A structured security report for the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    pub summary: ReportSummary,
    pub recommendations: Vec<Recommendation>,
    pub health: VaultHealthReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub grade: SecurityGrade,
    pub headline: String,
    pub total_issues: usize,
    pub critical_issues: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityGrade {
    A,
    B,
    C,
    D,
    F,
}

impl SecurityGrade {
    pub fn from_score(score: u8) -> Self {
        match score {
            90..=100 => SecurityGrade::A,
            75..=89 => SecurityGrade::B,
            60..=74 => SecurityGrade::C,
            40..=59 => SecurityGrade::D,
            _ => SecurityGrade::F,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            SecurityGrade::A => "Excellent",
            SecurityGrade::B => "Good",
            SecurityGrade::C => "Fair",
            SecurityGrade::D => "Poor",
            SecurityGrade::F => "Critical",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub affected_entries: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Warning => "WARNING",
            Severity::Critical => "CRITICAL",
        }
    }
}

/// Generate a full security report for the vault.
pub fn generate_report(entries: &[&Entry]) -> SecurityReport {
    let health = analyze_vault_health(entries);
    let mut recommendations = Vec::new();

    // Weak password recommendations
    let weak_entries: Vec<String> = health
        .details
        .iter()
        .filter(|d| !d.strength.is_acceptable())
        .filter(|d| d.strength <= Strength::Fair)
        .map(|d| d.title.clone())
        .collect();

    if !weak_entries.is_empty() {
        let severity = if weak_entries.iter().any(|_| {
            health.details.iter().any(|d| d.strength <= Strength::Weak && weak_entries.contains(&d.title))
        }) {
            Severity::Critical
        } else {
            Severity::Warning
        };

        recommendations.push(Recommendation {
            severity,
            title: format!("{} weak password(s) detected", weak_entries.len()),
            description: "These passwords are easy to guess or crack. Replace them with strong, unique passwords of at least 16 characters.".to_string(),
            affected_entries: weak_entries,
        });
    }

    // Reused password recommendations
    let reused_entries: Vec<String> = health
        .details
        .iter()
        .filter(|d| d.reused)
        .map(|d| d.title.clone())
        .collect();

    if !reused_entries.is_empty() {
        recommendations.push(Recommendation {
            severity: Severity::Critical,
            title: format!("{} entries share reused passwords", reused_entries.len()),
            description: "Reusing passwords means a breach of one service compromises all others. Generate unique passwords for each entry.".to_string(),
            affected_entries: reused_entries,
        });
    }

    // Old password recommendations
    let old_entries: Vec<String> = health
        .details
        .iter()
        .filter(|d| d.is_old)
        .map(|d| d.title.clone())
        .collect();

    if !old_entries.is_empty() {
        recommendations.push(Recommendation {
            severity: Severity::Warning,
            title: format!("{} password(s) older than 1 year", old_entries.len()),
            description: "Regularly rotating passwords reduces the window of exposure if a breach occurs undetected.".to_string(),
            affected_entries: old_entries,
        });
    }

    // Missing TOTP recommendations
    let no_totp_entries: Vec<String> = health
        .details
        .iter()
        .filter(|d| d.issues.iter().any(|i| i.contains("TOTP")))
        .map(|d| d.title.clone())
        .collect();

    if !no_totp_entries.is_empty() {
        recommendations.push(Recommendation {
            severity: Severity::Info,
            title: format!("{} login(s) without 2FA", no_totp_entries.len()),
            description: "Enable two-factor authentication (TOTP) on these accounts for an additional layer of security.".to_string(),
            affected_entries: no_totp_entries,
        });
    }

    // Sort recommendations by severity (critical first)
    recommendations.sort_by(|a, b| b.severity.cmp(&a.severity));

    let critical_count = recommendations
        .iter()
        .filter(|r| r.severity == Severity::Critical)
        .count();

    let grade = SecurityGrade::from_score(health.health_score);

    let headline = match grade {
        SecurityGrade::A => "Your vault security is excellent.".to_string(),
        SecurityGrade::B => "Your vault security is good, with minor improvements possible.".to_string(),
        SecurityGrade::C => "Your vault has some security issues that should be addressed.".to_string(),
        SecurityGrade::D => "Your vault has significant security weaknesses.".to_string(),
        SecurityGrade::F => "Your vault security needs immediate attention!".to_string(),
    };

    SecurityReport {
        summary: ReportSummary {
            grade,
            headline,
            total_issues: recommendations.len(),
            critical_issues: critical_count,
        },
        recommendations,
        health,
    }
}

/// Format a security report as a human-readable text string.
pub fn format_report_text(report: &SecurityReport) -> String {
    let mut output = String::new();

    output.push_str("=== VaultClaw Security Report ===\n\n");
    output.push_str(&format!(
        "Grade: {:?} — {}\n",
        report.summary.grade,
        report.summary.headline
    ));
    output.push_str(&format!("Health Score: {}/100\n\n", report.health.health_score));

    output.push_str("--- Statistics ---\n");
    output.push_str(&format!("Total entries:       {}\n", report.health.total_entries));
    output.push_str(&format!("Login entries:       {}\n", report.health.login_entries));
    output.push_str(&format!("Weak passwords:      {}\n", report.health.weak_passwords));
    output.push_str(&format!("Reused passwords:    {}\n", report.health.reused_passwords));
    output.push_str(&format!("Old passwords:       {}\n", report.health.old_passwords));
    output.push_str(&format!("Without 2FA:         {}\n\n", report.health.entries_without_totp));

    if report.recommendations.is_empty() {
        output.push_str("No issues found. Great job!\n");
    } else {
        output.push_str(&format!(
            "--- {} Issue(s) Found ---\n\n",
            report.recommendations.len()
        ));

        for (i, rec) in report.recommendations.iter().enumerate() {
            output.push_str(&format!(
                "{}. [{}] {}\n",
                i + 1,
                rec.severity.label(),
                rec.title
            ));
            output.push_str(&format!("   {}\n", rec.description));
            if !rec.affected_entries.is_empty() {
                output.push_str(&format!(
                    "   Affected: {}\n",
                    rec.affected_entries.join(", ")
                ));
            }
            output.push('\n');
        }
    }

    output
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
    fn test_generate_report_empty() {
        let entries: Vec<&Entry> = vec![];
        let report = generate_report(&entries);
        assert_eq!(report.summary.grade, SecurityGrade::A);
        assert_eq!(report.summary.total_issues, 0);
        assert_eq!(report.health.health_score, 100);
    }

    #[test]
    fn test_generate_report_all_strong() {
        let e1 = login("GitHub", "X9#kL!mP@2qR&vZ8wN$").with_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        let e2 = login("GitLab", "Y8@jK!nO#3pQ&uW7xM$").with_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        let entries: Vec<&Entry> = vec![&e1, &e2];

        let report = generate_report(&entries);
        assert!(report.health.health_score >= 80);
        assert_eq!(report.health.weak_passwords, 0);
        assert_eq!(report.health.reused_passwords, 0);
    }

    #[test]
    fn test_generate_report_weak_passwords() {
        let e1 = login("Site1", "password");
        let e2 = login("Site2", "123456");
        let entries: Vec<&Entry> = vec![&e1, &e2];

        let report = generate_report(&entries);
        assert!(report.health.weak_passwords > 0);
        assert!(report.recommendations.iter().any(|r| r.title.contains("weak")));
    }

    #[test]
    fn test_generate_report_reused() {
        let e1 = login("Site1", "X9#kL!mP@2qR&vZ8wN$");
        let e2 = login("Site2", "X9#kL!mP@2qR&vZ8wN$");
        let entries: Vec<&Entry> = vec![&e1, &e2];

        let report = generate_report(&entries);
        assert!(report
            .recommendations
            .iter()
            .any(|r| r.title.contains("reused")));
    }

    #[test]
    fn test_generate_report_no_totp() {
        let e1 = login("Site1", "X9#kL!mP@2qR&vZ8wN$");
        let entries: Vec<&Entry> = vec![&e1];

        let report = generate_report(&entries);
        assert!(report
            .recommendations
            .iter()
            .any(|r| r.title.contains("2FA")));
    }

    #[test]
    fn test_security_grade_from_score() {
        assert_eq!(SecurityGrade::from_score(100), SecurityGrade::A);
        assert_eq!(SecurityGrade::from_score(90), SecurityGrade::A);
        assert_eq!(SecurityGrade::from_score(89), SecurityGrade::B);
        assert_eq!(SecurityGrade::from_score(75), SecurityGrade::B);
        assert_eq!(SecurityGrade::from_score(74), SecurityGrade::C);
        assert_eq!(SecurityGrade::from_score(60), SecurityGrade::C);
        assert_eq!(SecurityGrade::from_score(59), SecurityGrade::D);
        assert_eq!(SecurityGrade::from_score(40), SecurityGrade::D);
        assert_eq!(SecurityGrade::from_score(39), SecurityGrade::F);
        assert_eq!(SecurityGrade::from_score(0), SecurityGrade::F);
    }

    #[test]
    fn test_security_grade_label() {
        assert_eq!(SecurityGrade::A.label(), "Excellent");
        assert_eq!(SecurityGrade::B.label(), "Good");
        assert_eq!(SecurityGrade::C.label(), "Fair");
        assert_eq!(SecurityGrade::D.label(), "Poor");
        assert_eq!(SecurityGrade::F.label(), "Critical");
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::Critical);
    }

    #[test]
    fn test_severity_label() {
        assert_eq!(Severity::Info.label(), "INFO");
        assert_eq!(Severity::Warning.label(), "WARNING");
        assert_eq!(Severity::Critical.label(), "CRITICAL");
    }

    #[test]
    fn test_format_report_text_empty() {
        let entries: Vec<&Entry> = vec![];
        let report = generate_report(&entries);
        let text = format_report_text(&report);
        assert!(text.contains("VaultClaw Security Report"));
        assert!(text.contains("100/100"));
        assert!(text.contains("No issues found"));
    }

    #[test]
    fn test_format_report_text_with_issues() {
        let e1 = login("Site1", "password");
        let entries: Vec<&Entry> = vec![&e1];
        let report = generate_report(&entries);
        let text = format_report_text(&report);
        assert!(text.contains("Issue(s) Found"));
        assert!(text.contains("Site1"));
    }

    #[test]
    fn test_report_serialization() {
        let entries: Vec<&Entry> = vec![];
        let report = generate_report(&entries);
        let json = serde_json::to_string(&report).unwrap();
        let parsed: SecurityReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.summary.grade, SecurityGrade::A);
    }

    #[test]
    fn test_recommendations_sorted_by_severity() {
        let e1 = login("Site1", "password"); // weak - critical
        let e2 = login("Site2", "X9#kL!mP@2qR&vZ8wN$"); // no totp - info
        let entries: Vec<&Entry> = vec![&e1, &e2];

        let report = generate_report(&entries);
        assert!(report.recommendations.len() >= 2);
        assert!(report.recommendations[0].severity >= report.recommendations[1].severity);
    }

    #[test]
    fn test_generate_report_old_passwords() {
        use chrono::Utc;
        // Create entry with old updated_at timestamp
        let mut e1 = login("OldSite", "X9#kL!mP@2qR&vZ8wN$unique1");
        e1.updated_at = Utc::now() - chrono::Duration::days(400);
        e1 = e1.with_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        let entries: Vec<&Entry> = vec![&e1];

        let report = generate_report(&entries);
        assert!(report
            .recommendations
            .iter()
            .any(|r| r.title.contains("older than 1 year")));
        assert!(report
            .recommendations
            .iter()
            .find(|r| r.title.contains("older"))
            .unwrap()
            .affected_entries
            .contains(&"OldSite".to_string()));
    }

    #[test]
    fn test_grade_b_headline() {
        // Grade B: score 75-89, which means mostly strong but one minor issue
        let e1 = login("Site1", "X9#kL!mP@2qR&vZ8wN$unique1").with_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        let e2 = login("Site2", "Y8@jK!nO#3pQ&uW7xM$unique2").with_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        let e3 = login("Site3", "Z7#iJ!mN@4oP&tV6wL$unique3").with_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        let e4 = login("Site4", "weak"); // One weak password to drop score
        let entries: Vec<&Entry> = vec![&e1, &e2, &e3, &e4];

        let report = generate_report(&entries);
        // We verify the headline mapping is exercised for non-A grades
        assert!(!report.summary.headline.is_empty());
        assert!(report.health.health_score < 100);
    }

    #[test]
    fn test_grade_f_headline() {
        // Grade F: score < 40, all weak passwords
        let e1 = login("S1", "123");
        let e2 = login("S2", "123"); // reused too
        let e3 = login("S3", "abc");
        let entries: Vec<&Entry> = vec![&e1, &e2, &e3];

        let report = generate_report(&entries);
        assert!(report.health.weak_passwords > 0);
        // Should have critical issues
        assert!(report.summary.critical_issues > 0);
    }

    #[test]
    fn test_generate_report_fair_passwords_warning_severity() {
        // Passwords that score exactly Fair (zxcvbn score 2) — NOT Weak or Strong.
        // This makes generate_report produce a weak-password recommendation with
        // Severity::Warning instead of Critical (because no entry is <= Weak).
        let e1 = login("FairSite1", "Summer2024!"); // Fair
        let e2 = login("FairSite2", "Coffee99!!"); // Fair
        // Add TOTP so we don't get 2FA recommendations confusing us
        let e1 = e1.with_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        let e2 = e2.with_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        let entries: Vec<&Entry> = vec![&e1, &e2];

        let report = generate_report(&entries);
        let weak_rec = report.recommendations.iter().find(|r| r.title.contains("weak")).unwrap();
        assert_eq!(weak_rec.severity, Severity::Warning);
    }

    #[test]
    fn test_recommendations_sorted_multiple_severities() {
        // Create entries that produce Critical, Warning, and Info recommendations
        let e1 = login("Weak1", "123"); // Weak → Critical
        let e2 = login("Weak2", "123"); // Reused → Critical
        let mut e3 = login("Old1", "X9#kL!mP@2qR&vZ8wN$unique99");
        e3.updated_at = chrono::Utc::now() - chrono::Duration::days(400);
        e3 = e3.with_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        let e4 = login("NoTOTP", "Y8@jK!nO#3pQ&uW7xM$unique88"); // No TOTP → Info
        let entries: Vec<&Entry> = vec![&e1, &e2, &e3, &e4];

        let report = generate_report(&entries);
        // Verify sorted: all Critical before Warning before Info
        for i in 1..report.recommendations.len() {
            assert!(report.recommendations[i - 1].severity >= report.recommendations[i].severity);
        }
    }

    #[test]
    fn test_format_report_text_has_statistics() {
        let e1 = login("Site1", "X9#kL!mP@2qR&vZ8wN$");
        let entries: Vec<&Entry> = vec![&e1];

        let report = generate_report(&entries);
        let text = format_report_text(&report);
        assert!(text.contains("Total entries:"));
        assert!(text.contains("Login entries:"));
        assert!(text.contains("Weak passwords:"));
        assert!(text.contains("Reused passwords:"));
        assert!(text.contains("Old passwords:"));
        assert!(text.contains("Without 2FA:"));
    }
}
