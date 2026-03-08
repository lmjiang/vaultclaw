use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::token::{AgentAction, TokenId};
use crate::vault::entry::EntryId;

/// A single entry in the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub agent_id: String,
    pub token_id: TokenId,
    pub credential_id: EntryId,
    pub action: AgentAction,
    pub result: AuditResult,
    pub approved_by: Option<String>,
    pub metadata: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    Success,
    Denied,
    TokenExpired,
    TokenRevoked,
    ScopeViolation,
    RateLimited,
    Error(String),
}

/// Append-only audit log.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditLog {
    entries: Vec<AuditEntry>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a new audit entry.
    pub fn record(
        &mut self,
        agent_id: String,
        token_id: TokenId,
        credential_id: EntryId,
        action: AgentAction,
        result: AuditResult,
        approved_by: Option<String>,
    ) -> Uuid {
        let entry = AuditEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            agent_id,
            token_id,
            credential_id,
            action,
            result,
            approved_by,
            metadata: None,
        };
        let id = entry.id;
        self.entries.push(entry);
        id
    }

    /// Get all entries.
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Get entries for a specific agent.
    pub fn entries_for_agent(&self, agent_id: &str) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.agent_id == agent_id)
            .collect()
    }

    /// Get entries for a specific credential.
    pub fn entries_for_credential(&self, credential_id: &EntryId) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| &e.credential_id == credential_id)
            .collect()
    }

    /// Get the last N entries.
    pub fn last_n(&self, n: usize) -> Vec<&AuditEntry> {
        self.entries.iter().rev().take(n).collect()
    }

    /// Count entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Export all entries as JSON.
    pub fn export_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.entries)
    }

    /// Export all entries as CSV.
    pub fn export_csv(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut wtr = csv::Writer::from_writer(vec![]);
        wtr.write_record(["id", "timestamp", "agent_id", "token_id", "credential_id", "action", "result"])?;
        for entry in &self.entries {
            wtr.write_record([
                &entry.id.to_string(),
                &entry.timestamp.to_rfc3339(),
                &entry.agent_id,
                &entry.token_id.to_string(),
                &entry.credential_id.to_string(),
                &serde_json::to_string(&entry.action).unwrap_or_default(),
                &serde_json::to_string(&entry.result).unwrap_or_default(),
            ])?;
        }
        Ok(String::from_utf8(wtr.into_inner()?)?)
    }

    /// Detect suspicious patterns: too many denied requests from same agent.
    pub fn suspicious_agents(&self, threshold: usize) -> Vec<(String, usize)> {
        let mut deny_counts: HashMap<String, usize> = HashMap::new();
        for entry in &self.entries {
            if entry.result != AuditResult::Success {
                *deny_counts.entry(entry.agent_id.clone()).or_default() += 1;
            }
        }
        deny_counts
            .into_iter()
            .filter(|(_, count)| *count >= threshold)
            .collect()
    }

    /// Produce a dashboard summary of audit activity.
    pub fn dashboard_summary(&self, active_token_count: usize, pending_request_count: usize, alert_config: &AlertConfig) -> DashboardSummary {
        let total_events = self.entries.len();
        let mut success_count = 0usize;
        let mut denied_count = 0usize;
        let mut rate_limited_count = 0usize;
        let mut error_count = 0usize;
        let mut unique_agents: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut agent_access_counts: HashMap<String, usize> = HashMap::new();

        for entry in &self.entries {
            unique_agents.insert(&entry.agent_id);
            *agent_access_counts.entry(entry.agent_id.clone()).or_default() += 1;
            match &entry.result {
                AuditResult::Success => success_count += 1,
                AuditResult::Denied | AuditResult::ScopeViolation | AuditResult::TokenExpired | AuditResult::TokenRevoked => denied_count += 1,
                AuditResult::RateLimited => rate_limited_count += 1,
                AuditResult::Error(_) => error_count += 1,
            }
        }

        let suspicious = self.suspicious_agents(alert_config.suspicious_deny_threshold);
        let recent = self.last_n(alert_config.recent_entries_count).into_iter().cloned().collect();

        // Build alerts
        let mut alerts = Vec::new();
        if denied_count >= alert_config.high_deny_rate_threshold {
            alerts.push(Alert {
                severity: AlertSeverity::Warning,
                message: format!("{} denied access attempts detected", denied_count),
            });
        }
        if rate_limited_count > 0 {
            alerts.push(Alert {
                severity: AlertSeverity::Warning,
                message: format!("{} rate-limited requests", rate_limited_count),
            });
        }
        for (agent, count) in &suspicious {
            alerts.push(Alert {
                severity: AlertSeverity::Critical,
                message: format!("Suspicious agent '{}': {} failed attempts", agent, count),
            });
        }
        if error_count > 0 {
            alerts.push(Alert {
                severity: AlertSeverity::Info,
                message: format!("{} error(s) in audit log", error_count),
            });
        }

        // Top agents by access count
        let mut top_agents: Vec<(String, usize)> = agent_access_counts.into_iter().collect();
        top_agents.sort_by(|a, b| b.1.cmp(&a.1));
        top_agents.truncate(5);

        DashboardSummary {
            total_events,
            success_count,
            denied_count,
            rate_limited_count,
            error_count,
            unique_agent_count: unique_agents.len(),
            active_token_count,
            pending_request_count,
            suspicious_agents: suspicious,
            top_agents,
            recent_entries: recent,
            alerts,
        }
    }
}

/// Configuration for audit alert thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    /// Number of denied accesses before flagging an agent as suspicious.
    pub suspicious_deny_threshold: usize,
    /// Deny count that triggers a high-deny-rate alert.
    pub high_deny_rate_threshold: usize,
    /// Number of recent entries to show in the dashboard.
    pub recent_entries_count: usize,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            suspicious_deny_threshold: 5,
            high_deny_rate_threshold: 10,
            recent_entries_count: 10,
        }
    }
}

/// Alert severity levels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

/// A single alert from the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub severity: AlertSeverity,
    pub message: String,
}

/// Summary data for the agent audit dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSummary {
    pub total_events: usize,
    pub success_count: usize,
    pub denied_count: usize,
    pub rate_limited_count: usize,
    pub error_count: usize,
    pub unique_agent_count: usize,
    pub active_token_count: usize,
    pub pending_request_count: usize,
    pub suspicious_agents: Vec<(String, usize)>,
    pub top_agents: Vec<(String, usize)>,
    pub recent_entries: Vec<AuditEntry>,
    pub alerts: Vec<Alert>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_log_with_entries() -> AuditLog {
        let mut log = AuditLog::new();
        let cred = Uuid::new_v4();
        let token = Uuid::new_v4();

        log.record("agent-a".into(), token, cred, AgentAction::Read, AuditResult::Success, Some("human".into()));
        log.record("agent-a".into(), token, cred, AgentAction::Read, AuditResult::Success, None);
        log.record("agent-b".into(), Uuid::new_v4(), Uuid::new_v4(), AgentAction::Use, AuditResult::Denied, None);
        log
    }

    #[test]
    fn test_record_and_entries() {
        let log = make_log_with_entries();
        assert_eq!(log.len(), 3);
        assert!(!log.is_empty());
    }

    #[test]
    fn test_entries_for_agent() {
        let log = make_log_with_entries();
        assert_eq!(log.entries_for_agent("agent-a").len(), 2);
        assert_eq!(log.entries_for_agent("agent-b").len(), 1);
        assert_eq!(log.entries_for_agent("agent-c").len(), 0);
    }

    #[test]
    fn test_entries_for_credential() {
        let mut log = AuditLog::new();
        let cred = Uuid::new_v4();
        let token = Uuid::new_v4();
        log.record("a".into(), token, cred, AgentAction::Read, AuditResult::Success, None);
        log.record("b".into(), token, Uuid::new_v4(), AgentAction::Read, AuditResult::Success, None);

        assert_eq!(log.entries_for_credential(&cred).len(), 1);
    }

    #[test]
    fn test_last_n() {
        let log = make_log_with_entries();
        let last = log.last_n(2);
        assert_eq!(last.len(), 2);
        assert_eq!(last[0].agent_id, "agent-b"); // Most recent first
    }

    #[test]
    fn test_export_json() {
        let log = make_log_with_entries();
        let json = log.export_json().unwrap();
        assert!(json.contains("agent-a"));
        assert!(json.contains("agent-b"));
    }

    #[test]
    fn test_export_csv() {
        let log = make_log_with_entries();
        let csv = log.export_csv().unwrap();
        assert!(csv.contains("agent-a"));
        assert!(csv.contains("id,timestamp"));
    }

    #[test]
    fn test_suspicious_agents() {
        let mut log = AuditLog::new();
        let token = Uuid::new_v4();
        for _ in 0..5 {
            log.record("bad-agent".into(), token, Uuid::new_v4(), AgentAction::Read, AuditResult::Denied, None);
        }
        log.record("good-agent".into(), token, Uuid::new_v4(), AgentAction::Read, AuditResult::Success, None);

        let suspicious = log.suspicious_agents(3);
        assert_eq!(suspicious.len(), 1);
        assert_eq!(suspicious[0].0, "bad-agent");
    }

    #[test]
    fn test_empty_log() {
        let log = AuditLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
        assert!(log.entries().is_empty());
    }

    #[test]
    fn test_audit_entry_serialization() {
        let entry = AuditEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            agent_id: "test".into(),
            token_id: Uuid::new_v4(),
            credential_id: Uuid::new_v4(),
            action: AgentAction::Read,
            result: AuditResult::Success,
            approved_by: Some("cli".into()),
            metadata: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.agent_id, "test");
    }

    #[test]
    fn test_audit_result_variants() {
        let results = vec![
            AuditResult::Success,
            AuditResult::Denied,
            AuditResult::TokenExpired,
            AuditResult::TokenRevoked,
            AuditResult::ScopeViolation,
            AuditResult::RateLimited,
            AuditResult::Error("test error".into()),
        ];
        for result in results {
            let json = serde_json::to_string(&result).unwrap();
            assert!(!json.is_empty());
        }
    }

    // ---- Dashboard summary tests ----

    #[test]
    fn test_dashboard_summary_empty() {
        let log = AuditLog::new();
        let config = AlertConfig::default();
        let summary = log.dashboard_summary(0, 0, &config);
        assert_eq!(summary.total_events, 0);
        assert_eq!(summary.success_count, 0);
        assert_eq!(summary.denied_count, 0);
        assert_eq!(summary.unique_agent_count, 0);
        assert!(summary.alerts.is_empty());
        assert!(summary.top_agents.is_empty());
        assert!(summary.suspicious_agents.is_empty());
    }

    #[test]
    fn test_dashboard_summary_mixed_results() {
        let mut log = AuditLog::new();
        let token = Uuid::new_v4();

        // 3 successes, 2 denied, 1 rate limited, 1 error
        log.record("a".into(), token, Uuid::new_v4(), AgentAction::Read, AuditResult::Success, None);
        log.record("a".into(), token, Uuid::new_v4(), AgentAction::Read, AuditResult::Success, None);
        log.record("b".into(), token, Uuid::new_v4(), AgentAction::Read, AuditResult::Success, None);
        log.record("b".into(), token, Uuid::new_v4(), AgentAction::Read, AuditResult::Denied, None);
        log.record("b".into(), token, Uuid::new_v4(), AgentAction::Read, AuditResult::ScopeViolation, None);
        log.record("c".into(), token, Uuid::new_v4(), AgentAction::Read, AuditResult::RateLimited, None);
        log.record("c".into(), token, Uuid::new_v4(), AgentAction::Read, AuditResult::Error("e".into()), None);

        let config = AlertConfig::default();
        let summary = log.dashboard_summary(3, 1, &config);

        assert_eq!(summary.total_events, 7);
        assert_eq!(summary.success_count, 3);
        assert_eq!(summary.denied_count, 2);
        assert_eq!(summary.rate_limited_count, 1);
        assert_eq!(summary.error_count, 1);
        assert_eq!(summary.unique_agent_count, 3);
        assert_eq!(summary.active_token_count, 3);
        assert_eq!(summary.pending_request_count, 1);

        // Rate limited alert + error alert
        assert!(summary.alerts.iter().any(|a| a.severity == AlertSeverity::Warning && a.message.contains("rate-limited")));
        assert!(summary.alerts.iter().any(|a| a.severity == AlertSeverity::Info && a.message.contains("error")));
    }

    #[test]
    fn test_dashboard_summary_high_deny_alert() {
        let mut log = AuditLog::new();
        let token = Uuid::new_v4();
        // Generate 10+ denied entries to trigger high-deny-rate alert
        for _ in 0..12 {
            log.record("bad".into(), token, Uuid::new_v4(), AgentAction::Read, AuditResult::Denied, None);
        }

        let config = AlertConfig {
            suspicious_deny_threshold: 5,
            high_deny_rate_threshold: 10,
            recent_entries_count: 5,
        };
        let summary = log.dashboard_summary(0, 0, &config);

        assert_eq!(summary.denied_count, 12);
        assert!(summary.alerts.iter().any(|a| a.message.contains("denied access")));
        assert!(summary.alerts.iter().any(|a| a.severity == AlertSeverity::Critical && a.message.contains("Suspicious")));
        assert_eq!(summary.recent_entries.len(), 5);
    }

    #[test]
    fn test_dashboard_summary_top_agents() {
        let mut log = AuditLog::new();
        let token = Uuid::new_v4();
        // agent-a: 5 events, agent-b: 3 events, agent-c: 1 event
        for _ in 0..5 {
            log.record("agent-a".into(), token, Uuid::new_v4(), AgentAction::Read, AuditResult::Success, None);
        }
        for _ in 0..3 {
            log.record("agent-b".into(), token, Uuid::new_v4(), AgentAction::Read, AuditResult::Success, None);
        }
        log.record("agent-c".into(), token, Uuid::new_v4(), AgentAction::Read, AuditResult::Success, None);

        let config = AlertConfig::default();
        let summary = log.dashboard_summary(0, 0, &config);

        assert_eq!(summary.top_agents.len(), 3);
        assert_eq!(summary.top_agents[0].0, "agent-a");
        assert_eq!(summary.top_agents[0].1, 5);
    }

    #[test]
    fn test_alert_config_default() {
        let config = AlertConfig::default();
        assert_eq!(config.suspicious_deny_threshold, 5);
        assert_eq!(config.high_deny_rate_threshold, 10);
        assert_eq!(config.recent_entries_count, 10);
    }

    #[test]
    fn test_alert_config_serialization() {
        let config = AlertConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: AlertConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.suspicious_deny_threshold, config.suspicious_deny_threshold);
    }

    #[test]
    fn test_alert_severity_serialization() {
        let severities = vec![AlertSeverity::Info, AlertSeverity::Warning, AlertSeverity::Critical];
        for s in severities {
            let json = serde_json::to_string(&s).unwrap();
            let parsed: AlertSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, s);
        }
    }

    #[test]
    fn test_dashboard_summary_serialization() {
        let log = make_log_with_entries();
        let summary = log.dashboard_summary(2, 1, &AlertConfig::default());
        let json = serde_json::to_string(&summary).unwrap();
        let parsed: DashboardSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_events, summary.total_events);
    }
}
