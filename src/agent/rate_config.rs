use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::vault::entry::EntryId;

/// Per-agent rate limit configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRateLimit {
    pub agent_id: String,
    /// Max requests per minute (0 = unlimited).
    pub rpm: u32,
    /// Max requests per hour (0 = unlimited).
    pub rph: u32,
    /// If true, automatically revoke the agent's tokens on anomaly detection.
    #[serde(default)]
    pub auto_revoke_on_anomaly: bool,
}

impl AgentRateLimit {
    pub fn new(agent_id: impl Into<String>, rpm: u32, rph: u32) -> Self {
        Self {
            agent_id: agent_id.into(),
            rpm,
            rph,
            auto_revoke_on_anomaly: false,
        }
    }
}

/// Configurable per-agent rate limit store.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RateLimitConfig {
    limits: HashMap<String, AgentRateLimit>,
}

impl RateLimitConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, limit: AgentRateLimit) {
        self.limits.insert(limit.agent_id.clone(), limit);
    }

    pub fn get(&self, agent_id: &str) -> Option<&AgentRateLimit> {
        self.limits.get(agent_id)
    }

    pub fn remove(&mut self, agent_id: &str) -> bool {
        self.limits.remove(agent_id).is_some()
    }

    pub fn list(&self) -> Vec<&AgentRateLimit> {
        self.limits.values().collect()
    }
}

/// Tracks per-agent access history for anomaly detection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccessTracker {
    /// agent_id -> list of access timestamps (kept for the last hour).
    access_times: HashMap<String, Vec<DateTime<Utc>>>,
    /// agent_id -> set of credential IDs previously accessed.
    known_credentials: HashMap<String, Vec<EntryId>>,
    /// agent_id -> typical access hours (0-23) observed.
    access_hours: HashMap<String, Vec<u8>>,
}

/// Types of anomalies that can be detected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyType {
    /// Access frequency is >3x the rolling average.
    FrequencySpike {
        current_rpm: u32,
        average_rpm: u32,
    },
    /// Agent accessed a credential it has never accessed before.
    NewCredential {
        credential_id: EntryId,
    },
    /// Access outside the agent's normal time window.
    UnusualTime {
        hour: u8,
        normal_hours: Vec<u8>,
    },
    /// Agent exceeded configured rate limit.
    RateLimitExceeded {
        limit_type: String,
        limit: u32,
        actual: u32,
    },
}

impl std::fmt::Display for AnomalyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnomalyType::FrequencySpike { current_rpm, average_rpm } => {
                write!(f, "Frequency spike: {} rpm vs {} avg", current_rpm, average_rpm)
            }
            AnomalyType::NewCredential { credential_id } => {
                write!(f, "New credential accessed: {}", credential_id)
            }
            AnomalyType::UnusualTime { hour, .. } => {
                write!(f, "Access at unusual hour: {}:00", hour)
            }
            AnomalyType::RateLimitExceeded { limit_type, limit, actual } => {
                write!(f, "{} exceeded: {}/{}", limit_type, actual, limit)
            }
        }
    }
}

impl AccessTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an access event for an agent.
    pub fn record_access(&mut self, agent_id: &str, credential_id: &EntryId, now: DateTime<Utc>) {
        // Track access time
        let times = self.access_times.entry(agent_id.to_string()).or_default();
        times.push(now);
        // Prune entries older than 1 hour
        let one_hour_ago = now - chrono::Duration::hours(1);
        times.retain(|t| *t > one_hour_ago);

        // Track known credentials
        let known = self.known_credentials.entry(agent_id.to_string()).or_default();
        if !known.contains(credential_id) {
            known.push(*credential_id);
        }

        // Track access hours
        let hours = self.access_hours.entry(agent_id.to_string()).or_default();
        let hour = now.format("%H").to_string().parse::<u8>().unwrap_or(0);
        if !hours.contains(&hour) {
            hours.push(hour);
        }
    }

    /// Check for anomalies in the current access pattern.
    pub fn check_anomalies(
        &self,
        agent_id: &str,
        credential_id: &EntryId,
        now: DateTime<Utc>,
        config: &RateLimitConfig,
    ) -> Vec<AnomalyType> {
        let mut anomalies = Vec::new();

        let times = self.access_times.get(agent_id);
        let known = self.known_credentials.get(agent_id);

        // Check configured rate limits
        if let Some(limit) = config.get(agent_id) {
            if let Some(times) = times {
                // RPM check: count accesses in the last 60 seconds
                let one_min_ago = now - chrono::Duration::minutes(1);
                let rpm = times.iter().filter(|t| **t > one_min_ago).count() as u32;
                if limit.rpm > 0 && rpm >= limit.rpm {
                    anomalies.push(AnomalyType::RateLimitExceeded {
                        limit_type: "RPM".into(),
                        limit: limit.rpm,
                        actual: rpm,
                    });
                }

                // RPH check: count accesses in the last hour
                let rph = times.len() as u32;
                if limit.rph > 0 && rph >= limit.rph {
                    anomalies.push(AnomalyType::RateLimitExceeded {
                        limit_type: "RPH".into(),
                        limit: limit.rph,
                        actual: rph,
                    });
                }
            }
        }

        // Frequency spike: current minute rate > 3x rolling average
        if let Some(times) = times {
            if times.len() >= 10 {
                // Calculate rolling average RPM over the available window
                let one_min_ago = now - chrono::Duration::minutes(1);
                let current_rpm = times.iter().filter(|t| **t > one_min_ago).count() as u32;

                // Average over the full tracked window
                let total_minutes = {
                    let earliest = times.first().copied().unwrap_or(now);
                    let duration = now.signed_duration_since(earliest);
                    (duration.num_seconds() as f64 / 60.0).max(1.0)
                };
                let average_rpm = (times.len() as f64 / total_minutes).ceil() as u32;

                if average_rpm > 0 && current_rpm > average_rpm * 3 {
                    anomalies.push(AnomalyType::FrequencySpike {
                        current_rpm,
                        average_rpm,
                    });
                }
            }
        }

        // New credential access (needs at least 5 known credentials to avoid false positives on fresh agents)
        if let Some(known) = known {
            if known.len() >= 5 && !known.contains(credential_id) {
                anomalies.push(AnomalyType::NewCredential {
                    credential_id: *credential_id,
                });
            }
        }

        // Unusual time access (needs at least 20 hours of data to establish pattern)
        if let Some(hours) = self.access_hours.get(agent_id) {
            if hours.len() >= 5 {
                let current_hour = now.format("%H").to_string().parse::<u8>().unwrap_or(0);
                if !hours.contains(&current_hour) {
                    anomalies.push(AnomalyType::UnusualTime {
                        hour: current_hour,
                        normal_hours: hours.clone(),
                    });
                }
            }
        }

        anomalies
    }

    /// Check if a credential has been accessed before by this agent.
    pub fn is_known_credential(&self, agent_id: &str, credential_id: &EntryId) -> bool {
        self.known_credentials
            .get(agent_id)
            .is_some_and(|known| known.contains(credential_id))
    }

    /// Get current RPM for an agent.
    pub fn current_rpm(&self, agent_id: &str, now: DateTime<Utc>) -> u32 {
        let one_min_ago = now - chrono::Duration::minutes(1);
        self.access_times
            .get(agent_id)
            .map(|times| times.iter().filter(|t| **t > one_min_ago).count() as u32)
            .unwrap_or(0)
    }

    /// Get current RPH for an agent.
    pub fn current_rph(&self, agent_id: &str) -> u32 {
        self.access_times
            .get(agent_id)
            .map(|times| times.len() as u32)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_rate_limit_config_crud() {
        let mut config = RateLimitConfig::new();
        assert!(config.list().is_empty());

        config.set(AgentRateLimit::new("agent-1", 10, 100));
        assert_eq!(config.list().len(), 1);
        assert!(config.get("agent-1").is_some());
        assert!(config.get("agent-2").is_none());

        config.set(AgentRateLimit::new("agent-2", 20, 200));
        assert_eq!(config.list().len(), 2);

        assert!(config.remove("agent-1"));
        assert_eq!(config.list().len(), 1);
        assert!(!config.remove("agent-1")); // Already removed
    }

    #[test]
    fn test_rate_limit_serialization() {
        let limit = AgentRateLimit::new("test", 10, 100);
        let json = serde_json::to_string(&limit).unwrap();
        let parsed: AgentRateLimit = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.agent_id, "test");
        assert_eq!(parsed.rpm, 10);
        assert_eq!(parsed.rph, 100);
    }

    #[test]
    fn test_rate_limit_config_serialization() {
        let mut config = RateLimitConfig::new();
        config.set(AgentRateLimit::new("agent-1", 10, 100));
        let json = serde_json::to_string(&config).unwrap();
        let parsed: RateLimitConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.list().len(), 1);
    }

    #[test]
    fn test_access_tracker_record() {
        let mut tracker = AccessTracker::new();
        let cred = Uuid::new_v4();
        let now = Utc::now();

        tracker.record_access("agent-1", &cred, now);
        assert!(tracker.is_known_credential("agent-1", &cred));
        assert!(!tracker.is_known_credential("agent-2", &cred));
        assert_eq!(tracker.current_rpm("agent-1", now), 1);
    }

    #[test]
    fn test_access_tracker_rpm() {
        let mut tracker = AccessTracker::new();
        let cred = Uuid::new_v4();
        let now = Utc::now();

        for _ in 0..5 {
            tracker.record_access("agent-1", &cred, now);
        }
        assert_eq!(tracker.current_rpm("agent-1", now), 5);
    }

    #[test]
    fn test_anomaly_rpm_exceeded() {
        let mut tracker = AccessTracker::new();
        let mut config = RateLimitConfig::new();
        config.set(AgentRateLimit::new("agent-1", 5, 100));

        let cred = Uuid::new_v4();
        let now = Utc::now();

        for _ in 0..6 {
            tracker.record_access("agent-1", &cred, now);
        }

        let anomalies = tracker.check_anomalies("agent-1", &cred, now, &config);
        assert!(anomalies.iter().any(|a| matches!(a, AnomalyType::RateLimitExceeded { limit_type, .. } if limit_type == "RPM")));
    }

    #[test]
    fn test_anomaly_rph_exceeded() {
        let mut tracker = AccessTracker::new();
        let mut config = RateLimitConfig::new();
        config.set(AgentRateLimit::new("agent-1", 0, 5));

        let cred = Uuid::new_v4();
        let now = Utc::now();

        for i in 0..6 {
            let t = now - chrono::Duration::minutes(i);
            tracker.record_access("agent-1", &cred, t);
        }

        let anomalies = tracker.check_anomalies("agent-1", &cred, now, &config);
        assert!(anomalies.iter().any(|a| matches!(a, AnomalyType::RateLimitExceeded { limit_type, .. } if limit_type == "RPH")));
    }

    #[test]
    fn test_anomaly_new_credential() {
        let mut tracker = AccessTracker::new();
        let config = RateLimitConfig::new();
        let now = Utc::now();

        // Establish 5 known credentials
        for _ in 0..5 {
            tracker.record_access("agent-1", &Uuid::new_v4(), now);
        }

        // Access a new one
        let new_cred = Uuid::new_v4();
        let anomalies = tracker.check_anomalies("agent-1", &new_cred, now, &config);
        assert!(anomalies.iter().any(|a| matches!(a, AnomalyType::NewCredential { .. })));
    }

    #[test]
    fn test_anomaly_new_credential_fresh_agent() {
        // Fresh agent with < 5 known credentials should NOT trigger
        let mut tracker = AccessTracker::new();
        let config = RateLimitConfig::new();
        let now = Utc::now();

        tracker.record_access("agent-1", &Uuid::new_v4(), now);

        let new_cred = Uuid::new_v4();
        let anomalies = tracker.check_anomalies("agent-1", &new_cred, now, &config);
        assert!(!anomalies.iter().any(|a| matches!(a, AnomalyType::NewCredential { .. })));
    }

    #[test]
    fn test_anomaly_unusual_time() {
        let mut tracker = AccessTracker::new();
        let config = RateLimitConfig::new();
        let now = Utc::now();
        let cred = Uuid::new_v4();

        // Establish 5 different hours
        for h in 9..14 {
            let t = now.date_naive()
                .and_hms_opt(h, 0, 0)
                .unwrap();
            let t = DateTime::<Utc>::from_naive_utc_and_offset(t, Utc);
            tracker.record_access("agent-1", &cred, t);
        }

        // Access at hour 3 (unusual)
        let unusual = now.date_naive().and_hms_opt(3, 0, 0).unwrap();
        let unusual = DateTime::<Utc>::from_naive_utc_and_offset(unusual, Utc);
        let anomalies = tracker.check_anomalies("agent-1", &cred, unusual, &config);
        assert!(anomalies.iter().any(|a| matches!(a, AnomalyType::UnusualTime { .. })));
    }

    #[test]
    fn test_no_anomaly_normal_access() {
        let mut tracker = AccessTracker::new();
        let config = RateLimitConfig::new();
        let cred = Uuid::new_v4();
        let now = Utc::now();

        tracker.record_access("agent-1", &cred, now);

        let anomalies = tracker.check_anomalies("agent-1", &cred, now, &config);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn test_anomaly_type_display() {
        let a = AnomalyType::FrequencySpike { current_rpm: 30, average_rpm: 5 };
        assert!(a.to_string().contains("30 rpm"));

        let a = AnomalyType::NewCredential { credential_id: Uuid::new_v4() };
        assert!(a.to_string().contains("New credential"));

        let a = AnomalyType::UnusualTime { hour: 3, normal_hours: vec![9, 10, 11] };
        assert!(a.to_string().contains("3:00"));

        let a = AnomalyType::RateLimitExceeded { limit_type: "RPM".into(), limit: 10, actual: 15 };
        assert!(a.to_string().contains("15/10"));
    }

    #[test]
    fn test_access_tracker_serialization() {
        let mut tracker = AccessTracker::new();
        let cred = Uuid::new_v4();
        tracker.record_access("agent-1", &cred, Utc::now());

        let json = serde_json::to_string(&tracker).unwrap();
        let parsed: AccessTracker = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_known_credential("agent-1", &cred));
    }

    #[test]
    fn test_auto_revoke_flag() {
        let mut limit = AgentRateLimit::new("agent-1", 10, 100);
        assert!(!limit.auto_revoke_on_anomaly);
        limit.auto_revoke_on_anomaly = true;
        assert!(limit.auto_revoke_on_anomaly);
    }

    #[test]
    fn test_rate_limit_update() {
        let mut config = RateLimitConfig::new();
        config.set(AgentRateLimit::new("agent-1", 10, 100));
        assert_eq!(config.get("agent-1").unwrap().rpm, 10);

        // Update
        config.set(AgentRateLimit::new("agent-1", 20, 200));
        assert_eq!(config.get("agent-1").unwrap().rpm, 20);
        assert_eq!(config.list().len(), 1); // Still just one
    }
}
