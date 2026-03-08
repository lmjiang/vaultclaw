use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::vault::entry::EntryId;

/// Sensitivity level for an entry, controlling the approval flow for leases.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    /// Auto-approve lease requests.
    #[default]
    Low,
    /// Requires push notification approval (phase 2).
    Medium,
    /// Requires YubiKey touch (future).
    High,
}

/// Scope of operations allowed on a leased credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseScope {
    /// Read the credential value.
    Read,
    /// Use the credential (e.g. autofill) without seeing the raw value.
    Use,
}

/// Status of a credential lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseStatus {
    /// Lease is active and credential is accessible.
    Active,
    /// Lease has expired (TTL reached).
    Expired,
    /// Lease was manually revoked.
    Revoked,
}

/// A time-limited credential lease granted to an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    pub id: Uuid,
    pub entry_id: EntryId,
    pub agent_id: String,
    pub scope: LeaseScope,
    pub reason: String,
    /// The resolved credential value (encrypted at rest in SQLite).
    /// Cleared when the lease expires or is revoked.
    pub credential: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub status: LeaseStatus,
}

impl Lease {
    /// Check if this lease is still valid (active and not expired).
    pub fn is_valid(&self) -> bool {
        self.status == LeaseStatus::Active && Utc::now() < self.expires_at
    }
}

/// Request to create a new credential lease.
#[derive(Debug, Clone, Deserialize)]
pub struct LeaseRequest {
    /// vclaw:// reference or entry ID.
    #[serde(rename = "ref")]
    pub entry_ref: String,
    pub scope: LeaseScope,
    /// TTL in seconds.
    pub ttl: u64,
    pub reason: String,
}

/// Response when a lease is created.
#[derive(Debug, Clone, Serialize)]
pub struct LeaseResponse {
    pub lease_id: Uuid,
    pub credential: String,
    pub expires_at: DateTime<Utc>,
}

/// In-memory lease store.
pub struct LeaseStore {
    leases: HashMap<Uuid, Lease>,
    /// Per-entry sensitivity overrides.
    sensitivity: HashMap<EntryId, Sensitivity>,
}

impl Default for LeaseStore {
    fn default() -> Self {
        Self::new()
    }
}

impl LeaseStore {
    pub fn new() -> Self {
        Self {
            leases: HashMap::new(),
            sensitivity: HashMap::new(),
        }
    }

    /// Create a new lease for an entry.
    pub fn create_lease(
        &mut self,
        entry_id: EntryId,
        agent_id: String,
        scope: LeaseScope,
        ttl_secs: u64,
        reason: String,
        credential: String,
    ) -> Lease {
        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(ttl_secs as i64);
        let lease = Lease {
            id: Uuid::new_v4(),
            entry_id,
            agent_id,
            scope,
            reason,
            credential: Some(credential),
            created_at: now,
            expires_at,
            revoked_at: None,
            status: LeaseStatus::Active,
        };
        self.leases.insert(lease.id, lease.clone());
        lease
    }

    /// Revoke a lease by ID. Returns true if found and revoked.
    pub fn revoke(&mut self, lease_id: &Uuid) -> bool {
        if let Some(lease) = self.leases.get_mut(lease_id) {
            if lease.status == LeaseStatus::Active {
                lease.status = LeaseStatus::Revoked;
                lease.revoked_at = Some(Utc::now());
                lease.credential = None; // Wipe credential from memory
                return true;
            }
        }
        false
    }

    /// Revoke all active leases for an agent. Returns count revoked.
    pub fn revoke_all(&mut self, agent_id: &str) -> usize {
        let now = Utc::now();
        let mut count = 0;
        for lease in self.leases.values_mut() {
            if lease.agent_id == agent_id && lease.status == LeaseStatus::Active {
                lease.status = LeaseStatus::Revoked;
                lease.revoked_at = Some(now);
                lease.credential = None;
                count += 1;
            }
        }
        count
    }

    /// Revoke all active leases (regardless of agent). Returns count revoked.
    pub fn revoke_all_leases(&mut self) -> usize {
        let now = Utc::now();
        let mut count = 0;
        for lease in self.leases.values_mut() {
            if lease.status == LeaseStatus::Active {
                lease.status = LeaseStatus::Revoked;
                lease.revoked_at = Some(now);
                lease.credential = None;
                count += 1;
            }
        }
        count
    }

    /// Get all active (non-expired, non-revoked) leases.
    pub fn active_leases(&mut self) -> Vec<&Lease> {
        self.cleanup_expired();
        self.leases.values().filter(|l| l.status == LeaseStatus::Active).collect()
    }

    /// Get all leases (active, expired, and revoked).
    pub fn all_leases(&mut self) -> Vec<&Lease> {
        self.cleanup_expired();
        self.leases.values().collect()
    }

    /// Get a lease by ID.
    pub fn get(&self, lease_id: &Uuid) -> Option<&Lease> {
        self.leases.get(lease_id)
    }

    /// Clean up expired leases: mark as expired and wipe credentials.
    pub fn cleanup_expired(&mut self) {
        let now = Utc::now();
        for lease in self.leases.values_mut() {
            if lease.status == LeaseStatus::Active && now >= lease.expires_at {
                lease.status = LeaseStatus::Expired;
                lease.credential = None; // Wipe credential
            }
        }
    }

    /// Set sensitivity level for an entry.
    pub fn set_sensitivity(&mut self, entry_id: EntryId, level: Sensitivity) {
        self.sensitivity.insert(entry_id, level);
    }

    /// Get sensitivity level for an entry.
    pub fn get_sensitivity(&self, entry_id: &EntryId) -> Sensitivity {
        self.sensitivity.get(entry_id).copied().unwrap_or_default()
    }

    /// Get all sensitivity overrides.
    pub fn sensitivity_map(&self) -> &HashMap<EntryId, Sensitivity> {
        &self.sensitivity
    }

    /// Total number of leases (including expired/revoked).
    pub fn len(&self) -> usize {
        self.leases.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.leases.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_lease_store() -> (LeaseStore, EntryId) {
        let mut store = LeaseStore::new();
        let entry_id = Uuid::new_v4();
        store.create_lease(
            entry_id,
            "agent-1".into(),
            LeaseScope::Read,
            3600,
            "deploy".into(),
            "secret_password".into(),
        );
        (store, entry_id)
    }

    #[test]
    fn test_create_lease() {
        let (store, entry_id) = sample_lease_store();
        assert_eq!(store.len(), 1);
        let leases: Vec<&Lease> = store.leases.values().collect();
        let lease = leases[0];
        assert_eq!(lease.entry_id, entry_id);
        assert_eq!(lease.agent_id, "agent-1");
        assert_eq!(lease.scope, LeaseScope::Read);
        assert_eq!(lease.status, LeaseStatus::Active);
        assert!(lease.is_valid());
        assert!(lease.credential.is_some());
    }

    #[test]
    fn test_revoke_lease() {
        let (mut store, _) = sample_lease_store();
        let lease_id = *store.leases.keys().next().unwrap();
        assert!(store.revoke(&lease_id));
        let lease = store.get(&lease_id).unwrap();
        assert_eq!(lease.status, LeaseStatus::Revoked);
        assert!(lease.revoked_at.is_some());
        assert!(lease.credential.is_none());
        assert!(!lease.is_valid());
    }

    #[test]
    fn test_revoke_already_revoked() {
        let (mut store, _) = sample_lease_store();
        let lease_id = *store.leases.keys().next().unwrap();
        assert!(store.revoke(&lease_id));
        assert!(!store.revoke(&lease_id)); // Second revoke returns false
    }

    #[test]
    fn test_revoke_nonexistent() {
        let (mut store, _) = sample_lease_store();
        assert!(!store.revoke(&Uuid::new_v4()));
    }

    #[test]
    fn test_revoke_all_by_agent() {
        let mut store = LeaseStore::new();
        let e1 = Uuid::new_v4();
        let e2 = Uuid::new_v4();
        store.create_lease(e1, "agent-1".into(), LeaseScope::Read, 3600, "r".into(), "s1".into());
        store.create_lease(e2, "agent-1".into(), LeaseScope::Read, 3600, "r".into(), "s2".into());
        store.create_lease(Uuid::new_v4(), "agent-2".into(), LeaseScope::Read, 3600, "r".into(), "s3".into());

        let count = store.revoke_all("agent-1");
        assert_eq!(count, 2);
        // agent-2's lease should still be active
        let active = store.leases.values().filter(|l| l.status == LeaseStatus::Active).count();
        assert_eq!(active, 1);
    }

    #[test]
    fn test_revoke_all_leases() {
        let mut store = LeaseStore::new();
        store.create_lease(Uuid::new_v4(), "a1".into(), LeaseScope::Read, 3600, "r".into(), "s1".into());
        store.create_lease(Uuid::new_v4(), "a2".into(), LeaseScope::Read, 3600, "r".into(), "s2".into());

        let count = store.revoke_all_leases();
        assert_eq!(count, 2);
        let active = store.leases.values().filter(|l| l.status == LeaseStatus::Active).count();
        assert_eq!(active, 0);
    }

    #[test]
    fn test_active_leases() {
        let mut store = LeaseStore::new();
        let e1 = Uuid::new_v4();
        let e2 = Uuid::new_v4();
        store.create_lease(e1, "a".into(), LeaseScope::Read, 3600, "r".into(), "s".into());
        let l2 = store.create_lease(e2, "b".into(), LeaseScope::Read, 3600, "r".into(), "s".into());
        store.revoke(&l2.id);

        let active = store.active_leases();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].entry_id, e1);
    }

    #[test]
    fn test_cleanup_expired() {
        let mut store = LeaseStore::new();
        let entry_id = Uuid::new_v4();
        // Create lease with TTL of 0 (already expired)
        let lease = store.create_lease(
            entry_id,
            "agent-1".into(),
            LeaseScope::Read,
            0,
            "r".into(),
            "secret".into(),
        );
        // Sleep briefly to ensure expiration
        std::thread::sleep(std::time::Duration::from_millis(10));

        store.cleanup_expired();
        let l = store.get(&lease.id).unwrap();
        assert_eq!(l.status, LeaseStatus::Expired);
        assert!(l.credential.is_none()); // Credential wiped
    }

    #[test]
    fn test_sensitivity_default_low() {
        let store = LeaseStore::new();
        assert_eq!(store.get_sensitivity(&Uuid::new_v4()), Sensitivity::Low);
    }

    #[test]
    fn test_sensitivity_set_get() {
        let mut store = LeaseStore::new();
        let entry_id = Uuid::new_v4();
        store.set_sensitivity(entry_id, Sensitivity::High);
        assert_eq!(store.get_sensitivity(&entry_id), Sensitivity::High);
    }

    #[test]
    fn test_sensitivity_map() {
        let mut store = LeaseStore::new();
        let e1 = Uuid::new_v4();
        let e2 = Uuid::new_v4();
        store.set_sensitivity(e1, Sensitivity::Medium);
        store.set_sensitivity(e2, Sensitivity::High);
        assert_eq!(store.sensitivity_map().len(), 2);
    }

    #[test]
    fn test_lease_store_empty() {
        let store = LeaseStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_lease_scope_serialization() {
        let scopes = vec![LeaseScope::Read, LeaseScope::Use];
        for scope in scopes {
            let json = serde_json::to_string(&scope).unwrap();
            let parsed: LeaseScope = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, scope);
        }
    }

    #[test]
    fn test_lease_status_serialization() {
        let statuses = vec![LeaseStatus::Active, LeaseStatus::Expired, LeaseStatus::Revoked];
        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let parsed: LeaseStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, status);
        }
    }

    #[test]
    fn test_sensitivity_serialization() {
        let levels = vec![Sensitivity::Low, Sensitivity::Medium, Sensitivity::High];
        for level in levels {
            let json = serde_json::to_string(&level).unwrap();
            let parsed: Sensitivity = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, level);
        }
    }

    #[test]
    fn test_lease_serialization() {
        let (store, _) = sample_lease_store();
        let lease = store.leases.values().next().unwrap();
        let json = serde_json::to_string(lease).unwrap();
        let parsed: Lease = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, lease.id);
        assert_eq!(parsed.agent_id, lease.agent_id);
    }

    #[test]
    fn test_lease_request_deserialization() {
        let json = r#"{"ref":"vclaw://default/github","scope":"read","ttl":3600,"reason":"deploy"}"#;
        let req: LeaseRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.entry_ref, "vclaw://default/github");
        assert_eq!(req.scope, LeaseScope::Read);
        assert_eq!(req.ttl, 3600);
        assert_eq!(req.reason, "deploy");
    }

    #[test]
    fn test_lease_response_serialization() {
        let resp = LeaseResponse {
            lease_id: Uuid::new_v4(),
            credential: "secret123".into(),
            expires_at: Utc::now(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("lease_id"));
        assert!(json.contains("credential"));
        assert!(json.contains("expires_at"));
    }

    #[test]
    fn test_sensitivity_default_trait() {
        let s = Sensitivity::default();
        assert_eq!(s, Sensitivity::Low);
    }

    #[test]
    fn test_revoke_all_no_active() {
        let mut store = LeaseStore::new();
        assert_eq!(store.revoke_all_leases(), 0);
        assert_eq!(store.revoke_all("nobody"), 0);
    }
}
