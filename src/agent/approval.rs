use serde::{Deserialize, Serialize};

use crate::vault::entry::EntryId;
use super::token::AgentAction;

/// Default policy for auto-approving agent requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalPolicy {
    pub agent_id: String,
    /// Pre-approved credential IDs.
    pub allowed_scopes: Vec<EntryId>,
    /// Pre-approved actions.
    pub allowed_actions: Vec<AgentAction>,
    /// Max TTL (seconds) for auto-approval. Requests with longer TTL require manual approval.
    pub max_auto_approve_ttl: u64,
    /// Whether to always require manual approval for credentials tagged "sensitive".
    pub require_manual_for_sensitive: bool,
}

impl ApprovalPolicy {
    /// Check if a request can be auto-approved by this policy.
    pub fn can_auto_approve(
        &self,
        agent_id: &str,
        scopes: &[EntryId],
        actions: &[AgentAction],
        ttl: u64,
        has_sensitive_creds: bool,
    ) -> bool {
        if self.agent_id != agent_id {
            return false;
        }

        if self.require_manual_for_sensitive && has_sensitive_creds {
            return false;
        }

        if ttl > self.max_auto_approve_ttl {
            return false;
        }

        let scopes_ok = scopes.iter().all(|s| self.allowed_scopes.contains(s));
        let actions_ok = actions.iter().all(|a| self.allowed_actions.contains(a));

        scopes_ok && actions_ok
    }
}

/// Manager for approval policies.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApprovalManager {
    policies: Vec<ApprovalPolicy>,
}

impl ApprovalManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_policy(&mut self, policy: ApprovalPolicy) {
        self.policies.push(policy);
    }

    pub fn remove_policy(&mut self, agent_id: &str) {
        self.policies.retain(|p| p.agent_id != agent_id);
    }

    pub fn get_policy(&self, agent_id: &str) -> Option<&ApprovalPolicy> {
        self.policies.iter().find(|p| p.agent_id == agent_id)
    }

    pub fn list_policies(&self) -> &[ApprovalPolicy] {
        &self.policies
    }

    /// Check if a request can be auto-approved.
    pub fn check_auto_approve(
        &self,
        agent_id: &str,
        scopes: &[EntryId],
        actions: &[AgentAction],
        ttl: u64,
        has_sensitive_creds: bool,
    ) -> bool {
        self.policies
            .iter()
            .any(|p| p.can_auto_approve(agent_id, scopes, actions, ttl, has_sensitive_creds))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn test_policy() -> ApprovalPolicy {
        let cred1 = Uuid::new_v4();
        let cred2 = Uuid::new_v4();
        ApprovalPolicy {
            agent_id: "trusted-agent".to_string(),
            allowed_scopes: vec![cred1, cred2],
            allowed_actions: vec![AgentAction::Read, AgentAction::Use],
            max_auto_approve_ttl: 3600,
            require_manual_for_sensitive: true,
        }
    }

    #[test]
    fn test_auto_approve_valid() {
        let policy = test_policy();
        let scope = &policy.allowed_scopes[0..1];
        assert!(policy.can_auto_approve(
            "trusted-agent",
            scope,
            &[AgentAction::Read],
            1800,
            false,
        ));
    }

    #[test]
    fn test_auto_approve_wrong_agent() {
        let policy = test_policy();
        assert!(!policy.can_auto_approve(
            "other-agent",
            &policy.allowed_scopes,
            &[AgentAction::Read],
            1800,
            false,
        ));
    }

    #[test]
    fn test_auto_approve_ttl_exceeded() {
        let policy = test_policy();
        assert!(!policy.can_auto_approve(
            "trusted-agent",
            &policy.allowed_scopes,
            &[AgentAction::Read],
            7200, // > max_auto_approve_ttl
            false,
        ));
    }

    #[test]
    fn test_auto_approve_sensitive_blocked() {
        let policy = test_policy();
        assert!(!policy.can_auto_approve(
            "trusted-agent",
            &policy.allowed_scopes,
            &[AgentAction::Read],
            1800,
            true, // sensitive
        ));
    }

    #[test]
    fn test_auto_approve_wrong_action() {
        let policy = test_policy();
        assert!(!policy.can_auto_approve(
            "trusted-agent",
            &policy.allowed_scopes,
            &[AgentAction::Rotate], // not allowed
            1800,
            false,
        ));
    }

    #[test]
    fn test_auto_approve_wrong_scope() {
        let policy = test_policy();
        let unknown_cred = Uuid::new_v4();
        assert!(!policy.can_auto_approve(
            "trusted-agent",
            &[unknown_cred],
            &[AgentAction::Read],
            1800,
            false,
        ));
    }

    #[test]
    fn test_approval_manager() {
        let mut manager = ApprovalManager::new();
        manager.add_policy(test_policy());
        assert_eq!(manager.list_policies().len(), 1);
        assert!(manager.get_policy("trusted-agent").is_some());
        assert!(manager.get_policy("unknown").is_none());
    }

    #[test]
    fn test_manager_check_auto_approve() {
        let mut manager = ApprovalManager::new();
        let policy = test_policy();
        let scope = vec![policy.allowed_scopes[0]];
        manager.add_policy(policy);

        assert!(manager.check_auto_approve("trusted-agent", &scope, &[AgentAction::Read], 1800, false));
        assert!(!manager.check_auto_approve("untrusted", &scope, &[AgentAction::Read], 1800, false));
    }

    #[test]
    fn test_remove_policy() {
        let mut manager = ApprovalManager::new();
        manager.add_policy(test_policy());
        assert_eq!(manager.list_policies().len(), 1);

        manager.remove_policy("trusted-agent");
        assert!(manager.list_policies().is_empty());
    }

    #[test]
    fn test_policy_serialization() {
        let policy = test_policy();
        let json = serde_json::to_string(&policy).unwrap();
        let parsed: ApprovalPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.agent_id, "trusted-agent");
        assert_eq!(parsed.max_auto_approve_ttl, 3600);
    }
}
