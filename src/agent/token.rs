use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::vault::entry::EntryId;

/// Unique identifier for an agent token.
pub type TokenId = Uuid;

/// Actions an agent can perform on a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentAction {
    Read,
    Use,
    Rotate,
}

/// A scoped, time-limited token granting an agent access to specific credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentToken {
    pub id: TokenId,
    pub agent_id: String,
    pub scopes: Vec<EntryId>,
    pub actions: Vec<AgentAction>,
    pub ttl_seconds: u64,
    pub max_uses: Option<u32>,
    pub uses: u32,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub approved_by: String,
    pub revoked: bool,
}

/// Request from an agent for credential access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRequest {
    pub id: Uuid,
    pub agent_id: String,
    pub requested_scopes: Vec<EntryId>,
    pub requested_actions: Vec<AgentAction>,
    pub requested_ttl: u64,
    pub requested_max_uses: Option<u32>,
    pub reason: String,
    pub created_at: DateTime<Utc>,
    pub status: RequestStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

impl AccessRequest {
    pub fn new(
        agent_id: String,
        scopes: Vec<EntryId>,
        actions: Vec<AgentAction>,
        ttl: u64,
        max_uses: Option<u32>,
        reason: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            agent_id,
            requested_scopes: scopes,
            requested_actions: actions,
            requested_ttl: ttl,
            requested_max_uses: max_uses,
            reason,
            created_at: Utc::now(),
            status: RequestStatus::Pending,
        }
    }
}

/// Manages agent tokens: issue, validate, revoke.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenStore {
    tokens: HashMap<TokenId, AgentToken>,
    pending_requests: HashMap<Uuid, AccessRequest>,
}

impl TokenStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Submit a new access request (agent calls this).
    pub fn submit_request(&mut self, request: AccessRequest) -> Uuid {
        let id = request.id;
        self.pending_requests.insert(id, request);
        id
    }

    /// Get a pending request by ID.
    pub fn get_request(&self, id: &Uuid) -> Option<&AccessRequest> {
        self.pending_requests.get(id)
    }

    /// List all pending requests.
    pub fn pending_requests(&self) -> Vec<&AccessRequest> {
        self.pending_requests
            .values()
            .filter(|r| r.status == RequestStatus::Pending)
            .collect()
    }

    /// Approve a request and issue a token.
    pub fn approve_request(&mut self, request_id: &Uuid, approved_by: String) -> Option<AgentToken> {
        let request = self.pending_requests.get_mut(request_id)?;
        if request.status != RequestStatus::Pending {
            return None;
        }
        request.status = RequestStatus::Approved;

        let now = Utc::now();
        let expires = now + chrono::Duration::seconds(request.requested_ttl as i64);

        let token = AgentToken {
            id: Uuid::new_v4(),
            agent_id: request.agent_id.clone(),
            scopes: request.requested_scopes.clone(),
            actions: request.requested_actions.clone(),
            ttl_seconds: request.requested_ttl,
            max_uses: request.requested_max_uses,
            uses: 0,
            issued_at: now,
            expires_at: expires,
            approved_by,
            revoked: false,
        };

        self.tokens.insert(token.id, token.clone());
        Some(token)
    }

    /// Deny a request.
    pub fn deny_request(&mut self, request_id: &Uuid) -> bool {
        if let Some(request) = self.pending_requests.get_mut(request_id) {
            if request.status == RequestStatus::Pending {
                request.status = RequestStatus::Denied;
                return true;
            }
        }
        false
    }

    /// Validate a token for a specific credential and action.
    /// Returns Ok(()) if valid, Err with reason if not.
    pub fn validate_token(
        &mut self,
        token_id: &TokenId,
        credential_id: &EntryId,
        action: AgentAction,
    ) -> Result<(), String> {
        let token = self
            .tokens
            .get_mut(token_id)
            .ok_or_else(|| "Token not found".to_string())?;

        if token.revoked {
            return Err("Token has been revoked".to_string());
        }

        if Utc::now() > token.expires_at {
            return Err("Token has expired".to_string());
        }

        if let Some(max) = token.max_uses {
            if token.uses >= max {
                return Err("Token has exceeded max uses".to_string());
            }
        }

        if !token.scopes.contains(credential_id) {
            return Err("Credential not in token scope".to_string());
        }

        if !token.actions.contains(&action) {
            return Err("Action not permitted by token".to_string());
        }

        token.uses += 1;
        Ok(())
    }

    /// Revoke a token immediately.
    pub fn revoke_token(&mut self, token_id: &TokenId) -> bool {
        if let Some(token) = self.tokens.get_mut(token_id) {
            token.revoked = true;
            true
        } else {
            false
        }
    }

    /// Get a token by ID.
    pub fn get_token(&self, id: &TokenId) -> Option<&AgentToken> {
        self.tokens.get(id)
    }

    /// List all active (non-revoked, non-expired) tokens.
    pub fn active_tokens(&self) -> Vec<&AgentToken> {
        let now = Utc::now();
        self.tokens
            .values()
            .filter(|t| !t.revoked && t.expires_at > now)
            .collect()
    }

    /// List all tokens for a specific agent.
    pub fn tokens_for_agent(&self, agent_id: &str) -> Vec<&AgentToken> {
        self.tokens
            .values()
            .filter(|t| t.agent_id == agent_id)
            .collect()
    }

    /// Clean up expired tokens and requests.
    pub fn cleanup_expired(&mut self) {
        let now = Utc::now();
        self.tokens.retain(|_, t| !t.revoked || t.expires_at > now);
        self.pending_requests.retain(|_, r| {
            r.status == RequestStatus::Pending
                || r.created_at + chrono::Duration::hours(24) > now
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_request() -> AccessRequest {
        let cred_id = Uuid::new_v4();
        AccessRequest::new(
            "test-agent".to_string(),
            vec![cred_id],
            vec![AgentAction::Read],
            3600,
            Some(10),
            "Need credentials for deployment".to_string(),
        )
    }

    #[test]
    fn test_submit_and_approve_request() {
        let mut store = TokenStore::new();
        let request = test_request();
        let req_id = request.id;

        store.submit_request(request);
        assert_eq!(store.pending_requests().len(), 1);

        let token = store.approve_request(&req_id, "human:cli".to_string()).unwrap();
        assert_eq!(token.agent_id, "test-agent");
        assert_eq!(token.ttl_seconds, 3600);
        assert_eq!(token.uses, 0);
        assert!(!token.revoked);
    }

    #[test]
    fn test_deny_request() {
        let mut store = TokenStore::new();
        let request = test_request();
        let req_id = request.id;

        store.submit_request(request);
        assert!(store.deny_request(&req_id));
        assert!(store.pending_requests().is_empty());
    }

    #[test]
    fn test_validate_token() {
        let mut store = TokenStore::new();
        let cred_id = Uuid::new_v4();
        let request = AccessRequest::new(
            "agent".to_string(),
            vec![cred_id],
            vec![AgentAction::Read],
            3600,
            Some(5),
            "test".to_string(),
        );
        let req_id = request.id;
        store.submit_request(request);

        let token = store.approve_request(&req_id, "human".to_string()).unwrap();
        let token_id = token.id;

        assert!(store.validate_token(&token_id, &cred_id, AgentAction::Read).is_ok());
        assert_eq!(store.get_token(&token_id).unwrap().uses, 1);
    }

    #[test]
    fn test_validate_wrong_credential() {
        let mut store = TokenStore::new();
        let cred_id = Uuid::new_v4();
        let wrong_id = Uuid::new_v4();
        let request = AccessRequest::new(
            "agent".to_string(),
            vec![cred_id],
            vec![AgentAction::Read],
            3600,
            None,
            "test".to_string(),
        );
        let req_id = request.id;
        store.submit_request(request);
        let token = store.approve_request(&req_id, "human".to_string()).unwrap();

        assert!(store.validate_token(&token.id, &wrong_id, AgentAction::Read).is_err());
    }

    #[test]
    fn test_validate_wrong_action() {
        let mut store = TokenStore::new();
        let cred_id = Uuid::new_v4();
        let request = AccessRequest::new(
            "agent".to_string(),
            vec![cred_id],
            vec![AgentAction::Read],
            3600,
            None,
            "test".to_string(),
        );
        let req_id = request.id;
        store.submit_request(request);
        let token = store.approve_request(&req_id, "human".to_string()).unwrap();

        assert!(store.validate_token(&token.id, &cred_id, AgentAction::Rotate).is_err());
    }

    #[test]
    fn test_max_uses_enforcement() {
        let mut store = TokenStore::new();
        let cred_id = Uuid::new_v4();
        let request = AccessRequest::new(
            "agent".to_string(),
            vec![cred_id],
            vec![AgentAction::Read],
            3600,
            Some(2),
            "test".to_string(),
        );
        let req_id = request.id;
        store.submit_request(request);
        let token = store.approve_request(&req_id, "human".to_string()).unwrap();
        let tid = token.id;

        assert!(store.validate_token(&tid, &cred_id, AgentAction::Read).is_ok());
        assert!(store.validate_token(&tid, &cred_id, AgentAction::Read).is_ok());
        assert!(store.validate_token(&tid, &cred_id, AgentAction::Read).is_err());
    }

    #[test]
    fn test_revoke_token() {
        let mut store = TokenStore::new();
        let cred_id = Uuid::new_v4();
        let request = AccessRequest::new(
            "agent".to_string(),
            vec![cred_id],
            vec![AgentAction::Read],
            3600,
            None,
            "test".to_string(),
        );
        let req_id = request.id;
        store.submit_request(request);
        let token = store.approve_request(&req_id, "human".to_string()).unwrap();
        let tid = token.id;

        assert!(store.revoke_token(&tid));
        assert!(store.validate_token(&tid, &cred_id, AgentAction::Read).is_err());
    }

    #[test]
    fn test_active_tokens() {
        let mut store = TokenStore::new();
        let request = test_request();
        let req_id = request.id;
        store.submit_request(request);
        store.approve_request(&req_id, "human".to_string());

        assert_eq!(store.active_tokens().len(), 1);
    }

    #[test]
    fn test_tokens_for_agent() {
        let mut store = TokenStore::new();

        let r1 = AccessRequest::new("agent-a".into(), vec![Uuid::new_v4()], vec![AgentAction::Read], 3600, None, "t".into());
        let r2 = AccessRequest::new("agent-b".into(), vec![Uuid::new_v4()], vec![AgentAction::Read], 3600, None, "t".into());
        let id1 = r1.id;
        let id2 = r2.id;
        store.submit_request(r1);
        store.submit_request(r2);
        store.approve_request(&id1, "h".into());
        store.approve_request(&id2, "h".into());

        assert_eq!(store.tokens_for_agent("agent-a").len(), 1);
        assert_eq!(store.tokens_for_agent("agent-b").len(), 1);
        assert_eq!(store.tokens_for_agent("agent-c").len(), 0);
    }

    #[test]
    fn test_double_approve_fails() {
        let mut store = TokenStore::new();
        let request = test_request();
        let req_id = request.id;
        store.submit_request(request);

        assert!(store.approve_request(&req_id, "h".into()).is_some());
        assert!(store.approve_request(&req_id, "h".into()).is_none());
    }

    #[test]
    fn test_deny_already_approved() {
        let mut store = TokenStore::new();
        let request = test_request();
        let req_id = request.id;
        store.submit_request(request);
        store.approve_request(&req_id, "h".into());

        assert!(!store.deny_request(&req_id));
    }

    #[test]
    fn test_revoke_nonexistent() {
        let mut store = TokenStore::new();
        assert!(!store.revoke_token(&Uuid::new_v4()));
    }

    #[test]
    fn test_validate_nonexistent_token() {
        let mut store = TokenStore::new();
        assert!(store.validate_token(&Uuid::new_v4(), &Uuid::new_v4(), AgentAction::Read).is_err());
    }

    #[test]
    fn test_request_status_serialization() {
        let request = test_request();
        let json = serde_json::to_string(&request).unwrap();
        let parsed: AccessRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.agent_id, "test-agent");
        assert_eq!(parsed.status, RequestStatus::Pending);
    }

    #[test]
    fn test_token_serialization() {
        let mut store = TokenStore::new();
        let request = test_request();
        let req_id = request.id;
        store.submit_request(request);
        let token = store.approve_request(&req_id, "h".into()).unwrap();

        let json = serde_json::to_string(&token).unwrap();
        let parsed: AgentToken = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.agent_id, "test-agent");
    }

    #[test]
    fn test_cleanup_expired() {
        let mut store = TokenStore::new();
        let request = test_request();
        let req_id = request.id;
        store.submit_request(request);
        store.approve_request(&req_id, "h".into());

        // No tokens should be cleaned up since they're still active
        store.cleanup_expired();
        assert_eq!(store.active_tokens().len(), 1);
    }

    #[test]
    fn test_get_request() {
        let mut store = TokenStore::new();
        let request = test_request();
        let req_id = request.id;
        store.submit_request(request);

        let fetched = store.get_request(&req_id).unwrap();
        assert_eq!(fetched.agent_id, "test-agent");
        assert_eq!(fetched.status, RequestStatus::Pending);

        // Nonexistent request
        assert!(store.get_request(&Uuid::new_v4()).is_none());
    }

    #[test]
    fn test_deny_nonexistent_request() {
        let mut store = TokenStore::new();
        assert!(!store.deny_request(&Uuid::new_v4()));
    }

    #[test]
    fn test_agent_action_serialization() {
        let actions = vec![AgentAction::Read, AgentAction::Use, AgentAction::Rotate];
        for action in actions {
            let json = serde_json::to_string(&action).unwrap();
            let parsed: AgentAction = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, action);
        }
    }

    #[test]
    fn test_request_status_all_variants() {
        let statuses = vec![
            RequestStatus::Pending,
            RequestStatus::Approved,
            RequestStatus::Denied,
            RequestStatus::Expired,
        ];
        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let parsed: RequestStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, status);
        }
    }
}
