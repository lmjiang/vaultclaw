use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::gateway::{AgentGateway, CredentialValue, GatewayData, GatewayRequest, GatewayResponse};
use super::token::TokenId;
use crate::vault::entry::{Entry, EntryId};

/// Session types that determine access control behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionType {
    /// Direct message — full vault access (with approval).
    Dm,
    /// Group chat — vault access denied by default (anti-cache-poisoning).
    Group,
    /// Sub-agent inheriting parent session scope.
    SubAgent { parent_token_id: TokenId },
    /// Cron/scheduled job with pre-approved tokens.
    Cron { schedule_id: String },
}

/// Represents the current agent session context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSession {
    pub session_id: String,
    pub agent_id: String,
    pub session_type: SessionType,
    /// Active token for this session (if granted).
    pub token_id: Option<TokenId>,
}

impl AgentSession {
    pub fn new(agent_id: impl Into<String>, session_type: SessionType) -> Self {
        Self {
            session_id: Uuid::new_v4().to_string(),
            agent_id: agent_id.into(),
            session_type,
            token_id: None,
        }
    }
}

/// Access control decision for a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessDecision {
    /// Access allowed — proceed with request.
    Allow,
    /// Access denied with reason.
    Deny(String),
    /// Needs human approval before proceeding.
    NeedsApproval,
}

/// Check if a session type allows vault access.
pub fn check_session_access(session: &AgentSession) -> AccessDecision {
    match &session.session_type {
        SessionType::Dm => AccessDecision::Allow,
        SessionType::Group => AccessDecision::Deny("Vault access denied in group chat sessions".into()),
        SessionType::SubAgent { parent_token_id } => {
            if session.token_id.is_some() {
                AccessDecision::Allow
            } else {
                // Sub-agent needs inherited token
                AccessDecision::Deny(format!(
                    "Sub-agent must inherit scope from parent token {}",
                    parent_token_id
                ))
            }
        }
        SessionType::Cron { .. } => {
            if session.token_id.is_some() {
                AccessDecision::Allow
            } else {
                AccessDecision::Deny("Cron jobs require pre-approved tokens".into())
            }
        }
    }
}

/// Create a sub-agent token that inherits the parent's scope.
/// Returns a new token with a subset of the parent's scopes and a shorter TTL.
pub fn inherit_token(
    gateway: &mut AgentGateway,
    parent_token_id: &TokenId,
    sub_agent_id: &str,
    requested_scopes: &[EntryId],
    ttl: u64,
) -> Result<TokenId, String> {
    let parent = gateway.token_store.get_token(parent_token_id)
        .ok_or("Parent token not found")?;

    if parent.revoked {
        return Err("Parent token has been revoked".into());
    }

    // Sub-agent scopes must be a subset of parent scopes
    for scope in requested_scopes {
        if !parent.scopes.contains(scope) {
            return Err(format!("Scope {} not in parent token", scope));
        }
    }

    // Sub-agent TTL capped at parent's remaining TTL
    let parent_remaining = parent.expires_at
        .signed_duration_since(chrono::Utc::now())
        .num_seconds()
        .max(0) as u64;
    let effective_ttl = ttl.min(parent_remaining);

    if effective_ttl == 0 {
        return Err("Parent token has expired".into());
    }

    // Sub-agent inherits parent's actions
    let actions = parent.actions.clone();
    let parent_approved_by = parent.approved_by.clone();

    // Create the request and auto-approve it
    let req = GatewayRequest::RequestAccess {
        agent_id: sub_agent_id.into(),
        scopes: requested_scopes.to_vec(),
        actions,
        ttl: effective_ttl,
        max_uses: None,
        reason: format!("Sub-agent of {}", parent.agent_id),
    };

    let resp = gateway.handle(req);
    match resp {
        GatewayResponse::Ok { data: GatewayData::RequestId(req_id) } => {
            // Auto-approve the sub-agent request
            let resp = gateway.handle(GatewayRequest::Grant {
                request_id: req_id,
                approved_by: format!("inherited:{}", parent_approved_by),
            });
            match resp {
                GatewayResponse::Ok { data: GatewayData::Token(token) } => Ok(token.id),
                _ => Err("Failed to issue sub-agent token".into()),
            }
        }
        GatewayResponse::Ok { data: GatewayData::Token(token) } => {
            // Auto-approved via policy
            Ok(token.id)
        }
        GatewayResponse::Error { message } => Err(message),
        _ => Err("Unexpected gateway response".into()),
    }
}

/// High-level: request a credential through the skill layer.
/// Enforces session-aware access control before delegating to the gateway.
pub fn request_credential<F>(
    gateway: &mut AgentGateway,
    session: &AgentSession,
    credential_id: &EntryId,
    credential_lookup: F,
) -> Result<CredentialValue, String>
where
    F: Fn(&EntryId) -> Option<Entry>,
{
    // Check session-level access
    match check_session_access(session) {
        AccessDecision::Allow => {}
        AccessDecision::Deny(reason) => return Err(reason),
        AccessDecision::NeedsApproval => return Err("Human approval required".into()),
    }

    // Must have a token
    let token_id = session.token_id
        .ok_or("No active token for this session")?;

    let resp = gateway.handle_with_lookup(
        GatewayRequest::GetCredential { token_id, credential_id: *credential_id },
        credential_lookup,
    );

    match resp {
        GatewayResponse::Ok { data: GatewayData::Credential(cv) } => Ok(cv),
        GatewayResponse::Error { message } => Err(message),
        _ => Err("Unexpected gateway response".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::gateway::SecretValue;
    use crate::agent::token::AgentAction;
    use crate::vault::entry::{Credential, LoginCredential};

    fn mock_gateway_with_token(cred_id: EntryId) -> (AgentGateway, TokenId) {
        let mut gw = AgentGateway::new();
        let resp = gw.handle(GatewayRequest::RequestAccess {
            agent_id: "test-agent".into(),
            scopes: vec![cred_id],
            actions: vec![AgentAction::Read],
            ttl: 3600,
            max_uses: None,
            reason: "test".into(),
        });
        let req_id = match resp {
            GatewayResponse::Ok { data: GatewayData::RequestId(id) } => id,
            _ => panic!("Expected RequestId"),
        };
        let resp = gw.handle(GatewayRequest::Grant {
            request_id: req_id,
            approved_by: "human".into(),
        });
        let token_id = match resp {
            GatewayResponse::Ok { data: GatewayData::Token(t) } => t.id,
            _ => panic!("Expected Token"),
        };
        (gw, token_id)
    }

    fn mock_entry(id: EntryId) -> Entry {
        let mut entry = Entry::new("GitHub".into(), Credential::Login(LoginCredential {
            url: "https://github.com".into(),
            username: "user".into(),
            password: "secret".into(),
        }));
        entry.id = id;
        entry
    }

    // ---- Session access tests ----

    #[test]
    fn test_dm_session_allows_access() {
        let session = AgentSession::new("agent-1", SessionType::Dm);
        assert_eq!(check_session_access(&session), AccessDecision::Allow);
    }

    #[test]
    fn test_group_session_denies_access() {
        let session = AgentSession::new("agent-1", SessionType::Group);
        assert!(matches!(check_session_access(&session), AccessDecision::Deny(_)));
    }

    #[test]
    fn test_sub_agent_without_token_denied() {
        let session = AgentSession::new(
            "sub-agent",
            SessionType::SubAgent { parent_token_id: Uuid::new_v4() },
        );
        assert!(matches!(check_session_access(&session), AccessDecision::Deny(_)));
    }

    #[test]
    fn test_sub_agent_with_token_allowed() {
        let mut session = AgentSession::new(
            "sub-agent",
            SessionType::SubAgent { parent_token_id: Uuid::new_v4() },
        );
        session.token_id = Some(Uuid::new_v4());
        assert_eq!(check_session_access(&session), AccessDecision::Allow);
    }

    #[test]
    fn test_cron_without_token_denied() {
        let session = AgentSession::new(
            "cron-job",
            SessionType::Cron { schedule_id: "daily-backup".into() },
        );
        assert!(matches!(check_session_access(&session), AccessDecision::Deny(_)));
    }

    #[test]
    fn test_cron_with_token_allowed() {
        let mut session = AgentSession::new(
            "cron-job",
            SessionType::Cron { schedule_id: "daily-backup".into() },
        );
        session.token_id = Some(Uuid::new_v4());
        assert_eq!(check_session_access(&session), AccessDecision::Allow);
    }

    // ---- Token inheritance tests ----

    #[test]
    fn test_inherit_token_success() {
        let cred_id = Uuid::new_v4();
        let (mut gw, parent_token) = mock_gateway_with_token(cred_id);

        let result = inherit_token(&mut gw, &parent_token, "sub-agent", &[cred_id], 1800);
        assert!(result.is_ok());

        let sub_token_id = result.unwrap();
        // Verify sub-token exists
        assert!(gw.token_store.get_token(&sub_token_id).is_some());
    }

    #[test]
    fn test_inherit_token_scope_not_in_parent() {
        let cred_id = Uuid::new_v4();
        let other_cred = Uuid::new_v4();
        let (mut gw, parent_token) = mock_gateway_with_token(cred_id);

        let result = inherit_token(&mut gw, &parent_token, "sub-agent", &[other_cred], 1800);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not in parent"));
    }

    #[test]
    fn test_inherit_token_parent_not_found() {
        let mut gw = AgentGateway::new();
        let result = inherit_token(&mut gw, &Uuid::new_v4(), "sub-agent", &[Uuid::new_v4()], 1800);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_inherit_token_revoked_parent() {
        let cred_id = Uuid::new_v4();
        let (mut gw, parent_token) = mock_gateway_with_token(cred_id);
        gw.token_store.revoke_token(&parent_token);

        let result = inherit_token(&mut gw, &parent_token, "sub-agent", &[cred_id], 1800);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("revoked"));
    }

    // ---- Credential request tests ----

    #[test]
    fn test_request_credential_dm_session() {
        let cred_id = Uuid::new_v4();
        let entry = mock_entry(cred_id);
        let (mut gw, token_id) = mock_gateway_with_token(cred_id);

        let mut session = AgentSession::new("test-agent", SessionType::Dm);
        session.token_id = Some(token_id);

        let result = request_credential(&mut gw, &session, &cred_id, |id| {
            if *id == cred_id { Some(entry.clone()) } else { None }
        });
        assert!(result.is_ok());
        let cv = result.unwrap();
        assert_eq!(cv.title, "GitHub");
        assert!(matches!(cv.value, SecretValue::Password { .. }));
    }

    #[test]
    fn test_request_credential_group_session_denied() {
        let cred_id = Uuid::new_v4();
        let (mut gw, token_id) = mock_gateway_with_token(cred_id);

        let mut session = AgentSession::new("test-agent", SessionType::Group);
        session.token_id = Some(token_id);

        let result = request_credential(&mut gw, &session, &cred_id, |_| None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("group chat"));
    }

    #[test]
    fn test_request_credential_no_token() {
        let cred_id = Uuid::new_v4();
        let mut gw = AgentGateway::new();

        let session = AgentSession::new("test-agent", SessionType::Dm);
        // No token set

        let result = request_credential(&mut gw, &session, &cred_id, |_| None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No active token"));
    }

    // ---- Serialization tests ----

    #[test]
    fn test_session_type_serialization() {
        let types = vec![
            SessionType::Dm,
            SessionType::Group,
            SessionType::SubAgent { parent_token_id: Uuid::new_v4() },
            SessionType::Cron { schedule_id: "daily".into() },
        ];
        for st in types {
            let json = serde_json::to_string(&st).unwrap();
            let parsed: SessionType = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, st);
        }
    }

    #[test]
    fn test_agent_session_serialization() {
        let session = AgentSession::new("agent-1", SessionType::Dm);
        let json = serde_json::to_string(&session).unwrap();
        let parsed: AgentSession = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.agent_id, "agent-1");
        assert_eq!(parsed.session_type, SessionType::Dm);
    }

    #[test]
    fn test_access_decision_variants() {
        assert_eq!(AccessDecision::Allow, AccessDecision::Allow);
        assert_ne!(AccessDecision::Allow, AccessDecision::NeedsApproval);
        let deny = AccessDecision::Deny("reason".into());
        assert!(matches!(deny, AccessDecision::Deny(r) if r == "reason"));
    }

    #[test]
    fn test_inherit_token_ttl_capped() {
        let cred_id = Uuid::new_v4();
        let (mut gw, parent_token) = mock_gateway_with_token(cred_id);

        // Request a huge TTL — should be capped to parent's remaining
        let result = inherit_token(&mut gw, &parent_token, "sub-agent", &[cred_id], 999_999);
        assert!(result.is_ok());
        let sub_token = gw.token_store.get_token(&result.unwrap()).unwrap();
        // Sub-token TTL should be <= parent's original 3600
        assert!(sub_token.ttl_seconds <= 3600);
    }
}
