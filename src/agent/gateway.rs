use std::time::Instant;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::vault::entry::{Credential, Entry, EntryId};
use super::approval::ApprovalManager;
use super::audit::{AlertConfig, AuditLog, AuditResult, DashboardSummary};
use super::token::{AccessRequest, AgentAction, AgentToken, TokenId, TokenStore};

/// Gateway API request types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method")]
pub enum GatewayRequest {
    /// Agent requests credential access.
    #[serde(rename = "agent.request")]
    RequestAccess {
        agent_id: String,
        scopes: Vec<EntryId>,
        actions: Vec<AgentAction>,
        ttl: u64,
        max_uses: Option<u32>,
        reason: String,
    },
    /// Human approves a request.
    #[serde(rename = "agent.grant")]
    Grant {
        request_id: Uuid,
        approved_by: String,
    },
    /// Human denies a request.
    #[serde(rename = "agent.deny")]
    Deny { request_id: Uuid },
    /// Revoke an active token.
    #[serde(rename = "agent.revoke")]
    Revoke { token_id: TokenId },
    /// List active tokens.
    #[serde(rename = "agent.tokens")]
    ListTokens,
    /// List pending requests.
    #[serde(rename = "agent.pending")]
    ListPending,
    /// Get audit log.
    #[serde(rename = "agent.audit")]
    Audit {
        agent_id: Option<String>,
        last_n: Option<usize>,
    },
    /// Agent retrieves a credential using a token.
    #[serde(rename = "agent.credential")]
    GetCredential {
        token_id: TokenId,
        credential_id: EntryId,
    },
    /// Get the audit dashboard summary.
    #[serde(rename = "agent.dashboard")]
    Dashboard,
}

/// Gateway API response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum GatewayResponse {
    #[serde(rename = "ok")]
    Ok { data: GatewayData },
    #[serde(rename = "error")]
    Error { message: String },
}

/// The secret value extracted from a credential — minimal data for agent use.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SecretValue {
    #[serde(rename = "password")]
    Password { password: String },
    #[serde(rename = "api_key")]
    ApiKey { key: String, secret: String },
    #[serde(rename = "note")]
    Note { content: String },
    #[serde(rename = "ssh_key")]
    SshKey { private_key: String },
}

/// Credential value returned to an agent — title + secret, no metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialValue {
    pub credential_id: EntryId,
    pub title: String,
    pub value: SecretValue,
}

impl CredentialValue {
    /// Extract minimal credential value from a full vault entry.
    pub fn from_entry(entry: &Entry) -> Self {
        let value = match &entry.credential {
            Credential::Login(c) => SecretValue::Password { password: c.password.clone() },
            Credential::ApiKey(c) => SecretValue::ApiKey { key: c.key.clone(), secret: c.secret.clone() },
            Credential::SecureNote(c) => SecretValue::Note { content: c.content.clone() },
            Credential::SshKey(c) => SecretValue::SshKey { private_key: c.private_key.clone() },
            Credential::Passkey(c) => SecretValue::Note { content: format!("passkey:{}", c.credential_id) },
        };
        Self {
            credential_id: entry.id,
            title: entry.title.clone(),
            value,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GatewayData {
    None,
    RequestId(Uuid),
    Token(AgentToken),
    Tokens(Vec<AgentToken>),
    Requests(Vec<AccessRequest>),
    AuditEntries(Vec<super::audit::AuditEntry>),
    Credential(CredentialValue),
    CredentialAccess { credential_id: EntryId, granted: bool },
    Dashboard(DashboardSummary),
}

impl GatewayResponse {
    pub fn ok(data: GatewayData) -> Self {
        Self::Ok { data }
    }

    pub fn error(msg: impl Into<String>) -> Self {
        Self::Error { message: msg.into() }
    }
}

/// Per-token rate limiter using a sliding window.
#[derive(Debug)]
pub struct RateLimiter {
    /// token_id -> (window_start, request_count)
    windows: std::collections::HashMap<TokenId, (Instant, u32)>,
    /// Default max requests per 60-second window.
    pub default_max_per_minute: u32,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self { windows: std::collections::HashMap::new(), default_max_per_minute: 60 }
    }
}

impl RateLimiter {
    pub fn new(default_max_per_minute: u32) -> Self {
        Self { windows: std::collections::HashMap::new(), default_max_per_minute }
    }

    /// Check and increment rate limit for a token. Returns true if allowed.
    pub fn check(&mut self, token_id: &TokenId) -> bool {
        let now = Instant::now();
        let entry = self.windows.entry(*token_id).or_insert((now, 0));

        // Reset window if 60 seconds have passed
        if now.duration_since(entry.0).as_secs() >= 60 {
            *entry = (now, 0);
        }

        if entry.1 >= self.default_max_per_minute {
            return false;
        }

        entry.1 += 1;
        true
    }

    /// Remove tracking for a revoked/expired token.
    pub fn remove(&mut self, token_id: &TokenId) {
        self.windows.remove(token_id);
    }
}

/// The Agent Gateway handles all agent-related operations.
pub struct AgentGateway {
    pub token_store: TokenStore,
    pub audit_log: AuditLog,
    pub approval_manager: ApprovalManager,
    pub rate_limiter: RateLimiter,
}

impl Default for AgentGateway {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentGateway {
    pub fn new() -> Self {
        Self {
            token_store: TokenStore::new(),
            audit_log: AuditLog::new(),
            approval_manager: ApprovalManager::new(),
            rate_limiter: RateLimiter::default(),
        }
    }

    /// Handle a gateway request.
    /// `credential_lookup` is called to fetch credential entries from the vault
    /// when a token is validated for `GetCredential`.
    pub fn handle(&mut self, request: GatewayRequest) -> GatewayResponse {
        self.handle_with_lookup(request, |_| None)
    }

    /// Handle a gateway request with a credential lookup function.
    /// The lookup takes an `EntryId` and returns `Option<&Entry>`.
    pub fn handle_with_lookup<F>(&mut self, request: GatewayRequest, credential_lookup: F) -> GatewayResponse
    where
        F: Fn(&EntryId) -> Option<Entry>,
    {
        match request {
            GatewayRequest::RequestAccess {
                agent_id,
                scopes,
                actions,
                ttl,
                max_uses,
                reason,
            } => {
                // Check if any requested credential is marked sensitive
                let has_sensitive = scopes.iter().any(|id| {
                    credential_lookup(id).is_some_and(|entry| entry.sensitive)
                });

                // Check auto-approval
                let can_auto = self.approval_manager.check_auto_approve(
                    &agent_id, &scopes, &actions, ttl, has_sensitive,
                );

                let access_request = AccessRequest::new(
                    agent_id.clone(),
                    scopes,
                    actions,
                    ttl,
                    max_uses,
                    reason,
                );
                let req_id = self.token_store.submit_request(access_request);

                if can_auto {
                    if let Some(token) = self.token_store.approve_request(&req_id, "auto-policy".to_string()) {
                        return GatewayResponse::ok(GatewayData::Token(token));
                    }
                }

                GatewayResponse::ok(GatewayData::RequestId(req_id))
            }

            GatewayRequest::Grant {
                request_id,
                approved_by,
            } => match self.token_store.approve_request(&request_id, approved_by) {
                Some(token) => GatewayResponse::ok(GatewayData::Token(token)),
                None => GatewayResponse::error("Request not found or already processed"),
            },

            GatewayRequest::Deny { request_id } => {
                if self.token_store.deny_request(&request_id) {
                    GatewayResponse::ok(GatewayData::None)
                } else {
                    GatewayResponse::error("Request not found or already processed")
                }
            }

            GatewayRequest::Revoke { token_id } => {
                if self.token_store.revoke_token(&token_id) {
                    GatewayResponse::ok(GatewayData::None)
                } else {
                    GatewayResponse::error("Token not found")
                }
            }

            GatewayRequest::ListTokens => {
                let tokens: Vec<AgentToken> = self.token_store.active_tokens().into_iter().cloned().collect();
                GatewayResponse::ok(GatewayData::Tokens(tokens))
            }

            GatewayRequest::ListPending => {
                let requests: Vec<AccessRequest> = self.token_store.pending_requests().into_iter().cloned().collect();
                GatewayResponse::ok(GatewayData::Requests(requests))
            }

            GatewayRequest::Audit { agent_id, last_n } => {
                let entries = if let Some(aid) = agent_id {
                    self.audit_log.entries_for_agent(&aid).into_iter().cloned().collect()
                } else if let Some(n) = last_n {
                    self.audit_log.last_n(n).into_iter().cloned().collect()
                } else {
                    self.audit_log.entries().to_vec()
                };
                GatewayResponse::ok(GatewayData::AuditEntries(entries))
            }

            GatewayRequest::Dashboard => {
                let active = self.token_store.active_tokens().len();
                let pending = self.token_store.pending_requests().len();
                let summary = self.audit_log.dashboard_summary(active, pending, &AlertConfig::default());
                GatewayResponse::ok(GatewayData::Dashboard(summary))
            }

            GatewayRequest::GetCredential {
                token_id,
                credential_id,
            } => {
                let agent_id = self.token_store.get_token(&token_id)
                    .map(|t| t.agent_id.clone())
                    .unwrap_or_default();

                // Rate limit check before token validation
                if !self.rate_limiter.check(&token_id) {
                    self.audit_log.record(
                        agent_id,
                        token_id,
                        credential_id,
                        AgentAction::Read,
                        AuditResult::RateLimited,
                        None,
                    );
                    return GatewayResponse::error("Rate limit exceeded");
                }

                match self.token_store.validate_token(&token_id, &credential_id, AgentAction::Read) {
                    Ok(()) => {
                        // Try to fetch the actual credential
                        match credential_lookup(&credential_id) {
                            Some(entry) => {
                                self.audit_log.record(
                                    agent_id,
                                    token_id,
                                    credential_id,
                                    AgentAction::Read,
                                    AuditResult::Success,
                                    None,
                                );
                                GatewayResponse::ok(GatewayData::Credential(
                                    CredentialValue::from_entry(&entry),
                                ))
                            }
                            None => {
                                // Token is valid but vault is locked or entry not found
                                self.audit_log.record(
                                    agent_id,
                                    token_id,
                                    credential_id,
                                    AgentAction::Read,
                                    AuditResult::Error("Credential not found in vault".into()),
                                    None,
                                );
                                GatewayResponse::error("Credential not found in vault (vault may be locked)")
                            }
                        }
                    }
                    Err(reason) => {
                        let result = if reason.contains("expired") {
                            AuditResult::TokenExpired
                        } else if reason.contains("revoked") {
                            AuditResult::TokenRevoked
                        } else if reason.contains("scope") {
                            AuditResult::ScopeViolation
                        } else {
                            AuditResult::Denied
                        };

                        self.audit_log.record(
                            agent_id,
                            token_id,
                            credential_id,
                            AgentAction::Read,
                            result,
                            None,
                        );
                        GatewayResponse::error(reason)
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::entry::{LoginCredential, ApiKeyCredential, SecureNoteCredential, SshKeyCredential};

    // ---- Helper functions for extracting response data ----

    fn expect_request_id(resp: GatewayResponse) -> Uuid {
        match resp {
            GatewayResponse::Ok { data: GatewayData::RequestId(id) } => id,
            other => panic!("Expected RequestId, got: {:?}", other),
        }
    }

    fn expect_token(resp: GatewayResponse) -> AgentToken {
        match resp {
            GatewayResponse::Ok { data: GatewayData::Token(t) } => t,
            other => panic!("Expected Token, got: {:?}", other),
        }
    }

    fn expect_tokens(resp: GatewayResponse) -> Vec<AgentToken> {
        match resp {
            GatewayResponse::Ok { data: GatewayData::Tokens(t) } => t,
            other => panic!("Expected Tokens, got: {:?}", other),
        }
    }

    fn expect_requests(resp: GatewayResponse) -> Vec<AccessRequest> {
        match resp {
            GatewayResponse::Ok { data: GatewayData::Requests(r) } => r,
            other => panic!("Expected Requests, got: {:?}", other),
        }
    }

    fn expect_audit_entries(resp: GatewayResponse) -> Vec<super::super::audit::AuditEntry> {
        match resp {
            GatewayResponse::Ok { data: GatewayData::AuditEntries(e) } => e,
            other => panic!("Expected AuditEntries, got: {:?}", other),
        }
    }

    fn expect_credential(resp: GatewayResponse) -> CredentialValue {
        match resp {
            GatewayResponse::Ok { data: GatewayData::Credential(c) } => c,
            other => panic!("Expected Credential, got: {:?}", other),
        }
    }

    fn expect_credential_access(resp: GatewayResponse) -> (EntryId, bool) {
        match resp {
            GatewayResponse::Ok { data: GatewayData::CredentialAccess { credential_id, granted } } => (credential_id, granted),
            other => panic!("Expected CredentialAccess, got: {:?}", other),
        }
    }

    fn expect_gw_error(resp: GatewayResponse) -> String {
        match resp {
            GatewayResponse::Error { message } => message,
            other => panic!("Expected Error, got: {:?}", other),
        }
    }

    /// Create a mock login entry with a specific ID.
    fn mock_login_entry(id: EntryId) -> Entry {
        let mut entry = Entry::new("GitHub".into(), Credential::Login(LoginCredential {
            url: "https://github.com".into(),
            username: "user".into(),
            password: "s3cret".into(),
        }));
        entry.id = id;
        entry
    }

    /// Create a mock API key entry with a specific ID.
    fn mock_api_key_entry(id: EntryId) -> Entry {
        let mut entry = Entry::new("AWS".into(), Credential::ApiKey(ApiKeyCredential {
            service: "aws".into(),
            key: "AKIAIOSFODNN7EXAMPLE".into(),
            secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
        }));
        entry.id = id;
        entry
    }

    /// Create a credential lookup that returns a clone of the entry for matching IDs.
    fn make_lookup(entries: Vec<Entry>) -> impl Fn(&EntryId) -> Option<Entry> {
        move |id| entries.iter().find(|e| &e.id == id).cloned()
    }

    // ---- Tests ----

    #[test]
    fn test_request_and_grant_flow_with_credential_delivery() {
        let mut gw = AgentGateway::new();
        let cred = Uuid::new_v4();
        let entry = mock_login_entry(cred);
        let lookup = make_lookup(vec![entry]);

        // Agent requests access
        let resp = gw.handle(GatewayRequest::RequestAccess {
            agent_id: "agent-1".into(),
            scopes: vec![cred],
            actions: vec![AgentAction::Read],
            ttl: 3600,
            max_uses: None,
            reason: "deploy".into(),
        });
        let req_id = expect_request_id(resp);

        // Human approves
        let resp = gw.handle(GatewayRequest::Grant {
            request_id: req_id,
            approved_by: "human:cli".into(),
        });
        let token = expect_token(resp);

        // Agent retrieves credential — should get actual value
        let resp = gw.handle_with_lookup(
            GatewayRequest::GetCredential { token_id: token.id, credential_id: cred },
            &lookup,
        );
        let cred_val = expect_credential(resp);
        assert_eq!(cred_val.credential_id, cred);
        assert_eq!(cred_val.title, "GitHub");
        assert!(matches!(cred_val.value, SecretValue::Password { password } if password == "s3cret"));

        assert_eq!(gw.audit_log.len(), 1);
    }

    #[test]
    fn test_credential_delivery_api_key() {
        let mut gw = AgentGateway::new();
        let cred = Uuid::new_v4();
        let entry = mock_api_key_entry(cred);
        let lookup = make_lookup(vec![entry]);

        let resp = gw.handle(GatewayRequest::RequestAccess {
            agent_id: "a".into(), scopes: vec![cred], actions: vec![AgentAction::Read],
            ttl: 3600, max_uses: None, reason: "t".into(),
        });
        let req_id = expect_request_id(resp);
        let resp = gw.handle(GatewayRequest::Grant { request_id: req_id, approved_by: "h".into() });
        let token = expect_token(resp);

        let resp = gw.handle_with_lookup(
            GatewayRequest::GetCredential { token_id: token.id, credential_id: cred },
            &lookup,
        );
        let cred_val = expect_credential(resp);
        assert!(matches!(cred_val.value, SecretValue::ApiKey { key, .. } if key == "AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_credential_delivery_secure_note() {
        let mut gw = AgentGateway::new();
        let cred = Uuid::new_v4();
        let mut entry = Entry::new("Note".into(), Credential::SecureNote(SecureNoteCredential {
            content: "top secret".into(),
        }));
        entry.id = cred;
        let lookup = make_lookup(vec![entry]);

        let resp = gw.handle(GatewayRequest::RequestAccess {
            agent_id: "a".into(), scopes: vec![cred], actions: vec![AgentAction::Read],
            ttl: 3600, max_uses: None, reason: "t".into(),
        });
        let req_id = expect_request_id(resp);
        let resp = gw.handle(GatewayRequest::Grant { request_id: req_id, approved_by: "h".into() });
        let token = expect_token(resp);

        let resp = gw.handle_with_lookup(
            GatewayRequest::GetCredential { token_id: token.id, credential_id: cred },
            &lookup,
        );
        let cred_val = expect_credential(resp);
        assert!(matches!(cred_val.value, SecretValue::Note { content } if content == "top secret"));
    }

    #[test]
    fn test_credential_delivery_ssh_key() {
        let mut gw = AgentGateway::new();
        let cred = Uuid::new_v4();
        let mut entry = Entry::new("SSH".into(), Credential::SshKey(SshKeyCredential {
            private_key: "-----BEGIN RSA PRIVATE KEY-----".into(),
            public_key: "ssh-rsa AAAA...".into(),
            passphrase: "pass".into(),
        }));
        entry.id = cred;
        let lookup = make_lookup(vec![entry]);

        let resp = gw.handle(GatewayRequest::RequestAccess {
            agent_id: "a".into(), scopes: vec![cred], actions: vec![AgentAction::Read],
            ttl: 3600, max_uses: None, reason: "t".into(),
        });
        let req_id = expect_request_id(resp);
        let resp = gw.handle(GatewayRequest::Grant { request_id: req_id, approved_by: "h".into() });
        let token = expect_token(resp);

        let resp = gw.handle_with_lookup(
            GatewayRequest::GetCredential { token_id: token.id, credential_id: cred },
            &lookup,
        );
        let cred_val = expect_credential(resp);
        assert!(matches!(cred_val.value, SecretValue::SshKey { private_key } if private_key.contains("RSA")));
    }

    #[test]
    fn test_credential_not_found_in_vault() {
        let mut gw = AgentGateway::new();
        let cred = Uuid::new_v4();

        // No lookup provided (default handle returns None for all lookups)
        let resp = gw.handle(GatewayRequest::RequestAccess {
            agent_id: "a".into(), scopes: vec![cred], actions: vec![AgentAction::Read],
            ttl: 3600, max_uses: None, reason: "t".into(),
        });
        let req_id = expect_request_id(resp);
        let resp = gw.handle(GatewayRequest::Grant { request_id: req_id, approved_by: "h".into() });
        let token = expect_token(resp);

        let resp = gw.handle(GatewayRequest::GetCredential { token_id: token.id, credential_id: cred });
        let msg = expect_gw_error(resp);
        assert!(msg.contains("not found in vault"));
    }

    #[test]
    fn test_deny_flow() {
        let mut gw = AgentGateway::new();
        let resp = gw.handle(GatewayRequest::RequestAccess {
            agent_id: "agent".into(),
            scopes: vec![Uuid::new_v4()],
            actions: vec![AgentAction::Read],
            ttl: 3600,
            max_uses: None,
            reason: "test".into(),
        });

        let req_id = expect_request_id(resp);

        let resp = gw.handle(GatewayRequest::Deny { request_id: req_id });
        assert!(matches!(resp, GatewayResponse::Ok { .. }));
    }

    #[test]
    fn test_revoke_flow() {
        let mut gw = AgentGateway::new();
        let cred = Uuid::new_v4();

        let resp = gw.handle(GatewayRequest::RequestAccess {
            agent_id: "agent".into(),
            scopes: vec![cred],
            actions: vec![AgentAction::Read],
            ttl: 3600,
            max_uses: None,
            reason: "test".into(),
        });
        let req_id = expect_request_id(resp);

        let resp = gw.handle(GatewayRequest::Grant { request_id: req_id, approved_by: "h".into() });
        let token = expect_token(resp);
        let token_id = token.id;

        // Revoke
        let resp = gw.handle(GatewayRequest::Revoke { token_id });
        assert!(matches!(resp, GatewayResponse::Ok { .. }));

        // Access should fail
        let resp = gw.handle(GatewayRequest::GetCredential { token_id, credential_id: cred });
        assert!(matches!(resp, GatewayResponse::Error { .. }));
    }

    #[test]
    fn test_auto_approve_with_policy() {
        let mut gw = AgentGateway::new();
        let cred = Uuid::new_v4();

        gw.approval_manager.add_policy(super::super::approval::ApprovalPolicy {
            agent_id: "trusted".into(),
            allowed_scopes: vec![cred],
            allowed_actions: vec![AgentAction::Read],
            max_auto_approve_ttl: 3600,
            require_manual_for_sensitive: false,
        });

        let resp = gw.handle(GatewayRequest::RequestAccess {
            agent_id: "trusted".into(),
            scopes: vec![cred],
            actions: vec![AgentAction::Read],
            ttl: 1800,
            max_uses: None,
            reason: "auto".into(),
        });

        // Should auto-approve and return a token directly
        let token = expect_token(resp);
        assert_eq!(token.agent_id, "trusted");
    }

    #[test]
    fn test_auto_approve_fallback_when_approve_returns_none() {
        let mut gw = AgentGateway::new();
        let cred = Uuid::new_v4();

        gw.approval_manager.add_policy(super::super::approval::ApprovalPolicy {
            agent_id: "trusted".into(),
            allowed_scopes: vec![cred],
            allowed_actions: vec![AgentAction::Read],
            max_auto_approve_ttl: 3600,
            require_manual_for_sensitive: false,
        });

        let access_request = AccessRequest::new(
            "trusted".into(), vec![cred], vec![AgentAction::Read], 1800, None, "pre-approved".into(),
        );
        let req_id = gw.token_store.submit_request(access_request);
        gw.token_store.approve_request(&req_id, "pre".into());

        let resp = gw.handle(GatewayRequest::RequestAccess {
            agent_id: "trusted".into(),
            scopes: vec![cred],
            actions: vec![AgentAction::Read],
            ttl: 1800,
            max_uses: None,
            reason: "auto-test".into(),
        });

        let token = expect_token(resp);
        assert_eq!(token.agent_id, "trusted");
    }

    #[test]
    fn test_list_tokens() {
        let mut gw = AgentGateway::new();
        let resp = gw.handle(GatewayRequest::ListTokens);
        let tokens = expect_tokens(resp);
        assert!(tokens.is_empty());
    }

    #[test]
    fn test_list_pending() {
        let mut gw = AgentGateway::new();
        gw.handle(GatewayRequest::RequestAccess {
            agent_id: "a".into(), scopes: vec![Uuid::new_v4()], actions: vec![AgentAction::Read],
            ttl: 3600, max_uses: None, reason: "t".into(),
        });
        let resp = gw.handle(GatewayRequest::ListPending);
        let requests = expect_requests(resp);
        assert_eq!(requests.len(), 1);
    }

    #[test]
    fn test_audit_query() {
        let mut gw = AgentGateway::new();
        gw.audit_log.record("a".into(), Uuid::new_v4(), Uuid::new_v4(), AgentAction::Read, AuditResult::Success, None);
        gw.audit_log.record("b".into(), Uuid::new_v4(), Uuid::new_v4(), AgentAction::Read, AuditResult::Denied, None);

        let resp = gw.handle(GatewayRequest::Audit { agent_id: Some("a".into()), last_n: None });
        let entries = expect_audit_entries(resp);
        assert_eq!(entries.len(), 1);

        let resp = gw.handle(GatewayRequest::Audit { agent_id: None, last_n: Some(1) });
        let entries = expect_audit_entries(resp);
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_scope_violation_audit() {
        let mut gw = AgentGateway::new();
        let cred = Uuid::new_v4();
        let wrong_cred = Uuid::new_v4();

        let resp = gw.handle(GatewayRequest::RequestAccess {
            agent_id: "a".into(), scopes: vec![cred], actions: vec![AgentAction::Read],
            ttl: 3600, max_uses: None, reason: "t".into(),
        });
        let req_id = expect_request_id(resp);
        let resp = gw.handle(GatewayRequest::Grant { request_id: req_id, approved_by: "h".into() });
        let token = expect_token(resp);

        let resp = gw.handle(GatewayRequest::GetCredential { token_id: token.id, credential_id: wrong_cred });
        assert!(matches!(resp, GatewayResponse::Error { .. }));
        assert_eq!(gw.audit_log.len(), 1);
    }

    #[test]
    fn test_gateway_serialization() {
        let req = GatewayRequest::RequestAccess {
            agent_id: "test".into(), scopes: vec![Uuid::new_v4()], actions: vec![AgentAction::Read],
            ttl: 3600, max_uses: Some(10), reason: "deploy".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("agent.request"));
    }

    #[test]
    fn test_grant_nonexistent_request() {
        let mut gw = AgentGateway::new();
        let resp = gw.handle(GatewayRequest::Grant { request_id: Uuid::new_v4(), approved_by: "human".into() });
        let msg = expect_gw_error(resp);
        assert!(msg.contains("not found"));
    }

    #[test]
    fn test_deny_nonexistent_request() {
        let mut gw = AgentGateway::new();
        let resp = gw.handle(GatewayRequest::Deny { request_id: Uuid::new_v4() });
        let msg = expect_gw_error(resp);
        assert!(msg.contains("not found"));
    }

    #[test]
    fn test_revoke_nonexistent_token() {
        let mut gw = AgentGateway::new();
        let resp = gw.handle(GatewayRequest::Revoke { token_id: Uuid::new_v4() });
        let msg = expect_gw_error(resp);
        assert!(msg.contains("not found"));
    }

    #[test]
    fn test_audit_all_entries() {
        let mut gw = AgentGateway::new();
        gw.audit_log.record("a".into(), Uuid::new_v4(), Uuid::new_v4(), AgentAction::Read, AuditResult::Success, None);
        gw.audit_log.record("b".into(), Uuid::new_v4(), Uuid::new_v4(), AgentAction::Read, AuditResult::Denied, None);

        let resp = gw.handle(GatewayRequest::Audit { agent_id: None, last_n: None });
        let entries = expect_audit_entries(resp);
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_get_credential_with_expired_token() {
        let mut gw = AgentGateway::new();
        let cred = Uuid::new_v4();

        let resp = gw.handle(GatewayRequest::RequestAccess {
            agent_id: "a".into(), scopes: vec![cred], actions: vec![AgentAction::Read],
            ttl: 1, max_uses: None, reason: "t".into(),
        });
        let req_id = expect_request_id(resp);
        let resp = gw.handle(GatewayRequest::Grant { request_id: req_id, approved_by: "h".into() });
        let token = expect_token(resp);

        std::thread::sleep(std::time::Duration::from_secs(2));

        let resp = gw.handle(GatewayRequest::GetCredential { token_id: token.id, credential_id: cred });
        let msg = expect_gw_error(resp);
        assert!(msg.contains("expired"));
        assert_eq!(gw.audit_log.len(), 1);
    }

    #[test]
    fn test_get_credential_max_uses_exceeded() {
        let mut gw = AgentGateway::new();
        let cred = Uuid::new_v4();
        let entry = mock_login_entry(cred);
        let lookup = make_lookup(vec![entry]);

        let resp = gw.handle(GatewayRequest::RequestAccess {
            agent_id: "a".into(), scopes: vec![cred], actions: vec![AgentAction::Read],
            ttl: 3600, max_uses: Some(1), reason: "t".into(),
        });
        let req_id = expect_request_id(resp);
        let resp = gw.handle(GatewayRequest::Grant { request_id: req_id, approved_by: "h".into() });
        let token = expect_token(resp);

        // First use succeeds with credential delivery
        let resp = gw.handle_with_lookup(
            GatewayRequest::GetCredential { token_id: token.id, credential_id: cred },
            &lookup,
        );
        assert!(matches!(resp, GatewayResponse::Ok { data: GatewayData::Credential(_) }));

        // Second use fails (max_uses=1 exceeded)
        let resp = gw.handle_with_lookup(
            GatewayRequest::GetCredential { token_id: token.id, credential_id: cred },
            &lookup,
        );
        assert!(matches!(resp, GatewayResponse::Error { .. }));
        assert_eq!(gw.audit_log.len(), 2);
    }

    #[test]
    fn test_get_credential_nonexistent_token() {
        let mut gw = AgentGateway::new();
        let resp = gw.handle(GatewayRequest::GetCredential {
            token_id: Uuid::new_v4(), credential_id: Uuid::new_v4(),
        });
        let _msg = expect_gw_error(resp);
        assert_eq!(gw.audit_log.len(), 1);
    }

    #[test]
    fn test_gateway_response_constructors() {
        let ok = GatewayResponse::ok(GatewayData::None);
        assert!(matches!(ok, GatewayResponse::Ok { .. }));

        let err = GatewayResponse::error("test error");
        let msg = expect_gw_error(err);
        assert_eq!(msg, "test error");
    }

    #[test]
    fn test_gateway_new() {
        let gw = AgentGateway::new();
        assert!(gw.token_store.active_tokens().is_empty());
        assert_eq!(gw.audit_log.len(), 0);
    }

    #[test]
    fn test_gateway_data_serialization() {
        let data = GatewayData::None;
        let json = serde_json::to_string(&data).unwrap();
        assert!(!json.is_empty());

        let data = GatewayData::RequestId(Uuid::new_v4());
        let json = serde_json::to_string(&data).unwrap();
        assert!(!json.is_empty());

        let data = GatewayData::Tokens(vec![]);
        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains("[]"));

        let data = GatewayData::Requests(vec![]);
        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains("[]"));

        let data = GatewayData::AuditEntries(vec![]);
        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains("[]"));

        let data = GatewayData::CredentialAccess { credential_id: Uuid::new_v4(), granted: true };
        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains("true"));

        // Test Credential variant serialization
        let cred_val = CredentialValue {
            credential_id: Uuid::new_v4(),
            title: "test".into(),
            value: SecretValue::Password { password: "pw".into() },
        };
        let data = GatewayData::Credential(cred_val);
        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains("password"));
    }

    #[test]
    fn test_gateway_request_all_variants_serialize() {
        let requests: Vec<GatewayRequest> = vec![
            GatewayRequest::RequestAccess {
                agent_id: "a".into(), scopes: vec![Uuid::new_v4()], actions: vec![AgentAction::Read],
                ttl: 3600, max_uses: Some(5), reason: "test".into(),
            },
            GatewayRequest::Grant { request_id: Uuid::new_v4(), approved_by: "h".into() },
            GatewayRequest::Deny { request_id: Uuid::new_v4() },
            GatewayRequest::Revoke { token_id: Uuid::new_v4() },
            GatewayRequest::ListTokens,
            GatewayRequest::ListPending,
            GatewayRequest::Audit { agent_id: Some("a".into()), last_n: None },
            GatewayRequest::Audit { agent_id: None, last_n: Some(10) },
            GatewayRequest::GetCredential { token_id: Uuid::new_v4(), credential_id: Uuid::new_v4() },
        ];
        for req in requests {
            let json = serde_json::to_string(&req).unwrap();
            assert!(!json.is_empty());
            let _: GatewayRequest = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_get_credential_use_action() {
        let mut gw = AgentGateway::new();
        let cred = Uuid::new_v4();

        let resp = gw.handle(GatewayRequest::RequestAccess {
            agent_id: "agent".into(), scopes: vec![cred], actions: vec![AgentAction::Use],
            ttl: 3600, max_uses: None, reason: "autofill".into(),
        });
        let req_id = expect_request_id(resp);
        let resp = gw.handle(GatewayRequest::Grant { request_id: req_id, approved_by: "h".into() });
        let token = expect_token(resp);

        // GetCredential requires Read action; Use-only token should fail
        let resp = gw.handle(GatewayRequest::GetCredential { token_id: token.id, credential_id: cred });
        assert!(matches!(resp, GatewayResponse::Error { .. }));
    }

    #[test]
    fn test_revoked_token_audit_result() {
        let mut gw = AgentGateway::new();
        let cred = Uuid::new_v4();

        let resp = gw.handle(GatewayRequest::RequestAccess {
            agent_id: "a".into(), scopes: vec![cred], actions: vec![AgentAction::Read],
            ttl: 3600, max_uses: None, reason: "t".into(),
        });
        let req_id = expect_request_id(resp);
        let resp = gw.handle(GatewayRequest::Grant { request_id: req_id, approved_by: "h".into() });
        let token = expect_token(resp);

        gw.handle(GatewayRequest::Revoke { token_id: token.id });
        let resp = gw.handle(GatewayRequest::GetCredential { token_id: token.id, credential_id: cred });
        assert!(matches!(resp, GatewayResponse::Error { .. }));
        assert!(!gw.audit_log.entries().is_empty());
    }

    // ---- Rate limiter tests ----

    #[test]
    fn test_rate_limiter_basic() {
        let mut rl = RateLimiter::new(3);
        let token = Uuid::new_v4();

        assert!(rl.check(&token));
        assert!(rl.check(&token));
        assert!(rl.check(&token));
        // 4th should fail
        assert!(!rl.check(&token));
    }

    #[test]
    fn test_rate_limiter_separate_tokens() {
        let mut rl = RateLimiter::new(2);
        let t1 = Uuid::new_v4();
        let t2 = Uuid::new_v4();

        assert!(rl.check(&t1));
        assert!(rl.check(&t1));
        assert!(!rl.check(&t1)); // t1 exhausted

        // t2 should still work
        assert!(rl.check(&t2));
    }

    #[test]
    fn test_rate_limiter_remove() {
        let mut rl = RateLimiter::new(1);
        let token = Uuid::new_v4();

        assert!(rl.check(&token));
        assert!(!rl.check(&token));

        rl.remove(&token);
        // After removal, token gets a fresh window
        assert!(rl.check(&token));
    }

    #[test]
    fn test_rate_limiter_default() {
        let rl = RateLimiter::default();
        assert_eq!(rl.default_max_per_minute, 60);
    }

    #[test]
    fn test_rate_limit_on_credential_access() {
        let mut gw = AgentGateway::new();
        gw.rate_limiter = RateLimiter::new(2); // Very low limit for testing
        let cred = Uuid::new_v4();
        let entry = mock_login_entry(cred);
        let lookup = make_lookup(vec![entry]);

        let resp = gw.handle(GatewayRequest::RequestAccess {
            agent_id: "a".into(), scopes: vec![cred], actions: vec![AgentAction::Read],
            ttl: 3600, max_uses: None, reason: "t".into(),
        });
        let req_id = expect_request_id(resp);
        let resp = gw.handle(GatewayRequest::Grant { request_id: req_id, approved_by: "h".into() });
        let token = expect_token(resp);

        // First two requests OK
        let resp = gw.handle_with_lookup(
            GatewayRequest::GetCredential { token_id: token.id, credential_id: cred },
            &lookup,
        );
        assert!(matches!(resp, GatewayResponse::Ok { .. }));

        let resp = gw.handle_with_lookup(
            GatewayRequest::GetCredential { token_id: token.id, credential_id: cred },
            &lookup,
        );
        assert!(matches!(resp, GatewayResponse::Ok { .. }));

        // Third request should be rate limited
        let resp = gw.handle_with_lookup(
            GatewayRequest::GetCredential { token_id: token.id, credential_id: cred },
            &lookup,
        );
        let msg = expect_gw_error(resp);
        assert!(msg.contains("Rate limit"));

        // Audit should have 2 Success + 1 RateLimited
        assert_eq!(gw.audit_log.len(), 3);
    }

    // ---- CredentialValue / SecretValue tests ----

    #[test]
    fn test_credential_value_from_login_entry() {
        let entry = Entry::new("GitHub".into(), Credential::Login(LoginCredential {
            url: "https://github.com".into(), username: "u".into(), password: "p".into(),
        }));
        let cv = CredentialValue::from_entry(&entry);
        assert_eq!(cv.title, "GitHub");
        assert!(matches!(cv.value, SecretValue::Password { password } if password == "p"));
    }

    #[test]
    fn test_credential_value_from_api_key_entry() {
        let entry = Entry::new("AWS".into(), Credential::ApiKey(ApiKeyCredential {
            service: "aws".into(), key: "K".into(), secret: "S".into(),
        }));
        let cv = CredentialValue::from_entry(&entry);
        assert!(matches!(cv.value, SecretValue::ApiKey { key, secret } if key == "K" && secret == "S"));
    }

    #[test]
    fn test_credential_value_from_note_entry() {
        let entry = Entry::new("Note".into(), Credential::SecureNote(SecureNoteCredential {
            content: "secret".into(),
        }));
        let cv = CredentialValue::from_entry(&entry);
        assert!(matches!(cv.value, SecretValue::Note { content } if content == "secret"));
    }

    #[test]
    fn test_credential_value_from_ssh_entry() {
        let entry = Entry::new("SSH".into(), Credential::SshKey(SshKeyCredential {
            private_key: "priv".into(), public_key: "pub".into(), passphrase: "pp".into(),
        }));
        let cv = CredentialValue::from_entry(&entry);
        assert!(matches!(cv.value, SecretValue::SshKey { private_key } if private_key == "priv"));
    }

    #[test]
    fn test_secret_value_serialization() {
        let values = vec![
            SecretValue::Password { password: "pw".into() },
            SecretValue::ApiKey { key: "k".into(), secret: "s".into() },
            SecretValue::Note { content: "c".into() },
            SecretValue::SshKey { private_key: "pk".into() },
        ];
        for val in values {
            let json = serde_json::to_string(&val).unwrap();
            let parsed: SecretValue = serde_json::from_str(&json).unwrap();
            assert_eq!(serde_json::to_string(&parsed).unwrap(), json);
        }
    }

    #[test]
    fn test_credential_value_serialization() {
        let cv = CredentialValue {
            credential_id: Uuid::new_v4(),
            title: "Test".into(),
            value: SecretValue::Password { password: "secret".into() },
        };
        let json = serde_json::to_string(&cv).unwrap();
        let parsed: CredentialValue = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.title, "Test");
    }

    // ---- #[should_panic] tests for helper coverage ----

    #[test]
    #[should_panic(expected = "Expected RequestId")]
    fn test_expect_request_id_wrong() {
        expect_request_id(GatewayResponse::error("wrong"));
    }

    #[test]
    #[should_panic(expected = "Expected Token")]
    fn test_expect_token_wrong() {
        expect_token(GatewayResponse::error("wrong"));
    }

    #[test]
    #[should_panic(expected = "Expected Tokens")]
    fn test_expect_tokens_wrong() {
        expect_tokens(GatewayResponse::error("wrong"));
    }

    #[test]
    #[should_panic(expected = "Expected Requests")]
    fn test_expect_requests_wrong() {
        expect_requests(GatewayResponse::error("wrong"));
    }

    #[test]
    #[should_panic(expected = "Expected AuditEntries")]
    fn test_expect_audit_entries_wrong() {
        expect_audit_entries(GatewayResponse::error("wrong"));
    }

    #[test]
    #[should_panic(expected = "Expected Credential")]
    fn test_expect_credential_wrong() {
        expect_credential(GatewayResponse::error("wrong"));
    }

    #[test]
    #[should_panic(expected = "Expected CredentialAccess")]
    fn test_expect_credential_access_wrong() {
        expect_credential_access(GatewayResponse::error("wrong"));
    }

    #[test]
    #[should_panic(expected = "Expected Error")]
    fn test_expect_gw_error_wrong() {
        expect_gw_error(GatewayResponse::ok(GatewayData::None));
    }

    // ---- Dashboard tests ----

    fn expect_dashboard(resp: GatewayResponse) -> super::super::audit::DashboardSummary {
        match resp {
            GatewayResponse::Ok { data: GatewayData::Dashboard(s) } => s,
            other => panic!("Expected Dashboard, got: {:?}", other),
        }
    }

    #[test]
    fn test_dashboard_empty() {
        let mut gw = AgentGateway::new();
        let resp = gw.handle(GatewayRequest::Dashboard);
        let summary = expect_dashboard(resp);
        assert_eq!(summary.total_events, 0);
        assert_eq!(summary.active_token_count, 0);
        assert_eq!(summary.pending_request_count, 0);
    }

    #[test]
    fn test_dashboard_with_activity() {
        let mut gw = AgentGateway::new();
        let cred = Uuid::new_v4();

        // Create a pending request + an active token
        gw.handle(GatewayRequest::RequestAccess {
            agent_id: "a".into(), scopes: vec![cred], actions: vec![AgentAction::Read],
            ttl: 3600, max_uses: None, reason: "t".into(),
        });
        let resp = gw.handle(GatewayRequest::RequestAccess {
            agent_id: "b".into(), scopes: vec![Uuid::new_v4()], actions: vec![AgentAction::Read],
            ttl: 3600, max_uses: None, reason: "t2".into(),
        });
        if let GatewayResponse::Ok { data: GatewayData::RequestId(req_id) } = resp {
            gw.handle(GatewayRequest::Grant { request_id: req_id, approved_by: "h".into() });
        }

        let resp = gw.handle(GatewayRequest::Dashboard);
        let summary = expect_dashboard(resp);
        assert_eq!(summary.pending_request_count, 1);
        assert_eq!(summary.active_token_count, 1);
    }

    #[test]
    fn test_dashboard_serialization() {
        let mut gw = AgentGateway::new();
        let resp = gw.handle(GatewayRequest::Dashboard);
        let summary = expect_dashboard(resp);
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("total_events"));
    }

    // ---- Sensitive credential auto-approve tests ----

    #[test]
    fn test_sensitive_credential_blocks_auto_approve() {
        let mut gw = AgentGateway::new();
        let cred = Uuid::new_v4();

        // Create a sensitive entry
        let mut entry = mock_login_entry(cred);
        entry.sensitive = true;
        let lookup = make_lookup(vec![entry]);

        // Add auto-approve policy
        gw.approval_manager.add_policy(super::super::approval::ApprovalPolicy {
            agent_id: "trusted".into(),
            allowed_scopes: vec![cred],
            allowed_actions: vec![AgentAction::Read],
            max_auto_approve_ttl: 3600,
            require_manual_for_sensitive: true,
        });

        // Request should NOT auto-approve because cred is sensitive
        let resp = gw.handle_with_lookup(GatewayRequest::RequestAccess {
            agent_id: "trusted".into(),
            scopes: vec![cred],
            actions: vec![AgentAction::Read],
            ttl: 1800,
            max_uses: None,
            reason: "auto".into(),
        }, &lookup);

        // Should get a RequestId (pending), not a Token (auto-approved)
        let _req_id = expect_request_id(resp);
    }

    #[test]
    fn test_non_sensitive_credential_auto_approves() {
        let mut gw = AgentGateway::new();
        let cred = Uuid::new_v4();

        // Non-sensitive entry
        let entry = mock_login_entry(cred);
        let lookup = make_lookup(vec![entry]);

        gw.approval_manager.add_policy(super::super::approval::ApprovalPolicy {
            agent_id: "trusted".into(),
            allowed_scopes: vec![cred],
            allowed_actions: vec![AgentAction::Read],
            max_auto_approve_ttl: 3600,
            require_manual_for_sensitive: true,
        });

        let resp = gw.handle_with_lookup(GatewayRequest::RequestAccess {
            agent_id: "trusted".into(),
            scopes: vec![cred],
            actions: vec![AgentAction::Read],
            ttl: 1800,
            max_uses: None,
            reason: "auto".into(),
        }, &lookup);

        // Should auto-approve
        let token = expect_token(resp);
        assert_eq!(token.agent_id, "trusted");
    }

    #[test]
    fn test_gateway_request_dashboard_serialization() {
        let req = GatewayRequest::Dashboard;
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("agent.dashboard"));
        let _: GatewayRequest = serde_json::from_str(&json).unwrap();
    }
}
