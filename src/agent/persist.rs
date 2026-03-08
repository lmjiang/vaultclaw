use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::crypto::{cipher, keys::MasterKey};
use crate::vault::format::VaultError;
use super::access_policy::AccessPolicy;
use super::approval::ApprovalManager;
use super::audit::AuditLog;
use super::rate_config::{AccessTracker, RateLimitConfig};
use super::token::TokenStore;
use crate::security::rotation::RotationScheduler;

/// Serializable snapshot of all agent gateway state.
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentState {
    pub token_store: TokenStore,
    pub audit_log: AuditLog,
    pub approval_manager: ApprovalManager,
    #[serde(default)]
    pub access_policy: AccessPolicy,
    #[serde(default)]
    pub rate_limit_config: RateLimitConfig,
    #[serde(default)]
    pub access_tracker: AccessTracker,
    #[serde(default)]
    pub rotation_scheduler: RotationScheduler,
}

impl AgentState {
    /// Derive the agent state file path from the vault path.
    /// e.g., `/path/to/vault.vclaw` → `/path/to/vault.vclaw.agent-state`
    pub fn state_path(vault_path: &Path) -> PathBuf {
        let mut p = vault_path.as_os_str().to_os_string();
        p.push(".agent-state");
        PathBuf::from(p)
    }

    /// Save agent state to an encrypted file alongside the vault.
    pub fn save(&self, vault_path: &Path, master_key: &MasterKey) -> Result<(), VaultError> {
        let state_path = Self::state_path(vault_path);
        let json = serde_json::to_vec(self)
            .map_err(|e| VaultError::Serialization(e.to_string()))?;

        let encrypted = cipher::encrypt(master_key, &json)
            .map_err(|_| VaultError::Serialization("Encryption failed".into()))?;

        let tmp_path = state_path.with_extension("agent-state.tmp");
        let mut file = fs::File::create(&tmp_path)?;
        file.write_all(&encrypted)?;
        file.sync_all()?;
        drop(file);

        fs::rename(&tmp_path, &state_path)?;
        Ok(())
    }

    /// Load agent state from an encrypted file.
    /// Returns default state if file doesn't exist.
    pub fn load(vault_path: &Path, master_key: &MasterKey) -> Result<Self, VaultError> {
        let state_path = Self::state_path(vault_path);

        if !state_path.exists() {
            return Ok(Self {
                token_store: TokenStore::new(),
                audit_log: AuditLog::new(),
                approval_manager: ApprovalManager::new(),
                access_policy: AccessPolicy::default(),
                rate_limit_config: RateLimitConfig::new(),
                access_tracker: AccessTracker::new(),
                rotation_scheduler: RotationScheduler::new(),
            });
        }

        let encrypted = fs::read(&state_path)?;
        let json = cipher::decrypt(master_key, &encrypted)
            .map_err(|_| VaultError::DecryptionFailed)?;
        let state: AgentState = serde_json::from_slice(&json)
            .map_err(|e| VaultError::Serialization(e.to_string()))?;
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::approval::ApprovalPolicy;
    use crate::agent::audit::AuditResult;
    use crate::agent::token::{AccessRequest, AgentAction};
    use crate::crypto::kdf;
    use crate::crypto::keys::password_secret;
    use uuid::Uuid;

    fn test_master_key() -> MasterKey {
        let password = password_secret("test-password".to_string());
        let salt = kdf::generate_salt(16);
        let params = kdf::KdfParams::fast_for_testing();
        kdf::derive_master_key(&password, &salt, &params).unwrap()
    }

    #[test]
    fn test_state_path() {
        let vault_path = Path::new("/home/user/.vaultclaw/vault.vclaw");
        let state_path = AgentState::state_path(vault_path);
        assert_eq!(state_path, PathBuf::from("/home/user/.vaultclaw/vault.vclaw.agent-state"));
    }

    #[test]
    fn test_save_and_load_empty_state() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.vclaw");
        let key = test_master_key();

        let state = AgentState {
            token_store: TokenStore::new(),
            audit_log: AuditLog::new(),
            approval_manager: ApprovalManager::new(),
            access_policy: AccessPolicy::default(),
            rate_limit_config: RateLimitConfig::new(),
            access_tracker: AccessTracker::new(),
            rotation_scheduler: RotationScheduler::new(),
        };

        state.save(&vault_path, &key).unwrap();

        let loaded = AgentState::load(&vault_path, &key).unwrap();
        assert!(loaded.token_store.active_tokens().is_empty());
        assert!(loaded.audit_log.is_empty());
        assert!(loaded.approval_manager.list_policies().is_empty());
    }

    #[test]
    fn test_save_and_load_with_data() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.vclaw");
        let key = test_master_key();

        let mut state = AgentState {
            token_store: TokenStore::new(),
            audit_log: AuditLog::new(),
            approval_manager: ApprovalManager::new(),
            access_policy: AccessPolicy::default(),
            rate_limit_config: RateLimitConfig::new(),
            access_tracker: AccessTracker::new(),
            rotation_scheduler: RotationScheduler::new(),
        };

        // Add a policy
        let cred_id = Uuid::new_v4();
        state.approval_manager.add_policy(ApprovalPolicy {
            agent_id: "test-agent".into(),
            allowed_scopes: vec![cred_id],
            allowed_actions: vec![AgentAction::Read],
            max_auto_approve_ttl: 3600,
            require_manual_for_sensitive: false,
        });

        // Submit and approve a request
        let req = AccessRequest::new(
            "test-agent".into(),
            vec![cred_id],
            vec![AgentAction::Read],
            3600,
            Some(10),
            "deploy".into(),
        );
        let req_id = state.token_store.submit_request(req);
        state.token_store.approve_request(&req_id, "human:cli".into());

        // Record an audit entry
        state.audit_log.record(
            "test-agent".into(),
            Uuid::new_v4(),
            cred_id,
            AgentAction::Read,
            AuditResult::Success,
            Some("human:cli".into()),
        );

        state.save(&vault_path, &key).unwrap();

        let loaded = AgentState::load(&vault_path, &key).unwrap();
        assert_eq!(loaded.token_store.active_tokens().len(), 1);
        assert_eq!(loaded.audit_log.len(), 1);
        assert_eq!(loaded.approval_manager.list_policies().len(), 1);
        assert_eq!(loaded.approval_manager.list_policies()[0].agent_id, "test-agent");
    }

    #[test]
    fn test_load_nonexistent_returns_default() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("nonexistent.vclaw");
        let key = test_master_key();

        let state = AgentState::load(&vault_path, &key).unwrap();
        assert!(state.token_store.active_tokens().is_empty());
        assert!(state.audit_log.is_empty());
    }

    #[test]
    fn test_load_wrong_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.vclaw");
        let key1 = test_master_key();
        let key2 = test_master_key(); // Different key (different random salt)

        let state = AgentState {
            token_store: TokenStore::new(),
            audit_log: AuditLog::new(),
            approval_manager: ApprovalManager::new(),
            access_policy: AccessPolicy::default(),
            rate_limit_config: RateLimitConfig::new(),
            access_tracker: AccessTracker::new(),
            rotation_scheduler: RotationScheduler::new(),
        };
        state.save(&vault_path, &key1).unwrap();

        let result = AgentState::load(&vault_path, &key2);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_corrupted_file_fails() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.vclaw");
        let state_path = AgentState::state_path(&vault_path);
        let key = test_master_key();

        // Write garbage data
        fs::write(&state_path, b"not encrypted data").unwrap();

        let result = AgentState::load(&vault_path, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut state = AgentState {
            token_store: TokenStore::new(),
            audit_log: AuditLog::new(),
            approval_manager: ApprovalManager::new(),
            access_policy: AccessPolicy::default(),
            rate_limit_config: RateLimitConfig::new(),
            access_tracker: AccessTracker::new(),
            rotation_scheduler: RotationScheduler::new(),
        };

        let cred_id = Uuid::new_v4();
        state.approval_manager.add_policy(ApprovalPolicy {
            agent_id: "agent".into(),
            allowed_scopes: vec![cred_id],
            allowed_actions: vec![AgentAction::Read, AgentAction::Use],
            max_auto_approve_ttl: 7200,
            require_manual_for_sensitive: true,
        });

        let json = serde_json::to_string(&state).unwrap();
        let parsed: AgentState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.approval_manager.list_policies().len(), 1);
    }
}
