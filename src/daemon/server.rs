use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::Mutex;

use crate::agent::access_policy::AccessPolicy;
use crate::agent::gateway::{AgentGateway, GatewayRequest, GatewayResponse};
use crate::agent::jwt;
use crate::agent::lease::LeaseStore;
use crate::agent::persist::AgentState;
use crate::agent::rate_config::{AccessTracker, RateLimitConfig};
use crate::security::rotation::RotationScheduler;
use crate::crypto::keys::{password_secret, MasterKey, PasswordSecret, RecoveryKey};
use crate::crypto::recovery;
use crate::vault::entry::Entry;
use crate::vault::format::{VaultError, VaultFile};
use crate::vault::search::fuzzy_search;

use super::protocol::*;

/// The daemon server state.
pub struct DaemonState {
    vault: Option<VaultFile>,
    vault_path: PathBuf,
    auto_lock_seconds: u64,
    last_activity: Instant,
    started_at: Instant,
    agent_gateway: AgentGateway,
    jwt_signing_key: Option<Vec<u8>>,
    pub lease_store: LeaseStore,
    pub access_policy: AccessPolicy,
    pub rate_limit_config: RateLimitConfig,
    pub access_tracker: AccessTracker,
    pub rotation_scheduler: RotationScheduler,
}

impl DaemonState {
    pub fn new(vault_path: PathBuf, auto_lock_seconds: u64) -> Self {
        Self {
            vault: None,
            vault_path,
            auto_lock_seconds,
            last_activity: Instant::now(),
            started_at: Instant::now(),
            agent_gateway: AgentGateway::new(),
            jwt_signing_key: None,
            lease_store: LeaseStore::new(),
            access_policy: AccessPolicy::default(),
            rate_limit_config: RateLimitConfig::new(),
            access_tracker: AccessTracker::new(),
            rotation_scheduler: RotationScheduler::new(),
        }
    }

    /// Unlock the vault with the given password.
    /// Also loads agent state (tokens, policies, audit log) from the sidecar file,
    /// and derives the JWT signing key from the master key.
    pub fn unlock(&mut self, password: &PasswordSecret) -> Result<(), VaultError> {
        let vault = VaultFile::open(&self.vault_path, password)?;

        // Derive JWT signing key from master key
        self.jwt_signing_key = Some(jwt::derive_jwt_signing_key(vault.master_key()));

        // Load persisted agent state
        match AgentState::load(vault.path(), vault.master_key()) {
            Ok(state) => {
                self.agent_gateway.token_store = state.token_store;
                self.agent_gateway.audit_log = state.audit_log;
                self.agent_gateway.approval_manager = state.approval_manager;
                self.access_policy = state.access_policy;
                self.rate_limit_config = state.rate_limit_config;
                self.access_tracker = state.access_tracker;
                self.rotation_scheduler = state.rotation_scheduler;
            }
            Err(_) => {
                // If agent state can't be loaded, start fresh (logged but not fatal)
            }
        }

        self.vault = Some(vault);
        self.last_activity = Instant::now();
        Ok(())
    }

    /// Unlock the vault directly with a master key (used by YubiKey flow).
    pub fn unlock_with_master_key(&mut self, master_key: MasterKey) -> Result<(), VaultError> {
        let vault = VaultFile::open_with_master_key(&self.vault_path, master_key)?;
        self.load_agent_state_from_vault(&vault);
        self.vault = Some(vault);
        self.last_activity = Instant::now();
        Ok(())
    }

    /// Unlock the vault with a recovery key.
    pub fn unlock_with_recovery_key(&mut self, recovery_key: &RecoveryKey) -> Result<(), VaultError> {
        let vault = VaultFile::open_with_recovery_key(&self.vault_path, recovery_key)?;
        self.load_agent_state_from_vault(&vault);
        self.vault = Some(vault);
        self.last_activity = Instant::now();
        Ok(())
    }

    /// Load agent state from a vault file (shared by all unlock methods).
    fn load_agent_state_from_vault(&mut self, vault: &VaultFile) {
        self.jwt_signing_key = Some(jwt::derive_jwt_signing_key(vault.master_key()));
        if let Ok(state) = AgentState::load(vault.path(), vault.master_key()) {
            self.agent_gateway.token_store = state.token_store;
            self.agent_gateway.audit_log = state.audit_log;
            self.agent_gateway.approval_manager = state.approval_manager;
            self.access_policy = state.access_policy;
            self.rate_limit_config = state.rate_limit_config;
            self.access_tracker = state.access_tracker;
            self.rotation_scheduler = state.rotation_scheduler;
        }
    }

    /// Lock the vault, clearing sensitive data from memory.
    /// Saves agent state before locking so it persists across lock/unlock cycles.
    pub fn lock(&mut self) {
        self.save_agent_state();
        self.vault = None;
        self.jwt_signing_key = None;
    }

    /// Save agent state to the encrypted sidecar file.
    fn save_agent_state(&self) {
        if let Some(vault) = &self.vault {
            let state = AgentState {
                token_store: self.agent_gateway.token_store.clone(),
                audit_log: self.agent_gateway.audit_log.clone(),
                approval_manager: self.agent_gateway.approval_manager.clone(),
                access_policy: self.access_policy.clone(),
                rate_limit_config: self.rate_limit_config.clone(),
                access_tracker: self.access_tracker.clone(),
                rotation_scheduler: self.rotation_scheduler.clone(),
            };
            let _ = state.save(vault.path(), vault.master_key());
        }
    }

    /// Save access policy by persisting agent state.
    pub fn save_policy(&self) {
        self.save_agent_state();
    }

    /// Record an audit log entry.
    pub fn record_audit(
        &mut self,
        agent_id: String,
        token_id: uuid::Uuid,
        credential_id: uuid::Uuid,
        action: crate::agent::token::AgentAction,
        result: crate::agent::audit::AuditResult,
        approved_by: Option<String>,
    ) {
        self.agent_gateway.audit_log.record(agent_id, token_id, credential_id, action, result, approved_by);
    }

    /// Attempt to auto-unlock the vault using Touch ID (macOS only).
    /// Returns true if auto-unlock succeeded, false otherwise.
    /// Silently returns false on non-macOS platforms or if Touch ID is not enrolled.
    #[cfg(target_os = "macos")]
    pub fn try_touchid_auto_unlock(&mut self) -> bool {
        match crate::vault::format::VaultFile::open_with_touchid(&self.vault_path) {
            Ok(vault) => {
                self.load_agent_state_from_vault(&vault);
                self.vault = Some(vault);
                self.last_activity = Instant::now();
                true
            }
            Err(_) => false,
        }
    }

    #[cfg(not(target_os = "macos"))]
    pub fn try_touchid_auto_unlock(&mut self) -> bool {
        false
    }

    /// Check if the vault is locked.
    pub fn is_locked(&self) -> bool {
        self.vault.is_none()
    }

    /// Check and enforce auto-lock timeout.
    pub fn check_auto_lock(&mut self) {
        if self.auto_lock_seconds > 0
            && !self.is_locked()
            && self.last_activity.elapsed().as_secs() >= self.auto_lock_seconds
        {
            self.lock();
        }
    }

    /// Get a reference to the JWT signing key (available when vault is unlocked).
    pub fn jwt_signing_key(&self) -> Option<&[u8]> {
        self.jwt_signing_key.as_deref()
    }

    /// Get a reference to the open vault (None if locked).
    pub fn vault_ref(&self) -> Option<&VaultFile> {
        self.vault.as_ref()
    }

    /// Get a mutable reference to the open vault (None if locked).
    pub fn vault_ref_mut(&mut self) -> Option<&mut VaultFile> {
        self.vault.as_mut()
    }

    /// Handle a gateway request directly (used by HTTP handlers).
    pub fn handle_gateway(&mut self, request: GatewayRequest) -> GatewayResponse {
        let is_mutation = matches!(
            request,
            GatewayRequest::RequestAccess { .. }
            | GatewayRequest::Grant { .. }
            | GatewayRequest::Deny { .. }
            | GatewayRequest::Revoke { .. }
            | GatewayRequest::GetCredential { .. }
        );
        let vault_ref = self.vault.as_ref();
        let resp = self.agent_gateway.handle_with_lookup(request, |id| {
            vault_ref.and_then(|v| v.store().get(id).cloned())
        });
        if is_mutation {
            self.save_agent_state();
        }
        resp
    }

    /// Handle a request and produce a response.
    pub fn handle_request(&mut self, request: Request) -> Response {
        self.check_auto_lock();

        match request {
            Request::Health => Response::ok(ResponseData::Health(HealthResponse {
                healthy: true,
                uptime_seconds: self.started_at.elapsed().as_secs(),
            })),
            Request::Status => {
                let (locked, count) = match &self.vault {
                    Some(v) => (false, v.store().len()),
                    None => (true, 0),
                };
                Response::ok(ResponseData::Status(VaultStatus {
                    locked,
                    entry_count: count,
                    vault_path: self.vault_path.display().to_string(),
                }))
            }
            Request::Lock => {
                self.lock();
                Response::ok(ResponseData::None)
            }
            Request::Unlock { password } => {
                let secret = password_secret(password);
                match self.unlock(&secret) {
                    Ok(()) => Response::ok(ResponseData::Unlocked { success: true }),
                    Err(e) => Response::error(format!("Unlock failed: {}", e)),
                }
            }
            Request::UnlockRecovery { recovery_key } => {
                match recovery::parse_recovery_key(&recovery_key) {
                    Ok(key) => match self.unlock_with_recovery_key(&key) {
                        Ok(()) => Response::ok(ResponseData::Unlocked { success: true }),
                        Err(e) => Response::error(format!("Recovery unlock failed: {}", e)),
                    },
                    Err(e) => Response::error(format!("Invalid recovery key: {}", e)),
                }
            }
            Request::UnlockMasterKey { master_key_hex } => {
                match hex::decode(&master_key_hex) {
                    Ok(bytes) if bytes.len() == 32 => {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        let key = MasterKey::from_bytes(arr);
                        match self.unlock_with_master_key(key) {
                            Ok(()) => Response::ok(ResponseData::Unlocked { success: true }),
                            Err(e) => Response::error(format!("Master key unlock failed: {}", e)),
                        }
                    }
                    Ok(bytes) => Response::error(format!("Master key must be 32 bytes, got {}", bytes.len())),
                    Err(e) => Response::error(format!("Invalid hex: {}", e)),
                }
            }
            Request::UnlockTouchId => {
                #[cfg(target_os = "macos")]
                {
                    match crate::vault::format::VaultFile::open_with_touchid(&self.vault_path) {
                        Ok(vault) => {
                            self.load_agent_state_from_vault(&vault);
                            self.vault = Some(vault);
                            self.last_activity = Instant::now();
                            Response::ok(ResponseData::Unlocked { success: true })
                        }
                        Err(e) => Response::error(format!("Touch ID unlock failed: {}", e)),
                    }
                }
                #[cfg(not(target_os = "macos"))]
                {
                    Response::error("Touch ID is only available on macOS".to_string())
                }
            }
            Request::Shutdown => {
                // Handled at the run_server level, not here
                Response::ok(ResponseData::None)
            }
            Request::Agent { request } => {
                match self.handle_gateway(request) {
                    GatewayResponse::Ok { data } => {
                        Response::ok(ResponseData::Agent(data))
                    }
                    GatewayResponse::Error { message } => {
                        Response::error(message)
                    }
                }
            }
            Request::LeaseList => {
                let active = self.lease_store.active_leases();
                let infos: Vec<LeaseInfo> = active.iter().map(|l| LeaseInfo {
                    lease_id: l.id,
                    entry_id: l.entry_id,
                    agent_id: l.agent_id.clone(),
                    scope: serde_json::to_string(&l.scope).unwrap_or_default(),
                    reason: l.reason.clone(),
                    created_at: l.created_at.to_rfc3339(),
                    expires_at: l.expires_at.to_rfc3339(),
                }).collect();
                Response::ok(ResponseData::LeaseList(LeaseListData { leases: infos }))
            }
            Request::LeaseRevoke { lease_id } => {
                if self.lease_store.revoke(&lease_id) {
                    Response::ok(ResponseData::LeaseRevoked { count: 1 })
                } else {
                    Response::error("Lease not found or already revoked")
                }
            }
            Request::LeaseRevokeAll => {
                let count = self.lease_store.revoke_all_leases();
                Response::ok(ResponseData::LeaseRevoked { count })
            }
            Request::SetSensitivity { entry_id, level } => {
                self.lease_store.set_sensitivity(entry_id, level);
                Response::ok(ResponseData::None)
            }
            _ => {
                // All other requests require an unlocked vault
                if self.vault.is_none() {
                    return Response::error("Vault is locked");
                }
                self.last_activity = Instant::now();
                let vault = self.vault.as_mut().unwrap();

                match request {
                    Request::Get { id } => match vault.store().get(&id) {
                        Some(entry) => Response::ok(ResponseData::Entry(entry.clone())),
                        None => Response::error("Entry not found"),
                    },
                    Request::FuzzyGet { query } => {
                        let entries = vault.store().list();
                        let results = fuzzy_search(&entries, &query);
                        if results.is_empty() {
                            Response::error(format!("No matching entries found for '{}'", query))
                        } else {
                            Response::ok(ResponseData::Entry(results[0].0.clone()))
                        }
                    }
                    Request::Search { query } => {
                        let entries: Vec<Entry> = vault
                            .store()
                            .search(&query)
                            .into_iter()
                            .cloned()
                            .collect();
                        Response::ok(ResponseData::Entries(entries))
                    }
                    Request::List {
                        tag,
                        category,
                        favorites_only,
                    } => {
                        let entries: Vec<Entry> = if favorites_only {
                            vault.store().list_favorites()
                        } else if let Some(t) = &tag {
                            vault.store().list_by_tag(t)
                        } else if let Some(c) = &category {
                            vault.store().list_by_category(c)
                        } else {
                            vault.store().list()
                        }
                        .into_iter()
                        .cloned()
                        .collect();
                        Response::ok(ResponseData::Entries(entries))
                    }
                    Request::Add { entry } => {
                        let id = vault.store_mut().add(entry);
                        if let Err(e) = vault.save() {
                            return Response::error(format!("Failed to save: {}", e));
                        }
                        Response::ok(ResponseData::Id(id))
                    }
                    Request::Update { entry } => {
                        if !vault.store_mut().update(entry) {
                            return Response::error("Entry not found");
                        }
                        if let Err(e) = vault.save() {
                            return Response::error(format!("Failed to save: {}", e));
                        }
                        Response::ok(ResponseData::None)
                    }
                    Request::Delete { id } => {
                        if vault.store_mut().remove(&id).is_none() {
                            return Response::error("Entry not found");
                        }
                        if let Err(e) = vault.save() {
                            return Response::error(format!("Failed to save: {}", e));
                        }
                        Response::ok(ResponseData::None)
                    }
                    Request::Totp { id } => {
                        let entry = match vault.store().get(&id) {
                            Some(e) => e,
                            None => return Response::error("Entry not found"),
                        };
                        let secret = match &entry.totp_secret {
                            Some(s) => s,
                            None => return Response::error("No TOTP secret for this entry"),
                        };
                        match crate::totp::generate_totp(secret) {
                            Ok(code) => Response::ok(ResponseData::Totp(TotpResponse {
                                code: code.code,
                                seconds_remaining: code.seconds_remaining,
                            })),
                            Err(e) => Response::error(format!("TOTP error: {}", e)),
                        }
                    }
                    // Already handled above
                    Request::Health | Request::Status | Request::Lock | Request::Unlock { .. }
                    | Request::UnlockRecovery { .. } | Request::UnlockMasterKey { .. }
                    | Request::UnlockTouchId
                    | Request::Shutdown | Request::Agent { .. }
                    | Request::LeaseList | Request::LeaseRevoke { .. }
                    | Request::LeaseRevokeAll | Request::SetSensitivity { .. } => unreachable!(),
                }
            }
        }
    }
}

/// Run the daemon server listening on a Unix socket.
pub async fn run_server(
    socket_path: &Path,
    state: Arc<Mutex<DaemonState>>,
) -> std::io::Result<()> {
    // Remove stale socket file
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }

    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(socket_path)?;
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let socket_path_owned = socket_path.to_path_buf();

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, _) = result?;
                let state = state.clone();
                let shutdown_tx = shutdown_tx.clone();

                tokio::spawn(async move {
                    let (reader, mut writer) = stream.into_split();
                    let mut reader = BufReader::new(reader);
                    let mut line = String::new();

                    while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                        let is_shutdown = matches!(
                            serde_json::from_str::<Request>(line.trim()),
                            Ok(Request::Shutdown)
                        );

                        let response = match serde_json::from_str::<Request>(line.trim()) {
                            Ok(req) => {
                                let mut state = state.lock().await;
                                state.handle_request(req)
                            }
                            Err(e) => Response::error(format!("Invalid request: {}", e)),
                        };

                        let resp_json = serde_json::to_string(&response).unwrap_or_default();
                        let _ = writer.write_all(resp_json.as_bytes()).await;
                        let _ = writer.write_all(b"\n").await;
                        let _ = writer.flush().await;

                        if is_shutdown {
                            let _ = shutdown_tx.send(true);
                            return;
                        }

                        line.clear();
                    }
                });
            }
            _ = shutdown_rx.changed() => {
                // Graceful shutdown: remove socket file and exit
                let _ = std::fs::remove_file(&socket_path_owned);
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::gateway::GatewayData;
    use crate::crypto::kdf::KdfParams;
    use crate::crypto::keys::password_secret;
    use crate::vault::entry::*;
    use crate::vault::format::VaultFile;
    use tempfile::TempDir;

    // -- Helper extraction functions --
    // Each consolidates the panic branch into one location, reducing
    // uncovered-line noise in coverage reports.

    fn unwrap_data(resp: Response) -> ResponseData {
        match resp {
            Response::Ok { data } => *data,
            other => panic!("Expected Ok response, got: {:?}", other),
        }
    }

    fn expect_status(resp: Response) -> VaultStatus {
        match unwrap_data(resp) { ResponseData::Status(s) => s, other => panic!("Expected Status, got: {:?}", other) }
    }

    fn expect_entries(resp: Response) -> Vec<Entry> {
        match unwrap_data(resp) { ResponseData::Entries(e) => e, other => panic!("Expected Entries, got: {:?}", other) }
    }

    fn expect_id(resp: Response) -> EntryId {
        match unwrap_data(resp) { ResponseData::Id(id) => id, other => panic!("Expected Id, got: {:?}", other) }
    }

    fn expect_entry(resp: Response) -> Entry {
        match unwrap_data(resp) { ResponseData::Entry(e) => e, other => panic!("Expected Entry, got: {:?}", other) }
    }

    fn expect_totp(resp: Response) -> TotpResponse {
        match unwrap_data(resp) { ResponseData::Totp(t) => t, other => panic!("Expected Totp, got: {:?}", other) }
    }

    fn expect_health(resp: Response) -> HealthResponse {
        match unwrap_data(resp) { ResponseData::Health(h) => h, other => panic!("Expected Health, got: {:?}", other) }
    }

    fn expect_error(resp: Response) -> String {
        match resp {
            Response::Error { message } => message,
            other => panic!("Expected Error response, got: {:?}", other),
        }
    }

    fn setup_state() -> (DaemonState, TempDir) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test-password".to_string());
        let params = KdfParams::fast_for_testing();

        let mut vault = VaultFile::create(&path, &password, params).unwrap();
        vault.store_mut().add(Entry::new(
            "GitHub".to_string(),
            Credential::Login(LoginCredential {
                url: "https://github.com".to_string(),
                username: "user".to_string(),
                password: "pass".to_string(),
            }),
        ).with_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));
        vault.save().unwrap();

        let mut state = DaemonState::new(path, 300);
        state.unlock(&password).unwrap();

        (state, dir)
    }

    #[test]
    fn test_status_unlocked() {
        let (mut state, _dir) = setup_state();
        let resp = state.handle_request(Request::Status);
        let s = expect_status(resp);
        assert!(!s.locked);
        assert_eq!(s.entry_count, 1);
    }

    #[test]
    fn test_status_locked() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test".to_string());
        VaultFile::create(&path, &password, KdfParams::fast_for_testing()).unwrap();

        let mut state = DaemonState::new(path, 300);
        let resp = state.handle_request(Request::Status);
        let s = expect_status(resp);
        assert!(s.locked);
    }

    #[test]
    fn test_lock() {
        let (mut state, _dir) = setup_state();
        assert!(!state.is_locked());

        state.handle_request(Request::Lock);
        assert!(state.is_locked());
    }

    #[test]
    fn test_search() {
        let (mut state, _dir) = setup_state();
        let resp = state.handle_request(Request::Search {
            query: "github".to_string(),
        });
        let entries = expect_entries(resp);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "GitHub");
    }

    #[test]
    fn test_search_when_locked() {
        let (mut state, _dir) = setup_state();
        state.lock();
        let resp = state.handle_request(Request::Search {
            query: "github".to_string(),
        });
        let message = expect_error(resp);
        assert!(message.contains("locked"));
    }

    #[test]
    fn test_add_entry() {
        let (mut state, _dir) = setup_state();
        let entry = Entry::new(
            "New Entry".to_string(),
            Credential::Login(LoginCredential {
                url: "https://new.com".to_string(),
                username: "u".to_string(),
                password: "p".to_string(),
            }),
        );

        let resp = state.handle_request(Request::Add { entry });
        let _ = expect_id(resp);

        // Verify count increased
        let s = expect_status(state.handle_request(Request::Status));
        assert_eq!(s.entry_count, 2);
    }

    #[test]
    fn test_delete_entry() {
        let (mut state, _dir) = setup_state();

        // Get the entry ID first
        let entries = expect_entries(state.handle_request(Request::List {
            tag: None,
            category: None,
            favorites_only: false,
        }));

        let id = entries[0].id;
        let resp = state.handle_request(Request::Delete { id });
        assert!(matches!(resp, Response::Ok { .. }));

        let s = expect_status(state.handle_request(Request::Status));
        assert_eq!(s.entry_count, 0);
    }

    #[test]
    fn test_get_entry() {
        let (mut state, _dir) = setup_state();

        let entries = expect_entries(state.handle_request(Request::List {
            tag: None,
            category: None,
            favorites_only: false,
        }));

        let id = entries[0].id;
        let resp = state.handle_request(Request::Get { id });
        let e = expect_entry(resp);
        assert_eq!(e.title, "GitHub");
    }

    #[test]
    fn test_get_nonexistent() {
        let (mut state, _dir) = setup_state();
        let resp = state.handle_request(Request::Get {
            id: uuid::Uuid::new_v4(),
        });
        let _ = expect_error(resp);
    }

    #[test]
    fn test_totp() {
        let (mut state, _dir) = setup_state();

        let entries = expect_entries(state.handle_request(Request::List {
            tag: None,
            category: None,
            favorites_only: false,
        }));

        let id = entries[0].id;
        let resp = state.handle_request(Request::Totp { id });
        let t = expect_totp(resp);
        assert_eq!(t.code.len(), 6);
        assert!(t.seconds_remaining > 0);
    }

    #[test]
    fn test_health() {
        let (mut state, _dir) = setup_state();
        let resp = state.handle_request(Request::Health);
        let h = expect_health(resp);
        assert!(h.healthy);
    }

    #[test]
    fn test_auto_lock() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test".to_string());
        VaultFile::create(&path, &password, KdfParams::fast_for_testing()).unwrap();

        // Set auto-lock to 0 seconds (immediate)
        let mut state = DaemonState::new(path, 0);
        state.unlock(&password).unwrap();
        // With 0 seconds timeout, auto-lock is disabled
        assert!(!state.is_locked());
    }

    #[test]
    fn test_update_entry() {
        let (mut state, _dir) = setup_state();

        let entries = expect_entries(state.handle_request(Request::List {
            tag: None,
            category: None,
            favorites_only: false,
        }));

        let mut entry = entries[0].clone();
        entry.title = "GitHub Updated".to_string();

        let resp = state.handle_request(Request::Update { entry });
        assert!(matches!(resp, Response::Ok { .. }));

        let entries = expect_entries(state.handle_request(Request::List {
            tag: None,
            category: None,
            favorites_only: false,
        }));
        assert_eq!(entries[0].title, "GitHub Updated");
    }

    #[test]
    fn test_list_favorites() {
        let (mut state, _dir) = setup_state();

        let entries = expect_entries(state.handle_request(Request::List {
            tag: None,
            category: None,
            favorites_only: true,
        }));
        assert_eq!(entries.len(), 0); // No favorites in test setup
    }

    #[test]
    fn test_list_by_tag() {
        let (mut state, _dir) = setup_state();

        // Add an entry with a tag
        let entry = Entry::new(
            "Tagged".to_string(),
            Credential::Login(LoginCredential {
                url: "https://tagged.com".to_string(),
                username: "u".to_string(),
                password: "p".to_string(),
            }),
        ).with_tags(vec!["work".to_string()]);
        state.handle_request(Request::Add { entry });

        let entries = expect_entries(state.handle_request(Request::List {
            tag: Some("work".to_string()),
            category: None,
            favorites_only: false,
        }));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "Tagged");
    }

    #[test]
    fn test_list_by_category() {
        let (mut state, _dir) = setup_state();

        // Add an entry with a category
        let entry = Entry::new(
            "CatEntry".to_string(),
            Credential::Login(LoginCredential {
                url: "https://cat.com".to_string(),
                username: "u".to_string(),
                password: "p".to_string(),
            }),
        ).with_category("development");
        state.handle_request(Request::Add { entry });

        let entries = expect_entries(state.handle_request(Request::List {
            tag: None,
            category: Some("development".to_string()),
            favorites_only: false,
        }));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "CatEntry");
    }

    #[test]
    fn test_update_nonexistent_entry() {
        let (mut state, _dir) = setup_state();

        let entry = Entry::new(
            "Ghost".to_string(),
            Credential::Login(LoginCredential {
                url: "https://ghost.com".to_string(),
                username: "u".to_string(),
                password: "p".to_string(),
            }),
        );

        let resp = state.handle_request(Request::Update { entry });
        let msg = expect_error(resp);
        assert!(msg.contains("not found"));
    }

    #[test]
    fn test_delete_nonexistent_entry() {
        let (mut state, _dir) = setup_state();
        let resp = state.handle_request(Request::Delete {
            id: uuid::Uuid::new_v4(),
        });
        let msg = expect_error(resp);
        assert!(msg.contains("not found"));
    }

    #[test]
    fn test_totp_entry_not_found() {
        let (mut state, _dir) = setup_state();
        let resp = state.handle_request(Request::Totp {
            id: uuid::Uuid::new_v4(),
        });
        let msg = expect_error(resp);
        assert!(msg.contains("not found"));
    }

    #[test]
    fn test_totp_no_secret() {
        let (mut state, _dir) = setup_state();

        // Add entry without TOTP
        let entry = Entry::new(
            "NoTOTP".to_string(),
            Credential::Login(LoginCredential {
                url: "https://nototp.com".to_string(),
                username: "u".to_string(),
                password: "p".to_string(),
            }),
        );
        let id = expect_id(state.handle_request(Request::Add { entry }));

        let resp = state.handle_request(Request::Totp { id });
        let msg = expect_error(resp);
        assert!(msg.contains("No TOTP"));
    }

    #[test]
    fn test_auto_lock_triggers() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test".to_string());
        VaultFile::create(&path, &password, KdfParams::fast_for_testing()).unwrap();

        // Set auto-lock to 1 second
        let mut state = DaemonState::new(path, 1);
        state.unlock(&password).unwrap();
        assert!(!state.is_locked());

        // Manually set last_activity far in the past
        state.last_activity = Instant::now() - std::time::Duration::from_secs(10);

        // check_auto_lock should trigger
        state.check_auto_lock();
        assert!(state.is_locked());
    }

    #[test]
    fn test_operations_when_locked_return_error() {
        let (mut state, _dir) = setup_state();
        state.lock();

        // Get
        let resp = state.handle_request(Request::Get { id: uuid::Uuid::new_v4() });
        assert!(matches!(resp, Response::Error { .. }));

        // Add
        let entry = Entry::new("X".to_string(), Credential::SecureNote(
            crate::vault::entry::SecureNoteCredential { content: "n".to_string() }
        ));
        let resp = state.handle_request(Request::Add { entry });
        assert!(matches!(resp, Response::Error { .. }));

        // Delete
        let resp = state.handle_request(Request::Delete { id: uuid::Uuid::new_v4() });
        assert!(matches!(resp, Response::Error { .. }));

        // Update
        let entry = Entry::new("X".to_string(), Credential::SecureNote(
            crate::vault::entry::SecureNoteCredential { content: "n".to_string() }
        ));
        let resp = state.handle_request(Request::Update { entry });
        assert!(matches!(resp, Response::Error { .. }));

        // TOTP
        let resp = state.handle_request(Request::Totp { id: uuid::Uuid::new_v4() });
        assert!(matches!(resp, Response::Error { .. }));

        // List
        let resp = state.handle_request(Request::List { tag: None, category: None, favorites_only: false });
        assert!(matches!(resp, Response::Error { .. }));
    }

    #[test]
    fn test_unlock_wrong_password() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("correct".to_string());
        // Must add an entry so the vault has encrypted data to verify against.
        // An empty vault has no ciphertext, so wrong password goes undetected.
        let mut vault = VaultFile::create(&path, &password, KdfParams::fast_for_testing()).unwrap();
        vault.store_mut().add(Entry::new(
            "Test".to_string(),
            Credential::Login(LoginCredential {
                url: "https://test.com".to_string(),
                username: "u".to_string(),
                password: "p".to_string(),
            }),
        ));
        vault.save().unwrap();

        let mut state = DaemonState::new(path, 300);
        let wrong = password_secret("wrong".to_string());
        let result = state.unlock(&wrong);
        assert!(result.is_err());
        assert!(state.is_locked());
    }

    #[test]
    fn test_unlock_nonexistent_vault() {
        let mut state = DaemonState::new(PathBuf::from("/tmp/nonexistent_daemon_test.vclaw"), 300);
        let password = password_secret("test".to_string());
        let result = state.unlock(&password);
        assert!(result.is_err());
    }

    #[test]
    fn test_auto_lock_disabled() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test".to_string());
        VaultFile::create(&path, &password, KdfParams::fast_for_testing()).unwrap();

        // auto_lock_seconds = 0 means disabled
        let mut state = DaemonState::new(path, 0);
        state.unlock(&password).unwrap();
        state.last_activity = Instant::now() - std::time::Duration::from_secs(9999);
        state.check_auto_lock();
        assert!(!state.is_locked()); // Should NOT lock
    }

    #[test]
    fn test_auto_lock_not_triggered_when_locked() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test".to_string());
        VaultFile::create(&path, &password, KdfParams::fast_for_testing()).unwrap();

        let mut state = DaemonState::new(path, 1);
        // Don't unlock — already locked
        state.check_auto_lock();
        assert!(state.is_locked());
    }

    #[test]
    fn test_lock_idempotent() {
        let (mut state, _dir) = setup_state();
        state.lock();
        assert!(state.is_locked());
        state.lock(); // lock again
        assert!(state.is_locked());
    }

    #[test]
    fn test_activity_updates_on_request() {
        let (mut state, _dir) = setup_state();
        let before = state.last_activity;
        std::thread::sleep(std::time::Duration::from_millis(10));
        state.handle_request(Request::Search { query: "x".to_string() });
        assert!(state.last_activity > before);
    }

    /// Helper: set up a daemon state and then corrupt the database so
    /// that vault.save() will fail.
    fn setup_state_with_broken_save() -> (DaemonState, TempDir) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test-password".to_string());
        let params = KdfParams::fast_for_testing();

        let mut vault = VaultFile::create(&path, &password, params).unwrap();
        vault.store_mut().add(
            Entry::new(
                "GitHub".to_string(),
                Credential::Login(LoginCredential {
                    url: "https://github.com".to_string(),
                    username: "user".to_string(),
                    password: "pass".to_string(),
                }),
            )
            .with_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
        );
        vault.save().unwrap();

        let mut state = DaemonState::new(path.clone(), 300);
        state.unlock(&password).unwrap();

        // Corrupt the SQLite database by dropping the entries table
        // through a separate connection, so vault.save() will fail.
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("DROP TABLE entries").unwrap();

        (state, dir)
    }

    #[test]
    fn test_add_save_failure() {
        let (mut state, _dir) = setup_state_with_broken_save();

        let entry = Entry::new(
            "New Entry".to_string(),
            Credential::Login(LoginCredential {
                url: "https://new.com".to_string(),
                username: "u".to_string(),
                password: "p".to_string(),
            }),
        );

        let resp = state.handle_request(Request::Add { entry });
        let msg = expect_error(resp);
        assert!(msg.contains("Failed to save"));
    }

    #[test]
    fn test_update_save_failure() {
        let (mut state, _dir) = setup_state_with_broken_save();

        // Get the existing entry's ID so we can update it
        let entries = expect_entries(state.handle_request(Request::List {
            tag: None,
            category: None,
            favorites_only: false,
        }));

        let mut entry = entries[0].clone();
        entry.title = "Updated Title".to_string();

        let resp = state.handle_request(Request::Update { entry });
        let msg = expect_error(resp);
        assert!(msg.contains("Failed to save"));
    }

    #[test]
    fn test_delete_save_failure() {
        let (mut state, _dir) = setup_state_with_broken_save();

        // Get the existing entry's ID so we can delete it
        let entries = expect_entries(state.handle_request(Request::List {
            tag: None,
            category: None,
            favorites_only: false,
        }));

        let id = entries[0].id;
        let resp = state.handle_request(Request::Delete { id });
        let msg = expect_error(resp);
        assert!(msg.contains("Failed to save"));
    }

    #[test]
    fn test_totp_invalid_secret_error() {
        let (mut state, _dir) = setup_state();

        // Add an entry with an invalid TOTP secret
        let entry = Entry::new(
            "BadTOTP".to_string(),
            Credential::Login(LoginCredential {
                url: "https://bad.com".to_string(),
                username: "u".to_string(),
                password: "p".to_string(),
            }),
        )
        .with_totp("!!not-valid-base32!!");

        let id = expect_id(state.handle_request(Request::Add { entry }));

        let resp = state.handle_request(Request::Totp { id });
        let msg = expect_error(resp);
        assert!(msg.contains("TOTP error"));
    }

    #[tokio::test]
    async fn test_run_server_accepts_connection() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::UnixStream;

        let dir = TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");
        let socket_path = dir.path().join("test.sock");
        let password = password_secret("test".to_string());
        VaultFile::create(&vault_path, &password, KdfParams::fast_for_testing()).unwrap();

        let mut state = DaemonState::new(vault_path, 300);
        state.unlock(&password).unwrap();
        let state = Arc::new(Mutex::new(state));

        let socket_path_clone = socket_path.clone();
        let state_clone = state.clone();
        let server_handle = tokio::spawn(async move {
            let _ = run_server(&socket_path_clone, state_clone).await;
        });

        // Give server time to start
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Connect as client
        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);

        // Send health request
        let req = serde_json::to_string(&Request::Health).unwrap();
        writer.write_all(req.as_bytes()).await.unwrap();
        writer.write_all(b"\n").await.unwrap();
        writer.flush().await.unwrap();

        // Read response
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let resp: Response = serde_json::from_str(line.trim()).unwrap();
        let h = expect_health(resp);
        assert!(h.healthy);

        // Send status request
        let mut line = String::new();
        let req = serde_json::to_string(&Request::Status).unwrap();
        writer.write_all(req.as_bytes()).await.unwrap();
        writer.write_all(b"\n").await.unwrap();
        writer.flush().await.unwrap();
        reader.read_line(&mut line).await.unwrap();
        let resp: Response = serde_json::from_str(line.trim()).unwrap();
        let s = expect_status(resp);
        assert!(!s.locked);

        // Send invalid JSON
        let mut line = String::new();
        writer.write_all(b"not valid json\n").await.unwrap();
        writer.flush().await.unwrap();
        reader.read_line(&mut line).await.unwrap();
        let resp: Response = serde_json::from_str(line.trim()).unwrap();
        assert!(matches!(resp, Response::Error { .. }));

        server_handle.abort();
    }

    #[tokio::test]
    async fn test_run_server_graceful_shutdown() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::UnixStream;

        let dir = TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");
        let socket_path = dir.path().join("shutdown_test.sock");
        let password = password_secret("test".to_string());
        VaultFile::create(&vault_path, &password, KdfParams::fast_for_testing()).unwrap();

        let mut state = DaemonState::new(vault_path, 300);
        state.unlock(&password).unwrap();
        let state = Arc::new(Mutex::new(state));

        let socket_path_clone = socket_path.clone();
        let state_clone = state.clone();
        let server_handle = tokio::spawn(async move {
            let _ = run_server(&socket_path_clone, state_clone).await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Connect and send shutdown
        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);

        let req = serde_json::to_string(&Request::Shutdown).unwrap();
        writer.write_all(req.as_bytes()).await.unwrap();
        writer.write_all(b"\n").await.unwrap();
        writer.flush().await.unwrap();

        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let resp: Response = serde_json::from_str(line.trim()).unwrap();
        assert!(matches!(resp, Response::Ok { .. }));

        // Server should exit cleanly
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            server_handle,
        ).await;
        assert!(result.is_ok());
    }

    fn expect_unlocked(resp: Response) -> bool {
        match unwrap_data(resp) { ResponseData::Unlocked { success } => success, other => panic!("Expected Unlocked, got: {:?}", other) }
    }

    #[test]
    fn test_unlock_via_request() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test-password".to_string());
        let params = KdfParams::fast_for_testing();
        let mut vault = VaultFile::create(&path, &password, params).unwrap();
        vault.store_mut().add(Entry::new(
            "Test".to_string(),
            Credential::Login(LoginCredential {
                url: "https://test.com".to_string(),
                username: "u".to_string(),
                password: "p".to_string(),
            }),
        ));
        vault.save().unwrap();

        let mut state = DaemonState::new(path, 300);
        assert!(state.is_locked());

        let resp = state.handle_request(Request::Unlock { password: "test-password".to_string() });
        assert!(expect_unlocked(resp));
        assert!(!state.is_locked());
    }

    #[test]
    fn test_unlock_wrong_password_via_request() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("correct".to_string());
        let params = KdfParams::fast_for_testing();
        let mut vault = VaultFile::create(&path, &password, params).unwrap();
        vault.store_mut().add(Entry::new(
            "Test".to_string(),
            Credential::Login(LoginCredential {
                url: "https://test.com".to_string(),
                username: "u".to_string(),
                password: "p".to_string(),
            }),
        ));
        vault.save().unwrap();

        let mut state = DaemonState::new(path, 300);
        let resp = state.handle_request(Request::Unlock { password: "wrong".to_string() });
        let msg = expect_error(resp);
        assert!(msg.contains("Unlock failed"));
        assert!(state.is_locked());
    }

    #[test]
    fn test_unlock_when_already_unlocked() {
        let (mut state, _dir) = setup_state();
        assert!(!state.is_locked());

        let resp = state.handle_request(Request::Unlock { password: "test-password".to_string() });
        assert!(expect_unlocked(resp));
        assert!(!state.is_locked());
    }

    #[test]
    fn test_fuzzy_get_found() {
        let (mut state, _dir) = setup_state();
        let resp = state.handle_request(Request::FuzzyGet { query: "git".to_string() });
        let entry = expect_entry(resp);
        assert_eq!(entry.title, "GitHub");
    }

    #[test]
    fn test_fuzzy_get_not_found() {
        let (mut state, _dir) = setup_state();
        let resp = state.handle_request(Request::FuzzyGet { query: "zzzzzzzzz".to_string() });
        let msg = expect_error(resp);
        assert!(msg.contains("No matching entries"));
    }

    #[test]
    fn test_fuzzy_get_when_locked() {
        let (mut state, _dir) = setup_state();
        state.lock();
        let resp = state.handle_request(Request::FuzzyGet { query: "git".to_string() });
        let msg = expect_error(resp);
        assert!(msg.contains("locked"));
    }

    #[test]
    fn test_shutdown_request_returns_ok() {
        let (mut state, _dir) = setup_state();
        let resp = state.handle_request(Request::Shutdown);
        assert!(matches!(resp, Response::Ok { .. }));
    }

    #[test]
    #[should_panic(expected = "Expected Unlocked,")]
    fn test_expect_unlocked_wrong_data() {
        expect_unlocked(Response::ok(ResponseData::None));
    }

    #[test]
    #[should_panic(expected = "Expected Ok response")]
    fn test_expect_unlocked_wrong_type() {
        expect_unlocked(Response::error("wrong"));
    }

    fn expect_agent(resp: Response) -> GatewayData {
        match unwrap_data(resp) { ResponseData::Agent(d) => d, other => panic!("Expected Agent, got: {:?}", other) }
    }

    #[test]
    fn test_agent_list_tokens_via_daemon() {
        let (mut state, _dir) = setup_state();
        let resp = state.handle_request(Request::Agent {
            request: crate::agent::gateway::GatewayRequest::ListTokens,
        });
        let data = expect_agent(resp);
        assert!(matches!(data, GatewayData::Tokens(tokens) if tokens.is_empty()));
    }

    #[test]
    fn test_agent_list_pending_via_daemon() {
        let (mut state, _dir) = setup_state();
        let resp = state.handle_request(Request::Agent {
            request: crate::agent::gateway::GatewayRequest::ListPending,
        });
        let data = expect_agent(resp);
        assert!(matches!(data, GatewayData::Requests(reqs) if reqs.is_empty()));
    }

    #[test]
    fn test_agent_request_grant_via_daemon() {
        let (mut state, _dir) = setup_state();

        // Submit a request
        let resp = state.handle_request(Request::Agent {
            request: crate::agent::gateway::GatewayRequest::RequestAccess {
                agent_id: "test-agent".to_string(),
                scopes: vec![uuid::Uuid::new_v4()],
                actions: vec![crate::agent::token::AgentAction::Read],
                ttl: 3600,
                max_uses: Some(10),
                reason: "testing".to_string(),
            },
        });
        let data = expect_agent(resp);
        let request_id = match data {
            GatewayData::RequestId(id) => id,
            other => panic!("Expected RequestId, got: {:?}", other),
        };

        // Grant the request
        let resp = state.handle_request(Request::Agent {
            request: crate::agent::gateway::GatewayRequest::Grant {
                request_id,
                approved_by: "admin".to_string(),
            },
        });
        let data = expect_agent(resp);
        assert!(matches!(data, GatewayData::Token(_)));
    }

    #[test]
    fn test_agent_works_when_vault_locked() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test".to_string());
        VaultFile::create(&path, &password, KdfParams::fast_for_testing()).unwrap();

        // Don't unlock — vault is locked
        let mut state = DaemonState::new(path, 300);
        let resp = state.handle_request(Request::Agent {
            request: crate::agent::gateway::GatewayRequest::ListTokens,
        });
        // Agent commands should work even without vault unlock
        let data = expect_agent(resp);
        assert!(matches!(data, GatewayData::Tokens(tokens) if tokens.is_empty()));
    }

    #[test]
    fn test_agent_audit_via_daemon() {
        let (mut state, _dir) = setup_state();
        let resp = state.handle_request(Request::Agent {
            request: crate::agent::gateway::GatewayRequest::Audit {
                agent_id: None,
                last_n: None,
            },
        });
        let data = expect_agent(resp);
        assert!(matches!(data, GatewayData::AuditEntries(entries) if entries.is_empty()));
    }

    #[test]
    #[should_panic(expected = "Expected Ok response")]
    fn test_expect_agent_wrong_type() {
        expect_agent(Response::error("wrong"));
    }

    // -- should_panic tests for helper functions --

    #[test]
    #[should_panic(expected = "Expected Ok response")]
    fn test_expect_status_wrong_type() {
        expect_status(Response::error("wrong"));
    }

    #[test]
    #[should_panic(expected = "Expected Ok response")]
    fn test_expect_entries_wrong_type() {
        expect_entries(Response::error("wrong"));
    }

    #[test]
    #[should_panic(expected = "Expected Ok response")]
    fn test_expect_id_wrong_type() {
        expect_id(Response::error("wrong"));
    }

    #[test]
    #[should_panic(expected = "Expected Ok response")]
    fn test_expect_entry_wrong_type() {
        expect_entry(Response::error("wrong"));
    }

    #[test]
    #[should_panic(expected = "Expected Ok response")]
    fn test_expect_totp_wrong_type() {
        expect_totp(Response::error("wrong"));
    }

    #[test]
    #[should_panic(expected = "Expected Ok response")]
    fn test_expect_health_wrong_type() {
        expect_health(Response::error("wrong"));
    }

    #[test]
    #[should_panic(expected = "Expected Error response")]
    fn test_expect_error_wrong_type() {
        expect_error(Response::ok(ResponseData::None));
    }

    #[test]
    #[should_panic(expected = "Expected Status,")]
    fn test_expect_status_wrong_data() {
        expect_status(Response::ok(ResponseData::None));
    }

    #[test]
    #[should_panic(expected = "Expected Agent,")]
    fn test_expect_agent_wrong_data() {
        expect_agent(Response::ok(ResponseData::None));
    }

    // ---- Recovery / master key unlock tests ----

    #[test]
    fn test_unlock_with_recovery_key() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test-password".to_string());
        let params = KdfParams::fast_for_testing();

        let recovery_hex;
        {
            let mut vault = VaultFile::create(&path, &password, params).unwrap();
            vault.store_mut().add(Entry::new(
                "RecTest".to_string(),
                Credential::Login(LoginCredential {
                    url: "https://test.com".to_string(),
                    username: "u".to_string(),
                    password: "p".to_string(),
                }),
            ));
            vault.save().unwrap();
            let rk = vault.setup_recovery_key().unwrap();
            recovery_hex = crate::crypto::recovery::format_recovery_key(&rk);
        }

        let mut state = DaemonState::new(path, 300);
        let resp = state.handle_request(Request::UnlockRecovery { recovery_key: recovery_hex });
        assert!(expect_unlocked(resp));
        assert!(!state.is_locked());

        let s = expect_status(state.handle_request(Request::Status));
        assert_eq!(s.entry_count, 1);
    }

    #[test]
    fn test_unlock_with_wrong_recovery_key() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test".to_string());

        {
            let vault = VaultFile::create(&path, &password, KdfParams::fast_for_testing()).unwrap();
            vault.setup_recovery_key().unwrap();
        }

        let mut state = DaemonState::new(path, 300);
        let wrong = "AA".repeat(32); // 64 hex chars, wrong key
        let resp = state.handle_request(Request::UnlockRecovery { recovery_key: wrong });
        let msg = expect_error(resp);
        assert!(msg.contains("Recovery unlock failed"));
    }

    #[test]
    fn test_unlock_with_invalid_recovery_key_format() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test".to_string());
        VaultFile::create(&path, &password, KdfParams::fast_for_testing()).unwrap();

        let mut state = DaemonState::new(path, 300);
        let resp = state.handle_request(Request::UnlockRecovery { recovery_key: "tooshort".to_string() });
        let msg = expect_error(resp);
        assert!(msg.contains("Invalid recovery key"));
    }

    #[test]
    fn test_unlock_with_master_key_hex() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test-password".to_string());
        let params = KdfParams::fast_for_testing();

        let master_key_hex;
        {
            let mut vault = VaultFile::create(&path, &password, params).unwrap();
            vault.store_mut().add(Entry::new(
                "MKTest".to_string(),
                Credential::Login(LoginCredential {
                    url: "https://test.com".to_string(),
                    username: "u".to_string(),
                    password: "p".to_string(),
                }),
            ));
            vault.save().unwrap();
            master_key_hex = hex::encode(vault.master_key().as_bytes());
        }

        let mut state = DaemonState::new(path, 300);
        let resp = state.handle_request(Request::UnlockMasterKey { master_key_hex });
        assert!(expect_unlocked(resp));
        assert!(!state.is_locked());
    }

    #[test]
    fn test_unlock_with_wrong_master_key_hex() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test".to_string());

        let mut vault = VaultFile::create(&path, &password, KdfParams::fast_for_testing()).unwrap();
        vault.store_mut().add(Entry::new(
            "Test".to_string(),
            Credential::Login(LoginCredential {
                url: "https://test.com".to_string(),
                username: "u".to_string(),
                password: "p".to_string(),
            }),
        ));
        vault.save().unwrap();

        let mut state = DaemonState::new(path, 300);
        let wrong = hex::encode([99u8; 32]);
        let resp = state.handle_request(Request::UnlockMasterKey { master_key_hex: wrong });
        let msg = expect_error(resp);
        assert!(msg.contains("Master key unlock failed"));
    }

    #[test]
    fn test_unlock_master_key_invalid_hex() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test".to_string());
        VaultFile::create(&path, &password, KdfParams::fast_for_testing()).unwrap();

        let mut state = DaemonState::new(path, 300);
        let resp = state.handle_request(Request::UnlockMasterKey { master_key_hex: "not-hex".to_string() });
        let msg = expect_error(resp);
        assert!(msg.contains("Invalid hex"));
    }

    #[test]
    fn test_unlock_master_key_wrong_length() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test".to_string());
        VaultFile::create(&path, &password, KdfParams::fast_for_testing()).unwrap();

        let mut state = DaemonState::new(path, 300);
        let resp = state.handle_request(Request::UnlockMasterKey { master_key_hex: "0102".to_string() });
        let msg = expect_error(resp);
        assert!(msg.contains("32 bytes"));
    }

    #[test]
    fn test_unlock_touchid_not_enrolled() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test".to_string());
        VaultFile::create(&path, &password, KdfParams::fast_for_testing()).unwrap();

        let mut state = DaemonState::new(path, 300);
        let resp = state.handle_request(Request::UnlockTouchId);
        // Should fail because Touch ID is not enrolled
        let msg = expect_error(resp);
        assert!(msg.contains("Touch ID") || msg.contains("not enrolled") || msg.contains("failed"));
    }

    #[test]
    fn test_try_touchid_auto_unlock_not_enrolled() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test".to_string());
        VaultFile::create(&path, &password, KdfParams::fast_for_testing()).unwrap();

        let mut state = DaemonState::new(path, 300);
        // Should return false since Touch ID is not enrolled
        assert!(!state.try_touchid_auto_unlock());
        assert!(state.is_locked());
    }
}
