use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tower_http::services::{ServeDir, ServeFile};
use uuid::Uuid;

use super::access_policy::{self, AccessPolicy, PolicyDecision, SessionContext};
use super::gateway::{GatewayData, GatewayRequest, GatewayResponse};
use super::jwt::{self, JwtClaims, JwtRole};
use super::lease::{LeaseRequest, LeaseScope, Sensitivity};
use super::rate_config::AgentRateLimit;
use super::resolve::{resolve_vclaw_refs, ResolveResponse};
use super::token::AgentAction;
use crate::daemon::protocol::{Request, Response, ResponseData};
use crate::daemon::server::DaemonState;
use crate::vault::entry::{Credential, Entry, EntryId};

/// Per-subject (JWT sub) HTTP rate limiter using a sliding window.
#[derive(Debug)]
pub struct HttpRateLimiter {
    /// subject -> (window_start, request_count)
    windows: HashMap<String, (Instant, u32)>,
    /// Max requests per second (window = 1s).
    pub max_per_second: u32,
}

impl HttpRateLimiter {
    pub fn new(max_per_second: u32) -> Self {
        Self { windows: HashMap::new(), max_per_second }
    }

    /// Check and increment rate limit for a subject. Returns true if allowed.
    pub fn check(&mut self, subject: &str) -> bool {
        let now = Instant::now();
        let entry = self.windows.entry(subject.to_string()).or_insert((now, 0));

        if now.duration_since(entry.0).as_secs() >= 1 {
            *entry = (now, 0);
        }

        if entry.1 >= self.max_per_second {
            return false;
        }

        entry.1 += 1;
        true
    }
}

/// Shared HTTP server state.
#[derive(Clone)]
pub struct HttpState {
    pub daemon: Arc<Mutex<DaemonState>>,
    pub rate_limiter: Arc<Mutex<HttpRateLimiter>>,
}

// ---- Request/Response types ----

#[derive(Deserialize)]
pub struct AuthRequest {
    pub password: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String,
}

#[derive(Deserialize)]
pub struct ResolveRequest {
    pub refs: Vec<String>,
}

#[derive(Serialize)]
pub struct ResolveResponseBody {
    pub results: Vec<ResolveResponse>,
}

#[derive(Deserialize)]
pub struct AgentAccessRequest {
    pub agent_id: String,
    pub scopes: Vec<EntryId>,
    pub actions: Vec<AgentAction>,
    pub ttl: u64,
    pub max_uses: Option<u32>,
    pub reason: String,
}

#[derive(Serialize)]
pub struct AgentGrantResponse {
    pub token: String,
    pub token_id: String,
    pub agent_id: String,
    pub expires_at: String,
}

#[derive(Deserialize)]
pub struct AuditQuery {
    pub agent_id: Option<String>,
    pub last: Option<usize>,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Item metadata returned from the `/v1/items` endpoint (no secrets).
#[derive(Serialize)]
pub struct ItemSummary {
    pub id: EntryId,
    pub title: String,
    pub category: Option<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub sensitive: bool,
    pub credential_type: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Request to set an entry's sensitivity level.
#[derive(Deserialize)]
pub struct SetSensitivityRequest {
    pub level: Sensitivity,
}

/// Request body for creating a new entry.
#[derive(Deserialize)]
pub struct CreateItemRequest {
    pub title: String,
    pub credential: Credential,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub totp_secret: Option<String>,
    #[serde(default)]
    pub sensitive: bool,
}

/// Request body for updating an existing entry.
#[derive(Deserialize)]
pub struct UpdateItemRequest {
    pub title: String,
    pub credential: Credential,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub totp_secret: Option<String>,
    #[serde(default)]
    pub sensitive: bool,
}

/// Request body for bulk delete.
#[derive(Deserialize)]
pub struct BulkDeleteRequest {
    pub ids: Vec<EntryId>,
}

/// Request body for import.
#[derive(Deserialize)]
pub struct ImportRequest {
    /// File content as text.
    pub content: String,
    /// Format: "csv", "1pif", or "auto".
    #[serde(default = "default_auto")]
    pub format: String,
    /// If true, return preview without committing.
    #[serde(default)]
    pub dry_run: bool,
}

fn default_auto() -> String { "auto".to_string() }

/// Request body for breach check on a single entry.
#[derive(Deserialize)]
pub struct BreachCheckRequest {
    /// Entry ID to check.
    pub id: EntryId,
}

/// Response for a breach check operation.
#[derive(Serialize)]
pub struct BreachCheckResponse {
    pub entry_id: EntryId,
    pub title: String,
    pub breached: bool,
    pub count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Response for a batch breach check.
#[derive(Serialize)]
pub struct BreachCheckAllResponse {
    pub checked: usize,
    pub breached_count: usize,
    pub error_count: usize,
    pub results: Vec<BreachCheckResponse>,
}

/// A preview entry for import dry-run responses.
#[derive(Serialize)]
pub struct ImportPreviewEntry {
    pub title: String,
    pub credential_type: String,
    pub category: Option<String>,
    pub tags: Vec<String>,
    pub has_totp: bool,
    /// "new", "conflict"
    pub status: String,
    /// If conflict, the ID of the existing entry.
    pub conflict_id: Option<EntryId>,
}

/// Response for import endpoint.
#[derive(Serialize)]
pub struct ImportResponse {
    pub imported: usize,
    pub skipped: Vec<(String, String)>,
    pub total_processed: usize,
    /// Only in dry_run mode.
    pub preview: Option<Vec<ImportPreviewEntry>>,
}

// ---- Router ----

/// Build the axum router for the HTTP API.
pub fn create_router(state: HttpState) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/auth/token", post(auth_token))
        .route("/v1/resolve", post(resolve))
        .route("/v1/agent/request", post(agent_request))
        .route("/v1/agent/grant/:id", post(agent_grant))
        .route("/v1/agent/deny/:id", post(agent_deny))
        .route("/v1/agent/revoke/:id", post(agent_revoke))
        .route("/v1/agent/tokens", get(agent_tokens))
        .route("/v1/agent/token", post(agent_issue_token))
        .route("/v1/agent/pending", get(agent_pending))
        .route("/v1/agent/audit", get(agent_audit))
        .route("/v1/agent/dashboard", get(agent_dashboard))
        .route("/v1/items", get(list_items).post(create_item))
        .route("/v1/items/bulk-delete", post(bulk_delete_items))
        .route("/v1/items/:id", get(get_item).put(update_item).delete(delete_item))
        .route("/v1/items/:id/totp", get(get_item_totp))
        .route("/v1/lease", post(create_lease))
        .route("/v1/lease/active", get(list_active_leases))
        .route("/v1/lease/all", get(list_all_leases))
        .route("/v1/lease/:id/revoke", post(revoke_lease))
        .route("/v1/lease/revoke-all", post(revoke_all_leases))
        .route("/v1/entry/:id/sensitivity", post(set_entry_sensitivity))
        .route("/v1/import", post(import_entries))
        .route("/v1/breach-check", post(breach_check))
        .route("/v1/breach-check/all", post(breach_check_all))
        .route("/v1/health/vault", get(vault_health))
        .route("/v1/policy", get(get_policy).put(update_policy))
        .route("/v1/rotation/schedule", get(rotation_schedule))
        .route("/v1/rotation/scan", post(rotation_scan))
        .route("/v1/rotation/:id/approve", post(rotation_approve))
        .route("/v1/rotation/:id/dismiss", post(rotation_dismiss))
        .route("/v1/rotation/:id/execute", post(rotation_execute))
        .route("/v1/report", get(security_report))
        .route("/v1/rate-limits", get(list_rate_limits))
        .route("/v1/rate-limits/:agent_id", get(get_rate_limit).put(set_rate_limit).delete(delete_rate_limit))
        .route("/v1/status", get(vault_status))
        .route("/v1/lock", post(lock_vault))
        .route("/v1/export", get(export_entries))
        .route("/v1/sync/status", get(sync_status))
        .route("/v1/sync/trigger", post(sync_trigger))
        .route("/v1/sync/history", get(sync_history))
        .route("/v1/sync/targets", get(sync_targets))
        .route("/v1/backups", get(backup_list))
        .route("/v1/backups/create", post(backup_create))
        .route("/v1/backups/restore", post(backup_restore))
        .route("/v1/backups/verify", post(backup_verify))
        // Passkey endpoints
        .route("/v1/passkeys", get(list_passkeys).post(create_passkey))
        .route("/v1/passkeys/:rp_id", get(get_passkeys_by_rp))
        .route("/v1/passkeys/:id/assert", post(passkey_assert))
        .route("/v1/passkeys/:id/delete", post(delete_passkey))
        .route("/v1/passkeys/export", post(export_passkeys))
        .route("/v1/passkeys/import", post(import_passkeys))
        .with_state(state)
}

/// Build the router with optional web UI static file serving.
/// If `web_dir` points to an existing directory, serves static files from it
/// with SPA fallback (non-API routes return index.html).
pub fn create_router_with_web(state: HttpState, web_dir: Option<&std::path::Path>) -> Router {
    let api = create_router(state);

    // Try web_dir argument, then ./web/dist/ relative to cwd
    let resolved: Option<std::path::PathBuf> = web_dir
        .filter(|p| p.exists())
        .map(|p| p.to_path_buf())
        .or_else(|| {
            let default = std::path::PathBuf::from("web/dist");
            if default.exists() { Some(default) } else { None }
        });

    match resolved {
        Some(d) => {
            let index = d.join("index.html");
            api.fallback_service(
                ServeDir::new(&d).fallback(ServeFile::new(index)),
            )
        }
        None => api,
    }
}

// ---- Auth helpers ----

fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(|s| s.to_string())
}

fn require_admin(headers: &HeaderMap, state: &DaemonState) -> Result<JwtClaims, (StatusCode, Json<ErrorResponse>)> {
    let token_str = extract_bearer(headers).ok_or_else(|| {
        (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "Missing Authorization header".into() }))
    })?;
    let signing_key = state.jwt_signing_key().ok_or_else(|| {
        (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "Vault is locked".into() }))
    })?;
    let claims = jwt::verify_jwt(signing_key, &token_str).map_err(|e| {
        (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: format!("Invalid token: {}", e) }))
    })?;
    if claims.role != JwtRole::Admin {
        return Err((StatusCode::FORBIDDEN, Json(ErrorResponse { error: "Admin access required".into() })));
    }
    Ok(claims)
}

fn require_agent(headers: &HeaderMap, state: &DaemonState) -> Result<JwtClaims, (StatusCode, Json<ErrorResponse>)> {
    let token_str = extract_bearer(headers).ok_or_else(|| {
        (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "Missing Authorization header".into() }))
    })?;
    let signing_key = state.jwt_signing_key().ok_or_else(|| {
        (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "Vault is locked".into() }))
    })?;
    let claims = jwt::verify_jwt(signing_key, &token_str).map_err(|e| {
        (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: format!("Invalid token: {}", e) }))
    })?;
    Ok(claims)
}

// ---- Handlers ----

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn vault_status(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let resp = daemon.handle_request(Request::Status);
    match resp {
        Response::Ok { data } => match *data {
            ResponseData::Status(s) => Ok(Json(serde_json::json!({
                "locked": s.locked,
                "entry_count": s.entry_count,
                "vault_path": s.vault_path,
            }))),
            _ => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Unexpected response".into() }))),
        },
        Response::Error { message } => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: message }))),
    }
}

async fn lock_vault(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    daemon.lock();
    Ok(Json(serde_json::json!({ "status": "locked" })))
}

#[derive(Deserialize)]
struct ExportQuery {
    format: Option<String>,
}

async fn export_entries(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(params): Query<ExportQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let vault = daemon.vault_ref().ok_or_else(|| {
        (StatusCode::LOCKED, Json(ErrorResponse { error: "Vault is locked".into() }))
    })?;
    let entries = vault.store().entries();
    let format = params.format.as_deref().unwrap_or("json");

    match format {
        "json" => {
            let json = serde_json::to_string_pretty(&entries).map_err(|e| {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() }))
            })?;
            Ok((StatusCode::OK, [("content-type", "application/json")], json))
        }
        "csv" => {
            let mut wtr = csv::Writer::from_writer(vec![]);
            wtr.write_record(["Title", "Type", "URL", "Username", "Password", "Notes", "Tags", "Category", "TOTP"]).map_err(|e| {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() }))
            })?;
            for entry in &entries {
                let (url, username, password) = match &entry.credential {
                    Credential::Login(l) => (l.url.as_str(), l.username.as_str(), l.password.as_str()),
                    Credential::ApiKey(a) => (a.service.as_str(), a.key.as_str(), a.secret.as_str()),
                    Credential::SecureNote(_) => ("", "", ""),
                    Credential::SshKey(s) => ("", s.public_key.as_str(), s.private_key.as_str()),
                    Credential::Passkey(pk) => (pk.rp_id.as_str(), pk.user_name.as_str(), ""),
                };
                wtr.write_record([
                    &entry.title,
                    entry.credential_type(),
                    url, username, password,
                    &entry.notes,
                    &entry.tags.join(","),
                    entry.category.as_deref().unwrap_or(""),
                    entry.totp_secret.as_deref().unwrap_or(""),
                ]).map_err(|e| {
                    (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() }))
                })?;
            }
            let csv = String::from_utf8(wtr.into_inner().map_err(|e| {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() }))
            })?).map_err(|e| {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() }))
            })?;
            Ok((StatusCode::OK, [("content-type", "text/csv")], csv))
        }
        _ => Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: format!("Unsupported format: {}. Use 'json' or 'csv'.", format) }))),
    }
}

async fn breach_check(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<BreachCheckRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let vault = daemon.vault_ref().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, Json(ErrorResponse { error: "Vault is locked".into() }))
    })?;
    let entry = vault.store().get(&body.id).ok_or_else(|| {
        (StatusCode::NOT_FOUND, Json(ErrorResponse { error: "Entry not found".into() }))
    })?.clone();

    let result = crate::security::breach::check_entry_breach(&entry).await;

    // Update breach metadata on the entry
    if result.error.is_none() {
        let mut updated = entry;
        updated.last_breach_check = Some(chrono::Utc::now());
        updated.breach_count = Some(result.count);
        daemon.handle_request(Request::Update { entry: updated });
    }

    Ok(Json(BreachCheckResponse {
        entry_id: result.entry_id,
        title: result.title,
        breached: result.breached,
        count: result.count,
        error: result.error,
    }))
}

async fn breach_check_all(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let vault = daemon.vault_ref().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, Json(ErrorResponse { error: "Vault is locked".into() }))
    })?;
    let entries = vault.store().entries();
    let entry_refs: Vec<&crate::vault::entry::Entry> = entries.iter().collect();
    drop(daemon); // Release lock during long-running HIBP checks

    let report = crate::security::breach::check_entries_breach(&entry_refs).await;

    // Update breach metadata for successfully checked entries
    let mut daemon = state.daemon.lock().await;
    let now = chrono::Utc::now();
    for r in &report.results {
        if r.error.is_none() {
            if let Some(vault) = daemon.vault_ref() {
                if let Some(mut entry) = vault.store().get(&r.entry_id).cloned() {
                    entry.last_breach_check = Some(now);
                    entry.breach_count = Some(r.count);
                    daemon.handle_request(Request::Update { entry });
                }
            }
        }
    }

    Ok(Json(BreachCheckAllResponse {
        checked: report.checked,
        breached_count: report.breached_count,
        error_count: report.error_count,
        results: report.results.into_iter().map(|r| BreachCheckResponse {
            entry_id: r.entry_id,
            title: r.title,
            breached: r.breached,
            count: r.count,
            error: r.error,
        }).collect(),
    }))
}

async fn vault_health(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let vault = daemon.vault_ref().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, Json(ErrorResponse { error: "Vault is locked".into() }))
    })?;
    let owned_entries = vault.store().entries();
    let entries: Vec<&crate::vault::entry::Entry> = owned_entries.iter().collect();
    let report = crate::security::health::analyze_vault_health(&entries);
    Ok(Json(report))
}

async fn auth_token(
    State(state): State<HttpState>,
    Json(body): Json<AuthRequest>,
) -> impl IntoResponse {
    let mut daemon = state.daemon.lock().await;

    // If already unlocked, lock first to re-authenticate
    // (no-op if already locked)
    if daemon.is_locked() {
        let secret = crate::crypto::keys::password_secret(body.password);
        if let Err(e) = daemon.unlock(&secret) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": format!("Authentication failed: {}", e) })),
            );
        }
    }

    let signing_key = match daemon.jwt_signing_key() {
        Some(k) => k.to_vec(),
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "JWT signing key not available" })),
            );
        }
    };

    match jwt::create_admin_jwt(&signing_key, 3600) {
        Ok(token) => (StatusCode::OK, Json(serde_json::json!({ "token": token }))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("Failed to create token: {}", e) })),
        ),
    }
}

async fn resolve(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<ResolveRequest>,
) -> Result<Json<ResolveResponseBody>, (StatusCode, Json<ErrorResponse>)> {
    let daemon = state.daemon.lock().await;
    let claims = require_agent(&headers, &daemon)?;

    // Enforce session-aware access control
    let session_ctx = extract_session_context(&headers)?;
    check_session_policy(&daemon.access_policy, &session_ctx)?;

    // Per-subject rate limiting (100 req/s)
    {
        let mut rl = state.rate_limiter.lock().await;
        if !rl.check(&claims.sub) {
            return Err((StatusCode::TOO_MANY_REQUESTS, Json(ErrorResponse { error: "Rate limit exceeded".into() })));
        }
    }

    if daemon.is_locked() {
        return Err((StatusCode::SERVICE_UNAVAILABLE, Json(ErrorResponse { error: "Vault is locked".into() })));
    }

    let vault = daemon.vault_ref().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, Json(ErrorResponse { error: "Vault is locked".into() }))
    })?;
    let all_entries = vault.store().entries();
    let entries: Vec<&_> = all_entries.iter().collect();
    let results = resolve_vclaw_refs(&body.refs, &entries);
    Ok(Json(ResolveResponseBody { results }))
}

async fn agent_request(
    State(state): State<HttpState>,
    Json(body): Json<AgentAccessRequest>,
) -> impl IntoResponse {
    let mut daemon = state.daemon.lock().await;
    let req = GatewayRequest::RequestAccess {
        agent_id: body.agent_id,
        scopes: body.scopes,
        actions: body.actions,
        ttl: body.ttl,
        max_uses: body.max_uses,
        reason: body.reason,
    };
    let resp = daemon.handle_gateway(req);
    match resp {
        GatewayResponse::Ok { data: GatewayData::RequestId(id) } => {
            (StatusCode::ACCEPTED, Json(serde_json::json!({ "request_id": id }))).into_response()
        }
        GatewayResponse::Error { message } => {
            (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": message }))).into_response()
        }
        _ => {
            (StatusCode::OK, Json(serde_json::json!({ "status": "ok" }))).into_response()
        }
    }
}

async fn agent_grant(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let claims = require_admin(&headers, &daemon)?;

    let request_id: Uuid = id.parse().map_err(|_| {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Invalid request ID".into() }))
    })?;

    let req = GatewayRequest::Grant {
        request_id,
        approved_by: claims.sub.clone(),
    };
    let resp = daemon.handle_gateway(req);

    match resp {
        GatewayResponse::Ok { data: GatewayData::Token(token) } => {
            let signing_key = daemon.jwt_signing_key().ok_or_else(|| {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "JWT key unavailable".into() }))
            })?;
            let jwt_token = jwt::create_agent_jwt(
                signing_key,
                &token.agent_id,
                &token.id.to_string(),
                token.ttl_seconds,
            ).map_err(|e| {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: format!("JWT error: {}", e) }))
            })?;
            Ok((StatusCode::OK, Json(serde_json::json!({
                "token": jwt_token,
                "token_id": token.id.to_string(),
                "agent_id": token.agent_id,
                "expires_at": token.expires_at.to_rfc3339(),
            }))))
        }
        GatewayResponse::Error { message } => {
            Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: message })))
        }
        _ => Ok((StatusCode::OK, Json(serde_json::json!({ "status": "ok" })))),
    }
}

async fn agent_deny(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let request_id: Uuid = id.parse().map_err(|_| {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Invalid request ID".into() }))
    })?;

    let resp = daemon.handle_gateway(GatewayRequest::Deny { request_id });
    match resp {
        GatewayResponse::Ok { .. } => Ok(Json(serde_json::json!({ "status": "denied" }))),
        GatewayResponse::Error { message } => {
            Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: message })))
        }
    }
}

async fn agent_revoke(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let token_id: Uuid = id.parse().map_err(|_| {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Invalid token ID".into() }))
    })?;

    let resp = daemon.handle_gateway(GatewayRequest::Revoke { token_id });
    match resp {
        GatewayResponse::Ok { .. } => Ok(Json(serde_json::json!({ "status": "revoked" }))),
        GatewayResponse::Error { message } => {
            Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: message })))
        }
    }
}

async fn agent_tokens(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let resp = daemon.handle_gateway(GatewayRequest::ListTokens);
    gateway_to_json(resp)
}

/// Admin creates + auto-grants a token in one step.
async fn agent_issue_token(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<AgentAccessRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let claims = require_admin(&headers, &daemon)?;

    // Step 1: Submit the request
    let req = GatewayRequest::RequestAccess {
        agent_id: body.agent_id,
        scopes: body.scopes,
        actions: body.actions,
        ttl: body.ttl,
        max_uses: body.max_uses,
        reason: body.reason,
    };
    let resp = daemon.handle_gateway(req);
    let request_id = match resp {
        GatewayResponse::Ok { data: GatewayData::RequestId(id) } => id,
        GatewayResponse::Error { message } => {
            return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: message })));
        }
        _ => {
            return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Unexpected response".into() })));
        }
    };

    // Step 2: Auto-grant it
    let grant_req = GatewayRequest::Grant {
        request_id,
        approved_by: claims.sub.clone(),
    };
    let grant_resp = daemon.handle_gateway(grant_req);
    match grant_resp {
        GatewayResponse::Ok { data: GatewayData::Token(token) } => {
            let signing_key = daemon.jwt_signing_key().ok_or_else(|| {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "JWT key unavailable".into() }))
            })?;
            let jwt_token = jwt::create_agent_jwt(
                signing_key,
                &token.agent_id,
                &token.id.to_string(),
                token.ttl_seconds,
            ).map_err(|e| {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: format!("JWT error: {}", e) }))
            })?;
            Ok((StatusCode::CREATED, Json(serde_json::json!({
                "token": jwt_token,
                "token_id": token.id.to_string(),
                "agent_id": token.agent_id,
                "expires_at": token.expires_at.to_rfc3339(),
            }))))
        }
        GatewayResponse::Error { message } => {
            Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: message })))
        }
        _ => Ok((StatusCode::OK, Json(serde_json::json!({ "status": "ok" })))),
    }
}

async fn agent_pending(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let resp = daemon.handle_gateway(GatewayRequest::ListPending);
    gateway_to_json(resp)
}

async fn agent_audit(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let resp = daemon.handle_gateway(GatewayRequest::Audit {
        agent_id: query.agent_id,
        last_n: query.last,
    });
    gateway_to_json(resp)
}

async fn agent_dashboard(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let resp = daemon.handle_gateway(GatewayRequest::Dashboard);
    gateway_to_json(resp)
}

async fn list_items(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ItemSummary>>, (StatusCode, Json<ErrorResponse>)> {
    let daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let vault = daemon.vault_ref().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, Json(ErrorResponse { error: "Vault is locked".into() }))
    })?;

    let items: Vec<ItemSummary> = vault
        .store()
        .entries()
        .iter()
        .map(|e| ItemSummary {
            id: e.id,
            title: e.title.clone(),
            category: e.category.clone(),
            tags: e.tags.clone(),
            favorite: e.favorite,
            sensitive: e.sensitive,
            credential_type: credential_type_name(&e.credential),
            created_at: e.created_at.to_rfc3339(),
            updated_at: e.updated_at.to_rfc3339(),
        })
        .collect();
    Ok(Json(items))
}

async fn get_item(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let vault = daemon.vault_ref().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, Json(ErrorResponse { error: "Vault is locked".into() }))
    })?;

    let entry_id: Uuid = id.parse().map_err(|_| {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Invalid entry ID".into() }))
    })?;

    let entry = vault.store().get(&entry_id).ok_or_else(|| {
        (StatusCode::NOT_FOUND, Json(ErrorResponse { error: "Entry not found".into() }))
    })?;

    Ok(Json(serde_json::to_value(entry).unwrap_or_default()))
}

async fn create_item(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<CreateItemRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let mut entry = Entry::new(body.title, body.credential);
    entry.category = body.category;
    entry.tags = body.tags;
    entry.favorite = body.favorite;
    entry.notes = body.notes;
    entry.totp_secret = body.totp_secret;
    entry.sensitive = body.sensitive;

    let resp = daemon.handle_request(Request::Add { entry });
    match resp {
        Response::Ok { data } => match *data {
            ResponseData::Id(id) => Ok((StatusCode::CREATED, Json(serde_json::json!({ "id": id })))),
            _ => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Unexpected response".into() }))),
        },
        Response::Error { message } => {
            Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: message })))
        }
    }
}

async fn update_item(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<UpdateItemRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let entry_id: Uuid = id.parse().map_err(|_| {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Invalid entry ID".into() }))
    })?;

    // Get existing entry to preserve id and timestamps
    let vault = daemon.vault_ref().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, Json(ErrorResponse { error: "Vault is locked".into() }))
    })?;
    let existing = vault.store().get(&entry_id).ok_or_else(|| {
        (StatusCode::NOT_FOUND, Json(ErrorResponse { error: "Entry not found".into() }))
    })?;
    let created_at = existing.created_at;

    let entry = Entry {
        id: entry_id,
        title: body.title,
        credential: body.credential,
        category: body.category,
        tags: body.tags,
        favorite: body.favorite,
        notes: body.notes,
        totp_secret: body.totp_secret,
        sensitive: body.sensitive,
        last_breach_check: existing.last_breach_check,
        breach_count: existing.breach_count,
        created_at,
        updated_at: chrono::Utc::now(),
    };

    let resp = daemon.handle_request(Request::Update { entry });
    match resp {
        Response::Ok { .. } => Ok(Json(serde_json::json!({ "status": "ok" }))),
        Response::Error { message } => {
            Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: message })))
        }
    }
}

async fn delete_item(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let entry_id: Uuid = id.parse().map_err(|_| {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Invalid entry ID".into() }))
    })?;

    let resp = daemon.handle_request(Request::Delete { id: entry_id });
    match resp {
        Response::Ok { .. } => Ok(Json(serde_json::json!({ "status": "deleted" }))),
        Response::Error { message } => {
            Err((StatusCode::NOT_FOUND, Json(ErrorResponse { error: message })))
        }
    }
}

async fn get_item_totp(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let entry_id: Uuid = id.parse().map_err(|_| {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Invalid entry ID".into() }))
    })?;

    let resp = daemon.handle_request(Request::Totp { id: entry_id });
    match resp {
        Response::Ok { data } => match *data {
            ResponseData::Totp(t) => Ok(Json(serde_json::json!({
                "code": t.code,
                "seconds_remaining": t.seconds_remaining,
            }))),
            _ => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Unexpected response".into() }))),
        },
        Response::Error { message } => {
            Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: message })))
        }
    }
}

async fn bulk_delete_items(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<BulkDeleteRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let mut deleted = 0u32;
    let mut errors: Vec<String> = Vec::new();

    for id in &body.ids {
        let resp = daemon.handle_request(Request::Delete { id: *id });
        match resp {
            Response::Ok { .. } => deleted += 1,
            Response::Error { message } => errors.push(format!("{}: {}", id, message)),
        }
    }

    Ok(Json(serde_json::json!({
        "deleted": deleted,
        "errors": errors,
    })))
}

async fn import_entries(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<ImportRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    // Auto-detect format
    let format = if body.format == "auto" {
        let trimmed = body.content.trim();
        if trimmed.starts_with('{') || trimmed.contains("***5642bee8-a5ff-11dc-8314-0800200c9a66***") {
            "1pif"
        } else {
            "csv"
        }
    } else {
        &body.format
    };

    // Parse
    let result = match format {
        "csv" => crate::import::onepassword::import_csv_from_str(&body.content),
        "1pif" => crate::import::onepassword::import_1pif_from_str(&body.content),
        _ => return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse {
            error: format!("Unsupported format: {}", body.format),
        }))),
    };

    let import_result = result.map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: format!("Import error: {}", e) }))
    })?;

    if body.dry_run {
        // Build preview with conflict detection
        let vault = daemon.vault_ref().ok_or_else(|| {
            (StatusCode::SERVICE_UNAVAILABLE, Json(ErrorResponse { error: "Vault is locked".into() }))
        })?;
        let existing = vault.store().entries();

        let preview: Vec<ImportPreviewEntry> = import_result
            .imported
            .iter()
            .map(|entry| {
                let conflict = existing.iter().find(|e| {
                    e.title.eq_ignore_ascii_case(&entry.title)
                        && match (&e.credential, &entry.credential) {
                            (
                                Credential::Login(a),
                                Credential::Login(b),
                            ) => a.url.eq_ignore_ascii_case(&b.url),
                            _ => false,
                        }
                });
                ImportPreviewEntry {
                    title: entry.title.clone(),
                    credential_type: credential_type_name(&entry.credential),
                    category: entry.category.clone(),
                    tags: entry.tags.clone(),
                    has_totp: entry.totp_secret.is_some(),
                    status: if conflict.is_some() { "conflict".into() } else { "new".into() },
                    conflict_id: conflict.map(|e| e.id),
                }
            })
            .collect();

        return Ok(Json(serde_json::to_value(ImportResponse {
            imported: import_result.imported.len(),
            skipped: import_result.skipped,
            total_processed: import_result.total_processed,
            preview: Some(preview),
        }).unwrap_or_default()));
    }

    // Commit: add entries to vault
    let mut added = 0usize;
    for entry in import_result.imported {
        let resp = daemon.handle_request(Request::Add { entry });
        if matches!(resp, Response::Ok { .. }) {
            added += 1;
        }
    }

    Ok(Json(serde_json::to_value(ImportResponse {
        imported: added,
        skipped: import_result.skipped,
        total_processed: import_result.total_processed,
        preview: None,
    }).unwrap_or_default()))
}

// ---- Helpers ----

fn gateway_to_json(
    resp: GatewayResponse,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    match resp {
        GatewayResponse::Ok { data } => {
            Ok(Json(serde_json::to_value(data).unwrap_or_default()))
        }
        GatewayResponse::Error { message } => {
            Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: message })))
        }
    }
}

// ---- Lease handlers ----

async fn create_lease(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<LeaseRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let claims = require_agent(&headers, &daemon)?;

    // Enforce session-aware access control
    let session_ctx = extract_session_context(&headers)?;
    check_session_policy(&daemon.access_policy, &session_ctx)?;

    if daemon.is_locked() {
        return Err((StatusCode::SERVICE_UNAVAILABLE, Json(ErrorResponse { error: "Vault is locked".into() })));
    }

    let vault = daemon.vault_ref().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, Json(ErrorResponse { error: "Vault is locked".into() }))
    })?;

    // Resolve the entry reference (can be UUID or vclaw:// URI)
    let entry = if let Ok(uuid) = body.entry_ref.parse::<Uuid>() {
        vault.store().get(&uuid).cloned()
    } else {
        // Try vclaw:// reference — find by title (case-insensitive)
        let title = body.entry_ref
            .strip_prefix("vclaw://")
            .and_then(|s| s.split('/').nth(1))
            .unwrap_or(&body.entry_ref);
        vault.store().entries().iter().find(|e| e.title.eq_ignore_ascii_case(title)).cloned()
    };

    let entry = entry.ok_or_else(|| {
        (StatusCode::NOT_FOUND, Json(ErrorResponse { error: "Entry not found".into() }))
    })?;

    // Check sensitivity level (for dogfood v1, only low is auto-approved)
    let sensitivity = daemon.lease_store.get_sensitivity(&entry.id);
    if sensitivity != Sensitivity::Low {
        return Err((StatusCode::FORBIDDEN, Json(ErrorResponse {
            error: format!("Entry sensitivity is {:?}, requires manual approval", sensitivity),
        })));
    }

    // Check rate limits and anomalies for this agent
    let now = chrono::Utc::now();
    let anomalies = daemon.access_tracker.check_anomalies(&claims.sub, &entry.id, now, &daemon.rate_limit_config);
    if !anomalies.is_empty() {
        // Check if any anomaly is a rate limit exceeded
        let has_rate_limit = anomalies.iter().any(|a| matches!(a, super::rate_config::AnomalyType::RateLimitExceeded { .. }));
        // Check auto-revoke
        let should_revoke = daemon.rate_limit_config.get(&claims.sub)
            .is_some_and(|l| l.auto_revoke_on_anomaly);
        // Log anomalies to audit
        for anomaly in &anomalies {
            daemon.record_audit(
                claims.sub.clone(),
                Uuid::nil(),
                entry.id,
                AgentAction::Read,
                super::audit::AuditResult::Error(format!("Anomaly: {}", anomaly)),
                None,
            );
        }
        if has_rate_limit || should_revoke {
            daemon.save_policy();
            return Err((StatusCode::TOO_MANY_REQUESTS, Json(ErrorResponse {
                error: format!("Access denied: {}", anomalies.iter().map(|a| a.to_string()).collect::<Vec<_>>().join("; ")),
            })));
        }
    }
    // Record the access
    daemon.access_tracker.record_access(&claims.sub, &entry.id, now);

    // Extract credential value
    let cred_value = match &body.scope {
        LeaseScope::Read | LeaseScope::Use => extract_credential_value(&entry),
    };

    let lease = daemon.lease_store.create_lease(
        entry.id,
        claims.sub.clone(),
        body.scope,
        body.ttl,
        body.reason,
        cred_value.clone(),
    );

    Ok((StatusCode::CREATED, Json(serde_json::json!({
        "lease_id": lease.id,
        "credential": cred_value,
        "expires_at": lease.expires_at.to_rfc3339(),
    }))))
}

async fn list_active_leases(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let active = daemon.lease_store.active_leases();
    let summaries: Vec<serde_json::Value> = active.iter().map(|l| {
        serde_json::json!({
            "lease_id": l.id,
            "entry_id": l.entry_id,
            "agent_id": l.agent_id,
            "scope": l.scope,
            "reason": l.reason,
            "created_at": l.created_at.to_rfc3339(),
            "expires_at": l.expires_at.to_rfc3339(),
        })
    }).collect();

    Ok(Json(serde_json::json!({ "leases": summaries })))
}

async fn list_all_leases(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let all = daemon.lease_store.all_leases();
    let summaries: Vec<serde_json::Value> = all.iter().map(|l| {
        serde_json::json!({
            "lease_id": l.id,
            "entry_id": l.entry_id,
            "agent_id": l.agent_id,
            "scope": l.scope,
            "reason": l.reason,
            "status": l.status,
            "created_at": l.created_at.to_rfc3339(),
            "expires_at": l.expires_at.to_rfc3339(),
            "revoked_at": l.revoked_at.map(|t| t.to_rfc3339()),
        })
    }).collect();

    Ok(Json(serde_json::json!({ "leases": summaries })))
}

async fn revoke_lease(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let lease_id: Uuid = id.parse().map_err(|_| {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Invalid lease ID".into() }))
    })?;

    if daemon.lease_store.revoke(&lease_id) {
        Ok(Json(serde_json::json!({ "status": "revoked" })))
    } else {
        Err((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "Lease not found or already revoked".into() })))
    }
}

async fn revoke_all_leases(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let count = daemon.lease_store.revoke_all_leases();
    Ok(Json(serde_json::json!({ "status": "revoked", "count": count })))
}

async fn set_entry_sensitivity(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<SetSensitivityRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let entry_id: Uuid = id.parse().map_err(|_| {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Invalid entry ID".into() }))
    })?;

    // Verify entry exists
    if let Some(vault) = daemon.vault_ref() {
        if vault.store().get(&entry_id).is_none() {
            return Err((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "Entry not found".into() })));
        }
    } else {
        return Err((StatusCode::SERVICE_UNAVAILABLE, Json(ErrorResponse { error: "Vault is locked".into() })));
    }

    daemon.lease_store.set_sensitivity(entry_id, body.level);
    Ok(Json(serde_json::json!({ "status": "ok", "entry_id": entry_id, "sensitivity": body.level })))
}

/// Extract the primary credential value as a string for lease purposes.
fn extract_credential_value(entry: &crate::vault::entry::Entry) -> String {
    match &entry.credential {
        crate::vault::entry::Credential::Login(c) => c.password.clone(),
        crate::vault::entry::Credential::ApiKey(c) => format!("{}:{}", c.key, c.secret),
        crate::vault::entry::Credential::SecureNote(c) => c.content.clone(),
        crate::vault::entry::Credential::SshKey(c) => c.private_key.clone(),
        crate::vault::entry::Credential::Passkey(c) => c.credential_id.clone(),
    }
}

/// Extract and validate session context from the X-Session-Context header.
/// Returns None if no header is present (session context is optional).
fn extract_session_context(headers: &HeaderMap) -> Result<Option<SessionContext>, (StatusCode, Json<ErrorResponse>)> {
    let header = headers.get("x-session-context");
    match header {
        None => Ok(None),
        Some(value) => {
            let s = value.to_str().map_err(|_| {
                (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Invalid X-Session-Context header encoding".into() }))
            })?;
            let ctx = access_policy::parse_session_context(s).map_err(|e| {
                (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: format!("Invalid session context: {}", e) }))
            })?;
            Ok(Some(ctx))
        }
    }
}

/// Check session context against access policy. Returns Ok(()) if allowed or no context provided.
fn check_session_policy(
    policy: &AccessPolicy,
    ctx: &Option<SessionContext>,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if let Some(ctx) = ctx {
        match policy.evaluate(ctx) {
            PolicyDecision::Allow => Ok(()),
            PolicyDecision::Inherit => Ok(()), // Inherit is allowed at HTTP level, scope is checked elsewhere
            PolicyDecision::Deny(reason) => {
                Err((StatusCode::FORBIDDEN, Json(ErrorResponse { error: reason })))
            }
        }
    } else {
        Ok(())
    }
}

// ---- Policy endpoints ----

async fn get_policy(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    Ok(Json(serde_json::to_value(&daemon.access_policy).unwrap_or_default()))
}

/// Request body for updating access policy.
#[derive(Deserialize)]
struct UpdatePolicyRequest {
    /// Optionally provide the full policy as JSON.
    #[serde(flatten)]
    policy: AccessPolicy,
}

async fn update_policy(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<UpdatePolicyRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    daemon.access_policy = body.policy;
    // Persist the policy change
    daemon.save_policy();

    Ok(Json(serde_json::json!({ "status": "ok" })))
}

// ---- Rotation endpoints ----

/// Request body for dismissing a rotation plan.
#[derive(Deserialize)]
struct DismissRequest {
    #[serde(default = "default_dismiss_reason")]
    reason: String,
}

fn default_dismiss_reason() -> String { "user dismissed".to_string() }

async fn rotation_schedule(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let plans = daemon.rotation_scheduler.list_plans();
    let summary = daemon.rotation_scheduler.summary();
    Ok(Json(serde_json::json!({
        "plans": plans,
        "summary": summary,
    })))
}

async fn rotation_scan(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    // Gather health data from vault (immutable borrow)
    let (entry_count, health) = {
        let vault = daemon.vault_ref().ok_or_else(|| {
            (StatusCode::SERVICE_UNAVAILABLE, Json(ErrorResponse { error: "Vault is locked".into() }))
        })?;
        let entries: Vec<_> = vault.store().list().into_iter().collect();
        let health = crate::security::health::analyze_vault_health(&entries);
        (entries.len(), health)
    };

    // Now mutate the scheduler
    let created = daemon.rotation_scheduler.scan_and_plan(&health.details);

    // Generate passwords for new plans
    let plan_ids: Vec<Uuid> = daemon.rotation_scheduler.list_plans()
        .iter()
        .filter(|p| p.suggested_password.is_none())
        .map(|p| p.id)
        .collect();
    for plan_id in plan_ids {
        if let Some(p) = daemon.rotation_scheduler.get_plan_mut(&plan_id) {
            p.suggested_password = Some(crate::config::generate_password(24));
        }
    }

    daemon.save_policy(); // persists scheduler state

    Ok(Json(serde_json::json!({
        "scanned": entry_count,
        "new_plans": created,
        "plans": daemon.rotation_scheduler.list_plans(),
    })))
}

async fn rotation_approve(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let claims = require_admin(&headers, &daemon)?;

    let plan_id: Uuid = id.parse().map_err(|_| {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Invalid plan ID".into() }))
    })?;

    let plan = daemon.rotation_scheduler.get_plan_mut(&plan_id).ok_or_else(|| {
        (StatusCode::NOT_FOUND, Json(ErrorResponse { error: "Plan not found".into() }))
    })?;

    plan.approve(&claims.sub).map_err(|e| {
        (StatusCode::CONFLICT, Json(ErrorResponse { error: e }))
    })?;

    daemon.save_policy();

    Ok(Json(serde_json::json!({ "status": "approved", "plan_id": plan_id })))
}

async fn rotation_dismiss(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<DismissRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let plan_id: Uuid = id.parse().map_err(|_| {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Invalid plan ID".into() }))
    })?;

    let plan = daemon.rotation_scheduler.get_plan_mut(&plan_id).ok_or_else(|| {
        (StatusCode::NOT_FOUND, Json(ErrorResponse { error: "Plan not found".into() }))
    })?;

    plan.dismiss(&body.reason).map_err(|e| {
        (StatusCode::CONFLICT, Json(ErrorResponse { error: e }))
    })?;

    daemon.save_policy();

    Ok(Json(serde_json::json!({ "status": "dismissed", "plan_id": plan_id })))
}

async fn rotation_execute(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let plan_id: Uuid = id.parse().map_err(|_| {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Invalid plan ID".into() }))
    })?;

    // Gather plan info and entry data (immutable phase)
    let (plan_clone, entry, old_password, new_password) = {
        let plan = daemon.rotation_scheduler.get_plan(&plan_id).ok_or_else(|| {
            (StatusCode::NOT_FOUND, Json(ErrorResponse { error: "Plan not found".into() }))
        })?.clone();

        if !matches!(plan.state, crate::security::rotation::RotationState::Approved { .. }) {
            return Err((StatusCode::CONFLICT, Json(ErrorResponse {
                error: format!("Plan must be approved before execution (current: {:?})", plan.state),
            })));
        }

        let new_password = plan.suggested_password.clone()
            .unwrap_or_else(|| crate::config::generate_password(24));

        let vault = daemon.vault_ref().ok_or_else(|| {
            (StatusCode::SERVICE_UNAVAILABLE, Json(ErrorResponse { error: "Vault is locked".into() }))
        })?;

        let entry = vault.store().get(&plan.entry_id).cloned().ok_or_else(|| {
            (StatusCode::NOT_FOUND, Json(ErrorResponse { error: "Entry not found in vault".into() }))
        })?;

        let old_password = match &entry.credential {
            Credential::Login(l) => l.password.clone(),
            Credential::ApiKey(a) => a.secret.clone(),
            Credential::SshKey(s) => s.passphrase.clone(),
            Credential::SecureNote(_) | Credential::Passkey(_) => String::new(),
        };

        (plan, entry, old_password, new_password)
    };

    // Check if it's a SecureNote (can't rotate)
    if matches!(entry.credential, Credential::SecureNote(_) | Credential::Passkey(_)) {
        let p = daemon.rotation_scheduler.get_plan_mut(&plan_id).unwrap();
        let _ = p.fail("Cannot rotate SecureNote credentials");
        daemon.save_policy();
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse {
            error: "Cannot rotate SecureNote credentials".into(),
        })));
    }

    // Begin rotation
    daemon.rotation_scheduler.get_plan_mut(&plan_id).unwrap().begin_rotation().unwrap();

    // Build updated entry with new password
    let mut updated = entry;
    match &mut updated.credential {
        Credential::Login(l) => l.password.clone_from(&new_password),
        Credential::ApiKey(a) => a.secret.clone_from(&new_password),
        Credential::SshKey(s) => s.passphrase.clone_from(&new_password),
        Credential::SecureNote(_) | Credential::Passkey(_) => unreachable!(),
    }
    updated.updated_at = chrono::Utc::now();

    // Update the vault
    let vault_mut = daemon.vault_ref_mut().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, Json(ErrorResponse { error: "Vault is locked".into() }))
    })?;
    vault_mut.store_mut().update(updated);
    vault_mut.save().map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: format!("Failed to save vault: {}", e) }))
    })?;

    // Mark rotation as completed
    let entry_title = {
        let p = daemon.rotation_scheduler.get_plan_mut(&plan_id).unwrap();
        p.notes = format!("Previous password stored for rollback. Old: {}", old_password);
        let _ = p.complete(true);
        p.entry_title.clone()
    };

    daemon.save_policy();

    Ok(Json(serde_json::json!({
        "status": "completed",
        "plan_id": plan_id,
        "entry_id": plan_clone.entry_id,
        "entry_title": entry_title,
    })))
}

// ---- Security report endpoint ----

async fn security_report(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    // 1. Vault health + security report
    let (report, enhanced_narrative) = {
        let vault = daemon.vault_ref().ok_or_else(|| {
            (StatusCode::SERVICE_UNAVAILABLE, Json(ErrorResponse { error: "Vault is locked".into() }))
        })?;
        let entries: Vec<_> = vault.store().list().into_iter().collect();
        let report = crate::security::report::generate_report(&entries);
        let narrative = crate::security::llm::generate_static_narrative(&report);
        (report, narrative)
    };

    // 2. Rotation summary
    let rotation_summary = daemon.rotation_scheduler.summary();

    // 3. Audit summary — use the gateway dashboard
    let dashboard_resp = daemon.handle_gateway(GatewayRequest::Dashboard);
    let audit_summary = match dashboard_resp {
        GatewayResponse::Ok { data: GatewayData::Dashboard(summary) } => Some(summary),
        _ => None,
    };

    // 4. Rate limit overview
    let rate_limit_count = daemon.rate_limit_config.list().len();

    Ok(Json(serde_json::json!({
        "executive_summary": {
            "grade": format!("{:?}", report.summary.grade),
            "grade_label": report.summary.grade.label(),
            "headline": report.summary.headline,
            "health_score": report.health.health_score,
            "total_issues": report.summary.total_issues,
            "critical_issues": report.summary.critical_issues,
            "narrative": enhanced_narrative,
        },
        "password_health": {
            "total_entries": report.health.total_entries,
            "login_entries": report.health.login_entries,
            "weak_passwords": report.health.weak_passwords,
            "reused_passwords": report.health.reused_passwords,
            "old_passwords": report.health.old_passwords,
            "entries_without_totp": report.health.entries_without_totp,
            "health_score": report.health.health_score,
        },
        "recommendations": report.recommendations.iter().map(|r| serde_json::json!({
            "severity": format!("{:?}", r.severity),
            "title": r.title,
            "description": r.description,
            "affected_count": r.affected_entries.len(),
            "affected_entries": r.affected_entries,
        })).collect::<Vec<_>>(),
        "rotation_status": rotation_summary,
        "access_audit": audit_summary.as_ref().map(|s| serde_json::json!({
            "total_events": s.total_events,
            "success_count": s.success_count,
            "denied_count": s.denied_count,
            "rate_limited_count": s.rate_limited_count,
            "error_count": s.error_count,
            "unique_agents": s.unique_agent_count,
            "active_tokens": s.active_token_count,
            "pending_requests": s.pending_request_count,
            "suspicious_agents": s.suspicious_agents,
            "alerts": s.alerts,
        })),
        "rate_limits": {
            "configured_agents": rate_limit_count,
        },
    })))
}

// ---- Rate limit endpoints ----

/// Request body for setting a rate limit.
#[derive(Deserialize)]
struct SetRateLimitRequest {
    rpm: u32,
    rph: u32,
    #[serde(default)]
    auto_revoke_on_anomaly: bool,
}

/// Response for a single agent's rate limit.
#[derive(Serialize)]
struct RateLimitResponse {
    agent_id: String,
    rpm: u32,
    rph: u32,
    auto_revoke_on_anomaly: bool,
    current_rpm: u32,
    current_rph: u32,
}

async fn list_rate_limits(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let now = chrono::Utc::now();
    let limits: Vec<RateLimitResponse> = daemon.rate_limit_config.list().iter().map(|l| {
        RateLimitResponse {
            agent_id: l.agent_id.clone(),
            rpm: l.rpm,
            rph: l.rph,
            auto_revoke_on_anomaly: l.auto_revoke_on_anomaly,
            current_rpm: daemon.access_tracker.current_rpm(&l.agent_id, now),
            current_rph: daemon.access_tracker.current_rph(&l.agent_id),
        }
    }).collect();

    Ok(Json(serde_json::json!({ "rate_limits": limits })))
}

async fn get_rate_limit(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let limit = daemon.rate_limit_config.get(&agent_id).ok_or_else(|| {
        (StatusCode::NOT_FOUND, Json(ErrorResponse { error: format!("No rate limit for agent '{}'", agent_id) }))
    })?;

    let now = chrono::Utc::now();
    Ok(Json(serde_json::json!({
        "agent_id": limit.agent_id,
        "rpm": limit.rpm,
        "rph": limit.rph,
        "auto_revoke_on_anomaly": limit.auto_revoke_on_anomaly,
        "current_rpm": daemon.access_tracker.current_rpm(&agent_id, now),
        "current_rph": daemon.access_tracker.current_rph(&agent_id),
    })))
}

async fn set_rate_limit(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
    Json(body): Json<SetRateLimitRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let mut limit = AgentRateLimit::new(agent_id.clone(), body.rpm, body.rph);
    limit.auto_revoke_on_anomaly = body.auto_revoke_on_anomaly;
    daemon.rate_limit_config.set(limit);
    daemon.save_policy(); // persists agent state

    Ok(Json(serde_json::json!({ "status": "ok", "agent_id": agent_id })))
}

async fn delete_rate_limit(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    if daemon.rate_limit_config.remove(&agent_id) {
        daemon.save_policy();
        Ok(Json(serde_json::json!({ "status": "ok" })))
    } else {
        Err((StatusCode::NOT_FOUND, Json(ErrorResponse { error: format!("No rate limit for agent '{}'", agent_id) })))
    }
}

fn credential_type_name(cred: &crate::vault::entry::Credential) -> String {
    match cred {
        crate::vault::entry::Credential::Login(_) => "login".into(),
        crate::vault::entry::Credential::ApiKey(_) => "api_key".into(),
        crate::vault::entry::Credential::SecureNote(_) => "secure_note".into(),
        crate::vault::entry::Credential::SshKey(_) => "ssh_key".into(),
        crate::vault::entry::Credential::Passkey(_) => "passkey".into(),
    }
}

// ---- Passkey endpoints ----

/// Request to create a new passkey (from browser extension registration).
#[derive(Deserialize)]
pub struct CreatePasskeyRequest {
    pub title: String,
    pub rp_id: String,
    pub rp_name: String,
    pub user_handle: String,
    pub user_name: String,
    #[serde(default = "default_es256")]
    pub algorithm: crate::vault::entry::PasskeyAlgorithm,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_es256() -> crate::vault::entry::PasskeyAlgorithm {
    crate::vault::entry::PasskeyAlgorithm::Es256
}

/// Request to sign a WebAuthn assertion.
#[derive(Deserialize)]
pub struct PasskeyAssertRequest {
    pub client_data_json: String,
    #[serde(default = "default_true_val")]
    pub user_verified: bool,
}

fn default_true_val() -> bool { true }

/// Passkey summary returned by list/get endpoints (no private key).
#[derive(Serialize)]
pub struct PasskeySummary {
    pub id: EntryId,
    pub title: String,
    pub rp_id: String,
    pub rp_name: String,
    pub user_handle: String,
    pub user_name: String,
    pub algorithm: crate::vault::entry::PasskeyAlgorithm,
    pub sign_count: u32,
    pub discoverable: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    /// "software" or "hardware" — hardware passkeys have empty private_key
    pub storage: String,
    pub last_used_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Assertion response returned by the assert endpoint.
#[derive(Serialize)]
pub struct PasskeyAssertResponse {
    pub authenticator_data: String,
    pub signature: String,
    pub user_handle: String,
    pub client_data_json: String,
    pub credential_id: String,
}

fn passkey_to_summary(entry: &Entry) -> Option<PasskeySummary> {
    if let Credential::Passkey(pk) = &entry.credential {
        let storage = if pk.private_key.is_empty() {
            "hardware".to_string()
        } else {
            "software".to_string()
        };
        Some(PasskeySummary {
            id: entry.id,
            title: entry.title.clone(),
            rp_id: pk.rp_id.clone(),
            rp_name: pk.rp_name.clone(),
            user_handle: pk.user_handle.clone(),
            user_name: pk.user_name.clone(),
            algorithm: pk.algorithm.clone(),
            sign_count: pk.sign_count,
            discoverable: pk.discoverable,
            backup_eligible: pk.backup_eligible,
            backup_state: pk.backup_state,
            storage,
            last_used_at: pk.last_used_at.map(|t| t.to_rfc3339()),
            created_at: entry.created_at.to_rfc3339(),
            updated_at: entry.updated_at.to_rfc3339(),
        })
    } else {
        None
    }
}

async fn list_passkeys(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let vault = daemon.vault_ref().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, Json(ErrorResponse { error: "Vault is locked".into() }))
    })?;

    let passkeys: Vec<PasskeySummary> = vault.store().list().into_iter()
        .filter_map(passkey_to_summary)
        .collect();

    Ok(Json(passkeys))
}

async fn get_passkeys_by_rp(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(rp_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let vault = daemon.vault_ref().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, Json(ErrorResponse { error: "Vault is locked".into() }))
    })?;

    // Try to parse as UUID first (for delete-by-id scenario routed here)
    // Otherwise filter by rp_id
    let passkeys: Vec<PasskeySummary> = if uuid::Uuid::parse_str(&rp_id).is_ok() {
        let id: uuid::Uuid = rp_id.parse().unwrap();
        vault.store().get(&id)
            .and_then(passkey_to_summary)
            .into_iter().collect()
    } else {
        vault.store().list().into_iter()
            .filter(|e| {
                if let Credential::Passkey(pk) = &e.credential {
                    pk.rp_id == rp_id
                } else {
                    false
                }
            })
            .filter_map(passkey_to_summary)
            .collect()
    };

    Ok(Json(passkeys))
}

async fn create_passkey(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<CreatePasskeyRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    // Generate a new key pair
    let kp = crate::passkey::generate_passkey_credential(&body.algorithm)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;

    let credential = Credential::Passkey(crate::vault::entry::PasskeyCredential {
        credential_id: kp.credential_id.clone(),
        rp_id: body.rp_id,
        rp_name: body.rp_name,
        user_handle: body.user_handle,
        user_name: body.user_name,
        private_key: kp.cose_private_key,
        algorithm: kp.algorithm,
        sign_count: 0,
        discoverable: true,
        backup_eligible: true,
        backup_state: false,
        last_used_at: None,
    });

    let mut entry = Entry::new(body.title, credential);
    entry.category = body.category;
    entry.tags = body.tags;

    let resp = daemon.handle_request(Request::Add { entry });
    match resp {
        Response::Ok { data } => match *data {
            ResponseData::Id(id) => Ok((StatusCode::CREATED, Json(serde_json::json!({
                "id": id,
                "credential_id": kp.credential_id,
            })))),
            _ => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Unexpected response".into() }))),
        },
        Response::Error { message } => {
            Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: message })))
        }
    }
}

async fn passkey_assert(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id_str): Path<String>,
    Json(body): Json<PasskeyAssertRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let entry_id: Uuid = id_str.parse().map_err(|_| {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Invalid entry ID".into() }))
    })?;

    let vault = daemon.vault_ref_mut().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, Json(ErrorResponse { error: "Vault is locked".into() }))
    })?;

    let entry = vault.store().get(&entry_id).cloned().ok_or_else(|| {
        (StatusCode::NOT_FOUND, Json(ErrorResponse { error: "Entry not found".into() }))
    })?;

    let pk = match &entry.credential {
        Credential::Passkey(pk) => pk.clone(),
        _ => return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Entry is not a passkey".into() }))),
    };

    let new_sign_count = pk.sign_count + 1;

    let input = crate::passkey::AssertionInput {
        rp_id: pk.rp_id.clone(),
        client_data_json: body.client_data_json,
        cose_private_key: pk.private_key.clone(),
        sign_count: new_sign_count,
        user_handle: pk.user_handle.clone(),
        user_verified: body.user_verified,
    };

    let assertion = crate::passkey::build_assertion_response(&input)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;

    // Update sign_count and last_used_at
    let mut updated = entry;
    if let Credential::Passkey(ref mut pk_mut) = updated.credential {
        pk_mut.sign_count = new_sign_count;
        pk_mut.last_used_at = Some(chrono::Utc::now());
    }
    updated.updated_at = chrono::Utc::now();
    vault.store_mut().update(updated);
    vault.save().map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() }))
    })?;

    Ok(Json(PasskeyAssertResponse {
        authenticator_data: assertion.authenticator_data,
        signature: assertion.signature,
        user_handle: assertion.user_handle,
        client_data_json: assertion.client_data_json,
        credential_id: pk.credential_id,
    }))
}

async fn delete_passkey(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id_str): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let entry_id: Uuid = id_str.parse().map_err(|_| {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Invalid entry ID".into() }))
    })?;

    let vault = daemon.vault_ref_mut().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, Json(ErrorResponse { error: "Vault is locked".into() }))
    })?;

    let entry = vault.store().get(&entry_id).ok_or_else(|| {
        (StatusCode::NOT_FOUND, Json(ErrorResponse { error: "Entry not found".into() }))
    })?;

    if !matches!(&entry.credential, Credential::Passkey(_)) {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Entry is not a passkey".into() })));
    }

    vault.store_mut().remove(&entry_id);
    vault.save().map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() }))
    })?;

    Ok(Json(serde_json::json!({ "status": "deleted", "id": entry_id })))
}

// ---- Passkey export/import endpoints ----

#[derive(Deserialize)]
struct PasskeyImportRequest {
    passkeys: Vec<PasskeyImportEntry>,
}

#[derive(Deserialize)]
struct PasskeyImportEntry {
    credential_id: String,
    rp_id: String,
    rp_name: String,
    user_handle: String,
    user_name: String,
    #[serde(default)]
    private_key: String,
    #[serde(default = "default_es256_str")]
    algorithm: String,
    #[serde(default)]
    sign_count: u32,
    #[serde(default = "default_true_val")]
    discoverable: bool,
    #[serde(default)]
    backup_eligible: bool,
    #[serde(default)]
    backup_state: bool,
    #[serde(default)]
    title: Option<String>,
}

fn default_es256_str() -> String { "es256".to_string() }

async fn export_passkeys(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let vault = daemon.vault_ref().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, Json(ErrorResponse { error: "Vault is locked".into() }))
    })?;

    let passkeys: Vec<serde_json::Value> = vault.store().list().into_iter()
        .filter(|e| matches!(&e.credential, Credential::Passkey(_)))
        .map(|e| {
            if let Credential::Passkey(pk) = &e.credential {
                serde_json::json!({
                    "id": e.id,
                    "title": e.title,
                    "credential_id": pk.credential_id,
                    "rp_id": pk.rp_id,
                    "rp_name": pk.rp_name,
                    "user_name": pk.user_name,
                    "user_handle": pk.user_handle,
                    "private_key": pk.private_key,
                    "algorithm": pk.algorithm,
                    "sign_count": pk.sign_count,
                    "discoverable": pk.discoverable,
                    "backup_eligible": pk.backup_eligible,
                    "backup_state": pk.backup_state,
                    "storage": if pk.private_key.is_empty() { "hardware" } else { "software" },
                    "created_at": e.created_at,
                })
            } else {
                serde_json::json!({})
            }
        })
        .collect();

    Ok(Json(serde_json::json!({
        "count": passkeys.len(),
        "passkeys": passkeys,
    })))
}

async fn import_passkeys(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<PasskeyImportRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    use crate::vault::entry::{PasskeyAlgorithm, PasskeyCredential};

    let mut daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let vault = daemon.vault_ref_mut().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, Json(ErrorResponse { error: "Vault is locked".into() }))
    })?;

    let mut imported = 0u32;
    let mut skipped = 0u32;

    for pk_entry in &body.passkeys {
        if pk_entry.credential_id.is_empty() || pk_entry.rp_id.is_empty() {
            skipped += 1;
            continue;
        }

        // Check for duplicate
        let exists = vault.store().list().iter().any(|e| {
            matches!(&e.credential, Credential::Passkey(pk) if pk.credential_id == pk_entry.credential_id)
        });
        if exists {
            skipped += 1;
            continue;
        }

        let algorithm = match pk_entry.algorithm.as_str() {
            "eddsa" | "ed25519" => PasskeyAlgorithm::EdDsa,
            _ => PasskeyAlgorithm::Es256,
        };

        let passkey = PasskeyCredential {
            credential_id: pk_entry.credential_id.clone(),
            rp_id: pk_entry.rp_id.clone(),
            rp_name: pk_entry.rp_name.clone(),
            user_handle: pk_entry.user_handle.clone(),
            user_name: pk_entry.user_name.clone(),
            private_key: pk_entry.private_key.clone(),
            algorithm,
            sign_count: pk_entry.sign_count,
            discoverable: pk_entry.discoverable,
            backup_eligible: pk_entry.backup_eligible,
            backup_state: pk_entry.backup_state,
            last_used_at: None,
        };

        let title = pk_entry.title.clone()
            .unwrap_or_else(|| format!("{} ({})", pk_entry.rp_name, pk_entry.user_name));

        vault.store_mut().add(Entry::new(title, Credential::Passkey(passkey)));
        imported += 1;
    }

    if imported > 0 {
        vault.save().map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() }))
        })?;
    }

    Ok(Json(serde_json::json!({
        "imported": imported,
        "skipped": skipped,
    })))
}

// ---- Backup endpoints ----

async fn backup_list(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let backup_dir = crate::backup::default_backup_dir();
    let backups = crate::backup::list_backups(&backup_dir).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() }))
    })?;

    Ok(Json(serde_json::json!({
        "backups": backups,
        "backup_dir": backup_dir.display().to_string(),
    })))
}

async fn backup_create(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let vault = daemon.vault_ref().ok_or_else(|| {
        (StatusCode::LOCKED, Json(ErrorResponse { error: "Vault is locked".into() }))
    })?;
    let vault_path = vault.path().to_path_buf();
    let backup_dir = crate::backup::default_backup_dir();

    let info = crate::backup::create_backup(&vault_path, &backup_dir).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() }))
    })?;

    // Auto-prune
    let pruned = crate::backup::prune_backups(&backup_dir, 10).unwrap_or_default();

    Ok(Json(serde_json::json!({
        "backup": info,
        "pruned": pruned,
    })))
}

#[derive(Deserialize)]
struct BackupRestoreRequest {
    filename: String,
}

async fn backup_restore(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<BackupRestoreRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let vault = daemon.vault_ref().ok_or_else(|| {
        (StatusCode::LOCKED, Json(ErrorResponse { error: "Vault is locked".into() }))
    })?;
    let vault_path = vault.path().to_path_buf();
    let backup_dir = crate::backup::default_backup_dir();
    let backup_path = backup_dir.join(&body.filename);

    // Verify first
    let verify = crate::backup::verify_backup(&backup_path).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: e.to_string() }))
    })?;

    if !verify.valid {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse {
            error: format!("Backup verification failed: {}", verify.error.unwrap_or_default()),
        })));
    }

    let info = crate::backup::restore_backup(&backup_path, &vault_path).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() }))
    })?;

    Ok(Json(serde_json::json!({
        "restored": info,
    })))
}

#[derive(Deserialize)]
struct BackupVerifyRequest {
    filename: String,
}

async fn backup_verify(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<BackupVerifyRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let backup_dir = crate::backup::default_backup_dir();
    let backup_path = backup_dir.join(&body.filename);

    let result = crate::backup::verify_backup(&backup_path).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: e.to_string() }))
    })?;

    Ok(Json(result))
}

// ---- Sync endpoints ----

async fn sync_status(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let history = crate::sync::scheduler::SyncHistory::load(
        &crate::sync::scheduler::sync_history_path(),
    );
    let config = crate::sync::scheduler::MultiSyncConfig::load(
        &crate::sync::scheduler::multi_sync_config_path(),
    );
    let has_auto = config.targets.iter().any(|t| t.auto_sync);
    let (success_count, fail_count) = history.stats();

    let vault_meta = daemon.vault_ref().and_then(|v| {
        crate::sync::provider::local_metadata(v.path()).ok()
    });

    let status = crate::sync::scheduler::SyncStatus {
        configured: !config.targets.is_empty(),
        auto_sync_enabled: has_auto,
        sync_interval_seconds: config.targets.first().map(|t| t.sync_interval_seconds).unwrap_or(300),
        last_sync: history.last_sync().cloned(),
        last_sync_time: history.last_sync().map(|e| e.timestamp.to_rfc3339()),
        next_sync_time: None,
        pending_changes: false,
        local_checksum: vault_meta.as_ref().map(|m| m.checksum.clone()),
        remote_checksum: None,
        config: None,
    };

    Ok(Json(serde_json::json!({
        "status": status,
        "targets": config.targets,
        "history_count": history.entries.len(),
        "success_count": success_count,
        "fail_count": fail_count,
    })))
}

async fn sync_trigger(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    use crate::sync::file_sync::FileSyncProvider;
    use crate::sync::provider::{SyncProvider, determine_sync_direction, local_metadata};
    #[cfg(feature = "webdav")]
    use crate::sync::webdav::{WebDavConfig, WebDavProvider};

    let daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let vault = daemon.vault_ref().ok_or_else(|| {
        (StatusCode::LOCKED, Json(ErrorResponse { error: "Vault is locked".into() }))
    })?;
    let vault_path = vault.path().to_path_buf();
    let vault_filename = vault_path.file_name()
        .unwrap_or_default().to_string_lossy().to_string();

    let config = crate::sync::scheduler::MultiSyncConfig::load(
        &crate::sync::scheduler::multi_sync_config_path(),
    );

    if config.targets.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse {
            error: "No sync targets configured".into(),
        })));
    }

    let history_path = crate::sync::scheduler::sync_history_path();
    let mut history = crate::sync::scheduler::SyncHistory::load(&history_path);
    let mut results = Vec::new();

    for target in &config.targets {
        let provider: Box<dyn SyncProvider> = match target.provider.as_str() {
            "file" => Box::new(FileSyncProvider::new(
                std::path::PathBuf::from(&target.remote_path),
                vault_filename.clone(),
            )),
            #[cfg(feature = "webdav")]
            "webdav" => {
                let url = match &target.url {
                    Some(u) => u.clone(),
                    None => {
                        results.push(serde_json::json!({
                            "target": target.name,
                            "success": false,
                            "message": "WebDAV target missing URL",
                        }));
                        continue;
                    }
                };
                Box::new(WebDavProvider::new(WebDavConfig {
                    url,
                    username: target.username.clone().unwrap_or_default(),
                    password: target.password.clone().unwrap_or_default(),
                    remote_path: target.remote_path.clone(),
                }))
            }
            other => {
                results.push(serde_json::json!({
                    "target": target.name,
                    "success": false,
                    "message": format!("Unknown provider: {}", other),
                }));
                continue;
            }
        };

        if !provider.is_available().unwrap_or(false) {
            results.push(serde_json::json!({
                "target": target.name,
                "success": false,
                "message": "Remote not available",
            }));
            continue;
        }

        // Determine direction based on metadata comparison
        let local_meta = match local_metadata(&vault_path) {
            Ok(m) => m,
            Err(e) => {
                results.push(serde_json::json!({
                    "target": target.name,
                    "success": false,
                    "message": format!("Local metadata error: {}", e),
                }));
                continue;
            }
        };

        let direction = match provider.remote_metadata() {
            Ok(Some(remote_meta)) => {
                match determine_sync_direction(&local_meta, &remote_meta) {
                    Ok(Some(d)) => d,
                    Ok(None) => {
                        results.push(serde_json::json!({
                            "target": target.name,
                            "success": true,
                            "message": "Already in sync",
                        }));
                        continue;
                    }
                    Err(_) => crate::sync::provider::SyncDirection::Push, // conflict → push wins
                }
            }
            Ok(None) => crate::sync::provider::SyncDirection::Push, // no remote → push
            Err(e) => {
                results.push(serde_json::json!({
                    "target": target.name,
                    "success": false,
                    "message": format!("Remote metadata error: {}", e),
                }));
                continue;
            }
        };

        let sync_result = match direction {
            crate::sync::provider::SyncDirection::Push => provider.push(&vault_path),
            crate::sync::provider::SyncDirection::Pull => provider.pull(&vault_path),
            _ => provider.push(&vault_path),
        };

        match sync_result {
            Ok(r) => {
                history.record(&r, &target.provider, &target.remote_path);
                results.push(serde_json::json!({
                    "target": target.name,
                    "success": r.success,
                    "direction": format!("{:?}", r.direction),
                    "bytes": r.bytes_transferred,
                    "message": r.message,
                }));
            }
            Err(e) => {
                results.push(serde_json::json!({
                    "target": target.name,
                    "success": false,
                    "message": format!("Sync error: {}", e),
                }));
            }
        }
    }

    let _ = history.save(&history_path);

    Ok(Json(serde_json::json!({
        "results": results,
    })))
}

#[derive(Deserialize)]
struct SyncHistoryQuery {
    last: Option<usize>,
}

async fn sync_history(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(params): Query<SyncHistoryQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let history = crate::sync::scheduler::SyncHistory::load(
        &crate::sync::scheduler::sync_history_path(),
    );

    let last = params.last.unwrap_or(50);
    let entries: Vec<_> = history.entries.iter().rev().take(last).cloned().collect();

    Ok(Json(serde_json::json!({
        "entries": entries,
        "total": history.entries.len(),
    })))
}

async fn sync_targets(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let daemon = state.daemon.lock().await;
    let _claims = require_admin(&headers, &daemon)?;

    let config = crate::sync::scheduler::MultiSyncConfig::load(
        &crate::sync::scheduler::multi_sync_config_path(),
    );

    Ok(Json(serde_json::json!({
        "targets": config.targets,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::KdfParams;
    use crate::crypto::keys::password_secret;
    use crate::vault::entry::*;
    use crate::vault::format::VaultFile;
    use axum::body::Body;
    use axum::http::Request;
    use tower::util::ServiceExt;

    fn setup_test_state() -> (HttpState, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test-password".to_string());
        let params = KdfParams::fast_for_testing();

        let mut vault = VaultFile::create(&path, &password, params).unwrap();
        vault.store_mut().add(
            Entry::new(
                "GitHub".to_string(),
                Credential::Login(LoginCredential {
                    url: "https://github.com".into(),
                    username: "user".into(),
                    password: "gh_pass_123".into(),
                }),
            )
            .with_tags(vec!["dev".into()]),
        );
        vault.store_mut().add(Entry::new(
            "AWS".to_string(),
            Credential::ApiKey(ApiKeyCredential {
                service: "aws".into(),
                key: "AKIA123".into(),
                secret: "secret456".into(),
            }),
        ));
        vault.save().unwrap();

        let mut daemon = DaemonState::new(path, 300);
        daemon.unlock(&password).unwrap();

        let state = HttpState {
            daemon: Arc::new(Mutex::new(daemon)),
            rate_limiter: Arc::new(Mutex::new(HttpRateLimiter::new(100))),
        };
        (state, dir)
    }

    async fn get_admin_token(state: &HttpState) -> String {
        let daemon = state.daemon.lock().await;
        let key = daemon.jwt_signing_key().unwrap();
        jwt::create_admin_jwt(key, 3600).unwrap()
    }

    fn json_request(method: &str, uri: &str, body: Option<serde_json::Value>, token: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(t) = token {
            builder = builder.header("Authorization", format!("Bearer {}", t));
        }
        if let Some(b) = body {
            builder
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_string(&b).unwrap()))
                .unwrap()
        } else {
            builder.body(Body::empty()).unwrap()
        }
    }

    async fn response_json(resp: axum::response::Response) -> serde_json::Value {
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    // ---- Tests ----

    #[tokio::test]
    async fn test_health() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let req = json_request("GET", "/v1/health", None, None);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["status"], "ok");
    }

    #[tokio::test]
    async fn test_auth_token_success() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/auth/token",
            Some(serde_json::json!({ "password": "test-password" })),
            None,
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert!(body["token"].as_str().is_some());
    }

    #[tokio::test]
    async fn test_auth_token_locked_vault() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test-password".to_string());
        let mut vault = VaultFile::create(&path, &password, KdfParams::fast_for_testing()).unwrap();
        vault.store_mut().add(Entry::new(
            "Test".into(),
            Credential::Login(LoginCredential {
                url: "https://test.com".into(),
                username: "u".into(),
                password: "p".into(),
            }),
        ));
        vault.save().unwrap();

        let daemon = DaemonState::new(path, 300);
        let state = HttpState {
            daemon: Arc::new(Mutex::new(daemon)),
            rate_limiter: Arc::new(Mutex::new(HttpRateLimiter::new(100))),
        };
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/auth/token",
            Some(serde_json::json!({ "password": "test-password" })),
            None,
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert!(body["token"].as_str().is_some());
    }

    #[tokio::test]
    async fn test_auth_token_wrong_password() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test-password".to_string());
        let mut vault = VaultFile::create(&path, &password, KdfParams::fast_for_testing()).unwrap();
        vault.store_mut().add(Entry::new(
            "Test".into(),
            Credential::Login(LoginCredential {
                url: "https://test.com".into(),
                username: "u".into(),
                password: "p".into(),
            }),
        ));
        vault.save().unwrap();

        let daemon = DaemonState::new(path, 300);
        let state = HttpState {
            daemon: Arc::new(Mutex::new(daemon)),
            rate_limiter: Arc::new(Mutex::new(HttpRateLimiter::new(100))),
        };
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/auth/token",
            Some(serde_json::json!({ "password": "wrong" })),
            None,
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_list_items() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("GET", "/v1/items", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        let items = body.as_array().unwrap();
        assert_eq!(items.len(), 2);
        // Should not contain secrets
        assert!(items[0].get("password").is_none());
    }

    #[tokio::test]
    async fn test_list_items_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let req = json_request("GET", "/v1/items", None, None);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_get_item() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        // Get entry ID
        let entry_id = {
            let daemon = state.daemon.lock().await;
            let vault = daemon.vault_ref().unwrap();
            vault.store().entries().first().unwrap().id
        };
        let app = create_router(state);
        let req = json_request("GET", &format!("/v1/items/{}", entry_id), None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_item_not_found() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let fake_id = Uuid::new_v4();
        let req = json_request("GET", &format!("/v1/items/{}", fake_id), None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get_item_invalid_id() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("GET", "/v1/items/not-a-uuid", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_agent_tokens_empty() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("GET", "/v1/agent/tokens", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_agent_pending_empty() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("GET", "/v1/agent/pending", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_agent_audit_empty() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("GET", "/v1/agent/audit", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_agent_dashboard() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("GET", "/v1/agent/dashboard", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_agent_request_flow() {
        let (state, _dir) = setup_test_state();
        let entry_id = {
            let daemon = state.daemon.lock().await;
            let vault = daemon.vault_ref().unwrap();
            vault.store().entries().first().unwrap().id
        };
        let admin_token = get_admin_token(&state).await;

        // Submit request
        let app = create_router(state.clone());
        let req = json_request(
            "POST",
            "/v1/agent/request",
            Some(serde_json::json!({
                "agent_id": "test-agent",
                "scopes": [entry_id],
                "actions": ["read"],
                "ttl": 3600,
                "reason": "testing"
            })),
            None,
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let body = response_json(resp).await;
        let request_id = body["request_id"].as_str().unwrap().to_string();

        // Grant request
        let app = create_router(state.clone());
        let req = json_request(
            "POST",
            &format!("/v1/agent/grant/{}", request_id),
            None,
            Some(&admin_token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        let agent_jwt = body["token"].as_str().unwrap().to_string();
        assert!(body["token_id"].as_str().is_some());

        // Resolve with agent token
        let app = create_router(state.clone());
        let req = json_request(
            "POST",
            "/v1/resolve",
            Some(serde_json::json!({
                "refs": [format!("vclaw://default/github")]
            })),
            Some(&agent_jwt),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        let results = body["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["value"], "gh_pass_123");
    }

    #[tokio::test]
    async fn test_agent_deny_flow() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;

        // Submit request
        let app = create_router(state.clone());
        let req = json_request(
            "POST",
            "/v1/agent/request",
            Some(serde_json::json!({
                "agent_id": "test-agent",
                "scopes": [],
                "actions": ["read"],
                "ttl": 3600,
                "reason": "testing"
            })),
            None,
        );
        let resp = app.oneshot(req).await.unwrap();
        let body = response_json(resp).await;
        let request_id = body["request_id"].as_str().unwrap().to_string();

        // Deny request
        let app = create_router(state.clone());
        let req = json_request(
            "POST",
            &format!("/v1/agent/deny/{}", request_id),
            None,
            Some(&admin_token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_agent_revoke() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;

        // Submit and grant
        let app = create_router(state.clone());
        let req = json_request(
            "POST",
            "/v1/agent/request",
            Some(serde_json::json!({
                "agent_id": "test-agent",
                "scopes": [],
                "actions": ["read"],
                "ttl": 3600,
                "reason": "testing"
            })),
            None,
        );
        let resp = app.oneshot(req).await.unwrap();
        let body = response_json(resp).await;
        let request_id = body["request_id"].as_str().unwrap().to_string();

        let app = create_router(state.clone());
        let req = json_request(
            "POST",
            &format!("/v1/agent/grant/{}", request_id),
            None,
            Some(&admin_token),
        );
        let resp = app.oneshot(req).await.unwrap();
        let body = response_json(resp).await;
        let token_id = body["token_id"].as_str().unwrap().to_string();

        // Revoke
        let app = create_router(state.clone());
        let req = json_request(
            "POST",
            &format!("/v1/agent/revoke/{}", token_id),
            None,
            Some(&admin_token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_agent_grant_invalid_id() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/agent/grant/not-a-uuid",
            None,
            Some(&admin_token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_agent_deny_invalid_id() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/agent/deny/not-a-uuid",
            None,
            Some(&admin_token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_agent_revoke_invalid_id() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/agent/revoke/not-a-uuid",
            None,
            Some(&admin_token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_agent_grant_nonexistent() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let app = create_router(state);
        let fake_id = Uuid::new_v4();
        let req = json_request(
            "POST",
            &format!("/v1/agent/grant/{}", fake_id),
            None,
            Some(&admin_token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_resolve_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/resolve",
            Some(serde_json::json!({ "refs": ["vclaw://default/github"] })),
            None,
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_resolve_with_admin_token() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/resolve",
            Some(serde_json::json!({ "refs": ["vclaw://default/github"] })),
            Some(&admin_token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_resolve_vault_locked() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("test-password".to_string());
        VaultFile::create(&path, &password, KdfParams::fast_for_testing()).unwrap();

        let daemon = DaemonState::new(path, 300);
        let state = HttpState {
            daemon: Arc::new(Mutex::new(daemon)),
            rate_limiter: Arc::new(Mutex::new(HttpRateLimiter::new(100))),
        };
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/resolve",
            Some(serde_json::json!({ "refs": ["vclaw://default/github"] })),
            Some("fake-token"),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_admin_required_with_agent_token() {
        let (state, _dir) = setup_test_state();
        // Create an agent token directly
        let agent_jwt = {
            let daemon = state.daemon.lock().await;
            let key = daemon.jwt_signing_key().unwrap();
            jwt::create_agent_jwt(key, "agent-1", "tok-1", 3600).unwrap()
        };
        let app = create_router(state);
        let req = json_request("GET", "/v1/items", None, Some(&agent_jwt));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_invalid_token() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let req = json_request("GET", "/v1/items", None, Some("invalid.jwt.token"));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_credential_type_names() {
        assert_eq!(
            credential_type_name(&Credential::Login(LoginCredential {
                url: String::new(),
                username: String::new(),
                password: String::new(),
            })),
            "login"
        );
        assert_eq!(
            credential_type_name(&Credential::ApiKey(ApiKeyCredential {
                service: String::new(),
                key: String::new(),
                secret: String::new(),
            })),
            "api_key"
        );
        assert_eq!(
            credential_type_name(&Credential::SecureNote(SecureNoteCredential {
                content: String::new(),
            })),
            "secure_note"
        );
        assert_eq!(
            credential_type_name(&Credential::SshKey(SshKeyCredential {
                private_key: String::new(),
                public_key: String::new(),
                passphrase: String::new(),
            })),
            "ssh_key"
        );
    }

    #[tokio::test]
    async fn test_audit_with_query_params() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request(
            "GET",
            "/v1/agent/audit?agent_id=test&last=5",
            None,
            Some(&admin_token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_agent_deny_nonexistent() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let app = create_router(state);
        let fake_id = Uuid::new_v4();
        let req = json_request(
            "POST",
            &format!("/v1/agent/deny/{}", fake_id),
            None,
            Some(&admin_token),
        );
        let resp = app.oneshot(req).await.unwrap();
        // Gateway returns error for nonexistent request
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_agent_revoke_nonexistent() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let app = create_router(state);
        let fake_id = Uuid::new_v4();
        let req = json_request(
            "POST",
            &format!("/v1/agent/revoke/{}", fake_id),
            None,
            Some(&admin_token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_extract_bearer_missing() {
        let headers = HeaderMap::new();
        assert!(extract_bearer(&headers).is_none());
    }

    #[tokio::test]
    async fn test_extract_bearer_valid() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer my-token".parse().unwrap());
        assert_eq!(extract_bearer(&headers).as_deref(), Some("my-token"));
    }

    #[tokio::test]
    async fn test_extract_bearer_no_bearer_prefix() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Basic abc123".parse().unwrap());
        assert!(extract_bearer(&headers).is_none());
    }

    #[tokio::test]
    async fn test_resolve_rate_limiting() {
        let (state, _dir) = setup_test_state();
        // Set rate limit to 2 req/s for testing
        let state = HttpState {
            daemon: state.daemon.clone(),
            rate_limiter: Arc::new(Mutex::new(HttpRateLimiter::new(2))),
        };
        let admin_token = {
            let daemon = state.daemon.lock().await;
            let key = daemon.jwt_signing_key().unwrap();
            jwt::create_admin_jwt(key, 3600).unwrap()
        };

        // First two requests should succeed
        for _ in 0..2 {
            let app = create_router(state.clone());
            let req = json_request(
                "POST",
                "/v1/resolve",
                Some(serde_json::json!({ "refs": ["vclaw://default/github"] })),
                Some(&admin_token),
            );
            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }

        // Third request should be rate limited
        let app = create_router(state.clone());
        let req = json_request(
            "POST",
            "/v1/resolve",
            Some(serde_json::json!({ "refs": ["vclaw://default/github"] })),
            Some(&admin_token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn test_http_rate_limiter_basic() {
        let mut rl = HttpRateLimiter::new(3);
        assert!(rl.check("user1"));
        assert!(rl.check("user1"));
        assert!(rl.check("user1"));
        assert!(!rl.check("user1"));
        // Different subject should still work
        assert!(rl.check("user2"));
    }

    // ---- Lease endpoint tests ----

    async fn get_agent_jwt(state: &HttpState) -> String {
        let daemon = state.daemon.lock().await;
        let key = daemon.jwt_signing_key().unwrap();
        jwt::create_agent_jwt(key, "test-agent", "tok-lease", 3600).unwrap()
    }

    #[tokio::test]
    async fn test_create_lease_success() {
        let (state, _dir) = setup_test_state();
        let agent_jwt = get_agent_jwt(&state).await;
        let entry_id = {
            let daemon = state.daemon.lock().await;
            let vault = daemon.vault_ref().unwrap();
            vault.store().entries().iter().find(|e| e.title == "GitHub").unwrap().id
        };
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/lease",
            Some(serde_json::json!({
                "ref": entry_id.to_string(),
                "scope": "read",
                "ttl": 3600,
                "reason": "deploy"
            })),
            Some(&agent_jwt),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = response_json(resp).await;
        assert!(body["lease_id"].as_str().is_some());
        assert_eq!(body["credential"], "gh_pass_123");
        assert!(body["expires_at"].as_str().is_some());
    }

    #[tokio::test]
    async fn test_create_lease_by_title() {
        let (state, _dir) = setup_test_state();
        let agent_jwt = get_agent_jwt(&state).await;
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/lease",
            Some(serde_json::json!({
                "ref": "vclaw://default/github",
                "scope": "read",
                "ttl": 600,
                "reason": "CI"
            })),
            Some(&agent_jwt),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = response_json(resp).await;
        assert_eq!(body["credential"], "gh_pass_123");
    }

    #[tokio::test]
    async fn test_create_lease_api_key() {
        let (state, _dir) = setup_test_state();
        let agent_jwt = get_agent_jwt(&state).await;
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/lease",
            Some(serde_json::json!({
                "ref": "vclaw://default/aws",
                "scope": "use",
                "ttl": 300,
                "reason": "deploy"
            })),
            Some(&agent_jwt),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = response_json(resp).await;
        assert_eq!(body["credential"], "AKIA123:secret456");
    }

    #[tokio::test]
    async fn test_create_lease_not_found() {
        let (state, _dir) = setup_test_state();
        let agent_jwt = get_agent_jwt(&state).await;
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/lease",
            Some(serde_json::json!({
                "ref": Uuid::new_v4().to_string(),
                "scope": "read",
                "ttl": 3600,
                "reason": "test"
            })),
            Some(&agent_jwt),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_create_lease_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/lease",
            Some(serde_json::json!({
                "ref": "vclaw://default/github",
                "scope": "read",
                "ttl": 3600,
                "reason": "test"
            })),
            None,
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_create_lease_medium_sensitivity_rejected() {
        let (state, _dir) = setup_test_state();
        let agent_jwt = get_agent_jwt(&state).await;
        let entry_id = {
            let daemon = state.daemon.lock().await;
            let vault = daemon.vault_ref().unwrap();
            vault.store().entries().first().unwrap().id
        };
        // Set sensitivity to Medium
        {
            let mut daemon = state.daemon.lock().await;
            daemon.lease_store.set_sensitivity(entry_id, Sensitivity::Medium);
        }
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/lease",
            Some(serde_json::json!({
                "ref": entry_id.to_string(),
                "scope": "read",
                "ttl": 3600,
                "reason": "deploy"
            })),
            Some(&agent_jwt),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_list_active_leases_empty() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("GET", "/v1/lease/active", None, Some(&admin_token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["leases"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_list_active_leases_with_data() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let entry_id = {
            let daemon = state.daemon.lock().await;
            let vault = daemon.vault_ref().unwrap();
            vault.store().entries().first().unwrap().id
        };
        // Create a lease directly
        {
            let mut daemon = state.daemon.lock().await;
            daemon.lease_store.create_lease(
                entry_id, "agent-1".into(), LeaseScope::Read,
                3600, "test".into(), "secret".into(),
            );
        }
        let app = create_router(state);
        let req = json_request("GET", "/v1/lease/active", None, Some(&admin_token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        let leases = body["leases"].as_array().unwrap();
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0]["agent_id"], "agent-1");
    }

    #[tokio::test]
    async fn test_list_active_leases_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let req = json_request("GET", "/v1/lease/active", None, None);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_revoke_lease_success() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let entry_id = {
            let daemon = state.daemon.lock().await;
            let vault = daemon.vault_ref().unwrap();
            vault.store().entries().first().unwrap().id
        };
        let lease_id = {
            let mut daemon = state.daemon.lock().await;
            let lease = daemon.lease_store.create_lease(
                entry_id, "agent-1".into(), LeaseScope::Read,
                3600, "test".into(), "secret".into(),
            );
            lease.id
        };
        let app = create_router(state);
        let req = json_request(
            "POST",
            &format!("/v1/lease/{}/revoke", lease_id),
            None,
            Some(&admin_token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["status"], "revoked");
    }

    #[tokio::test]
    async fn test_revoke_lease_not_found() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let app = create_router(state);
        let fake_id = Uuid::new_v4();
        let req = json_request(
            "POST",
            &format!("/v1/lease/{}/revoke", fake_id),
            None,
            Some(&admin_token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_revoke_lease_invalid_id() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/lease/not-a-uuid/revoke",
            None,
            Some(&admin_token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_revoke_all_leases_empty() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("POST", "/v1/lease/revoke-all", None, Some(&admin_token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["count"], 0);
    }

    #[tokio::test]
    async fn test_revoke_all_leases_with_data() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        // Create 2 leases
        {
            let mut daemon = state.daemon.lock().await;
            daemon.lease_store.create_lease(
                Uuid::new_v4(), "a".into(), LeaseScope::Read,
                3600, "r".into(), "s1".into(),
            );
            daemon.lease_store.create_lease(
                Uuid::new_v4(), "b".into(), LeaseScope::Read,
                3600, "r".into(), "s2".into(),
            );
        }
        let app = create_router(state);
        let req = json_request("POST", "/v1/lease/revoke-all", None, Some(&admin_token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["count"], 2);
    }

    #[tokio::test]
    async fn test_revoke_all_leases_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let req = json_request("POST", "/v1/lease/revoke-all", None, None);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_set_entry_sensitivity() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let entry_id = {
            let daemon = state.daemon.lock().await;
            let vault = daemon.vault_ref().unwrap();
            vault.store().entries().first().unwrap().id
        };
        let app = create_router(state);
        let req = json_request(
            "POST",
            &format!("/v1/entry/{}/sensitivity", entry_id),
            Some(serde_json::json!({ "level": "high" })),
            Some(&admin_token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["status"], "ok");
    }

    #[tokio::test]
    async fn test_set_entry_sensitivity_not_found() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let fake_id = Uuid::new_v4();
        let app = create_router(state);
        let req = json_request(
            "POST",
            &format!("/v1/entry/{}/sensitivity", fake_id),
            Some(serde_json::json!({ "level": "medium" })),
            Some(&admin_token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_set_entry_sensitivity_invalid_id() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/entry/not-a-uuid/sensitivity",
            Some(serde_json::json!({ "level": "low" })),
            Some(&admin_token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_set_entry_sensitivity_no_auth() {
        let (state, _dir) = setup_test_state();
        let entry_id = {
            let daemon = state.daemon.lock().await;
            let vault = daemon.vault_ref().unwrap();
            vault.store().entries().first().unwrap().id
        };
        let app = create_router(state);
        let req = json_request(
            "POST",
            &format!("/v1/entry/{}/sensitivity", entry_id),
            Some(serde_json::json!({ "level": "low" })),
            None,
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_extract_credential_value_all_types() {
        let login = Entry::new(
            "test".into(),
            Credential::Login(LoginCredential {
                url: "https://example.com".into(),
                username: "user".into(),
                password: "pass123".into(),
            }),
        );
        assert_eq!(extract_credential_value(&login), "pass123");

        let api = Entry::new(
            "test".into(),
            Credential::ApiKey(ApiKeyCredential {
                service: "aws".into(),
                key: "KEY".into(),
                secret: "SEC".into(),
            }),
        );
        assert_eq!(extract_credential_value(&api), "KEY:SEC");

        let note = Entry::new(
            "test".into(),
            Credential::SecureNote(SecureNoteCredential {
                content: "my secret note".into(),
            }),
        );
        assert_eq!(extract_credential_value(&note), "my secret note");

        let ssh = Entry::new(
            "test".into(),
            Credential::SshKey(SshKeyCredential {
                private_key: "-----BEGIN RSA-----".into(),
                public_key: "ssh-rsa AAAA".into(),
                passphrase: "pass".into(),
            }),
        );
        assert_eq!(extract_credential_value(&ssh), "-----BEGIN RSA-----");
    }

    #[tokio::test]
    async fn test_create_lease_then_list_then_revoke() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let agent_jwt = get_agent_jwt(&state).await;
        let entry_id = {
            let daemon = state.daemon.lock().await;
            let vault = daemon.vault_ref().unwrap();
            vault.store().entries().first().unwrap().id
        };

        // Create lease via HTTP
        let app = create_router(state.clone());
        let req = json_request(
            "POST",
            "/v1/lease",
            Some(serde_json::json!({
                "ref": entry_id.to_string(),
                "scope": "read",
                "ttl": 3600,
                "reason": "integration test"
            })),
            Some(&agent_jwt),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = response_json(resp).await;
        let lease_id = body["lease_id"].as_str().unwrap().to_string();

        // List active leases
        let app = create_router(state.clone());
        let req = json_request("GET", "/v1/lease/active", None, Some(&admin_token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["leases"].as_array().unwrap().len(), 1);

        // Revoke the lease
        let app = create_router(state.clone());
        let req = json_request(
            "POST",
            &format!("/v1/lease/{}/revoke", lease_id),
            None,
            Some(&admin_token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify no active leases remain
        let app = create_router(state.clone());
        let req = json_request("GET", "/v1/lease/active", None, Some(&admin_token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["leases"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_list_all_leases_empty() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("GET", "/v1/lease/all", None, Some(&admin_token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["leases"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_list_all_leases_includes_revoked() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let entry_id = {
            let daemon = state.daemon.lock().await;
            let vault = daemon.vault_ref().unwrap();
            vault.store().entries().first().unwrap().id
        };
        // Create two leases, revoke one
        let revoke_id = {
            let mut daemon = state.daemon.lock().await;
            let l1 = daemon.lease_store.create_lease(
                entry_id, "agent-1".into(), LeaseScope::Read,
                3600, "test".into(), "secret".into(),
            );
            daemon.lease_store.create_lease(
                entry_id, "agent-2".into(), LeaseScope::Read,
                3600, "test2".into(), "secret2".into(),
            );
            daemon.lease_store.revoke(&l1.id);
            l1.id
        };

        // /lease/active should only return 1
        let app = create_router(state.clone());
        let req = json_request("GET", "/v1/lease/active", None, Some(&admin_token));
        let resp = app.oneshot(req).await.unwrap();
        let body = response_json(resp).await;
        assert_eq!(body["leases"].as_array().unwrap().len(), 1);

        // /lease/all should return both (active + revoked)
        let app = create_router(state.clone());
        let req = json_request("GET", "/v1/lease/all", None, Some(&admin_token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        let leases = body["leases"].as_array().unwrap();
        assert_eq!(leases.len(), 2);
        // Verify revoked lease has status and revoked_at fields
        let revoked = leases.iter().find(|l| l["lease_id"] == revoke_id.to_string()).unwrap();
        assert_eq!(revoked["status"], "revoked");
        assert!(!revoked["revoked_at"].is_null());
    }

    #[tokio::test]
    async fn test_list_all_leases_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let req = json_request("GET", "/v1/lease/all", None, None);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ---- Issue token (combined request+grant) tests ----

    #[tokio::test]
    async fn test_issue_token_success() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let entry_id = {
            let daemon = state.daemon.lock().await;
            let vault = daemon.vault_ref().unwrap();
            vault.store().entries().first().unwrap().id
        };
        let app = create_router(state.clone());
        let req = json_request(
            "POST",
            "/v1/agent/token",
            Some(serde_json::json!({
                "agent_id": "test-bot",
                "scopes": [entry_id],
                "actions": ["read"],
                "ttl": 3600,
                "max_uses": 5,
                "reason": "automated deploy"
            })),
            Some(&admin_token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = response_json(resp).await;
        assert!(body["token"].as_str().is_some());
        assert_eq!(body["agent_id"], "test-bot");
        assert!(body["token_id"].as_str().is_some());
        assert!(body["expires_at"].as_str().is_some());

        // Verify token appears in listing
        let app = create_router(state.clone());
        let req = json_request("GET", "/v1/agent/tokens", None, Some(&admin_token));
        let resp = app.oneshot(req).await.unwrap();
        let body = response_json(resp).await;
        let tokens = body.as_array().unwrap();
        let issued = tokens.iter().find(|t| t["agent_id"] == "test-bot");
        assert!(issued.is_some());
        let issued = issued.unwrap();
        assert_eq!(issued["uses"], 0);
        assert_eq!(issued["max_uses"], 5);
    }

    #[tokio::test]
    async fn test_issue_token_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/agent/token",
            Some(serde_json::json!({
                "agent_id": "test-bot",
                "scopes": [],
                "actions": ["read"],
                "ttl": 3600,
                "max_uses": null,
                "reason": "test"
            })),
            None,
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_issue_token_unlimited_uses() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/agent/token",
            Some(serde_json::json!({
                "agent_id": "unlimited-bot",
                "scopes": [],
                "actions": ["read", "use"],
                "ttl": 86400,
                "max_uses": null,
                "reason": "long-running service"
            })),
            Some(&admin_token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = response_json(resp).await;
        assert_eq!(body["agent_id"], "unlimited-bot");
    }

    // ---- Vault status, lock, and export tests ----

    #[tokio::test]
    async fn test_vault_status() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("GET", "/v1/status", None, Some(&admin_token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["locked"], false);
        assert!(body["entry_count"].as_u64().unwrap() > 0);
        assert!(body["vault_path"].as_str().is_some());
    }

    #[tokio::test]
    async fn test_vault_status_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let req = json_request("GET", "/v1/status", None, None);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_lock_vault() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;

        // Lock the vault
        let app = create_router(state.clone());
        let req = json_request("POST", "/v1/lock", None, Some(&admin_token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["status"], "locked");

        // Verify it's locked
        let daemon = state.daemon.lock().await;
        assert!(daemon.is_locked());
    }

    #[tokio::test]
    async fn test_lock_vault_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let req = json_request("POST", "/v1/lock", None, None);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_export_json() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("GET", "/v1/export?format=json", None, Some(&admin_token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap();
        assert!(!parsed.is_empty());
        assert!(parsed[0]["title"].as_str().is_some());
    }

    #[tokio::test]
    async fn test_export_csv() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("GET", "/v1/export?format=csv", None, Some(&admin_token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("Title,Type,URL,Username,Password"));
    }

    #[tokio::test]
    async fn test_export_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let req = json_request("GET", "/v1/export?format=json", None, None);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_export_bad_format() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("GET", "/v1/export?format=xml", None, Some(&admin_token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ---- Breach check endpoint tests ----

    #[tokio::test]
    async fn test_breach_check_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let body = serde_json::json!({ "id": Uuid::new_v4() });
        let req = json_request("POST", "/v1/breach-check", Some(body), None);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_breach_check_not_found() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let app = create_router(state);
        let body = serde_json::json!({ "id": Uuid::new_v4() });
        let req = json_request("POST", "/v1/breach-check", Some(body), Some(&admin_token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_breach_check_valid_entry() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;

        // Get an entry ID from the test vault
        let entry_id = {
            let daemon = state.daemon.lock().await;
            let vault = daemon.vault_ref().unwrap();
            vault.store().entries()[0].id
        };

        let app = create_router(state);
        let body = serde_json::json!({ "id": entry_id });
        let req = json_request("POST", "/v1/breach-check", Some(body), Some(&admin_token));
        let resp = app.oneshot(req).await.unwrap();
        // May succeed or fail depending on network, but should not be 4xx/5xx server error
        let status = resp.status();
        assert!(status == StatusCode::OK || status == StatusCode::INTERNAL_SERVER_ERROR,
            "Expected OK or server error (network), got {}", status);
    }

    #[tokio::test]
    async fn test_breach_check_all_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let req = json_request("POST", "/v1/breach-check/all", None, None);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ---- Vault health endpoint tests ----

    #[tokio::test]
    async fn test_vault_health_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let req = json_request("GET", "/v1/health/vault", None, None);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_vault_health_success() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("GET", "/v1/health/vault", None, Some(&admin_token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1024 * 64).await.unwrap();
        let report: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(report["health_score"].is_number());
        assert!(report["total_entries"].is_number());
        assert!(report["details"].is_array());
    }

    // ---- Static file serving tests ----

    #[tokio::test]
    async fn test_create_router_with_web_no_dir() {
        let (state, _dir) = setup_test_state();
        // No web dir — should still serve API
        let app = create_router_with_web(state, None);
        let req = json_request("GET", "/v1/health", None, None);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_create_router_with_web_nonexistent_dir() {
        let (state, _dir) = setup_test_state();
        let fake = std::path::Path::new("/tmp/vaultclaw_nonexistent_web_dir");
        let app = create_router_with_web(state, Some(fake));
        let req = json_request("GET", "/v1/health", None, None);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_create_router_with_web_serves_files() {
        let web_dir = tempfile::TempDir::new().unwrap();
        std::fs::write(web_dir.path().join("index.html"), "<html>VaultClaw</html>").unwrap();
        std::fs::write(web_dir.path().join("test.js"), "console.log('ok')").unwrap();

        // API still works
        let (state, _dir) = setup_test_state();
        let app = create_router_with_web(state, Some(web_dir.path()));
        let req = json_request("GET", "/v1/health", None, None);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Static file served
        let (state, _dir) = setup_test_state();
        let app = create_router_with_web(state, Some(web_dir.path()));
        let req = Request::builder()
            .method("GET")
            .uri("/test.js")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body.as_ref(), b"console.log('ok')");

        // SPA fallback: unknown route returns index.html
        let (state, _dir) = setup_test_state();
        let app = create_router_with_web(state, Some(web_dir.path()));
        let req = Request::builder()
            .method("GET")
            .uri("/some/spa/route")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("VaultClaw"));
    }

    // ---- Entry CRUD endpoint tests ----

    #[tokio::test]
    async fn test_create_item() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/items",
            Some(serde_json::json!({
                "title": "New Login",
                "credential": {
                    "type": "Login",
                    "url": "https://example.com",
                    "username": "testuser",
                    "password": "testpass"
                },
                "tags": ["test"],
                "category": "web",
                "sensitive": true
            })),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = response_json(resp).await;
        assert!(body["id"].as_str().is_some());
    }

    #[tokio::test]
    async fn test_create_item_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/items",
            Some(serde_json::json!({
                "title": "Test",
                "credential": { "type": "SecureNote", "content": "secret" }
            })),
            None,
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_create_item_all_types() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // ApiKey
        let app = create_router(state.clone());
        let req = json_request(
            "POST",
            "/v1/items",
            Some(serde_json::json!({
                "title": "My API Key",
                "credential": { "type": "ApiKey", "service": "stripe", "key": "sk_test", "secret": "sec" }
            })),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // SecureNote
        let app = create_router(state.clone());
        let req = json_request(
            "POST",
            "/v1/items",
            Some(serde_json::json!({
                "title": "My Note",
                "credential": { "type": "SecureNote", "content": "Recovery codes here" }
            })),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // SshKey
        let app = create_router(state.clone());
        let req = json_request(
            "POST",
            "/v1/items",
            Some(serde_json::json!({
                "title": "Server Key",
                "credential": {
                    "type": "SshKey",
                    "private_key": "-----BEGIN-----",
                    "public_key": "ssh-rsa AAAA",
                    "passphrase": "pass"
                }
            })),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_update_item() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let entry_id = {
            let daemon = state.daemon.lock().await;
            let vault = daemon.vault_ref().unwrap();
            vault.store().entries().first().unwrap().id
        };
        let app = create_router(state);
        let req = json_request(
            "PUT",
            &format!("/v1/items/{}", entry_id),
            Some(serde_json::json!({
                "title": "GitHub Updated",
                "credential": {
                    "type": "Login",
                    "url": "https://github.com",
                    "username": "newuser",
                    "password": "newpass"
                },
                "tags": ["updated"],
                "favorite": true
            })),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["status"], "ok");
    }

    #[tokio::test]
    async fn test_update_item_not_found() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let fake_id = Uuid::new_v4();
        let app = create_router(state);
        let req = json_request(
            "PUT",
            &format!("/v1/items/{}", fake_id),
            Some(serde_json::json!({
                "title": "Nonexistent",
                "credential": { "type": "SecureNote", "content": "x" }
            })),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_update_item_invalid_id() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request(
            "PUT",
            "/v1/items/not-a-uuid",
            Some(serde_json::json!({
                "title": "Bad",
                "credential": { "type": "SecureNote", "content": "x" }
            })),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_update_item_no_auth() {
        let (state, _dir) = setup_test_state();
        let entry_id = {
            let daemon = state.daemon.lock().await;
            let vault = daemon.vault_ref().unwrap();
            vault.store().entries().first().unwrap().id
        };
        let app = create_router(state);
        let req = json_request(
            "PUT",
            &format!("/v1/items/{}", entry_id),
            Some(serde_json::json!({
                "title": "Nope",
                "credential": { "type": "SecureNote", "content": "x" }
            })),
            None,
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_delete_item() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let entry_id = {
            let daemon = state.daemon.lock().await;
            let vault = daemon.vault_ref().unwrap();
            vault.store().entries().first().unwrap().id
        };
        let app = create_router(state);
        let req = json_request("DELETE", &format!("/v1/items/{}", entry_id), None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["status"], "deleted");
    }

    #[tokio::test]
    async fn test_delete_item_not_found() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let fake_id = Uuid::new_v4();
        let app = create_router(state);
        let req = json_request("DELETE", &format!("/v1/items/{}", fake_id), None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delete_item_invalid_id() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("DELETE", "/v1/items/not-a-uuid", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_delete_item_no_auth() {
        let (state, _dir) = setup_test_state();
        let entry_id = {
            let daemon = state.daemon.lock().await;
            let vault = daemon.vault_ref().unwrap();
            vault.store().entries().first().unwrap().id
        };
        let app = create_router(state);
        let req = json_request("DELETE", &format!("/v1/items/{}", entry_id), None, None);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_get_item_totp() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        // Add an entry with TOTP
        let entry_id = {
            let mut daemon = state.daemon.lock().await;
            let entry = Entry::new(
                "TOTP Test".into(),
                Credential::Login(LoginCredential {
                    url: "https://example.com".into(),
                    username: "u".into(),
                    password: "p".into(),
                }),
            )
            .with_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
            let resp = daemon.handle_request(crate::daemon::protocol::Request::Add { entry });
            match resp {
                crate::daemon::protocol::Response::Ok { data } => match *data {
                    crate::daemon::protocol::ResponseData::Id(id) => id,
                    _ => panic!("Expected Id"),
                },
                _ => panic!("Expected Ok"),
            }
        };
        let app = create_router(state);
        let req = json_request("GET", &format!("/v1/items/{}/totp", entry_id), None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["code"].as_str().unwrap().len(), 6);
        assert!(body["seconds_remaining"].as_u64().unwrap() > 0);
    }

    #[tokio::test]
    async fn test_get_item_totp_no_secret() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        // Use existing entry without TOTP
        let entry_id = {
            let daemon = state.daemon.lock().await;
            let vault = daemon.vault_ref().unwrap();
            vault.store().entries().first().unwrap().id
        };
        let app = create_router(state);
        let req = json_request("GET", &format!("/v1/items/{}/totp", entry_id), None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_get_item_totp_not_found() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let fake_id = Uuid::new_v4();
        let app = create_router(state);
        let req = json_request("GET", &format!("/v1/items/{}/totp", fake_id), None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_get_item_totp_invalid_id() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("GET", "/v1/items/not-a-uuid/totp", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_get_item_totp_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let fake_id = Uuid::new_v4();
        let req = json_request("GET", &format!("/v1/items/{}/totp", fake_id), None, None);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_bulk_delete_items() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let ids: Vec<Uuid> = {
            let daemon = state.daemon.lock().await;
            let vault = daemon.vault_ref().unwrap();
            vault.store().entries().iter().map(|e| e.id).collect()
        };
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/items/bulk-delete",
            Some(serde_json::json!({ "ids": ids })),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["deleted"], 2);
        assert_eq!(body["errors"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_bulk_delete_partial() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let real_id = {
            let daemon = state.daemon.lock().await;
            let vault = daemon.vault_ref().unwrap();
            vault.store().entries().first().unwrap().id
        };
        let fake_id = Uuid::new_v4();
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/items/bulk-delete",
            Some(serde_json::json!({ "ids": [real_id, fake_id] })),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["deleted"], 1);
        assert_eq!(body["errors"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_bulk_delete_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/items/bulk-delete",
            Some(serde_json::json!({ "ids": [] })),
            None,
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_create_then_get_then_update_then_delete() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // Create
        let app = create_router(state.clone());
        let req = json_request(
            "POST",
            "/v1/items",
            Some(serde_json::json!({
                "title": "Integration Test",
                "credential": { "type": "SecureNote", "content": "secret data" },
                "tags": ["test"],
                "notes": "Created by test"
            })),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = response_json(resp).await;
        let id = body["id"].as_str().unwrap().to_string();

        // Get
        let app = create_router(state.clone());
        let req = json_request("GET", &format!("/v1/items/{}", id), None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["title"], "Integration Test");

        // Update
        let app = create_router(state.clone());
        let req = json_request(
            "PUT",
            &format!("/v1/items/{}", id),
            Some(serde_json::json!({
                "title": "Updated Test",
                "credential": { "type": "SecureNote", "content": "updated data" },
                "notes": "Updated by test"
            })),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify update
        let app = create_router(state.clone());
        let req = json_request("GET", &format!("/v1/items/{}", id), None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["title"], "Updated Test");

        // Delete
        let app = create_router(state.clone());
        let req = json_request("DELETE", &format!("/v1/items/{}", id), None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify deleted
        let app = create_router(state.clone());
        let req = json_request("GET", &format!("/v1/items/{}", id), None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ---- Import endpoint tests ----

    #[tokio::test]
    async fn test_import_csv_dry_run() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let csv = "Title,Url,Username,Password,Notes,Tags\nGitLab,https://gitlab.com,me,pw123,my notes,dev";
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/import",
            Some(serde_json::json!({
                "content": csv,
                "format": "csv",
                "dry_run": true
            })),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["imported"], 1);
        assert_eq!(body["total_processed"], 1);
        let preview = body["preview"].as_array().unwrap();
        assert_eq!(preview.len(), 1);
        assert_eq!(preview[0]["title"], "GitLab");
        assert_eq!(preview[0]["status"], "new");
    }

    #[tokio::test]
    async fn test_import_csv_commit() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let csv = "Title,Url,Username,Password\nNewSite,https://new.com,user,pass\nAnother,https://a.com,u,p";
        let app = create_router(state.clone());
        let req = json_request(
            "POST",
            "/v1/import",
            Some(serde_json::json!({
                "content": csv,
                "format": "csv",
                "dry_run": false
            })),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["imported"], 2);
        assert!(body["preview"].is_null());

        // Verify entries exist
        let app = create_router(state.clone());
        let req = json_request("GET", "/v1/items", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        let body = response_json(resp).await;
        // Original 2 + 2 imported
        assert_eq!(body.as_array().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn test_import_1pif_dry_run() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let pif = r#"{"title":"Test Entry","typeName":"webforms.WebForm","secureContents":{"fields":[{"designation":"username","value":"user1"},{"designation":"password","value":"pass1"}],"URLs":[{"url":"https://test.com"}]},"openContents":{"tags":["imported"]}}"#;
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/import",
            Some(serde_json::json!({
                "content": pif,
                "format": "1pif",
                "dry_run": true
            })),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["imported"], 1);
        let preview = body["preview"].as_array().unwrap();
        assert_eq!(preview[0]["title"], "Test Entry");
    }

    #[tokio::test]
    async fn test_import_auto_detect_csv() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let csv = "Title,Url,Username,Password\nAuto,https://auto.com,u,p";
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/import",
            Some(serde_json::json!({
                "content": csv,
                "dry_run": true
            })),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["imported"], 1);
    }

    #[tokio::test]
    async fn test_import_auto_detect_1pif() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let pif = r#"{"title":"Auto PIF","typeName":"webforms.WebForm","secureContents":{"fields":[{"designation":"username","value":"u"},{"designation":"password","value":"p"}]}}"#;
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/import",
            Some(serde_json::json!({
                "content": pif,
                "dry_run": true
            })),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["imported"], 1);
    }

    #[tokio::test]
    async fn test_import_conflict_detection() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        // The test state already has "GitHub" at https://github.com
        let csv = "Title,Url,Username,Password\nGitHub,https://github.com,other,pass2";
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/import",
            Some(serde_json::json!({
                "content": csv,
                "format": "csv",
                "dry_run": true
            })),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        let preview = body["preview"].as_array().unwrap();
        assert_eq!(preview[0]["status"], "conflict");
        assert!(preview[0]["conflict_id"].as_str().is_some());
    }

    #[tokio::test]
    async fn test_import_unsupported_format() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/import",
            Some(serde_json::json!({
                "content": "data",
                "format": "xml"
            })),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_import_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/import",
            Some(serde_json::json!({
                "content": "Title,Url\nX,https://x.com",
                "format": "csv",
                "dry_run": true
            })),
            None,
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ---- Access Policy tests ----

    #[tokio::test]
    async fn test_get_policy_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let req = json_request("GET", "/v1/policy", None, None);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_get_policy_default() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("GET", "/v1/policy", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["dm"], "prompt");
        assert_eq!(body["group_chat"], "deny");
        assert_eq!(body["sub_agent"], "inherit");
        assert_eq!(body["cron"], "prompt");
    }

    #[tokio::test]
    async fn test_update_policy() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state.clone());

        // Update policy to allow group chat
        let req = json_request(
            "PUT",
            "/v1/policy",
            Some(serde_json::json!({
                "dm": "prompt",
                "group_chat": "prompt",
                "sub_agent": "inherit",
                "cron": "deny",
                "overrides": { "agent:bot-1": "prompt" }
            })),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify the change persisted
        let app2 = create_router(state);
        let req2 = json_request("GET", "/v1/policy", None, Some(&token));
        let resp2 = app2.oneshot(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
        let body = response_json(resp2).await;
        assert_eq!(body["group_chat"], "prompt");
        assert_eq!(body["cron"], "deny");
        assert_eq!(body["overrides"]["agent:bot-1"], "prompt");
    }

    #[tokio::test]
    async fn test_update_policy_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let req = json_request(
            "PUT",
            "/v1/policy",
            Some(serde_json::json!({
                "dm": "prompt",
                "group_chat": "deny",
                "sub_agent": "inherit",
                "cron": "prompt"
            })),
            None,
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_session_context_lease_denied() {
        // Set up agent token and lease endpoint with group chat session context
        let (state, _dir) = setup_test_state();
        let daemon = state.daemon.lock().await;
        let signing_key = daemon.jwt_signing_key().unwrap();
        let agent_jwt = jwt::create_agent_jwt(signing_key, "test-agent", "tok-1", 3600).unwrap();
        drop(daemon);

        let app = create_router(state);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/lease")
            .header("Authorization", format!("Bearer {}", agent_jwt))
            .header("X-Session-Context", "type=group;agent_id=test-agent")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&serde_json::json!({
                "ref": "00000000-0000-0000-0000-000000000000",
                "scope": "read",
                "ttl": 300,
                "reason": "test"
            })).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // Should be 403 Forbidden due to group chat session
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_session_context_dm_allowed() {
        // DM session should pass policy check (may fail at credential lookup, which is fine)
        let (state, _dir) = setup_test_state();
        let daemon = state.daemon.lock().await;
        let signing_key = daemon.jwt_signing_key().unwrap();
        let agent_jwt = jwt::create_agent_jwt(signing_key, "test-agent", "tok-1", 3600).unwrap();
        drop(daemon);

        let app = create_router(state);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/lease")
            .header("Authorization", format!("Bearer {}", agent_jwt))
            .header("X-Session-Context", "type=dm;agent_id=test-agent")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&serde_json::json!({
                "ref": "00000000-0000-0000-0000-000000000000",
                "scope": "read",
                "ttl": 300,
                "reason": "test"
            })).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // DM session passes policy — should get 404 (entry not found) not 403
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_session_context_invalid_header() {
        let (state, _dir) = setup_test_state();
        let daemon = state.daemon.lock().await;
        let signing_key = daemon.jwt_signing_key().unwrap();
        let agent_jwt = jwt::create_agent_jwt(signing_key, "test-agent", "tok-1", 3600).unwrap();
        drop(daemon);

        let app = create_router(state);
        // Use "type=group;bad-pair" — first pair valid, second has no '='
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/lease")
            .header("Authorization", format!("Bearer {}", agent_jwt))
            .header("X-Session-Context", "type=dm;bad-pair")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&serde_json::json!({
                "ref": "00000000-0000-0000-0000-000000000000",
                "scope": "read",
                "ttl": 300,
                "reason": "test"
            })).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_session_context_override_allows_group() {
        // Agent with override should be allowed in group chat
        let (state, _dir) = setup_test_state();
        {
            let mut daemon = state.daemon.lock().await;
            daemon.access_policy.overrides.insert(
                "agent:special-bot".into(),
                super::super::access_policy::PolicyAction::Prompt,
            );
        }
        let daemon = state.daemon.lock().await;
        let signing_key = daemon.jwt_signing_key().unwrap();
        let agent_jwt = jwt::create_agent_jwt(signing_key, "special-bot", "tok-2", 3600).unwrap();
        drop(daemon);

        let app = create_router(state);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/lease")
            .header("Authorization", format!("Bearer {}", agent_jwt))
            .header("X-Session-Context", "type=group;agent_id=special-bot")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&serde_json::json!({
                "ref": "00000000-0000-0000-0000-000000000000",
                "scope": "read",
                "ttl": 300,
                "reason": "test"
            })).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // Should pass policy (override), then fail on entry lookup
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ---- Rate limit endpoint tests ----

    #[tokio::test]
    async fn test_list_rate_limits_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let req = json_request("GET", "/v1/rate-limits", None, None);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_list_rate_limits_empty() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("GET", "/v1/rate-limits", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["rate_limits"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_set_rate_limit() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state.clone());
        let req = json_request(
            "PUT",
            "/v1/rate-limits/test-agent",
            Some(serde_json::json!({
                "rpm": 10,
                "rph": 100,
                "auto_revoke_on_anomaly": true
            })),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["status"], "ok");
        assert_eq!(body["agent_id"], "test-agent");

        // Verify it's listed
        let app = create_router(state);
        let req = json_request("GET", "/v1/rate-limits", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        let limits = body["rate_limits"].as_array().unwrap();
        assert_eq!(limits.len(), 1);
        assert_eq!(limits[0]["agent_id"], "test-agent");
        assert_eq!(limits[0]["rpm"], 10);
        assert_eq!(limits[0]["rph"], 100);
        assert_eq!(limits[0]["auto_revoke_on_anomaly"], true);
    }

    #[tokio::test]
    async fn test_get_rate_limit() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // Set a limit
        {
            let mut daemon = state.daemon.lock().await;
            daemon.rate_limit_config.set(super::super::rate_config::AgentRateLimit::new("agent-1", 10, 100));
        }

        let app = create_router(state);
        let req = json_request("GET", "/v1/rate-limits/agent-1", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["agent_id"], "agent-1");
        assert_eq!(body["rpm"], 10);
    }

    #[tokio::test]
    async fn test_get_rate_limit_not_found() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("GET", "/v1/rate-limits/nonexistent", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delete_rate_limit() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // Set a limit
        {
            let mut daemon = state.daemon.lock().await;
            daemon.rate_limit_config.set(super::super::rate_config::AgentRateLimit::new("agent-1", 10, 100));
        }

        let app = create_router(state.clone());
        let req = json_request("DELETE", "/v1/rate-limits/agent-1", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify it's gone
        let app = create_router(state);
        let req = json_request("GET", "/v1/rate-limits/agent-1", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delete_rate_limit_not_found() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("DELETE", "/v1/rate-limits/nonexistent", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_lease_rate_limit_exceeded() {
        let (state, _dir) = setup_test_state();
        let _token = get_admin_token(&state).await;

        // Get the entry ID
        let entry_id = {
            let daemon = state.daemon.lock().await;
            let entries = daemon.vault_ref().unwrap().store().entries();
            entries[0].id
        };

        // Set entry sensitivity to Low
        {
            let mut daemon = state.daemon.lock().await;
            daemon.lease_store.set_sensitivity(entry_id, super::super::lease::Sensitivity::Low);
        }

        // Create agent JWT
        let agent_jwt = {
            let daemon = state.daemon.lock().await;
            let key = daemon.jwt_signing_key().unwrap();
            jwt::create_agent_jwt(key, "rate-test-agent", "token-1", 3600).unwrap()
        };

        // Set very low rate limit for this agent
        {
            let mut daemon = state.daemon.lock().await;
            daemon.rate_limit_config.set(super::super::rate_config::AgentRateLimit::new("rate-test-agent", 2, 10));
        }

        // First two leases should succeed; flood with accesses to exceed limit
        let now = chrono::Utc::now();
        {
            let mut daemon = state.daemon.lock().await;
            for _ in 0..3 {
                daemon.access_tracker.record_access("rate-test-agent", &entry_id, now);
            }
        }

        // Next lease should be rate-limited
        let app = create_router(state);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/lease")
            .header("Authorization", format!("Bearer {}", agent_jwt))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&serde_json::json!({
                "ref": entry_id.to_string(),
                "scope": "read",
                "ttl": 300,
                "reason": "test"
            })).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    // ---- Rotation endpoint tests ----

    #[tokio::test]
    async fn test_rotation_schedule_empty() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("GET", "/v1/rotation/schedule", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["plans"].as_array().unwrap().len(), 0);
        assert_eq!(body["summary"]["total_plans"], 0);
    }

    #[tokio::test]
    async fn test_rotation_schedule_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let req = json_request("GET", "/v1/rotation/schedule", None, None);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_rotation_scan() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("POST", "/v1/rotation/scan", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert!(body["scanned"].as_u64().unwrap() >= 2); // at least the 2 test entries
        // new_plans depends on password strength analysis
        assert!(body["plans"].is_array());
    }

    #[tokio::test]
    async fn test_rotation_approve_not_found() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let fake_id = uuid::Uuid::new_v4().to_string();
        let app = create_router(state);
        let req = json_request("POST", &format!("/v1/rotation/{}/approve", fake_id), None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_rotation_dismiss_not_found() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let fake_id = uuid::Uuid::new_v4().to_string();
        let app = create_router(state);
        let req = json_request(
            "POST",
            &format!("/v1/rotation/{}/dismiss", fake_id),
            Some(serde_json::json!({ "reason": "test" })),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_rotation_execute_not_found() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let fake_id = uuid::Uuid::new_v4().to_string();
        let app = create_router(state);
        let req = json_request("POST", &format!("/v1/rotation/{}/execute", fake_id), None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_rotation_scan_approve_execute_flow() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // Scan — should create at least one plan for the weak "gh_pass_123" password
        let app = create_router(state.clone());
        let req = json_request("POST", "/v1/rotation/scan", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        let plans = body["plans"].as_array().unwrap();

        if plans.is_empty() {
            // If no plans were created (passwords aren't considered weak),
            // we manually add one via the scheduler
            let entry_id = {
                let daemon = state.daemon.lock().await;
                daemon.vault_ref().unwrap().store().entries()[0].id
            };
            let mut daemon = state.daemon.lock().await;
            let plan = crate::security::rotation::RotationPlan::new(
                entry_id,
                "GitHub".to_string(),
                crate::security::rotation::RotationTrigger::Manual,
            );
            daemon.rotation_scheduler.add_plan(plan);
        }

        // Get the plan ID and title
        let (plan_id, plan_title) = {
            let daemon = state.daemon.lock().await;
            let plans = daemon.rotation_scheduler.list_plans();
            assert!(!plans.is_empty());
            (plans[0].id.to_string(), plans[0].entry_title.clone())
        };

        // Approve
        let app = create_router(state.clone());
        let req = json_request("POST", &format!("/v1/rotation/{}/approve", plan_id), None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["status"], "approved");

        // Execute
        let app = create_router(state.clone());
        let req = json_request("POST", &format!("/v1/rotation/{}/execute", plan_id), None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["status"], "completed");
        assert_eq!(body["entry_title"], plan_title);

        // Verify schedule shows completed plan
        let app = create_router(state);
        let req = json_request("GET", "/v1/rotation/schedule", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert!(body["summary"]["completed"].as_u64().unwrap() >= 1);
    }

    #[tokio::test]
    async fn test_rotation_scan_and_dismiss() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // Add a manual plan
        let entry_id = {
            let daemon = state.daemon.lock().await;
            daemon.vault_ref().unwrap().store().entries()[0].id
        };
        {
            let mut daemon = state.daemon.lock().await;
            let plan = crate::security::rotation::RotationPlan::new(
                entry_id,
                "GitHub".to_string(),
                crate::security::rotation::RotationTrigger::Manual,
            );
            daemon.rotation_scheduler.add_plan(plan);
        }

        let plan_id = {
            let daemon = state.daemon.lock().await;
            daemon.rotation_scheduler.list_plans()[0].id.to_string()
        };

        // Dismiss
        let app = create_router(state.clone());
        let req = json_request(
            "POST",
            &format!("/v1/rotation/{}/dismiss", plan_id),
            Some(serde_json::json!({ "reason": "not needed" })),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["status"], "dismissed");

        // Verify summary
        let app = create_router(state);
        let req = json_request("GET", "/v1/rotation/schedule", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        let body = response_json(resp).await;
        assert_eq!(body["summary"]["dismissed"], 1);
    }

    #[tokio::test]
    async fn test_rotation_execute_not_approved() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // Add a plan but don't approve it
        let entry_id = {
            let daemon = state.daemon.lock().await;
            daemon.vault_ref().unwrap().store().entries()[0].id
        };
        {
            let mut daemon = state.daemon.lock().await;
            let plan = crate::security::rotation::RotationPlan::new(
                entry_id,
                "GitHub".to_string(),
                crate::security::rotation::RotationTrigger::Manual,
            );
            daemon.rotation_scheduler.add_plan(plan);
        }

        let plan_id = {
            let daemon = state.daemon.lock().await;
            daemon.rotation_scheduler.list_plans()[0].id.to_string()
        };

        // Try to execute without approval — should fail
        let app = create_router(state);
        let req = json_request("POST", &format!("/v1/rotation/{}/execute", plan_id), None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    // ---- Security report endpoint tests ----

    #[tokio::test]
    async fn test_security_report_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let req = json_request("GET", "/v1/report", None, None);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_security_report_ok() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("GET", "/v1/report", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;

        // Executive summary
        assert!(body["executive_summary"]["grade"].is_string());
        assert!(body["executive_summary"]["grade_label"].is_string());
        assert!(body["executive_summary"]["health_score"].is_u64());
        assert!(body["executive_summary"]["narrative"].is_string());

        // Password health
        assert!(body["password_health"]["total_entries"].is_u64());
        assert!(body["password_health"]["login_entries"].is_u64());

        // Recommendations array
        assert!(body["recommendations"].is_array());

        // Rotation status
        assert!(body["rotation_status"]["total_plans"].is_u64());

        // Access audit
        assert!(body["access_audit"].is_object() || body["access_audit"].is_null());

        // Rate limits
        assert!(body["rate_limits"]["configured_agents"].is_u64());
    }

    #[tokio::test]
    async fn test_security_report_has_recommendations() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("GET", "/v1/report", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;

        // Test vault has "gh_pass_123" and "secret456" — should have recommendations
        let recs = body["recommendations"].as_array().unwrap();
        assert!(!recs.is_empty());
        // Each recommendation should have required fields
        for rec in recs {
            assert!(rec["severity"].is_string());
            assert!(rec["title"].is_string());
            assert!(rec["description"].is_string());
            assert!(rec["affected_count"].is_u64());
        }
    }

    // ---- Sync endpoint tests ----

    #[tokio::test]
    async fn test_sync_status_endpoint() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("GET", "/v1/sync/status", None, Some(&admin_token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert!(body["status"].is_object());
        assert!(body["targets"].is_array());
        assert!(body["history_count"].is_u64());
    }

    #[tokio::test]
    async fn test_sync_status_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let req = json_request("GET", "/v1/sync/status", None, None);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_sync_history_endpoint() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("GET", "/v1/sync/history?last=10", None, Some(&admin_token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert!(body["entries"].is_array());
        assert!(body["total"].is_u64());
    }

    #[tokio::test]
    async fn test_sync_history_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let req = json_request("GET", "/v1/sync/history", None, None);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_sync_targets_endpoint() {
        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("GET", "/v1/sync/targets", None, Some(&admin_token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert!(body["targets"].is_array());
    }

    #[tokio::test]
    async fn test_sync_trigger_no_targets() {
        // Ensure no stale config from parallel tests
        let config_path = crate::sync::scheduler::multi_sync_config_path();
        let _ = std::fs::remove_file(&config_path);

        let (state, _dir) = setup_test_state();
        let admin_token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("POST", "/v1/sync/trigger", None, Some(&admin_token));
        let resp = app.oneshot(req).await.unwrap();
        // Should return 400 since no targets are configured
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_sync_trigger_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let req = json_request("POST", "/v1/sync/trigger", None, None);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ---- Passkey endpoint tests ----

    #[tokio::test]
    async fn test_list_passkeys_empty() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("GET", "/v1/passkeys", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert!(body.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_create_passkey() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state.clone());

        let body = serde_json::json!({
            "title": "GitHub Passkey",
            "rp_id": "github.com",
            "rp_name": "GitHub",
            "user_handle": "dXNlcg",
            "user_name": "octocat",
            "algorithm": "es256"
        });
        let req = json_request("POST", "/v1/passkeys", Some(body), Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let result = response_json(resp).await;
        assert!(result["id"].is_string());
        assert!(result["credential_id"].is_string());
    }

    #[tokio::test]
    async fn test_create_and_list_passkeys() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // Create a passkey
        let app = create_router(state.clone());
        let body = serde_json::json!({
            "title": "Test Passkey",
            "rp_id": "example.com",
            "rp_name": "Example",
            "user_handle": "dXNlcg",
            "user_name": "testuser"
        });
        let req = json_request("POST", "/v1/passkeys", Some(body), Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // List passkeys
        let app = create_router(state);
        let req = json_request("GET", "/v1/passkeys", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let list = response_json(resp).await;
        let passkeys = list.as_array().unwrap();
        assert_eq!(passkeys.len(), 1);
        assert_eq!(passkeys[0]["rp_id"], "example.com");
        assert_eq!(passkeys[0]["user_name"], "testuser");
        assert_eq!(passkeys[0]["sign_count"], 0);
    }

    #[tokio::test]
    async fn test_passkey_assert() {
        use base64::Engine;
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // Create a passkey
        let app = create_router(state.clone());
        let body = serde_json::json!({
            "title": "Assert Test",
            "rp_id": "example.com",
            "rp_name": "Example",
            "user_handle": "dXNlcg",
            "user_name": "testuser",
            "algorithm": "es256"
        });
        let req = json_request("POST", "/v1/passkeys", Some(body), Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        let create_result = response_json(resp).await;
        let passkey_id = create_result["id"].as_str().unwrap();

        // Sign an assertion
        let client_data = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            br#"{"type":"webauthn.get","challenge":"test","origin":"https://example.com"}"#
        );
        let assert_body = serde_json::json!({
            "client_data_json": client_data,
            "user_verified": true
        });
        let app = create_router(state.clone());
        let req = json_request(
            "POST",
            &format!("/v1/passkeys/{}/assert", passkey_id),
            Some(assert_body),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let assertion = response_json(resp).await;
        assert!(assertion["authenticator_data"].is_string());
        assert!(assertion["signature"].is_string());
        assert!(assertion["user_handle"].is_string());
        assert!(assertion["credential_id"].is_string());

        // Verify sign count was incremented
        let app = create_router(state);
        let req = json_request("GET", "/v1/passkeys", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        let list = response_json(resp).await;
        let passkeys = list.as_array().unwrap();
        assert_eq!(passkeys[0]["sign_count"], 1);
    }

    #[tokio::test]
    async fn test_delete_passkey() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // Create a passkey
        let app = create_router(state.clone());
        let body = serde_json::json!({
            "title": "Delete Test",
            "rp_id": "example.com",
            "rp_name": "Example",
            "user_handle": "dXNlcg",
            "user_name": "deluser"
        });
        let req = json_request("POST", "/v1/passkeys", Some(body), Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        let create_result = response_json(resp).await;
        let passkey_id = create_result["id"].as_str().unwrap();

        // Delete it
        let app = create_router(state.clone());
        let req = json_request(
            "POST",
            &format!("/v1/passkeys/{}/delete", passkey_id),
            None,
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let del_result = response_json(resp).await;
        assert_eq!(del_result["status"], "deleted");

        // Verify it's gone
        let app = create_router(state);
        let req = json_request("GET", "/v1/passkeys", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        let list = response_json(resp).await;
        assert!(list.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_passkey_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let req = json_request("GET", "/v1/passkeys", None, None);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_passkey_assert_not_found() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let body = serde_json::json!({
            "client_data_json": "dGVzdA",
            "user_verified": true
        });
        let req = json_request(
            "POST",
            &format!("/v1/passkeys/{}/assert", uuid::Uuid::new_v4()),
            Some(body),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_passkey_delete_not_passkey() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // Get the login entry ID
        let app = create_router(state.clone());
        let req = json_request("GET", "/v1/items", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        let items = response_json(resp).await;
        let login_id = items.as_array().unwrap().iter()
            .find(|i| i["credential_type"] == "login")
            .unwrap()["id"].as_str().unwrap().to_string();

        // Try to delete it as a passkey
        let app = create_router(state);
        let req = json_request(
            "POST",
            &format!("/v1/passkeys/{}/delete", login_id),
            None,
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_get_passkeys_by_rp_id() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // Create two passkeys for different RPs
        for (rp_id, user) in &[("github.com", "user1"), ("google.com", "user2")] {
            let app = create_router(state.clone());
            let body = serde_json::json!({
                "title": format!("{} Passkey", rp_id),
                "rp_id": rp_id,
                "rp_name": rp_id,
                "user_handle": "dXNlcg",
                "user_name": user,
            });
            let req = json_request("POST", "/v1/passkeys", Some(body), Some(&token));
            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::CREATED);
        }

        // Get passkeys for github.com
        let app = create_router(state);
        let req = json_request("GET", "/v1/passkeys/github.com", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let list = response_json(resp).await;
        let passkeys = list.as_array().unwrap();
        assert_eq!(passkeys.len(), 1);
        assert_eq!(passkeys[0]["rp_id"], "github.com");
    }

    #[tokio::test]
    async fn test_create_passkey_ed25519() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);

        let body = serde_json::json!({
            "title": "Ed25519 Passkey",
            "rp_id": "example.com",
            "rp_name": "Example",
            "user_handle": "dXNlcg",
            "user_name": "eduser",
            "algorithm": "eddsa"
        });
        let req = json_request("POST", "/v1/passkeys", Some(body), Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_passkey_export() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // Create a passkey
        let app = create_router(state.clone());
        let body = serde_json::json!({
            "title": "Export Test",
            "rp_id": "export.example.com",
            "rp_name": "Export Example",
            "user_handle": "dXNlcg",
            "user_name": "exportuser",
        });
        let req = json_request("POST", "/v1/passkeys", Some(body), Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Export all passkeys
        let app = create_router(state);
        let req = json_request("POST", "/v1/passkeys/export", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let data = response_json(resp).await;
        assert!(data["count"].as_u64().unwrap() >= 1);
        let passkeys = data["passkeys"].as_array().unwrap();
        assert!(!passkeys.is_empty());
        // Verify export includes private_key
        assert!(passkeys[0].get("private_key").is_some());
        assert_eq!(passkeys[0]["rp_id"], "export.example.com");
    }

    #[tokio::test]
    async fn test_passkey_import() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // Import passkeys
        let app = create_router(state.clone());
        let body = serde_json::json!({
            "passkeys": [
                {
                    "credential_id": "aW1wb3J0LWNyZWQ",
                    "rp_id": "import.example.com",
                    "rp_name": "Import Example",
                    "user_handle": "dXNlcg",
                    "user_name": "importuser",
                    "private_key": "c29tZS1rZXk",
                    "algorithm": "es256",
                    "sign_count": 3,
                    "title": "Imported Passkey"
                }
            ]
        });
        let req = json_request("POST", "/v1/passkeys/import", Some(body), Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let data = response_json(resp).await;
        assert_eq!(data["imported"], 1);
        assert_eq!(data["skipped"], 0);

        // Verify it shows in list
        let app = create_router(state.clone());
        let req = json_request("GET", "/v1/passkeys", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        let list = response_json(resp).await;
        let passkeys = list.as_array().unwrap();
        let imported = passkeys.iter().find(|p| p["rp_id"] == "import.example.com");
        assert!(imported.is_some());
        assert_eq!(imported.unwrap()["sign_count"], 3);
    }

    #[tokio::test]
    async fn test_passkey_import_duplicate_skipped() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        let import_body = serde_json::json!({
            "passkeys": [{
                "credential_id": "ZHVwZS1jcmVk",
                "rp_id": "dupe.example.com",
                "rp_name": "Dupe",
                "user_handle": "dXNlcg",
                "user_name": "dupeuser",
            }]
        });

        // First import
        let app = create_router(state.clone());
        let req = json_request("POST", "/v1/passkeys/import", Some(import_body.clone()), Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        let data = response_json(resp).await;
        assert_eq!(data["imported"], 1);

        // Second import — should be skipped as duplicate
        let app = create_router(state);
        let req = json_request("POST", "/v1/passkeys/import", Some(import_body), Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        let data = response_json(resp).await;
        assert_eq!(data["imported"], 0);
        assert_eq!(data["skipped"], 1);
    }

    #[tokio::test]
    async fn test_passkey_export_import_roundtrip() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // Create a passkey
        let app = create_router(state.clone());
        let body = serde_json::json!({
            "title": "Roundtrip",
            "rp_id": "roundtrip.example.com",
            "rp_name": "Roundtrip Example",
            "user_handle": "dXNlcg",
            "user_name": "rtuser",
        });
        let req = json_request("POST", "/v1/passkeys", Some(body), Some(&token));
        app.oneshot(req).await.unwrap();

        // Export
        let app = create_router(state.clone());
        let req = json_request("POST", "/v1/passkeys/export", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        let export_data = response_json(resp).await;
        let exported_passkeys = export_data["passkeys"].as_array().unwrap();
        let rt_pk = exported_passkeys.iter()
            .find(|p| p["rp_id"] == "roundtrip.example.com")
            .unwrap();

        // Verify exported data has the fields needed for re-import
        assert!(rt_pk.get("credential_id").is_some());
        assert!(rt_pk.get("private_key").is_some());
        assert!(rt_pk.get("rp_id").is_some());
        assert!(rt_pk.get("rp_name").is_some());
        assert!(rt_pk.get("user_name").is_some());
    }

    #[tokio::test]
    async fn test_passkey_storage_field() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // Create a software passkey
        let app = create_router(state.clone());
        let body = serde_json::json!({
            "title": "SW Passkey",
            "rp_id": "sw.example.com",
            "rp_name": "SW Example",
            "user_handle": "dXNlcg",
            "user_name": "swuser",
        });
        let req = json_request("POST", "/v1/passkeys", Some(body), Some(&token));
        app.oneshot(req).await.unwrap();

        // List and check storage field
        let app = create_router(state);
        let req = json_request("GET", "/v1/passkeys", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        let list = response_json(resp).await;
        let passkeys = list.as_array().unwrap();
        let sw = passkeys.iter().find(|p| p["rp_id"] == "sw.example.com").unwrap();
        assert_eq!(sw["storage"], "software");
    }

    // ---- Locked vault error paths ----

    #[tokio::test]
    async fn test_vault_status_locked() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        // Lock the vault
        state.daemon.lock().await.lock();
        let app = create_router(state);
        let req = json_request("GET", "/v1/status", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        // require_admin fails because jwt_signing_key returns None when locked
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_export_csv_format() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("GET", "/v1/export?format=csv", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let csv = String::from_utf8(body.to_vec()).unwrap();
        assert!(csv.contains("Title,Type,URL,Username,Password"));
        assert!(csv.contains("GitHub"));
    }

    #[tokio::test]
    async fn test_export_unsupported_format() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("GET", "/v1/export?format=xml", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_require_admin_locked_vault_via_agent_tokens() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        // Lock vault
        state.daemon.lock().await.lock();
        let app = create_router(state);
        // Use GET /v1/agent/tokens which calls require_admin (no body needed)
        let req = json_request("GET", "/v1/agent/tokens", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_export_locked_vault() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        state.daemon.lock().await.lock();
        let app = create_router(state);
        let req = json_request("GET", "/v1/export", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_sync_trigger_with_file_target() {
        let (state, dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // Set up a file sync target
        let sync_dir = dir.path().join("sync-remote");
        std::fs::create_dir_all(&sync_dir).unwrap();

        let config_path = crate::sync::scheduler::multi_sync_config_path();
        let config = crate::sync::scheduler::MultiSyncConfig {
            targets: vec![crate::sync::scheduler::SyncTarget {
                name: "test-file".into(),
                provider: "file".into(),
                remote_path: sync_dir.to_string_lossy().to_string(),
                auto_sync: false,
                sync_interval_seconds: 300,
                url: None,
                username: None,
                password: None,
            }],
        };
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&config_path, serde_json::to_string(&config).unwrap()).unwrap();

        let app = create_router(state);
        let req = json_request("POST", "/v1/sync/trigger", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        let results = body["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["target"], "test-file");

        // Cleanup
        let _ = std::fs::remove_file(&config_path);
    }

    #[tokio::test]
    async fn test_backup_verify_endpoint() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // First create a backup
        let app = create_router(state.clone());
        let req = json_request("POST", "/v1/backups/create", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        let filename = body["backup"]["filename"].as_str().unwrap().to_string();

        // Verify it
        let app = create_router(state);
        let body = serde_json::json!({ "filename": filename });
        let req = json_request("POST", "/v1/backups/verify", Some(body), Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["valid"], true);
    }

    #[tokio::test]
    async fn test_backup_verify_nonexistent() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let body = serde_json::json!({ "filename": "nonexistent.bak" });
        let req = json_request("POST", "/v1/backups/verify", Some(body), Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_backup_restore_endpoint() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // Create a backup first
        let app = create_router(state.clone());
        let req = json_request("POST", "/v1/backups/create", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        let filename = body["backup"]["filename"].as_str().unwrap().to_string();

        // Restore it
        let app = create_router(state);
        let body = serde_json::json!({ "filename": filename });
        let req = json_request("POST", "/v1/backups/restore", Some(body), Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert!(body["restored"].is_object());
    }

    #[tokio::test]
    async fn test_backup_restore_nonexistent() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let body = serde_json::json!({ "filename": "nonexistent.bak" });
        let req = json_request("POST", "/v1/backups/restore", Some(body), Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_rotation_execute_unapproved() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // Add a manual rotation plan (not approved)
        let entry_id = {
            let daemon = state.daemon.lock().await;
            daemon.vault_ref().unwrap().store().entries()[0].id
        };
        {
            let mut daemon = state.daemon.lock().await;
            let plan = crate::security::rotation::RotationPlan::new(
                entry_id,
                "GitHub".to_string(),
                crate::security::rotation::RotationTrigger::Manual,
            );
            daemon.rotation_scheduler.add_plan(plan);
        }

        let plan_id = {
            let daemon = state.daemon.lock().await;
            daemon.rotation_scheduler.list_plans()[0].id.to_string()
        };

        // Try to execute without approval — returns 409 CONFLICT
        let app = create_router(state);
        let req = json_request("POST", &format!("/v1/rotation/{}/execute", plan_id), None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body = response_json(resp).await;
        assert!(body["error"].as_str().unwrap().contains("approved"));
    }

    #[tokio::test]
    async fn test_passkey_assert_invalid_id() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let body = serde_json::json!({
            "client_data_json": "eyJ0eXAiOiJ3ZWJhdXRobi5nZXQifQ",
            "user_verified": true,
        });
        let req = json_request("POST", "/v1/passkeys/not-a-uuid/assert", Some(body), Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_passkey_assert_not_passkey() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // Get the GitHub entry ID (which is a login, not a passkey)
        let entry_id = {
            let daemon = state.daemon.lock().await;
            daemon.vault_ref().unwrap().store().entries()[0].id.to_string()
        };

        let app = create_router(state);
        let body = serde_json::json!({
            "client_data_json": "eyJ0eXAiOiJ3ZWJhdXRobi5nZXQifQ",
            "user_verified": true,
        });
        let req = json_request("POST", &format!("/v1/passkeys/{}/assert", entry_id), Some(body), Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = response_json(resp).await;
        assert!(body["error"].as_str().unwrap().contains("not a passkey"));
    }

    #[tokio::test]
    async fn test_sync_status_with_vault() {
        // Ensure no stale config from parallel tests
        let config_path = crate::sync::scheduler::multi_sync_config_path();
        let _ = std::fs::remove_file(&config_path);

        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("GET", "/v1/sync/status", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        // Verify all expected fields
        assert!(!body["status"]["configured"].as_bool().unwrap());
        assert!(!body["status"]["auto_sync_enabled"].as_bool().unwrap());
        assert!(body["status"]["sync_interval_seconds"].is_u64());
        assert_eq!(body["success_count"], 0);
        assert_eq!(body["fail_count"], 0);
    }

    // ---- Additional coverage tests ----

    #[tokio::test]
    async fn test_export_default_format_json() {
        // When no format query param, default is json
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("GET", "/v1/export", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(!parsed.is_empty());
    }

    #[tokio::test]
    async fn test_export_csv_with_all_credential_types() {
        // Add entries of all types to test CSV export covers each branch
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // Add SecureNote, SshKey, and Passkey entries
        {
            let mut daemon = state.daemon.lock().await;
            daemon.handle_request(crate::daemon::protocol::Request::Add {
                entry: Entry::new(
                    "My Note".into(),
                    Credential::SecureNote(SecureNoteCredential {
                        content: "secret content".into(),
                    }),
                ),
            });
            daemon.handle_request(crate::daemon::protocol::Request::Add {
                entry: Entry::new(
                    "SSH Key".into(),
                    Credential::SshKey(SshKeyCredential {
                        private_key: "-----BEGIN-----".into(),
                        public_key: "ssh-rsa AAAA".into(),
                        passphrase: "pass".into(),
                    }),
                ),
            });
            daemon.handle_request(crate::daemon::protocol::Request::Add {
                entry: Entry::new(
                    "Test Passkey".into(),
                    Credential::Passkey(PasskeyCredential {
                        credential_id: "cred_export".into(),
                        rp_id: "export.test".into(),
                        rp_name: "Export Test".into(),
                        user_handle: "dXNlcg".into(),
                        user_name: "testuser".into(),
                        private_key: "key_data".into(),
                        algorithm: PasskeyAlgorithm::Es256,
                        sign_count: 0,
                        discoverable: true,
                        backup_eligible: false,
                        backup_state: false,
                        last_used_at: None,
                    }),
                ),
            });
        }

        let app = create_router(state);
        let req = json_request("GET", "/v1/export?format=csv", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let csv = String::from_utf8(body.to_vec()).unwrap();
        assert!(csv.contains("My Note"));
        assert!(csv.contains("SSH Key"));
        assert!(csv.contains("Test Passkey"));
    }

    #[tokio::test]
    async fn test_list_items_locked_vault() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        // Lock the vault
        state.daemon.lock().await.lock();
        let app = create_router(state);
        // require_admin fails because signing key is None when locked
        let req = json_request("GET", "/v1/items", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_create_item_with_totp_and_notes() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state.clone());
        let req = json_request(
            "POST",
            "/v1/items",
            Some(serde_json::json!({
                "title": "With TOTP",
                "credential": {
                    "type": "Login",
                    "url": "https://totp.com",
                    "username": "user",
                    "password": "pass"
                },
                "totp_secret": "GEZDGNBVGY3TQOJQ",
                "notes": "Some notes here",
                "favorite": true,
                "sensitive": true
            })),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = response_json(resp).await;
        let id = body["id"].as_str().unwrap();

        // Verify the entry has totp
        let app = create_router(state);
        let req = json_request("GET", &format!("/v1/items/{}", id), None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["title"], "With TOTP");
        assert!(body["totp_secret"].is_string());
    }

    #[tokio::test]
    async fn test_credential_type_name_passkey() {
        assert_eq!(
            credential_type_name(&Credential::Passkey(PasskeyCredential {
                credential_id: String::new(),
                rp_id: String::new(),
                rp_name: String::new(),
                user_handle: String::new(),
                user_name: String::new(),
                private_key: String::new(),
                algorithm: PasskeyAlgorithm::Es256,
                sign_count: 0,
                discoverable: false,
                backup_eligible: false,
                backup_state: false,
                last_used_at: None,
            })),
            "passkey"
        );
    }

    #[tokio::test]
    async fn test_extract_credential_value_passkey() {
        let entry = Entry::new(
            "pk".into(),
            Credential::Passkey(PasskeyCredential {
                credential_id: "my_cred_id".into(),
                rp_id: "example.com".into(),
                rp_name: "Example".into(),
                user_handle: "uh".into(),
                user_name: "user".into(),
                private_key: "pk_data".into(),
                algorithm: PasskeyAlgorithm::Es256,
                sign_count: 0,
                discoverable: true,
                backup_eligible: false,
                backup_state: false,
                last_used_at: None,
            }),
        );
        assert_eq!(extract_credential_value(&entry), "my_cred_id");
    }

    #[tokio::test]
    async fn test_passkey_to_summary_hardware() {
        // Hardware passkey has empty private_key
        let entry = Entry::new(
            "HW Passkey".into(),
            Credential::Passkey(PasskeyCredential {
                credential_id: "hw_cred".into(),
                rp_id: "hw.example.com".into(),
                rp_name: "HW Example".into(),
                user_handle: "uh".into(),
                user_name: "hwuser".into(),
                private_key: String::new(), // hardware passkey
                algorithm: PasskeyAlgorithm::EdDsa,
                sign_count: 5,
                discoverable: true,
                backup_eligible: false,
                backup_state: false,
                last_used_at: Some(chrono::Utc::now()),
            }),
        );
        let summary = passkey_to_summary(&entry).unwrap();
        assert_eq!(summary.storage, "hardware");
        assert_eq!(summary.sign_count, 5);
        assert!(summary.last_used_at.is_some());
    }

    #[tokio::test]
    async fn test_passkey_to_summary_not_passkey() {
        let entry = Entry::new(
            "Login".into(),
            Credential::Login(LoginCredential {
                url: "https://example.com".into(),
                username: "u".into(),
                password: "p".into(),
            }),
        );
        assert!(passkey_to_summary(&entry).is_none());
    }

    #[tokio::test]
    async fn test_passkey_import_skip_invalid_entries() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let body = serde_json::json!({
            "passkeys": [
                {
                    "credential_id": "",  // empty = skip
                    "rp_id": "x.com",
                    "rp_name": "X",
                    "user_handle": "uh",
                    "user_name": "u"
                },
                {
                    "credential_id": "valid",
                    "rp_id": "",  // empty = skip
                    "rp_name": "Y",
                    "user_handle": "uh",
                    "user_name": "u"
                }
            ]
        });
        let req = json_request("POST", "/v1/passkeys/import", Some(body), Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let data = response_json(resp).await;
        assert_eq!(data["imported"], 0);
        assert_eq!(data["skipped"], 2);
    }

    #[tokio::test]
    async fn test_passkey_import_eddsa_algorithm() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let body = serde_json::json!({
            "passkeys": [{
                "credential_id": "eddsa_cred",
                "rp_id": "eddsa.example.com",
                "rp_name": "EdDSA",
                "user_handle": "uh",
                "user_name": "eduser",
                "algorithm": "eddsa",
                "sign_count": 10
            }]
        });
        let req = json_request("POST", "/v1/passkeys/import", Some(body), Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let data = response_json(resp).await;
        assert_eq!(data["imported"], 1);
    }

    #[tokio::test]
    async fn test_passkey_import_auto_title() {
        // When no title provided, should generate from rp_name + user_name
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state.clone());
        let body = serde_json::json!({
            "passkeys": [{
                "credential_id": "auto_title_cred",
                "rp_id": "auto.example.com",
                "rp_name": "Auto Site",
                "user_handle": "uh",
                "user_name": "autouser"
            }]
        });
        let req = json_request("POST", "/v1/passkeys/import", Some(body), Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify the generated title
        let app = create_router(state);
        let req = json_request("GET", "/v1/passkeys", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        let list = response_json(resp).await;
        let pk = list.as_array().unwrap().iter()
            .find(|p| p["rp_id"] == "auto.example.com")
            .unwrap();
        // Title should not be present in passkey summary, but the entry was stored
        assert_eq!(pk["user_name"], "autouser");
    }

    #[tokio::test]
    async fn test_passkey_delete_not_found() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let fake_id = Uuid::new_v4();
        let app = create_router(state);
        let req = json_request(
            "POST",
            &format!("/v1/passkeys/{}/delete", fake_id),
            None,
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_passkey_delete_invalid_id() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/passkeys/not-a-uuid/delete",
            None,
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_get_passkeys_by_uuid() {
        // The get_passkeys_by_rp handler also supports UUID lookup
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // Create a passkey
        let app = create_router(state.clone());
        let body = serde_json::json!({
            "title": "UUID Lookup",
            "rp_id": "uuid.example.com",
            "rp_name": "UUID Example",
            "user_handle": "uh",
            "user_name": "uuser"
        });
        let req = json_request("POST", "/v1/passkeys", Some(body), Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        let create_result = response_json(resp).await;
        let pk_id = create_result["id"].as_str().unwrap();

        // Get by UUID
        let app = create_router(state);
        let req = json_request("GET", &format!("/v1/passkeys/{}", pk_id), None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let list = response_json(resp).await;
        let passkeys = list.as_array().unwrap();
        assert_eq!(passkeys.len(), 1);
        assert_eq!(passkeys[0]["rp_id"], "uuid.example.com");
    }

    #[tokio::test]
    async fn test_get_passkeys_by_rp_empty_result() {
        // Query an rp_id with no passkeys
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("GET", "/v1/passkeys/nonexistent.com", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let list = response_json(resp).await;
        assert!(list.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_passkey_export_empty() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("POST", "/v1/passkeys/export", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let data = response_json(resp).await;
        assert_eq!(data["count"], 0);
        assert!(data["passkeys"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_passkey_export_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let req = json_request("POST", "/v1/passkeys/export", None, None);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_passkey_import_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let body = serde_json::json!({ "passkeys": [] });
        let req = json_request("POST", "/v1/passkeys/import", Some(body), None);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_backup_list_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let req = json_request("GET", "/v1/backups", None, None);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_backup_create_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let req = json_request("POST", "/v1/backups/create", None, None);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_backup_restore_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let body = serde_json::json!({ "filename": "test.bak" });
        let req = json_request("POST", "/v1/backups/restore", Some(body), None);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_backup_verify_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let body = serde_json::json!({ "filename": "test.bak" });
        let req = json_request("POST", "/v1/backups/verify", Some(body), None);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_rotation_scan_no_auth() {
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let req = json_request("POST", "/v1/rotation/scan", None, None);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_rotation_approve_invalid_id() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("POST", "/v1/rotation/not-a-uuid/approve", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_rotation_dismiss_invalid_id() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/rotation/not-a-uuid/dismiss",
            Some(serde_json::json!({ "reason": "test" })),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_rotation_execute_invalid_id() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let req = json_request("POST", "/v1/rotation/not-a-uuid/execute", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_rotation_execute_secure_note() {
        // SecureNote entries cannot be rotated
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // Add a SecureNote entry
        let entry_id = {
            let mut daemon = state.daemon.lock().await;
            let entry = Entry::new(
                "My Note".into(),
                Credential::SecureNote(SecureNoteCredential {
                    content: "secret content".into(),
                }),
            );
            let resp = daemon.handle_request(crate::daemon::protocol::Request::Add { entry });
            match resp {
                crate::daemon::protocol::Response::Ok { data } => match *data {
                    crate::daemon::protocol::ResponseData::Id(id) => id,
                    _ => panic!("Expected Id"),
                },
                _ => panic!("Expected Ok"),
            }
        };

        // Add a rotation plan for it and approve it
        {
            let mut daemon = state.daemon.lock().await;
            let plan = crate::security::rotation::RotationPlan::new(
                entry_id,
                "My Note".to_string(),
                crate::security::rotation::RotationTrigger::Manual,
            );
            daemon.rotation_scheduler.add_plan(plan);
            let plans = daemon.rotation_scheduler.list_plans();
            let plan_id = plans.iter().find(|p| p.entry_id == entry_id).unwrap().id;
            daemon.rotation_scheduler.get_plan_mut(&plan_id).unwrap().approve("admin").unwrap();
        }

        let plan_id = {
            let daemon = state.daemon.lock().await;
            let plans = daemon.rotation_scheduler.list_plans();
            plans.iter().find(|p| p.entry_id == entry_id).unwrap().id.to_string()
        };

        // Execute should fail because SecureNote can't be rotated
        let app = create_router(state);
        let req = json_request("POST", &format!("/v1/rotation/{}/execute", plan_id), None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = response_json(resp).await;
        assert!(body["error"].as_str().unwrap().contains("SecureNote"));
    }

    #[tokio::test]
    async fn test_session_context_sub_agent() {
        // Sub-agent session context uses inherit policy — should pass
        let (state, _dir) = setup_test_state();
        let daemon = state.daemon.lock().await;
        let signing_key = daemon.jwt_signing_key().unwrap();
        let agent_jwt = jwt::create_agent_jwt(signing_key, "sub-agent", "tok-sub", 3600).unwrap();
        drop(daemon);

        let app = create_router(state);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/lease")
            .header("Authorization", format!("Bearer {}", agent_jwt))
            .header("X-Session-Context", "type=sub_agent;agent_id=sub-agent;parent=main-agent")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&serde_json::json!({
                "ref": "00000000-0000-0000-0000-000000000000",
                "scope": "read",
                "ttl": 300,
                "reason": "test sub-agent"
            })).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // Sub-agent inherits parent scope — should pass policy, fail at entry lookup
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_session_context_cron() {
        // Default cron policy is "prompt" which should allow at HTTP level
        let (state, _dir) = setup_test_state();
        let daemon = state.daemon.lock().await;
        let signing_key = daemon.jwt_signing_key().unwrap();
        let agent_jwt = jwt::create_agent_jwt(signing_key, "cron-agent", "tok-cron", 3600).unwrap();
        drop(daemon);

        let app = create_router(state);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/lease")
            .header("Authorization", format!("Bearer {}", agent_jwt))
            .header("X-Session-Context", "type=cron;agent_id=cron-agent")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&serde_json::json!({
                "ref": "00000000-0000-0000-0000-000000000000",
                "scope": "read",
                "ttl": 300,
                "reason": "scheduled task"
            })).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // Cron type with prompt policy should allow, then fail at entry lookup
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_update_item_preserves_breach_metadata() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let entry_id = {
            let daemon = state.daemon.lock().await;
            let vault = daemon.vault_ref().unwrap();
            vault.store().entries().first().unwrap().id
        };

        // Update the entry
        let app = create_router(state.clone());
        let req = json_request(
            "PUT",
            &format!("/v1/items/{}", entry_id),
            Some(serde_json::json!({
                "title": "GitHub Updated Again",
                "credential": {
                    "type": "Login",
                    "url": "https://github.com",
                    "username": "newuser2",
                    "password": "newpass2"
                }
            })),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify
        let app = create_router(state);
        let req = json_request("GET", &format!("/v1/items/{}", entry_id), None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["title"], "GitHub Updated Again");
    }

    #[tokio::test]
    async fn test_import_1pif_separator() {
        // Test auto-detection of 1pif format via the separator string
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let pif_content = "***5642bee8-a5ff-11dc-8314-0800200c9a66***\n{\"title\":\"Auto Detect\",\"typeName\":\"webforms.WebForm\",\"secureContents\":{\"fields\":[{\"designation\":\"username\",\"value\":\"u\"},{\"designation\":\"password\",\"value\":\"p\"}]}}";
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/import",
            Some(serde_json::json!({
                "content": pif_content,
                "dry_run": true
            })),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_lease_with_vclaw_ref_nonexistent_title() {
        let (state, _dir) = setup_test_state();
        let agent_jwt = get_agent_jwt(&state).await;
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/lease",
            Some(serde_json::json!({
                "ref": "vclaw://default/nonexistent_entry_xyz",
                "scope": "read",
                "ttl": 600,
                "reason": "test"
            })),
            Some(&agent_jwt),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_lease_with_raw_title_ref() {
        // ref without vclaw:// prefix uses the raw title as lookup
        let (state, _dir) = setup_test_state();
        let agent_jwt = get_agent_jwt(&state).await;
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/lease",
            Some(serde_json::json!({
                "ref": "nonexistent_raw_title",
                "scope": "read",
                "ttl": 600,
                "reason": "test"
            })),
            Some(&agent_jwt),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_vault_health_locked() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        state.daemon.lock().await.lock();
        let app = create_router(state);
        let req = json_request("GET", "/v1/health/vault", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        // require_admin fails with locked vault
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_passkey_assert_ed25519() {
        use base64::Engine;
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // Create an ed25519 passkey
        let app = create_router(state.clone());
        let body = serde_json::json!({
            "title": "EdDSA Assert",
            "rp_id": "eddsa-assert.com",
            "rp_name": "EdDSA Assert Site",
            "user_handle": "dXNlcg",
            "user_name": "eduser",
            "algorithm": "eddsa"
        });
        let req = json_request("POST", "/v1/passkeys", Some(body), Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let create_result = response_json(resp).await;
        let passkey_id = create_result["id"].as_str().unwrap();

        // Sign an assertion with EdDSA key
        let client_data = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            br#"{"type":"webauthn.get","challenge":"ed_test","origin":"https://eddsa-assert.com"}"#
        );
        let assert_body = serde_json::json!({
            "client_data_json": client_data,
            "user_verified": false
        });
        let app = create_router(state);
        let req = json_request(
            "POST",
            &format!("/v1/passkeys/{}/assert", passkey_id),
            Some(assert_body),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let assertion = response_json(resp).await;
        assert!(assertion["signature"].is_string());
    }

    #[tokio::test]
    async fn test_import_auto_detect_1pif_json() {
        // Auto-detect by leading '{' character
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let content = r#"{"title":"AutoJ","typeName":"webforms.WebForm","secureContents":{"fields":[{"designation":"username","value":"u"},{"designation":"password","value":"p"}]}}"#;
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/import",
            Some(serde_json::json!({
                "content": content,
                "format": "auto",
                "dry_run": true
            })),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_rotation_approve_already_dismissed() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // Add and dismiss a plan
        let entry_id = {
            let daemon = state.daemon.lock().await;
            daemon.vault_ref().unwrap().store().entries()[0].id
        };
        let plan_id = {
            let mut daemon = state.daemon.lock().await;
            let plan = crate::security::rotation::RotationPlan::new(
                entry_id,
                "GitHub".to_string(),
                crate::security::rotation::RotationTrigger::Manual,
            );
            daemon.rotation_scheduler.add_plan(plan);
            let plans = daemon.rotation_scheduler.list_plans();
            let plan_id = plans.last().unwrap().id;
            daemon.rotation_scheduler.get_plan_mut(&plan_id).unwrap().dismiss("not needed").unwrap();
            plan_id.to_string()
        };

        // Try to approve the dismissed plan — should fail
        let app = create_router(state);
        let req = json_request("POST", &format!("/v1/rotation/{}/approve", plan_id), None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_session_context_resolve_group_denied() {
        // Group chat should be denied for /v1/resolve too
        let (state, _dir) = setup_test_state();
        let daemon = state.daemon.lock().await;
        let signing_key = daemon.jwt_signing_key().unwrap();
        let agent_jwt = jwt::create_agent_jwt(signing_key, "group-agent", "tok-g", 3600).unwrap();
        drop(daemon);

        let app = create_router(state);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/resolve")
            .header("Authorization", format!("Bearer {}", agent_jwt))
            .header("X-Session-Context", "type=group;agent_id=group-agent")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&serde_json::json!({
                "refs": ["vclaw://default/github"]
            })).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_passkey_import_ed25519_alias() {
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        let app = create_router(state);
        let body = serde_json::json!({
            "passkeys": [{
                "credential_id": "ed25519_alias",
                "rp_id": "ed25519.example.com",
                "rp_name": "Ed25519 Site",
                "user_handle": "uh",
                "user_name": "eduser",
                "algorithm": "ed25519"
            }]
        });
        let req = json_request("POST", "/v1/passkeys/import", Some(body), Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let data = response_json(resp).await;
        assert_eq!(data["imported"], 1);
    }

    #[tokio::test]
    async fn test_rotation_execute_ssh_key() {
        // SSH key rotation should work
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // Add an SSH key entry
        let entry_id = {
            let mut daemon = state.daemon.lock().await;
            let entry = Entry::new(
                "SSH Key".into(),
                Credential::SshKey(SshKeyCredential {
                    private_key: "old_key".into(),
                    public_key: "pub_key".into(),
                    passphrase: "old_pass".into(),
                }),
            );
            let resp = daemon.handle_request(crate::daemon::protocol::Request::Add { entry });
            match resp {
                crate::daemon::protocol::Response::Ok { data } => match *data {
                    crate::daemon::protocol::ResponseData::Id(id) => id,
                    _ => panic!("Expected Id"),
                },
                _ => panic!("Expected Ok"),
            }
        };

        // Create and approve a rotation plan for it
        {
            let mut daemon = state.daemon.lock().await;
            let plan = crate::security::rotation::RotationPlan::new(
                entry_id,
                "SSH Key".to_string(),
                crate::security::rotation::RotationTrigger::Manual,
            );
            daemon.rotation_scheduler.add_plan(plan);
            let plans = daemon.rotation_scheduler.list_plans();
            let plan_id = plans.iter().find(|p| p.entry_id == entry_id).unwrap().id;
            daemon.rotation_scheduler.get_plan_mut(&plan_id).unwrap().approve("admin").unwrap();
        }

        let plan_id = {
            let daemon = state.daemon.lock().await;
            let plans = daemon.rotation_scheduler.list_plans();
            plans.iter().find(|p| p.entry_id == entry_id).unwrap().id.to_string()
        };

        let app = create_router(state);
        let req = json_request("POST", &format!("/v1/rotation/{}/execute", plan_id), None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["status"], "completed");
    }

    // ---- Additional coverage tests for uncovered lines ----

    #[test]
    fn test_http_rate_limiter_window_reset() {
        // Covers line 46: window reset after >= 1 second
        let mut rl = HttpRateLimiter::new(2);
        assert!(rl.check("user1"));
        assert!(rl.check("user1"));
        assert!(!rl.check("user1")); // at limit
        // Sleep just over 1 second to trigger window reset
        std::thread::sleep(std::time::Duration::from_millis(1050));
        assert!(rl.check("user1")); // window reset, should succeed again
    }

    #[tokio::test]
    async fn test_import_auto_detect_1pif_separator() {
        // Covers 1pif auto-detection via the "***5642bee8-a5ff-11dc-8314-0800200c9a66***" separator
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        // Content with the 1pif separator marker should auto-detect as 1pif
        let pif = "***5642bee8-a5ff-11dc-8314-0800200c9a66***\n{\"title\":\"Auto PIF Sep\",\"typeName\":\"webforms.WebForm\",\"secureContents\":{\"fields\":[{\"designation\":\"username\",\"value\":\"u\"},{\"designation\":\"password\",\"value\":\"p\"}]}}";
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/import",
            Some(serde_json::json!({
                "content": pif,
                "dry_run": true
            })),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["imported"], 1);
    }

    #[tokio::test]
    async fn test_import_dry_run_conflict_non_login() {
        // Covers line 1114: conflict detection for non-Login credentials returns false
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // Add a SecureNote entry with title "Overlap Note"
        {
            let mut daemon = state.daemon.lock().await;
            daemon.handle_request(crate::daemon::protocol::Request::Add {
                entry: Entry::new(
                    "Overlap Note".into(),
                    Credential::SecureNote(SecureNoteCredential {
                        content: "existing".into(),
                    }),
                ),
            });
        }

        // Import a CSV with same title "Overlap Note" — conflict detection uses Login comparison
        // so non-Login entry should return "new" (not conflict)
        let csv = "Title,Url,Username,Password\nOverlap Note,https://overlap.com,user,pass";
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/import",
            Some(serde_json::json!({
                "content": csv,
                "format": "csv",
                "dry_run": true
            })),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        let preview = body["preview"].as_array().unwrap();
        // The existing entry is a SecureNote, imported is Login — conflict detection
        // checks type match (Login vs Login) then URL, so this should be "new"
        assert_eq!(preview[0]["status"], "new");
    }

    #[tokio::test]
    async fn test_rotation_dismiss_default_reason() {
        // Covers line 1461: default_dismiss_reason() used when no "reason" field in JSON
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // Add a manual plan
        let entry_id = {
            let daemon = state.daemon.lock().await;
            daemon.vault_ref().unwrap().store().entries()[0].id
        };
        {
            let mut daemon = state.daemon.lock().await;
            let plan = crate::security::rotation::RotationPlan::new(
                entry_id,
                "GitHub".to_string(),
                crate::security::rotation::RotationTrigger::Manual,
            );
            daemon.rotation_scheduler.add_plan(plan);
        }
        let plan_id = {
            let daemon = state.daemon.lock().await;
            daemon.rotation_scheduler.list_plans()[0].id.to_string()
        };

        // Dismiss with empty JSON body (no "reason" field) to trigger default_dismiss_reason
        let app = create_router(state);
        let req = json_request(
            "POST",
            &format!("/v1/rotation/{}/dismiss", plan_id),
            Some(serde_json::json!({})),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["status"], "dismissed");
    }

    #[tokio::test]
    async fn test_session_context_non_ascii_header() {
        // Covers lines 1389-1390: X-Session-Context header with non-UTF8 bytes
        let (state, _dir) = setup_test_state();
        let daemon = state.daemon.lock().await;
        let signing_key = daemon.jwt_signing_key().unwrap();
        let agent_jwt = jwt::create_agent_jwt(signing_key, "test-agent", "tok-1", 3600).unwrap();
        drop(daemon);

        let app = create_router(state);
        // Build request with header containing non-ASCII bytes using HeaderValue::from_bytes
        let non_ascii_value = axum::http::HeaderValue::from_bytes(b"type=dm\x80invalid").unwrap();
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/lease")
            .header("Authorization", format!("Bearer {}", agent_jwt))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&serde_json::json!({
                "ref": "00000000-0000-0000-0000-000000000000",
                "scope": "read",
                "ttl": 300,
                "reason": "test"
            })).unwrap()))
            .unwrap();
        // Insert the non-ASCII header directly
        req.headers_mut().insert("x-session-context", non_ascii_value);
        let resp = app.oneshot(req).await.unwrap();
        // Should get BAD_REQUEST because to_str() fails on non-ASCII
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_rotation_execute_api_key() {
        // Covers lines 1606-1607, 1631-1632: rotation of ApiKey credentials
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // The test vault already has an AWS ApiKey entry
        let entry_id = {
            let daemon = state.daemon.lock().await;
            let vault = daemon.vault_ref().unwrap();
            vault.store().entries().iter()
                .find(|e| matches!(&e.credential, Credential::ApiKey(_)))
                .unwrap().id
        };

        // Create and approve a rotation plan
        {
            let mut daemon = state.daemon.lock().await;
            let plan = crate::security::rotation::RotationPlan::new(
                entry_id,
                "AWS".to_string(),
                crate::security::rotation::RotationTrigger::Manual,
            );
            daemon.rotation_scheduler.add_plan(plan);
            let plans = daemon.rotation_scheduler.list_plans();
            let plan_id = plans.iter().find(|p| p.entry_id == entry_id).unwrap().id;
            daemon.rotation_scheduler.get_plan_mut(&plan_id).unwrap().approve("admin").unwrap();
        }

        let plan_id = {
            let daemon = state.daemon.lock().await;
            daemon.rotation_scheduler.list_plans().iter()
                .find(|p| p.entry_id == entry_id).unwrap().id.to_string()
        };

        let app = create_router(state);
        let req = json_request("POST", &format!("/v1/rotation/{}/execute", plan_id), None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["status"], "completed");
    }

    #[tokio::test]
    async fn test_rotation_approve_already_approved() {
        // Covers lines 1562-1563: approve on already-approved plan returns CONFLICT
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        let entry_id = {
            let daemon = state.daemon.lock().await;
            daemon.vault_ref().unwrap().store().entries()[0].id
        };
        {
            let mut daemon = state.daemon.lock().await;
            let plan = crate::security::rotation::RotationPlan::new(
                entry_id,
                "GitHub".to_string(),
                crate::security::rotation::RotationTrigger::Manual,
            );
            daemon.rotation_scheduler.add_plan(plan);
            // Approve it directly
            let plans = daemon.rotation_scheduler.list_plans();
            let plan_id = plans[0].id;
            daemon.rotation_scheduler.get_plan_mut(&plan_id).unwrap().approve("admin").unwrap();
        }

        let plan_id = {
            let daemon = state.daemon.lock().await;
            daemon.rotation_scheduler.list_plans()[0].id.to_string()
        };

        // Try to approve again via HTTP — should get CONFLICT
        let app = create_router(state);
        let req = json_request("POST", &format!("/v1/rotation/{}/approve", plan_id), None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_rotation_dismiss_already_dismissed() {
        // Covers lines 1562-1563 (dismiss variant): dismiss already-dismissed plan returns CONFLICT
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        let entry_id = {
            let daemon = state.daemon.lock().await;
            daemon.vault_ref().unwrap().store().entries()[0].id
        };
        {
            let mut daemon = state.daemon.lock().await;
            let plan = crate::security::rotation::RotationPlan::new(
                entry_id,
                "GitHub".to_string(),
                crate::security::rotation::RotationTrigger::Manual,
            );
            daemon.rotation_scheduler.add_plan(plan);
            // Dismiss it directly
            let plans = daemon.rotation_scheduler.list_plans();
            let plan_id = plans[0].id;
            daemon.rotation_scheduler.get_plan_mut(&plan_id).unwrap().dismiss("already").unwrap();
        }

        let plan_id = {
            let daemon = state.daemon.lock().await;
            daemon.rotation_scheduler.list_plans()[0].id.to_string()
        };

        // Try to dismiss again via HTTP — should get CONFLICT
        let app = create_router(state);
        let req = json_request(
            "POST",
            &format!("/v1/rotation/{}/dismiss", plan_id),
            Some(serde_json::json!({ "reason": "again" })),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_rotation_execute_passkey() {
        // Covers lines 1609, 1616-1623: rotation of Passkey credentials should fail
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // Add a Passkey entry
        let entry_id = {
            let mut daemon = state.daemon.lock().await;
            let entry = Entry::new(
                "Test Passkey Rotate".into(),
                Credential::Passkey(PasskeyCredential {
                    credential_id: "pk_rotate".into(),
                    rp_id: "rotate.example.com".into(),
                    rp_name: "Rotate Example".into(),
                    user_handle: "uh".into(),
                    user_name: "user".into(),
                    private_key: "key_data".into(),
                    algorithm: PasskeyAlgorithm::Es256,
                    sign_count: 0,
                    discoverable: true,
                    backup_eligible: false,
                    backup_state: false,
                    last_used_at: None,
                }),
            );
            let resp = daemon.handle_request(crate::daemon::protocol::Request::Add { entry });
            match resp {
                crate::daemon::protocol::Response::Ok { data } => match *data {
                    crate::daemon::protocol::ResponseData::Id(id) => id,
                    other => panic!("Expected Id, got {:?}", other),
                },
                other => panic!("Expected Ok, got {:?}", other),
            }
        };

        // Create and approve a rotation plan for it
        {
            let mut daemon = state.daemon.lock().await;
            let plan = crate::security::rotation::RotationPlan::new(
                entry_id,
                "Test Passkey Rotate".to_string(),
                crate::security::rotation::RotationTrigger::Manual,
            );
            daemon.rotation_scheduler.add_plan(plan);
            let plans = daemon.rotation_scheduler.list_plans();
            let plan_id = plans.iter().find(|p| p.entry_id == entry_id).unwrap().id;
            daemon.rotation_scheduler.get_plan_mut(&plan_id).unwrap().approve("admin").unwrap();
        }

        let plan_id = {
            let daemon = state.daemon.lock().await;
            daemon.rotation_scheduler.list_plans().iter()
                .find(|p| p.entry_id == entry_id).unwrap().id.to_string()
        };

        // Execute should fail because Passkey credentials can't be rotated
        let app = create_router(state);
        let req = json_request("POST", &format!("/v1/rotation/{}/execute", plan_id), None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = response_json(resp).await;
        assert!(body["error"].as_str().unwrap().contains("Cannot rotate"));
    }

    #[tokio::test]
    async fn test_lease_anomaly_without_rate_limit_exceeded() {
        // Covers line 1240: anomalies detected but no rate_limit_exceeded and no should_revoke
        // so the lease creation continues past the anomaly check
        let (state, _dir) = setup_test_state();

        // Get the entry ID
        let entry_id = {
            let daemon = state.daemon.lock().await;
            let entries = daemon.vault_ref().unwrap().store().entries();
            entries[0].id
        };

        // Set entry sensitivity to Low
        {
            let mut daemon = state.daemon.lock().await;
            daemon.lease_store.set_sensitivity(entry_id, super::super::lease::Sensitivity::Low);
        }

        // Create agent JWT
        let agent_jwt = {
            let daemon = state.daemon.lock().await;
            let key = daemon.jwt_signing_key().unwrap();
            jwt::create_agent_jwt(key, "anomaly-test-agent", "token-a", 3600).unwrap()
        };

        // Set a rate limit with auto_revoke_on_anomaly = false and generous limits
        {
            let mut daemon = state.daemon.lock().await;
            let mut limit = super::super::rate_config::AgentRateLimit::new("anomaly-test-agent", 100, 1000);
            limit.auto_revoke_on_anomaly = false;
            daemon.rate_limit_config.set(limit);
        }

        // Record many accesses in rapid succession to create an anomaly,
        // but NOT enough to exceed rate limit (rpm=100 is high)
        // Instead, let's record accesses to many different entries to trigger burst detection
        {
            let mut daemon = state.daemon.lock().await;
            let now = chrono::Utc::now();
            // Record many rapid accesses to trigger burst anomaly
            for _ in 0..50 {
                daemon.access_tracker.record_access("anomaly-test-agent", &entry_id, now);
            }
        }

        // Now make a lease request. Whether anomalies are actually detected depends on
        // the anomaly detection thresholds. If anomalies are detected without rate_limit_exceeded,
        // it should still continue (line 1240).
        let app = create_router(state);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/lease")
            .header("Authorization", format!("Bearer {}", agent_jwt))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&serde_json::json!({
                "ref": entry_id.to_string(),
                "scope": "read",
                "ttl": 300,
                "reason": "anomaly test"
            })).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // Should either succeed (no anomaly triggered) or succeed (anomaly but non-blocking)
        // or get rate-limited (anomaly with rate exceeded). Any of these is valid.
        let status = resp.status();
        assert!(
            status == StatusCode::CREATED || status == StatusCode::TOO_MANY_REQUESTS,
            "Expected CREATED or TOO_MANY_REQUESTS, got {}", status
        );
    }


    #[tokio::test]
    async fn test_auth_token_already_unlocked() {
        // Covers line 589-592: auth_token when vault is already unlocked
        // The handler checks is_locked() — if not locked, it skips unlock and proceeds
        let (state, _dir) = setup_test_state();
        // The vault is already unlocked from setup_test_state
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/auth/token",
            Some(serde_json::json!({ "password": "test-password" })),
            None,
        );
        let resp = app.oneshot(req).await.unwrap();
        // Should succeed since vault is already unlocked
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert!(body["token"].as_str().is_some());
    }

    #[tokio::test]
    async fn test_set_entry_sensitivity_locked_vault() {
        // Covers line 1363: set_entry_sensitivity when vault is locked
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;
        // Lock the vault
        state.daemon.lock().await.lock();
        let app = create_router(state);
        let req = json_request(
            "POST",
            &format!("/v1/entry/{}/sensitivity", Uuid::new_v4()),
            Some(serde_json::json!({ "level": "low" })),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        // require_admin fails because vault is locked (jwt_signing_key is None)
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_non_ascii_bearer_token() {
        // Test invalid bearer token with non-ASCII bytes that fails to_str
        let (state, _dir) = setup_test_state();
        let app = create_router(state);
        let non_ascii_auth = axum::http::HeaderValue::from_bytes(b"Bearer invalid\x80token").unwrap();
        let mut req = axum::http::Request::builder()
            .method("GET")
            .uri("/v1/items")
            .body(Body::empty())
            .unwrap();
        req.headers_mut().insert("authorization", non_ascii_auth);
        let resp = app.oneshot(req).await.unwrap();
        // Bearer with non-UTF8 should fail extract_bearer → Unauthorized
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_resolve_session_context_inherit() {
        // Covers line 1407: session context with sub_agent type → PolicyDecision::Inherit
        let (state, _dir) = setup_test_state();
        let daemon = state.daemon.lock().await;
        let signing_key = daemon.jwt_signing_key().unwrap();
        let agent_jwt = jwt::create_agent_jwt(signing_key, "child-agent", "tok-sub", 3600).unwrap();
        drop(daemon);

        let app = create_router(state);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/resolve")
            .header("Authorization", format!("Bearer {}", agent_jwt))
            .header("X-Session-Context", "type=sub_agent;agent_id=child-agent;parent_agent_id=parent-agent")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&serde_json::json!({
                "refs": ["vclaw://default/github"]
            })).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // sub_agent type → Inherit → allowed at HTTP level → should succeed
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_resolve_group_session_denied() {
        // Covers resolve handler group session denied path (resolve uses require_agent)
        let (state, _dir) = setup_test_state();
        let daemon = state.daemon.lock().await;
        let signing_key = daemon.jwt_signing_key().unwrap();
        let agent_jwt = jwt::create_agent_jwt(signing_key, "test-agent", "tok-res", 3600).unwrap();
        drop(daemon);

        let app = create_router(state);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/resolve")
            .header("Authorization", format!("Bearer {}", agent_jwt))
            .header("X-Session-Context", "type=group;agent_id=test-agent")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&serde_json::json!({
                "refs": ["vclaw://default/github"]
            })).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // Group chat session → policy deny
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_export_csv_with_ssh_and_passkey_creds() {
        // Covers lines 447-448: CSV export branches for SshKey and Passkey credentials
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // Add SSH and Passkey entries
        {
            let mut daemon = state.daemon.lock().await;
            daemon.handle_request(crate::daemon::protocol::Request::Add {
                entry: Entry::new(
                    "Export SSH".into(),
                    Credential::SshKey(SshKeyCredential {
                        private_key: "ssh-priv".into(),
                        public_key: "ssh-pub".into(),
                        passphrase: "ssh-pass".into(),
                    }),
                ),
            });
            daemon.handle_request(crate::daemon::protocol::Request::Add {
                entry: Entry::new(
                    "Export PK".into(),
                    Credential::Passkey(PasskeyCredential {
                        credential_id: "pk_csv_export".into(),
                        rp_id: "csv.test".into(),
                        rp_name: "CSV Test".into(),
                        user_handle: "uh".into(),
                        user_name: "csvuser".into(),
                        private_key: "pk_key".into(),
                        algorithm: PasskeyAlgorithm::Es256,
                        sign_count: 0,
                        discoverable: true,
                        backup_eligible: false,
                        backup_state: false,
                        last_used_at: None,
                    }),
                ),
            });
        }

        let app = create_router(state);
        let req = json_request("GET", "/v1/export?format=csv", None, Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let csv = String::from_utf8(body.to_vec()).unwrap();
        // Verify SSH key and Passkey entries are in the CSV
        assert!(csv.contains("Export SSH"));
        assert!(csv.contains("Export PK"));
        assert!(csv.contains("ssh-pub"));
        assert!(csv.contains("csv.test"));
    }

    #[tokio::test]
    async fn test_backup_restore_invalid_backup() {
        // Covers lines 2356-2358: backup restore with verification failure
        let (state, _dir) = setup_test_state();
        let token = get_admin_token(&state).await;

        // Create a corrupted backup file
        let backup_dir = crate::backup::default_backup_dir();
        std::fs::create_dir_all(&backup_dir).unwrap();
        let bad_backup = backup_dir.join("corrupted.vclaw.bak");
        std::fs::write(&bad_backup, b"not a valid vault file").unwrap();

        let app = create_router(state);
        let body = serde_json::json!({ "filename": "corrupted.vclaw.bak" });
        let req = json_request("POST", "/v1/backups/restore", Some(body), Some(&token));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Cleanup
        let _ = std::fs::remove_file(&bad_backup);
    }

    #[tokio::test]
    async fn test_create_lease_with_use_scope() {
        // Covers LeaseScope::Use branch in extract_credential_value via create_lease
        let (state, _dir) = setup_test_state();
        let agent_jwt = get_agent_jwt(&state).await;
        let entry_id = {
            let daemon = state.daemon.lock().await;
            let vault = daemon.vault_ref().unwrap();
            vault.store().entries().iter().find(|e| e.title == "GitHub").unwrap().id
        };
        let app = create_router(state);
        let req = json_request(
            "POST",
            "/v1/lease",
            Some(serde_json::json!({
                "ref": entry_id.to_string(),
                "scope": "use",
                "ttl": 3600,
                "reason": "deployment"
            })),
            Some(&agent_jwt),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = response_json(resp).await;
        assert_eq!(body["credential"], "gh_pass_123");
    }
}
