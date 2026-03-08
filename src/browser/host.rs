use serde::{Deserialize, Serialize};

use crate::daemon::client::DaemonClient;
use crate::daemon::protocol::{Request, Response, ResponseData};
use crate::passkey::{build_assertion_response, generate_passkey_credential, AssertionInput};
use crate::vault::entry::{
    Credential, Entry, EntryId, LoginCredential, PasskeyAlgorithm, PasskeyCredential,
};

/// Request from the browser extension to the native host.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action")]
pub enum BrowserRequest {
    /// Check if daemon is running and vault is unlocked.
    #[serde(rename = "status")]
    Status,

    /// Search credentials by query (url, title, etc.).
    #[serde(rename = "search")]
    Search { query: String },

    /// Get a specific credential for autofill.
    #[serde(rename = "get")]
    GetCredential { id: EntryId },

    /// Generate a random password.
    #[serde(rename = "generate")]
    GeneratePassword { length: Option<usize> },

    /// Save a new credential captured from form submission.
    #[serde(rename = "save")]
    SaveCredential {
        title: String,
        url: String,
        username: String,
        password: String,
    },

    /// Get TOTP code for an entry.
    #[serde(rename = "totp")]
    GetTotp { id: EntryId },

    /// Lock the vault.
    #[serde(rename = "lock")]
    Lock,

    /// List passkeys for a domain (rp_id).
    #[serde(rename = "passkey_list")]
    PasskeyList { rp_id: String },

    /// Create a new passkey (registration).
    #[serde(rename = "passkey_create")]
    PasskeyCreate {
        rp_id: String,
        rp_name: String,
        user_handle: String,
        user_name: String,
        #[serde(default = "default_es256")]
        algorithm: String,
    },

    /// Sign an assertion with a stored passkey (authentication).
    #[serde(rename = "passkey_assert")]
    PasskeyAssert {
        credential_id: String,
        client_data_json: String,
        #[serde(default)]
        user_verified: bool,
    },
}

fn default_es256() -> String {
    "es256".to_string()
}

/// Response from the native host to the browser extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum BrowserResponse {
    #[serde(rename = "ok")]
    Ok { data: BrowserData },
    #[serde(rename = "error")]
    Error { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BrowserData {
    None,
    Status {
        locked: bool,
        version: String,
    },
    Credentials(Vec<CredentialSummary>),
    Credential(CredentialDetail),
    Password(String),
    Totp {
        code: String,
        seconds_remaining: u64,
    },
    Saved {
        id: EntryId,
    },
    PasskeyList(Vec<PasskeySummaryBrowser>),
    PasskeyCreated {
        id: EntryId,
        credential_id: String,
    },
    PasskeyAssertion {
        credential_id: String,
        authenticator_data: String,
        signature: String,
        user_handle: String,
        client_data_json: String,
    },
}

/// Summary of a passkey for the browser extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeySummaryBrowser {
    pub id: EntryId,
    pub credential_id: String,
    pub rp_id: String,
    pub rp_name: String,
    pub user_name: String,
    pub user_handle: String,
    pub algorithm: String,
}

/// Summary of a credential for the extension popup list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSummary {
    pub id: EntryId,
    pub title: String,
    pub username: String,
    pub url: String,
    pub has_totp: bool,
}

/// Full credential detail for autofill.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialDetail {
    pub id: EntryId,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub totp_code: Option<String>,
}

impl BrowserResponse {
    pub fn ok(data: BrowserData) -> Self {
        Self::Ok { data }
    }

    pub fn error(msg: impl Into<String>) -> Self {
        Self::Error {
            message: msg.into(),
        }
    }
}

// ---- Entry conversion helpers ----

fn entry_to_summary(entry: &Entry) -> CredentialSummary {
    let (username, url) = match &entry.credential {
        Credential::Login(login) => (login.username.clone(), login.url.clone()),
        Credential::ApiKey(key) => (key.service.clone(), String::new()),
        _ => (String::new(), String::new()),
    };
    CredentialSummary {
        id: entry.id,
        title: entry.title.clone(),
        username,
        url,
        has_totp: entry.totp_secret.is_some(),
    }
}

fn entry_to_passkey_summary(entry: &Entry) -> Option<PasskeySummaryBrowser> {
    if let Credential::Passkey(pk) = &entry.credential {
        Some(PasskeySummaryBrowser {
            id: entry.id,
            credential_id: pk.credential_id.clone(),
            rp_id: pk.rp_id.clone(),
            rp_name: pk.rp_name.clone(),
            user_name: pk.user_name.clone(),
            user_handle: pk.user_handle.clone(),
            algorithm: match pk.algorithm {
                PasskeyAlgorithm::Es256 => "es256".to_string(),
                PasskeyAlgorithm::EdDsa => "eddsa".to_string(),
            },
        })
    } else {
        None
    }
}

fn entry_to_detail(entry: &Entry) -> CredentialDetail {
    let (username, password, url) = match &entry.credential {
        Credential::Login(login) => {
            (login.username.clone(), login.password.clone(), login.url.clone())
        }
        Credential::ApiKey(key) => (key.service.clone(), key.secret.clone(), String::new()),
        _ => (String::new(), String::new(), String::new()),
    };
    CredentialDetail {
        id: entry.id,
        title: entry.title.clone(),
        username,
        password,
        url,
        totp_code: None,
    }
}

// ---- Daemon-connected request handlers ----

fn handle_status(client: &mut DaemonClient) -> BrowserResponse {
    match client.send(&Request::Status) {
        Ok(Response::Ok { data }) => match *data {
            ResponseData::Status(status) => BrowserResponse::ok(BrowserData::Status {
                locked: status.locked,
                version: env!("CARGO_PKG_VERSION").to_string(),
            }),
            _ => BrowserResponse::ok(BrowserData::Status {
                locked: false,
                version: env!("CARGO_PKG_VERSION").to_string(),
            }),
        },
        Ok(Response::Error { message }) => BrowserResponse::ok(BrowserData::Status {
            locked: true,
            version: format!("{} ({})", env!("CARGO_PKG_VERSION"), message),
        }),
        Err(e) => BrowserResponse::error(format!("Daemon error: {}", e)),
    }
}

fn handle_search(client: &mut DaemonClient, query: &str) -> BrowserResponse {
    match client.send(&Request::Search { query: query.to_string() }) {
        Ok(Response::Ok { data }) => match *data {
            ResponseData::Entries(entries) => {
                let summaries: Vec<CredentialSummary> =
                    entries.iter().map(entry_to_summary).collect();
                BrowserResponse::ok(BrowserData::Credentials(summaries))
            }
            _ => BrowserResponse::ok(BrowserData::Credentials(vec![])),
        },
        Ok(Response::Error { message }) => BrowserResponse::error(message),
        Err(e) => BrowserResponse::error(format!("Search failed: {}", e)),
    }
}

fn handle_get(client: &mut DaemonClient, id: &EntryId) -> BrowserResponse {
    match client.send(&Request::Get { id: *id }) {
        Ok(Response::Ok { data }) => match *data {
            ResponseData::Entry(entry) => {
                BrowserResponse::ok(BrowserData::Credential(entry_to_detail(&entry)))
            }
            _ => BrowserResponse::error("Unexpected response"),
        },
        Ok(Response::Error { message }) => BrowserResponse::error(message),
        Err(e) => BrowserResponse::error(format!("Get failed: {}", e)),
    }
}

fn handle_save(
    client: &mut DaemonClient,
    title: &str,
    url: &str,
    username: &str,
    password: &str,
) -> BrowserResponse {
    let entry = Entry::new(
        title.to_string(),
        Credential::Login(LoginCredential {
            url: url.to_string(),
            username: username.to_string(),
            password: password.to_string(),
        }),
    );
    let id = entry.id;
    match client.send(&Request::Add { entry }) {
        Ok(Response::Ok { .. }) => BrowserResponse::ok(BrowserData::Saved { id }),
        Ok(Response::Error { message }) => BrowserResponse::error(message),
        Err(e) => BrowserResponse::error(format!("Save failed: {}", e)),
    }
}

fn handle_totp(client: &mut DaemonClient, id: &EntryId) -> BrowserResponse {
    match client.send(&Request::Totp { id: *id }) {
        Ok(Response::Ok { data }) => match *data {
            ResponseData::Totp(totp) => BrowserResponse::ok(BrowserData::Totp {
                code: totp.code,
                seconds_remaining: totp.seconds_remaining,
            }),
            _ => BrowserResponse::error("Unexpected response"),
        },
        Ok(Response::Error { message }) => BrowserResponse::error(message),
        Err(e) => BrowserResponse::error(format!("TOTP failed: {}", e)),
    }
}

fn handle_lock(client: &mut DaemonClient) -> BrowserResponse {
    match client.send(&Request::Lock) {
        Ok(Response::Ok { .. }) => BrowserResponse::ok(BrowserData::None),
        Ok(Response::Error { message }) => BrowserResponse::error(message),
        Err(e) => BrowserResponse::error(format!("Lock failed: {}", e)),
    }
}

fn handle_passkey_list(client: &mut DaemonClient, rp_id: &str) -> BrowserResponse {
    match client.send(&Request::Search {
        query: rp_id.to_string(),
    }) {
        Ok(Response::Ok { data }) => match *data {
            ResponseData::Entries(entries) => {
                let passkeys: Vec<PasskeySummaryBrowser> = entries
                    .iter()
                    .filter_map(entry_to_passkey_summary)
                    .filter(|pk| pk.rp_id == rp_id)
                    .collect();
                BrowserResponse::ok(BrowserData::PasskeyList(passkeys))
            }
            _ => BrowserResponse::ok(BrowserData::PasskeyList(vec![])),
        },
        Ok(Response::Error { message }) => BrowserResponse::error(message),
        Err(e) => BrowserResponse::error(format!("Passkey list failed: {}", e)),
    }
}

fn handle_passkey_create(
    client: &mut DaemonClient,
    rp_id: &str,
    rp_name: &str,
    user_handle: &str,
    user_name: &str,
    algorithm_str: &str,
) -> BrowserResponse {
    let algorithm = match algorithm_str {
        "eddsa" | "ed25519" => PasskeyAlgorithm::EdDsa,
        _ => PasskeyAlgorithm::Es256,
    };

    let key_pair = match generate_passkey_credential(&algorithm) {
        Ok(kp) => kp,
        Err(e) => return BrowserResponse::error(format!("Key generation failed: {}", e)),
    };

    let passkey = PasskeyCredential {
        credential_id: key_pair.credential_id.clone(),
        rp_id: rp_id.to_string(),
        rp_name: rp_name.to_string(),
        user_handle: user_handle.to_string(),
        user_name: user_name.to_string(),
        private_key: key_pair.cose_private_key,
        algorithm,
        sign_count: 0,
        discoverable: true,
        backup_eligible: true,
        backup_state: false,
        last_used_at: None,
    };

    let entry = Entry::new(
        format!("{} ({})", rp_name, user_name),
        Credential::Passkey(passkey),
    );
    let id = entry.id;
    let credential_id = key_pair.credential_id;

    match client.send(&Request::Add { entry }) {
        Ok(Response::Ok { .. }) => {
            BrowserResponse::ok(BrowserData::PasskeyCreated { id, credential_id })
        }
        Ok(Response::Error { message }) => BrowserResponse::error(message),
        Err(e) => BrowserResponse::error(format!("Save passkey failed: {}", e)),
    }
}

fn handle_passkey_assert(
    client: &mut DaemonClient,
    credential_id: &str,
    client_data_json: &str,
    user_verified: bool,
) -> BrowserResponse {
    // Search for the passkey by credential_id
    match client.send(&Request::Search {
        query: credential_id.to_string(),
    }) {
        Ok(Response::Ok { data }) => match *data {
            ResponseData::Entries(entries) => {
                let passkey_entry = entries.iter().find(|e| {
                    matches!(&e.credential, Credential::Passkey(pk) if pk.credential_id == credential_id)
                });

                let Some(entry) = passkey_entry else {
                    return BrowserResponse::error("Passkey not found");
                };

                let Credential::Passkey(ref pk) = entry.credential else {
                    return BrowserResponse::error("Not a passkey");
                };

                let input = AssertionInput {
                    rp_id: pk.rp_id.clone(),
                    client_data_json: client_data_json.to_string(),
                    cose_private_key: pk.private_key.clone(),
                    sign_count: pk.sign_count + 1,
                    user_handle: pk.user_handle.clone(),
                    user_verified,
                };

                match build_assertion_response(&input) {
                    Ok(assertion) => BrowserResponse::ok(BrowserData::PasskeyAssertion {
                        credential_id: pk.credential_id.clone(),
                        authenticator_data: assertion.authenticator_data,
                        signature: assertion.signature,
                        user_handle: assertion.user_handle,
                        client_data_json: assertion.client_data_json,
                    }),
                    Err(e) => BrowserResponse::error(format!("Assertion failed: {}", e)),
                }
            }
            _ => BrowserResponse::error("Passkey not found"),
        },
        Ok(Response::Error { message }) => BrowserResponse::error(message),
        Err(e) => BrowserResponse::error(format!("Passkey assert failed: {}", e)),
    }
}

/// Handle a browser extension request.
/// If `client` is `Some`, requests are forwarded to the running daemon.
/// If `None`, only password generation works; other requests return errors.
pub fn handle_browser_request(
    client: Option<&mut DaemonClient>,
    request: &BrowserRequest,
) -> BrowserResponse {
    // Password generation doesn't need daemon
    if let BrowserRequest::GeneratePassword { length } = request {
        let len = length.unwrap_or(24);
        return BrowserResponse::ok(BrowserData::Password(crate::config::generate_password(len)));
    }

    let Some(client) = client else {
        return match request {
            BrowserRequest::Status => BrowserResponse::ok(BrowserData::Status {
                locked: true,
                version: env!("CARGO_PKG_VERSION").to_string(),
            }),
            BrowserRequest::Search { .. } => {
                BrowserResponse::ok(BrowserData::Credentials(vec![]))
            }
            BrowserRequest::PasskeyList { .. } => {
                BrowserResponse::ok(BrowserData::PasskeyList(vec![]))
            }
            _ => BrowserResponse::error("Daemon not connected"),
        };
    };

    match request {
        BrowserRequest::Status => handle_status(client),
        BrowserRequest::Search { query } => handle_search(client, query),
        BrowserRequest::GetCredential { id } => handle_get(client, id),
        BrowserRequest::SaveCredential {
            title,
            url,
            username,
            password,
        } => handle_save(client, title, url, username, password),
        BrowserRequest::GetTotp { id } => handle_totp(client, id),
        BrowserRequest::Lock => handle_lock(client),
        BrowserRequest::PasskeyList { rp_id } => handle_passkey_list(client, rp_id),
        BrowserRequest::PasskeyCreate {
            rp_id,
            rp_name,
            user_handle,
            user_name,
            algorithm,
        } => handle_passkey_create(client, rp_id, rp_name, user_handle, user_name, algorithm),
        BrowserRequest::PasskeyAssert {
            credential_id,
            client_data_json,
            user_verified,
        } => handle_passkey_assert(client, credential_id, client_data_json, *user_verified),
        BrowserRequest::GeneratePassword { .. } => unreachable!(),
    }
}

/// Run the native messaging host loop with custom reader/writer.
/// If `client` contains a `Some(DaemonClient)`, daemon operations are available.
pub fn run_native_host_with<R: std::io::Read, W: std::io::Write>(
    client: &mut Option<DaemonClient>,
    reader: &mut R,
    writer: &mut W,
) -> std::io::Result<()> {
    use super::native_messaging::{read_json, write_json};

    loop {
        let request: Option<BrowserRequest> = read_json(reader)?;
        match request {
            Some(req) => {
                let response = handle_browser_request(client.as_mut(), &req);
                write_json(writer, &response)?;
            }
            None => break,
        }
    }
    Ok(())
}

#[rustfmt::skip]
/// Run the native messaging host loop (reads from stdin, writes to stdout).
/// Connects to the daemon via Unix socket if available.
pub fn run_native_host() -> std::io::Result<()> {
    let config = crate::config::AppConfig::load();
    let mut client = DaemonClient::try_connect(&config.socket_path);
    let (i, o) = (std::io::stdin(), std::io::stdout());
    run_native_host_with(&mut client, &mut i.lock(), &mut o.lock())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expect_browser_status(resp: BrowserResponse) -> (bool, String) {
        match resp {
            BrowserResponse::Ok { data: BrowserData::Status { locked, version } } => (locked, version),
            other => panic!("Expected Status, got: {:?}", other),
        }
    }

    fn expect_browser_password(resp: BrowserResponse) -> String {
        match resp {
            BrowserResponse::Ok { data: BrowserData::Password(pw) } => pw,
            other => panic!("Expected Password, got: {:?}", other),
        }
    }

    fn expect_browser_credentials(resp: BrowserResponse) -> Vec<CredentialSummary> {
        match resp {
            BrowserResponse::Ok { data: BrowserData::Credentials(c) } => c,
            other => panic!("Expected Credentials, got: {:?}", other),
        }
    }

    fn expect_browser_error(resp: BrowserResponse) -> String {
        match resp {
            BrowserResponse::Error { message } => message,
            other => panic!("Expected Error, got: {:?}", other),
        }
    }

    // ---- Tests without daemon (client = None) ----

    #[test]
    fn test_status_request_no_daemon() {
        let resp = handle_browser_request(None, &BrowserRequest::Status);
        let (locked, version) = expect_browser_status(resp);
        assert!(locked); // locked when no daemon
        assert!(!version.is_empty());
    }

    #[test]
    fn test_generate_password_default() {
        let resp = handle_browser_request(None, &BrowserRequest::GeneratePassword { length: None });
        let pw = expect_browser_password(resp);
        assert_eq!(pw.len(), 24);
    }

    #[test]
    fn test_generate_password_custom_length() {
        let resp = handle_browser_request(None, &BrowserRequest::GeneratePassword { length: Some(32) });
        let pw = expect_browser_password(resp);
        assert_eq!(pw.len(), 32);
    }

    #[test]
    fn test_search_no_daemon() {
        let resp = handle_browser_request(None, &BrowserRequest::Search {
            query: "github".to_string(),
        });
        let creds = expect_browser_credentials(resp);
        assert!(creds.is_empty());
    }

    #[test]
    fn test_get_credential_no_daemon() {
        let resp = handle_browser_request(None, &BrowserRequest::GetCredential {
            id: uuid::Uuid::new_v4(),
        });
        assert!(matches!(resp, BrowserResponse::Error { .. }));
    }

    #[test]
    fn test_save_credential_no_daemon() {
        let resp = handle_browser_request(None, &BrowserRequest::SaveCredential {
            title: "Test".to_string(),
            url: "https://test.com".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
        });
        assert!(matches!(resp, BrowserResponse::Error { .. }));
    }

    #[test]
    fn test_totp_no_daemon() {
        let resp = handle_browser_request(None, &BrowserRequest::GetTotp {
            id: uuid::Uuid::new_v4(),
        });
        assert!(matches!(resp, BrowserResponse::Error { .. }));
    }

    #[test]
    fn test_lock_no_daemon() {
        let resp = handle_browser_request(None, &BrowserRequest::Lock);
        assert!(matches!(resp, BrowserResponse::Error { .. }));
    }

    // ---- Serialization tests ----

    #[test]
    fn test_request_serialization() {
        let req = BrowserRequest::Search {
            query: "test".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("search"));
        let parsed: BrowserRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, BrowserRequest::Search { query } if query == "test"));
    }

    #[test]
    fn test_response_serialization() {
        let resp = BrowserResponse::ok(BrowserData::Password("abc123".to_string()));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("abc123"));
    }

    #[test]
    fn test_all_request_variants_serialize() {
        let requests: Vec<BrowserRequest> = vec![
            BrowserRequest::Status,
            BrowserRequest::Search { query: "x".into() },
            BrowserRequest::GetCredential { id: uuid::Uuid::new_v4() },
            BrowserRequest::GeneratePassword { length: Some(16) },
            BrowserRequest::SaveCredential {
                title: "t".into(),
                url: "u".into(),
                username: "n".into(),
                password: "p".into(),
            },
            BrowserRequest::GetTotp { id: uuid::Uuid::new_v4() },
            BrowserRequest::Lock,
            BrowserRequest::PasskeyList { rp_id: "example.com".into() },
            BrowserRequest::PasskeyCreate {
                rp_id: "example.com".into(),
                rp_name: "Example".into(),
                user_handle: "dXNlcjE".into(),
                user_name: "user@example.com".into(),
                algorithm: "es256".into(),
            },
            BrowserRequest::PasskeyAssert {
                credential_id: "cred123".into(),
                client_data_json: "Y2xpZW50RGF0YQ".into(),
                user_verified: true,
            },
        ];
        for req in requests {
            let json = serde_json::to_string(&req).unwrap();
            assert!(!json.is_empty());
        }
    }

    #[test]
    fn test_credential_summary_serialization() {
        let summary = CredentialSummary {
            id: uuid::Uuid::new_v4(),
            title: "GitHub".to_string(),
            username: "octocat".to_string(),
            url: "https://github.com".to_string(),
            has_totp: true,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let parsed: CredentialSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.title, "GitHub");
        assert!(parsed.has_totp);
    }

    #[test]
    fn test_credential_detail_serialization() {
        let detail = CredentialDetail {
            id: uuid::Uuid::new_v4(),
            title: "GitHub".to_string(),
            username: "octocat".to_string(),
            password: "secret".to_string(),
            url: "https://github.com".to_string(),
            totp_code: Some("123456".to_string()),
        };
        let json = serde_json::to_string(&detail).unwrap();
        let parsed: CredentialDetail = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.username, "octocat");
        assert_eq!(parsed.totp_code, Some("123456".to_string()));
    }

    #[test]
    fn test_response_error_serialization() {
        let resp = BrowserResponse::error("something failed");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("something failed"));
        let parsed: BrowserResponse = serde_json::from_str(&json).unwrap();
        let msg = expect_browser_error(parsed);
        assert_eq!(msg, "something failed");
    }

    #[test]
    fn test_browser_data_none() {
        let resp = BrowserResponse::ok(BrowserData::None);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("ok"));
    }

    #[test]
    fn test_browser_data_status() {
        let resp = BrowserResponse::ok(BrowserData::Status {
            locked: true,
            version: "0.1.0".to_string(),
        });
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("locked"));
    }

    #[test]
    fn test_browser_data_totp() {
        let resp = BrowserResponse::ok(BrowserData::Totp {
            code: "123456".to_string(),
            seconds_remaining: 15,
        });
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("123456"));
    }

    #[test]
    fn test_browser_data_saved() {
        let resp = BrowserResponse::ok(BrowserData::Saved {
            id: uuid::Uuid::new_v4(),
        });
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.is_empty());
    }

    #[test]
    fn test_entry_to_passkey_summary_eddsa() {
        use crate::vault::entry::{PasskeyAlgorithm, PasskeyCredential};
        let entry = Entry::new(
            "EdDSA Passkey".to_string(),
            Credential::Passkey(PasskeyCredential {
                credential_id: "ed_cred".to_string(),
                rp_id: "ed.example.com".to_string(),
                rp_name: "Ed Example".to_string(),
                user_handle: "dXNlcg".to_string(),
                user_name: "ed_user".to_string(),
                private_key: "ed_key".to_string(),
                algorithm: PasskeyAlgorithm::EdDsa,
                sign_count: 0,
                discoverable: true,
                backup_eligible: false,
                backup_state: false,
                last_used_at: None,
            }),
        );
        let summary = entry_to_passkey_summary(&entry).unwrap();
        assert_eq!(summary.algorithm, "eddsa");
        assert_eq!(summary.rp_id, "ed.example.com");
    }

    #[test]
    fn test_native_host_roundtrip() {
        use super::super::native_messaging::{read_json, write_json};
        use std::io::Cursor;

        let req = BrowserRequest::GeneratePassword { length: Some(16) };
        let mut buf = Vec::new();
        write_json(&mut buf, &req).unwrap();

        let mut reader = Cursor::new(buf);
        let parsed: BrowserRequest = read_json(&mut reader).unwrap().unwrap();
        let resp = handle_browser_request(None, &parsed);
        let pw = expect_browser_password(resp);
        assert_eq!(pw.len(), 16);
    }

    #[test]
    fn test_native_host_loop_simulation() {
        use super::super::native_messaging::{read_json, write_json};
        use std::io::Cursor;

        let mut input_buf = Vec::new();
        write_json(&mut input_buf, &BrowserRequest::Status).unwrap();
        write_json(&mut input_buf, &BrowserRequest::GeneratePassword { length: Some(8) }).unwrap();
        write_json(&mut input_buf, &BrowserRequest::Lock).unwrap();

        let mut reader = Cursor::new(input_buf);
        let mut output_buf = Vec::new();

        loop {
            let request: Option<BrowserRequest> = read_json(&mut reader).unwrap();
            match request {
                Some(req) => {
                    let response = handle_browser_request(None, &req);
                    write_json(&mut output_buf, &response).unwrap();
                }
                None => break,
            }
        }

        let mut out_reader = Cursor::new(output_buf);
        let resp1: BrowserResponse = read_json(&mut out_reader).unwrap().unwrap();
        assert!(matches!(resp1, BrowserResponse::Ok { data: BrowserData::Status { .. } }));

        let resp2: BrowserResponse = read_json(&mut out_reader).unwrap().unwrap();
        let pw = expect_browser_password(resp2);
        assert_eq!(pw.len(), 8);

        let resp3: BrowserResponse = read_json(&mut out_reader).unwrap().unwrap();
        assert!(matches!(resp3, BrowserResponse::Error { .. }));

        let eof: Option<BrowserResponse> = read_json(&mut out_reader).unwrap();
        assert!(eof.is_none());
    }

    #[test]
    fn test_browser_data_credential() {
        let detail = CredentialDetail {
            id: uuid::Uuid::new_v4(),
            title: "Test".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
            url: "https://example.com".to_string(),
            totp_code: None,
        };
        let resp = BrowserResponse::ok(BrowserData::Credential(detail));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("example.com"));
    }

    #[test]
    fn test_run_native_host_with_no_daemon() {
        use super::super::native_messaging::write_json;
        use std::io::Cursor;

        let mut input_buf = Vec::new();
        write_json(&mut input_buf, &BrowserRequest::Status).unwrap();
        write_json(&mut input_buf, &BrowserRequest::GeneratePassword { length: Some(12) }).unwrap();

        let mut reader = Cursor::new(input_buf);
        let mut output_buf = Vec::new();

        run_native_host_with(&mut None, &mut reader, &mut output_buf).unwrap();

        let mut out_reader = Cursor::new(output_buf);
        use super::super::native_messaging::read_json;
        let resp1: BrowserResponse = read_json(&mut out_reader).unwrap().unwrap();
        let (locked, version) = expect_browser_status(resp1);
        assert!(locked);
        assert!(!version.is_empty());

        let resp2: BrowserResponse = read_json(&mut out_reader).unwrap().unwrap();
        let pw = expect_browser_password(resp2);
        assert_eq!(pw.len(), 12);
    }

    #[test]
    #[should_panic(expected = "Expected Status")]
    fn test_expect_browser_status_wrong() {
        expect_browser_status(BrowserResponse::error("wrong"));
    }

    #[test]
    #[should_panic(expected = "Expected Password")]
    fn test_expect_browser_password_wrong() {
        expect_browser_password(BrowserResponse::error("wrong"));
    }

    #[test]
    #[should_panic(expected = "Expected Credentials")]
    fn test_expect_browser_credentials_wrong() {
        expect_browser_credentials(BrowserResponse::error("wrong"));
    }

    #[test]
    #[should_panic(expected = "Expected Error")]
    fn test_expect_browser_error_wrong() {
        expect_browser_error(BrowserResponse::ok(BrowserData::None));
    }

    #[test]
    fn test_run_native_host_with_read_error() {
        struct FailingReader;
        impl std::io::Read for FailingReader {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "broken"))
            }
        }
        let mut reader = FailingReader;
        let mut output = Vec::new();
        let result = run_native_host_with(&mut None, &mut reader, &mut output);
        assert!(result.is_err());
    }

    #[test]
    fn test_run_native_host_with_write_error() {
        use crate::browser::native_messaging::write_json;
        use std::io::Write as _;
        struct FailingWriter;
        impl std::io::Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "broken"))
            }
            fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
        }
        let mut input_buf = Vec::new();
        write_json(&mut input_buf, &BrowserRequest::Status).unwrap();
        let mut reader = std::io::Cursor::new(input_buf);
        let mut writer = FailingWriter;
        let _ = writer.flush();
        let result = run_native_host_with(&mut None, &mut reader, &mut writer);
        assert!(result.is_err());
    }

    // ---- Entry conversion tests ----

    #[test]
    fn test_entry_to_summary_login() {
        let entry = Entry::new(
            "GitHub".to_string(),
            Credential::Login(LoginCredential {
                url: "https://github.com".to_string(),
                username: "octocat".to_string(),
                password: "secret".to_string(),
            }),
        );
        let summary = entry_to_summary(&entry);
        assert_eq!(summary.title, "GitHub");
        assert_eq!(summary.username, "octocat");
        assert_eq!(summary.url, "https://github.com");
        assert!(!summary.has_totp);
    }

    #[test]
    fn test_entry_to_summary_api_key() {
        let entry = Entry::new(
            "AWS".to_string(),
            Credential::ApiKey(crate::vault::entry::ApiKeyCredential {
                service: "AWS".to_string(),
                key: "AKIA...".to_string(),
                secret: "secret".to_string(),
            }),
        );
        let summary = entry_to_summary(&entry);
        assert_eq!(summary.username, "AWS");
        assert!(summary.url.is_empty());
    }

    #[test]
    fn test_entry_to_summary_secure_note() {
        let entry = Entry::new(
            "Note".to_string(),
            Credential::SecureNote(crate::vault::entry::SecureNoteCredential {
                content: "secret note".to_string(),
            }),
        );
        let summary = entry_to_summary(&entry);
        assert!(summary.username.is_empty());
        assert!(summary.url.is_empty());
    }

    #[test]
    fn test_entry_to_detail_login() {
        let entry = Entry::new(
            "GitHub".to_string(),
            Credential::Login(LoginCredential {
                url: "https://github.com".to_string(),
                username: "octocat".to_string(),
                password: "secret123".to_string(),
            }),
        );
        let detail = entry_to_detail(&entry);
        assert_eq!(detail.title, "GitHub");
        assert_eq!(detail.username, "octocat");
        assert_eq!(detail.password, "secret123");
        assert_eq!(detail.url, "https://github.com");
        assert!(detail.totp_code.is_none());
    }

    #[test]
    fn test_entry_to_detail_api_key() {
        let entry = Entry::new(
            "AWS".to_string(),
            Credential::ApiKey(crate::vault::entry::ApiKeyCredential {
                service: "AWS".to_string(),
                key: "AKIA123".to_string(),
                secret: "secretkey".to_string(),
            }),
        );
        let detail = entry_to_detail(&entry);
        assert_eq!(detail.username, "AWS");
        assert_eq!(detail.password, "secretkey");
    }

    // ---- Daemon-connected handler unit tests (mock daemon) ----

    #[tokio::test]
    async fn test_handle_status_connected() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
        use tokio::net::UnixListener;

        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("status_test.sock");
        let socket_path_clone = socket_path.clone();

        let server = tokio::spawn(async move {
            let listener = UnixListener::bind(&socket_path_clone).unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = TokioBufReader::new(reader);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();

            let resp = Response::ok(ResponseData::Status(
                crate::daemon::protocol::VaultStatus {
                    locked: false,
                    entry_count: 5,
                    vault_path: "/tmp/test.vclaw".to_string(),
                },
            ));
            let json = serde_json::to_string(&resp).unwrap();
            writer.write_all(json.as_bytes()).await.unwrap();
            writer.write_all(b"\n").await.unwrap();
            writer.flush().await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let sp = socket_path.clone();
        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_status(&mut client);
            let (locked, version) = expect_browser_status(resp);
            assert!(!locked);
            assert!(!version.is_empty());
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_search_connected() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
        use tokio::net::UnixListener;

        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("search_test.sock");
        let socket_path_clone = socket_path.clone();

        let server = tokio::spawn(async move {
            let listener = UnixListener::bind(&socket_path_clone).unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = TokioBufReader::new(reader);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();

            let entries = vec![Entry::new(
                "GitHub".to_string(),
                Credential::Login(LoginCredential {
                    url: "https://github.com".to_string(),
                    username: "octocat".to_string(),
                    password: "secret".to_string(),
                }),
            )];
            let resp = Response::ok(ResponseData::Entries(entries));
            let json = serde_json::to_string(&resp).unwrap();
            writer.write_all(json.as_bytes()).await.unwrap();
            writer.write_all(b"\n").await.unwrap();
            writer.flush().await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let sp = socket_path.clone();
        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_search(&mut client, "github");
            let creds = expect_browser_credentials(resp);
            assert_eq!(creds.len(), 1);
            assert_eq!(creds[0].title, "GitHub");
            assert_eq!(creds[0].username, "octocat");
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_lock_connected() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
        use tokio::net::UnixListener;

        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("lock_test.sock");
        let socket_path_clone = socket_path.clone();

        let server = tokio::spawn(async move {
            let listener = UnixListener::bind(&socket_path_clone).unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = TokioBufReader::new(reader);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();

            let resp = Response::ok(ResponseData::None);
            let json = serde_json::to_string(&resp).unwrap();
            writer.write_all(json.as_bytes()).await.unwrap();
            writer.write_all(b"\n").await.unwrap();
            writer.flush().await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let sp = socket_path.clone();
        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_lock(&mut client);
            assert!(matches!(resp, BrowserResponse::Ok { .. }));
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_get_connected() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
        use tokio::net::UnixListener;

        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("get_test.sock");
        let socket_path_clone = socket_path.clone();
        let entry = Entry::new(
            "GitHub".to_string(),
            Credential::Login(LoginCredential {
                url: "https://github.com".to_string(),
                username: "octocat".to_string(),
                password: "secret".to_string(),
            }),
        );
        let entry_id = entry.id;

        let server = tokio::spawn(async move {
            let listener = UnixListener::bind(&socket_path_clone).unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = TokioBufReader::new(reader);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();

            let resp = Response::ok(ResponseData::Entry(entry));
            let json = serde_json::to_string(&resp).unwrap();
            writer.write_all(json.as_bytes()).await.unwrap();
            writer.write_all(b"\n").await.unwrap();
            writer.flush().await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let sp = socket_path.clone();
        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_get(&mut client, &entry_id);
            match resp {
                BrowserResponse::Ok { data: BrowserData::Credential(detail) } => {
                    assert_eq!(detail.username, "octocat");
                    assert_eq!(detail.password, "secret");
                }
                other => panic!("Expected Credential, got: {:?}", other),
            }
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_totp_connected() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
        use tokio::net::UnixListener;

        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("totp_test.sock");
        let socket_path_clone = socket_path.clone();

        let server = tokio::spawn(async move {
            let listener = UnixListener::bind(&socket_path_clone).unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = TokioBufReader::new(reader);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();

            let resp = Response::ok(ResponseData::Totp(crate::daemon::protocol::TotpResponse {
                code: "654321".to_string(),
                seconds_remaining: 20,
            }));
            let json = serde_json::to_string(&resp).unwrap();
            writer.write_all(json.as_bytes()).await.unwrap();
            writer.write_all(b"\n").await.unwrap();
            writer.flush().await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let sp = socket_path.clone();
        let id = uuid::Uuid::new_v4();
        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_totp(&mut client, &id);
            match resp {
                BrowserResponse::Ok { data: BrowserData::Totp { code, seconds_remaining } } => {
                    assert_eq!(code, "654321");
                    assert_eq!(seconds_remaining, 20);
                }
                other => panic!("Expected Totp, got: {:?}", other),
            }
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_save_connected() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
        use tokio::net::UnixListener;

        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("save_test.sock");
        let socket_path_clone = socket_path.clone();

        let server = tokio::spawn(async move {
            let listener = UnixListener::bind(&socket_path_clone).unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = TokioBufReader::new(reader);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();

            let resp = Response::ok(ResponseData::Id(uuid::Uuid::new_v4()));
            let json = serde_json::to_string(&resp).unwrap();
            writer.write_all(json.as_bytes()).await.unwrap();
            writer.write_all(b"\n").await.unwrap();
            writer.flush().await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let sp = socket_path.clone();
        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_save(&mut client, "Test", "https://test.com", "user", "pass");
            assert!(matches!(resp, BrowserResponse::Ok { data: BrowserData::Saved { .. } }));
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    // ---- Passkey tests ----

    #[test]
    fn test_passkey_list_no_daemon() {
        let resp = handle_browser_request(None, &BrowserRequest::PasskeyList {
            rp_id: "example.com".into(),
        });
        match resp {
            BrowserResponse::Ok { data: BrowserData::PasskeyList(list) } => {
                assert!(list.is_empty());
            }
            other => panic!("Expected PasskeyList, got: {:?}", other),
        }
    }

    #[test]
    fn test_passkey_create_no_daemon() {
        let resp = handle_browser_request(None, &BrowserRequest::PasskeyCreate {
            rp_id: "example.com".into(),
            rp_name: "Example".into(),
            user_handle: "dXNlcjE".into(),
            user_name: "user@example.com".into(),
            algorithm: "es256".into(),
        });
        assert!(matches!(resp, BrowserResponse::Error { .. }));
    }

    #[test]
    fn test_passkey_assert_no_daemon() {
        let resp = handle_browser_request(None, &BrowserRequest::PasskeyAssert {
            credential_id: "cred123".into(),
            client_data_json: "Y2xpZW50RGF0YQ".into(),
            user_verified: false,
        });
        assert!(matches!(resp, BrowserResponse::Error { .. }));
    }

    #[test]
    fn test_passkey_request_serialization() {
        let req = BrowserRequest::PasskeyCreate {
            rp_id: "example.com".to_string(),
            rp_name: "Example".to_string(),
            user_handle: "dXNlcjE".to_string(),
            user_name: "user@example.com".to_string(),
            algorithm: "es256".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("passkey_create"));
        assert!(json.contains("example.com"));
        let parsed: BrowserRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, BrowserRequest::PasskeyCreate { rp_id, .. } if rp_id == "example.com"));
    }

    #[test]
    fn test_passkey_assert_request_serialization() {
        let req = BrowserRequest::PasskeyAssert {
            credential_id: "abc123".to_string(),
            client_data_json: "Y2xpZW50RGF0YQ".to_string(),
            user_verified: true,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("passkey_assert"));
        let parsed: BrowserRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, BrowserRequest::PasskeyAssert { user_verified: true, .. }));
    }

    #[test]
    fn test_passkey_list_request_serialization() {
        let req = BrowserRequest::PasskeyList {
            rp_id: "google.com".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("passkey_list"));
        let parsed: BrowserRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, BrowserRequest::PasskeyList { rp_id } if rp_id == "google.com"));
    }

    #[test]
    fn test_passkey_summary_browser_serialization() {
        let summary = PasskeySummaryBrowser {
            id: uuid::Uuid::new_v4(),
            credential_id: "cred123".to_string(),
            rp_id: "example.com".to_string(),
            rp_name: "Example Site".to_string(),
            user_name: "user@example.com".to_string(),
            user_handle: "dXNlcjE".to_string(),
            algorithm: "es256".to_string(),
        };
        let json = serde_json::to_string(&summary).unwrap();
        let parsed: PasskeySummaryBrowser = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.rp_id, "example.com");
        assert_eq!(parsed.user_name, "user@example.com");
    }

    #[test]
    fn test_browser_data_passkey_list() {
        let resp = BrowserResponse::ok(BrowserData::PasskeyList(vec![
            PasskeySummaryBrowser {
                id: uuid::Uuid::new_v4(),
                credential_id: "cred1".to_string(),
                rp_id: "example.com".to_string(),
                rp_name: "Example".to_string(),
                user_name: "user1".to_string(),
                user_handle: "dXNlcjE".to_string(),
                algorithm: "es256".to_string(),
            },
        ]));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("example.com"));
        assert!(json.contains("cred1"));
    }

    #[test]
    fn test_browser_data_passkey_created() {
        let resp = BrowserResponse::ok(BrowserData::PasskeyCreated {
            id: uuid::Uuid::new_v4(),
            credential_id: "new_cred_id".to_string(),
        });
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("new_cred_id"));
    }

    #[test]
    fn test_browser_data_passkey_assertion() {
        let resp = BrowserResponse::ok(BrowserData::PasskeyAssertion {
            credential_id: "cred1".to_string(),
            authenticator_data: "authdata_b64".to_string(),
            signature: "sig_b64".to_string(),
            user_handle: "user_b64".to_string(),
            client_data_json: "cdj_b64".to_string(),
        });
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("authdata_b64"));
        assert!(json.contains("sig_b64"));
    }

    #[test]
    fn test_entry_to_passkey_summary_login_returns_none() {
        let entry = Entry::new(
            "GitHub".to_string(),
            Credential::Login(LoginCredential {
                url: "https://github.com".to_string(),
                username: "user".to_string(),
                password: "pass".to_string(),
            }),
        );
        assert!(entry_to_passkey_summary(&entry).is_none());
    }

    #[test]
    fn test_entry_to_passkey_summary_passkey_returns_some() {
        use crate::vault::entry::{PasskeyAlgorithm, PasskeyCredential};
        let entry = Entry::new(
            "Example Passkey".to_string(),
            Credential::Passkey(PasskeyCredential {
                credential_id: "cred_id".to_string(),
                rp_id: "example.com".to_string(),
                rp_name: "Example".to_string(),
                user_handle: "dXNlcjE".to_string(),
                user_name: "user@example.com".to_string(),
                private_key: "key_data".to_string(),
                algorithm: PasskeyAlgorithm::Es256,
                sign_count: 5,
                discoverable: true,
                backup_eligible: true,
                backup_state: false,
                last_used_at: None,
            }),
        );
        let summary = entry_to_passkey_summary(&entry).unwrap();
        assert_eq!(summary.rp_id, "example.com");
        assert_eq!(summary.user_name, "user@example.com");
        assert_eq!(summary.credential_id, "cred_id");
        assert_eq!(summary.algorithm, "es256");
    }

    #[test]
    fn test_passkey_create_default_algorithm() {
        let json = r#"{"action":"passkey_create","rp_id":"example.com","rp_name":"Example","user_handle":"dXNlcjE","user_name":"user@example.com"}"#;
        let req: BrowserRequest = serde_json::from_str(json).unwrap();
        match req {
            BrowserRequest::PasskeyCreate { algorithm, .. } => {
                assert_eq!(algorithm, "es256");
            }
            _ => panic!("Expected PasskeyCreate"),
        }
    }

    #[test]
    fn test_passkey_native_host_roundtrip() {
        use super::super::native_messaging::{read_json, write_json};
        use std::io::Cursor;

        // passkey_list with no daemon returns empty list
        let req = BrowserRequest::PasskeyList { rp_id: "test.com".into() };
        let mut buf = Vec::new();
        write_json(&mut buf, &req).unwrap();

        let mut reader = Cursor::new(buf);
        let parsed: BrowserRequest = read_json(&mut reader).unwrap().unwrap();
        let resp = handle_browser_request(None, &parsed);
        match resp {
            BrowserResponse::Ok { data: BrowserData::PasskeyList(list) } => assert!(list.is_empty()),
            other => panic!("Expected PasskeyList, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_handle_daemon_error_response() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
        use tokio::net::UnixListener;

        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("err_test.sock");
        let socket_path_clone = socket_path.clone();

        let server = tokio::spawn(async move {
            let listener = UnixListener::bind(&socket_path_clone).unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = TokioBufReader::new(reader);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();

            let resp = Response::error("vault locked");
            let json = serde_json::to_string(&resp).unwrap();
            writer.write_all(json.as_bytes()).await.unwrap();
            writer.write_all(b"\n").await.unwrap();
            writer.flush().await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let sp = socket_path.clone();
        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_search(&mut client, "test");
            let msg = expect_browser_error(resp);
            assert_eq!(msg, "vault locked");
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    /// Helper: spawn a mock daemon that reads one request and replies with the given response.
    async fn mock_daemon_one_shot(
        socket_path: &std::path::Path,
        response: Response,
    ) -> tokio::task::JoinHandle<()> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
        use tokio::net::UnixListener;

        let listener = UnixListener::bind(socket_path).unwrap();
        let resp_json = serde_json::to_string(&response).unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = TokioBufReader::new(reader);
            let mut line = String::new();
            let _ = reader.read_line(&mut line).await;
            writer.write_all(resp_json.as_bytes()).await.unwrap();
            writer.write_all(b"\n").await.unwrap();
            writer.flush().await.unwrap();
        })
    }

    #[tokio::test]
    async fn test_handle_status_with_daemon() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("status.sock");
        let sp = socket_path.clone();

        let resp = Response::ok(ResponseData::Status(crate::daemon::protocol::VaultStatus {
            locked: false,
            entry_count: 5,
            vault_path: "/tmp/test.vclaw".to_string(),
        }));
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_status(&mut client);
            let (locked, version) = expect_browser_status(resp);
            assert!(!locked);
            assert!(!version.is_empty());
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_search_with_daemon() {
        use crate::vault::entry::*;
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("search.sock");
        let sp = socket_path.clone();

        let entry = Entry::new(
            "GitHub".to_string(),
            Credential::Login(LoginCredential {
                url: "https://github.com".into(),
                username: "user".into(),
                password: "pass".into(),
            }),
        );
        let resp = Response::ok(ResponseData::Entries(vec![entry]));
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_search(&mut client, "github");
            let creds = expect_browser_credentials(resp);
            assert_eq!(creds.len(), 1);
            assert_eq!(creds[0].title, "GitHub");
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_get_with_daemon() {
        use crate::vault::entry::*;
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("get.sock");
        let sp = socket_path.clone();

        let entry = Entry::new(
            "Test".to_string(),
            Credential::Login(LoginCredential {
                url: "https://test.com".into(),
                username: "u".into(),
                password: "p".into(),
            }),
        );
        let resp = Response::ok(ResponseData::Entry(entry));
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_get(&mut client, &uuid::Uuid::new_v4());
            match resp {
                BrowserResponse::Ok { data: BrowserData::Credential(cred) } => {
                    assert_eq!(cred.title, "Test");
                    assert_eq!(cred.username, "u");
                }
                other => panic!("Expected Credential, got: {:?}", other),
            }
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_save_with_daemon() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("save.sock");
        let sp = socket_path.clone();

        let resp = Response::ok(ResponseData::Id(uuid::Uuid::new_v4()));
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_save(&mut client, "New", "https://new.com", "user", "pass");
            match resp {
                BrowserResponse::Ok { data: BrowserData::Saved { .. } } => {}
                other => panic!("Expected Saved, got: {:?}", other),
            }
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_totp_with_daemon() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("totp.sock");
        let sp = socket_path.clone();

        let resp = Response::ok(ResponseData::Totp(crate::daemon::protocol::TotpResponse {
            code: "123456".to_string(),
            seconds_remaining: 15,
        }));
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_totp(&mut client, &uuid::Uuid::new_v4());
            match resp {
                BrowserResponse::Ok { data: BrowserData::Totp { code, seconds_remaining } } => {
                    assert_eq!(code, "123456");
                    assert_eq!(seconds_remaining, 15);
                }
                other => panic!("Expected Totp, got: {:?}", other),
            }
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_lock_with_daemon() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("lock.sock");
        let sp = socket_path.clone();

        let resp = Response::ok(ResponseData::None);
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_lock(&mut client);
            assert!(matches!(resp, BrowserResponse::Ok { data: BrowserData::None }));
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_passkey_list_with_daemon() {
        use crate::vault::entry::*;
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("pklist.sock");
        let sp = socket_path.clone();

        let entry = Entry::new(
            "Passkey".to_string(),
            Credential::Passkey(PasskeyCredential {
                credential_id: "cred1".into(),
                rp_id: "example.com".into(),
                rp_name: "Example".into(),
                user_handle: "uh".into(),
                user_name: "alice".into(),
                private_key: "pk".into(),
                algorithm: PasskeyAlgorithm::Es256,
                sign_count: 0,
                discoverable: true,
                backup_eligible: false,
                backup_state: false,
                last_used_at: None,
            }),
        );
        let resp = Response::ok(ResponseData::Entries(vec![entry]));
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_passkey_list(&mut client, "example.com");
            match resp {
                BrowserResponse::Ok { data: BrowserData::PasskeyList(list) } => {
                    assert_eq!(list.len(), 1);
                    assert_eq!(list[0].rp_id, "example.com");
                }
                other => panic!("Expected PasskeyList, got: {:?}", other),
            }
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_passkey_create_with_daemon() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("pkcreate.sock");
        let sp = socket_path.clone();

        let resp = Response::ok(ResponseData::Id(uuid::Uuid::new_v4()));
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_passkey_create(
                &mut client,
                "example.com",
                "Example",
                "dXNlcg",
                "alice",
                "es256",
            );
            match resp {
                BrowserResponse::Ok { data: BrowserData::PasskeyCreated { .. } } => {}
                other => panic!("Expected PasskeyCreated, got: {:?}", other),
            }
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_passkey_create_eddsa() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("pkcreate_eddsa.sock");
        let sp = socket_path.clone();

        let resp = Response::ok(ResponseData::Id(uuid::Uuid::new_v4()));
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_passkey_create(
                &mut client,
                "eddsa-site.com",
                "EdDSA Site",
                "dXNlcg",
                "bob",
                "eddsa",
            );
            match resp {
                BrowserResponse::Ok { data: BrowserData::PasskeyCreated { .. } } => {}
                other => panic!("Expected PasskeyCreated, got: {:?}", other),
            }
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_browser_request_dispatch_with_daemon() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("dispatch.sock");
        let sp = socket_path.clone();

        let resp = Response::ok(ResponseData::Status(crate::daemon::protocol::VaultStatus {
            locked: false,
            entry_count: 3,
            vault_path: "/tmp/test.vclaw".to_string(),
        }));
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_browser_request(Some(&mut client), &BrowserRequest::Status);
            let (locked, _) = expect_browser_status(resp);
            assert!(!locked);
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    // ---- Additional coverage tests ----

    #[tokio::test]
    async fn test_handle_passkey_assert_with_daemon() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("pk_assert.sock");
        let sp = socket_path.clone();

        // Create a passkey entry that the search will return
        let passkey_cred = PasskeyCredential {
            credential_id: "assert_cred_id".into(),
            rp_id: "assert.example.com".into(),
            rp_name: "Assert Example".into(),
            user_handle: "dXNlcg".into(),
            user_name: "assertuser".into(),
            private_key: String::new(), // We need a real key; let's generate one
            algorithm: PasskeyAlgorithm::Es256,
            sign_count: 0,
            discoverable: true,
            backup_eligible: false,
            backup_state: false,
            last_used_at: None,
        };

        // Generate a real key pair for signing
        let kp = generate_passkey_credential(&PasskeyAlgorithm::Es256).unwrap();
        let mut pk = passkey_cred;
        pk.private_key = kp.cose_private_key;
        pk.credential_id = kp.credential_id.clone();

        let cred_id = pk.credential_id.clone();
        let entry = Entry::new("Assert Passkey".into(), Credential::Passkey(pk));
        let resp = Response::ok(ResponseData::Entries(vec![entry]));
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            use base64::Engine;
            let mut client = DaemonClient::connect(&sp).unwrap();
            let client_data = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                br#"{"type":"webauthn.get","challenge":"test_challenge","origin":"https://assert.example.com"}"#
            );
            let resp = handle_passkey_assert(&mut client, &cred_id, &client_data, true);
            match resp {
                BrowserResponse::Ok { data: BrowserData::PasskeyAssertion { credential_id, .. } } => {
                    assert_eq!(credential_id, cred_id);
                }
                other => panic!("Expected PasskeyAssertion, got: {:?}", other),
            }
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_passkey_assert_not_found() {
        // Daemon returns entries but none match the credential_id
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("pk_assert_nf.sock");
        let sp = socket_path.clone();

        let entry = Entry::new(
            "Login Not Passkey".into(),
            Credential::Login(LoginCredential {
                url: "https://test.com".into(),
                username: "u".into(),
                password: "p".into(),
            }),
        );
        let resp = Response::ok(ResponseData::Entries(vec![entry]));
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_passkey_assert(&mut client, "nonexistent_cred", "cdj", true);
            let msg = expect_browser_error(resp);
            assert!(msg.contains("not found"));
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_passkey_assert_daemon_error() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("pk_assert_err.sock");
        let sp = socket_path.clone();

        let resp = Response::error("vault locked");
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_passkey_assert(&mut client, "cred", "cdj", true);
            let msg = expect_browser_error(resp);
            assert_eq!(msg, "vault locked");
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_passkey_assert_unexpected_response() {
        // Daemon returns OK but with non-Entries data
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("pk_assert_unex.sock");
        let sp = socket_path.clone();

        let resp = Response::ok(ResponseData::None);
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_passkey_assert(&mut client, "cred", "cdj", true);
            let msg = expect_browser_error(resp);
            assert!(msg.contains("not found"));
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_status_error_response() {
        // Daemon returns Error response
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("status_err.sock");
        let sp = socket_path.clone();

        let resp = Response::error("vault locked for maintenance");
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_status(&mut client);
            // Status handler treats Error as locked
            let (locked, version) = expect_browser_status(resp);
            assert!(locked);
            assert!(version.contains("vault locked for maintenance"));
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_status_unexpected_data() {
        // Daemon returns Ok with non-Status data
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("status_unex.sock");
        let sp = socket_path.clone();

        let resp = Response::ok(ResponseData::None);
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_status(&mut client);
            // Falls through to the else branch which returns unlocked
            let (locked, _) = expect_browser_status(resp);
            assert!(!locked);
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_search_unexpected_data() {
        // Daemon returns Ok with non-Entries data
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("search_unex.sock");
        let sp = socket_path.clone();

        let resp = Response::ok(ResponseData::None);
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_search(&mut client, "test");
            let creds = expect_browser_credentials(resp);
            assert!(creds.is_empty());
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_get_unexpected_data() {
        // Daemon returns Ok with non-Entry data
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("get_unex.sock");
        let sp = socket_path.clone();

        let resp = Response::ok(ResponseData::None);
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_get(&mut client, &uuid::Uuid::new_v4());
            let msg = expect_browser_error(resp);
            assert!(msg.contains("Unexpected"));
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_get_error_response() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("get_err.sock");
        let sp = socket_path.clone();

        let resp = Response::error("Entry not found");
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_get(&mut client, &uuid::Uuid::new_v4());
            let msg = expect_browser_error(resp);
            assert_eq!(msg, "Entry not found");
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_totp_unexpected_data() {
        // Daemon returns Ok with non-Totp data
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("totp_unex.sock");
        let sp = socket_path.clone();

        let resp = Response::ok(ResponseData::None);
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_totp(&mut client, &uuid::Uuid::new_v4());
            let msg = expect_browser_error(resp);
            assert!(msg.contains("Unexpected"));
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_totp_error_response() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("totp_err.sock");
        let sp = socket_path.clone();

        let resp = Response::error("No TOTP secret");
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_totp(&mut client, &uuid::Uuid::new_v4());
            let msg = expect_browser_error(resp);
            assert_eq!(msg, "No TOTP secret");
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_lock_error_response() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("lock_err.sock");
        let sp = socket_path.clone();

        let resp = Response::error("Already locked");
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_lock(&mut client);
            let msg = expect_browser_error(resp);
            assert_eq!(msg, "Already locked");
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_save_error_response() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("save_err.sock");
        let sp = socket_path.clone();

        let resp = Response::error("Vault is locked");
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_save(&mut client, "Test", "https://test.com", "u", "p");
            let msg = expect_browser_error(resp);
            assert_eq!(msg, "Vault is locked");
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_passkey_list_error_response() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("pklist_err.sock");
        let sp = socket_path.clone();

        let resp = Response::error("vault locked");
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_passkey_list(&mut client, "example.com");
            let msg = expect_browser_error(resp);
            assert_eq!(msg, "vault locked");
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_passkey_list_unexpected_data() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("pklist_unex.sock");
        let sp = socket_path.clone();

        let resp = Response::ok(ResponseData::None);
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_passkey_list(&mut client, "example.com");
            match resp {
                BrowserResponse::Ok { data: BrowserData::PasskeyList(list) } => {
                    assert!(list.is_empty());
                }
                other => panic!("Expected PasskeyList, got: {:?}", other),
            }
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_passkey_list_filters_by_rp_id() {
        // Daemon returns passkeys for multiple rp_ids, should be filtered
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("pklist_filter.sock");
        let sp = socket_path.clone();

        let entry1 = Entry::new(
            "Passkey 1".into(),
            Credential::Passkey(PasskeyCredential {
                credential_id: "cred1".into(),
                rp_id: "match.com".into(),
                rp_name: "Match".into(),
                user_handle: "uh".into(),
                user_name: "user1".into(),
                private_key: "pk".into(),
                algorithm: PasskeyAlgorithm::Es256,
                sign_count: 0,
                discoverable: true,
                backup_eligible: false,
                backup_state: false,
                last_used_at: None,
            }),
        );
        let entry2 = Entry::new(
            "Passkey 2".into(),
            Credential::Passkey(PasskeyCredential {
                credential_id: "cred2".into(),
                rp_id: "other.com".into(),
                rp_name: "Other".into(),
                user_handle: "uh".into(),
                user_name: "user2".into(),
                private_key: "pk".into(),
                algorithm: PasskeyAlgorithm::Es256,
                sign_count: 0,
                discoverable: true,
                backup_eligible: false,
                backup_state: false,
                last_used_at: None,
            }),
        );
        let resp = Response::ok(ResponseData::Entries(vec![entry1, entry2]));
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_passkey_list(&mut client, "match.com");
            match resp {
                BrowserResponse::Ok { data: BrowserData::PasskeyList(list) } => {
                    assert_eq!(list.len(), 1);
                    assert_eq!(list[0].rp_id, "match.com");
                }
                other => panic!("Expected PasskeyList, got: {:?}", other),
            }
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_passkey_create_error_response() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("pkcreate_err.sock");
        let sp = socket_path.clone();

        let resp = Response::error("vault locked");
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_passkey_create(
                &mut client, "example.com", "Example", "uh", "user", "es256",
            );
            let msg = expect_browser_error(resp);
            assert_eq!(msg, "vault locked");
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[test]
    fn test_entry_to_detail_secure_note() {
        let entry = Entry::new(
            "Note".into(),
            Credential::SecureNote(crate::vault::entry::SecureNoteCredential {
                content: "secret content".into(),
            }),
        );
        let detail = entry_to_detail(&entry);
        assert_eq!(detail.title, "Note");
        assert!(detail.username.is_empty());
        assert!(detail.password.is_empty());
        assert!(detail.url.is_empty());
    }

    #[test]
    fn test_entry_to_detail_ssh_key() {
        let entry = Entry::new(
            "SSH".into(),
            Credential::SshKey(crate::vault::entry::SshKeyCredential {
                private_key: "priv_key".into(),
                public_key: "pub_key".into(),
                passphrase: "pass".into(),
            }),
        );
        let detail = entry_to_detail(&entry);
        assert_eq!(detail.title, "SSH");
        assert!(detail.username.is_empty());
        assert!(detail.password.is_empty());
    }

    #[test]
    fn test_entry_to_summary_with_totp() {
        let entry = Entry::new(
            "TOTP Site".into(),
            Credential::Login(LoginCredential {
                url: "https://totp.com".into(),
                username: "user".into(),
                password: "pass".into(),
            }),
        ).with_totp("GEZDGNBVGY3TQOJQ");
        let summary = entry_to_summary(&entry);
        assert!(summary.has_totp);
    }

    #[test]
    fn test_entry_to_summary_ssh_key() {
        let entry = Entry::new(
            "SSH".into(),
            Credential::SshKey(crate::vault::entry::SshKeyCredential {
                private_key: "priv".into(),
                public_key: "pub".into(),
                passphrase: "pass".into(),
            }),
        );
        let summary = entry_to_summary(&entry);
        assert!(summary.username.is_empty());
        assert!(summary.url.is_empty());
    }

    #[tokio::test]
    async fn test_handle_browser_request_dispatch_search_with_daemon() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("dispatch_search.sock");
        let sp = socket_path.clone();

        let entry = Entry::new(
            "Search Result".into(),
            Credential::Login(LoginCredential {
                url: "https://search.com".into(),
                username: "suser".into(),
                password: "spass".into(),
            }),
        );
        let resp = Response::ok(ResponseData::Entries(vec![entry]));
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_browser_request(
                Some(&mut client),
                &BrowserRequest::Search { query: "search".into() },
            );
            let creds = expect_browser_credentials(resp);
            assert_eq!(creds.len(), 1);
            assert_eq!(creds[0].title, "Search Result");
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_browser_request_dispatch_get_with_daemon() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("dispatch_get.sock");
        let sp = socket_path.clone();

        let entry = Entry::new(
            "Get Result".into(),
            Credential::Login(LoginCredential {
                url: "https://get.com".into(),
                username: "guser".into(),
                password: "gpass".into(),
            }),
        );
        let entry_id = entry.id;
        let resp = Response::ok(ResponseData::Entry(entry));
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_browser_request(
                Some(&mut client),
                &BrowserRequest::GetCredential { id: entry_id },
            );
            match resp {
                BrowserResponse::Ok { data: BrowserData::Credential(detail) } => {
                    assert_eq!(detail.title, "Get Result");
                }
                other => panic!("Expected Credential, got: {:?}", other),
            }
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_browser_request_dispatch_save_with_daemon() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("dispatch_save.sock");
        let sp = socket_path.clone();

        let resp = Response::ok(ResponseData::Id(uuid::Uuid::new_v4()));
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_browser_request(
                Some(&mut client),
                &BrowserRequest::SaveCredential {
                    title: "Saved".into(),
                    url: "https://saved.com".into(),
                    username: "u".into(),
                    password: "p".into(),
                },
            );
            assert!(matches!(resp, BrowserResponse::Ok { data: BrowserData::Saved { .. } }));
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_browser_request_dispatch_totp_with_daemon() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("dispatch_totp.sock");
        let sp = socket_path.clone();

        let resp = Response::ok(ResponseData::Totp(crate::daemon::protocol::TotpResponse {
            code: "789012".into(),
            seconds_remaining: 10,
        }));
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_browser_request(
                Some(&mut client),
                &BrowserRequest::GetTotp { id: uuid::Uuid::new_v4() },
            );
            match resp {
                BrowserResponse::Ok { data: BrowserData::Totp { code, seconds_remaining } } => {
                    assert_eq!(code, "789012");
                    assert_eq!(seconds_remaining, 10);
                }
                other => panic!("Expected Totp, got: {:?}", other),
            }
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_browser_request_dispatch_lock_with_daemon() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("dispatch_lock.sock");
        let sp = socket_path.clone();

        let resp = Response::ok(ResponseData::None);
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_browser_request(
                Some(&mut client),
                &BrowserRequest::Lock,
            );
            assert!(matches!(resp, BrowserResponse::Ok { data: BrowserData::None }));
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_browser_request_dispatch_passkey_list_with_daemon() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("dispatch_pklist.sock");
        let sp = socket_path.clone();

        let entry = Entry::new(
            "PK".into(),
            Credential::Passkey(PasskeyCredential {
                credential_id: "pk_cred".into(),
                rp_id: "dispatch.com".into(),
                rp_name: "Dispatch".into(),
                user_handle: "uh".into(),
                user_name: "pkuser".into(),
                private_key: "key".into(),
                algorithm: PasskeyAlgorithm::Es256,
                sign_count: 0,
                discoverable: true,
                backup_eligible: false,
                backup_state: false,
                last_used_at: None,
            }),
        );
        let resp = Response::ok(ResponseData::Entries(vec![entry]));
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_browser_request(
                Some(&mut client),
                &BrowserRequest::PasskeyList { rp_id: "dispatch.com".into() },
            );
            match resp {
                BrowserResponse::Ok { data: BrowserData::PasskeyList(list) } => {
                    assert_eq!(list.len(), 1);
                    assert_eq!(list[0].rp_id, "dispatch.com");
                }
                other => panic!("Expected PasskeyList, got: {:?}", other),
            }
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_browser_request_dispatch_passkey_create_with_daemon() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("dispatch_pkcreate.sock");
        let sp = socket_path.clone();

        let resp = Response::ok(ResponseData::Id(uuid::Uuid::new_v4()));
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_browser_request(
                Some(&mut client),
                &BrowserRequest::PasskeyCreate {
                    rp_id: "create.com".into(),
                    rp_name: "Create Site".into(),
                    user_handle: "uh".into(),
                    user_name: "cuser".into(),
                    algorithm: "es256".into(),
                },
            );
            match resp {
                BrowserResponse::Ok { data: BrowserData::PasskeyCreated { .. } } => {}
                other => panic!("Expected PasskeyCreated, got: {:?}", other),
            }
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_browser_request_dispatch_passkey_assert_with_daemon() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("dispatch_pkassert.sock");
        let sp = socket_path.clone();

        // Generate a real key pair for assertion
        let kp = generate_passkey_credential(&PasskeyAlgorithm::Es256).unwrap();
        let cred_id = kp.credential_id.clone();
        let entry = Entry::new(
            "Assert PK".into(),
            Credential::Passkey(PasskeyCredential {
                credential_id: kp.credential_id,
                rp_id: "assertdisp.com".into(),
                rp_name: "Assert Dispatch".into(),
                user_handle: "uh".into(),
                user_name: "auser".into(),
                private_key: kp.cose_private_key,
                algorithm: PasskeyAlgorithm::Es256,
                sign_count: 0,
                discoverable: true,
                backup_eligible: false,
                backup_state: false,
                last_used_at: None,
            }),
        );
        let resp = Response::ok(ResponseData::Entries(vec![entry]));
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            use base64::Engine;
            let mut client = DaemonClient::connect(&sp).unwrap();
            let client_data = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                br#"{"type":"webauthn.get","challenge":"disp_test","origin":"https://assertdisp.com"}"#
            );
            let resp = handle_browser_request(
                Some(&mut client),
                &BrowserRequest::PasskeyAssert {
                    credential_id: cred_id.clone(),
                    client_data_json: client_data,
                    user_verified: true,
                },
            );
            match resp {
                BrowserResponse::Ok { data: BrowserData::PasskeyAssertion { credential_id, .. } } => {
                    assert_eq!(credential_id, cred_id);
                }
                other => panic!("Expected PasskeyAssertion, got: {:?}", other),
            }
        });

        client_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_browser_request_generate_password_with_daemon() {
        // GeneratePassword should work even with a daemon connection
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("dispatch_gen.sock");
        let sp = socket_path.clone();

        // We don't even need a daemon for this, but test the dispatch path
        // when client is Some but request is GeneratePassword
        let resp = Response::ok(ResponseData::None);
        let server = mock_daemon_one_shot(&socket_path, resp).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_task = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&sp).unwrap();
            let resp = handle_browser_request(
                Some(&mut client),
                &BrowserRequest::GeneratePassword { length: Some(20) },
            );
            let pw = expect_browser_password(resp);
            assert_eq!(pw.len(), 20);
        });

        client_task.await.unwrap();
        // Server may or may not get a connection since GeneratePassword returns early
        let _ = server.await;
    }

    #[test]
    fn test_entry_to_detail_passkey() {
        let entry = Entry::new(
            "PK".into(),
            Credential::Passkey(PasskeyCredential {
                credential_id: "cred".into(),
                rp_id: "pk.com".into(),
                rp_name: "PK Site".into(),
                user_handle: "uh".into(),
                user_name: "pkuser".into(),
                private_key: "key".into(),
                algorithm: PasskeyAlgorithm::Es256,
                sign_count: 0,
                discoverable: true,
                backup_eligible: false,
                backup_state: false,
                last_used_at: None,
            }),
        );
        let detail = entry_to_detail(&entry);
        assert_eq!(detail.title, "PK");
        assert!(detail.username.is_empty());
        assert!(detail.password.is_empty());
    }

    #[tokio::test]
    async fn test_run_native_host_with_daemon_multiple_requests() {
        use super::super::native_messaging::write_json;
        use std::io::Cursor;

        // Test run_native_host_with using no daemon but multiple requests
        let mut input_buf = Vec::new();
        write_json(&mut input_buf, &BrowserRequest::GeneratePassword { length: Some(16) }).unwrap();
        write_json(&mut input_buf, &BrowserRequest::Search { query: "test".into() }).unwrap();
        write_json(&mut input_buf, &BrowserRequest::PasskeyList { rp_id: "test.com".into() }).unwrap();

        let mut reader = Cursor::new(input_buf);
        let mut output_buf = Vec::new();

        run_native_host_with(&mut None, &mut reader, &mut output_buf).unwrap();

        let mut out_reader = Cursor::new(output_buf);
        use super::super::native_messaging::read_json;

        let resp1: BrowserResponse = read_json(&mut out_reader).unwrap().unwrap();
        let pw = expect_browser_password(resp1);
        assert_eq!(pw.len(), 16);

        let resp2: BrowserResponse = read_json(&mut out_reader).unwrap().unwrap();
        let creds = expect_browser_credentials(resp2);
        assert!(creds.is_empty()); // no daemon, so empty

        let resp3: BrowserResponse = read_json(&mut out_reader).unwrap().unwrap();
        // Note: BrowserData is #[serde(untagged)], so an empty array deserializes as
        // Credentials([]) (first matching variant) rather than PasskeyList([]).
        match resp3 {
            BrowserResponse::Ok { data: BrowserData::Credentials(list) } => {
                assert!(list.is_empty());
            }
            BrowserResponse::Ok { data: BrowserData::PasskeyList(list) } => {
                assert!(list.is_empty());
            }
            other => panic!("Expected empty PasskeyList or Credentials, got: {:?}", other),
        }
    }
}
