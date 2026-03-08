use serde::{Deserialize, Serialize};

use crate::agent::gateway::{GatewayData, GatewayRequest};
use crate::agent::lease::Sensitivity;
use crate::vault::entry::{Entry, EntryId};

/// Request from a client (CLI, extension) to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method")]
pub enum Request {
    #[serde(rename = "status")]
    Status,

    #[serde(rename = "get")]
    Get { id: EntryId },

    #[serde(rename = "search")]
    Search { query: String },

    #[serde(rename = "list")]
    List {
        tag: Option<String>,
        category: Option<String>,
        favorites_only: bool,
    },

    #[serde(rename = "add")]
    Add { entry: Entry },

    #[serde(rename = "update")]
    Update { entry: Entry },

    #[serde(rename = "delete")]
    Delete { id: EntryId },

    #[serde(rename = "totp")]
    Totp { id: EntryId },

    #[serde(rename = "lock")]
    Lock,

    #[serde(rename = "unlock")]
    Unlock { password: String },

    /// Unlock the vault with a recovery key (hex string).
    #[serde(rename = "unlock_recovery")]
    UnlockRecovery { recovery_key: String },

    /// Unlock the vault with a raw 32-byte master key (hex-encoded).
    #[serde(rename = "unlock_master_key")]
    UnlockMasterKey { master_key_hex: String },

    /// Unlock the vault using Touch ID (macOS only).
    /// The daemon retrieves the wrapping key from Keychain via biometric prompt.
    #[serde(rename = "unlock_touchid")]
    UnlockTouchId,

    #[serde(rename = "shutdown")]
    Shutdown,

    #[serde(rename = "fuzzy_get")]
    FuzzyGet { query: String },

    #[serde(rename = "health")]
    Health,

    #[serde(rename = "agent")]
    Agent { request: GatewayRequest },

    #[serde(rename = "lease_list")]
    LeaseList,

    #[serde(rename = "lease_revoke")]
    LeaseRevoke { lease_id: uuid::Uuid },

    #[serde(rename = "lease_revoke_all")]
    LeaseRevokeAll,

    #[serde(rename = "set_sensitivity")]
    SetSensitivity { entry_id: EntryId, level: Sensitivity },
}

/// Response from the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum Response {
    #[serde(rename = "ok")]
    Ok { data: Box<ResponseData> },

    #[serde(rename = "error")]
    Error { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResponseData {
    None,
    Entry(Entry),
    Entries(Vec<Entry>),
    Status(VaultStatus),
    Totp(TotpResponse),
    Health(HealthResponse),
    Unlocked { success: bool },
    Id(EntryId),
    Agent(GatewayData),
    LeaseList(LeaseListData),
    LeaseRevoked { count: usize },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseListData {
    pub leases: Vec<LeaseInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultStatus {
    pub locked: bool,
    pub entry_count: usize,
    pub vault_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpResponse {
    pub code: String,
    pub seconds_remaining: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub healthy: bool,
    pub uptime_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseInfo {
    pub lease_id: uuid::Uuid,
    pub entry_id: EntryId,
    pub agent_id: String,
    pub scope: String,
    pub reason: String,
    pub created_at: String,
    pub expires_at: String,
}

impl Response {
    pub fn ok(data: ResponseData) -> Self {
        Self::Ok { data: Box::new(data) }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self::Error {
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_serialization() {
        let req = Request::Search {
            query: "github".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("search"));
        assert!(json.contains("github"));

        let parsed: Request = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, Request::Search { query } if query == "github"));
    }

    #[test]
    fn test_response_ok_serialization() {
        let resp = Response::ok(ResponseData::Status(VaultStatus {
            locked: false,
            entry_count: 42,
            vault_path: "/tmp/test.vclaw".to_string(),
        }));

        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("ok"));
        assert!(json.contains("42"));
    }

    #[test]
    fn test_response_error_serialization() {
        let resp = Response::error("vault locked");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("error"));
        assert!(json.contains("vault locked"));
    }

    #[test]
    fn test_all_request_types() {
        let requests = vec![
            Request::Status,
            Request::Get { id: uuid::Uuid::new_v4() },
            Request::Search { query: "test".to_string() },
            Request::List { tag: None, category: None, favorites_only: false },
            Request::Delete { id: uuid::Uuid::new_v4() },
            Request::Lock,
            Request::Unlock { password: "pw".to_string() },
            Request::UnlockRecovery { recovery_key: "ABCD".to_string() },
            Request::UnlockMasterKey { master_key_hex: "0102".to_string() },
            Request::UnlockTouchId,
            Request::Shutdown,
            Request::FuzzyGet { query: "github".to_string() },
            Request::Health,
            Request::Agent {
                request: GatewayRequest::ListTokens,
            },
            Request::LeaseList,
            Request::LeaseRevoke { lease_id: uuid::Uuid::new_v4() },
            Request::LeaseRevokeAll,
            Request::SetSensitivity { entry_id: uuid::Uuid::new_v4(), level: Sensitivity::High },
        ];

        for req in requests {
            let json = serde_json::to_string(&req).unwrap();
            assert!(!json.is_empty());
        }
    }

    #[test]
    fn test_lease_list_response_data() {
        let resp = Response::ok(ResponseData::LeaseList(LeaseListData { leases: vec![LeaseInfo {
            lease_id: uuid::Uuid::new_v4(),
            entry_id: uuid::Uuid::new_v4(),
            agent_id: "test-agent".to_string(),
            scope: "\"read\"".to_string(),
            reason: "deploy".to_string(),
            created_at: "2025-01-01T00:00:00Z".to_string(),
            expires_at: "2025-01-01T01:00:00Z".to_string(),
        }] }));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("test-agent"));
        assert!(json.contains("deploy"));
    }

    #[test]
    fn test_lease_revoked_response_data() {
        let resp = Response::ok(ResponseData::LeaseRevoked { count: 3 });
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("3"));
    }

    #[test]
    fn test_totp_response() {
        let resp = Response::ok(ResponseData::Totp(TotpResponse {
            code: "123456".to_string(),
            seconds_remaining: 15,
        }));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("123456"));
        assert!(json.contains("15"));
    }

    #[test]
    fn test_health_response() {
        let resp = Response::ok(ResponseData::Health(HealthResponse {
            healthy: true,
            uptime_seconds: 3600,
        }));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("true"));
        assert!(json.contains("3600"));
    }

    fn expect_search_query(req: Request) -> String {
        match req {
            Request::Search { query } => query,
            other => panic!("Expected Search, got: {:?}", other),
        }
    }

    #[test]
    fn test_request_deserialization_roundtrip() {
        let req = Request::Search { query: "github".to_string() };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: Request = serde_json::from_str(&json).unwrap();
        let query = expect_search_query(parsed);
        assert_eq!(query, "github");
    }

    #[test]
    #[should_panic(expected = "Expected Search")]
    fn test_expect_search_query_wrong_type() {
        expect_search_query(Request::Status);
    }

    #[test]
    fn test_agent_request_serialization() {
        let req = Request::Agent {
            request: GatewayRequest::ListTokens,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("agent"));

        let parsed: Request = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, Request::Agent { .. }));
    }

    #[test]
    fn test_agent_response_data() {
        let resp = Response::ok(ResponseData::Agent(GatewayData::None));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("ok"));
    }

    #[test]
    fn test_unlock_request_serialization() {
        let req = Request::Unlock { password: "secret".to_string() };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("unlock"));
        assert!(json.contains("secret"));

        let parsed: Request = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, Request::Unlock { password } if password == "secret"));
    }

    #[test]
    fn test_shutdown_request_serialization() {
        let req = Request::Shutdown;
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("shutdown"));

        let parsed: Request = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, Request::Shutdown));
    }

    #[test]
    fn test_fuzzy_get_request_serialization() {
        let req = Request::FuzzyGet { query: "github".to_string() };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("fuzzy_get"));
        assert!(json.contains("github"));

        let parsed: Request = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, Request::FuzzyGet { query } if query == "github"));
    }

    #[test]
    fn test_unlock_recovery_request_serialization() {
        let req = Request::UnlockRecovery { recovery_key: "ABCD1234".to_string() };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("unlock_recovery"));
        assert!(json.contains("ABCD1234"));

        let parsed: Request = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, Request::UnlockRecovery { recovery_key } if recovery_key == "ABCD1234"));
    }

    #[test]
    fn test_unlock_touchid_request_serialization() {
        let req = Request::UnlockTouchId;
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("unlock_touchid"));

        let parsed: Request = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, Request::UnlockTouchId));
    }

    #[test]
    fn test_unlock_master_key_request_serialization() {
        let req = Request::UnlockMasterKey { master_key_hex: "0102030405".to_string() };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("unlock_master_key"));
        assert!(json.contains("0102030405"));

        let parsed: Request = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, Request::UnlockMasterKey { master_key_hex } if master_key_hex == "0102030405"));
    }

    #[test]
    fn test_unlocked_response_data() {
        let resp = Response::ok(ResponseData::Unlocked { success: true });
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("ok"));
        assert!(json.contains("true"));

        let resp = Response::ok(ResponseData::Unlocked { success: false });
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("false"));
    }
}
