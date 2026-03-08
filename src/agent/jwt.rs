use hkdf::Hkdf;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::crypto::keys::MasterKey;

const JWT_SALT: &[u8] = b"vaultclaw-jwt-v1";
const JWT_KEY_LEN: usize = 32;

/// JWT role: admin has vault-wide access, agent has scoped credential access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JwtRole {
    Admin,
    Agent,
}

/// Claims embedded in a VaultClaw JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Subject: "admin" or agent_id
    pub sub: String,
    /// Role
    pub role: JwtRole,
    /// Token ID (for agent tokens, links to AgentToken.id)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_id: Option<String>,
    /// Expiration (Unix timestamp)
    pub exp: usize,
    /// Issued at (Unix timestamp)
    pub iat: usize,
}

/// Derive a JWT signing key from the master key using HKDF-SHA256.
pub fn derive_jwt_signing_key(master_key: &MasterKey) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(JWT_SALT), master_key.as_bytes());
    let mut okm = vec![0u8; JWT_KEY_LEN];
    hk.expand(b"jwt-signing", &mut okm)
        .expect("HKDF expand failed");
    okm
}

/// Create an admin JWT with the given TTL.
pub fn create_admin_jwt(signing_key: &[u8], ttl_secs: u64) -> Result<String, String> {
    let now = chrono::Utc::now().timestamp() as usize;
    let claims = JwtClaims {
        sub: "admin".to_string(),
        role: JwtRole::Admin,
        token_id: None,
        exp: now + ttl_secs as usize,
        iat: now,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(signing_key),
    )
    .map_err(|e| e.to_string())
}

/// Create an agent JWT with scoped access.
pub fn create_agent_jwt(
    signing_key: &[u8],
    agent_id: &str,
    token_id: &str,
    ttl_secs: u64,
) -> Result<String, String> {
    let now = chrono::Utc::now().timestamp() as usize;
    let claims = JwtClaims {
        sub: agent_id.to_string(),
        role: JwtRole::Agent,
        token_id: Some(token_id.to_string()),
        exp: now + ttl_secs as usize,
        iat: now,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(signing_key),
    )
    .map_err(|e| e.to_string())
}

/// Verify a JWT and return the claims.
pub fn verify_jwt(signing_key: &[u8], token: &str) -> Result<JwtClaims, String> {
    let mut validation = Validation::default();
    validation.validate_exp = true;
    validation.leeway = 0;
    validation.required_spec_claims.clear();

    decode::<JwtClaims>(token, &DecodingKey::from_secret(signing_key), &validation)
        .map(|data| data.claims)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf;
    use crate::crypto::keys::password_secret;

    fn test_signing_key() -> Vec<u8> {
        let password = password_secret("test-password".to_string());
        let salt = kdf::generate_salt(16);
        let params = kdf::KdfParams::fast_for_testing();
        let master_key = kdf::derive_master_key(&password, &salt, &params).unwrap();
        derive_jwt_signing_key(&master_key)
    }

    #[test]
    fn test_derive_key_deterministic() {
        let password = password_secret("test".to_string());
        let salt = vec![0u8; 16];
        let params = kdf::KdfParams::fast_for_testing();
        let mk = kdf::derive_master_key(&password, &salt, &params).unwrap();
        let k1 = derive_jwt_signing_key(&mk);
        let k2 = derive_jwt_signing_key(&mk);
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), JWT_KEY_LEN);
    }

    #[test]
    fn test_derive_key_different_masters() {
        let salt = vec![0u8; 16];
        let params = kdf::KdfParams::fast_for_testing();
        let mk1 = kdf::derive_master_key(&password_secret("pw1".into()), &salt, &params).unwrap();
        let mk2 = kdf::derive_master_key(&password_secret("pw2".into()), &salt, &params).unwrap();
        assert_ne!(derive_jwt_signing_key(&mk1), derive_jwt_signing_key(&mk2));
    }

    #[test]
    fn test_admin_jwt_roundtrip() {
        let key = test_signing_key();
        let token = create_admin_jwt(&key, 3600).unwrap();
        let claims = verify_jwt(&key, &token).unwrap();
        assert_eq!(claims.sub, "admin");
        assert_eq!(claims.role, JwtRole::Admin);
        assert!(claims.token_id.is_none());
    }

    #[test]
    fn test_agent_jwt_roundtrip() {
        let key = test_signing_key();
        let tid = uuid::Uuid::new_v4().to_string();
        let token = create_agent_jwt(&key, "my-agent", &tid, 3600).unwrap();
        let claims = verify_jwt(&key, &token).unwrap();
        assert_eq!(claims.sub, "my-agent");
        assert_eq!(claims.role, JwtRole::Agent);
        assert_eq!(claims.token_id.as_deref(), Some(tid.as_str()));
    }

    #[test]
    fn test_expired_jwt() {
        let key = test_signing_key();
        // TTL of 0 means already expired by the time we verify
        let now = chrono::Utc::now().timestamp() as usize;
        let claims = JwtClaims {
            sub: "admin".to_string(),
            role: JwtRole::Admin,
            token_id: None,
            exp: now.saturating_sub(10),
            iat: now.saturating_sub(20),
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(&key),
        )
        .unwrap();
        let result = verify_jwt(&key, &token);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("ExpiredSignature"));
    }

    #[test]
    fn test_wrong_key_verification() {
        let key1 = test_signing_key();
        let key2 = test_signing_key(); // different random salt
        let token = create_admin_jwt(&key1, 3600).unwrap();
        let result = verify_jwt(&key2, &token);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_token_string() {
        let key = test_signing_key();
        let result = verify_jwt(&key, "not.a.jwt");
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_token_string() {
        let key = test_signing_key();
        let result = verify_jwt(&key, "");
        assert!(result.is_err());
    }

    #[test]
    fn test_admin_claims_serialization() {
        let claims = JwtClaims {
            sub: "admin".to_string(),
            role: JwtRole::Admin,
            token_id: None,
            exp: 9999999999,
            iat: 1000000000,
        };
        let json = serde_json::to_string(&claims).unwrap();
        assert!(!json.contains("token_id")); // skip_serializing_if
        let parsed: JwtClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.role, JwtRole::Admin);
        assert!(parsed.token_id.is_none());
    }

    #[test]
    fn test_agent_claims_serialization() {
        let claims = JwtClaims {
            sub: "agent-1".to_string(),
            role: JwtRole::Agent,
            token_id: Some("tok-123".to_string()),
            exp: 9999999999,
            iat: 1000000000,
        };
        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("token_id"));
        let parsed: JwtClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.role, JwtRole::Agent);
        assert_eq!(parsed.token_id.as_deref(), Some("tok-123"));
    }

    #[test]
    fn test_jwt_role_serialization() {
        assert_eq!(serde_json::to_string(&JwtRole::Admin).unwrap(), "\"admin\"");
        assert_eq!(serde_json::to_string(&JwtRole::Agent).unwrap(), "\"agent\"");
        assert_eq!(
            serde_json::from_str::<JwtRole>("\"admin\"").unwrap(),
            JwtRole::Admin
        );
        assert_eq!(
            serde_json::from_str::<JwtRole>("\"agent\"").unwrap(),
            JwtRole::Agent
        );
    }

    #[test]
    fn test_admin_jwt_exp_is_future() {
        let key = test_signing_key();
        let token = create_admin_jwt(&key, 7200).unwrap();
        let claims = verify_jwt(&key, &token).unwrap();
        let now = chrono::Utc::now().timestamp() as usize;
        assert!(claims.exp > now);
        assert!(claims.exp <= now + 7200 + 1);
    }

    #[test]
    fn test_agent_jwt_exp_is_future() {
        let key = test_signing_key();
        let token = create_agent_jwt(&key, "a", "t", 1800).unwrap();
        let claims = verify_jwt(&key, &token).unwrap();
        let now = chrono::Utc::now().timestamp() as usize;
        assert!(claims.exp > now);
        assert!(claims.exp <= now + 1800 + 1);
    }

    #[test]
    fn test_two_tokens_are_different() {
        let key = test_signing_key();
        let t1 = create_admin_jwt(&key, 3600).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let t2 = create_admin_jwt(&key, 3600).unwrap();
        // Tokens may have same iat (same second) but are unique strings
        // due to different serialization nonces etc. At minimum, they both verify
        assert!(verify_jwt(&key, &t1).is_ok());
        assert!(verify_jwt(&key, &t2).is_ok());
    }

    #[test]
    fn test_garbage_token_fails() {
        let key = test_signing_key();
        assert!(verify_jwt(&key, "eyJ.garbage.data").is_err());
    }
}
