use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::Digest;

use crate::vault::entry::PasskeyAlgorithm;
use super::keys::{decode_cose_private_key, generate_passkey_credential};
use super::webauthn::{build_assertion_response, verify_ed25519_signature, verify_p256_signature, AssertionInput};

// ---- Key Generation Tests ----

#[test]
fn test_generate_p256_passkey() {
    let kp = generate_passkey_credential(&PasskeyAlgorithm::Es256).unwrap();
    assert!(!kp.cose_private_key.is_empty());
    assert!(!kp.credential_id.is_empty());
    assert_eq!(kp.algorithm, PasskeyAlgorithm::Es256);

    // Credential ID should be 32 random bytes, base64url-encoded
    let id_bytes = URL_SAFE_NO_PAD.decode(&kp.credential_id).unwrap();
    assert_eq!(id_bytes.len(), 32);
}

#[test]
fn test_generate_ed25519_passkey() {
    let kp = generate_passkey_credential(&PasskeyAlgorithm::EdDsa).unwrap();
    assert!(!kp.cose_private_key.is_empty());
    assert!(!kp.credential_id.is_empty());
    assert_eq!(kp.algorithm, PasskeyAlgorithm::EdDsa);
}

#[test]
fn test_unique_credential_ids() {
    let kp1 = generate_passkey_credential(&PasskeyAlgorithm::Es256).unwrap();
    let kp2 = generate_passkey_credential(&PasskeyAlgorithm::Es256).unwrap();
    assert_ne!(kp1.credential_id, kp2.credential_id);
    assert_ne!(kp1.cose_private_key, kp2.cose_private_key);
}

// ---- COSE Encoding/Decoding Tests ----

#[test]
fn test_cose_roundtrip_p256() {
    let kp = generate_passkey_credential(&PasskeyAlgorithm::Es256).unwrap();
    let (key_bytes, alg) = decode_cose_private_key(&kp.cose_private_key).unwrap();
    assert_eq!(alg, PasskeyAlgorithm::Es256);
    assert_eq!(key_bytes.len(), 32); // P-256 private key is 32 bytes
}

#[test]
fn test_cose_roundtrip_ed25519() {
    let kp = generate_passkey_credential(&PasskeyAlgorithm::EdDsa).unwrap();
    let (key_bytes, alg) = decode_cose_private_key(&kp.cose_private_key).unwrap();
    assert_eq!(alg, PasskeyAlgorithm::EdDsa);
    assert_eq!(key_bytes.len(), 32); // Ed25519 private key is 32 bytes
}

#[test]
fn test_cose_decode_invalid_base64() {
    let result = decode_cose_private_key("not-valid-base64!!!");
    assert!(result.is_err());
}

#[test]
fn test_cose_decode_invalid_cbor() {
    let bad = URL_SAFE_NO_PAD.encode([0u8; 4]);
    let result = decode_cose_private_key(&bad);
    assert!(result.is_err());
}

// ---- WebAuthn Assertion Tests ----

fn make_client_data_json(challenge: &str) -> String {
    let json = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://example.com"}}"#,
        challenge
    );
    URL_SAFE_NO_PAD.encode(json.as_bytes())
}

#[test]
fn test_assertion_p256() {
    let kp = generate_passkey_credential(&PasskeyAlgorithm::Es256).unwrap();

    let input = AssertionInput {
        rp_id: "example.com".to_string(),
        client_data_json: make_client_data_json("dGVzdC1jaGFsbGVuZ2U"),
        cose_private_key: kp.cose_private_key.clone(),
        sign_count: 1,
        user_handle: URL_SAFE_NO_PAD.encode(b"user123"),
        user_verified: true,
    };

    let response = build_assertion_response(&input).unwrap();

    // authenticatorData should be 37 bytes (32 rpIdHash + 1 flags + 4 signCount)
    let auth_data = URL_SAFE_NO_PAD.decode(&response.authenticator_data).unwrap();
    assert_eq!(auth_data.len(), 37);

    // Flags: UP (0x01) | UV (0x04) = 0x05
    assert_eq!(auth_data[32], 0x05);

    // Sign count (big-endian)
    let sign_count = u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    assert_eq!(sign_count, 1);

    // Verify the signature
    let sig_bytes = URL_SAFE_NO_PAD.decode(&response.signature).unwrap();
    let client_data_bytes = URL_SAFE_NO_PAD.decode(&input.client_data_json).unwrap();
    let client_data_hash = sha2::Sha256::digest(&client_data_bytes);
    let mut signed_data = auth_data.clone();
    signed_data.extend_from_slice(&client_data_hash);

    assert!(verify_p256_signature(&signed_data, &sig_bytes, &kp.cose_private_key).unwrap());
}

#[test]
fn test_assertion_ed25519() {
    let kp = generate_passkey_credential(&PasskeyAlgorithm::EdDsa).unwrap();

    let input = AssertionInput {
        rp_id: "example.com".to_string(),
        client_data_json: make_client_data_json("dGVzdC1jaGFsbGVuZ2U"),
        cose_private_key: kp.cose_private_key.clone(),
        sign_count: 5,
        user_handle: URL_SAFE_NO_PAD.encode(b"user456"),
        user_verified: false,
    };

    let response = build_assertion_response(&input).unwrap();

    let auth_data = URL_SAFE_NO_PAD.decode(&response.authenticator_data).unwrap();
    assert_eq!(auth_data.len(), 37);

    // Flags: UP (0x01) only, UV not set
    assert_eq!(auth_data[32], 0x01);

    // Sign count = 5
    let sign_count = u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    assert_eq!(sign_count, 5);

    // Verify the signature
    let sig_bytes = URL_SAFE_NO_PAD.decode(&response.signature).unwrap();
    let client_data_bytes = URL_SAFE_NO_PAD.decode(&input.client_data_json).unwrap();
    let client_data_hash = sha2::Sha256::digest(&client_data_bytes);
    let mut signed_data = auth_data.clone();
    signed_data.extend_from_slice(&client_data_hash);

    assert!(verify_ed25519_signature(&signed_data, &sig_bytes, &kp.cose_private_key).unwrap());
}

#[test]
fn test_assertion_user_handle_echoed() {
    let kp = generate_passkey_credential(&PasskeyAlgorithm::Es256).unwrap();
    let user_handle = URL_SAFE_NO_PAD.encode(b"my-user-id");

    let input = AssertionInput {
        rp_id: "test.com".to_string(),
        client_data_json: make_client_data_json("Y2hhbGxlbmdl"),
        cose_private_key: kp.cose_private_key,
        sign_count: 0,
        user_handle: user_handle.clone(),
        user_verified: false,
    };

    let response = build_assertion_response(&input).unwrap();
    assert_eq!(response.user_handle, user_handle);
    assert_eq!(response.client_data_json, input.client_data_json);
}

#[test]
fn test_assertion_invalid_client_data() {
    let kp = generate_passkey_credential(&PasskeyAlgorithm::Es256).unwrap();

    let input = AssertionInput {
        rp_id: "test.com".to_string(),
        client_data_json: "!!!invalid-base64!!!".to_string(),
        cose_private_key: kp.cose_private_key,
        sign_count: 0,
        user_handle: "dXNlcg".to_string(),
        user_verified: false,
    };

    let result = build_assertion_response(&input);
    assert!(result.is_err());
}

#[test]
fn test_assertion_sign_count_encoding() {
    let kp = generate_passkey_credential(&PasskeyAlgorithm::Es256).unwrap();

    for count in [0u32, 1, 255, 256, 65535, 100_000] {
        let input = AssertionInput {
            rp_id: "example.com".to_string(),
            client_data_json: make_client_data_json("Y2hhbGxlbmdl"),
            cose_private_key: kp.cose_private_key.clone(),
            sign_count: count,
            user_handle: "dXNlcg".to_string(),
            user_verified: true,
        };

        let response = build_assertion_response(&input).unwrap();
        let auth_data = URL_SAFE_NO_PAD.decode(&response.authenticator_data).unwrap();
        let decoded = u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
        assert_eq!(decoded, count);
    }
}

// ---- PasskeyCredential Serialization Tests ----

#[test]
fn test_passkey_credential_json_roundtrip() {
    use crate::vault::entry::{Credential, Entry, PasskeyCredential};

    let entry = Entry::new(
        "GitHub Passkey".to_string(),
        Credential::Passkey(PasskeyCredential {
            credential_id: "dGVzdC1pZA".to_string(),
            rp_id: "github.com".to_string(),
            rp_name: "GitHub".to_string(),
            user_handle: "dXNlci0xMjM".to_string(),
            user_name: "octocat".to_string(),
            private_key: "cHJpdmF0ZS1rZXk".to_string(),
            algorithm: PasskeyAlgorithm::Es256,
            sign_count: 42,
            discoverable: true,
            backup_eligible: true,
            backup_state: false,
            last_used_at: None,
        }),
    );

    let json = serde_json::to_string(&entry).unwrap();
    let parsed: Entry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, parsed);
    assert_eq!(parsed.credential_type(), "passkey");
}

#[test]
fn test_passkey_credential_msgpack_roundtrip() {
    use crate::vault::entry::{Credential, Entry, PasskeyCredential};

    let entry = Entry::new(
        "Google Passkey".to_string(),
        Credential::Passkey(PasskeyCredential {
            credential_id: "Y3JlZC1pZA".to_string(),
            rp_id: "google.com".to_string(),
            rp_name: "Google".to_string(),
            user_handle: "dXNlcg".to_string(),
            user_name: "user@gmail.com".to_string(),
            private_key: "a2V5".to_string(),
            algorithm: PasskeyAlgorithm::EdDsa,
            sign_count: 0,
            discoverable: true,
            backup_eligible: false,
            backup_state: false,
            last_used_at: Some(chrono::Utc::now()),
        }),
    );

    let serialized = rmp_serde::to_vec(&entry).unwrap();
    let deserialized: Entry = rmp_serde::from_slice(&serialized).unwrap();
    assert_eq!(entry, deserialized);
}

#[test]
fn test_passkey_matches_search() {
    use crate::vault::entry::{Credential, Entry, PasskeyCredential};

    let entry = Entry::new(
        "GitHub Passkey".to_string(),
        Credential::Passkey(PasskeyCredential {
            credential_id: "id".to_string(),
            rp_id: "github.com".to_string(),
            rp_name: "GitHub Inc".to_string(),
            user_handle: "uh".to_string(),
            user_name: "octocat".to_string(),
            private_key: "key".to_string(),
            algorithm: PasskeyAlgorithm::Es256,
            sign_count: 0,
            discoverable: true,
            backup_eligible: false,
            backup_state: false,
            last_used_at: None,
        }),
    );

    assert!(entry.matches("github"));
    assert!(entry.matches("GitHub Inc"));
    assert!(entry.matches("octocat"));
    assert!(!entry.matches("microsoft"));
}

#[test]
fn test_passkey_algorithm_serde() {
    let es256 = serde_json::to_string(&PasskeyAlgorithm::Es256).unwrap();
    assert_eq!(es256, r#""es256""#);

    let eddsa = serde_json::to_string(&PasskeyAlgorithm::EdDsa).unwrap();
    assert_eq!(eddsa, r#""eddsa""#);

    let parsed: PasskeyAlgorithm = serde_json::from_str(r#""es256""#).unwrap();
    assert_eq!(parsed, PasskeyAlgorithm::Es256);

    let parsed: PasskeyAlgorithm = serde_json::from_str(r#""eddsa""#).unwrap();
    assert_eq!(parsed, PasskeyAlgorithm::EdDsa);
}

// ---- Error Path Coverage Tests ----

#[test]
fn test_cose_decode_unsupported_algorithm() {
    use coset::{iana, CborSerializable, CoseKeyBuilder};

    // Build a COSE key with an unsupported algorithm (PS256 / RSASSA-PKCS1-v1_5 using SHA-256)
    let mut cose_key = CoseKeyBuilder::new_ec2_priv_key(
        iana::EllipticCurve::P_256,
        vec![0u8; 32],
        vec![0u8; 32],
        vec![0u8; 32],
    )
    .build();
    // Override algorithm to something unsupported
    cose_key.alg = Some(coset::Algorithm::Assigned(iana::Algorithm::PS256));
    // Ensure 'd' parameter is present (CoseKeyBuilder includes it in params)
    let cbor = cose_key.to_vec().unwrap();
    let b64 = URL_SAFE_NO_PAD.encode(&cbor);

    let result = decode_cose_private_key(&b64);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("unsupported COSE algorithm"));
}

#[test]
fn test_cose_decode_no_algorithm() {
    use coset::{iana, CborSerializable, CoseKeyBuilder};

    // Build a COSE key with no algorithm set at all (alg = None)
    let mut cose_key = CoseKeyBuilder::new_ec2_priv_key(
        iana::EllipticCurve::P_256,
        vec![0u8; 32],
        vec![0u8; 32],
        vec![0u8; 32],
    )
    .build();
    cose_key.alg = None;
    let cbor = cose_key.to_vec().unwrap();
    let b64 = URL_SAFE_NO_PAD.encode(&cbor);

    let result = decode_cose_private_key(&b64);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("unsupported COSE algorithm"));
}

#[test]
fn test_cose_decode_d_param_not_bytes() {
    use coset::{iana, CborSerializable, CoseKeyBuilder, Label};

    // Build a COSE key where the 'd' parameter is a text string instead of bytes
    let mut cose_key = CoseKeyBuilder::new_ec2_priv_key(
        iana::EllipticCurve::P_256,
        vec![0u8; 32],
        vec![0u8; 32],
        vec![0u8; 32], // This will be bytes, so we need to replace it
    )
    .algorithm(iana::Algorithm::ES256)
    .build();

    // Replace the 'd' parameter with a text value instead of bytes
    let d_label = Label::Int(iana::Ec2KeyParameter::D as i64);
    cose_key.params.retain(|(label, _)| *label != d_label);
    cose_key.params.push((d_label, ciborium::Value::Text("not-bytes".to_string())));

    let cbor = cose_key.to_vec().unwrap();
    let b64 = URL_SAFE_NO_PAD.encode(&cbor);

    let result = decode_cose_private_key(&b64);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not bytes"));
}

#[test]
fn test_assertion_with_invalid_cose_key() {
    // Use a COSE key that decodes but has invalid P-256 key bytes (all zeros)
    use coset::{iana, CborSerializable, CoseKeyBuilder};

    let cose_key = CoseKeyBuilder::new_ec2_priv_key(
        iana::EllipticCurve::P_256,
        vec![0u8; 32],
        vec![0u8; 32],
        vec![0u8; 32], // All-zero is not a valid P-256 private key
    )
    .algorithm(iana::Algorithm::ES256)
    .build();
    let cbor = cose_key.to_vec().unwrap();
    let bad_cose = URL_SAFE_NO_PAD.encode(&cbor);

    let input = AssertionInput {
        rp_id: "example.com".to_string(),
        client_data_json: make_client_data_json("dGVzdA"),
        cose_private_key: bad_cose,
        sign_count: 0,
        user_handle: "dXNlcg".to_string(),
        user_verified: false,
    };

    let result = build_assertion_response(&input);
    let err = result.err().expect("expected error for invalid P-256 key");
    assert!(err.contains("P-256 key decode"), "unexpected error: {}", err);
}

#[test]
fn test_assertion_with_invalid_ed25519_key_length() {
    // Use a COSE key with EdDSA algorithm but wrong-length 'd' parameter (16 bytes instead of 32)
    use coset::{iana, CborSerializable, CoseKeyBuilder, Label};

    let mut cose_key = CoseKeyBuilder::new_okp_key()
        .algorithm(iana::Algorithm::EdDSA)
        .param(
            iana::OkpKeyParameter::Crv as i64,
            ciborium::Value::from(iana::EllipticCurve::Ed25519 as i64),
        )
        .param(
            iana::OkpKeyParameter::X as i64,
            ciborium::Value::Bytes(vec![0u8; 32]),
        )
        .build();

    // Add 'd' parameter with wrong length (16 bytes instead of 32)
    cose_key.params.push((
        Label::Int(iana::OkpKeyParameter::D as i64),
        ciborium::Value::Bytes(vec![0u8; 16]),
    ));

    let cbor = cose_key.to_vec().unwrap();
    let bad_cose = URL_SAFE_NO_PAD.encode(&cbor);

    let input = AssertionInput {
        rp_id: "example.com".to_string(),
        client_data_json: make_client_data_json("dGVzdA"),
        cose_private_key: bad_cose,
        sign_count: 0,
        user_handle: "dXNlcg".to_string(),
        user_verified: false,
    };

    let result = build_assertion_response(&input);
    let err = result.err().expect("expected error for wrong-length Ed25519 key");
    assert!(err.contains("Ed25519 key must be 32 bytes"), "unexpected error: {}", err);
}
