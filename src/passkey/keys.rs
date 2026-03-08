//! Passkey key generation and COSE key encoding/decoding.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use coset::{
    iana, CborSerializable, CoseKey, CoseKeyBuilder, Label,
};
use p256::ecdsa::SigningKey as P256SigningKey;
use rand::rngs::OsRng;

use crate::vault::entry::PasskeyAlgorithm;

/// A generated passkey key pair: the COSE-encoded private key and credential ID.
pub struct PasskeyKeyPair {
    /// COSE key in CBOR, base64url-encoded.
    pub cose_private_key: String,
    /// Random credential ID, base64url-encoded.
    pub credential_id: String,
    /// Algorithm used.
    pub algorithm: PasskeyAlgorithm,
}

/// Generate a new passkey key pair using the specified algorithm.
pub fn generate_passkey_credential(algorithm: &PasskeyAlgorithm) -> Result<PasskeyKeyPair, String> {
    match algorithm {
        PasskeyAlgorithm::Es256 => generate_p256_key(),
        PasskeyAlgorithm::EdDsa => generate_ed25519_key(),
    }
}

/// Decode a base64url-encoded COSE private key and return the raw signing key bytes.
pub fn decode_cose_private_key(cose_b64: &str) -> Result<(Vec<u8>, PasskeyAlgorithm), String> {
    let cbor = URL_SAFE_NO_PAD.decode(cose_b64).map_err(|e| format!("base64 decode: {}", e))?;
    let cose_key = CoseKey::from_slice(&cbor).map_err(|e| format!("COSE decode: {}", e))?;

    let alg = match cose_key.alg {
        Some(coset::Algorithm::Assigned(iana::Algorithm::ES256)) => PasskeyAlgorithm::Es256,
        Some(coset::Algorithm::Assigned(iana::Algorithm::EdDSA)) => PasskeyAlgorithm::EdDsa,
        other => return Err(format!("unsupported COSE algorithm: {:?}", other)),
    };

    // Extract the private key parameter 'd'
    let d_label = Label::Int(iana::Ec2KeyParameter::D as i64);
    let d_value = cose_key.params.iter()
        .find(|(label, _)| *label == d_label)
        .ok_or("missing 'd' parameter in COSE key")?;

    match &d_value.1 {
        ciborium::Value::Bytes(bytes) => Ok((bytes.clone(), alg)),
        _ => Err("COSE key 'd' parameter is not bytes".to_string()),
    }
}

/// Encode a P-256 private key as a COSE Key (CBOR, base64url).
pub fn encode_p256_cose_key(signing_key: &P256SigningKey) -> Result<String, String> {
    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);

    let x = point.x().ok_or("missing x coordinate")?.to_vec();
    let y = point.y().ok_or("missing y coordinate")?.to_vec();
    let d = signing_key.to_bytes().to_vec();

    let cose_key = CoseKeyBuilder::new_ec2_priv_key(iana::EllipticCurve::P_256, x, y, d)
        .algorithm(iana::Algorithm::ES256)
        .build();

    let cbor = cose_key.to_vec().map_err(|e| format!("COSE encode: {}", e))?;
    Ok(URL_SAFE_NO_PAD.encode(&cbor))
}

/// Encode an Ed25519 private key as a COSE Key (CBOR, base64url).
pub fn encode_ed25519_cose_key(secret: &[u8; 32], public: &[u8; 32]) -> Result<String, String> {
    let mut cose_key = CoseKeyBuilder::new_okp_key()
        .algorithm(iana::Algorithm::EdDSA)
        .param(
            iana::OkpKeyParameter::Crv as i64,
            ciborium::Value::from(iana::EllipticCurve::Ed25519 as i64),
        )
        .param(
            iana::OkpKeyParameter::X as i64,
            ciborium::Value::Bytes(public.to_vec()),
        )
        .build();

    // Add private key parameter 'd'
    cose_key.params.push((
        Label::Int(iana::OkpKeyParameter::D as i64),
        ciborium::Value::Bytes(secret.to_vec()),
    ));

    let cbor = cose_key.to_vec().map_err(|e| format!("COSE encode: {}", e))?;
    Ok(URL_SAFE_NO_PAD.encode(&cbor))
}

fn generate_p256_key() -> Result<PasskeyKeyPair, String> {
    let signing_key = P256SigningKey::random(&mut OsRng);
    let cose_private_key = encode_p256_cose_key(&signing_key)?;
    let credential_id = generate_credential_id();

    Ok(PasskeyKeyPair {
        cose_private_key,
        credential_id,
        algorithm: PasskeyAlgorithm::Es256,
    })
}

fn generate_ed25519_key() -> Result<PasskeyKeyPair, String> {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let public_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
    let secret_bytes: [u8; 32] = signing_key.to_bytes();

    let cose_private_key = encode_ed25519_cose_key(&secret_bytes, &public_bytes)?;
    let credential_id = generate_credential_id();

    Ok(PasskeyKeyPair {
        cose_private_key,
        credential_id,
        algorithm: PasskeyAlgorithm::EdDsa,
    })
}

fn generate_credential_id() -> String {
    let mut id = [0u8; 32];
    use rand::RngCore;
    OsRng.fill_bytes(&mut id);
    URL_SAFE_NO_PAD.encode(id)
}
