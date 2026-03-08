//! WebAuthn assertion response construction per W3C spec.
//!
//! Builds `AuthenticatorAssertionResponse` with authenticatorData, signature,
//! and userHandle as required by the WebAuthn Level 2 specification.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::{signature::Signer, Signature as P256Signature, SigningKey as P256SigningKey};
use sha2::{Digest, Sha256};

use crate::vault::entry::PasskeyAlgorithm;
use super::keys::decode_cose_private_key;

/// Input for generating a WebAuthn assertion response.
pub struct AssertionInput {
    /// Relying party ID (used to derive rpIdHash).
    pub rp_id: String,
    /// Client data JSON (provided by the browser/client), base64url-encoded.
    pub client_data_json: String,
    /// COSE private key, base64url-encoded CBOR.
    pub cose_private_key: String,
    /// Current signature counter value (will be embedded in authenticatorData).
    pub sign_count: u32,
    /// User handle (relying party's user ID), base64url-encoded.
    pub user_handle: String,
    /// Whether the user was verified (UV flag).
    pub user_verified: bool,
}

/// The signed assertion response to return to the browser.
pub struct AssertionResponse {
    /// authenticatorData, base64url-encoded.
    pub authenticator_data: String,
    /// DER-encoded signature over (authenticatorData || clientDataHash), base64url-encoded.
    pub signature: String,
    /// User handle, base64url-encoded.
    pub user_handle: String,
    /// Client data JSON, base64url-encoded (echoed back).
    pub client_data_json: String,
}

/// Build a WebAuthn `AuthenticatorAssertionResponse`.
///
/// Per the W3C WebAuthn spec, the authenticator signs the concatenation of
/// `authenticatorData || SHA-256(clientDataJSON)`.
pub fn build_assertion_response(input: &AssertionInput) -> Result<AssertionResponse, String> {
    // 1. Decode client data JSON
    let client_data_bytes = URL_SAFE_NO_PAD.decode(&input.client_data_json)
        .map_err(|e| format!("client_data_json decode: {}", e))?;

    // 2. Compute rpIdHash = SHA-256(rpId)
    let rp_id_hash = Sha256::digest(input.rp_id.as_bytes());

    // 3. Build authenticatorData
    //    Format: rpIdHash (32) || flags (1) || signCount (4)
    let mut auth_data = Vec::with_capacity(37);
    auth_data.extend_from_slice(&rp_id_hash);

    // Flags: bit 0 = UP (user present), bit 2 = UV (user verified)
    let mut flags: u8 = 0x01; // UP always set
    if input.user_verified {
        flags |= 0x04; // UV
    }
    auth_data.push(flags);

    // Sign count (big-endian u32)
    auth_data.extend_from_slice(&input.sign_count.to_be_bytes());

    // 4. Compute clientDataHash = SHA-256(clientDataJSON)
    let client_data_hash = Sha256::digest(&client_data_bytes);

    // 5. Sign (authenticatorData || clientDataHash)
    let mut signed_data = Vec::with_capacity(auth_data.len() + 32);
    signed_data.extend_from_slice(&auth_data);
    signed_data.extend_from_slice(&client_data_hash);

    let (private_key_bytes, algorithm) = decode_cose_private_key(&input.cose_private_key)?;
    let signature_bytes = sign_data(&signed_data, &private_key_bytes, &algorithm)?;

    Ok(AssertionResponse {
        authenticator_data: URL_SAFE_NO_PAD.encode(&auth_data),
        signature: URL_SAFE_NO_PAD.encode(&signature_bytes),
        user_handle: input.user_handle.clone(),
        client_data_json: input.client_data_json.clone(),
    })
}

/// Sign data using the appropriate algorithm.
fn sign_data(data: &[u8], private_key_bytes: &[u8], algorithm: &PasskeyAlgorithm) -> Result<Vec<u8>, String> {
    match algorithm {
        PasskeyAlgorithm::Es256 => sign_p256(data, private_key_bytes),
        PasskeyAlgorithm::EdDsa => sign_ed25519(data, private_key_bytes),
    }
}

fn sign_p256(data: &[u8], key_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let signing_key = P256SigningKey::from_bytes(key_bytes.into())
        .map_err(|e| format!("P-256 key decode: {}", e))?;
    let signature: P256Signature = signing_key.sign(data);
    Ok(signature.to_der().as_bytes().to_vec())
}

fn sign_ed25519(data: &[u8], key_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let secret: [u8; 32] = key_bytes.try_into()
        .map_err(|_| "Ed25519 key must be 32 bytes".to_string())?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
    use ed25519_dalek::Signer;
    let signature = signing_key.sign(data);
    Ok(signature.to_bytes().to_vec())
}

/// Verify a P-256 ECDSA signature (used for testing).
#[cfg(test)]
pub fn verify_p256_signature(
    data: &[u8],
    signature_der: &[u8],
    cose_private_key: &str,
) -> Result<bool, String> {
    let (key_bytes, _) = decode_cose_private_key(cose_private_key)?;
    let signing_key = P256SigningKey::from_bytes(key_bytes.as_slice().into())
        .map_err(|e| format!("P-256 key decode: {}", e))?;
    let verifying_key = signing_key.verifying_key();
    let sig = P256Signature::from_der(signature_der)
        .map_err(|e| format!("DER decode: {}", e))?;
    use p256::ecdsa::signature::Verifier;
    Ok(verifying_key.verify(data, &sig).is_ok())
}

/// Verify an Ed25519 signature (used for testing).
#[cfg(test)]
pub fn verify_ed25519_signature(
    data: &[u8],
    signature_bytes: &[u8],
    cose_private_key: &str,
) -> Result<bool, String> {
    let (key_bytes, _) = decode_cose_private_key(cose_private_key)?;
    let secret: [u8; 32] = key_bytes.try_into()
        .map_err(|_| "Ed25519 key must be 32 bytes".to_string())?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
    let verifying_key = signing_key.verifying_key();
    let sig = ed25519_dalek::Signature::from_bytes(
        signature_bytes.try_into().map_err(|_| "signature must be 64 bytes".to_string())?
    );
    use ed25519_dalek::Verifier;
    Ok(verifying_key.verify(data, &sig).is_ok())
}
