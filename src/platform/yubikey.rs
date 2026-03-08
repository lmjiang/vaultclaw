//! YubiKey FIDO2 hmac-secret operations via ctap-hid-fido2.
//!
//! This module is only compiled with the `yubikey` feature flag.

use ctap_hid_fido2::{
    Cfg, FidoKeyHid, FidoKeyHidFactory,
    fidokey::GetAssertionArgsBuilder,
    fidokey::MakeCredentialArgsBuilder,
    verifier,
    HidParam,
};

/// Information about a connected FIDO2 device.
#[derive(Debug, Clone)]
pub struct FidoDevice {
    pub product_name: String,
    pub manufacturer: String,
}

/// List connected FIDO2 devices.
pub fn list_devices() -> Result<Vec<FidoDevice>, String> {
    let devs = FidoKeyHidFactory::create(&Cfg::init())
        .map_err(|e| format!("Failed to enumerate FIDO2 devices: {}", e))?;

    Ok(devs
        .iter()
        .map(|d| FidoDevice {
            product_name: d.get_info().map(|i| i.product.clone()).unwrap_or_default(),
            manufacturer: d.get_info().map(|i| i.manufacturer.clone()).unwrap_or_default(),
        })
        .collect())
}

/// Enroll a new FIDO2 credential with hmac-secret extension.
/// Returns (credential_id, hmac_secret_output).
pub fn enroll(
    device: &FidoKeyHid,
    rp_id: &str,
    user_id: &[u8],
    user_name: &str,
    salt: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 32]), String> {
    // Create credential with hmac-secret extension
    let args = MakeCredentialArgsBuilder::new(rp_id, &verifier::create_challenge())
        .extensions(&["hmac-secret"])
        .build();

    let attestation = device
        .make_credential_with_args(&args)
        .map_err(|e| format!("MakeCredential failed: {}", e))?;

    let cred_id = attestation.credential_descriptor.id.clone();

    // Immediately derive the hmac-secret
    let secret = derive_secret(device, rp_id, &cred_id, salt)?;

    Ok((cred_id, secret))
}

/// Create a FIDO2 resident/discoverable credential on the YubiKey for use as a passkey.
/// Returns (credential_id_bytes, public_key_der) — the private key stays on the device.
pub fn create_resident_credential(
    device: &FidoKeyHid,
    rp_id: &str,
    rp_name: &str,
    user_id: &[u8],
    user_name: &str,
) -> Result<Vec<u8>, String> {
    let args = MakeCredentialArgsBuilder::new(rp_id, &verifier::create_challenge())
        .resident_key()
        .build();

    let attestation = device
        .make_credential_with_args(&args)
        .map_err(|e| format!("MakeCredential (resident) failed: {}", e))?;

    Ok(attestation.credential_descriptor.id.clone())
}

/// Sign an assertion on the YubiKey with a resident credential.
/// Returns (authenticator_data, signature, credential_id) from the hardware key.
pub fn assert_with_resident(
    device: &FidoKeyHid,
    rp_id: &str,
    credential_id: Option<&[u8]>,
) -> Result<HardwareAssertionResult, String> {
    let mut builder = GetAssertionArgsBuilder::new(rp_id, &verifier::create_challenge());
    if let Some(cid) = credential_id {
        builder = builder.credential_id(cid);
    }
    let args = builder.build();

    let assertions = device
        .get_assertion_with_args(&args)
        .map_err(|e| format!("GetAssertion (resident) failed: {}", e))?;

    let assertion = assertions
        .first()
        .ok_or_else(|| "No assertion returned".to_string())?;

    let auth_data = assertion.auth_data.to_vec();
    let sig = assertion.signature.to_vec();
    let cred_id = assertion.credential_id
        .as_ref()
        .map(|c| c.id.clone())
        .unwrap_or_default();
    let user_handle = assertion.user
        .as_ref()
        .map(|u| u.id.clone())
        .unwrap_or_default();

    Ok(HardwareAssertionResult {
        authenticator_data: auth_data,
        signature: sig,
        credential_id: cred_id,
        user_handle,
    })
}

/// Result from a hardware assertion operation.
#[derive(Debug, Clone)]
pub struct HardwareAssertionResult {
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub user_handle: Vec<u8>,
}

/// List discoverable (resident) credentials on the device for a given rp_id.
pub fn list_resident_credentials(
    device: &FidoKeyHid,
    rp_id: &str,
) -> Result<Vec<ResidentCredentialInfo>, String> {
    // Attempt to enumerate via GetAssertion with no credential ID
    // If multiple credentials exist, CTAP2 returns them all
    let args = GetAssertionArgsBuilder::new(rp_id, &verifier::create_challenge())
        .build();

    match device.get_assertion_with_args(&args) {
        Ok(assertions) => {
            Ok(assertions.iter().map(|a| {
                ResidentCredentialInfo {
                    credential_id: a.credential_id
                        .as_ref()
                        .map(|c| c.id.clone())
                        .unwrap_or_default(),
                    user_handle: a.user
                        .as_ref()
                        .map(|u| u.id.clone())
                        .unwrap_or_default(),
                    user_name: a.user
                        .as_ref()
                        .and_then(|u| u.name.clone())
                        .unwrap_or_default(),
                }
            }).collect())
        }
        Err(_) => {
            // No credentials found for this rpId
            Ok(vec![])
        }
    }
}

/// Info about a resident credential discovered on hardware.
#[derive(Debug, Clone)]
pub struct ResidentCredentialInfo {
    pub credential_id: Vec<u8>,
    pub user_handle: Vec<u8>,
    pub user_name: String,
}

/// Derive a 32-byte secret from an enrolled FIDO2 credential using hmac-secret.
pub fn derive_secret(
    device: &FidoKeyHid,
    rp_id: &str,
    credential_id: &[u8],
    salt: &[u8; 32],
) -> Result<[u8; 32], String> {
    let args = GetAssertionArgsBuilder::new(rp_id, &verifier::create_challenge())
        .extensions(&[("hmac-secret", salt.to_vec())])
        .credential_id(credential_id)
        .build();

    let assertions = device
        .get_assertion_with_args(&args)
        .map_err(|e| format!("GetAssertion failed: {}", e))?;

    let assertion = assertions
        .first()
        .ok_or_else(|| "No assertion returned".to_string())?;

    let hmac_output = assertion
        .extensions
        .as_ref()
        .and_then(|e| e.hmac_secret.as_ref())
        .ok_or_else(|| "hmac-secret extension not in response".to_string())?;

    if hmac_output.len() != 32 {
        return Err(format!("Unexpected hmac-secret length: {}", hmac_output.len()));
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(hmac_output);
    Ok(out)
}

#[cfg(test)]
mod tests {
    // Hardware-dependent tests — run with `cargo test --features yubikey -- --ignored`

    #[test]
    #[ignore]
    fn test_list_devices() {
        let devices = super::list_devices().unwrap();
        println!("Found {} FIDO2 device(s):", devices.len());
        for d in &devices {
            println!("  {} ({})", d.product_name, d.manufacturer);
        }
    }
}
