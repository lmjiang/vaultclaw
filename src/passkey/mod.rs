//! Passkey (WebAuthn) support: key generation, COSE encoding, assertion signing.

mod keys;
mod webauthn;

pub use keys::{generate_passkey_credential, PasskeyKeyPair};
pub use webauthn::{build_assertion_response, AssertionInput, AssertionResponse};

#[cfg(test)]
mod tests;
