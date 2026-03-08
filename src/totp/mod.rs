use thiserror::Error;
use totp_rs::{Algorithm, TOTP, Secret};

#[derive(Debug, Error)]
pub enum TotpError {
    #[error("Invalid TOTP secret: {0}")]
    InvalidSecret(String),
    #[error("Invalid otpauth URI: {0}")]
    InvalidUri(String),
    #[error("TOTP generation failed: {0}")]
    GenerationFailed(String),
}

/// Result of generating a TOTP code.
#[derive(Debug, Clone)]
pub struct TotpCode {
    pub code: String,
    pub seconds_remaining: u64,
    pub period: u64,
}

/// Generate a TOTP code from a base32-encoded secret.
pub fn generate_totp(secret_base32: &str) -> Result<TotpCode, TotpError> {
    generate_totp_at(secret_base32, current_timestamp())
}

/// Generate a TOTP code at a specific timestamp (for testing).
pub fn generate_totp_at(secret_base32: &str, timestamp: u64) -> Result<TotpCode, TotpError> {
    let secret = Secret::Encoded(secret_base32.to_string());
    let secret_bytes = secret
        .to_bytes()
        .map_err(|e| TotpError::InvalidSecret(e.to_string()))?;

    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes, None, "".to_string())
        .map_err(|e| TotpError::GenerationFailed(e.to_string()))?;

    let code = totp
        .generate(timestamp);

    let period = 30u64;
    let seconds_remaining = period - (timestamp % period);

    Ok(TotpCode {
        code,
        seconds_remaining,
        period,
    })
}

/// Parse an otpauth:// URI and return the TOTP secret (base32).
pub fn parse_otpauth_uri(uri: &str) -> Result<OtpAuthData, TotpError> {
    if !uri.starts_with("otpauth://totp/") {
        return Err(TotpError::InvalidUri("Must start with otpauth://totp/".to_string()));
    }

    let parsed = url::Url::parse(uri)
        .map_err(|e| TotpError::InvalidUri(e.to_string()))?;

    let label = parsed.path().trim_start_matches('/').to_string();
    let label = urlencoding_decode(&label);

    let mut secret = None;
    let mut issuer = None;
    let mut digits = 6u32;
    let mut period = 30u64;
    let mut algorithm = "SHA1".to_string();

    for (key, value) in parsed.query_pairs() {
        match key.as_ref() {
            "secret" => secret = Some(value.to_string()),
            "issuer" => issuer = Some(value.to_string()),
            "digits" => digits = value.parse().unwrap_or(6),
            "period" => period = value.parse().unwrap_or(30),
            "algorithm" => algorithm = value.to_string(),
            _ => {}
        }
    }

    let secret = secret.ok_or_else(|| TotpError::InvalidUri("Missing secret parameter".to_string()))?;

    Ok(OtpAuthData {
        label,
        secret,
        issuer,
        digits,
        period,
        algorithm,
    })
}

fn urlencoding_decode(s: &str) -> String {
    url::form_urlencoded::parse(s.as_bytes())
        .map(|(k, v)| {
            if v.is_empty() {
                k.to_string()
            } else {
                format!("{}={}", k, v)
            }
        })
        .collect::<Vec<_>>()
        .join("")
}

/// Data extracted from an otpauth:// URI.
#[derive(Debug, Clone)]
pub struct OtpAuthData {
    pub label: String,
    pub secret: String,
    pub issuer: Option<String>,
    pub digits: u32,
    pub period: u64,
    pub algorithm: String,
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 test secret (base32 of "12345678901234567890")
    const TEST_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn test_generate_totp_known_vector() {
        // RFC 6238 test vector: at time 59, SHA1, 6 digits → "287082"
        // Note: totp-rs uses the secret directly, the RFC test vector
        // uses ASCII "12345678901234567890" as the secret.
        let result = generate_totp_at(TEST_SECRET, 59).unwrap();
        assert_eq!(result.code.len(), 6);
        assert_eq!(result.code, "287082");
    }

    #[test]
    fn test_generate_totp_different_times() {
        let t1 = generate_totp_at(TEST_SECRET, 0).unwrap();
        let t2 = generate_totp_at(TEST_SECRET, 30).unwrap();
        // Different time steps should (very likely) produce different codes
        // At t=0 and t=30 they're in different periods
        assert_ne!(t1.code, t2.code);
    }

    #[test]
    fn test_same_period_same_code() {
        let t1 = generate_totp_at(TEST_SECRET, 0).unwrap();
        let t2 = generate_totp_at(TEST_SECRET, 15).unwrap();
        // Same 30-second window → same code
        assert_eq!(t1.code, t2.code);
    }

    #[test]
    fn test_seconds_remaining() {
        let result = generate_totp_at(TEST_SECRET, 10).unwrap();
        assert_eq!(result.seconds_remaining, 20); // 30 - 10 = 20
        assert_eq!(result.period, 30);

        let result2 = generate_totp_at(TEST_SECRET, 29).unwrap();
        assert_eq!(result2.seconds_remaining, 1);

        let result3 = generate_totp_at(TEST_SECRET, 30).unwrap();
        assert_eq!(result3.seconds_remaining, 30); // New period starts
    }

    #[test]
    fn test_code_is_six_digits() {
        let result = generate_totp_at(TEST_SECRET, 1000000).unwrap();
        assert_eq!(result.code.len(), 6);
        assert!(result.code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_invalid_secret() {
        let result = generate_totp_at("not-valid-base32!!!", 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_totp_current_time() {
        // Just verify it doesn't crash with current time
        let result = generate_totp(TEST_SECRET);
        assert!(result.is_ok());
        let code = result.unwrap();
        assert_eq!(code.code.len(), 6);
        assert!(code.seconds_remaining > 0);
        assert!(code.seconds_remaining <= 30);
    }

    #[test]
    fn test_parse_otpauth_uri_basic() {
        let uri = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
        let data = parse_otpauth_uri(uri).unwrap();

        assert_eq!(data.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(data.issuer.as_deref(), Some("Example"));
        assert_eq!(data.digits, 6);
        assert_eq!(data.period, 30);
    }

    #[test]
    fn test_parse_otpauth_uri_all_params() {
        let uri = "otpauth://totp/Service:user?secret=JBSWY3DPEHPK3PXP&issuer=Service&digits=8&period=60&algorithm=SHA256";
        let data = parse_otpauth_uri(uri).unwrap();

        assert_eq!(data.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(data.issuer.as_deref(), Some("Service"));
        assert_eq!(data.digits, 8);
        assert_eq!(data.period, 60);
        assert_eq!(data.algorithm, "SHA256");
    }

    #[test]
    fn test_parse_otpauth_uri_minimal() {
        let uri = "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP";
        let data = parse_otpauth_uri(uri).unwrap();
        assert_eq!(data.secret, "JBSWY3DPEHPK3PXP");
        assert!(data.issuer.is_none());
    }

    #[test]
    fn test_parse_otpauth_uri_no_secret() {
        let uri = "otpauth://totp/Test?issuer=Foo";
        assert!(parse_otpauth_uri(uri).is_err());
    }

    #[test]
    fn test_parse_otpauth_uri_wrong_type() {
        let uri = "otpauth://hotp/Test?secret=JBSWY3DPEHPK3PXP";
        assert!(parse_otpauth_uri(uri).is_err());
    }

    #[test]
    fn test_parse_otpauth_uri_invalid() {
        assert!(parse_otpauth_uri("not a uri").is_err());
        assert!(parse_otpauth_uri("").is_err());
    }

    #[test]
    fn test_parse_otpauth_uri_unknown_param() {
        // Has an unknown parameter "foo" to hit the `_ => {}` branch
        let uri = "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&foo=bar";
        let data = parse_otpauth_uri(uri).unwrap();
        assert_eq!(data.secret, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn test_urlencoding_decode_with_values() {
        // Label with encoded characters that produce key=value pairs
        let uri = "otpauth://totp/Example%3Aalice%40example.com?secret=JBSWY3DPEHPK3PXP";
        let data = parse_otpauth_uri(uri).unwrap();
        assert!(data.label.contains("alice"));
    }

    #[test]
    fn test_urlencoding_decode_with_equals_sign() {
        // Label with a literal '=' (not percent-encoded) so form_urlencoded::parse
        // splits into k="Example", v="value" → hits the format!("{}={}", k, v) branch.
        let uri = "otpauth://totp/Example=value?secret=JBSWY3DPEHPK3PXP";
        let data = parse_otpauth_uri(uri).unwrap();
        assert!(data.label.contains("Example"));
        assert!(data.label.contains("value"));
    }
}
