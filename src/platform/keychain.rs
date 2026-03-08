use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};

const SERVICE_NAME: &str = "com.vaultclaw.credential-manager";

/// Store the master password in the macOS Keychain.
pub fn store_master_password(vault_label: &str, password: &str) -> Result<(), KeychainError> {
    set_generic_password(SERVICE_NAME, vault_label, password.as_bytes())
        .map_err(|e| KeychainError::Store(e.to_string()))
}

/// Retrieve the master password from the macOS Keychain.
pub fn retrieve_master_password(vault_label: &str) -> Result<Option<String>, KeychainError> {
    match get_generic_password(SERVICE_NAME, vault_label) {
        Ok(bytes) => {
            let password = String::from_utf8(bytes.to_vec())
                .map_err(|e| KeychainError::Retrieve(e.to_string()))?;
            Ok(Some(password))
        }
        Err(e) => {
            let code = e.code();
            // errSecItemNotFound = -25300
            if code == -25300 {
                Ok(None)
            } else {
                Err(KeychainError::Retrieve(e.to_string()))
            }
        }
    }
}

/// Delete the master password from the macOS Keychain.
pub fn delete_master_password(vault_label: &str) -> Result<bool, KeychainError> {
    match delete_generic_password(SERVICE_NAME, vault_label) {
        Ok(()) => Ok(true),
        Err(e) => {
            let code = e.code();
            if code == -25300 {
                Ok(false) // Not found, nothing to delete
            } else {
                Err(KeychainError::Delete(e.to_string()))
            }
        }
    }
}

/// Check if a master password is stored for a vault.
pub fn has_stored_password(vault_label: &str) -> bool {
    matches!(retrieve_master_password(vault_label), Ok(Some(_)))
}

/// Errors from Keychain operations.
#[derive(Debug, Clone)]
pub enum KeychainError {
    Store(String),
    Retrieve(String),
    Delete(String),
}

impl std::fmt::Display for KeychainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeychainError::Store(msg) => write!(f, "Keychain store failed: {}", msg),
            KeychainError::Retrieve(msg) => write!(f, "Keychain retrieve failed: {}", msg),
            KeychainError::Delete(msg) => write!(f, "Keychain delete failed: {}", msg),
        }
    }
}

impl std::error::Error for KeychainError {}

#[cfg(test)]
mod tests {
    use super::*;

    // Use a unique label per test to avoid interference between parallel tests.
    fn test_label(suffix: &str) -> String {
        format!("vaultclaw-test-{}-{}", std::process::id(), suffix)
    }

    /// Try a keychain write; returns false if the keychain is locked or
    /// user interaction is not allowed (e.g. headless / CI environments).
    fn keychain_writable() -> bool {
        let probe = test_label("probe");
        match store_master_password(&probe, "probe") {
            Ok(()) => {
                let _ = delete_master_password(&probe);
                true
            }
            Err(_) => false,
        }
    }

    #[test]
    fn test_store_and_retrieve() {
        if !keychain_writable() {
            return; // skip — keychain not accessible
        }
        let label = test_label("store-retrieve");
        // Clean up in case of leftover from a previous run
        let _ = delete_master_password(&label);

        store_master_password(&label, "test_password_123").unwrap();
        let retrieved = retrieve_master_password(&label).unwrap();
        assert_eq!(retrieved.as_deref(), Some("test_password_123"));

        // Cleanup
        delete_master_password(&label).unwrap();
    }

    #[test]
    fn test_retrieve_not_found() {
        let label = test_label("not-found");
        let _ = delete_master_password(&label);

        let result = retrieve_master_password(&label).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_delete_existing() {
        if !keychain_writable() {
            return;
        }
        let label = test_label("delete-existing");
        let _ = delete_master_password(&label);

        store_master_password(&label, "to_delete").unwrap();
        let deleted = delete_master_password(&label).unwrap();
        assert!(deleted);

        // Verify it's gone
        let result = retrieve_master_password(&label).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_delete_not_found() {
        let label = test_label("delete-notfound");
        let _ = delete_master_password(&label);

        let deleted = delete_master_password(&label).unwrap();
        assert!(!deleted);
    }

    #[test]
    fn test_has_stored_password() {
        if !keychain_writable() {
            return;
        }
        let label = test_label("has-stored");
        let _ = delete_master_password(&label);

        assert!(!has_stored_password(&label));

        store_master_password(&label, "pw").unwrap();
        assert!(has_stored_password(&label));

        delete_master_password(&label).unwrap();
        assert!(!has_stored_password(&label));
    }

    #[test]
    fn test_overwrite_password() {
        if !keychain_writable() {
            return;
        }
        let label = test_label("overwrite");
        let _ = delete_master_password(&label);

        store_master_password(&label, "first").unwrap();
        store_master_password(&label, "second").unwrap();

        let retrieved = retrieve_master_password(&label).unwrap();
        assert_eq!(retrieved.as_deref(), Some("second"));

        delete_master_password(&label).unwrap();
    }

    #[test]
    fn test_keychain_error_display() {
        let err = KeychainError::Store("access denied".into());
        assert!(err.to_string().contains("Keychain store failed"));
        assert!(err.to_string().contains("access denied"));

        let err = KeychainError::Retrieve("not found".into());
        assert!(err.to_string().contains("Keychain retrieve failed"));

        let err = KeychainError::Delete("locked".into());
        assert!(err.to_string().contains("Keychain delete failed"));
    }

    #[test]
    fn test_service_name() {
        assert_eq!(SERVICE_NAME, "com.vaultclaw.credential-manager");
    }

    #[test]
    fn test_keychain_error_debug_and_clone() {
        let err = KeychainError::Store("test".into());
        let cloned = err.clone();
        assert_eq!(format!("{:?}", err), format!("{:?}", cloned));

        let err = KeychainError::Retrieve("test".into());
        let cloned = err.clone();
        assert_eq!(format!("{:?}", err), format!("{:?}", cloned));

        let err = KeychainError::Delete("test".into());
        let cloned = err.clone();
        assert_eq!(format!("{:?}", err), format!("{:?}", cloned));
    }

    #[test]
    fn test_keychain_error_is_error_trait() {
        let err = KeychainError::Store("oops".into());
        let dyn_err: &dyn std::error::Error = &err;
        assert!(dyn_err.source().is_none());
        assert!(dyn_err.to_string().contains("oops"));

        let err = KeychainError::Retrieve("oops".into());
        let dyn_err: &dyn std::error::Error = &err;
        assert!(dyn_err.source().is_none());

        let err = KeychainError::Delete("oops".into());
        let dyn_err: &dyn std::error::Error = &err;
        assert!(dyn_err.source().is_none());
    }

    #[test]
    fn test_has_stored_password_false_for_nonexistent() {
        let label = test_label("has-none");
        let _ = delete_master_password(&label);
        assert!(!has_stored_password(&label));
    }

    #[test]
    fn test_store_and_retrieve_special_chars() {
        if !keychain_writable() {
            return;
        }
        let label = test_label("special-chars");
        let _ = delete_master_password(&label);

        let special_pw = "p@ss!w0rd#$%^&*()_+{}|:<>?";
        store_master_password(&label, special_pw).unwrap();
        let retrieved = retrieve_master_password(&label).unwrap();
        assert_eq!(retrieved.as_deref(), Some(special_pw));

        delete_master_password(&label).unwrap();
    }

    #[test]
    fn test_store_and_retrieve_empty_password() {
        if !keychain_writable() {
            return;
        }
        let label = test_label("empty-pw");
        let _ = delete_master_password(&label);

        store_master_password(&label, "").unwrap();
        let retrieved = retrieve_master_password(&label).unwrap();
        assert_eq!(retrieved.as_deref(), Some(""));

        delete_master_password(&label).unwrap();
    }

    #[test]
    fn test_store_and_retrieve_unicode() {
        if !keychain_writable() {
            return;
        }
        let label = test_label("unicode-pw");
        let _ = delete_master_password(&label);

        let unicode_pw = "\u{1F512}\u{1F511} vault key \u{00FC}\u{00F6}\u{00E4}";
        store_master_password(&label, unicode_pw).unwrap();
        let retrieved = retrieve_master_password(&label).unwrap();
        assert_eq!(retrieved.as_deref(), Some(unicode_pw));

        delete_master_password(&label).unwrap();
    }

    #[test]
    fn test_store_and_delete_returns_true() {
        if !keychain_writable() {
            return;
        }
        let label = test_label("del-returns-true");
        let _ = delete_master_password(&label);

        store_master_password(&label, "temp").unwrap();
        let result = delete_master_password(&label).unwrap();
        assert!(result);
    }

    #[test]
    fn test_retrieve_after_delete_is_none() {
        if !keychain_writable() {
            return;
        }
        let label = test_label("retrieve-after-del");
        let _ = delete_master_password(&label);

        store_master_password(&label, "gone_soon").unwrap();
        delete_master_password(&label).unwrap();

        let retrieved = retrieve_master_password(&label).unwrap();
        assert_eq!(retrieved, None);
    }

    #[test]
    fn test_double_delete_second_returns_false() {
        if !keychain_writable() {
            return;
        }
        let label = test_label("double-del");
        let _ = delete_master_password(&label);

        store_master_password(&label, "temp").unwrap();
        let first = delete_master_password(&label).unwrap();
        assert!(first);
        let second = delete_master_password(&label).unwrap();
        assert!(!second);
    }

    #[test]
    fn test_has_stored_password_lifecycle() {
        if !keychain_writable() {
            return;
        }
        let label = test_label("has-lifecycle");
        let _ = delete_master_password(&label);

        // Initially not stored
        assert!(!has_stored_password(&label));

        // After store, should be found
        store_master_password(&label, "x").unwrap();
        assert!(has_stored_password(&label));

        // After overwrite, still found
        store_master_password(&label, "y").unwrap();
        assert!(has_stored_password(&label));

        // After delete, gone
        delete_master_password(&label).unwrap();
        assert!(!has_stored_password(&label));
    }

    #[test]
    fn test_store_long_password() {
        if !keychain_writable() {
            return;
        }
        let label = test_label("long-pw");
        let _ = delete_master_password(&label);

        let long_pw = "a".repeat(4096);
        store_master_password(&label, &long_pw).unwrap();
        let retrieved = retrieve_master_password(&label).unwrap();
        assert_eq!(retrieved.as_deref(), Some(long_pw.as_str()));

        delete_master_password(&label).unwrap();
    }
}
