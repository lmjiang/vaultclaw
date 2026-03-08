//! macOS Touch ID integration for vault unlock.
//!
//! Stores the vault's wrapped encryption key in the macOS Keychain protected by
//! biometry (Touch ID / Face ID). When the user authenticates via biometric,
//! the Keychain releases the wrapped key, which is then used to unwrap the
//! vault master key.
//!
//! The Keychain item uses `kSecAccessControlBiometryCurrentSet`, meaning the
//! item is invalidated if the biometric enrollment changes (e.g., new finger
//! added). This ensures the key is only accessible to the exact set of
//! biometrics that existed at enrollment time.

use core_foundation::base::TCFType;
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::string::CFString;
use security_framework::access_control::ProtectionMode;
use security_framework::access_control::SecAccessControl;
use security_framework_sys::access_control::kSecAccessControlBiometryCurrentSet;
use security_framework_sys::item::{
    kSecAttrAccessControl, kSecAttrAccount, kSecAttrService, kSecClass,
    kSecClassGenericPassword, kSecReturnData, kSecValueData,
};
use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete};
use std::ffi::c_void;

const SERVICE_NAME: &str = "com.vaultclaw.touchid";

/// Errors from Touch ID / Keychain operations.
#[derive(Debug, Clone)]
pub enum TouchIdError {
    /// Touch ID is not available on this system.
    NotAvailable(String),
    /// Failed to store key in Keychain.
    Store(String),
    /// Failed to retrieve key from Keychain (biometric auth failed or item not found).
    Retrieve(String),
    /// Failed to delete key from Keychain.
    Delete(String),
    /// The wrapped key was not found (Touch ID not enrolled for this vault).
    NotEnrolled,
}

impl std::fmt::Display for TouchIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TouchIdError::NotAvailable(msg) => write!(f, "Touch ID not available: {}", msg),
            TouchIdError::Store(msg) => write!(f, "Touch ID Keychain store failed: {}", msg),
            TouchIdError::Retrieve(msg) => write!(f, "Touch ID Keychain retrieve failed: {}", msg),
            TouchIdError::Delete(msg) => write!(f, "Touch ID Keychain delete failed: {}", msg),
            TouchIdError::NotEnrolled => write!(f, "Touch ID not enrolled for this vault"),
        }
    }
}

impl std::error::Error for TouchIdError {}

/// Account name for a vault label in the Keychain.
fn account_name(vault_label: &str) -> String {
    format!("vaultclaw-touchid-{}", vault_label)
}

/// Build a base query dictionary with class, service, and account.
unsafe fn base_query(vault_label: &str) -> core_foundation_sys::dictionary::CFMutableDictionaryRef {
    let dict = core_foundation_sys::dictionary::CFDictionaryCreateMutable(
        std::ptr::null(),
        0,
        &core_foundation_sys::dictionary::kCFTypeDictionaryKeyCallBacks,
        &core_foundation_sys::dictionary::kCFTypeDictionaryValueCallBacks,
    );

    core_foundation_sys::dictionary::CFDictionarySetValue(
        dict,
        kSecClass as *const c_void,
        kSecClassGenericPassword as *const c_void,
    );

    let service = CFString::new(SERVICE_NAME);
    core_foundation_sys::dictionary::CFDictionarySetValue(
        dict,
        kSecAttrService as *const c_void,
        service.as_concrete_TypeRef() as *const c_void,
    );

    let account = CFString::new(&account_name(vault_label));
    core_foundation_sys::dictionary::CFDictionarySetValue(
        dict,
        kSecAttrAccount as *const c_void,
        account.as_concrete_TypeRef() as *const c_void,
    );

    // We need to keep the CFStrings alive until after the dict is used.
    // Since CFDictionary retains values, we can release our handles safely.
    // The CFString::new creates owned handles, but CFDictionarySetValue calls CFRetain
    // on both key and value, so dropping our handles is safe.

    dict
}

/// Store a wrapped vault key in the Keychain, protected by biometry.
///
/// The key is stored as a generic password item with
/// `kSecAccessControlBiometryCurrentSet` access control, meaning:
/// - Touch ID (or Face ID) is required to read the item
/// - If biometric enrollment changes, the item becomes inaccessible
///
/// If an item already exists for this vault label, it is replaced.
pub fn store_wrapped_key(vault_label: &str, wrapped_key: &[u8]) -> Result<(), TouchIdError> {
    // Remove existing item first (ignore errors if not found)
    let _ = delete_wrapped_key(vault_label);

    // Create access control with biometry requirement
    let access_control = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
        kSecAccessControlBiometryCurrentSet as _,
    )
    .map_err(|e| TouchIdError::Store(format!("Failed to create access control: {}", e)))?;

    unsafe {
        let dict = base_query(vault_label);

        let data = CFData::from_buffer(wrapped_key);
        core_foundation_sys::dictionary::CFDictionarySetValue(
            dict,
            kSecValueData as *const c_void,
            data.as_concrete_TypeRef() as *const c_void,
        );

        core_foundation_sys::dictionary::CFDictionarySetValue(
            dict,
            kSecAttrAccessControl as *const c_void,
            access_control.as_concrete_TypeRef() as *const c_void,
        );

        let status = SecItemAdd(dict as _, std::ptr::null_mut());

        core_foundation_sys::base::CFRelease(dict as _);

        if status != 0 {
            return Err(TouchIdError::Store(format!(
                "SecItemAdd failed with status {}",
                status
            )));
        }
    }

    Ok(())
}

/// Retrieve the wrapped vault key from the Keychain.
///
/// This triggers a Touch ID prompt. If the user authenticates successfully,
/// the wrapped key bytes are returned. If authentication fails or the item
/// doesn't exist, an error is returned.
pub fn retrieve_wrapped_key(vault_label: &str) -> Result<Vec<u8>, TouchIdError> {
    unsafe {
        let dict = base_query(vault_label);

        core_foundation_sys::dictionary::CFDictionarySetValue(
            dict,
            kSecReturnData as *const c_void,
            CFBoolean::true_value().as_concrete_TypeRef() as *const c_void,
        );

        let mut result: core_foundation::base::CFTypeRef = std::ptr::null();
        let status = SecItemCopyMatching(dict as _, &mut result as *mut _ as *mut _);

        core_foundation_sys::base::CFRelease(dict as _);

        // errSecItemNotFound = -25300, errSecAuthFailed = -25293, errSecUserCanceled = -128
        if status == -25300 {
            return Err(TouchIdError::NotEnrolled);
        }
        if status != 0 {
            return Err(TouchIdError::Retrieve(format!(
                "SecItemCopyMatching failed with status {}",
                status
            )));
        }

        if result.is_null() {
            return Err(TouchIdError::NotEnrolled);
        }

        let data = CFData::wrap_under_create_rule(result as _);
        Ok(data.to_vec())
    }
}

/// Delete the wrapped vault key from the Keychain.
///
/// Returns `true` if an item was deleted, `false` if no item was found.
pub fn delete_wrapped_key(vault_label: &str) -> Result<bool, TouchIdError> {
    unsafe {
        let dict = base_query(vault_label);
        let status = SecItemDelete(dict as _);
        core_foundation_sys::base::CFRelease(dict as _);

        // errSecItemNotFound = -25300
        if status == -25300 {
            return Ok(false);
        }
        if status != 0 {
            return Err(TouchIdError::Delete(format!(
                "SecItemDelete failed with status {}",
                status
            )));
        }

        Ok(true)
    }
}

/// Check if Touch ID is enrolled for a vault (checks if a Keychain item exists).
///
/// This does NOT trigger a biometric prompt — it only checks for existence
/// by attempting a metadata-only query (no data retrieval).
pub fn is_enrolled(vault_label: &str) -> bool {
    unsafe {
        let dict = base_query(vault_label);
        let status = SecItemCopyMatching(dict as _, std::ptr::null_mut());
        core_foundation_sys::base::CFRelease(dict as _);
        status == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_label(suffix: &str) -> String {
        format!("test-{}-{}", std::process::id(), suffix)
    }

    #[test]
    fn test_account_name_format() {
        assert_eq!(account_name("default"), "vaultclaw-touchid-default");
        assert_eq!(account_name("my-vault"), "vaultclaw-touchid-my-vault");
    }

    #[test]
    fn test_service_name() {
        assert_eq!(SERVICE_NAME, "com.vaultclaw.touchid");
    }

    #[test]
    fn test_touchid_error_display() {
        let err = TouchIdError::NotAvailable("no sensor".into());
        assert!(err.to_string().contains("not available"));

        let err = TouchIdError::Store("failed".into());
        assert!(err.to_string().contains("store failed"));

        let err = TouchIdError::Retrieve("denied".into());
        assert!(err.to_string().contains("retrieve failed"));

        let err = TouchIdError::Delete("locked".into());
        assert!(err.to_string().contains("delete failed"));

        let err = TouchIdError::NotEnrolled;
        assert!(err.to_string().contains("not enrolled"));
    }

    #[test]
    fn test_is_enrolled_false_for_unknown() {
        let label = test_label("enrolled-check");
        assert!(!is_enrolled(&label));
    }

    #[test]
    fn test_delete_not_found() {
        let label = test_label("delete-notfound");
        let result = delete_wrapped_key(&label).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_retrieve_not_enrolled() {
        let label = test_label("not-enrolled");
        let result = retrieve_wrapped_key(&label);
        assert!(matches!(result, Err(TouchIdError::NotEnrolled)));
    }

    #[test]
    fn test_touchid_error_debug_and_clone() {
        let err = TouchIdError::NotAvailable("no hw".into());
        let cloned = err.clone();
        assert_eq!(format!("{:?}", err), format!("{:?}", cloned));

        let err = TouchIdError::Store("fail".into());
        let cloned = err.clone();
        assert_eq!(format!("{:?}", err), format!("{:?}", cloned));

        let err = TouchIdError::Retrieve("denied".into());
        let cloned = err.clone();
        assert_eq!(format!("{:?}", err), format!("{:?}", cloned));

        let err = TouchIdError::Delete("err".into());
        let cloned = err.clone();
        assert_eq!(format!("{:?}", err), format!("{:?}", cloned));

        let err = TouchIdError::NotEnrolled;
        let cloned = err.clone();
        assert_eq!(format!("{:?}", err), format!("{:?}", cloned));
    }

    #[test]
    fn test_touchid_error_is_error_trait() {
        let err = TouchIdError::NotAvailable("test".into());
        let dyn_err: &dyn std::error::Error = &err;
        assert!(dyn_err.source().is_none());
        assert!(dyn_err.to_string().contains("not available"));

        let err = TouchIdError::Store("test".into());
        let dyn_err: &dyn std::error::Error = &err;
        assert!(dyn_err.source().is_none());

        let err = TouchIdError::Retrieve("test".into());
        let dyn_err: &dyn std::error::Error = &err;
        assert!(dyn_err.source().is_none());

        let err = TouchIdError::Delete("test".into());
        let dyn_err: &dyn std::error::Error = &err;
        assert!(dyn_err.source().is_none());

        let err = TouchIdError::NotEnrolled;
        let dyn_err: &dyn std::error::Error = &err;
        assert!(dyn_err.source().is_none());
        assert!(dyn_err.to_string().contains("not enrolled"));
    }

    #[test]
    fn test_account_name_edge_cases() {
        assert_eq!(account_name(""), "vaultclaw-touchid-");
        assert_eq!(
            account_name("a-b-c-d"),
            "vaultclaw-touchid-a-b-c-d"
        );
        assert_eq!(
            account_name("with spaces"),
            "vaultclaw-touchid-with spaces"
        );
        assert_eq!(
            account_name("unicode\u{1F512}"),
            "vaultclaw-touchid-unicode\u{1F512}"
        );
    }

    #[test]
    fn test_base_query_creates_valid_dictionary() {
        // Exercise the unsafe base_query to cover dictionary construction lines
        unsafe {
            let label = test_label("base-query");
            let dict = base_query(&label);
            // dict should be non-null
            assert!(!dict.is_null());
            // Verify the dictionary has entries (class, service, account = 3)
            let count = core_foundation_sys::dictionary::CFDictionaryGetCount(dict);
            assert_eq!(count, 3);
            core_foundation_sys::base::CFRelease(dict as _);
        }
    }

    #[test]
    fn test_base_query_with_empty_label() {
        unsafe {
            let dict = base_query("");
            assert!(!dict.is_null());
            let count = core_foundation_sys::dictionary::CFDictionaryGetCount(dict);
            assert_eq!(count, 3);
            core_foundation_sys::base::CFRelease(dict as _);
        }
    }

    #[test]
    fn test_base_query_with_long_label() {
        unsafe {
            let long_label = "x".repeat(1024);
            let dict = base_query(&long_label);
            assert!(!dict.is_null());
            let count = core_foundation_sys::dictionary::CFDictionaryGetCount(dict);
            assert_eq!(count, 3);
            core_foundation_sys::base::CFRelease(dict as _);
        }
    }

    #[test]
    fn test_is_enrolled_multiple_nonexistent() {
        // Different labels should all be not enrolled
        for i in 0..5 {
            let label = test_label(&format!("not-enrolled-{}", i));
            assert!(!is_enrolled(&label));
        }
    }

    #[test]
    fn test_delete_not_found_multiple() {
        // Deleting various nonexistent labels should all return false
        for suffix in &["a", "b", "c", "nonexistent-key"] {
            let label = test_label(suffix);
            let result = delete_wrapped_key(&label).unwrap();
            assert!(!result);
        }
    }

    #[test]
    fn test_retrieve_not_enrolled_returns_correct_error() {
        let label = test_label("retrieve-err");
        let result = retrieve_wrapped_key(&label);
        match result {
            Err(TouchIdError::NotEnrolled) => {} // expected
            Err(other) => panic!("Expected NotEnrolled, got: {:?}", other),
            Ok(_) => panic!("Expected error, got Ok"),
        }
    }

    #[test]
    fn test_delete_then_is_enrolled_false() {
        let label = test_label("del-enrolled");
        // Even if nothing exists, delete + is_enrolled should be consistent
        let _ = delete_wrapped_key(&label);
        assert!(!is_enrolled(&label));
    }

    #[test]
    fn test_touchid_error_display_messages() {
        // More thorough display message checks
        let err = TouchIdError::NotAvailable("hardware missing".into());
        assert_eq!(
            err.to_string(),
            "Touch ID not available: hardware missing"
        );

        let err = TouchIdError::Store("access denied".into());
        assert_eq!(
            err.to_string(),
            "Touch ID Keychain store failed: access denied"
        );

        let err = TouchIdError::Retrieve("auth failed".into());
        assert_eq!(
            err.to_string(),
            "Touch ID Keychain retrieve failed: auth failed"
        );

        let err = TouchIdError::Delete("item locked".into());
        assert_eq!(
            err.to_string(),
            "Touch ID Keychain delete failed: item locked"
        );

        let err = TouchIdError::NotEnrolled;
        assert_eq!(
            err.to_string(),
            "Touch ID not enrolled for this vault"
        );
    }

    // Interactive Touch ID tests — run with:
    //   cargo test -- --ignored touchid
    // These require a Mac with Touch ID hardware.

    #[test]
    #[ignore]
    fn test_store_and_retrieve_wrapped_key() {
        let label = test_label("store-retrieve");
        let key_data = vec![42u8; 72]; // 72 bytes = wrapped key size

        store_wrapped_key(&label, &key_data).unwrap();
        assert!(is_enrolled(&label));

        // This will trigger Touch ID prompt
        let retrieved = retrieve_wrapped_key(&label).unwrap();
        assert_eq!(retrieved, key_data);

        delete_wrapped_key(&label).unwrap();
    }

    #[test]
    #[ignore]
    fn test_delete_wrapped_key() {
        let label = test_label("delete");
        let key_data = vec![7u8; 72];

        store_wrapped_key(&label, &key_data).unwrap();
        let deleted = delete_wrapped_key(&label).unwrap();
        assert!(deleted);
        assert!(!is_enrolled(&label));
    }

    #[test]
    #[ignore]
    fn test_store_overwrites_existing() {
        let label = test_label("overwrite");
        let key1 = vec![1u8; 72];
        let key2 = vec![2u8; 72];

        store_wrapped_key(&label, &key1).unwrap();
        store_wrapped_key(&label, &key2).unwrap();

        let retrieved = retrieve_wrapped_key(&label).unwrap();
        assert_eq!(retrieved, key2);

        delete_wrapped_key(&label).unwrap();
    }
}
