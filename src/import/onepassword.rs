use std::path::Path;

use serde::Deserialize;
use thiserror::Error;

use crate::vault::entry::*;

#[derive(Debug, Error)]
pub enum ImportError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("CSV parse error: {0}")]
    Csv(#[from] csv::Error),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),
}

/// A record from 1Password CSV export.
#[derive(Debug, Deserialize)]
struct OnePasswordCsvRecord {
    #[serde(alias = "Title", alias = "title")]
    title: String,
    #[serde(alias = "Url", alias = "URL", alias = "url")]
    url: Option<String>,
    #[serde(alias = "Username", alias = "username")]
    username: Option<String>,
    #[serde(alias = "Password", alias = "password")]
    password: Option<String>,
    #[serde(alias = "Notes", alias = "notes", alias = "notesPlain")]
    notes: Option<String>,
    #[serde(alias = "Type", alias = "type", alias = "typeName")]
    entry_type: Option<String>,
    #[serde(alias = "Tags", alias = "tags")]
    tags: Option<String>,
    #[serde(alias = "OTPAuth", alias = "otp", alias = "otpauth")]
    otp: Option<String>,
}

/// Result of an import operation.
#[derive(Debug)]
pub struct ImportResult {
    pub imported: Vec<Entry>,
    pub skipped: Vec<(String, String)>, // (title, reason)
    pub total_processed: usize,
}

/// Import entries from a 1Password CSV string.
pub fn import_csv_from_str(content: &str) -> Result<ImportResult, ImportError> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .has_headers(true)
        .from_reader(content.as_bytes());

    let mut imported = Vec::new();
    let mut skipped = Vec::new();
    let mut total = 0;

    for result in reader.deserialize() {
        total += 1;
        match result {
            Ok(record) => {
                let record: OnePasswordCsvRecord = record;
                match convert_record(record) {
                    Some(entry) => imported.push(entry),
                    None => skipped.push(("unknown".to_string(), "empty record".to_string())),
                }
            }
            Err(e) => {
                skipped.push(("parse error".to_string(), e.to_string()));
            }
        }
    }

    Ok(ImportResult {
        imported,
        skipped,
        total_processed: total,
    })
}

/// Import entries from a 1Password 1PIF string.
pub fn import_1pif_from_str(content: &str) -> Result<ImportResult, ImportError> {
    let mut imported = Vec::new();
    let mut skipped = Vec::new();
    let mut total = 0;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line == "***5642bee8-a5ff-11dc-8314-0800200c9a66***" {
            continue;
        }

        total += 1;

        match serde_json::from_str::<serde_json::Value>(line) {
            Ok(value) => match convert_1pif_entry(&value) {
                Some(entry) => imported.push(entry),
                None => skipped.push((
                    value.get("title").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                    "unsupported type".to_string(),
                )),
            },
            Err(e) => {
                skipped.push(("parse error".to_string(), e.to_string()));
            }
        }
    }

    Ok(ImportResult {
        imported,
        skipped,
        total_processed: total,
    })
}

/// Import entries from a 1Password CSV export file.
pub fn import_csv(path: &Path) -> Result<ImportResult, ImportError> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .has_headers(true)
        .from_path(path)?;

    let mut imported = Vec::new();
    let mut skipped = Vec::new();
    let mut total = 0;

    for result in reader.deserialize() {
        total += 1;
        match result {
            Ok(record) => {
                let record: OnePasswordCsvRecord = record;
                match convert_record(record) {
                    Some(entry) => imported.push(entry),
                    None => skipped.push(("unknown".to_string(), "empty record".to_string())),
                }
            }
            Err(e) => {
                skipped.push(("parse error".to_string(), e.to_string()));
            }
        }
    }

    Ok(ImportResult {
        imported,
        skipped,
        total_processed: total,
    })
}

/// Import entries from a 1Password 1PIF (JSON lines) export file.
pub fn import_1pif(path: &Path) -> Result<ImportResult, ImportError> {
    let content = std::fs::read_to_string(path)?;
    let mut imported = Vec::new();
    let mut skipped = Vec::new();
    let mut total = 0;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line == "***5642bee8-a5ff-11dc-8314-0800200c9a66***" {
            continue;
        }

        total += 1;

        match serde_json::from_str::<serde_json::Value>(line) {
            Ok(value) => match convert_1pif_entry(&value) {
                Some(entry) => imported.push(entry),
                None => skipped.push((
                    value.get("title").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                    "unsupported type".to_string(),
                )),
            },
            Err(e) => {
                skipped.push(("parse error".to_string(), e.to_string()));
            }
        }
    }

    Ok(ImportResult {
        imported,
        skipped,
        total_processed: total,
    })
}

fn convert_record(record: OnePasswordCsvRecord) -> Option<Entry> {
    if record.title.is_empty() {
        return None;
    }

    let notes_str = record.notes.unwrap_or_default();

    let credential = match record.entry_type.as_deref() {
        Some("securenote") | Some("Secure Note") | Some("note") => {
            Credential::SecureNote(SecureNoteCredential {
                content: notes_str.clone(),
            })
        }
        _ => {
            Credential::Login(LoginCredential {
                url: record.url.unwrap_or_default(),
                username: record.username.unwrap_or_default(),
                password: record.password.unwrap_or_default(),
            })
        }
    };

    let tags: Vec<String> = record
        .tags
        .map(|t| t.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();

    let mut entry = Entry::new(record.title, credential)
        .with_tags(tags)
        .with_notes(notes_str);

    if let Some(otp) = record.otp.filter(|s| !s.is_empty()) {
        // Try to extract secret from otpauth URI
        if let Ok(data) = crate::totp::parse_otpauth_uri(&otp) {
            entry = entry.with_totp(data.secret);
        } else {
            // Might be raw secret
            entry = entry.with_totp(otp);
        }
    }

    Some(entry)
}

fn convert_1pif_entry(value: &serde_json::Value) -> Option<Entry> {
    let title = value.get("title")?.as_str()?.to_string();
    let type_name = value.get("typeName").and_then(|v| v.as_str()).unwrap_or("webforms.WebForm");

    let credential = match type_name {
        "securenotes.SecureNote" => {
            let content = value
                .get("secureContents")
                .and_then(|v| v.get("notesPlain"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Credential::SecureNote(SecureNoteCredential { content })
        }
        _ => {
            let fields = value
                .get("secureContents")
                .and_then(|v| v.get("fields"))
                .and_then(|v| v.as_array());

            let mut username = String::new();
            let mut password = String::new();

            if let Some(fields) = fields {
                for field in fields {
                    let designation = field.get("designation").and_then(|v| v.as_str()).unwrap_or("");
                    let val = field.get("value").and_then(|v| v.as_str()).unwrap_or("");
                    match designation {
                        "username" => username = val.to_string(),
                        "password" => password = val.to_string(),
                        _ => {}
                    }
                }
            }

            let url = value
                .get("secureContents")
                .and_then(|v| v.get("URLs"))
                .and_then(|v| v.as_array())
                .and_then(|urls| urls.first())
                .and_then(|u| u.get("url"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            Credential::Login(LoginCredential {
                url,
                username,
                password,
            })
        }
    };

    let notes = value
        .get("secureContents")
        .and_then(|v| v.get("notesPlain"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let tags: Vec<String> = value
        .get("openContents")
        .and_then(|v| v.get("tags"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let favorite = value
        .get("openContents")
        .and_then(|v| v.get("faveIndex"))
        .is_some();

    let mut entry = Entry::new(title, credential)
        .with_tags(tags)
        .with_notes(notes)
        .with_favorite(favorite);

    // Check for TOTP
    if let Some(sections) = value
        .get("secureContents")
        .and_then(|v| v.get("sections"))
        .and_then(|v| v.as_array())
    {
        for section in sections {
            if let Some(fields) = section.get("fields").and_then(|v| v.as_array()) {
                for field in fields {
                    if field.get("n").and_then(|v| v.as_str()) == Some("TOTP") {
                        if let Some(totp_val) = field.get("v").and_then(|v| v.as_str()) {
                            entry = entry.with_totp(totp_val);
                        }
                    }
                }
            }
        }
    }

    Some(entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_csv(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.flush().unwrap();
        file
    }

    #[test]
    fn test_import_csv_basic() {
        let csv = write_csv(
            "Title,Url,Username,Password,Notes,Type,Tags\n\
             GitHub,https://github.com,octocat,pass123,My account,,dev\n\
             AWS,,admin,secret,,,,\n"
        );

        let result = import_csv(csv.path()).unwrap();
        assert_eq!(result.imported.len(), 2);
        assert_eq!(result.total_processed, 2);
        assert_eq!(result.imported[0].title, "GitHub");
        assert_eq!(result.imported[1].title, "AWS");
    }

    #[test]
    fn test_import_csv_with_tags() {
        let csv = write_csv(
            "Title,Url,Username,Password,Notes,Type,Tags\n\
             Test,https://test.com,user,pass,,,\"work, personal\"\n"
        );

        let result = import_csv(csv.path()).unwrap();
        assert_eq!(result.imported.len(), 1);
        assert_eq!(result.imported[0].tags, vec!["work", "personal"]);
    }

    #[test]
    fn test_import_csv_secure_note() {
        let csv = write_csv(
            "Title,Url,Username,Password,Notes,Type,Tags\n\
             Recovery Codes,,,,,Secure Note,\n"
        );

        let result = import_csv(csv.path()).unwrap();
        assert_eq!(result.imported.len(), 1);
        assert_eq!(result.imported[0].credential_type(), "secure_note");
    }

    #[test]
    fn test_import_csv_with_otp() {
        let csv = write_csv(
            "Title,Url,Username,Password,Notes,Type,Tags,OTPAuth\n\
             GitHub,https://github.com,user,pass,,,dev,otpauth://totp/GitHub:user?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\n"
        );

        let result = import_csv(csv.path()).unwrap();
        assert_eq!(result.imported.len(), 1);
        assert_eq!(
            result.imported[0].totp_secret.as_deref(),
            Some("JBSWY3DPEHPK3PXP")
        );
    }

    #[test]
    fn test_import_csv_with_empty_otp() {
        // OTP column exists but is empty → should not set totp_secret.
        // Covers the `if !otp.is_empty() { ... }` else branch.
        let csv = write_csv(
            "Title,Url,Username,Password,Notes,Type,Tags,OTPAuth\n\
             GitHub,https://github.com,user,pass,,,dev,\n"
        );
        let result = import_csv(csv.path()).unwrap();
        assert_eq!(result.imported.len(), 1);
        assert!(result.imported[0].totp_secret.is_none());
    }

    #[test]
    fn test_import_csv_with_raw_secret_otp() {
        // OTP value is a raw base32 secret, not an otpauth:// URI.
        // Covers the else branch in parse_otpauth_uri failure.
        let csv = write_csv(
            "Title,Url,Username,Password,Notes,Type,Tags,OTPAuth\n\
             GitHub,https://github.com,user,pass,,,dev,JBSWY3DPEHPK3PXP\n"
        );
        let result = import_csv(csv.path()).unwrap();
        assert_eq!(result.imported.len(), 1);
        assert_eq!(result.imported[0].totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn test_import_csv_empty_file() {
        let csv = write_csv("Title,Url,Username,Password,Notes,Type,Tags\n");

        let result = import_csv(csv.path()).unwrap();
        assert_eq!(result.imported.len(), 0);
        assert_eq!(result.total_processed, 0);
    }

    #[test]
    fn test_import_csv_nonexistent_file() {
        let result = import_csv(Path::new("/nonexistent/file.csv"));
        assert!(result.is_err());
    }

    #[test]
    fn test_import_1pif_basic() {
        let content = r#"{"title":"GitHub","secureContents":{"fields":[{"designation":"username","value":"octocat"},{"designation":"password","value":"pass123"}],"URLs":[{"url":"https://github.com"}],"notesPlain":"notes"},"typeName":"webforms.WebForm","openContents":{"tags":["dev"]}}
***5642bee8-a5ff-11dc-8314-0800200c9a66***
{"title":"Secure Note","secureContents":{"notesPlain":"secret content"},"typeName":"securenotes.SecureNote","openContents":{}}"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.flush().unwrap();

        let result = import_1pif(file.path()).unwrap();
        assert_eq!(result.imported.len(), 2);
        assert_eq!(result.imported[0].title, "GitHub");
        assert_eq!(result.imported[1].title, "Secure Note");
    }

    #[test]
    fn test_import_1pif_with_totp() {
        let content = r#"{"title":"Test","secureContents":{"fields":[{"designation":"username","value":"user"},{"designation":"password","value":"pass"}],"sections":[{"fields":[{"n":"TOTP","v":"JBSWY3DPEHPK3PXP"}]}]},"typeName":"webforms.WebForm","openContents":{}}"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.flush().unwrap();

        let result = import_1pif(file.path()).unwrap();
        assert_eq!(result.imported.len(), 1);
        assert_eq!(
            result.imported[0].totp_secret.as_deref(),
            Some("JBSWY3DPEHPK3PXP")
        );
    }

    #[test]
    fn test_import_1pif_with_favorite() {
        let content = r#"{"title":"Fav","secureContents":{},"typeName":"webforms.WebForm","openContents":{"faveIndex":1}}"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.flush().unwrap();

        let result = import_1pif(file.path()).unwrap();
        assert_eq!(result.imported.len(), 1);
        assert!(result.imported[0].favorite);
    }

    #[test]
    fn test_import_1pif_empty() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"").unwrap();
        file.flush().unwrap();

        let result = import_1pif(file.path()).unwrap();
        assert_eq!(result.imported.len(), 0);
    }

    #[test]
    fn test_import_result_skipped() {
        let csv = write_csv(
            "Title,Url,Username,Password,Notes,Type,Tags\n\
             GitHub,https://github.com,user,pass,,,\n"
        );

        let result = import_csv(csv.path()).unwrap();
        assert!(result.skipped.is_empty());
    }

    #[test]
    fn test_import_csv_empty_title_skipped() {
        let csv = write_csv(
            "Title,Url,Username,Password,Notes,Type,Tags\n\
             ,https://empty.com,user,pass,,,\n"
        );

        let result = import_csv(csv.path()).unwrap();
        assert_eq!(result.imported.len(), 0);
        assert_eq!(result.skipped.len(), 1);
        assert_eq!(result.total_processed, 1);
    }

    #[test]
    fn test_import_csv_with_raw_totp_secret() {
        let csv = write_csv(
            "Title,Url,Username,Password,Notes,Type,Tags,OTPAuth\n\
             Site,https://site.com,user,pass,,,dev,JBSWY3DPEHPK3PXP\n"
        );

        let result = import_csv(csv.path()).unwrap();
        assert_eq!(result.imported.len(), 1);
        // Raw secret (not otpauth URI) should be stored directly
        assert_eq!(
            result.imported[0].totp_secret.as_deref(),
            Some("JBSWY3DPEHPK3PXP")
        );
    }

    #[test]
    fn test_import_csv_securenote_variant_names() {
        // Test the "securenote" variant
        let csv = write_csv(
            "Title,Url,Username,Password,Notes,Type,Tags\n\
             Note1,,,,,securenote,\n\
             Note2,,,,,note,\n"
        );

        let result = import_csv(csv.path()).unwrap();
        assert_eq!(result.imported.len(), 2);
        assert_eq!(result.imported[0].credential_type(), "secure_note");
        assert_eq!(result.imported[1].credential_type(), "secure_note");
    }

    #[test]
    fn test_import_csv_empty_otp_field() {
        let csv = write_csv(
            "Title,Url,Username,Password,Notes,Type,Tags,OTPAuth\n\
             Site,https://site.com,user,pass,,,,\n"
        );

        let result = import_csv(csv.path()).unwrap();
        assert_eq!(result.imported.len(), 1);
        assert!(result.imported[0].totp_secret.is_none());
    }

    #[test]
    fn test_import_1pif_json_parse_error() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"this is not valid json\n").unwrap();
        file.flush().unwrap();

        let result = import_1pif(file.path()).unwrap();
        assert_eq!(result.imported.len(), 0);
        assert_eq!(result.skipped.len(), 1);
        assert_eq!(result.skipped[0].0, "parse error");
    }

    #[test]
    fn test_import_1pif_unknown_type_skipped() {
        // An entry with no "title" field → convert_1pif_entry returns None
        let content = r#"{"noTitle": true, "typeName": "passwords.Password"}"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.flush().unwrap();

        let result = import_1pif(file.path()).unwrap();
        assert_eq!(result.imported.len(), 0);
        assert_eq!(result.skipped.len(), 1);
    }

    #[test]
    fn test_import_1pif_unknown_field_designation() {
        // Has a field with an unknown designation (not username/password)
        let content = r#"{"title":"Test","secureContents":{"fields":[{"designation":"email","value":"test@example.com"},{"designation":"username","value":"user"},{"designation":"password","value":"pass"}]},"typeName":"webforms.WebForm","openContents":{}}"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.flush().unwrap();

        let result = import_1pif(file.path()).unwrap();
        assert_eq!(result.imported.len(), 1);
        // The unknown "email" designation should be ignored, username/password still captured
        let login = unwrap_login_credential(&result.imported[0].credential);
        assert_eq!(login.username, "user");
        assert_eq!(login.password, "pass");
    }

    #[test]
    fn test_import_1pif_no_fields() {
        // Entry with no fields array at all
        let content = r#"{"title":"NoFields","secureContents":{},"typeName":"webforms.WebForm","openContents":{}}"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.flush().unwrap();

        let result = import_1pif(file.path()).unwrap();
        assert_eq!(result.imported.len(), 1);
        let login = unwrap_login_credential(&result.imported[0].credential);
        assert!(login.username.is_empty());
        assert!(login.password.is_empty());
    }

    #[test]
    fn test_import_csv_malformed_record() {
        // Write a CSV with invalid UTF-8 bytes in the data row to trigger a deserialization error.
        use std::io::Write;
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"Title,Url,Username,Password,Notes,Type,Tags\n").unwrap();
        file.write_all(b"good,http://x,u,p,n,Login,\n").unwrap();
        // Invalid UTF-8 sequence in a row
        file.write_all(b"\xff\xfe,http://y,u2,p2,n2,Login,\n").unwrap();
        file.flush().unwrap();

        let result = import_csv(file.path()).unwrap();
        // First row imports fine, second row has invalid UTF-8 → parse error
        assert_eq!(result.imported.len(), 1);
        assert_eq!(result.skipped.len(), 1);
        assert_eq!(result.skipped[0].0, "parse error");
    }

    #[test]
    fn test_import_1pif_section_without_totp_n_field() {
        // Section has fields but none with n=TOTP, so no TOTP is extracted
        let content = r#"{"title":"NoTOTP","secureContents":{"fields":[{"designation":"username","value":"user"},{"designation":"password","value":"pass"}],"sections":[{"fields":[{"n":"other","v":"value123"}]}]},"typeName":"webforms.WebForm","openContents":{}}"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.flush().unwrap();

        let result = import_1pif(file.path()).unwrap();
        assert_eq!(result.imported.len(), 1);
        assert!(result.imported[0].totp_secret.is_none());
    }

    #[test]
    fn test_import_1pif_section_without_fields_key() {
        // Section exists but has no "fields" key at all → skips field iteration.
        // This covers the else path of `if let Some(fields) = section.get("fields")`.
        let content = r#"{"title":"NoFieldsSection","secureContents":{"fields":[{"designation":"username","value":"user"},{"designation":"password","value":"pass"}],"sections":[{"name":"empty section"}]},"typeName":"webforms.WebForm","openContents":{}}"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.flush().unwrap();

        let result = import_1pif(file.path()).unwrap();
        assert_eq!(result.imported.len(), 1);
        assert!(result.imported[0].totp_secret.is_none());
    }

    #[test]
    fn test_import_1pif_section_totp_without_v_field() {
        // Section has TOTP field but no "v" key
        let content = r#"{"title":"NoV","secureContents":{"fields":[{"designation":"username","value":"user"},{"designation":"password","value":"pass"}],"sections":[{"fields":[{"n":"TOTP"}]}]},"typeName":"webforms.WebForm","openContents":{}}"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.flush().unwrap();

        let result = import_1pif(file.path()).unwrap();
        assert_eq!(result.imported.len(), 1);
        assert!(result.imported[0].totp_secret.is_none());
    }

    fn unwrap_login_credential(cred: &Credential) -> &LoginCredential {
        match cred {
            Credential::Login(l) => l,
            other => panic!("Expected Login credential, got: {:?}", other),
        }
    }

    #[test]
    fn test_import_1pif_unknown_field_designation_with_helper() {
        let content = r#"{"title":"Test","secureContents":{"fields":[{"designation":"email","value":"test@example.com"},{"designation":"username","value":"user"},{"designation":"password","value":"pass"}]},"typeName":"webforms.WebForm","openContents":{}}"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.flush().unwrap();

        let result = import_1pif(file.path()).unwrap();
        let login = unwrap_login_credential(&result.imported[0].credential);
        assert_eq!(login.username, "user");
        assert_eq!(login.password, "pass");
    }

    #[test]
    #[should_panic(expected = "Expected Login credential")]
    fn test_unwrap_login_credential_wrong_type() {
        let cred = Credential::SecureNote(SecureNoteCredential { content: "x".to_string() });
        unwrap_login_credential(&cred);
    }

    #[test]
    fn test_import_1pif_separator_line_skipped() {
        // Only separator lines and empty lines → nothing imported
        let content = "***5642bee8-a5ff-11dc-8314-0800200c9a66***\n\n***5642bee8-a5ff-11dc-8314-0800200c9a66***\n";

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.flush().unwrap();

        let result = import_1pif(file.path()).unwrap();
        assert_eq!(result.imported.len(), 0);
        assert_eq!(result.total_processed, 0);
    }

    // ---- import_csv_from_str / import_1pif_from_str tests ----

    #[test]
    fn test_csv_from_str_basic() {
        let csv = "Title,Url,Username,Password,Notes\nGitHub,https://github.com,user,pass123,my notes";
        let result = import_csv_from_str(csv).unwrap();
        assert_eq!(result.imported.len(), 1);
        assert_eq!(result.imported[0].title, "GitHub");
        assert!(matches!(result.imported[0].credential, Credential::Login(_)));
    }

    #[test]
    fn test_csv_from_str_multiple() {
        let csv = "Title,Url,Username,Password\nA,https://a.com,u1,p1\nB,https://b.com,u2,p2\nC,https://c.com,u3,p3";
        let result = import_csv_from_str(csv).unwrap();
        assert_eq!(result.imported.len(), 3);
        assert_eq!(result.total_processed, 3);
    }

    #[test]
    fn test_csv_from_str_empty() {
        let csv = "Title,Url,Username,Password\n";
        let result = import_csv_from_str(csv).unwrap();
        assert_eq!(result.imported.len(), 0);
    }

    #[test]
    fn test_1pif_from_str_basic() {
        let pif = r#"{"title":"Test","typeName":"webforms.WebForm","secureContents":{"fields":[{"designation":"username","value":"u"},{"designation":"password","value":"p"}],"URLs":[{"url":"https://t.com"}]}}"#;
        let result = import_1pif_from_str(pif).unwrap();
        assert_eq!(result.imported.len(), 1);
        assert_eq!(result.imported[0].title, "Test");
    }

    #[test]
    fn test_1pif_from_str_with_separator() {
        let pif = "***5642bee8-a5ff-11dc-8314-0800200c9a66***\n\
            {\"title\":\"Entry1\",\"typeName\":\"webforms.WebForm\",\"secureContents\":{\"fields\":[{\"designation\":\"username\",\"value\":\"u\"},{\"designation\":\"password\",\"value\":\"p\"}]}}\n\
            ***5642bee8-a5ff-11dc-8314-0800200c9a66***";
        let result = import_1pif_from_str(pif).unwrap();
        assert_eq!(result.imported.len(), 1);
    }

    #[test]
    fn test_1pif_from_str_empty() {
        let result = import_1pif_from_str("").unwrap();
        assert_eq!(result.imported.len(), 0);
    }
}
