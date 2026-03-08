use clap::Subcommand;
use uuid::Uuid;

use crate::security::health::{analyze_vault_health, extract_password};
use crate::security::llm::{format_enhanced_report, EnhancedReport};
use crate::security::report::{format_report_text, generate_report};
use crate::security::rotation::{
    format_rotation_plans, format_rotation_summary, RotationPlan, RotationScheduler,
    RotationTrigger,
};
use crate::vault::format::VaultFile;

/// Subcommands for `vaultclaw rotate`.
#[derive(Subcommand, Debug, Clone)]
pub enum RotateCommands {
    /// Scan vault and create rotation plans for weak/old/reused passwords
    Scan,
    /// List current rotation plans
    List,
    /// Show rotation summary
    Status,
    /// Approve a pending rotation plan
    Approve {
        /// Plan ID (first 8 chars or full UUID)
        plan_id: String,
    },
    /// Dismiss a pending rotation plan
    Dismiss {
        /// Plan ID (first 8 chars or full UUID)
        plan_id: String,
        /// Reason for dismissal
        #[arg(short, long, default_value = "user dismissed")]
        reason: String,
    },
    /// Manually create a rotation plan for a specific entry
    Add {
        /// Entry title or ID
        query: String,
    },
}

/// Handle the `health` command: analyze vault password health.
pub fn cmd_health_with_vault(vault: &VaultFile, json_output: bool) -> anyhow::Result<()> {
    let entries: Vec<_> = vault.store().list().into_iter().collect();
    let report = analyze_vault_health(&entries);

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("=== Vault Health ===\n");
        println!("Health Score: {}/100", report.health_score);
        println!("Total entries:    {}", report.total_entries);
        println!("Login entries:    {}", report.login_entries);
        println!("Weak passwords:   {}", report.weak_passwords);
        println!("Reused passwords: {}", report.reused_passwords);
        println!("Old passwords:    {}", report.old_passwords);
        println!("Without 2FA:      {}", report.entries_without_totp);

        if !report.details.is_empty() {
            println!("\n--- Details ---");
            for detail in &report.details {
                let issues = if detail.issues.is_empty() {
                    "OK".to_string()
                } else {
                    detail.issues.join(", ")
                };
                println!(
                    "  {} — {} (age: {}d) {}",
                    detail.title,
                    detail.strength.label(),
                    detail.age_days,
                    issues
                );
            }
        }
    }
    Ok(())
}

/// Handle the `breach` command: check passwords against HIBP.
pub fn cmd_breach_with_vault(
    vault: &VaultFile,
    check_all: bool,
    entry_filter: Option<&str>,
    json_output: bool,
) -> anyhow::Result<()> {
    let all_entries: Vec<_> = vault.store().list().into_iter().collect();

    // Filter to specific entry if --entry is provided
    let entries: Vec<_> = if let Some(filter) = entry_filter {
        let lower = filter.to_lowercase();
        all_entries
            .into_iter()
            .filter(|e| e.title.to_lowercase().contains(&lower))
            .collect()
    } else {
        all_entries
    };

    let to_check: Vec<_> = entries
        .iter()
        .filter_map(|entry| {
            extract_password(entry).map(|pw| (entry.id, entry.title.clone(), pw.to_string()))
        })
        .collect();

    if to_check.is_empty() {
        if json_output {
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "checked": 0,
                "breached": [],
                "errors": [],
            }))?);
        } else {
            println!("No passwords to check.");
        }
        return Ok(());
    }

    if !json_output {
        println!(
            "Checking {} password(s) against Have I Been Pwned...",
            to_check.len()
        );
    }

    let rt = tokio::runtime::Runtime::new()?;
    let mut breached = Vec::new();
    let mut errors = Vec::new();

    for (i, (id, title, password)) in to_check.iter().enumerate() {
        // Rate limit: 1.5s between HIBP API requests (free tier)
        if i > 0 {
            std::thread::sleep(std::time::Duration::from_millis(1500));
        }

        match rt.block_on(crate::security::breach::check_password_breach(password)) {
            Ok(result) => {
                if result.breached {
                    breached.push(serde_json::json!({
                        "entry_id": id,
                        "title": title,
                        "count": result.count,
                    }));
                    if !json_output {
                        println!(
                            "  [BREACHED] {} — found in {} breaches",
                            title, result.count
                        );
                    }
                } else if !json_output && check_all {
                    println!("  [OK] {}", title);
                }
            }
            Err(e) => {
                errors.push(serde_json::json!({
                    "entry_id": id,
                    "title": title,
                    "error": e.to_string(),
                }));
                if !json_output {
                    println!("  [ERROR] {} — {}", title, e);
                }
            }
        }
    }

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "checked": to_check.len(),
                "breached": breached,
                "errors": errors,
            }))?
        );
    } else {
        println!(
            "\nChecked: {} | Breached: {} | Errors: {}",
            to_check.len(),
            breached.len(),
            errors.len()
        );
    }
    Ok(())
}

/// Handle the `watch` command: generate a full security report.
pub fn cmd_watch_with_vault(vault: &VaultFile, json_output: bool) -> anyhow::Result<()> {
    let entries: Vec<_> = vault.store().list().into_iter().collect();
    let report = generate_report(&entries);

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", format_report_text(&report));
    }
    Ok(())
}

/// Handle the `report` command: AI-enhanced security report.
pub fn cmd_report_with_vault(vault: &VaultFile, json_output: bool) -> anyhow::Result<()> {
    let entries: Vec<_> = vault.store().list().into_iter().collect();
    let report = generate_report(&entries);
    let enhanced = EnhancedReport::without_llm(report);

    if json_output {
        println!("{}", serde_json::to_string_pretty(&enhanced)?);
    } else {
        print!("{}", format_enhanced_report(&enhanced));
    }
    Ok(())
}

/// Handle `vaultclaw rotate <subcommand>`.
pub fn handle_rotate_command(
    command: RotateCommands,
    vault: &mut VaultFile,
    json_output: bool,
) -> anyhow::Result<()> {
    match command {
        RotateCommands::Scan => cmd_rotate_scan(vault, json_output),
        RotateCommands::List => cmd_rotate_list(json_output),
        RotateCommands::Status => cmd_rotate_status(json_output),
        RotateCommands::Approve { plan_id } => cmd_rotate_approve(&plan_id, json_output),
        RotateCommands::Dismiss { plan_id, reason } => {
            cmd_rotate_dismiss(&plan_id, &reason, json_output)
        }
        RotateCommands::Add { query } => cmd_rotate_add(vault, &query, json_output),
    }
}

fn cmd_rotate_scan(vault: &VaultFile, json_output: bool) -> anyhow::Result<()> {
    let entries: Vec<_> = vault.store().list().into_iter().collect();
    let health = analyze_vault_health(&entries);

    let mut scheduler = RotationScheduler::new();
    let created = scheduler.scan_and_plan(&health.details);

    if json_output {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "scanned": entries.len(),
            "new_plans": created,
            "plans": scheduler.list_plans(),
        }))?);
    } else {
        println!("Scanned {} entries, created {} rotation plan(s).\n", entries.len(), created);
        if created > 0 {
            let plans: Vec<_> = scheduler.list_plans().iter().collect();
            print!("{}", format_rotation_plans(&plans));
        }
    }
    Ok(())
}

fn cmd_rotate_list(json_output: bool) -> anyhow::Result<()> {
    // In the current implementation, rotation state is session-local.
    // Future: persist in vault or daemon state.
    let scheduler = RotationScheduler::new();
    let plans: Vec<_> = scheduler.list_plans().iter().collect();

    if json_output {
        println!("{}", serde_json::to_string_pretty(&scheduler.list_plans())?);
    } else {
        print!("{}", format_rotation_plans(&plans));
    }
    Ok(())
}

fn cmd_rotate_status(json_output: bool) -> anyhow::Result<()> {
    let scheduler = RotationScheduler::new();
    let summary = scheduler.summary();

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        print!("{}", format_rotation_summary(&summary));
    }
    Ok(())
}

fn cmd_rotate_approve(plan_id: &str, json_output: bool) -> anyhow::Result<()> {
    let _uuid = parse_plan_id(plan_id)?;

    // Future: look up plan in persistent scheduler state
    if json_output {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "plan_id": plan_id,
            "status": "not_found",
            "message": "Rotation plans are session-scoped. Use `rotate scan` first, then approve interactively.",
        }))?);
    } else {
        println!(
            "Plan {} not found. Rotation plans are currently session-scoped.\n\
             Use `vaultclaw rotate scan` to create plans, then approve interactively.",
            plan_id
        );
    }
    Ok(())
}

fn cmd_rotate_dismiss(plan_id: &str, _reason: &str, json_output: bool) -> anyhow::Result<()> {
    let _uuid = parse_plan_id(plan_id)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "plan_id": plan_id,
            "status": "not_found",
            "message": "Rotation plans are session-scoped. Use `rotate scan` first.",
        }))?);
    } else {
        println!(
            "Plan {} not found. Rotation plans are currently session-scoped.",
            plan_id
        );
    }
    Ok(())
}

fn cmd_rotate_add(vault: &VaultFile, query: &str, json_output: bool) -> anyhow::Result<()> {
    let entries = vault.store().list();
    let found = entries
        .iter()
        .find(|e| e.title.to_lowercase().contains(&query.to_lowercase()));

    let entry = match found {
        Some(e) => e,
        None => anyhow::bail!("No entry matching '{}'", query),
    };

    let plan = RotationPlan::new(entry.id, entry.title.clone(), RotationTrigger::Manual);

    if json_output {
        println!("{}", serde_json::to_string_pretty(&plan)?);
    } else {
        println!("Created manual rotation plan for '{}'", entry.title);
        println!("Plan ID: {}", plan.id);
        println!("Status: PENDING (awaiting approval)");
    }
    Ok(())
}

/// Parse a plan ID from a short prefix or full UUID string.
fn parse_plan_id(id_str: &str) -> anyhow::Result<Uuid> {
    // Try full UUID first
    if let Ok(uuid) = Uuid::parse_str(id_str) {
        return Ok(uuid);
    }

    // If it's a short prefix, we can't resolve without the scheduler state
    // Just validate it looks like a hex prefix
    if id_str.len() >= 4 && id_str.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        // Return a nil UUID as placeholder — the caller handles "not found"
        return Ok(Uuid::nil());
    }

    anyhow::bail!("Invalid plan ID: '{}'. Use a UUID or hex prefix.", id_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::KdfParams;
    use crate::crypto::keys::password_secret;
    use crate::vault::entry::*;
    use crate::vault::format::VaultFile;

    fn create_test_vault_for_security() -> (tempfile::TempDir, VaultFile) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("testpass".to_string());
        let vault = VaultFile::create(&path, &password, KdfParams::fast_for_testing()).unwrap();
        (dir, vault)
    }

    fn add_login(vault: &mut VaultFile, title: &str, password: &str) {
        vault.store_mut().add(
            Entry::new(
                title.to_string(),
                Credential::Login(LoginCredential {
                    url: format!("https://{}.com", title.to_lowercase()),
                    username: "user".to_string(),
                    password: password.to_string(),
                }),
            ),
        );
    }

    // ---- Health command tests ----

    #[test]
    fn test_cmd_health_empty_vault() {
        let (_dir, vault) = create_test_vault_for_security();
        let result = cmd_health_with_vault(&vault, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_health_empty_vault_json() {
        let (_dir, vault) = create_test_vault_for_security();
        let result = cmd_health_with_vault(&vault, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_health_with_weak_password() {
        let (_dir, mut vault) = create_test_vault_for_security();
        add_login(&mut vault, "Weak Site", "123");
        let result = cmd_health_with_vault(&vault, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_health_with_weak_password_json() {
        let (_dir, mut vault) = create_test_vault_for_security();
        add_login(&mut vault, "Weak Site", "123");
        let result = cmd_health_with_vault(&vault, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_health_with_strong_password() {
        let (_dir, mut vault) = create_test_vault_for_security();
        add_login(&mut vault, "Strong Site", "c0mpl3x!P@ssw0rd#2024xYz");
        let result = cmd_health_with_vault(&vault, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_health_with_mixed_entries() {
        let (_dir, mut vault) = create_test_vault_for_security();
        add_login(&mut vault, "Strong", "c0mpl3x!P@ssw0rd#2024xYz");
        add_login(&mut vault, "Weak", "123");
        vault.store_mut().add(
            Entry::new(
                "Note".to_string(),
                Credential::SecureNote(SecureNoteCredential {
                    content: "secret".to_string(),
                }),
            ),
        );
        let result = cmd_health_with_vault(&vault, false);
        assert!(result.is_ok());
    }

    // ---- Breach command tests ----

    #[test]
    fn test_cmd_breach_empty_vault() {
        let (_dir, vault) = create_test_vault_for_security();
        let result = cmd_breach_with_vault(&vault, false, None, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_breach_empty_vault_json() {
        let (_dir, vault) = create_test_vault_for_security();
        let result = cmd_breach_with_vault(&vault, false, None, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_breach_with_entries() {
        let (_dir, mut vault) = create_test_vault_for_security();
        add_login(&mut vault, "TestSite", "password123");
        let result = cmd_breach_with_vault(&vault, false, None, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_breach_with_entries_all() {
        let (_dir, mut vault) = create_test_vault_for_security();
        add_login(&mut vault, "TestSite", "password123");
        let result = cmd_breach_with_vault(&vault, true, None, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_breach_with_entries_json() {
        let (_dir, mut vault) = create_test_vault_for_security();
        add_login(&mut vault, "TestSite", "password123");
        let result = cmd_breach_with_vault(&vault, false, None, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_breach_with_entries_all_json() {
        let (_dir, mut vault) = create_test_vault_for_security();
        add_login(&mut vault, "TestSite", "password123");
        let result = cmd_breach_with_vault(&vault, true, None, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_breach_only_secure_notes() {
        let (_dir, mut vault) = create_test_vault_for_security();
        vault.store_mut().add(
            Entry::new(
                "Note".to_string(),
                Credential::SecureNote(SecureNoteCredential {
                    content: "secret".to_string(),
                }),
            ),
        );
        let result = cmd_breach_with_vault(&vault, false, None, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_breach_with_entry_filter() {
        let (_dir, mut vault) = create_test_vault_for_security();
        add_login(&mut vault, "GitHub", "password123");
        add_login(&mut vault, "AWS", "secret456");
        let result = cmd_breach_with_vault(&vault, false, Some("github"), false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_breach_with_entry_filter_json() {
        let (_dir, mut vault) = create_test_vault_for_security();
        add_login(&mut vault, "GitHub", "password123");
        let result = cmd_breach_with_vault(&vault, false, Some("github"), true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_breach_with_entry_filter_not_found() {
        let (_dir, mut vault) = create_test_vault_for_security();
        add_login(&mut vault, "GitHub", "password123");
        let result = cmd_breach_with_vault(&vault, false, Some("nonexistent"), false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_breach_with_entry_filter_not_found_json() {
        let (_dir, mut vault) = create_test_vault_for_security();
        add_login(&mut vault, "GitHub", "password123");
        let result = cmd_breach_with_vault(&vault, false, Some("nonexistent"), true);
        assert!(result.is_ok());
    }

    // ---- Watch command tests ----

    #[test]
    fn test_cmd_watch_empty_vault() {
        let (_dir, vault) = create_test_vault_for_security();
        let result = cmd_watch_with_vault(&vault, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_watch_empty_vault_json() {
        let (_dir, vault) = create_test_vault_for_security();
        let result = cmd_watch_with_vault(&vault, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_watch_with_entries() {
        let (_dir, mut vault) = create_test_vault_for_security();
        add_login(&mut vault, "GitHub", "c0mpl3x!P@ssw0rd#2024xYz");
        add_login(&mut vault, "Weak", "password");
        let result = cmd_watch_with_vault(&vault, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_watch_with_entries_json() {
        let (_dir, mut vault) = create_test_vault_for_security();
        add_login(&mut vault, "GitHub", "c0mpl3x!P@ssw0rd#2024xYz");
        add_login(&mut vault, "Weak", "password");
        let result = cmd_watch_with_vault(&vault, true);
        assert!(result.is_ok());
    }

    // ---- Report command tests ----

    #[test]
    fn test_cmd_report_empty_vault() {
        let (_dir, vault) = create_test_vault_for_security();
        let result = cmd_report_with_vault(&vault, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_report_empty_vault_json() {
        let (_dir, vault) = create_test_vault_for_security();
        let result = cmd_report_with_vault(&vault, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_report_with_entries() {
        let (_dir, mut vault) = create_test_vault_for_security();
        add_login(&mut vault, "GitHub", "c0mpl3x!P@ssw0rd#2024xYz");
        add_login(&mut vault, "Weak", "password");
        let result = cmd_report_with_vault(&vault, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_report_with_entries_json() {
        let (_dir, mut vault) = create_test_vault_for_security();
        add_login(&mut vault, "GitHub", "c0mpl3x!P@ssw0rd#2024xYz");
        add_login(&mut vault, "Weak", "password");
        let result = cmd_report_with_vault(&vault, true);
        assert!(result.is_ok());
    }

    // ---- Rotate command tests ----

    #[test]
    fn test_rotate_scan_empty() {
        let (_dir, vault) = create_test_vault_for_security();
        let result = cmd_rotate_scan(&vault, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rotate_scan_empty_json() {
        let (_dir, vault) = create_test_vault_for_security();
        let result = cmd_rotate_scan(&vault, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rotate_scan_with_weak() {
        let (_dir, mut vault) = create_test_vault_for_security();
        add_login(&mut vault, "Weak", "123");
        let result = cmd_rotate_scan(&vault, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rotate_scan_with_weak_json() {
        let (_dir, mut vault) = create_test_vault_for_security();
        add_login(&mut vault, "Weak", "123");
        let result = cmd_rotate_scan(&vault, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rotate_list() {
        let result = cmd_rotate_list(false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rotate_list_json() {
        let result = cmd_rotate_list(true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rotate_status() {
        let result = cmd_rotate_status(false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rotate_status_json() {
        let result = cmd_rotate_status(true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rotate_approve() {
        let result = cmd_rotate_approve("abcd1234", false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rotate_approve_json() {
        let result = cmd_rotate_approve("abcd1234", true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rotate_approve_full_uuid() {
        let uuid = Uuid::new_v4().to_string();
        let result = cmd_rotate_approve(&uuid, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rotate_dismiss() {
        let result = cmd_rotate_dismiss("abcd1234", "not needed", false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rotate_dismiss_json() {
        let result = cmd_rotate_dismiss("abcd1234", "skip", true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rotate_add() {
        let (_dir, mut vault) = create_test_vault_for_security();
        add_login(&mut vault, "GitHub", "password");
        let result = cmd_rotate_add(&vault, "github", false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rotate_add_json() {
        let (_dir, mut vault) = create_test_vault_for_security();
        add_login(&mut vault, "GitHub", "password");
        let result = cmd_rotate_add(&vault, "github", true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rotate_add_not_found() {
        let (_dir, vault) = create_test_vault_for_security();
        let result = cmd_rotate_add(&vault, "nonexistent", false);
        assert!(result.is_err());
    }

    // ---- parse_plan_id tests ----

    #[test]
    fn test_parse_plan_id_full_uuid() {
        let uuid = Uuid::new_v4();
        let result = parse_plan_id(&uuid.to_string());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), uuid);
    }

    #[test]
    fn test_parse_plan_id_short_hex() {
        let result = parse_plan_id("abcd1234");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_plan_id_invalid() {
        let result = parse_plan_id("xx");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_plan_id_too_short() {
        let result = parse_plan_id("ab");
        assert!(result.is_err());
    }

    // ---- handle_rotate_command tests ----

    #[test]
    fn test_handle_rotate_scan() {
        let (_dir, mut vault) = create_test_vault_for_security();
        let result = handle_rotate_command(RotateCommands::Scan, &mut vault, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_rotate_list() {
        let (_dir, mut vault) = create_test_vault_for_security();
        let result = handle_rotate_command(RotateCommands::List, &mut vault, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_rotate_status() {
        let (_dir, mut vault) = create_test_vault_for_security();
        let result = handle_rotate_command(RotateCommands::Status, &mut vault, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_rotate_approve() {
        let (_dir, mut vault) = create_test_vault_for_security();
        let result = handle_rotate_command(
            RotateCommands::Approve { plan_id: "abcd1234".into() },
            &mut vault,
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_rotate_dismiss() {
        let (_dir, mut vault) = create_test_vault_for_security();
        let result = handle_rotate_command(
            RotateCommands::Dismiss {
                plan_id: "abcd1234".into(),
                reason: "skip".into(),
            },
            &mut vault,
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_rotate_add() {
        let (_dir, mut vault) = create_test_vault_for_security();
        add_login(&mut vault, "Test", "password");
        let result = handle_rotate_command(
            RotateCommands::Add { query: "test".into() },
            &mut vault,
            false,
        );
        assert!(result.is_ok());
    }
}
