use std::path::PathBuf;

use clap::Subcommand;

use crate::browser::native_messaging;

/// Subcommands for `vaultclaw browser-host`.
#[derive(Subcommand, Debug, Clone)]
pub enum BrowserHostCommands {
    /// Install the native messaging host manifest for Chrome/Chromium
    InstallChrome {
        /// Chrome extension ID (from chrome://extensions)
        extension_id: String,
    },
    /// Install the native messaging host manifest for Firefox
    InstallFirefox {
        /// Firefox extension ID (e.g., vaultclaw@example.com)
        extension_id: String,
    },
    /// Show the native messaging manifest (without installing)
    ShowManifest {
        /// Browser: "chrome" or "firefox"
        browser: String,
        /// Extension ID
        extension_id: String,
    },
    /// Remove installed native messaging host manifests
    Uninstall,
}

const HOST_NAME: &str = "com.vaultclaw.host";
const HOST_DESCRIPTION: &str = "VaultClaw Native Messaging Host";

pub fn handle_browser_host_command(
    command: BrowserHostCommands,
    json_output: bool,
) -> anyhow::Result<()> {
    match command {
        BrowserHostCommands::InstallChrome { extension_id } => {
            cmd_install_chrome(&extension_id, json_output)
        }
        BrowserHostCommands::InstallFirefox { extension_id } => {
            cmd_install_firefox(&extension_id, json_output)
        }
        BrowserHostCommands::ShowManifest { browser, extension_id } => {
            cmd_show_manifest(&browser, &extension_id, json_output)
        }
        BrowserHostCommands::Uninstall => cmd_uninstall(json_output),
    }
}

fn binary_path() -> String {
    std::env::current_exe()
        .unwrap_or_else(|_| PathBuf::from("vaultclaw"))
        .to_string_lossy()
        .to_string()
}

fn chrome_manifest_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("~"))
            .join("Library/Application Support/Google/Chrome/NativeMessagingHosts")
    }
    #[cfg(target_os = "linux")]
    {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("~"))
            .join(".config/google-chrome/NativeMessagingHosts")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        PathBuf::from(".")
    }
}

fn firefox_manifest_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("~"))
            .join("Library/Application Support/Mozilla/NativeMessagingHosts")
    }
    #[cfg(target_os = "linux")]
    {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("~"))
            .join(".mozilla/native-messaging-hosts")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        PathBuf::from(".")
    }
}

fn manifest_filename() -> String {
    format!("{}.json", HOST_NAME)
}

fn cmd_install_chrome(extension_id: &str, json_output: bool) -> anyhow::Result<()> {
    let dir = chrome_manifest_dir();
    let manifest = native_messaging::chrome_manifest(
        HOST_NAME,
        HOST_DESCRIPTION,
        &binary_path(),
        extension_id,
    );
    install_manifest(&dir, &manifest, "Chrome", json_output)
}

fn cmd_install_firefox(extension_id: &str, json_output: bool) -> anyhow::Result<()> {
    let dir = firefox_manifest_dir();
    let manifest = native_messaging::firefox_manifest(
        HOST_NAME,
        HOST_DESCRIPTION,
        &binary_path(),
        extension_id,
    );
    install_manifest(&dir, &manifest, "Firefox", json_output)
}

fn install_manifest(
    dir: &PathBuf,
    manifest: &str,
    browser: &str,
    json_output: bool,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(manifest_filename());
    std::fs::write(&path, manifest)?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "installed": true,
                "browser": browser,
                "path": path.display().to_string(),
            }))?
        );
    } else {
        println!(
            "Installed {} native messaging host at {}",
            browser,
            path.display()
        );
    }
    Ok(())
}

fn cmd_show_manifest(browser: &str, extension_id: &str, json_output: bool) -> anyhow::Result<()> {
    let manifest = match browser.to_lowercase().as_str() {
        "chrome" | "chromium" => native_messaging::chrome_manifest(
            HOST_NAME,
            HOST_DESCRIPTION,
            &binary_path(),
            extension_id,
        ),
        "firefox" => native_messaging::firefox_manifest(
            HOST_NAME,
            HOST_DESCRIPTION,
            &binary_path(),
            extension_id,
        ),
        _ => anyhow::bail!("Unknown browser: {}. Use 'chrome' or 'firefox'.", browser),
    };

    if json_output {
        // Already JSON, print directly
        println!("{}", manifest);
    } else {
        println!("{}", manifest);
    }
    Ok(())
}

fn cmd_uninstall(json_output: bool) -> anyhow::Result<()> {
    let filename = manifest_filename();
    let mut removed = Vec::new();

    for (browser, dir) in [
        ("Chrome", chrome_manifest_dir()),
        ("Firefox", firefox_manifest_dir()),
    ] {
        let path = dir.join(&filename);
        if path.exists() {
            std::fs::remove_file(&path)?;
            removed.push((browser, path.display().to_string()));
        }
    }

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "removed": removed.iter().map(|(b, p)| serde_json::json!({
                    "browser": b,
                    "path": p,
                })).collect::<Vec<_>>(),
            }))?
        );
    } else if removed.is_empty() {
        println!("No native messaging host manifests found.");
    } else {
        for (browser, path) in &removed {
            println!("Removed {} manifest: {}", browser, path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serializes tests that write to the real Chrome/Firefox NativeMessagingHosts
    /// directories to avoid TOCTOU races between parallel test threads.
    static FS_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_host_name() {
        assert_eq!(HOST_NAME, "com.vaultclaw.host");
    }

    #[test]
    fn test_manifest_filename() {
        assert_eq!(manifest_filename(), "com.vaultclaw.host.json");
    }

    #[test]
    fn test_binary_path_returns_string() {
        let path = binary_path();
        assert!(!path.is_empty());
    }

    #[test]
    fn test_chrome_manifest_dir() {
        let dir = chrome_manifest_dir();
        assert!(dir.to_string_lossy().contains("NativeMessagingHosts"));
    }

    #[test]
    fn test_firefox_manifest_dir() {
        let dir = firefox_manifest_dir();
        let s = dir.to_string_lossy();
        assert!(
            s.contains("NativeMessagingHosts") || s.contains("native-messaging-hosts")
        );
    }

    #[test]
    fn test_show_manifest_chrome() {
        cmd_show_manifest("chrome", "test-extension-id", false).unwrap();
    }

    #[test]
    fn test_show_manifest_chromium() {
        cmd_show_manifest("chromium", "test-extension-id", false).unwrap();
    }

    #[test]
    fn test_show_manifest_firefox() {
        cmd_show_manifest("firefox", "ext@example.com", false).unwrap();
    }

    #[test]
    fn test_show_manifest_json() {
        cmd_show_manifest("chrome", "test-ext", true).unwrap();
    }

    #[test]
    fn test_show_manifest_unknown_browser() {
        let result = cmd_show_manifest("safari", "test-ext", false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown browser"));
    }

    #[test]
    fn test_install_manifest_to_temp_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let manifest = native_messaging::chrome_manifest(
            HOST_NAME,
            HOST_DESCRIPTION,
            "/usr/local/bin/vaultclaw",
            "test-ext-id",
        );
        install_manifest(
            &dir.path().to_path_buf(),
            &manifest,
            "Chrome",
            false,
        )
        .unwrap();

        let installed = dir.path().join(manifest_filename());
        assert!(installed.exists());
        let content = std::fs::read_to_string(&installed).unwrap();
        assert!(content.contains("com.vaultclaw.host"));
        assert!(content.contains("test-ext-id"));
    }

    #[test]
    fn test_install_manifest_json_output() {
        let dir = tempfile::TempDir::new().unwrap();
        let manifest = native_messaging::chrome_manifest(
            HOST_NAME,
            HOST_DESCRIPTION,
            "/usr/local/bin/vaultclaw",
            "test-ext",
        );
        install_manifest(
            &dir.path().to_path_buf(),
            &manifest,
            "Chrome",
            true,
        )
        .unwrap();
    }

    #[test]
    fn test_handle_command_dispatch_show() {
        handle_browser_host_command(
            BrowserHostCommands::ShowManifest {
                browser: "chrome".into(),
                extension_id: "test".into(),
            },
            false,
        )
        .unwrap();
    }

    #[test]
    fn test_uninstall_no_manifests() {
        let _lock = FS_LOCK.lock().unwrap();
        // Ensure no manifests exist before testing the "none found" path
        std::fs::remove_file(chrome_manifest_dir().join(manifest_filename())).ok();
        std::fs::remove_file(firefox_manifest_dir().join(manifest_filename())).ok();
        cmd_uninstall(false).unwrap();
    }

    #[test]
    fn test_uninstall_json_no_manifests() {
        let _lock = FS_LOCK.lock().unwrap();
        std::fs::remove_file(chrome_manifest_dir().join(manifest_filename())).ok();
        std::fs::remove_file(firefox_manifest_dir().join(manifest_filename())).ok();
        cmd_uninstall(true).unwrap();
    }

    #[test]
    fn test_install_chrome_to_temp() {
        let dir = tempfile::TempDir::new().unwrap();
        let manifest = native_messaging::chrome_manifest(
            HOST_NAME,
            HOST_DESCRIPTION,
            "/usr/local/bin/vaultclaw",
            "abcdef123456",
        );
        install_manifest(
            &dir.path().to_path_buf(),
            &manifest,
            "Chrome",
            false,
        )
        .unwrap();

        // Verify content
        let path = dir.path().join(manifest_filename());
        let content = std::fs::read_to_string(path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["name"], "com.vaultclaw.host");
        assert_eq!(parsed["type"], "stdio");
        assert!(parsed["allowed_origins"][0]
            .as_str()
            .unwrap()
            .contains("abcdef123456"));
    }

    #[test]
    fn test_install_firefox_to_temp() {
        let dir = tempfile::TempDir::new().unwrap();
        let manifest = native_messaging::firefox_manifest(
            HOST_NAME,
            HOST_DESCRIPTION,
            "/usr/local/bin/vaultclaw",
            "vaultclaw@example.com",
        );
        install_manifest(
            &dir.path().to_path_buf(),
            &manifest,
            "Firefox",
            false,
        )
        .unwrap();

        let path = dir.path().join(manifest_filename());
        let content = std::fs::read_to_string(path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(parsed["allowed_extensions"][0]
            .as_str()
            .unwrap()
            .contains("vaultclaw"));
    }

    // --- Tests for handle_browser_host_command dispatch and cmd_install/cmd_uninstall ---
    //
    // NOTE: cmd_install_chrome / cmd_install_firefox / cmd_uninstall all write to
    // real system directories (chrome_manifest_dir / firefox_manifest_dir).  Because
    // Rust tests run in parallel and share the same manifest file paths, we cannot
    // assert intermediate filesystem state.  Instead we verify the functions return
    // Ok(()) and best-effort clean up.  The `install_manifest` helper (which does the
    // actual I/O) is already thoroughly tested via temp-dir tests above.

    #[test]
    fn test_dispatch_install_chrome() {
        let _lock = FS_LOCK.lock().unwrap();
        // Covers handle_browser_host_command InstallChrome arm (lines 39-40)
        // and cmd_install_chrome body (lines 101-110)
        let result = handle_browser_host_command(
            BrowserHostCommands::InstallChrome {
                extension_id: "test-dispatch-chrome".into(),
            },
            false,
        );
        assert!(result.is_ok());
        std::fs::remove_file(chrome_manifest_dir().join(manifest_filename())).ok();
    }

    #[test]
    fn test_dispatch_install_chrome_json() {
        let _lock = FS_LOCK.lock().unwrap();
        let result = handle_browser_host_command(
            BrowserHostCommands::InstallChrome {
                extension_id: "test-dispatch-chrome-json".into(),
            },
            true,
        );
        assert!(result.is_ok());
        std::fs::remove_file(chrome_manifest_dir().join(manifest_filename())).ok();
    }

    #[test]
    fn test_dispatch_install_firefox() {
        let _lock = FS_LOCK.lock().unwrap();
        // Covers handle_browser_host_command InstallFirefox arm (lines 42-43)
        // and cmd_install_firefox body (lines 112-121)
        let result = handle_browser_host_command(
            BrowserHostCommands::InstallFirefox {
                extension_id: "test-dispatch-ff@example.com".into(),
            },
            false,
        );
        assert!(result.is_ok());
        std::fs::remove_file(firefox_manifest_dir().join(manifest_filename())).ok();
    }

    #[test]
    fn test_dispatch_install_firefox_json() {
        let _lock = FS_LOCK.lock().unwrap();
        let result = handle_browser_host_command(
            BrowserHostCommands::InstallFirefox {
                extension_id: "test-dispatch-ff-json@example.com".into(),
            },
            true,
        );
        assert!(result.is_ok());
        std::fs::remove_file(firefox_manifest_dir().join(manifest_filename())).ok();
    }

    #[test]
    fn test_dispatch_uninstall() {
        let _lock = FS_LOCK.lock().unwrap();
        // Covers handle_browser_host_command Uninstall arm (line 48)
        cmd_install_chrome("test-dispatch-uninstall", false).unwrap();
        std::fs::remove_file(firefox_manifest_dir().join(manifest_filename())).ok();
        let result = handle_browser_host_command(BrowserHostCommands::Uninstall, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_dispatch_uninstall_json() {
        let _lock = FS_LOCK.lock().unwrap();
        cmd_install_firefox("test-dispatch-uninstall-json@example.com", false).unwrap();
        std::fs::remove_file(chrome_manifest_dir().join(manifest_filename())).ok();
        let result = handle_browser_host_command(BrowserHostCommands::Uninstall, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_install_chrome_text() {
        let _lock = FS_LOCK.lock().unwrap();
        assert!(cmd_install_chrome("test-direct-chrome-text", false).is_ok());
        std::fs::remove_file(chrome_manifest_dir().join(manifest_filename())).ok();
    }

    #[test]
    fn test_cmd_install_chrome_json() {
        let _lock = FS_LOCK.lock().unwrap();
        assert!(cmd_install_chrome("test-direct-chrome-json", true).is_ok());
        std::fs::remove_file(chrome_manifest_dir().join(manifest_filename())).ok();
    }

    #[test]
    fn test_cmd_install_firefox_text() {
        let _lock = FS_LOCK.lock().unwrap();
        assert!(cmd_install_firefox("test-direct-ff-text@example.com", false).is_ok());
        std::fs::remove_file(firefox_manifest_dir().join(manifest_filename())).ok();
    }

    #[test]
    fn test_cmd_install_firefox_json() {
        let _lock = FS_LOCK.lock().unwrap();
        assert!(cmd_install_firefox("test-direct-ff-json@example.com", true).is_ok());
        std::fs::remove_file(firefox_manifest_dir().join(manifest_filename())).ok();
    }

    #[test]
    fn test_uninstall_existing_chrome_text() {
        let _lock = FS_LOCK.lock().unwrap();
        // Install Chrome manifest, then uninstall with text output
        // Covers lines 188-189 (remove_file + push) and 206-208 (text output loop)
        cmd_install_chrome("test-uninstall-existing-chrome", false).unwrap();
        std::fs::remove_file(firefox_manifest_dir().join(manifest_filename())).ok();
        assert!(cmd_uninstall(false).is_ok());
    }

    #[test]
    fn test_uninstall_existing_firefox_json() {
        let _lock = FS_LOCK.lock().unwrap();
        // Install Firefox manifest, then uninstall with json output
        // Covers lines 188-189 (remove_file + push) and 198-199, 201 (json output)
        cmd_install_firefox("test-uninstall-existing-ff-json@example.com", false).unwrap();
        std::fs::remove_file(chrome_manifest_dir().join(manifest_filename())).ok();
        assert!(cmd_uninstall(true).is_ok());
    }

    #[test]
    fn test_uninstall_both_browsers_text() {
        let _lock = FS_LOCK.lock().unwrap();
        // Install both, uninstall with text output (lines 206-208 loop over multiple)
        cmd_install_chrome("test-both-text-c", false).unwrap();
        cmd_install_firefox("test-both-text-f@example.com", false).unwrap();
        assert!(cmd_uninstall(false).is_ok());
    }

    #[test]
    fn test_uninstall_both_browsers_json() {
        let _lock = FS_LOCK.lock().unwrap();
        // Install both, uninstall with json output (lines 198-199, 201)
        cmd_install_chrome("test-both-json-c", false).unwrap();
        cmd_install_firefox("test-both-json-f@example.com", false).unwrap();
        assert!(cmd_uninstall(true).is_ok());
    }
}
