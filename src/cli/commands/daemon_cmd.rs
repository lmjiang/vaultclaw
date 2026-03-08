use std::path::PathBuf;
use std::sync::Arc;

use clap::Subcommand;
use tokio::sync::Mutex;

use crate::config::AppConfig;
use crate::daemon::client::DaemonClient;
use crate::daemon::lifecycle;
use crate::daemon::protocol::Request;
use crate::daemon::server::{DaemonState, run_server};

#[derive(Subcommand)]
pub enum DaemonCommands {
    /// Start the daemon in background
    Start,

    /// Stop the running daemon
    Stop,

    /// Show daemon status
    Status,

    /// Run the daemon (internal, used by `daemon start`)
    #[command(hide = true)]
    Run {
        /// Socket path
        #[arg(long)]
        socket: PathBuf,
        /// Vault file path
        #[arg(long)]
        vault: PathBuf,
        /// Auto-lock timeout in seconds
        #[arg(long, default_value = "300")]
        auto_lock: u64,
        /// HTTP API port (0 to disable)
        #[arg(long, default_value = "6274")]
        http_port: u16,
        /// Directory to serve web UI from (default: web/dist next to binary)
        #[arg(long)]
        web_dir: Option<PathBuf>,
    },
}

pub fn handle_daemon_command(
    command: DaemonCommands,
    config: &AppConfig,
    json_output: bool,
) -> anyhow::Result<()> {
    match command {
        DaemonCommands::Start => cmd_daemon_start(config, json_output),
        DaemonCommands::Stop => cmd_daemon_stop(config, json_output),
        DaemonCommands::Status => cmd_daemon_status(config, json_output),
        DaemonCommands::Run { socket, vault, auto_lock, http_port, web_dir } => cmd_daemon_run(socket, vault, auto_lock, http_port, web_dir),
    }
}

fn cmd_daemon_start(config: &AppConfig, json_output: bool) -> anyhow::Result<()> {
    if lifecycle::is_daemon_running(&config.socket_path) {
        if json_output {
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "status": "already_running",
                "socket": config.socket_path.display().to_string(),
            }))?);
        } else {
            println!("Daemon is already running.");
        }
        return Ok(());
    }

    let pid = lifecycle::start_daemon(config)?;

    // Wait for the socket to appear
    for _ in 0..30 {
        if lifecycle::is_daemon_running(&config.socket_path) {
            if json_output {
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                    "status": "started",
                    "pid": pid,
                    "socket": config.socket_path.display().to_string(),
                }))?);
            } else {
                println!("Daemon started (PID {}).", pid);
            }
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    if json_output {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "status": "started",
            "pid": pid,
            "socket": config.socket_path.display().to_string(),
            "warning": "Socket not yet ready",
        }))?);
    } else {
        println!("Daemon started (PID {}), but socket not yet ready.", pid);
    }
    Ok(())
}

fn cmd_daemon_stop(config: &AppConfig, json_output: bool) -> anyhow::Result<()> {
    if !lifecycle::is_daemon_running(&config.socket_path) {
        if json_output {
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "status": "not_running",
            }))?);
        } else {
            println!("Daemon is not running.");
        }
        return Ok(());
    }

    lifecycle::stop_daemon(&config.socket_path)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "status": "stopped",
        }))?);
    } else {
        println!("Daemon stopped.");
    }
    Ok(())
}

fn cmd_daemon_status(config: &AppConfig, json_output: bool) -> anyhow::Result<()> {
    let running = lifecycle::is_daemon_running(&config.socket_path);
    let pid = lifecycle::read_pid(&config.socket_path);

    if json_output {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "running": running,
            "pid": pid,
            "socket": config.socket_path.display().to_string(),
        }))?);
    } else if running {
        match pid {
            Some(p) => println!("Daemon is running (PID {}).", p),
            None => println!("Daemon is running."),
        }
    } else {
        println!("Daemon is not running.");
    }
    Ok(())
}

fn cmd_daemon_run(socket: PathBuf, vault: PathBuf, auto_lock: u64, http_port: u16, web_dir: Option<PathBuf>) -> anyhow::Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    let mut state = DaemonState::new(vault, auto_lock);

    // Attempt Touch ID auto-unlock on daemon start
    if state.try_touchid_auto_unlock() {
        eprintln!("Vault auto-unlocked via Touch ID.");
    }

    let state = Arc::new(Mutex::new(state));
    rt.block_on(async {
        if http_port > 0 {
            let http_state = crate::agent::http::HttpState {
                daemon: state.clone(),
                rate_limiter: Arc::new(Mutex::new(crate::agent::http::HttpRateLimiter::new(100))),
            };
            let router = crate::agent::http::create_router_with_web(http_state, web_dir.as_deref());
            let addr = std::net::SocketAddr::from(([127, 0, 0, 1], http_port));
            let listener = tokio::net::TcpListener::bind(addr).await?;
            tokio::spawn(async move {
                let _ = axum::serve(listener, router).await;
            });
        }
        run_server(&socket, state).await
    })?;
    Ok(())
}

/// Send an unlock request to the running daemon.
pub fn cmd_unlock(config: &AppConfig, get_pw: impl Fn(&str) -> String, json_output: bool) -> anyhow::Result<()> {
    let mut client = DaemonClient::connect(&config.socket_path)
        .map_err(|e| anyhow::anyhow!("Daemon not running: {}. Start it with 'vaultclaw daemon start'.", e))?;

    let password = get_pw("Master password: ");
    let resp = client.send(&Request::Unlock { password })
        .map_err(|e| anyhow::anyhow!("Failed to send unlock: {}", e))?;

    match resp {
        crate::daemon::protocol::Response::Ok { .. } => {
            if json_output {
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                    "status": "unlocked",
                }))?);
            } else {
                println!("Vault unlocked.");
            }
            Ok(())
        }
        crate::daemon::protocol::Response::Error { message } => {
            anyhow::bail!("Unlock failed: {}", message)
        }
    }
}

#[cfg(target_os = "macos")]
pub fn cmd_unlock_touchid(config: &AppConfig, vault_path: &std::path::Path, json_output: bool) -> anyhow::Result<()> {
    let mut client = DaemonClient::connect(&config.socket_path)
        .map_err(|e| anyhow::anyhow!("Daemon not running: {}. Start it with 'vaultclaw daemon start'.", e))?;

    // Use VaultFile::open_with_touchid to get the master key, then send it to daemon
    // We open the vault directly to retrieve the master key, then send it as hex
    let vault = crate::vault::format::VaultFile::open_with_touchid(vault_path)?;
    let master_key_hex = hex::encode(vault.master_key().as_bytes());

    let resp = client.send(&Request::UnlockMasterKey { master_key_hex })
        .map_err(|e| anyhow::anyhow!("Failed to send unlock: {}", e))?;

    match resp {
        crate::daemon::protocol::Response::Ok { .. } => {
            if json_output {
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                    "status": "unlocked",
                    "method": "touchid",
                }))?);
            } else {
                println!("Vault unlocked via Touch ID.");
            }
            Ok(())
        }
        crate::daemon::protocol::Response::Error { message } => {
            anyhow::bail!("Touch ID unlock failed: {}", message)
        }
    }
}

pub fn cmd_unlock_recovery(config: &AppConfig, get_pw: impl Fn(&str) -> String, json_output: bool) -> anyhow::Result<()> {
    let mut client = DaemonClient::connect(&config.socket_path)
        .map_err(|e| anyhow::anyhow!("Daemon not running: {}. Start it with 'vaultclaw daemon start'.", e))?;

    let recovery_key = get_pw("Recovery key: ");
    let resp = client.send(&Request::UnlockRecovery { recovery_key })
        .map_err(|e| anyhow::anyhow!("Failed to send unlock: {}", e))?;

    match resp {
        crate::daemon::protocol::Response::Ok { .. } => {
            if json_output {
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                    "status": "unlocked",
                    "method": "recovery",
                }))?);
            } else {
                println!("Vault unlocked via recovery key.");
            }
            Ok(())
        }
        crate::daemon::protocol::Response::Error { message } => {
            anyhow::bail!("Recovery unlock failed: {}", message)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_status_not_running() {
        let config = AppConfig {
            socket_path: PathBuf::from("/tmp/nonexistent_vaultclaw_daemon_test.sock"),
            ..AppConfig::default()
        };
        let result = handle_daemon_command(DaemonCommands::Status, &config, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_daemon_status_not_running_json() {
        let config = AppConfig {
            socket_path: PathBuf::from("/tmp/nonexistent_vaultclaw_daemon_test.sock"),
            ..AppConfig::default()
        };
        let result = handle_daemon_command(DaemonCommands::Status, &config, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_daemon_stop_not_running() {
        let config = AppConfig {
            socket_path: PathBuf::from("/tmp/nonexistent_vaultclaw_daemon_test.sock"),
            ..AppConfig::default()
        };
        let result = handle_daemon_command(DaemonCommands::Stop, &config, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_daemon_stop_not_running_json() {
        let config = AppConfig {
            socket_path: PathBuf::from("/tmp/nonexistent_vaultclaw_daemon_test.sock"),
            ..AppConfig::default()
        };
        let result = handle_daemon_command(DaemonCommands::Stop, &config, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_unlock_no_daemon() {
        let config = AppConfig {
            socket_path: PathBuf::from("/tmp/nonexistent_vaultclaw_daemon_test.sock"),
            ..AppConfig::default()
        };
        let result = cmd_unlock(&config, |_| "test".to_string(), false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not running"));
    }

    /// Helper to start a test daemon and return the socket path, temp dir, and join handle.
    fn start_test_daemon() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf, tokio::runtime::Runtime) {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");
        let socket_path = dir.path().join("daemon_cmd_test.sock");
        let password = crate::crypto::keys::password_secret("testpass".to_string());
        let params = crate::crypto::kdf::KdfParams::fast_for_testing();
        let mut vault = crate::vault::format::VaultFile::create(&vault_path, &password, params).unwrap();
        vault.store_mut().add(
            crate::vault::entry::Entry::new(
                "GitHub".to_string(),
                crate::vault::entry::Credential::Login(crate::vault::entry::LoginCredential {
                    url: "https://github.com".to_string(),
                    username: "user".to_string(),
                    password: "pass".to_string(),
                }),
            ).with_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
        );
        vault.save().unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let state = crate::daemon::server::DaemonState::new(vault_path.clone(), 300);
        let state = std::sync::Arc::new(tokio::sync::Mutex::new(state));
        let socket_clone = socket_path.clone();
        let state_clone = state.clone();
        rt.spawn(async move {
            let _ = crate::daemon::server::run_server(&socket_clone, state_clone).await;
        });

        // Wait for socket
        std::thread::sleep(std::time::Duration::from_millis(150));

        (dir, vault_path, socket_path, rt)
    }

    #[test]
    fn test_daemon_status_running() {
        let (_dir, _vault_path, socket_path, _rt) = start_test_daemon();
        let config = AppConfig {
            socket_path: socket_path.clone(),
            ..AppConfig::default()
        };
        let result = cmd_daemon_status(&config, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_daemon_status_running_json() {
        let (_dir, _vault_path, socket_path, _rt) = start_test_daemon();
        let config = AppConfig {
            socket_path: socket_path.clone(),
            ..AppConfig::default()
        };
        let result = cmd_daemon_status(&config, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_daemon_status_running_with_pid() {
        let (_dir, _vault_path, socket_path, _rt) = start_test_daemon();
        crate::daemon::lifecycle::write_pid(&socket_path, 12345).unwrap();
        let config = AppConfig {
            socket_path: socket_path.clone(),
            ..AppConfig::default()
        };
        let result = cmd_daemon_status(&config, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_daemon_start_already_running() {
        let (_dir, _vault_path, socket_path, _rt) = start_test_daemon();
        let config = AppConfig {
            socket_path: socket_path.clone(),
            ..AppConfig::default()
        };
        // Start when already running should print "already running"
        let result = cmd_daemon_start(&config, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_daemon_start_already_running_json() {
        let (_dir, _vault_path, socket_path, _rt) = start_test_daemon();
        let config = AppConfig {
            socket_path: socket_path.clone(),
            ..AppConfig::default()
        };
        let result = cmd_daemon_start(&config, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_unlock_success() {
        let (_dir, _vault_path, socket_path, _rt) = start_test_daemon();
        let config = AppConfig {
            socket_path: socket_path.clone(),
            ..AppConfig::default()
        };
        let result = cmd_unlock(&config, |_| "testpass".to_string(), false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_unlock_success_json() {
        let (_dir, _vault_path, socket_path, _rt) = start_test_daemon();
        let config = AppConfig {
            socket_path: socket_path.clone(),
            ..AppConfig::default()
        };
        let result = cmd_unlock(&config, |_| "testpass".to_string(), true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_unlock_wrong_password() {
        let (_dir, _vault_path, socket_path, _rt) = start_test_daemon();
        let config = AppConfig {
            socket_path: socket_path.clone(),
            ..AppConfig::default()
        };
        let result = cmd_unlock(&config, |_| "wrongpass".to_string(), false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unlock failed"));
    }

    #[test]
    fn test_daemon_stop_running() {
        let (_dir, _vault_path, socket_path, _rt) = start_test_daemon();
        let config = AppConfig {
            socket_path: socket_path.clone(),
            ..AppConfig::default()
        };
        let result = cmd_daemon_stop(&config, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_daemon_stop_running_json() {
        let (_dir, _vault_path, socket_path, _rt) = start_test_daemon();
        let config = AppConfig {
            socket_path: socket_path.clone(),
            ..AppConfig::default()
        };
        let result = cmd_daemon_stop(&config, true);
        assert!(result.is_ok());
    }
}
