use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::AppConfig;
use super::client::DaemonClient;
use super::protocol::Request;

/// Get the PID file path from a socket path.
pub fn pid_path(socket_path: &Path) -> PathBuf {
    socket_path.with_extension("pid")
}

/// Check if the daemon is running by attempting to connect to the socket.
pub fn is_daemon_running(socket_path: &Path) -> bool {
    UnixStream::connect(socket_path).is_ok()
}

/// Read the PID from the PID file.
pub fn read_pid(socket_path: &Path) -> Option<u32> {
    let path = pid_path(socket_path);
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Write the PID to the PID file.
pub fn write_pid(socket_path: &Path, pid: u32) -> io::Result<()> {
    let path = pid_path(socket_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, pid.to_string())
}

/// Remove the PID file.
pub fn remove_pid(socket_path: &Path) {
    let path = pid_path(socket_path);
    let _ = std::fs::remove_file(path);
}

/// Start the daemon as a detached background process.
/// Returns the child PID on success.
pub fn start_daemon(config: &AppConfig) -> anyhow::Result<u32> {
    let exe = std::env::current_exe()?;

    let child = Command::new(exe)
        .arg("daemon")
        .arg("run")
        .arg("--socket")
        .arg(&config.socket_path)
        .arg("--vault")
        .arg(&config.vault_path)
        .arg("--auto-lock")
        .arg(config.auto_lock_seconds.to_string())
        .arg("--http-port")
        .arg(config.http_port.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    let pid = child.id();
    write_pid(&config.socket_path, pid)?;
    Ok(pid)
}

/// Stop the daemon by sending a Shutdown request.
pub fn stop_daemon(socket_path: &Path) -> anyhow::Result<()> {
    let mut client = DaemonClient::connect(socket_path)
        .map_err(|e| anyhow::anyhow!("Cannot connect to daemon: {}", e))?;

    client.send(&Request::Shutdown)
        .map_err(|e| anyhow::anyhow!("Failed to send shutdown: {}", e))?;

    remove_pid(socket_path);

    // Wait briefly for socket to disappear
    for _ in 0..10 {
        if !socket_path.exists() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pid_path() {
        let socket = Path::new("/tmp/vaultclaw/daemon.sock");
        let pid = pid_path(socket);
        assert_eq!(pid, PathBuf::from("/tmp/vaultclaw/daemon.pid"));
    }

    #[test]
    fn test_pid_path_no_extension() {
        let socket = Path::new("/tmp/vaultclaw/daemon");
        let pid = pid_path(socket);
        assert_eq!(pid, PathBuf::from("/tmp/vaultclaw/daemon.pid"));
    }

    #[test]
    fn test_write_read_remove_pid() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket = dir.path().join("test.sock");

        write_pid(&socket, 12345).unwrap();
        assert_eq!(read_pid(&socket), Some(12345));

        remove_pid(&socket);
        assert_eq!(read_pid(&socket), None);
    }

    #[test]
    fn test_read_pid_no_file() {
        let result = read_pid(Path::new("/tmp/nonexistent_vaultclaw_pid_test.sock"));
        assert_eq!(result, None);
    }

    #[test]
    fn test_is_daemon_running_false() {
        assert!(!is_daemon_running(Path::new("/tmp/nonexistent_vaultclaw_socket_test.sock")));
    }

    #[test]
    fn test_remove_pid_no_file() {
        // Should not panic even if file doesn't exist
        remove_pid(Path::new("/tmp/nonexistent_vaultclaw_pid_test2.sock"));
    }

    #[test]
    fn test_write_pid_creates_parent_dirs() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket = dir.path().join("nested").join("deep").join("test.sock");
        write_pid(&socket, 99999).unwrap();
        assert_eq!(read_pid(&socket), Some(99999));
    }

    #[tokio::test]
    async fn test_is_daemon_running_true() {
        use tokio::net::UnixListener;

        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("running_test.sock");

        let socket_path_clone = socket_path.clone();
        let server_handle = tokio::spawn(async move {
            let _listener = UnixListener::bind(&socket_path_clone).unwrap();
            // Keep the listener alive for the test
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(is_daemon_running(&socket_path));

        server_handle.abort();
    }

    #[tokio::test]
    async fn test_stop_daemon_with_server() {
        use std::sync::Arc;
        use tokio::sync::Mutex;

        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");
        let socket_path = dir.path().join("stop_test.sock");
        let password = crate::crypto::keys::password_secret("test".to_string());
        crate::vault::format::VaultFile::create(
            &vault_path,
            &password,
            crate::crypto::kdf::KdfParams::fast_for_testing(),
        ).unwrap();

        let state = crate::daemon::server::DaemonState::new(vault_path, 300);
        let state = Arc::new(Mutex::new(state));

        let socket_path_clone = socket_path.clone();
        let state_clone = state.clone();
        let server_handle = tokio::spawn(async move {
            let _ = crate::daemon::server::run_server(&socket_path_clone, state_clone).await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(is_daemon_running(&socket_path));

        // Write a PID so stop_daemon can clean it up
        write_pid(&socket_path, 99999).unwrap();

        // Stop via blocking call
        let socket_path_clone = socket_path.clone();
        let stop_handle = tokio::task::spawn_blocking(move || {
            stop_daemon(&socket_path_clone).unwrap();
        });

        stop_handle.await.unwrap();

        // Server should have exited
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            server_handle,
        ).await;
        assert!(result.is_ok());

        // PID file should be cleaned up
        assert_eq!(read_pid(&socket_path), None);
    }

    #[test]
    fn test_stop_daemon_not_running() {
        let result = stop_daemon(Path::new("/tmp/nonexistent_vaultclaw_stop_test.sock"));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Cannot connect"));
    }
}
