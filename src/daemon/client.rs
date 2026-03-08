use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use super::protocol::{Request, Response, ResponseData};

/// Errors from the daemon client.
#[derive(Debug)]
pub enum ClientError {
    /// Could not connect to daemon (not running).
    NotRunning(String),
    /// I/O error during communication.
    Io(std::io::Error),
    /// Malformed JSON in response.
    Protocol(String),
    /// Daemon returned an error response.
    DaemonError(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::NotRunning(msg) => write!(f, "Daemon not running: {}", msg),
            ClientError::Io(e) => write!(f, "I/O error: {}", e),
            ClientError::Protocol(msg) => write!(f, "Protocol error: {}", msg),
            ClientError::DaemonError(msg) => write!(f, "Daemon error: {}", msg),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        ClientError::Io(e)
    }
}

/// Synchronous Unix socket client for the daemon.
#[derive(Debug)]
pub struct DaemonClient {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl DaemonClient {
    /// Connect to the daemon socket. Returns an error if the daemon is not running.
    pub fn connect(socket_path: &Path) -> Result<Self, ClientError> {
        let stream = UnixStream::connect(socket_path).map_err(|e| {
            ClientError::NotRunning(format!("{}: {}", socket_path.display(), e))
        })?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        let writer = stream.try_clone()?;
        let reader = BufReader::new(stream);
        Ok(Self { reader, writer })
    }

    /// Try to connect to the daemon. Returns `None` if not running.
    pub fn try_connect(socket_path: &Path) -> Option<Self> {
        Self::connect(socket_path).ok()
    }

    /// Send a request and receive a raw response.
    pub fn send(&mut self, request: &Request) -> Result<Response, ClientError> {
        let json = serde_json::to_string(request)
            .map_err(|e| ClientError::Protocol(format!("Failed to serialize request: {}", e)))?;

        self.writer.write_all(json.as_bytes())?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;

        let mut line = String::new();
        self.reader.read_line(&mut line)?;

        if line.is_empty() {
            return Err(ClientError::Protocol("Empty response from daemon".to_string()));
        }

        serde_json::from_str(line.trim())
            .map_err(|e| ClientError::Protocol(format!("Invalid response JSON: {}", e)))
    }

    /// Send a request and unwrap the response data, converting errors.
    pub fn request(&mut self, req: &Request) -> Result<Box<ResponseData>, ClientError> {
        match self.send(req)? {
            Response::Ok { data } => Ok(data),
            Response::Error { message } => Err(ClientError::DaemonError(message)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_try_connect_no_socket() {
        let result = DaemonClient::try_connect(&PathBuf::from("/tmp/nonexistent_vaultclaw_test.sock"));
        assert!(result.is_none());
    }

    #[test]
    fn test_connect_no_socket() {
        let result = DaemonClient::connect(&PathBuf::from("/tmp/nonexistent_vaultclaw_test.sock"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ClientError::NotRunning(_)));
        assert!(err.to_string().contains("not running"));
    }

    #[test]
    fn test_client_error_display() {
        let e = ClientError::NotRunning("test".to_string());
        assert!(e.to_string().contains("not running"));

        let e = ClientError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "broken"));
        assert!(e.to_string().contains("I/O error"));

        let e = ClientError::Protocol("bad json".to_string());
        assert!(e.to_string().contains("Protocol error"));

        let e = ClientError::DaemonError("vault locked".to_string());
        assert!(e.to_string().contains("Daemon error"));
    }

    #[test]
    fn test_client_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        let client_err: ClientError = io_err.into();
        assert!(matches!(client_err, ClientError::Io(_)));
    }

    #[tokio::test]
    async fn test_client_roundtrip() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
        use tokio::net::UnixListener;

        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("client_test.sock");

        let socket_path_clone = socket_path.clone();
        let server_handle = tokio::spawn(async move {
            let listener = UnixListener::bind(&socket_path_clone).unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = TokioBufReader::new(reader);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();

            // Parse request and send a Health response
            let _req: Request = serde_json::from_str(line.trim()).unwrap();
            let resp = Response::ok(crate::daemon::protocol::ResponseData::Health(
                crate::daemon::protocol::HealthResponse {
                    healthy: true,
                    uptime_seconds: 42,
                },
            ));
            let resp_json = serde_json::to_string(&resp).unwrap();
            writer.write_all(resp_json.as_bytes()).await.unwrap();
            writer.write_all(b"\n").await.unwrap();
            writer.flush().await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Use sync client from a blocking context
        let socket_path_clone = socket_path.clone();
        let client_handle = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&socket_path_clone).unwrap();
            let data = client.request(&Request::Health).unwrap();
            assert!(matches!(*data, ResponseData::Health(ref h) if h.healthy && h.uptime_seconds == 42));
        });

        client_handle.await.unwrap();
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_client_send_receive() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
        use tokio::net::UnixListener;

        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("send_recv_test.sock");

        let socket_path_clone = socket_path.clone();
        let server_handle = tokio::spawn(async move {
            let listener = UnixListener::bind(&socket_path_clone).unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = TokioBufReader::new(reader);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();

            // Return an error response
            let resp = Response::error("vault locked");
            let resp_json = serde_json::to_string(&resp).unwrap();
            writer.write_all(resp_json.as_bytes()).await.unwrap();
            writer.write_all(b"\n").await.unwrap();
            writer.flush().await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let socket_path_clone = socket_path.clone();
        let client_handle = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&socket_path_clone).unwrap();

            // send() returns the raw response
            let resp = client.send(&Request::Status).unwrap();
            assert!(matches!(resp, Response::Error { ref message } if message == "vault locked"));
        });

        client_handle.await.unwrap();
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_client_request_daemon_error() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
        use tokio::net::UnixListener;

        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("daemon_err_test.sock");

        let socket_path_clone = socket_path.clone();
        let server_handle = tokio::spawn(async move {
            let listener = UnixListener::bind(&socket_path_clone).unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = TokioBufReader::new(reader);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();

            let resp = Response::error("some daemon error");
            let resp_json = serde_json::to_string(&resp).unwrap();
            writer.write_all(resp_json.as_bytes()).await.unwrap();
            writer.write_all(b"\n").await.unwrap();
            writer.flush().await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let socket_path_clone = socket_path.clone();
        let client_handle = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&socket_path_clone).unwrap();
            let result = client.request(&Request::Health);
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(matches!(err, ClientError::DaemonError(ref msg) if msg == "some daemon error"));
        });

        client_handle.await.unwrap();
        server_handle.await.unwrap();
    }
}
