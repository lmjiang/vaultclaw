use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

/// Chrome/Firefox native messaging protocol.
/// Messages are length-prefixed: 4 bytes (little-endian u32) followed by JSON payload.
///
/// Maximum message size (1 MB, Chrome's limit).
const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;

/// Read a native message from stdin.
/// Returns None on EOF.
pub fn read_message(reader: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }

    let len = u32::from_le_bytes(len_buf);
    if len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Message too large: {} bytes (max {})", len, MAX_MESSAGE_SIZE),
        ));
    }

    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf)?;
    Ok(Some(buf))
}

/// Write a native message to stdout.
pub fn write_message(writer: &mut impl Write, data: &[u8]) -> io::Result<()> {
    let len = data.len() as u32;
    if len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Message too large to send",
        ));
    }
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(data)?;
    writer.flush()
}

/// Read a typed JSON message from the native messaging channel.
pub fn read_json<T: for<'de> Deserialize<'de>>(reader: &mut impl Read) -> io::Result<Option<T>> {
    match read_message(reader)? {
        Some(data) => {
            let msg: T = serde_json::from_slice(&data)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            Ok(Some(msg))
        }
        None => Ok(None),
    }
}

/// Write a typed JSON message to the native messaging channel.
pub fn write_json<T: Serialize>(writer: &mut impl Write, msg: &T) -> io::Result<()> {
    let data = serde_json::to_vec(msg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    write_message(writer, &data)
}

/// Generate the Chrome native messaging host manifest JSON.
pub fn chrome_manifest(
    name: &str,
    description: &str,
    binary_path: &str,
    extension_id: &str,
) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "name": name,
        "description": description,
        "path": binary_path,
        "type": "stdio",
        "allowed_origins": [
            format!("chrome-extension://{}/", extension_id)
        ]
    }))
    .unwrap()
}

/// Generate the Firefox native messaging host manifest JSON.
pub fn firefox_manifest(
    name: &str,
    description: &str,
    binary_path: &str,
    extension_id: &str,
) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "name": name,
        "description": description,
        "path": binary_path,
        "type": "stdio",
        "allowed_extensions": [extension_id]
    }))
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_write_and_read_message() {
        let data = b"hello world";
        let mut buf = Vec::new();
        write_message(&mut buf, data).unwrap();

        let mut reader = Cursor::new(buf);
        let result = read_message(&mut reader).unwrap().unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_read_message_eof() {
        let mut reader = Cursor::new(Vec::new());
        let result = read_message(&mut reader).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_write_and_read_json() {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Msg {
            action: String,
            value: i32,
        }

        let msg = Msg {
            action: "search".to_string(),
            value: 42,
        };

        let mut buf = Vec::new();
        write_json(&mut buf, &msg).unwrap();

        let mut reader = Cursor::new(buf);
        let result: Msg = read_json(&mut reader).unwrap().unwrap();
        assert_eq!(result, msg);
    }

    #[test]
    fn test_read_json_eof() {
        let mut reader = Cursor::new(Vec::new());
        let result: Option<serde_json::Value> = read_json(&mut reader).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_message_too_large_read() {
        // Write a length header that exceeds max
        let len: u32 = MAX_MESSAGE_SIZE + 1;
        let mut buf = Vec::new();
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&[0u8; 10]);

        let mut reader = Cursor::new(buf);
        let result = read_message(&mut reader);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }

    #[test]
    fn test_length_prefix_format() {
        let data = b"test";
        let mut buf = Vec::new();
        write_message(&mut buf, data).unwrap();

        // First 4 bytes should be the length in little-endian
        assert_eq!(&buf[0..4], &4u32.to_le_bytes());
        assert_eq!(&buf[4..], data);
    }

    #[test]
    fn test_empty_message() {
        let data = b"";
        let mut buf = Vec::new();
        write_message(&mut buf, data).unwrap();

        let mut reader = Cursor::new(buf);
        let result = read_message(&mut reader).unwrap().unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_chrome_manifest() {
        let manifest = chrome_manifest(
            "com.vaultclaw.host",
            "VaultClaw Native Messaging Host",
            "/usr/local/bin/vaultclaw-host",
            "abcdefghijklmnopqrstuvwxyz123456",
        );
        let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
        assert_eq!(parsed["name"], "com.vaultclaw.host");
        assert_eq!(parsed["type"], "stdio");
        assert!(parsed["allowed_origins"][0]
            .as_str()
            .unwrap()
            .starts_with("chrome-extension://"));
    }

    #[test]
    fn test_firefox_manifest() {
        let manifest = firefox_manifest(
            "com.vaultclaw.host",
            "VaultClaw Native Messaging Host",
            "/usr/local/bin/vaultclaw-host",
            "vaultclaw@example.com",
        );
        let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
        assert_eq!(parsed["name"], "com.vaultclaw.host");
        assert!(parsed["allowed_extensions"][0]
            .as_str()
            .unwrap()
            .contains("vaultclaw"));
    }

    #[test]
    fn test_multiple_messages() {
        let mut buf = Vec::new();
        write_message(&mut buf, b"first").unwrap();
        write_message(&mut buf, b"second").unwrap();
        write_message(&mut buf, b"third").unwrap();

        let mut reader = Cursor::new(buf);
        assert_eq!(
            read_message(&mut reader).unwrap().unwrap(),
            b"first".to_vec()
        );
        assert_eq!(
            read_message(&mut reader).unwrap().unwrap(),
            b"second".to_vec()
        );
        assert_eq!(
            read_message(&mut reader).unwrap().unwrap(),
            b"third".to_vec()
        );
        assert!(read_message(&mut reader).unwrap().is_none());
    }

    #[test]
    fn test_write_message_too_large() {
        let data = vec![0u8; (MAX_MESSAGE_SIZE + 1) as usize];
        let mut buf = Vec::new();
        let result = write_message(&mut buf, &data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }

    #[test]
    fn test_read_message_truncated_payload() {
        // Write a length header claiming 100 bytes, but only provide 5
        let mut buf = Vec::new();
        buf.extend_from_slice(&100u32.to_le_bytes());
        buf.extend_from_slice(&[0u8; 5]);

        let mut reader = Cursor::new(buf);
        let result = read_message(&mut reader);
        assert!(result.is_err()); // UnexpectedEof
    }

    #[test]
    fn test_read_json_invalid_json() {
        // Write valid length-prefixed message but with invalid JSON
        let data = b"not json {{{";
        let mut buf = Vec::new();
        write_message(&mut buf, data).unwrap();

        let mut reader = Cursor::new(buf);
        let result: io::Result<Option<serde_json::Value>> = read_json(&mut reader);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_message_non_eof_error() {
        // A reader that returns a non-EOF error on the first read
        struct FailingReader;
        impl std::io::Read for FailingReader {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::PermissionDenied, "access denied"))
            }
        }

        let mut reader = FailingReader;
        let result = read_message(&mut reader);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn test_write_message_io_error() {
        struct FailingWriter;
        impl Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "broken"))
            }
            fn flush(&mut self) -> io::Result<()> { Ok(()) }
        }
        let mut fw = FailingWriter;
        let _ = fw.flush(); // exercise flush to cover that line
        let result = write_message(&mut fw, b"data");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn test_read_json_io_error() {
        struct FailingReader;
        impl std::io::Read for FailingReader {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "broken"))
            }
        }
        let result: io::Result<Option<serde_json::Value>> = read_json(&mut FailingReader);
        assert!(result.is_err());
    }

    #[test]
    fn test_write_json_serialization_error() {
        struct FailSerializer;
        impl Serialize for FailSerializer {
            fn serialize<S: serde::Serializer>(&self, _s: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("intentional failure"))
            }
        }
        let mut buf = Vec::new();
        let result = write_json(&mut buf, &FailSerializer);
        assert!(result.is_err());
    }
}
