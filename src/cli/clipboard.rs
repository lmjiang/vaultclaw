use std::time::Duration;

/// Copy text to clipboard and optionally clear it after a timeout.
pub fn copy_to_clipboard(text: &str, clear_after_secs: u64) -> Result<(), String> {
    set_clipboard(text)?;

    if clear_after_secs > 0 {
        let duration = Duration::from_secs(clear_after_secs);
        std::thread::spawn(move || {
            std::thread::sleep(duration);
            let _ = set_clipboard("");
        });
    }

    Ok(())
}

fn set_clipboard(text: &str) -> Result<(), String> {
    // Use pbcopy on macOS, xclip on Linux
    #[cfg(target_os = "macos")]
    {
        use std::process::{Command, Stdio};
        use std::io::Write;
        let mut child = Command::new("pbcopy")
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to start pbcopy: {}", e))?;
        child.stdin.take().ok_or("Failed to get pbcopy stdin")?
            .write_all(text.as_bytes())
            .map_err(|e| format!("Failed to write to pbcopy: {}", e))?;
        child.wait().map_err(|e| format!("pbcopy failed: {}", e))?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    {
        use std::process::{Command, Stdio};
        use std::io::Write;
        let mut child = Command::new("xclip")
            .args(["-selection", "clipboard"])
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to start xclip: {}", e))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(text.as_bytes())
                .map_err(|e| format!("Failed to write to xclip: {}", e))?;
        }
        child.wait().map_err(|e| format!("xclip failed: {}", e))?;
        Ok(())
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err("Clipboard not supported on this platform".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_clipboard_basic() {
        set_clipboard("test_value").unwrap();
    }

    #[test]
    fn test_set_clipboard_empty() {
        set_clipboard("").unwrap();
    }

    #[test]
    fn test_set_clipboard_unicode() {
        set_clipboard("密码测试🔒").unwrap();
    }

    #[test]
    fn test_set_clipboard_long_string() {
        let long_text = "a".repeat(10_000);
        set_clipboard(&long_text).unwrap();
    }

    #[test]
    fn test_set_clipboard_special_chars() {
        set_clipboard("line1\nline2\ttab\r\nwindows").unwrap();
    }

    #[test]
    fn test_copy_to_clipboard_no_clear() {
        copy_to_clipboard("test_value", 0).unwrap();
        // Also works with empty string
        copy_to_clipboard("", 0).unwrap();
    }

    #[test]
    fn test_copy_to_clipboard_with_clear() {
        // Spawns background thread, returns immediately
        copy_to_clipboard("temp_value", 1).unwrap();
    }

    #[test]
    fn test_copy_to_clipboard_multiple_calls() {
        for i in 0..3 {
            let text = format!("copy_test_{}", i);
            copy_to_clipboard(&text, 0).unwrap();
        }
    }
}
