use serde::{Deserialize, Serialize};

use super::token::AccessRequest;

/// Notification channels for agent access requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationChannel {
    /// Log to stdout (CLI mode).
    Cli,
    /// Execute a shell command with request details as JSON on stdin.
    Webhook { url: String },
    /// Execute a local command with request details as arguments.
    Command { program: String, args: Vec<String> },
}

/// A single notification hook configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationHook {
    pub name: String,
    pub channel: NotificationChannel,
    pub enabled: bool,
}

/// Manages notification hooks for pending access requests.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NotificationManager {
    hooks: Vec<NotificationHook>,
}

impl NotificationManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a notification hook.
    pub fn add_hook(&mut self, hook: NotificationHook) {
        self.hooks.push(hook);
    }

    /// Remove a hook by name.
    pub fn remove_hook(&mut self, name: &str) -> bool {
        let before = self.hooks.len();
        self.hooks.retain(|h| h.name != name);
        self.hooks.len() < before
    }

    /// List all hooks.
    pub fn list_hooks(&self) -> &[NotificationHook] {
        &self.hooks
    }

    /// Fire notifications for a new pending access request.
    /// Returns the list of channels that were notified.
    pub fn notify_pending_request(&self, request: &AccessRequest) -> Vec<String> {
        let mut notified = Vec::new();
        for hook in &self.hooks {
            if !hook.enabled {
                continue;
            }
            match &hook.channel {
                NotificationChannel::Cli => {
                    eprintln!(
                        "[VaultClaw] Pending agent request: {} wants access to {} credential(s) — reason: {}",
                        request.agent_id,
                        request.requested_scopes.len(),
                        request.reason,
                    );
                    notified.push(hook.name.clone());
                }
                NotificationChannel::Webhook { url } => {
                    // Fire-and-forget HTTP POST (best-effort)
                    if let Ok(body) = serde_json::to_string(request) {
                        let _ = fire_webhook(url, &body);
                    }
                    notified.push(hook.name.clone());
                }
                NotificationChannel::Command { program, args } => {
                    let mut cmd_args: Vec<String> = args.clone();
                    cmd_args.push(request.agent_id.clone());
                    cmd_args.push(request.requested_scopes.len().to_string());
                    cmd_args.push(request.reason.clone());

                    let _ = std::process::Command::new(program)
                        .args(&cmd_args)
                        .spawn();
                    notified.push(hook.name.clone());
                }
            }
        }
        notified
    }
}

/// Best-effort webhook POST using blocking reqwest.
fn fire_webhook(url: &str, body: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
    client.post(url).body(body.to_string()).send()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::token::{AccessRequest, AgentAction};
    use uuid::Uuid;

    fn test_request() -> AccessRequest {
        AccessRequest::new(
            "test-agent".into(),
            vec![Uuid::new_v4()],
            vec![AgentAction::Read],
            3600,
            None,
            "deploy script".into(),
        )
    }

    #[test]
    fn test_notification_manager_add_remove() {
        let mut mgr = NotificationManager::new();
        assert!(mgr.list_hooks().is_empty());

        mgr.add_hook(NotificationHook {
            name: "cli".into(),
            channel: NotificationChannel::Cli,
            enabled: true,
        });
        assert_eq!(mgr.list_hooks().len(), 1);

        assert!(mgr.remove_hook("cli"));
        assert!(mgr.list_hooks().is_empty());

        // Remove nonexistent
        assert!(!mgr.remove_hook("nonexistent"));
    }

    #[test]
    fn test_notify_cli_channel() {
        let mut mgr = NotificationManager::new();
        mgr.add_hook(NotificationHook {
            name: "cli-hook".into(),
            channel: NotificationChannel::Cli,
            enabled: true,
        });

        let request = test_request();
        let notified = mgr.notify_pending_request(&request);
        assert_eq!(notified, vec!["cli-hook"]);
    }

    #[test]
    fn test_notify_disabled_hook_skipped() {
        let mut mgr = NotificationManager::new();
        mgr.add_hook(NotificationHook {
            name: "disabled".into(),
            channel: NotificationChannel::Cli,
            enabled: false,
        });

        let request = test_request();
        let notified = mgr.notify_pending_request(&request);
        assert!(notified.is_empty());
    }

    #[test]
    fn test_notify_multiple_hooks() {
        let mut mgr = NotificationManager::new();
        mgr.add_hook(NotificationHook {
            name: "hook-1".into(),
            channel: NotificationChannel::Cli,
            enabled: true,
        });
        mgr.add_hook(NotificationHook {
            name: "hook-2".into(),
            channel: NotificationChannel::Cli,
            enabled: true,
        });
        mgr.add_hook(NotificationHook {
            name: "hook-3".into(),
            channel: NotificationChannel::Cli,
            enabled: false,
        });

        let request = test_request();
        let notified = mgr.notify_pending_request(&request);
        assert_eq!(notified.len(), 2);
        assert_eq!(notified, vec!["hook-1", "hook-2"]);
    }

    #[test]
    fn test_notification_channel_serialization() {
        let channels = vec![
            NotificationChannel::Cli,
            NotificationChannel::Webhook { url: "https://example.com/hook".into() },
            NotificationChannel::Command { program: "/usr/bin/notify-send".into(), args: vec!["VaultClaw".into()] },
        ];
        for ch in channels {
            let json = serde_json::to_string(&ch).unwrap();
            let parsed: NotificationChannel = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, ch);
        }
    }

    #[test]
    fn test_notification_hook_serialization() {
        let hook = NotificationHook {
            name: "test".into(),
            channel: NotificationChannel::Cli,
            enabled: true,
        };
        let json = serde_json::to_string(&hook).unwrap();
        let parsed: NotificationHook = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "test");
        assert!(parsed.enabled);
    }

    #[test]
    fn test_notification_manager_serialization() {
        let mut mgr = NotificationManager::new();
        mgr.add_hook(NotificationHook {
            name: "cli".into(),
            channel: NotificationChannel::Cli,
            enabled: true,
        });

        let json = serde_json::to_string(&mgr).unwrap();
        let parsed: NotificationManager = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.list_hooks().len(), 1);
    }

    #[test]
    fn test_notify_command_channel() {
        let mut mgr = NotificationManager::new();
        mgr.add_hook(NotificationHook {
            name: "cmd".into(),
            channel: NotificationChannel::Command {
                program: "echo".into(),
                args: vec!["notification:".into()],
            },
            enabled: true,
        });

        let request = test_request();
        let notified = mgr.notify_pending_request(&request);
        assert_eq!(notified, vec!["cmd"]);
    }

    #[test]
    fn test_notify_webhook_channel_invalid_url() {
        let mut mgr = NotificationManager::new();
        mgr.add_hook(NotificationHook {
            name: "webhook".into(),
            channel: NotificationChannel::Webhook {
                url: "http://localhost:99999/nonexistent".into(),
            },
            enabled: true,
        });

        let request = test_request();
        // Should not panic even with invalid URL — best-effort
        let notified = mgr.notify_pending_request(&request);
        assert_eq!(notified, vec!["webhook"]);
    }
}
