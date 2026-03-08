use clap::Subcommand;
use uuid::Uuid;

use crate::agent::lease::Sensitivity;
use crate::daemon::client::DaemonClient;
use crate::daemon::protocol::{LeaseListData, Request, Response, ResponseData};

#[derive(Subcommand)]
pub enum LeaseCommands {
    /// List active credential leases
    List,

    /// Revoke a specific lease
    Revoke {
        /// Lease ID to revoke
        lease_id: Uuid,
    },

    /// Revoke all active leases
    RevokeAll,

    /// Set sensitivity level for an entry
    Sensitivity {
        /// Entry ID (UUID) or name
        entry: String,
        /// Sensitivity level: low, medium, high
        level: String,
    },
}

pub fn handle_lease_command(
    client: &mut DaemonClient,
    command: LeaseCommands,
    json_output: bool,
) -> anyhow::Result<()> {
    match command {
        LeaseCommands::List => {
            let resp = client.send(&Request::LeaseList)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            match resp {
                Response::Ok { data } => match *data {
                    ResponseData::LeaseList(LeaseListData { leases }) => {
                        if json_output {
                            println!("{}", serde_json::to_string_pretty(&leases)?);
                        } else if leases.is_empty() {
                            println!("No active leases.");
                        } else {
                            for lease in &leases {
                                println!(
                                    "  {} | {} | entry {} | {} | expires {}",
                                    lease.lease_id, lease.agent_id, lease.entry_id,
                                    lease.reason, lease.expires_at,
                                );
                            }
                        }
                        Ok(())
                    }
                    _ => anyhow::bail!("Unexpected response from daemon"),
                },
                Response::Error { message } => anyhow::bail!("{}", message),
            }
        }
        LeaseCommands::Revoke { lease_id } => {
            let resp = client.send(&Request::LeaseRevoke { lease_id })
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            match resp {
                Response::Ok { .. } => {
                    if json_output {
                        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                            "status": "revoked", "lease_id": lease_id.to_string(),
                        }))?);
                    } else {
                        println!("Lease {} revoked.", lease_id);
                    }
                    Ok(())
                }
                Response::Error { message } => anyhow::bail!("{}", message),
            }
        }
        LeaseCommands::RevokeAll => {
            let resp = client.send(&Request::LeaseRevokeAll)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            match resp {
                Response::Ok { data } => match *data {
                    ResponseData::LeaseRevoked { count } => {
                        if json_output {
                            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                                "status": "revoked", "count": count,
                            }))?);
                        } else {
                            println!("{} lease(s) revoked.", count);
                        }
                        Ok(())
                    }
                    _ => anyhow::bail!("Unexpected response from daemon"),
                },
                Response::Error { message } => anyhow::bail!("{}", message),
            }
        }
        LeaseCommands::Sensitivity { entry, level } => {
            let sensitivity = match level.to_lowercase().as_str() {
                "low" => Sensitivity::Low,
                "medium" | "med" => Sensitivity::Medium,
                "high" => Sensitivity::High,
                other => anyhow::bail!("Unknown sensitivity level '{}'. Use: low, medium, high", other),
            };
            let entry_id: Uuid = entry.parse()
                .map_err(|_| anyhow::anyhow!("Entry must be a UUID. Use `vaultclaw ls` to find entry IDs."))?;
            let resp = client.send(&Request::SetSensitivity { entry_id, level: sensitivity })
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            match resp {
                Response::Ok { .. } => {
                    if json_output {
                        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                            "status": "ok", "entry_id": entry_id.to_string(), "level": level.to_lowercase(),
                        }))?);
                    } else {
                        println!("Entry {} sensitivity set to {}.", entry_id, level.to_lowercase());
                    }
                    Ok(())
                }
                Response::Error { message } => anyhow::bail!("{}", message),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lease_commands_parse() {
        use clap::Parser;
        #[derive(Parser)]
        struct TestCli {
            #[command(subcommand)]
            command: LeaseCommands,
        }

        let cli = TestCli::parse_from(["test", "list"]);
        assert!(matches!(cli.command, LeaseCommands::List));

        let cli = TestCli::parse_from(["test", "revoke-all"]);
        assert!(matches!(cli.command, LeaseCommands::RevokeAll));
    }

    #[test]
    fn test_lease_revoke_parse() {
        use clap::Parser;
        #[derive(Parser)]
        struct TestCli {
            #[command(subcommand)]
            command: LeaseCommands,
        }

        let id = Uuid::new_v4();
        let cli = TestCli::parse_from(["test", "revoke", &id.to_string()]);
        assert!(matches!(cli.command, LeaseCommands::Revoke { lease_id } if lease_id == id));
    }

    #[test]
    fn test_lease_sensitivity_parse() {
        use clap::Parser;
        #[derive(Parser)]
        struct TestCli {
            #[command(subcommand)]
            command: LeaseCommands,
        }

        let id = Uuid::new_v4();
        let cli = TestCli::parse_from(["test", "sensitivity", &id.to_string(), "high"]);
        assert!(matches!(cli.command, LeaseCommands::Sensitivity { .. }));
    }

    fn connect_test_daemon() -> Option<(tempfile::TempDir, DaemonClient, tokio::runtime::Runtime)> {
        let dir = tempfile::TempDir::new().ok()?;
        let vault_path = dir.path().join("test.vclaw");
        let socket_path = dir.path().join("lease_cmd_test.sock");
        let password = crate::crypto::keys::password_secret("testpass".to_string());
        let params = crate::crypto::kdf::KdfParams::fast_for_testing();
        let mut vault = crate::vault::format::VaultFile::create(&vault_path, &password, params).ok()?;
        vault.store_mut().add(
            crate::vault::entry::Entry::new(
                "GitHub".to_string(),
                crate::vault::entry::Credential::Login(crate::vault::entry::LoginCredential {
                    url: "https://github.com".into(),
                    username: "user".into(),
                    password: "pass".into(),
                }),
            ),
        );
        vault.save().ok()?;

        let rt = tokio::runtime::Runtime::new().ok()?;
        let mut state = crate::daemon::server::DaemonState::new(vault_path, 300);
        state.unlock(&password).ok()?;
        let state = std::sync::Arc::new(tokio::sync::Mutex::new(state));
        let socket_clone = socket_path.clone();
        let state_clone = state.clone();
        rt.spawn(async move {
            let _ = crate::daemon::server::run_server(&socket_clone, state_clone).await;
        });
        std::thread::sleep(std::time::Duration::from_millis(150));
        let client = DaemonClient::connect(&socket_path).ok()?;
        Some((dir, client, rt))
    }

    #[test]
    fn test_lease_list_empty() {
        let Some((_dir, mut client, _rt)) = connect_test_daemon() else { return };
        let result = handle_lease_command(&mut client, LeaseCommands::List, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_lease_list_empty_json() {
        let Some((_dir, mut client, _rt)) = connect_test_daemon() else { return };
        let result = handle_lease_command(&mut client, LeaseCommands::List, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_lease_revoke_all_empty() {
        let Some((_dir, mut client, _rt)) = connect_test_daemon() else { return };
        let result = handle_lease_command(&mut client, LeaseCommands::RevokeAll, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_lease_revoke_all_empty_json() {
        let Some((_dir, mut client, _rt)) = connect_test_daemon() else { return };
        let result = handle_lease_command(&mut client, LeaseCommands::RevokeAll, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_lease_revoke_nonexistent() {
        let Some((_dir, mut client, _rt)) = connect_test_daemon() else { return };
        let result = handle_lease_command(
            &mut client,
            LeaseCommands::Revoke { lease_id: Uuid::new_v4() },
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_lease_set_sensitivity() {
        let Some((_dir, mut client, _rt)) = connect_test_daemon() else { return };
        let entry_id = Uuid::new_v4();
        let result = handle_lease_command(
            &mut client,
            LeaseCommands::Sensitivity {
                entry: entry_id.to_string(),
                level: "high".to_string(),
            },
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_lease_set_sensitivity_json() {
        let Some((_dir, mut client, _rt)) = connect_test_daemon() else { return };
        let entry_id = Uuid::new_v4();
        let result = handle_lease_command(
            &mut client,
            LeaseCommands::Sensitivity {
                entry: entry_id.to_string(),
                level: "medium".to_string(),
            },
            true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_lease_set_sensitivity_invalid_level() {
        let Some((_dir, mut client, _rt)) = connect_test_daemon() else { return };
        let result = handle_lease_command(
            &mut client,
            LeaseCommands::Sensitivity {
                entry: Uuid::new_v4().to_string(),
                level: "ultra".to_string(),
            },
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_lease_set_sensitivity_invalid_entry() {
        let Some((_dir, mut client, _rt)) = connect_test_daemon() else { return };
        let result = handle_lease_command(
            &mut client,
            LeaseCommands::Sensitivity {
                entry: "not-a-uuid".to_string(),
                level: "low".to_string(),
            },
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_lease_set_sensitivity_med_alias() {
        let Some((_dir, mut client, _rt)) = connect_test_daemon() else { return };
        let result = handle_lease_command(
            &mut client,
            LeaseCommands::Sensitivity {
                entry: Uuid::new_v4().to_string(),
                level: "med".to_string(),
            },
            false,
        );
        assert!(result.is_ok());
    }

    /// Spawn a mock daemon that returns a canned response to the first request.
    fn mock_daemon(response: Response) -> Option<(tempfile::TempDir, DaemonClient, tokio::runtime::Runtime)> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
        use tokio::net::UnixListener;

        let dir = tempfile::TempDir::new().ok()?;
        let socket_path = dir.path().join("mock.sock");
        let rt = tokio::runtime::Runtime::new().ok()?;

        let socket_clone = socket_path.clone();
        let resp_json = serde_json::to_string(&response).ok()?;
        rt.spawn(async move {
            let listener = UnixListener::bind(&socket_clone).unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = TokioBufReader::new(reader);
            let mut line = String::new();
            let _ = reader.read_line(&mut line).await;
            writer.write_all(resp_json.as_bytes()).await.unwrap();
            writer.write_all(b"\n").await.unwrap();
            writer.flush().await.unwrap();
        });

        std::thread::sleep(std::time::Duration::from_millis(80));
        let client = DaemonClient::connect(&socket_path).ok()?;
        Some((dir, client, rt))
    }

    // --- Coverage for lines 48-54: non-empty lease list, non-JSON ---

    #[test]
    fn test_lease_list_nonempty_text() {
        use crate::daemon::protocol::{LeaseInfo, LeaseListData};
        let resp = Response::ok(ResponseData::LeaseList(LeaseListData {
            leases: vec![LeaseInfo {
                lease_id: Uuid::new_v4(),
                entry_id: Uuid::new_v4(),
                agent_id: "agent-1".to_string(),
                scope: "read".to_string(),
                reason: "deploy".to_string(),
                created_at: "2025-01-01T00:00:00Z".to_string(),
                expires_at: "2025-01-01T01:00:00Z".to_string(),
            }],
        }));
        let Some((_dir, mut client, _rt)) = mock_daemon(resp) else { return };
        let result = handle_lease_command(&mut client, LeaseCommands::List, false);
        assert!(result.is_ok());
    }

    // --- Coverage for line 58: unexpected response data for List ---

    #[test]
    fn test_lease_list_unexpected_data() {
        let resp = Response::ok(ResponseData::LeaseRevoked { count: 0 });
        let Some((_dir, mut client, _rt)) = mock_daemon(resp) else { return };
        let result = handle_lease_command(&mut client, LeaseCommands::List, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unexpected"));
    }

    // --- Coverage for line 60: error response for List ---

    #[test]
    fn test_lease_list_error_response() {
        let resp = Response::error("vault locked");
        let Some((_dir, mut client, _rt)) = mock_daemon(resp) else { return };
        let result = handle_lease_command(&mut client, LeaseCommands::List, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("vault locked"));
    }

    // --- Coverage for lines 68-75: revoke success, non-JSON and JSON ---

    #[test]
    fn test_lease_revoke_success_text() {
        let resp = Response::ok(ResponseData::None);
        let Some((_dir, mut client, _rt)) = mock_daemon(resp) else { return };
        let lease_id = Uuid::new_v4();
        let result = handle_lease_command(
            &mut client,
            LeaseCommands::Revoke { lease_id },
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_lease_revoke_success_json() {
        let resp = Response::ok(ResponseData::None);
        let Some((_dir, mut client, _rt)) = mock_daemon(resp) else { return };
        let lease_id = Uuid::new_v4();
        let result = handle_lease_command(
            &mut client,
            LeaseCommands::Revoke { lease_id },
            true,
        );
        assert!(result.is_ok());
    }

    // --- Coverage for line 95: unexpected response data for RevokeAll ---

    #[test]
    fn test_lease_revoke_all_unexpected_data() {
        use crate::daemon::protocol::LeaseListData;
        let resp = Response::ok(ResponseData::LeaseList(LeaseListData { leases: vec![] }));
        let Some((_dir, mut client, _rt)) = mock_daemon(resp) else { return };
        let result = handle_lease_command(&mut client, LeaseCommands::RevokeAll, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unexpected"));
    }

    // --- Coverage for line 97: error response for RevokeAll ---

    #[test]
    fn test_lease_revoke_all_error_response() {
        let resp = Response::error("internal error");
        let Some((_dir, mut client, _rt)) = mock_daemon(resp) else { return };
        let result = handle_lease_command(&mut client, LeaseCommands::RevokeAll, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("internal error"));
    }

    // --- Coverage for line 122: error response for Sensitivity ---

    #[test]
    fn test_lease_sensitivity_error_response() {
        let resp = Response::error("entry not found");
        let Some((_dir, mut client, _rt)) = mock_daemon(resp) else { return };
        let result = handle_lease_command(
            &mut client,
            LeaseCommands::Sensitivity {
                entry: Uuid::new_v4().to_string(),
                level: "high".to_string(),
            },
            false,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("entry not found"));
    }
}
