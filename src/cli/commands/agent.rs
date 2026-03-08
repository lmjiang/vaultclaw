use clap::Subcommand;
use uuid::Uuid;

use crate::agent::approval::ApprovalPolicy;
use crate::agent::gateway::{AgentGateway, GatewayData, GatewayRequest, GatewayResponse};
use crate::agent::token::AgentAction;
use crate::daemon::client::DaemonClient;
use crate::daemon::protocol::{Request, ResponseData};

#[derive(Subcommand)]
pub enum AgentCommands {
    /// Request credential access for an agent
    Request {
        /// Agent identifier
        #[arg(long)]
        agent_id: String,
        /// Credential IDs to request access to (comma-separated UUIDs)
        #[arg(long, value_delimiter = ',')]
        scopes: Vec<Uuid>,
        /// Actions to request (read, use, rotate)
        #[arg(long, value_delimiter = ',', default_value = "read")]
        actions: Vec<String>,
        /// Time-to-live in seconds
        #[arg(long, default_value = "3600")]
        ttl: u64,
        /// Maximum number of uses
        #[arg(long)]
        max_uses: Option<u32>,
        /// Reason for the request
        #[arg(long, default_value = "CLI request")]
        reason: String,
    },

    /// Grant a pending access request
    Grant {
        /// Request ID to approve
        request_id: Uuid,
        /// Approver identity
        #[arg(long, default_value = "cli-user")]
        approved_by: String,
    },

    /// Deny a pending access request
    Deny {
        /// Request ID to deny
        request_id: Uuid,
    },

    /// Revoke an active agent token
    Revoke {
        /// Token ID to revoke
        token_id: Uuid,
    },

    /// List active agent tokens
    Tokens,

    /// List pending access requests
    Pending,

    /// Show audit log
    Audit {
        /// Filter by agent ID
        #[arg(long)]
        agent: Option<String>,
        /// Show last N entries
        #[arg(long)]
        last: Option<usize>,
    },

    /// Manage auto-approval policies
    Policy {
        #[command(subcommand)]
        command: AgentPolicyCommands,
    },

    /// Show the agent audit dashboard with summary stats and alerts
    Dashboard,
}

#[derive(Subcommand)]
pub enum AgentPolicyCommands {
    /// Add an auto-approval policy
    Add {
        /// Agent ID this policy applies to
        #[arg(long)]
        agent_id: String,
        /// Pre-approved credential IDs (comma-separated UUIDs)
        #[arg(long, value_delimiter = ',')]
        scopes: Vec<Uuid>,
        /// Pre-approved actions (read, use, rotate)
        #[arg(long, value_delimiter = ',', default_value = "read")]
        actions: Vec<String>,
        /// Max TTL for auto-approval (seconds)
        #[arg(long, default_value = "3600")]
        max_ttl: u64,
    },

    /// List all policies
    List,

    /// Remove a policy by agent ID
    Remove {
        /// Agent ID whose policy to remove
        agent_id: String,
    },
}

fn parse_actions(actions: &[String]) -> Vec<AgentAction> {
    actions
        .iter()
        .map(|a| match a.to_lowercase().as_str() {
            "read" => AgentAction::Read,
            "use" => AgentAction::Use,
            "rotate" => AgentAction::Rotate,
            other => {
                eprintln!("Warning: unknown action '{}', defaulting to Read", other);
                AgentAction::Read
            }
        })
        .collect()
}

/// Handle an agent subcommand. Creates an ephemeral gateway (state is not persisted without daemon).
pub fn handle_agent_command(command: AgentCommands, json_output: bool) -> anyhow::Result<()> {
    let mut gateway = AgentGateway::new();

    match command {
        AgentCommands::Request {
            agent_id,
            scopes,
            actions,
            ttl,
            max_uses,
            reason,
        } => {
            let actions = parse_actions(&actions);
            let req = GatewayRequest::RequestAccess {
                agent_id,
                scopes,
                actions,
                ttl,
                max_uses,
                reason,
            };
            format_gateway_response(gateway.handle(req), json_output)
        }
        AgentCommands::Grant {
            request_id,
            approved_by,
        } => {
            let req = GatewayRequest::Grant {
                request_id,
                approved_by,
            };
            format_gateway_response(gateway.handle(req), json_output)
        }
        AgentCommands::Deny { request_id } => {
            format_gateway_response(
                gateway.handle(GatewayRequest::Deny { request_id }),
                json_output,
            )
        }
        AgentCommands::Revoke { token_id } => {
            format_gateway_response(
                gateway.handle(GatewayRequest::Revoke { token_id }),
                json_output,
            )
        }
        AgentCommands::Tokens => {
            format_gateway_response(gateway.handle(GatewayRequest::ListTokens), json_output)
        }
        AgentCommands::Pending => {
            format_gateway_response(gateway.handle(GatewayRequest::ListPending), json_output)
        }
        AgentCommands::Audit { agent, last } => {
            let req = GatewayRequest::Audit {
                agent_id: agent,
                last_n: last,
            };
            format_gateway_response(gateway.handle(req), json_output)
        }
        AgentCommands::Policy { command } => handle_policy_command(&mut gateway, command, json_output),
        AgentCommands::Dashboard => {
            format_gateway_response(gateway.handle(GatewayRequest::Dashboard), json_output)
        }
    }
}

fn handle_policy_command(
    gateway: &mut AgentGateway,
    command: AgentPolicyCommands,
    json_output: bool,
) -> anyhow::Result<()> {
    match command {
        AgentPolicyCommands::Add {
            agent_id,
            scopes,
            actions,
            max_ttl,
        } => {
            let actions = parse_actions(&actions);
            let policy = ApprovalPolicy {
                agent_id: agent_id.clone(),
                allowed_scopes: scopes,
                allowed_actions: actions,
                max_auto_approve_ttl: max_ttl,
                require_manual_for_sensitive: true,
            };
            gateway.approval_manager.add_policy(policy);
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "status": "ok",
                        "message": format!("Policy added for agent '{}'", agent_id),
                    }))?
                );
            } else {
                println!("Policy added for agent '{}'", agent_id);
            }
            Ok(())
        }
        AgentPolicyCommands::List => {
            let policies = gateway.approval_manager.list_policies();
            if json_output {
                println!("{}", serde_json::to_string_pretty(policies)?);
            } else if policies.is_empty() {
                println!("No policies configured.");
            } else {
                for policy in policies {
                    println!(
                        "Agent: {} | Scopes: {} | Actions: {:?} | Max TTL: {}s",
                        policy.agent_id,
                        policy.allowed_scopes.len(),
                        policy.allowed_actions,
                        policy.max_auto_approve_ttl,
                    );
                }
            }
            Ok(())
        }
        AgentPolicyCommands::Remove { agent_id } => {
            gateway.approval_manager.remove_policy(&agent_id);
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "status": "ok",
                        "message": format!("Policy removed for agent '{}'", agent_id),
                    }))?
                );
            } else {
                println!("Policy removed for agent '{}'", agent_id);
            }
            Ok(())
        }
    }
}

/// Handle an agent subcommand via the running daemon (state persists).
pub fn handle_agent_command_via_daemon(
    client: &mut DaemonClient,
    command: AgentCommands,
    json_output: bool,
) -> anyhow::Result<()> {
    let gateway_request = match command {
        AgentCommands::Request {
            agent_id, scopes, actions, ttl, max_uses, reason,
        } => GatewayRequest::RequestAccess {
            agent_id,
            scopes,
            actions: parse_actions(&actions),
            ttl,
            max_uses,
            reason,
        },
        AgentCommands::Grant { request_id, approved_by } => {
            GatewayRequest::Grant { request_id, approved_by }
        }
        AgentCommands::Deny { request_id } => GatewayRequest::Deny { request_id },
        AgentCommands::Revoke { token_id } => GatewayRequest::Revoke { token_id },
        AgentCommands::Tokens => GatewayRequest::ListTokens,
        AgentCommands::Pending => GatewayRequest::ListPending,
        AgentCommands::Audit { agent, last } => {
            GatewayRequest::Audit { agent_id: agent, last_n: last }
        }
        AgentCommands::Dashboard => GatewayRequest::Dashboard,
        AgentCommands::Policy { command } => {
            // Policy management isn't wired through daemon protocol yet.
            // Fall back to ephemeral gateway for now.
            let mut gateway = AgentGateway::new();
            return handle_policy_command(&mut gateway, command, json_output);
        }
    };

    let req = Request::Agent { request: gateway_request };
    let resp = client.send(&req).map_err(|e| anyhow::anyhow!("{}", e))?;

    match resp {
        crate::daemon::protocol::Response::Ok { data } => {
            match *data {
                ResponseData::Agent(gateway_data) => {
                    format_gateway_response(
                        GatewayResponse::Ok { data: gateway_data },
                        json_output,
                    )
                }
                _ => anyhow::bail!("Unexpected response from daemon"),
            }
        }
        crate::daemon::protocol::Response::Error { message } => {
            format_gateway_response(
                GatewayResponse::Error { message },
                json_output,
            )
        }
    }
}

fn format_gateway_response(resp: GatewayResponse, json_output: bool) -> anyhow::Result<()> {
    match resp {
        GatewayResponse::Ok { data } => {
            if json_output {
                println!("{}", serde_json::to_string_pretty(&data)?);
                return Ok(());
            }
            match data {
                GatewayData::None => println!("OK"),
                GatewayData::RequestId(id) => println!("Request submitted: {}", id),
                GatewayData::Token(token) => {
                    println!("Token issued:");
                    println!("  ID:       {}", token.id);
                    println!("  Agent:    {}", token.agent_id);
                    println!("  Scopes:   {} credential(s)", token.scopes.len());
                    println!("  Expires:  {}", token.expires_at);
                }
                GatewayData::Tokens(tokens) => {
                    if tokens.is_empty() {
                        println!("No active tokens.");
                    } else {
                        for token in &tokens {
                            println!(
                                "  {} | {} | {} scope(s) | expires {}",
                                token.id,
                                token.agent_id,
                                token.scopes.len(),
                                token.expires_at,
                            );
                        }
                    }
                }
                GatewayData::Requests(reqs) => {
                    if reqs.is_empty() {
                        println!("No pending requests.");
                    } else {
                        for req in &reqs {
                            println!(
                                "  {} | {} | {} scope(s) | {}",
                                req.id, req.agent_id, req.requested_scopes.len(), req.reason,
                            );
                        }
                    }
                }
                GatewayData::AuditEntries(entries) => {
                    if entries.is_empty() {
                        println!("No audit entries.");
                    } else {
                        for entry in &entries {
                            println!(
                                "  {} | {} | {:?} | {:?}",
                                entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
                                entry.agent_id,
                                entry.action,
                                entry.result,
                            );
                        }
                    }
                }
                GatewayData::Credential(cred) => {
                    println!("Credential: {} ({})", cred.title, cred.credential_id);
                    match &cred.value {
                        crate::agent::gateway::SecretValue::Password { password } => {
                            println!("  Password: {}", password);
                        }
                        crate::agent::gateway::SecretValue::ApiKey { key, secret } => {
                            println!("  Key:    {}", key);
                            println!("  Secret: {}", secret);
                        }
                        crate::agent::gateway::SecretValue::Note { content } => {
                            println!("  Note: {}", content);
                        }
                        crate::agent::gateway::SecretValue::SshKey { private_key } => {
                            println!("  Private Key: {}", private_key);
                        }
                    }
                }
                GatewayData::Dashboard(summary) => {
                    println!("=== Agent Audit Dashboard ===");
                    println!();
                    println!("Active tokens:     {}", summary.active_token_count);
                    println!("Pending requests:  {}", summary.pending_request_count);
                    println!("Unique agents:     {}", summary.unique_agent_count);
                    println!();
                    println!("--- Event Summary ---");
                    println!("Total events:      {}", summary.total_events);
                    println!("  Successful:      {}", summary.success_count);
                    println!("  Denied:          {}", summary.denied_count);
                    println!("  Rate-limited:    {}", summary.rate_limited_count);
                    println!("  Errors:          {}", summary.error_count);

                    if !summary.top_agents.is_empty() {
                        println!();
                        println!("--- Top Agents ---");
                        for (agent, count) in &summary.top_agents {
                            println!("  {}: {} access(es)", agent, count);
                        }
                    }

                    if !summary.suspicious_agents.is_empty() {
                        println!();
                        println!("--- Suspicious Agents ---");
                        for (agent, count) in &summary.suspicious_agents {
                            println!("  {}: {} failed attempt(s)", agent, count);
                        }
                    }

                    if !summary.alerts.is_empty() {
                        println!();
                        println!("--- Alerts ---");
                        for alert in &summary.alerts {
                            let prefix = match alert.severity {
                                crate::agent::audit::AlertSeverity::Info => "[INFO]",
                                crate::agent::audit::AlertSeverity::Warning => "[WARN]",
                                crate::agent::audit::AlertSeverity::Critical => "[CRIT]",
                            };
                            println!("  {} {}", prefix, alert.message);
                        }
                    }

                    if !summary.recent_entries.is_empty() {
                        println!();
                        println!("--- Recent Activity ---");
                        for entry in &summary.recent_entries {
                            println!(
                                "  {} | {} | {:?} | {:?}",
                                entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
                                entry.agent_id,
                                entry.action,
                                entry.result,
                            );
                        }
                    }
                }
                GatewayData::CredentialAccess {
                    credential_id,
                    granted,
                } => {
                    println!(
                        "Credential {}: {}",
                        credential_id,
                        if granted { "ACCESS GRANTED" } else { "ACCESS DENIED" }
                    );
                }
            }
            Ok(())
        }
        GatewayResponse::Error { message } => {
            anyhow::bail!("Agent gateway error: {}", message);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_actions_known() {
        let actions = vec!["read".to_string(), "use".to_string(), "rotate".to_string()];
        let parsed = parse_actions(&actions);
        assert_eq!(parsed, vec![AgentAction::Read, AgentAction::Use, AgentAction::Rotate]);
    }

    #[test]
    fn test_parse_actions_unknown_defaults_to_read() {
        let actions = vec!["unknown".to_string()];
        let parsed = parse_actions(&actions);
        assert_eq!(parsed, vec![AgentAction::Read]);
    }

    #[test]
    fn test_parse_actions_case_insensitive() {
        let actions = vec!["READ".to_string(), "Use".to_string(), "ROTATE".to_string()];
        let parsed = parse_actions(&actions);
        assert_eq!(parsed, vec![AgentAction::Read, AgentAction::Use, AgentAction::Rotate]);
    }

    #[test]
    fn test_handle_agent_tokens_empty() {
        let result = handle_agent_command(AgentCommands::Tokens, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_agent_tokens_empty_json() {
        let result = handle_agent_command(AgentCommands::Tokens, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_agent_pending_empty() {
        let result = handle_agent_command(AgentCommands::Pending, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_agent_pending_empty_json() {
        let result = handle_agent_command(AgentCommands::Pending, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_agent_audit_empty() {
        let result = handle_agent_command(
            AgentCommands::Audit {
                agent: None,
                last: None,
            },
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_agent_audit_empty_json() {
        let result = handle_agent_command(
            AgentCommands::Audit {
                agent: None,
                last: None,
            },
            true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_agent_audit_with_agent_filter() {
        let result = handle_agent_command(
            AgentCommands::Audit {
                agent: Some("test-agent".to_string()),
                last: None,
            },
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_agent_audit_with_last_n() {
        let result = handle_agent_command(
            AgentCommands::Audit {
                agent: None,
                last: Some(10),
            },
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_agent_request_creates_pending() {
        // With ephemeral gateway, request goes to pending (no auto-approve policy)
        let result = handle_agent_command(
            AgentCommands::Request {
                agent_id: "test-agent".to_string(),
                scopes: vec![Uuid::new_v4()],
                actions: vec!["read".to_string()],
                ttl: 3600,
                max_uses: Some(5),
                reason: "testing".to_string(),
            },
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_agent_request_json() {
        let result = handle_agent_command(
            AgentCommands::Request {
                agent_id: "test-agent".to_string(),
                scopes: vec![Uuid::new_v4()],
                actions: vec!["read".to_string()],
                ttl: 3600,
                max_uses: None,
                reason: "testing".to_string(),
            },
            true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_agent_grant_nonexistent() {
        let result = handle_agent_command(
            AgentCommands::Grant {
                request_id: Uuid::new_v4(),
                approved_by: "admin".to_string(),
            },
            false,
        );
        // Should fail because the request doesn't exist in ephemeral gateway
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_agent_deny_nonexistent() {
        let result = handle_agent_command(
            AgentCommands::Deny {
                request_id: Uuid::new_v4(),
            },
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_agent_revoke_nonexistent() {
        let result = handle_agent_command(
            AgentCommands::Revoke {
                token_id: Uuid::new_v4(),
            },
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_policy_add_list_remove() {
        let mut gateway = AgentGateway::new();
        let scope_id = Uuid::new_v4();

        // Add
        let result = handle_policy_command(
            &mut gateway,
            AgentPolicyCommands::Add {
                agent_id: "bot-1".to_string(),
                scopes: vec![scope_id],
                actions: vec!["read".to_string()],
                max_ttl: 1800,
            },
            false,
        );
        assert!(result.is_ok());
        assert_eq!(gateway.approval_manager.list_policies().len(), 1);

        // List
        let result = handle_policy_command(
            &mut gateway,
            AgentPolicyCommands::List,
            false,
        );
        assert!(result.is_ok());

        // List JSON
        let result = handle_policy_command(
            &mut gateway,
            AgentPolicyCommands::List,
            true,
        );
        assert!(result.is_ok());

        // Remove
        let result = handle_policy_command(
            &mut gateway,
            AgentPolicyCommands::Remove {
                agent_id: "bot-1".to_string(),
            },
            false,
        );
        assert!(result.is_ok());
        assert!(gateway.approval_manager.list_policies().is_empty());
    }

    #[test]
    fn test_handle_policy_add_json() {
        let mut gateway = AgentGateway::new();
        let result = handle_policy_command(
            &mut gateway,
            AgentPolicyCommands::Add {
                agent_id: "bot-2".to_string(),
                scopes: vec![],
                actions: vec!["read".to_string()],
                max_ttl: 3600,
            },
            true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_policy_remove_json() {
        let mut gateway = AgentGateway::new();
        let result = handle_policy_command(
            &mut gateway,
            AgentPolicyCommands::Remove {
                agent_id: "nonexistent".to_string(),
            },
            true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_policy_list_empty() {
        let mut gateway = AgentGateway::new();
        let result = handle_policy_command(
            &mut gateway,
            AgentPolicyCommands::List,
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_format_gateway_response_none() {
        let resp = GatewayResponse::ok(GatewayData::None);
        assert!(format_gateway_response(resp, false).is_ok());
    }

    #[test]
    fn test_format_gateway_response_none_json() {
        let resp = GatewayResponse::ok(GatewayData::None);
        assert!(format_gateway_response(resp, true).is_ok());
    }

    #[test]
    fn test_format_gateway_response_credential_access() {
        let resp = GatewayResponse::ok(GatewayData::CredentialAccess {
            credential_id: Uuid::new_v4(),
            granted: true,
        });
        assert!(format_gateway_response(resp, false).is_ok());

        let resp = GatewayResponse::ok(GatewayData::CredentialAccess {
            credential_id: Uuid::new_v4(),
            granted: false,
        });
        assert!(format_gateway_response(resp, false).is_ok());
    }

    #[test]
    fn test_format_gateway_response_error() {
        let resp = GatewayResponse::error("something failed");
        let result = format_gateway_response(resp, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("something failed"));
    }

    #[test]
    fn test_format_gateway_response_token() {
        use crate::agent::token::AgentToken;
        use chrono::Utc;

        let token = AgentToken {
            id: Uuid::new_v4(),
            agent_id: "test-agent".to_string(),
            scopes: vec![Uuid::new_v4()],
            actions: vec![AgentAction::Read],
            ttl_seconds: 3600,
            max_uses: Some(10),
            uses: 0,
            issued_at: Utc::now(),
            expires_at: Utc::now(),
            approved_by: "admin".to_string(),
            revoked: false,
        };
        let resp = GatewayResponse::ok(GatewayData::Token(token));
        assert!(format_gateway_response(resp, false).is_ok());
    }

    #[test]
    fn test_format_gateway_response_tokens_nonempty() {
        use crate::agent::token::AgentToken;
        use chrono::Utc;

        let token = AgentToken {
            id: Uuid::new_v4(),
            agent_id: "bot-1".to_string(),
            scopes: vec![Uuid::new_v4(), Uuid::new_v4()],
            actions: vec![AgentAction::Read],
            ttl_seconds: 1800,
            max_uses: None,
            uses: 3,
            issued_at: Utc::now(),
            expires_at: Utc::now(),
            approved_by: "cli".to_string(),
            revoked: false,
        };
        let resp = GatewayResponse::ok(GatewayData::Tokens(vec![token]));
        assert!(format_gateway_response(resp, false).is_ok());
    }

    #[test]
    fn test_format_gateway_response_requests_nonempty() {
        use crate::agent::token::AccessRequest;

        let req = AccessRequest::new(
            "test-agent".to_string(),
            vec![Uuid::new_v4()],
            vec![AgentAction::Read],
            3600,
            None,
            "testing".to_string(),
        );
        let resp = GatewayResponse::ok(GatewayData::Requests(vec![req]));
        assert!(format_gateway_response(resp, false).is_ok());
    }

    #[test]
    fn test_format_gateway_response_audit_nonempty() {
        use crate::agent::audit::{AuditEntry, AuditResult};
        use chrono::Utc;

        let entry = AuditEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            agent_id: "bot-1".to_string(),
            token_id: Uuid::new_v4(),
            credential_id: Uuid::new_v4(),
            action: AgentAction::Read,
            result: AuditResult::Success,
            approved_by: None,
            metadata: None,
        };
        let resp = GatewayResponse::ok(GatewayData::AuditEntries(vec![entry]));
        assert!(format_gateway_response(resp, false).is_ok());
    }

    #[test]
    fn test_format_gateway_response_request_id() {
        let resp = GatewayResponse::ok(GatewayData::RequestId(Uuid::new_v4()));
        assert!(format_gateway_response(resp, false).is_ok());
    }

    #[test]
    fn test_format_gateway_response_request_id_json() {
        let resp = GatewayResponse::ok(GatewayData::RequestId(Uuid::new_v4()));
        assert!(format_gateway_response(resp, true).is_ok());
    }

    #[test]
    fn test_handle_agent_dashboard() {
        let result = handle_agent_command(AgentCommands::Dashboard, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_agent_dashboard_json() {
        let result = handle_agent_command(AgentCommands::Dashboard, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_format_gateway_response_dashboard() {
        use crate::agent::audit::DashboardSummary;
        let summary = DashboardSummary {
            total_events: 5,
            success_count: 3,
            denied_count: 1,
            rate_limited_count: 0,
            error_count: 1,
            unique_agent_count: 2,
            active_token_count: 1,
            pending_request_count: 0,
            suspicious_agents: vec![],
            top_agents: vec![("agent-a".into(), 3)],
            recent_entries: vec![],
            alerts: vec![
                crate::agent::audit::Alert {
                    severity: crate::agent::audit::AlertSeverity::Info,
                    message: "1 error(s) in audit log".into(),
                },
            ],
        };
        let resp = GatewayResponse::ok(GatewayData::Dashboard(summary));
        assert!(format_gateway_response(resp, false).is_ok());
    }

    #[test]
    fn test_format_gateway_response_dashboard_with_suspicious() {
        use crate::agent::audit::DashboardSummary;
        let summary = DashboardSummary {
            total_events: 10,
            success_count: 5,
            denied_count: 5,
            rate_limited_count: 0,
            error_count: 0,
            unique_agent_count: 1,
            active_token_count: 0,
            pending_request_count: 0,
            suspicious_agents: vec![("bad-bot".into(), 5)],
            top_agents: vec![],
            recent_entries: vec![],
            alerts: vec![
                crate::agent::audit::Alert {
                    severity: crate::agent::audit::AlertSeverity::Critical,
                    message: "Suspicious agent".into(),
                },
                crate::agent::audit::Alert {
                    severity: crate::agent::audit::AlertSeverity::Warning,
                    message: "5 denied".into(),
                },
            ],
        };
        let resp = GatewayResponse::ok(GatewayData::Dashboard(summary));
        assert!(format_gateway_response(resp, false).is_ok());
    }

    #[test]
    fn test_handle_agent_command_policy_add() {
        // Covers line 183: AgentCommands::Policy branch in handle_agent_command
        let result = handle_agent_command(
            AgentCommands::Policy {
                command: AgentPolicyCommands::Add {
                    agent_id: "policy-agent".to_string(),
                    scopes: vec![Uuid::new_v4()],
                    actions: vec!["read".to_string()],
                    max_ttl: 1800,
                },
            },
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_agent_command_policy_list() {
        let result = handle_agent_command(
            AgentCommands::Policy {
                command: AgentPolicyCommands::List,
            },
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_agent_command_policy_remove() {
        let result = handle_agent_command(
            AgentCommands::Policy {
                command: AgentPolicyCommands::Remove {
                    agent_id: "nonexistent".to_string(),
                },
            },
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_format_gateway_response_credential_password() {
        use crate::agent::gateway::{CredentialValue, SecretValue};

        let cred = CredentialValue {
            credential_id: Uuid::new_v4(),
            title: "My Login".to_string(),
            value: SecretValue::Password {
                password: "s3cret".to_string(),
            },
        };
        let resp = GatewayResponse::ok(GatewayData::Credential(cred));
        assert!(format_gateway_response(resp, false).is_ok());
    }

    #[test]
    fn test_format_gateway_response_credential_api_key() {
        use crate::agent::gateway::{CredentialValue, SecretValue};

        let cred = CredentialValue {
            credential_id: Uuid::new_v4(),
            title: "AWS Key".to_string(),
            value: SecretValue::ApiKey {
                key: "AKIA1234".to_string(),
                secret: "wJalrXUtnFEMI/K7MDENG".to_string(),
            },
        };
        let resp = GatewayResponse::ok(GatewayData::Credential(cred));
        assert!(format_gateway_response(resp, false).is_ok());
    }

    #[test]
    fn test_format_gateway_response_credential_note() {
        use crate::agent::gateway::{CredentialValue, SecretValue};

        let cred = CredentialValue {
            credential_id: Uuid::new_v4(),
            title: "Secure Note".to_string(),
            value: SecretValue::Note {
                content: "This is a secret note.".to_string(),
            },
        };
        let resp = GatewayResponse::ok(GatewayData::Credential(cred));
        assert!(format_gateway_response(resp, false).is_ok());
    }

    #[test]
    fn test_format_gateway_response_credential_ssh_key() {
        use crate::agent::gateway::{CredentialValue, SecretValue};

        let cred = CredentialValue {
            credential_id: Uuid::new_v4(),
            title: "SSH Key".to_string(),
            value: SecretValue::SshKey {
                private_key: "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----".to_string(),
            },
        };
        let resp = GatewayResponse::ok(GatewayData::Credential(cred));
        assert!(format_gateway_response(resp, false).is_ok());
    }

    #[test]
    fn test_format_gateway_response_credential_json() {
        use crate::agent::gateway::{CredentialValue, SecretValue};

        let cred = CredentialValue {
            credential_id: Uuid::new_v4(),
            title: "My Login".to_string(),
            value: SecretValue::Password {
                password: "s3cret".to_string(),
            },
        };
        let resp = GatewayResponse::ok(GatewayData::Credential(cred));
        assert!(format_gateway_response(resp, true).is_ok());
    }

    #[test]
    fn test_format_gateway_response_dashboard_with_recent_entries() {
        use crate::agent::audit::{AuditEntry, AuditResult, DashboardSummary};
        use chrono::Utc;

        let entry = AuditEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            agent_id: "recent-agent".to_string(),
            token_id: Uuid::new_v4(),
            credential_id: Uuid::new_v4(),
            action: AgentAction::Read,
            result: AuditResult::Success,
            approved_by: None,
            metadata: None,
        };
        let summary = DashboardSummary {
            total_events: 1,
            success_count: 1,
            denied_count: 0,
            rate_limited_count: 0,
            error_count: 0,
            unique_agent_count: 1,
            active_token_count: 1,
            pending_request_count: 0,
            suspicious_agents: vec![],
            top_agents: vec![],
            recent_entries: vec![entry],
            alerts: vec![],
        };
        let resp = GatewayResponse::ok(GatewayData::Dashboard(summary));
        assert!(format_gateway_response(resp, false).is_ok());
    }

    /// Helper: start a mock daemon that reads one request and writes a fixed JSON response.
    /// Returns the socket path. The server runs on a background tokio task.
    async fn mock_daemon_one_shot_json(
        response_json: String,
    ) -> (tempfile::TempDir, std::path::PathBuf) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
        use tokio::net::UnixListener;

        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("agent_test.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let path_clone = socket_path.clone();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = TokioBufReader::new(reader);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();

            writer.write_all(response_json.as_bytes()).await.unwrap();
            writer.write_all(b"\n").await.unwrap();
            writer.flush().await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        (dir, path_clone)
    }

    /// Build a JSON response containing Agent(Dashboard(...)) data.
    /// Dashboard has a unique shape with many numeric fields, so it survives
    /// serde untagged roundtrips without being mistaken for other ResponseData
    /// variants like Entries or Entry.
    fn agent_dashboard_response_json() -> String {
        serde_json::to_string(&crate::daemon::protocol::Response::ok(
            crate::daemon::protocol::ResponseData::Agent(GatewayData::Dashboard(
                crate::agent::audit::DashboardSummary {
                    total_events: 0,
                    success_count: 0,
                    denied_count: 0,
                    rate_limited_count: 0,
                    error_count: 0,
                    unique_agent_count: 0,
                    active_token_count: 0,
                    pending_request_count: 0,
                    suspicious_agents: vec![],
                    top_agents: vec![],
                    recent_entries: vec![],
                    alerts: vec![],
                },
            )),
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn test_daemon_request_access() {
        let json = agent_dashboard_response_json();
        let (_dir, socket_path) = mock_daemon_one_shot_json(json).await;

        let result = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&socket_path).unwrap();
            handle_agent_command_via_daemon(
                &mut client,
                AgentCommands::Request {
                    agent_id: "test-agent".to_string(),
                    scopes: vec![Uuid::new_v4()],
                    actions: vec!["read".to_string()],
                    ttl: 3600,
                    max_uses: Some(5),
                    reason: "testing daemon".to_string(),
                },
                false,
            )
        })
        .await
        .unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_daemon_grant() {
        let json = agent_dashboard_response_json();
        let (_dir, socket_path) = mock_daemon_one_shot_json(json).await;

        let result = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&socket_path).unwrap();
            handle_agent_command_via_daemon(
                &mut client,
                AgentCommands::Grant {
                    request_id: Uuid::new_v4(),
                    approved_by: "admin".to_string(),
                },
                false,
            )
        })
        .await
        .unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_daemon_deny() {
        let json = agent_dashboard_response_json();
        let (_dir, socket_path) = mock_daemon_one_shot_json(json).await;

        let result = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&socket_path).unwrap();
            handle_agent_command_via_daemon(
                &mut client,
                AgentCommands::Deny {
                    request_id: Uuid::new_v4(),
                },
                false,
            )
        })
        .await
        .unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_daemon_revoke() {
        let json = agent_dashboard_response_json();
        let (_dir, socket_path) = mock_daemon_one_shot_json(json).await;

        let result = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&socket_path).unwrap();
            handle_agent_command_via_daemon(
                &mut client,
                AgentCommands::Revoke {
                    token_id: Uuid::new_v4(),
                },
                false,
            )
        })
        .await
        .unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_daemon_tokens() {
        let json = agent_dashboard_response_json();
        let (_dir, socket_path) = mock_daemon_one_shot_json(json).await;

        let result = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&socket_path).unwrap();
            handle_agent_command_via_daemon(&mut client, AgentCommands::Tokens, false)
        })
        .await
        .unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_daemon_pending() {
        let json = agent_dashboard_response_json();
        let (_dir, socket_path) = mock_daemon_one_shot_json(json).await;

        let result = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&socket_path).unwrap();
            handle_agent_command_via_daemon(&mut client, AgentCommands::Pending, false)
        })
        .await
        .unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_daemon_audit() {
        let json = agent_dashboard_response_json();
        let (_dir, socket_path) = mock_daemon_one_shot_json(json).await;

        let result = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&socket_path).unwrap();
            handle_agent_command_via_daemon(
                &mut client,
                AgentCommands::Audit {
                    agent: Some("bot-1".to_string()),
                    last: Some(10),
                },
                false,
            )
        })
        .await
        .unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_daemon_dashboard() {
        let json = agent_dashboard_response_json();
        let (_dir, socket_path) = mock_daemon_one_shot_json(json).await;

        let result = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&socket_path).unwrap();
            handle_agent_command_via_daemon(&mut client, AgentCommands::Dashboard, false)
        })
        .await
        .unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_daemon_policy_falls_back_to_ephemeral() {
        // Policy commands are not wired through the daemon protocol;
        // the function falls back to an ephemeral gateway immediately, so
        // the socket is never used for sending -- but DaemonClient::connect
        // requires a live listener to complete the handshake.
        use tokio::net::UnixListener;

        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("policy_test.sock");
        let _listener = UnixListener::bind(&socket_path).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let result = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&socket_path).unwrap();
            handle_agent_command_via_daemon(
                &mut client,
                AgentCommands::Policy {
                    command: AgentPolicyCommands::Add {
                        agent_id: "policy-agent".to_string(),
                        scopes: vec![Uuid::new_v4()],
                        actions: vec!["read".to_string()],
                        max_ttl: 1800,
                    },
                },
                false,
            )
        })
        .await
        .unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_daemon_error_response() {
        let json = serde_json::to_string(
            &crate::daemon::protocol::Response::error("vault is locked"),
        )
        .unwrap();
        let (_dir, socket_path) = mock_daemon_one_shot_json(json).await;

        let result = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&socket_path).unwrap();
            handle_agent_command_via_daemon(&mut client, AgentCommands::Tokens, false)
        })
        .await
        .unwrap();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("vault is locked"));
    }

    #[tokio::test]
    async fn test_daemon_unexpected_response_data() {
        // Server returns a non-Agent response variant (Health), triggering
        // the "Unexpected response from daemon" bail path.
        let json = serde_json::to_string(
            &crate::daemon::protocol::Response::ok(
                crate::daemon::protocol::ResponseData::Health(
                    crate::daemon::protocol::HealthResponse {
                        healthy: true,
                        uptime_seconds: 99,
                    },
                ),
            ),
        )
        .unwrap();
        let (_dir, socket_path) = mock_daemon_one_shot_json(json).await;

        let result = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&socket_path).unwrap();
            handle_agent_command_via_daemon(&mut client, AgentCommands::Tokens, false)
        })
        .await
        .unwrap();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unexpected response"));
    }

    #[tokio::test]
    async fn test_daemon_request_json_output() {
        let json = agent_dashboard_response_json();
        let (_dir, socket_path) = mock_daemon_one_shot_json(json).await;

        let result = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&socket_path).unwrap();
            handle_agent_command_via_daemon(
                &mut client,
                AgentCommands::Request {
                    agent_id: "json-agent".to_string(),
                    scopes: vec![Uuid::new_v4()],
                    actions: vec!["use".to_string(), "rotate".to_string()],
                    ttl: 600,
                    max_uses: None,
                    reason: "json test".to_string(),
                },
                true,
            )
        })
        .await
        .unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_daemon_error_response_json() {
        let json = serde_json::to_string(
            &crate::daemon::protocol::Response::error("unauthorized"),
        )
        .unwrap();
        let (_dir, socket_path) = mock_daemon_one_shot_json(json).await;

        let result = tokio::task::spawn_blocking(move || {
            let mut client = DaemonClient::connect(&socket_path).unwrap();
            handle_agent_command_via_daemon(&mut client, AgentCommands::Pending, true)
        })
        .await
        .unwrap();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unauthorized"));
    }
}
