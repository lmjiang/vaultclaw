use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Default access decision for a session type when no override matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    /// Allow access (with approval flow).
    Prompt,
    /// Deny access entirely.
    Deny,
    /// Inherit parent session scope (sub-agents only).
    Inherit,
}

impl std::fmt::Display for PolicyAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyAction::Prompt => write!(f, "prompt"),
            PolicyAction::Deny => write!(f, "deny"),
            PolicyAction::Inherit => write!(f, "inherit"),
        }
    }
}

/// Session-aware access control policy.
///
/// Controls how different session types (DM, group chat, sub-agent, cron)
/// are handled by the agent gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPolicy {
    /// Default policy for DM sessions.
    #[serde(default = "default_dm")]
    pub dm: PolicyAction,
    /// Default policy for group chat sessions.
    #[serde(default = "default_group_chat")]
    pub group_chat: PolicyAction,
    /// Default policy for sub-agent sessions.
    #[serde(default = "default_sub_agent")]
    pub sub_agent: PolicyAction,
    /// Default policy for cron job sessions.
    #[serde(default = "default_cron")]
    pub cron: PolicyAction,
    /// Per-agent overrides. Key is "agent:<agent_id>", value is the policy action.
    #[serde(default)]
    pub overrides: HashMap<String, PolicyAction>,
}

fn default_dm() -> PolicyAction { PolicyAction::Prompt }
fn default_group_chat() -> PolicyAction { PolicyAction::Deny }
fn default_sub_agent() -> PolicyAction { PolicyAction::Inherit }
fn default_cron() -> PolicyAction { PolicyAction::Prompt }

impl Default for AccessPolicy {
    fn default() -> Self {
        Self {
            dm: default_dm(),
            group_chat: default_group_chat(),
            sub_agent: default_sub_agent(),
            cron: default_cron(),
            overrides: HashMap::new(),
        }
    }
}

/// Parsed session context from the X-Session-Context header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionContext {
    /// Session type: "dm", "group", "sub_agent", "cron".
    pub session_type: String,
    /// Agent identity (from JWT sub or header).
    pub agent_id: String,
    /// Optional session ID for tracking.
    pub session_id: Option<String>,
    /// For sub_agent: parent token ID.
    pub parent_token_id: Option<String>,
    /// For cron: schedule identifier.
    pub schedule_id: Option<String>,
}

/// Result of evaluating session context against access policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Access allowed — proceed to approval flow.
    Allow,
    /// Access denied by policy.
    Deny(String),
    /// Sub-agent: inherit parent scope.
    Inherit,
}

impl AccessPolicy {
    /// Evaluate the policy for a given session context.
    pub fn evaluate(&self, ctx: &SessionContext) -> PolicyDecision {
        // Check agent-specific override first
        let override_key = format!("agent:{}", ctx.agent_id);
        if let Some(action) = self.overrides.get(&override_key) {
            return action_to_decision(action, &ctx.session_type);
        }

        // Fall back to default for session type
        let action = match ctx.session_type.as_str() {
            "dm" => &self.dm,
            "group" | "group_chat" => &self.group_chat,
            "sub_agent" => &self.sub_agent,
            "cron" => &self.cron,
            other => return PolicyDecision::Deny(format!("Unknown session type: {}", other)),
        };

        action_to_decision(action, &ctx.session_type)
    }

    /// Load access policy from a TOML file.
    pub fn load_from_toml(content: &str) -> Result<Self, String> {
        // Parse TOML into our intermediate format
        let raw: RawAccessPolicy = toml::from_str(content)
            .map_err(|e| format!("Invalid TOML: {}", e))?;

        let mut policy = AccessPolicy::default();

        if let Some(defaults) = raw.defaults {
            if let Some(v) = defaults.dm { policy.dm = parse_action(&v)?; }
            if let Some(v) = defaults.group_chat { policy.group_chat = parse_action(&v)?; }
            if let Some(v) = defaults.sub_agent { policy.sub_agent = parse_action(&v)?; }
            if let Some(v) = defaults.cron { policy.cron = parse_action(&v)?; }
        }

        if let Some(overrides) = raw.overrides {
            for (key, value) in overrides {
                let action = parse_action(&value)?;
                policy.overrides.insert(key, action);
            }
        }

        Ok(policy)
    }

    /// Serialize the policy to TOML format.
    pub fn to_toml(&self) -> Result<String, String> {
        let mut lines = Vec::new();
        lines.push("[defaults]".to_string());
        lines.push(format!("dm = \"{}\"", self.dm));
        lines.push(format!("group_chat = \"{}\"", self.group_chat));
        lines.push(format!("sub_agent = \"{}\"", self.sub_agent));
        lines.push(format!("cron = \"{}\"", self.cron));

        if !self.overrides.is_empty() {
            lines.push(String::new());
            lines.push("[overrides]".to_string());
            let mut sorted_keys: Vec<&String> = self.overrides.keys().collect();
            sorted_keys.sort();
            for key in sorted_keys {
                let action = &self.overrides[key];
                lines.push(format!("\"{}\" = \"{}\"", key, action));
            }
        }

        lines.push(String::new());
        Ok(lines.join("\n"))
    }
}

/// Parse a string action into a PolicyAction.
fn parse_action(s: &str) -> Result<PolicyAction, String> {
    match s {
        "prompt" => Ok(PolicyAction::Prompt),
        "deny" => Ok(PolicyAction::Deny),
        "inherit" => Ok(PolicyAction::Inherit),
        other => Err(format!("Invalid policy action: '{}'. Must be 'prompt', 'deny', or 'inherit'.", other)),
    }
}

/// Convert a PolicyAction to a PolicyDecision.
fn action_to_decision(action: &PolicyAction, session_type: &str) -> PolicyDecision {
    match action {
        PolicyAction::Prompt => PolicyDecision::Allow,
        PolicyAction::Deny => PolicyDecision::Deny(
            format!("Access denied by policy for session type '{}'", session_type),
        ),
        PolicyAction::Inherit => PolicyDecision::Inherit,
    }
}

/// Parse the X-Session-Context header value.
/// Format: "type=dm;agent_id=my-agent;session_id=abc123"
/// or JSON: {"session_type":"dm","agent_id":"my-agent"}
pub fn parse_session_context(header_value: &str) -> Result<SessionContext, String> {
    let trimmed = header_value.trim();

    // Try JSON first
    if trimmed.starts_with('{') {
        return serde_json::from_str(trimmed)
            .map_err(|e| format!("Invalid JSON session context: {}", e));
    }

    // Parse key=value;key=value format
    let mut session_type = None;
    let mut agent_id = None;
    let mut session_id = None;
    let mut parent_token_id = None;
    let mut schedule_id = None;

    for part in trimmed.split(';') {
        let part = part.trim();
        if part.is_empty() { continue; }
        let (key, value) = part.split_once('=')
            .ok_or_else(|| format!("Invalid key=value pair: '{}'", part))?;
        match key.trim() {
            "type" | "session_type" => session_type = Some(value.trim().to_string()),
            "agent_id" | "agent" => agent_id = Some(value.trim().to_string()),
            "session_id" => session_id = Some(value.trim().to_string()),
            "parent_token_id" | "parent_token" => parent_token_id = Some(value.trim().to_string()),
            "schedule_id" | "schedule" => schedule_id = Some(value.trim().to_string()),
            _ => {} // ignore unknown keys for forward compatibility
        }
    }

    Ok(SessionContext {
        session_type: session_type.ok_or("Missing 'type' in session context")?,
        agent_id: agent_id.unwrap_or_default(),
        session_id,
        parent_token_id,
        schedule_id,
    })
}

/// TOML deserialization intermediate types.
#[derive(Deserialize)]
struct RawAccessPolicy {
    defaults: Option<RawDefaults>,
    overrides: Option<HashMap<String, String>>,
}

#[derive(Deserialize)]
struct RawDefaults {
    dm: Option<String>,
    group_chat: Option<String>,
    sub_agent: Option<String>,
    cron: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy() {
        let policy = AccessPolicy::default();
        assert_eq!(policy.dm, PolicyAction::Prompt);
        assert_eq!(policy.group_chat, PolicyAction::Deny);
        assert_eq!(policy.sub_agent, PolicyAction::Inherit);
        assert_eq!(policy.cron, PolicyAction::Prompt);
        assert!(policy.overrides.is_empty());
    }

    #[test]
    fn test_evaluate_dm_default() {
        let policy = AccessPolicy::default();
        let ctx = SessionContext {
            session_type: "dm".into(),
            agent_id: "test-agent".into(),
            session_id: None,
            parent_token_id: None,
            schedule_id: None,
        };
        assert_eq!(policy.evaluate(&ctx), PolicyDecision::Allow);
    }

    #[test]
    fn test_evaluate_group_default() {
        let policy = AccessPolicy::default();
        let ctx = SessionContext {
            session_type: "group".into(),
            agent_id: "test-agent".into(),
            session_id: None,
            parent_token_id: None,
            schedule_id: None,
        };
        assert!(matches!(policy.evaluate(&ctx), PolicyDecision::Deny(_)));
    }

    #[test]
    fn test_evaluate_group_chat_alias() {
        let policy = AccessPolicy::default();
        let ctx = SessionContext {
            session_type: "group_chat".into(),
            agent_id: "test-agent".into(),
            session_id: None,
            parent_token_id: None,
            schedule_id: None,
        };
        assert!(matches!(policy.evaluate(&ctx), PolicyDecision::Deny(_)));
    }

    #[test]
    fn test_evaluate_sub_agent_default() {
        let policy = AccessPolicy::default();
        let ctx = SessionContext {
            session_type: "sub_agent".into(),
            agent_id: "sub-1".into(),
            session_id: None,
            parent_token_id: Some("parent-tok".into()),
            schedule_id: None,
        };
        assert_eq!(policy.evaluate(&ctx), PolicyDecision::Inherit);
    }

    #[test]
    fn test_evaluate_cron_default() {
        let policy = AccessPolicy::default();
        let ctx = SessionContext {
            session_type: "cron".into(),
            agent_id: "cron-job".into(),
            session_id: None,
            parent_token_id: None,
            schedule_id: Some("daily-backup".into()),
        };
        assert_eq!(policy.evaluate(&ctx), PolicyDecision::Allow);
    }

    #[test]
    fn test_evaluate_unknown_session_type() {
        let policy = AccessPolicy::default();
        let ctx = SessionContext {
            session_type: "unknown".into(),
            agent_id: "test".into(),
            session_id: None,
            parent_token_id: None,
            schedule_id: None,
        };
        assert!(matches!(policy.evaluate(&ctx), PolicyDecision::Deny(_)));
    }

    #[test]
    fn test_agent_override() {
        let mut policy = AccessPolicy::default();
        policy.overrides.insert("agent:special-bot".into(), PolicyAction::Prompt);

        // Special bot allowed even in group chat
        let ctx = SessionContext {
            session_type: "group".into(),
            agent_id: "special-bot".into(),
            session_id: None,
            parent_token_id: None,
            schedule_id: None,
        };
        assert_eq!(policy.evaluate(&ctx), PolicyDecision::Allow);
    }

    #[test]
    fn test_agent_override_deny() {
        let mut policy = AccessPolicy::default();
        policy.overrides.insert("agent:bad-bot".into(), PolicyAction::Deny);

        // bad-bot denied even in DM
        let ctx = SessionContext {
            session_type: "dm".into(),
            agent_id: "bad-bot".into(),
            session_id: None,
            parent_token_id: None,
            schedule_id: None,
        };
        assert!(matches!(policy.evaluate(&ctx), PolicyDecision::Deny(_)));
    }

    #[test]
    fn test_load_toml_defaults() {
        let toml = r#"
[defaults]
dm = "prompt"
group_chat = "deny"
sub_agent = "inherit"
cron = "prompt"
"#;
        let policy = AccessPolicy::load_from_toml(toml).unwrap();
        assert_eq!(policy.dm, PolicyAction::Prompt);
        assert_eq!(policy.group_chat, PolicyAction::Deny);
        assert_eq!(policy.sub_agent, PolicyAction::Inherit);
        assert_eq!(policy.cron, PolicyAction::Prompt);
    }

    #[test]
    fn test_load_toml_with_overrides() {
        let toml = r#"
[defaults]
group_chat = "deny"
dm = "prompt"

[overrides]
"agent:bt7274" = "prompt"
"agent:bad-bot" = "deny"
"#;
        let policy = AccessPolicy::load_from_toml(toml).unwrap();
        assert_eq!(policy.overrides.len(), 2);
        assert_eq!(policy.overrides["agent:bt7274"], PolicyAction::Prompt);
        assert_eq!(policy.overrides["agent:bad-bot"], PolicyAction::Deny);
    }

    #[test]
    fn test_load_toml_partial() {
        let toml = r#"
[defaults]
group_chat = "prompt"
"#;
        let policy = AccessPolicy::load_from_toml(toml).unwrap();
        assert_eq!(policy.group_chat, PolicyAction::Prompt);
        assert_eq!(policy.dm, PolicyAction::Prompt); // default
        assert_eq!(policy.sub_agent, PolicyAction::Inherit); // default
    }

    #[test]
    fn test_load_toml_invalid() {
        let toml = "not valid toml {{{";
        let result = AccessPolicy::load_from_toml(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_toml_invalid_action() {
        let toml = r#"
[defaults]
dm = "invalid"
"#;
        let result = AccessPolicy::load_from_toml(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_to_toml_roundtrip() {
        let mut policy = AccessPolicy::default();
        policy.overrides.insert("agent:bt7274".into(), PolicyAction::Prompt);

        let toml_str = policy.to_toml().unwrap();
        let loaded = AccessPolicy::load_from_toml(&toml_str).unwrap();

        assert_eq!(loaded.dm, policy.dm);
        assert_eq!(loaded.group_chat, policy.group_chat);
        assert_eq!(loaded.sub_agent, policy.sub_agent);
        assert_eq!(loaded.cron, policy.cron);
        assert_eq!(loaded.overrides.len(), 1);
        assert_eq!(loaded.overrides["agent:bt7274"], PolicyAction::Prompt);
    }

    #[test]
    fn test_parse_session_context_kv() {
        let ctx = parse_session_context("type=dm;agent_id=my-agent;session_id=abc123").unwrap();
        assert_eq!(ctx.session_type, "dm");
        assert_eq!(ctx.agent_id, "my-agent");
        assert_eq!(ctx.session_id, Some("abc123".into()));
    }

    #[test]
    fn test_parse_session_context_kv_sub_agent() {
        let ctx = parse_session_context("type=sub_agent;agent=sub-1;parent_token=tok-123").unwrap();
        assert_eq!(ctx.session_type, "sub_agent");
        assert_eq!(ctx.agent_id, "sub-1");
        assert_eq!(ctx.parent_token_id, Some("tok-123".into()));
    }

    #[test]
    fn test_parse_session_context_kv_cron() {
        let ctx = parse_session_context("type=cron;agent_id=cronjob;schedule_id=daily").unwrap();
        assert_eq!(ctx.session_type, "cron");
        assert_eq!(ctx.schedule_id, Some("daily".into()));
    }

    #[test]
    fn test_parse_session_context_json() {
        let ctx = parse_session_context(r#"{"session_type":"group","agent_id":"bot-1"}"#).unwrap();
        assert_eq!(ctx.session_type, "group");
        assert_eq!(ctx.agent_id, "bot-1");
    }

    #[test]
    fn test_parse_session_context_missing_type() {
        let result = parse_session_context("agent_id=test");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_session_context_invalid_json() {
        let result = parse_session_context("{bad json");
        assert!(result.is_err());
    }

    #[test]
    fn test_policy_serialization_json() {
        let policy = AccessPolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        let parsed: AccessPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.dm, PolicyAction::Prompt);
        assert_eq!(parsed.group_chat, PolicyAction::Deny);
    }

    #[test]
    fn test_policy_action_display() {
        assert_eq!(PolicyAction::Prompt.to_string(), "prompt");
        assert_eq!(PolicyAction::Deny.to_string(), "deny");
        assert_eq!(PolicyAction::Inherit.to_string(), "inherit");
    }

    #[test]
    fn test_session_context_serialization() {
        let ctx = SessionContext {
            session_type: "dm".into(),
            agent_id: "test".into(),
            session_id: Some("sess-1".into()),
            parent_token_id: None,
            schedule_id: None,
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let parsed: SessionContext = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.session_type, "dm");
        assert_eq!(parsed.session_id, Some("sess-1".into()));
    }

    #[test]
    fn test_parse_session_context_empty_parts() {
        // Handles trailing semicolons
        let ctx = parse_session_context("type=dm;agent_id=test;").unwrap();
        assert_eq!(ctx.session_type, "dm");
        assert_eq!(ctx.agent_id, "test");
    }

    #[test]
    fn test_parse_session_context_whitespace() {
        let ctx = parse_session_context("  type = dm ; agent_id = test  ").unwrap();
        assert_eq!(ctx.session_type, "dm");
        assert_eq!(ctx.agent_id, "test");
    }

    #[test]
    fn test_to_toml_empty_overrides() {
        let policy = AccessPolicy::default();
        let toml_str = policy.to_toml().unwrap();
        assert!(toml_str.contains("[defaults]"));
        assert!(!toml_str.contains("[overrides]"));
    }

    #[test]
    fn test_parse_action_valid() {
        assert_eq!(parse_action("prompt").unwrap(), PolicyAction::Prompt);
        assert_eq!(parse_action("deny").unwrap(), PolicyAction::Deny);
        assert_eq!(parse_action("inherit").unwrap(), PolicyAction::Inherit);
    }

    #[test]
    fn test_parse_action_invalid() {
        assert!(parse_action("allow").is_err());
        assert!(parse_action("").is_err());
    }

    #[test]
    fn test_load_toml_empty() {
        let policy = AccessPolicy::load_from_toml("").unwrap();
        assert_eq!(policy.dm, PolicyAction::Prompt);
        assert_eq!(policy.group_chat, PolicyAction::Deny);
    }
}
