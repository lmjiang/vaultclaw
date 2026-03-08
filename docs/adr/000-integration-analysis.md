# ADR-000: VaultClaw × OpenClaw Integration Analysis

**Status:** Accepted
**Date:** 2026-02-16
**Context:** Analyzing how VaultClaw integrates with OpenClaw as an agent-facing credential manager

## Context

OpenClaw is an AI agent platform that runs on the user's machine with full access to the filesystem, environment variables, and external services. Its [MITRE ATLAS threat model](../../security/THREAT-MODEL-ATLAS.md) identifies several critical credential-related vulnerabilities that VaultClaw is uniquely positioned to solve.

This ADR maps VaultClaw's capabilities to OpenClaw's actual attack surfaces and architecture.

## Integration Points

### 🔴 P0 — Critical (Addresses known high/critical risks)

#### 1. Configuration File Credential Encryption

**Problem:** `~/.openclaw/openclaw.json` stores `botToken`, API keys, and gateway auth tokens in plaintext on disk. The threat model rates this **High risk** (T-ACCESS-003: Token Theft).

**Integration:**
- Config values reference vault entries: `"botToken": "vault://telegram/bot-token"`
- At gateway startup, VaultClaw daemon resolves references → injects decrypted values
- If daemon is locked, gateway prompts for unlock or waits
- Rotation: update credential in vault, gateway picks up on next restart/reload

**VaultClaw component:** Daemon API + config resolver library

#### 2. Context Window Sensitive Data Redaction

**Problem:** The LLM sees the entire conversation context, workspace files, and tool output. In group chats, other participants can use prompt injection to extract sensitive data from the agent's context (T-DISC-002: Session Data Extraction).

**Integration:**
- **Pre-context injection:** Before messages enter the LLM context, scan for known credential patterns (API keys, tokens, passwords) and replace with `[VAULT:key_name]` placeholders
- **Compaction scrubbing:** During context compaction, automatically strip any residual sensitive fragments
- **Runtime resolution:** When the agent actually needs a credential (e.g., to call an API), it requests it via VaultClaw daemon — the credential value never enters the LLM context window
- **Pattern registry:** VaultClaw maintains a list of known credential formats (AWS keys, GitHub tokens, Anthropic API keys, etc.) for automated detection

**VaultClaw component:** Redaction engine + pattern registry

#### 3. Environment Variable & Filesystem Exposure

**Problem:** The `exec` tool can run `env`, `cat ~/.openclaw/openclaw.json`, read `~/.ssh/`, `~/.aws/`, etc. Skills run with full agent privileges (T-EXFIL-003: Credential Harvesting — **Critical**).

**Integration:**
- **Sensitive path blocklist:** VaultClaw knows which files contain credentials; provide a blocklist that OpenClaw's exec layer can enforce
- **Exec output redaction:** Scan command output for key/token patterns before returning to the LLM; replace with `[REDACTED]`
- **Env var isolation:** Strip sensitive environment variables from the exec environment; agent retrieves secrets via VaultClaw API when needed

**VaultClaw component:** Path registry + output filter + env sanitizer

### 🟡 P1 — Important (Architecture enhancements)

#### 4. Agent Gateway Credential Brokering

**Problem:** When agents need external API access (GitHub, email, cloud services), credentials are either in environment variables or config files — both persistently exposed.

**Integration:**
- Agent requests credential via VaultClaw daemon with scope and purpose
- Daemon issues short-lived, scoped token (TTL-bounded)
- Credential delivered through Unix socket (never touches disk or env)
- Auto-expires after use or timeout
- Human approval required for first-time access per agent+credential pair; policy caches subsequent requests

**VaultClaw component:** Agent Gateway (existing Phase 1C design)

#### 5. Group Chat Cache Poisoning Defense

**Problem:** Group chat messages from other participants enter the LLM context. If workspace files (MEMORY.md, daily logs) contain sensitive data, attackers can induce the agent to recall and leak it.

**Integration:**
- **Scope-based vault access:** DM sessions can access vault; group chat sessions cannot
- **Workspace file isolation:** VaultClaw provides a pre-flight check — before loading workspace files into a group chat session, scan and redact credential patterns
- **Session-level access control:** VaultClaw daemon accepts session metadata (channel, chat_type) and enforces access policies accordingly

**VaultClaw component:** Access policy engine + session-aware auth

#### 6. Sub-agent & Cron Credential Passing

**Problem:** When spawning sub-agents or cron jobs that need credentials, the only option is hardcoding them in the prompt text — which enters the LLM context and gets logged.

**Integration:**
- Sub-agents inherit a session token that can request credentials from VaultClaw daemon
- Credential requests are scoped to the parent task's approval policy
- Cron jobs use pre-approved, time-scoped tokens (configured at job creation time)
- No credential text in prompt, session history, or cron job definition

**VaultClaw component:** Session token inheritance + cron token pre-auth

### 🟢 P2 — Long-term (Ecosystem)

#### 7. Audit Trail Integration

VaultClaw's audit module records every credential access with timestamp, agent_id, credential_id, and action. Combined with OpenClaw's session metadata, this provides full traceability from a specific conversation turn → tool call → credential access.

#### 8. Skill Sandbox Credential Isolation

Third-party ClawHub skills currently run with agent privileges. VaultClaw can provide a credential proxy for sandboxed skills — skills declare required credentials in their manifest, user approves at install time, and the skill only receives those specific credentials through the proxy.

#### 9. Message-Layer Auto-Sanitization

Outbound messages (Telegram, Discord, etc.) are scanned for credential patterns before sending. Inbound messages containing credentials are flagged and scrubbed during compaction. This prevents accidental credential leaks in both directions.

## Implementation Priority

| Priority | Integration | VaultClaw Dependency | OpenClaw Change Required |
|----------|------------|---------------------|------------------------|
| P0 | Config credential encryption | Daemon API | Config resolver hook |
| P0 | Context redaction | Pattern registry + redaction engine | Pre-context filter hook |
| P0 | Exec output redaction | Output filter | Exec post-processing hook |
| P1 | Agent credential brokering | Agent Gateway (Phase 1C) | Tool/skill API |
| P1 | Group chat isolation | Access policy engine | Session metadata passing |
| P1 | Sub-agent credential passing | Session token auth | Spawn/cron token support |
| P2 | Audit trail | Audit module | Session ID correlation |
| P2 | Skill sandbox isolation | Credential proxy | Skill manifest extension |
| P2 | Message sanitization | Pattern registry | Message send/receive hooks |

## Decision

VaultClaw's Agent Gateway (Phase 1C) should be designed around these concrete integration points rather than abstract API surface area. The P0 items directly address OpenClaw's highest-risk vulnerabilities and should be implemented first.

## References

- [OpenClaw MITRE ATLAS Threat Model](https://github.com/openclaw/openclaw/blob/main/docs/security/THREAT-MODEL-ATLAS.md)
- T-ACCESS-003: Token Theft (High)
- T-EXFIL-003: Credential Harvesting (Critical)
- T-DISC-002: Session Data Extraction (Medium)
- T-EXEC-001: Direct Prompt Injection (Critical)
