# ADR-003: Agent Token System Design

**Status:** Accepted
**Date:** 2026-02-16
**Context:** Design the scoped token system for AI agent credential access

## Context

VaultClaw's Agent Gateway (Phase 1C) needs a secure token system for AI agents to request and use vault credentials without accessing the master password. Tokens must be scoped, time-limited, auditable, and revocable. See [ADR-000](000-integration-analysis.md) for integration context.

## Decision

### Token Format

```
AgentToken {
    id:           UUID v4
    agent_id:     String          // e.g., "openclaw-main", "ci-deploy"
    scopes:       Vec<EntryId>    // credential UUIDs the token can access
    actions:      Vec<AgentAction> // Read | Use | Rotate
    ttl_seconds:  u64
    max_uses:     Option<u32>     // None = unlimited within TTL
    uses:         u32             // incremented on each successful validation
    issued_at:    DateTime<Utc>
    expires_at:   DateTime<Utc>
    approved_by:  String          // "human:cli", "human:telegram", "auto-policy"
    revoked:      bool
}
```

Tokens are **opaque UUIDs** — agents present the token ID to the daemon, which validates it server-side. No JWT/HMAC needed since all validation is local (no distributed verification).

### Scope Model

**Credential scopes** are explicit `Vec<EntryId>`. An agent can only access credentials whose UUIDs are listed in its token's `scopes` field. This is an allowlist — credentials not in scope are denied even if the agent knows the UUID.

**Action scopes** control what the agent can do with in-scope credentials:

| Action | Meaning | Returns to Agent |
|--------|---------|-----------------|
| `Read` | Retrieve credential value | Password/key/note content |
| `Use`  | Inject into autofill or exec env | Confirmation only (daemon injects directly) |
| `Rotate` | Trigger password rotation | New password after rotation |

`GetCredential` requires `Read` action. Future `UseCredential` and `RotateCredential` endpoints will require their respective actions.

### TTL & Max Uses

- **TTL**: Token has hard expiry (`expires_at = issued_at + ttl_seconds`). Checked on every validation.
- **Max uses**: Optional upper bound on successful validations. Each `validate_token()` success increments `uses`. When `uses >= max_uses`, token is exhausted.
- **Recommended defaults**: TTL=3600s (1 hour), max_uses=None for interactive agents; TTL=300s, max_uses=1 for one-shot CI/cron jobs.

### Token Lifecycle

```
Agent → RequestAccess(agent_id, scopes, actions, ttl, reason)
                          ↓
         [ApprovalManager checks auto-approve policies]
                    ↓                    ↓
              Policy match          No policy match
                    ↓                    ↓
            Auto-approve         Return RequestId (pending)
            Return Token              ↓
                               Human → Grant(request_id)
                                         ↓
                                    Return Token
                                         ↓
Agent → GetCredential(token_id, credential_id)
                          ↓
         [TokenStore validates: not revoked, not expired,
          uses < max_uses, credential in scope, action allowed]
                    ↓                    ↓
              Valid                   Invalid
                    ↓                    ↓
         Increment uses          Return error reason
         Fetch from vault        Log to audit
         Return credential
         Log to audit
```

### Revocation

- **Immediate**: `Revoke(token_id)` sets `revoked=true`. Next validation fails.
- **Bulk**: `RevokeAgent(agent_id)` revokes all active tokens for an agent (future enhancement).
- **Auto-revoke**: When anomaly detection finds suspicious patterns (e.g., rapid scope violations), tokens can be auto-revoked (P1, not implemented yet).

### Rate Limiting

Per-token sliding window rate limiter:

```
RateLimit {
    max_requests_per_minute: u32    // default: 60
    window_start: Instant
    request_count: u32
}
```

Rate limit is checked **before** token validation. If exceeded, `AuditResult::RateLimited` is recorded and request is denied. Rate limits are configurable per approval policy.

### Credential Delivery

The `GetCredential` flow must deliver **actual credential values**, not just access validation. The daemon server mediates between the gateway (token validation) and the vault (credential storage):

1. Gateway validates token (scope, TTL, max_uses, revocation)
2. If valid, daemon looks up credential in unlocked vault
3. Returns **minimal credential data** — only the secret value, no metadata:

```
CredentialValue {
    credential_id: EntryId
    title: String           // for agent display/logging
    value: SecretValue      // the actual secret
}

SecretValue = Password(String) | ApiKey { key, secret } | Note(String) | SshKey { private_key }
```

This ensures agents receive the minimum data needed. Full `Entry` objects (with tags, notes, timestamps) are never sent to agents.

### Persistence

Tokens, pending requests, approval policies, and audit logs are persisted to a sidecar file alongside the vault:

- **File**: `<vault_path>.agent-state` (e.g., `~/.vaultclaw/vault.vclaw.agent-state`)
- **Format**: JSON, encrypted with the vault's derived key
- **Write strategy**: Flush on state change (token issued, revoked, policy added)
- **Load strategy**: Loaded when vault is unlocked (requires derived key)
- **Separate from vault**: Agent state changes don't trigger vault re-encryption

Audit logs grow unbounded. Future enhancement: rotation/archival after configurable size.

### Auto-Approval Policies

```
ApprovalPolicy {
    agent_id:                    String
    allowed_scopes:              Vec<EntryId>
    allowed_actions:             Vec<AgentAction>
    max_auto_approve_ttl:        u64
    require_manual_for_sensitive: bool
    max_requests_per_minute:     u32    // rate limit for this agent
}
```

Policies are set by the human via CLI (`vaultclaw agent policy add ...`). When a request matches a policy, it's auto-approved without human intervention. Requests exceeding policy limits (TTL too long, scope not pre-approved, sensitive credentials) require manual approval.

## Consequences

### Positive
- Agents never see the master password or full vault
- Every access is audited with agent identity and purpose
- Token expiry and max_uses provide defense in depth
- Auto-approval policies reduce friction for trusted workflows
- Rate limiting prevents token abuse

### Negative
- In-memory tokens are lost on daemon crash (mitigated by persistence)
- Credential delivery requires vault to be unlocked (by design — locked vault = no agent access)
- UUID tokens could be stolen if Unix socket is compromised (mitigated by socket permissions)

### Risks
- Agent could share its token with untrusted code → mitigated by TTL + max_uses + audit
- Approval fatigue → mitigated by auto-approve policies for trusted agents

## References

- [ADR-000: Integration Analysis](000-integration-analysis.md)
- CLAUDE.md Agent Security Model section
- OpenClaw MITRE ATLAS Threat Model (T-ACCESS-003, T-EXFIL-003)
