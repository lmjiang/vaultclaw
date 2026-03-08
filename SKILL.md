---
name: vaultclaw
description: >
  Securely retrieve, lease, and manage credentials from VaultClaw — a local-first encrypted
  credential vault. Use this skill whenever an AI agent needs API keys, tokens, passwords,
  or other secrets. Credentials are never exposed in plaintext in the agent's context window.
  Supports scoped access with TTL, human-in-the-loop approval, audit logging, and instant
  revocation. Works with any LLM-powered agent (Codex, Claude Code, OpenClaw, Cline, etc.).
version: 1.0.0
metadata:
  openclaw:
    requires:
      bins:
        - vaultclaw
    emoji: "\U0001F510"
    homepage: "https://github.com/lmjiang/vaultclaw"
---

# VaultClaw — Credential Skill for AI Agents

You are a skill that provides secure credential access through VaultClaw's local daemon. **Never paste, echo, or log raw secrets into the conversation.** Always use the structured API below.

## Prerequisites

The VaultClaw daemon must be running and unlocked:

```bash
vaultclaw daemon start
vaultclaw unlock
```

The daemon listens on `http://127.0.0.1:6274` (HTTP API) and a Unix socket at `~/.vaultclaw/daemon.sock`.

## Authentication

All API calls require a JWT bearer token. Obtain one first:

```bash
TOKEN=$(curl -s http://127.0.0.1:6274/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"password":"<master_password>"}' | jq -r .token)
```

Or via CLI (the CLI handles auth automatically when the daemon is unlocked):

```bash
vaultclaw get <query>
```

## Core Operations

### 1. Resolve a credential (preferred for agents)

Use `vclaw://` URI references to retrieve secrets without exposing them in conversation:

```bash
# Resolve one or more vclaw:// references
curl -s http://127.0.0.1:6274/v1/resolve \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"refs":["vclaw://default/anthropic","vclaw://default/openai"]}'
```

**URI format:** `vclaw://{vault}/{entry}[/{field}]`
- `vault` — vault name (usually `default`)
- `entry` — entry title, case-insensitive fuzzy match
- `field` — optional: `password`, `username`, `key`, `url`, `notes`

### 2. Search for credentials

```bash
# CLI (fuzzy search)
vaultclaw search <query>

# API
curl -s http://127.0.0.1:6274/v1/items \
  -H "Authorization: Bearer $TOKEN"
```

### 3. Get a specific credential

```bash
# CLI
vaultclaw get <query>

# API
curl -s http://127.0.0.1:6274/v1/items/<entry-uuid> \
  -H "Authorization: Bearer $TOKEN"
```

### 4. Generate TOTP code

```bash
# CLI
vaultclaw totp <query>

# API
curl -s http://127.0.0.1:6274/v1/items/<entry-uuid>/totp \
  -H "Authorization: Bearer $TOKEN"
```

## Credential Leasing (for agent-to-agent delegation)

When an agent needs time-limited access to a credential:

### Request a lease

```bash
curl -s http://127.0.0.1:6274/v1/lease \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ref": "vclaw://default/github",
    "scope": "read",
    "ttl": 3600,
    "reason": "CI deployment"
  }'
```

Response includes `lease_id`, `credential`, and `expires_at`.

### List active leases

```bash
curl -s http://127.0.0.1:6274/v1/lease/active \
  -H "Authorization: Bearer $TOKEN"
```

### Revoke a lease

```bash
curl -s -X POST http://127.0.0.1:6274/v1/lease/<lease-id>/revoke \
  -H "Authorization: Bearer $TOKEN"
```

### Emergency: revoke all leases

```bash
curl -s -X POST http://127.0.0.1:6274/v1/lease/revoke-all \
  -H "Authorization: Bearer $TOKEN"
```

## Credential Injection (run commands with secrets)

Instead of setting environment variables manually, use VaultClaw to inject secrets at runtime:

```bash
# Inject vclaw:// references from .env file into command environment
vaultclaw run --env .env -- <command>

# Inject into a config file
vaultclaw run --config config.json -- <command>

# Run with output redaction (secrets stripped from stdout/stderr)
vaultclaw run --redact-output -- <command>
```

## Redaction (prevent secret leakage)

```bash
# Redact credential patterns from text/file
vaultclaw redact [file]

# Scan a directory for plaintext secrets
vaultclaw scan <path>

# Auto-replace plaintext secrets with vclaw:// references
vaultclaw scan <path> --fix
```

## Agent Token Management

For multi-agent scenarios where sub-agents need scoped access:

```bash
# Issue a scoped agent token
curl -s http://127.0.0.1:6274/v1/agent/token \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "deploy-bot",
    "scopes": ["<entry-uuid>"],
    "actions": ["read"],
    "ttl": 3600,
    "reason": "automated deployment"
  }'

# List active agent tokens
curl -s http://127.0.0.1:6274/v1/agent/tokens \
  -H "Authorization: Bearer $TOKEN"

# View audit log
curl -s http://127.0.0.1:6274/v1/agent/audit \
  -H "Authorization: Bearer $TOKEN"

# Revoke a token
curl -s -X POST http://127.0.0.1:6274/v1/agent/revoke/<token-id> \
  -H "Authorization: Bearer $TOKEN"
```

## Security Operations

```bash
# Password health check
vaultclaw health

# Breach check (HIBP, k-anonymity)
vaultclaw breach [--all]

# Security dashboard
vaultclaw watch

# AI-enhanced security report
vaultclaw report
```

## API Reference (full endpoint list)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/auth/token` | Authenticate, get JWT |
| POST | `/v1/resolve` | Resolve `vclaw://` references |
| GET | `/v1/items` | List all entries |
| POST | `/v1/items` | Create entry |
| GET | `/v1/items/:id` | Get entry by ID |
| PUT | `/v1/items/:id` | Update entry |
| DELETE | `/v1/items/:id` | Delete entry |
| GET | `/v1/items/:id/totp` | Generate TOTP code |
| POST | `/v1/lease` | Create credential lease |
| GET | `/v1/lease/active` | List active leases |
| POST | `/v1/lease/:id/revoke` | Revoke a lease |
| POST | `/v1/lease/revoke-all` | Revoke all leases |
| POST | `/v1/agent/token` | Issue scoped agent token |
| GET | `/v1/agent/tokens` | List agent tokens |
| GET | `/v1/agent/audit` | Query audit log |
| POST | `/v1/agent/revoke/:id` | Revoke agent token |
| GET | `/v1/agent/dashboard` | Agent activity dashboard |
| POST | `/v1/breach-check` | Check single entry for breach |
| POST | `/v1/breach-check/all` | Check all entries |
| GET | `/v1/health/vault` | Vault health analysis |
| GET | `/v1/report` | Security report |
| GET | `/v1/status` | Vault status (locked/unlocked) |
| GET | `/v1/health` | Daemon health check |

## Important Rules

1. **Never log or display raw credential values in conversation.** Use `vclaw://` references and resolve them only when needed for execution.
2. **Prefer `vaultclaw run` for command execution** — it handles injection and redaction automatically.
3. **Use leases for delegation** — never pass raw secrets between agents. Issue a scoped, time-limited lease instead.
4. **Check daemon status first** — if the vault is locked, prompt the user to unlock before proceeding.
5. **Revoke when done** — if you created a lease for a specific task, revoke it after the task completes.
