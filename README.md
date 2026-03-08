# VaultClaw

**Secure your AI/Agentic life.**

A local-first encrypted credential vault purpose-built for AI agents. Humans keep full control over their digital identity while safely lending credentials to LLM-powered tools — scoped, time-limited, auditable, and instantly revocable.

```
Human: "Post this thread to my X account"
  → Agent requests lease: vclaw://social/x-account/session-token
  → VaultClaw: scope=POST, TTL=30min, requires approval
  → Human taps "Approve"
  → Agent gets time-limited session token
  → Posts thread, token auto-expires
  → Full audit trail logged
```

## The Problem

AI agents (OpenClaw, Claude Code, Codex, custom agents) are becoming capable enough to act on our behalf — posting to social media, managing cloud resources, filing PRs, paying bills. But there's a fundamental security gap: **how does a human safely lend their digital identity to an AI?**

Today's reality:
- **Plaintext secrets everywhere** — `.env` files, config files, agent context windows
- **Context window leakage** — secrets enter LLM context and persist in conversation history
- **All-or-nothing access** — agents get permanent keys with no scope limits or expiry
- **No audit trail** — no record of which agent accessed what, when, or why
- **No kill switch** — if an agent misbehaves, there's no instant revocation

VaultClaw solves this with **credential leasing** — time-limited, scope-limited delegation of human credentials to AI agents. Not "AI has its own vault" but "human lends access, on their terms."

## Key Features

### For AI Agent Security
- **Credential leasing** — time-limited, scope-limited delegation with auto-expiry
- **Context-window redaction** — scan messages for credential patterns, replace with `[VAULT:key_name]`
- **Exec output redaction** — detect key/token patterns in command output before LLM sees it
- **Placeholder references** — `vclaw://vault/entry/field` in configs, secrets never on disk or in context
- **Scoped agent tokens** — per-vault, per-entry, with TTL and operation scope
- **Instant revocation** — one command kills all active leases
- **Real-time audit** — every lease logged: who, what, when, how long
- **Human-in-the-loop approval** — sensitive entries require explicit human approval

### Core Vault
- **AES-256-GCM encryption** with per-entry encryption keys
- **Argon2id key derivation** with configurable parameters
- **Single encrypted SQLite file** — portable, self-contained, sync via any method
- **TOTP/2FA** — built-in authenticator with code generation
- **Password health** — weak/reused/old password detection and scoring
- **HIBP breach checking** — k-anonymity API, no plaintext sent
- **YubiKey FIDO2** — passwordless unlock via hmac-secret
- **Import from 1Password** — .1pif and CSV import
- **Single binary** — Rust daemon with CLI and HTTP API

## Quick Start

### Build from source

```bash
git clone https://github.com/lmjiang/vaultclaw.git
cd vaultclaw
cargo build --release

# Add to PATH
cp target/release/vaultclaw /usr/local/bin/
```

### Initialize a vault

```bash
vaultclaw init
# Enter master password when prompted
# Creates ~/.vaultclaw/default.db
```

### Add credentials

```bash
# API key
vaultclaw add --title "Anthropic" --type api_key --password "sk-ant-..."

# Login
vaultclaw add --title "GitHub" --type login \
  --url "https://github.com" --username "myuser" --password "ghp_..."

# List entries
vaultclaw ls
```

### Start the daemon

```bash
vaultclaw daemon start
vaultclaw unlock
# Daemon listens on http://127.0.0.1:6274
```

### Use credentials in your agent

Replace hardcoded secrets with `vclaw://` references:

```json
{
  "providers": {
    "anthropic": { "apiKey": "vclaw://default/anthropic" },
    "openai": { "apiKey": "vclaw://default/openai" }
  }
}
```

Then run with credential injection:

```bash
vaultclaw run --env .env -- node my-agent.js
```

### Redact secrets from agent context

```bash
# Scan and redact credential patterns from text/output
vaultclaw redact [file]

# Run command with output redaction (secrets never reach LLM context)
vaultclaw run --redact-output -- <cmd>

# Replace plaintext secrets in config files with vclaw:// references
vaultclaw scan <path> --fix
```

## CLI Reference

### Core Vault

| Command | Description |
|---------|-------------|
| `vaultclaw init` | Create a new encrypted vault |
| `vaultclaw get <query>` | Retrieve credential by name (fuzzy match) |
| `vaultclaw add --title <t>` | Add a new credential |
| `vaultclaw edit <query>` | Edit an existing credential |
| `vaultclaw rm <query>` | Delete a credential |
| `vaultclaw ls` | List credentials (filter by `--tag`, `--category`, `--favorites`) |
| `vaultclaw search <query>` | Full text search |
| `vaultclaw totp <query>` | Generate TOTP code |
| `vaultclaw gen` | Generate random password |
| `vaultclaw export` | Export vault (JSON or CSV) |
| `vaultclaw import --from <fmt> <file>` | Import from 1Password (.1pif) or CSV |
| `vaultclaw status` | Show vault status |

### Security

| Command | Description |
|---------|-------------|
| `vaultclaw health` | Analyze password health (weak, reused, old) |
| `vaultclaw breach [--all]` | Check passwords against HIBP breach database |
| `vaultclaw watch` | Full security dashboard (Watchtower-style) |
| `vaultclaw report` | AI-enhanced security report |
| `vaultclaw rotate scan` | Identify password rotation candidates |
| `vaultclaw scan <path>` | Find plaintext secrets in files |
| `vaultclaw scan <path> --fix` | Replace secrets with `vclaw://` references |

### Agent & Credential Delegation

| Command | Description |
|---------|-------------|
| `vaultclaw agent dashboard` | Agent activity dashboard |
| `vaultclaw agent audit` | Query audit log |
| `vaultclaw lease list` | List active leases |
| `vaultclaw lease revoke-all` | Emergency: revoke all leases |
| `vaultclaw lease sensitivity <id> <level>` | Set approval level (low/medium/high) |

### Credential Injection & Redaction

| Command | Description |
|---------|-------------|
| `vaultclaw run --env .env -- <cmd>` | Run command with resolved `vclaw://` env vars |
| `vaultclaw run --config config.json -- <cmd>` | Inject secrets into config at runtime |
| `vaultclaw run --redact-output -- <cmd>` | Redact secrets from command output |
| `vaultclaw inject <file>` | Resolve references in a config file to stdout |
| `vaultclaw redact [file]` | Scan/redact credential patterns from text |

### Infrastructure

| Command | Description |
|---------|-------------|
| `vaultclaw daemon start` | Start background daemon |
| `vaultclaw daemon stop` | Stop daemon |
| `vaultclaw daemon status` | Check daemon status |
| `vaultclaw unlock` | Unlock vault in running daemon |
| `vaultclaw vault list` | List configured vaults |
| `vaultclaw sync push` | Push vault to sync target |
| `vaultclaw yubikey enroll` | Enroll YubiKey for passwordless unlock |

## HTTP API

The daemon exposes a REST API on `http://127.0.0.1:6274`:

```bash
# Authenticate
TOKEN=$(curl -s http://127.0.0.1:6274/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"password":"your-master-password"}' | jq -r .token)

# Resolve a credential
curl -s http://127.0.0.1:6274/v1/resolve \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"refs":["vclaw://default/anthropic"]}'

# Create a time-limited lease
curl -s http://127.0.0.1:6274/v1/lease \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"ref":"vclaw://default/anthropic","scope":"read","ttl":3600}'
```

### vclaw:// URI Format

```
vclaw://{vault}/{entry}[/{field}]
```

| Component | Description | Example |
|-----------|-------------|---------|
| `vault` | Vault name | `default` |
| `entry` | Entry title (case-insensitive) | `github`, `anthropic` |
| `field` | Optional: specific field | `password`, `key`, `username` |

## Architecture

```
Rust Daemon (single binary, localhost HTTP)
├── Vault Engine (SQLite + per-entry AES-256-GCM encryption)
├── Crypto (RustCrypto, Argon2id KDF, XChaCha20-Poly1305)
├── Agent Gateway
│   ├── Scoped token issuance (JWT, TTL-enforced)
│   ├── Credential leasing with auto-expiry
│   ├── Human-in-the-loop approval flow
│   └── Full audit logging
├── Context Redaction Engine
│   ├── Pre-context credential pattern scanning
│   ├── Exec output secret detection
│   └── Pattern registry (AWS, GitHub, Anthropic, OpenAI, etc.)
├── REST API (localhost:6274, JWT bearer auth)
│   ├── /v1/resolve    — resolve vclaw:// references
│   ├── /v1/items      — CRUD operations
│   ├── /v1/agent      — token management + audit
│   ├── /v1/lease      — credential leasing
│   └── /v1/export     — vault export
├── CLI (clap, talks to daemon via HTTP)
└── YubiKey FIDO2 hmac-secret unlock
```

### Security Model

- **Encryption**: AES-256-GCM with per-entry encryption keys
- **Key derivation**: Argon2id with configurable parameters
- **Vault format**: Single encrypted SQLite file, portable, self-contained
- **Agent tokens**: JWT-based, scoped to specific entries, TTL-enforced
- **Credential leasing**: Every access is time-limited and audited
- **Context redaction**: Secrets detected and stripped before entering LLM context
- **Zero plaintext**: Secrets never written to disk outside the vault
- **No custom crypto**: Only audited, battle-tested primitives (RustCrypto)

## Building

### Prerequisites

- Rust 1.70+ (stable toolchain)

### Build

```bash
# Full build (default — includes WebDAV sync)
cargo build --release

# Minimal build (no optional features, smaller binary)
cargo build --release --no-default-features

# With YubiKey FIDO2 support
cargo build --release --features yubikey
```

### Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `full` | Yes | Enables all features below |
| `webdav` | Yes | WebDAV sync provider |
| `web-ui` | Yes | Web dashboard static file serving |
| `yubikey` | No | YubiKey FIDO2 passwordless unlock |

### Test

```bash
# Run all tests
cargo test

# Integration tests only
cargo test --test integration

# Benchmarks
cargo bench --bench vault_ops

# Clippy
cargo clippy -- -D warnings
```

## Comparison

| Feature | 1Password | Bitwarden | VaultClaw |
|---------|-----------|-----------|-----------|
| Credential leasing (TTL + scope) | - | - | Yes |
| Context-window redaction | - | - | Yes |
| Exec output redaction | - | - | Yes |
| Placeholder references (`vclaw://`) | - | - | Yes |
| Scoped agent tokens | - | - | Yes |
| Instant lease revocation | - | - | Yes |
| Real-time agent audit | Coming soon | - | Yes |
| Human approval flow | Per-fill only | - | Yes |
| Auto-expiry by default | - | - | Yes |
| YubiKey native unlock | Yes | Yes | Yes |
| Local-first | No (cloud required) | Self-host option | Yes |
| Price | $36/yr | Free/$10yr | Free |

## Why This Matters for AI Agents

Every AI coding agent (OpenClaw, Claude Code, Codex, Cline, etc.) needs access to credentials — API keys, tokens, SSH keys. Today, these secrets are typically:

1. Stored in plaintext `.env` files
2. Pasted directly into agent prompts
3. Visible in LLM context windows and conversation logs
4. Shared with no scope limits, expiry, or audit trail

VaultClaw provides the missing security layer: an encrypted vault that AI agents can query through a structured API, receiving only the specific credentials they need, for a limited time, with full audit logging and human approval.

## License

[MIT](LICENSE)
