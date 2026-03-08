# VaultClaw Business Plan

## Vision

**Secure your AI/Agentic life.**

The first credential manager built for the age of AI agents. Free for everyone, with a premium macOS experience.

## Problem

AI agents are becoming capable enough to act on our behalf — posting to social media, managing cloud resources, filing PRs, paying bills. But there's a fundamental gap: **how does a human safely lend their digital identity to an AI?**

Today's reality:
- **Plaintext secrets everywhere** — `.env` files, config files, environment variables, agent context windows
- **All-or-nothing access** — agents get permanent keys with no scope limits or expiry
- **No audit trail** — no record of which agent accessed what credential, when, or why
- **No kill switch** — if an agent misbehaves, there's no instant revocation
- **Identity confusion** — do you give AI its own accounts, or let it use yours?

The answer is almost always: **humans want AI to use their own accounts.** "Post this to MY Twitter." "Check MY AWS bill." "Push to MY GitHub repo." Nobody wants to create a separate Twitter account for their AI assistant.

1Password's "Agentic Autofill" only covers browser login form filling via a single partner (Browserbase). It doesn't address the real problem: **controlled, time-limited delegation of human credentials to AI agents.**

## Solution

VaultClaw: a **credential delegation layer** for the AI agent era. Humans keep full control over their digital identity while safely lending credentials to AI agents — scoped, time-limited, auditable, and instantly revocable.

### Core Concept: Credential Leasing

The key insight: AI agents don't need their own accounts. They need **temporary, scoped access to human credentials.** VaultClaw makes this a first-class primitive:

```
Human: "Post this thread to my X account"
  → Agent requests lease: vclaw://social/x-account/session-token
  → VaultClaw: scope=POST /tweets, TTL=30min, requires approval
  → Human taps "Approve" on push notification
  → Agent gets time-limited session token
  → Posts thread, token auto-expires
  → Full audit trail logged
```

This is **OAuth for human-to-AI delegation** — but without requiring every service to support it natively. VaultClaw works with any credential type: API keys, session tokens, cookies, SSH keys, database passwords.

### Core Differentiators

1. **Credential leasing** — time-limited, scope-limited delegation of human credentials to AI agents. Not "AI has its own vault" but "human lends access, on their terms"
2. **Placeholder references** (`vclaw://vault/entry/field`) — agents never see raw secrets in config files
3. **Scoped agent tokens** — grant access per-vault, per-entry, with TTL and operation scope
4. **Instant revocation** — one command kills all active leases
5. **Real-time audit** — every credential lease logged: who, what, when, how long, what they did
6. **Human-in-the-loop approval** — sensitive entries require explicit tap-to-approve before agent access
7. **Auto-expiry by default** — no permanent access grants; everything has a TTL
8. **YubiKey-native** — passwordless unlock via FIDO2 hmac-secret

### What We Don't Do (v1)

- Browser autofill for humans (future, not core)
- Enterprise SSO / SCIM provisioning
- Cloud-hosted vault service — local-first only

## Architecture

```
Rust Daemon (single binary, localhost HTTP)
├── Vault Engine (SQLite + application-layer encryption)
├── Crypto (ring/RustCrypto, Argon2id, AES-256-GCM)
├── REST API (localhost:6274, bearer token auth)
│   ├── /v1/resolve    — resolve vclaw:// references
│   ├── /v1/items      — CRUD
│   ├── /v1/agent      — token management, audit
│   └── /v1/approve    — human approval webhook
├── CLI (clap, talks to daemon via HTTP)
├── YubiKey FIDO2 hmac-secret unlock
└── Sync (iCloud/file-based, encrypted blob)

Node.js Ecosystem (npm packages)
├── @vaultclaw/sdk     — TypeScript client SDK (HTTP, zero native deps)
├── @vaultclaw/mcp     — MCP tool server (agent-universal)
└── @vaultclaw/openclaw — OpenClaw skill/plugin

Future:
├── macOS GUI (SwiftUI, calls Rust daemon via localhost HTTP)
└── Browser Extension (agent-aware credential UI)
```

### Why localhost HTTP (not Unix socket)

1Password 8 uses localhost HTTP REST API for external integrations (Connect Server, SDKs).
We follow the same pattern:

- **Cross-platform** — macOS, Linux, Windows all work identically
- **Node.js native** — `fetch('http://127.0.0.1:6274/v1/resolve')`, zero deps
- **Language agnostic** — any HTTP client can integrate
- **MCP compatible** — MCP protocol is HTTP/SSE, natural fit
- **Security** — bound to 127.0.0.1 only, scoped bearer tokens for auth

### Agent Integration Flow

**Scenario 1: Config-time resolution (API keys, bot tokens)**
```
OpenClaw config (no plaintext secrets):
  "apiKey": "vclaw://agent-keys/anthropic/api-key"
  "botToken": "vclaw://agent-keys/telegram/bot-token"

Startup:
  1. Agent loads @vaultclaw/sdk
  2. SDK connects to localhost:6274 with scoped bearer token
  3. Resolves vclaw:// references → secrets returned in memory
  4. Secrets never written to disk by agent
```

**Scenario 2: Runtime credential leasing (human identity delegation)**
```
User: "用我的 X 账号发这条推文"
  1. Agent calls POST /v1/lease with:
     - ref: vclaw://social/x-account/session-token
     - scope: "post:tweets"
     - ttl: "30m"
     - reason: "User requested tweet post"
  2. VaultClaw checks entry sensitivity level:
     - Low: auto-approve, return credential
     - Medium: push notification, wait for tap
     - High: require YubiKey touch
  3. Agent receives time-limited credential lease
  4. Lease auto-expires after TTL or on explicit revoke
  5. All actions audited: agent ID, timestamp, scope used, lease duration
```

**Scenario 3: Instant revocation**
```
Human realizes AI is doing something wrong:
  $ vaultclaw lease revoke --all
  → All active leases invalidated instantly
  → Agents get 401 on next credential use
  → Push notification confirms: "3 active leases revoked"
```

### Node.js SDK Example

```typescript
import { VaultClaw } from '@vaultclaw/sdk';

const vc = new VaultClaw({ token: process.env.VAULTCLAW_TOKEN });

// Scenario 1: Resolve config-time secrets
const apiKey = await vc.resolve('vclaw://agent-keys/anthropic/api-key');

// Scenario 2: Lease a human credential for a specific task
const lease = await vc.lease({
  ref: 'vclaw://social/x-account/session-token',
  scope: 'post:tweets',
  ttl: '30m',
  reason: 'User requested tweet post'
});
// lease.credential — the actual token (auto-expires)
// lease.id — for audit/revoke
// lease.expiresAt — ISO timestamp

// Scenario 3: Grant a scoped token to a sub-agent
const token = await vc.grant({
  scope: ['agent-keys'],
  permissions: ['read'],
  ttl: '1h',
  agentId: 'openclaw-bt7274'
});

// Revoke all active leases + agent tokens
await vc.revokeAll();

// Audit log — who accessed what, when, for how long
const logs = await vc.audit({ last: '24h' });
// [{ agent: "bt7274", ref: "vclaw://social/x-account/...", action: "lease",
//    scope: "post:tweets", duration: "12m", status: "expired" }]
```

## Business Model

### Free (forever)

- CLI + daemon
- Agent credential management (core value prop)
- Personal password storage and management
- YubiKey / FIDO2 authentication
- iCloud sync
- Unlimited entries, unlimited vaults
- OpenClaw / Claude Code / MCP integration

### $20 USD — Lifetime (macOS GUI)

- Native SwiftUI management app
- Visual audit dashboard
- Drag-and-drop vault organization
- Quick Look integration
- Menu bar agent status monitor
- Touch ID unlock

### Why Lifetime, Not Subscription

- Solo developer project — no team to feed monthly
- Password managers are trust products — subscription creates misaligned incentives ("pay us or lose access to your passwords")
- $20 is impulse-buy territory for Mac users
- Differentiates against 1Password ($36/yr) and Bitwarden ($10/yr)

## Market

### Primary: AI/Agent Developers

- OpenClaw users, Claude Code users, Cursor/Windsurf users
- Anyone running AI agents that need API keys and credentials
- Distribution: OpenClaw skill, Claude Code integration, GitHub/HN

### Secondary: Privacy-Conscious Mac Users

- People who want local-first, no-cloud-dependency credential management
- YubiKey enthusiasts
- Developers who already use CLI tools daily

## Competitive Landscape

| Feature | 1Password | Bitwarden | VaultClaw |
|---|---|---|---|
| **Credential leasing (TTL + scope)** | ❌ | ❌ | ✅ Core feature |
| Agent credential lifecycle | ❌ (form fill only) | ❌ | ✅ Core feature |
| Placeholder references | ❌ | ❌ | ✅ `vclaw://` |
| Scoped agent tokens | ❌ | ❌ | ✅ TTL + per-entry + scope |
| Instant lease revocation | ❌ | ❌ | ✅ |
| Real-time agent audit | "coming soon" | ❌ | ✅ |
| Human approval flow | Per-fill only | ❌ | ✅ Sensitivity levels |
| Auto-expiry by default | ❌ | ❌ | ✅ Everything has TTL |
| YubiKey native unlock | ✅ | ✅ | ✅ |
| Local-first | ❌ (cloud required) | Self-host option | ✅ Default |
| Price | $36/yr | Free/$10yr | Free/$20 lifetime |

## Roadmap

### Phase 1: Dogfood (now)
- Storage layer: SQLite + app-layer encryption
- YubiKey FIDO2 hmac-secret authentication
- Agent gateway: Unix socket + scoped tokens
- OpenClaw integration: `vclaw://` reference resolution
- Dogfood on BT-7274 / OpenClaw system

### Phase 2: Public CLI Release
- Polish CLI UX
- Documentation + quickstart guides
- OpenClaw skill package
- MCP tool server for broader agent compatibility
- GitHub release + Homebrew formula

### Phase 3: macOS GUI ($20)
- SwiftUI native app
- Visual vault management
- Agent audit dashboard
- Menu bar quick access
- Touch ID integration

### Phase 4: Expand
- Browser extension (agent-aware, not competing on form fill)
- Linux GUI (if demand)
- Team/shared vault features

## Technical Decisions

### Storage: SQLite + Application-Layer Encryption
- SQLite WAL mode for local concurrent access
- Each entry encrypted individually (AES-256-GCM)
- Vault file is a single encrypted SQLite DB for sync simplicity
- iCloud sync: whole-file sync (low write frequency makes conflicts rare)
- Conflict resolution: `updated_at` per-entry merge when iCloud conflict copies detected
- Can upgrade to oplog/CRDT later without changing agent interface

### Crypto: Industry Standard
- Key derivation: Argon2id (or YubiKey hmac-secret bypass)
- Encryption: AES-256-GCM (via ring or aes-gcm crate)
- Key material: zeroize + secrecy crates for memory safety
- No custom crypto — only audited, battle-tested primitives

### Agent Interface: Unix Socket + Scoped Tokens
- Daemon listens on `~/.vaultclaw/agent.sock`
- Agents authenticate with scoped tokens (JWT-like, signed by vault key)
- Token specifies: allowed vaults, allowed entries, TTL, permissions (read/list)
- Every access logged to audit table in SQLite
- Sensitive entries require real-time human approval (push notification)

---

*"AI agents act on your behalf. VaultClaw makes sure they do it on your terms."*
