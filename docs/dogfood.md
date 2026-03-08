# VaultClaw Dogfood Guide

How to set up VaultClaw as your AI agent credential manager.

## Prerequisites

- Rust toolchain (1.70+)
- Node.js 18+ (for the SDK)

## 1. Build VaultClaw

```bash
cargo build --release
# Binary at target/release/vaultclaw
```

Add to your PATH or create an alias:

```bash
alias vaultclaw="./target/release/vaultclaw"
```

## 2. Initialize a Vault

```bash
vaultclaw init
# Enter master password when prompted
# Creates ~/.vaultclaw/default.db
```

## 3. Add Credentials

```bash
# Add an API key
vaultclaw add \
  --title "OpenAI" \
  --type api_key \
  --key "sk-..." \
  --secret "org-..."

# Add a login
vaultclaw add \
  --title "GitHub" \
  --type login \
  --url "https://github.com" \
  --username "myuser" \
  --password "ghp_..."

# Add an Anthropic key
vaultclaw add \
  --title "Anthropic" \
  --type api_key \
  --key "sk-ant-..." \
  --secret ""
```

Verify entries:

```bash
vaultclaw ls
```

## 4. Start the Daemon

```bash
vaultclaw daemon start
```

The daemon listens on:
- Unix socket (for CLI communication)
- HTTP API on `127.0.0.1:6274` (for SDK/agent access)

Unlock the vault:

```bash
vaultclaw unlock
# Enter master password
```

Check status:

```bash
vaultclaw daemon status
```

## 5. Configure Your Agent

### Using vclaw:// References

In your agent configuration, replace hardcoded secrets with `vclaw://` references:

**Before:**
```json
{
  "providers": {
    "anthropic": {
      "apiKey": "sk-ant-abc123..."
    },
    "openai": {
      "apiKey": "sk-xyz..."
    }
  }
}
```

**After (openclaw.json):**
```json
{
  "providers": {
    "anthropic": {
      "apiKey": "vclaw://default/anthropic"
    },
    "openai": {
      "apiKey": "vclaw://default/openai"
    }
  },
  "vaultclaw": {
    "endpoint": "http://127.0.0.1:6274",
    "autoResolve": true
  }
}
```

### Using the Node.js SDK

Install the SDK:

```bash
npm install @vaultclaw/sdk
```

In your agent startup:

```typescript
import { VaultClaw } from "@vaultclaw/sdk";

const vc = new VaultClaw();
await vc.authenticate(process.env.VAULTCLAW_PASSWORD);

// Resolve credentials at startup
const anthropicKey = await vc.resolve("vclaw://default/anthropic");
const openaiKey = await vc.resolve("vclaw://default/openai");

// Use the resolved values
const client = new Anthropic({ apiKey: anthropicKey.value });
```

### Using Credential Leasing (Recommended)

For time-limited access with automatic expiration:

```typescript
import { VaultClaw } from "@vaultclaw/sdk";

const vc = new VaultClaw();
await vc.authenticate(process.env.VAULTCLAW_PASSWORD);

// Lease a credential for 1 hour
const lease = await vc.lease({
  ref: "vclaw://default/anthropic",
  scope: "read",
  ttl: 3600,
  reason: "Agent session started",
});

console.log(lease.credential);  // the API key
console.log(lease.expires_at);  // when it auto-expires

// When done, revoke early
await vc.revokeLease(lease.lease_id);
```

### Using the HTTP API Directly

If not using the SDK, call the HTTP API with `curl`:

```bash
# Authenticate
TOKEN=$(curl -s http://127.0.0.1:6274/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"password":"your-master-password"}' | jq -r .token)

# Resolve a credential
curl -s http://127.0.0.1:6274/v1/resolve \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"refs":["vclaw://default/anthropic"]}'

# Create a lease
curl -s http://127.0.0.1:6274/v1/lease \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ref":"vclaw://default/anthropic","scope":"read","ttl":3600,"reason":"manual test"}'

# List active leases
curl -s http://127.0.0.1:6274/v1/lease/active \
  -H "Authorization: Bearer $TOKEN"

# Revoke all leases (emergency)
curl -s -X POST http://127.0.0.1:6274/v1/lease/revoke-all \
  -H "Authorization: Bearer $TOKEN"
```

## 6. Entry Sensitivity Levels

Control which entries require manual approval before leasing:

```bash
# Auto-approve (default)
vaultclaw lease sensitivity <entry-uuid> low

# Requires push notification approval (future)
vaultclaw lease sensitivity <entry-uuid> medium

# Requires YubiKey touch (future)
vaultclaw lease sensitivity <entry-uuid> high
```

For dogfood v1, only `low` sensitivity is auto-approved. `medium` and `high` will reject lease requests with a 403 Forbidden until the approval flow is implemented.

## 7. Monitoring

### CLI Dashboard

```bash
vaultclaw agent dashboard
```

### Active Leases

```bash
vaultclaw lease list
```

### Audit Log

```bash
vaultclaw agent audit
vaultclaw agent audit --agent test-agent --last 20
```

### Emergency Revocation

Revoke all leases immediately:

```bash
vaultclaw lease revoke-all
```

## vclaw:// URI Format

```
vclaw://{vault}/{entry}[/{field}]
```

| Component | Description | Example |
|-----------|-------------|---------|
| `vault` | Vault name (use `default`) | `default` |
| `entry` | Entry title (case-insensitive) | `github`, `anthropic` |
| `field` | Optional: specific field | `password`, `key`, `username` |

Examples:
- `vclaw://default/github` — resolves to the password
- `vclaw://default/github/username` — resolves to the username
- `vclaw://default/aws/key` — resolves to the API key

## Troubleshooting

### Daemon not running

```
Error: Daemon not running. Start it with 'vaultclaw daemon start'.
```

Start the daemon: `vaultclaw daemon start`

### Vault is locked

```
Error: Vault is locked
```

Unlock: `vaultclaw unlock`

### Entry not found

```
Error: Entry not found
```

Check entry names: `vaultclaw ls`

The `vclaw://` resolver uses case-insensitive title matching. Make sure the entry title in your config matches.

### Rate limit exceeded

```
Error: Rate limit exceeded (429)
```

The HTTP API has a per-subject rate limit of 100 requests/second. Batch your resolve calls using `resolveAll()` instead of calling `resolve()` in a loop.

### Sensitivity rejection

```
Error: Entry sensitivity is Medium, requires manual approval (403)
```

Either lower the sensitivity (`vaultclaw lease sensitivity <id> low`) or wait for the push notification approval flow (coming in phase 2).

### Port conflict

If port 6274 is already in use:

```bash
vaultclaw daemon run --socket /tmp/vc.sock --vault ~/.vaultclaw/default.db --http-port 7000
```

Then configure the SDK:

```typescript
const vc = new VaultClaw({ baseUrl: "http://127.0.0.1:7000" });
```
