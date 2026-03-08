# @vaultclaw/mcp

MCP (Model Context Protocol) tool server for [VaultClaw](https://github.com/lmjiang/vaultclaw) credential manager.

Exposes VaultClaw credential operations as MCP tools that any MCP-compatible AI agent can call — including Codex, Claude Desktop, OpenClaw, Cursor, and Windsurf.

## Tools

| Tool | Description |
|------|-------------|
| `vaultclaw_resolve` | Resolve `vclaw://` credential references to secret values |
| `vaultclaw_list` | List vault entries (titles/metadata only, no secrets) |
| `vaultclaw_lease` | Create a time-limited credential lease |
| `vaultclaw_revoke` | Revoke a lease by ID, or all active leases |

## Prerequisites

1. VaultClaw daemon running with HTTP API enabled (default port 6274)
2. Vault unlocked (`vaultclaw unlock`)
3. Auth token (from `POST /v1/auth/token`)

## Configuration

Set these environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULTCLAW_ENDPOINT` | `http://127.0.0.1:6274` | Daemon HTTP API URL |
| `VAULTCLAW_TOKEN` | — | Bearer token for authentication |

## Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "vaultclaw": {
      "command": "npx",
      "args": ["@vaultclaw/mcp"],
      "env": {
        "VAULTCLAW_TOKEN": "your-jwt-token"
      }
    }
  }
}
```

Or if installed globally:

```json
{
  "mcpServers": {
    "vaultclaw": {
      "command": "vaultclaw-mcp",
      "env": {
        "VAULTCLAW_TOKEN": "your-jwt-token"
      }
    }
  }
}
```

## Codex (OpenAI)

Add to your Codex agent's MCP config or `codex.json`:

```json
{
  "mcpServers": {
    "vaultclaw": {
      "command": "npx",
      "args": ["@vaultclaw/mcp"],
      "env": {
        "VAULTCLAW_TOKEN": "your-jwt-token"
      }
    }
  }
}
```

This gives Codex agents secure, scoped credential access — no more plaintext API keys in `.env` files or agent prompts.

## OpenClaw

Add to your OpenClaw config:

```json
{
  "mcpServers": {
    "vaultclaw": {
      "command": "npx",
      "args": ["@vaultclaw/mcp"],
      "env": {
        "VAULTCLAW_TOKEN": "your-jwt-token"
      }
    }
  }
}
```

## Usage Examples

Once configured, AI agents can:

```
# List available credentials
> Use vaultclaw_list to see what credentials are available

# Resolve a credential
> Use vaultclaw_resolve to get the value of vclaw://default/github

# Create a time-limited lease
> Use vaultclaw_lease to get a 1-hour read lease on vclaw://default/api-key for "CI deployment"

# Revoke a lease
> Use vaultclaw_revoke to revoke lease abc-123
```

## Development

```bash
npm install
npm run build
npm test
```

## License

MIT
