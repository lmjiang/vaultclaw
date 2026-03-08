#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

// ---- VaultClaw HTTP client (inline, zero deps beyond fetch) ----

interface ResolveResult {
  ref: string;
  value: string;
  found: boolean;
  entry_id?: string;
  field?: string;
}

interface ItemSummary {
  id: string;
  title: string;
  category: string | null;
  tags: string[];
  favorite: boolean;
  sensitive: boolean;
  credential_type: string;
  created_at: string;
  updated_at: string;
}

interface LeaseResponse {
  lease_id: string;
  credential: string;
  expires_at: string;
}

interface ActiveLease {
  lease_id: string;
  entry_id: string;
  agent_id: string;
  scope: string;
  reason: string;
  created_at: string;
  expires_at: string;
}

export function createClient() {
  const baseUrl = (
    process.env.VAULTCLAW_ENDPOINT ?? "http://127.0.0.1:6274"
  ).replace(/\/+$/, "");
  const token = process.env.VAULTCLAW_TOKEN ?? null;

  async function request<T>(
    method: string,
    path: string,
    body?: unknown
  ): Promise<T> {
    const url = `${baseUrl}${path}`;
    const headers: Record<string, string> = {};

    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
    }

    const response = await fetch(url, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });

    if (!response.ok) {
      const text = await response.text().catch(() => "");
      let msg: string;
      try {
        msg = (JSON.parse(text) as { error: string }).error ?? text;
      } catch {
        msg = text || response.statusText;
      }
      throw new Error(`VaultClaw API error (${response.status}): ${msg}`);
    }

    const text = await response.text();
    return text ? (JSON.parse(text) as T) : ({} as T);
  }

  return {
    async resolve(refs: string[]): Promise<ResolveResult[]> {
      const data = await request<{ results: ResolveResult[] }>(
        "POST",
        "/v1/resolve",
        { refs }
      );
      return data.results;
    },

    async listItems(): Promise<ItemSummary[]> {
      return request<ItemSummary[]>("GET", "/v1/items");
    },

    async createLease(
      ref: string,
      scope: string,
      ttl: number,
      reason: string
    ): Promise<LeaseResponse> {
      return request<LeaseResponse>("POST", "/v1/lease", {
        ref,
        scope,
        ttl,
        reason,
      });
    },

    async revokeLease(leaseId: string): Promise<void> {
      await request<unknown>("POST", `/v1/lease/${leaseId}/revoke`);
    },

    async revokeAllLeases(): Promise<{ count: number }> {
      return request<{ count: number }>("POST", "/v1/lease/revoke-all");
    },

    async activeLeases(): Promise<ActiveLease[]> {
      const data = await request<{ leases: ActiveLease[] }>(
        "GET",
        "/v1/lease/active"
      );
      return data.leases;
    },
  };
}

// ---- MCP Server setup ----

export function createServer() {
  const server = new McpServer({
    name: "vaultclaw",
    version: "0.1.0",
  });

  const client = createClient();

  // Tool 1: vaultclaw_resolve
  server.tool(
    "vaultclaw_resolve",
    "Resolve vclaw:// credential references to their secret values. " +
      "Returns the resolved values for each reference.",
    {
      refs: z
        .array(z.string())
        .describe(
          'Array of vclaw:// URIs to resolve, e.g. ["vclaw://default/github", "vclaw://default/aws/key"]'
        ),
    },
    async ({ refs }) => {
      try {
        const results = await client.resolve(refs);
        const resolved = results.filter((r) => r.found);
        const failed = results.filter((r) => !r.found);

        const lines: string[] = [];
        for (const r of resolved) {
          lines.push(`${r.ref} = ${r.value}`);
        }
        for (const r of failed) {
          lines.push(`${r.ref} = [NOT FOUND]`);
        }

        return {
          content: [{ type: "text", text: lines.join("\n") }],
        };
      } catch (err) {
        return {
          content: [
            {
              type: "text",
              text: `Error resolving credentials: ${err instanceof Error ? err.message : String(err)}`,
            },
          ],
          isError: true,
        };
      }
    }
  );

  // Tool 2: vaultclaw_list
  server.tool(
    "vaultclaw_list",
    "List available credential entries in the vault. " +
      "Returns titles and metadata only — no secret values.",
    {},
    async () => {
      try {
        const items = await client.listItems();
        if (items.length === 0) {
          return {
            content: [{ type: "text", text: "No entries in the vault." }],
          };
        }

        const lines = items.map((item) => {
          const tags = item.tags.length > 0 ? ` [${item.tags.join(", ")}]` : "";
          const cat = item.category ? ` (${item.category})` : "";
          const flags = [
            item.favorite ? "fav" : "",
            item.sensitive ? "sensitive" : "",
          ]
            .filter(Boolean)
            .join(", ");
          const flagStr = flags ? ` {${flags}}` : "";
          return `- ${item.title} (${item.credential_type})${cat}${tags}${flagStr}  [id: ${item.id}]`;
        });

        return {
          content: [
            {
              type: "text",
              text: `${items.length} entries:\n${lines.join("\n")}`,
            },
          ],
        };
      } catch (err) {
        return {
          content: [
            {
              type: "text",
              text: `Error listing entries: ${err instanceof Error ? err.message : String(err)}`,
            },
          ],
          isError: true,
        };
      }
    }
  );

  // Tool 3: vaultclaw_lease
  server.tool(
    "vaultclaw_lease",
    "Create a time-limited credential lease. " +
      "Returns the credential value and an expiration timestamp. " +
      "The lease is automatically revoked after the TTL expires.",
    {
      ref: z
        .string()
        .describe('vclaw:// URI of the credential, e.g. "vclaw://default/github"'),
      scope: z
        .enum(["read", "use"])
        .describe('"read" to view the value, "use" to autofill/inject'),
      ttl: z
        .number()
        .int()
        .positive()
        .describe("Time-to-live in seconds for the lease"),
      reason: z.string().describe("Why this credential is needed"),
    },
    async ({ ref, scope, ttl, reason }) => {
      try {
        const lease = await client.createLease(ref, scope, ttl, reason);
        return {
          content: [
            {
              type: "text",
              text: [
                `Lease created: ${lease.lease_id}`,
                `Credential: ${lease.credential}`,
                `Expires: ${lease.expires_at}`,
              ].join("\n"),
            },
          ],
        };
      } catch (err) {
        return {
          content: [
            {
              type: "text",
              text: `Error creating lease: ${err instanceof Error ? err.message : String(err)}`,
            },
          ],
          isError: true,
        };
      }
    }
  );

  // Tool 4: vaultclaw_revoke
  server.tool(
    "vaultclaw_revoke",
    "Revoke a credential lease by ID, or revoke all active leases. " +
      'Pass a specific lease_id, or "all" to revoke everything.',
    {
      lease_id: z
        .string()
        .describe('Lease ID to revoke, or "all" to revoke all active leases'),
    },
    async ({ lease_id }) => {
      try {
        if (lease_id === "all") {
          const result = await client.revokeAllLeases();
          return {
            content: [
              {
                type: "text",
                text: `Revoked ${result.count} lease(s).`,
              },
            ],
          };
        }

        await client.revokeLease(lease_id);
        return {
          content: [{ type: "text", text: `Lease ${lease_id} revoked.` }],
        };
      } catch (err) {
        return {
          content: [
            {
              type: "text",
              text: `Error revoking lease: ${err instanceof Error ? err.message : String(err)}`,
            },
          ],
          isError: true,
        };
      }
    }
  );

  return server;
}

// ---- Main ----

async function main() {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  process.stderr.write(`Fatal: ${err}\n`);
  process.exit(1);
});
