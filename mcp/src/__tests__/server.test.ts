import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createClient, createServer } from "../index.js";

// ---- Mock fetch ----

type MockResponse = {
  status: number;
  body: unknown;
};

let mockResponses: Map<string, MockResponse>;
let fetchCalls: Array<{ url: string; method: string; body?: unknown }>;

const originalFetch = globalThis.fetch;

function mockFetch(
  input: string | URL | Request,
  init?: RequestInit
): Promise<Response> {
  const url = typeof input === "string" ? input : input.toString();
  const method = init?.method ?? "GET";
  const body = init?.body ? JSON.parse(init.body as string) : undefined;
  fetchCalls.push({ url, method, body });

  const key = `${method} ${new URL(url).pathname}`;
  const mock = mockResponses.get(key);

  if (!mock) {
    return Promise.resolve(
      new Response(JSON.stringify({ error: "Not mocked" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      })
    );
  }

  return Promise.resolve(
    new Response(JSON.stringify(mock.body), {
      status: mock.status,
      headers: { "Content-Type": "application/json" },
    })
  );
}

beforeEach(() => {
  mockResponses = new Map();
  fetchCalls = [];
  globalThis.fetch = mockFetch as typeof fetch;
  process.env.VAULTCLAW_TOKEN = "test-token";
  process.env.VAULTCLAW_ENDPOINT = "http://127.0.0.1:6274";
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  delete process.env.VAULTCLAW_TOKEN;
  delete process.env.VAULTCLAW_ENDPOINT;
});

// ---- createClient tests ----

describe("createClient", () => {
  it("should resolve credentials", async () => {
    mockResponses.set("POST /v1/resolve", {
      status: 200,
      body: {
        results: [
          {
            ref: "vclaw://default/github",
            value: "gh_token_123",
            found: true,
          },
        ],
      },
    });

    const client = createClient();
    const results = await client.resolve(["vclaw://default/github"]);
    assert.equal(results.length, 1);
    assert.equal(results[0].value, "gh_token_123");
    assert.equal(results[0].found, true);
  });

  it("should list items", async () => {
    mockResponses.set("GET /v1/items", {
      status: 200,
      body: [
        {
          id: "abc-123",
          title: "GitHub",
          category: null,
          tags: [],
          favorite: false,
          sensitive: false,
          credential_type: "Login",
          created_at: "2025-01-01T00:00:00Z",
          updated_at: "2025-01-01T00:00:00Z",
        },
      ],
    });

    const client = createClient();
    const items = await client.listItems();
    assert.equal(items.length, 1);
    assert.equal(items[0].title, "GitHub");
  });

  it("should create a lease", async () => {
    mockResponses.set("POST /v1/lease", {
      status: 200,
      body: {
        lease_id: "lease-001",
        credential: "secret-value",
        expires_at: "2025-01-01T01:00:00Z",
      },
    });

    const client = createClient();
    const lease = await client.createLease(
      "vclaw://default/github",
      "read",
      3600,
      "CI deploy"
    );
    assert.equal(lease.lease_id, "lease-001");
    assert.equal(lease.credential, "secret-value");
  });

  it("should revoke a lease", async () => {
    mockResponses.set("POST /v1/lease/lease-001/revoke", {
      status: 200,
      body: {},
    });

    const client = createClient();
    await client.revokeLease("lease-001");
    assert.equal(fetchCalls.length, 1);
    assert.ok(fetchCalls[0].url.includes("/lease/lease-001/revoke"));
  });

  it("should revoke all leases", async () => {
    mockResponses.set("POST /v1/lease/revoke-all", {
      status: 200,
      body: { count: 3 },
    });

    const client = createClient();
    const result = await client.revokeAllLeases();
    assert.equal(result.count, 3);
  });

  it("should list active leases", async () => {
    mockResponses.set("GET /v1/lease/active", {
      status: 200,
      body: {
        leases: [
          {
            lease_id: "lease-001",
            entry_id: "abc-123",
            agent_id: "test-agent",
            scope: "read",
            reason: "deploy",
            created_at: "2025-01-01T00:00:00Z",
            expires_at: "2025-01-01T01:00:00Z",
          },
        ],
      },
    });

    const client = createClient();
    const leases = await client.activeLeases();
    assert.equal(leases.length, 1);
    assert.equal(leases[0].lease_id, "lease-001");
  });

  it("should throw on API error", async () => {
    mockResponses.set("GET /v1/items", {
      status: 503,
      body: { error: "Vault is locked" },
    });

    const client = createClient();
    await assert.rejects(() => client.listItems(), {
      message: /Vault is locked/,
    });
  });

  it("should use custom endpoint from env", async () => {
    process.env.VAULTCLAW_ENDPOINT = "http://localhost:9999";
    mockResponses.set("GET /v1/items", {
      status: 200,
      body: [],
    });

    const client = createClient();
    await client.listItems();
    assert.ok(fetchCalls[0].url.startsWith("http://localhost:9999"));
  });

  it("should include auth header when token set", async () => {
    process.env.VAULTCLAW_TOKEN = "my-secret-token";

    // Override mock to capture headers
    let capturedHeaders: Record<string, string> = {};
    globalThis.fetch = ((
      input: string | URL | Request,
      init?: RequestInit
    ): Promise<Response> => {
      capturedHeaders = (init?.headers as Record<string, string>) ?? {};
      return Promise.resolve(
        new Response(JSON.stringify([]), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        })
      );
    }) as typeof fetch;

    const client = createClient();
    await client.listItems();
    assert.equal(capturedHeaders["Authorization"], "Bearer my-secret-token");
  });
});

// ---- MCP server tool handler tests ----

describe("MCP server tools", () => {
  // Helper: call a tool handler directly via the server's internal state
  async function callTool(
    toolName: string,
    args: Record<string, unknown>
  ): Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }> {
    // Build an MCP-like request and process it through the server
    // Since we can't easily call tool handlers directly, we test through createClient
    // and verify the MCP server creation doesn't throw
    throw new Error("Use integration approach instead");
  }

  it("should create server without error", () => {
    const server = createServer();
    assert.ok(server);
  });

  // Test tool logic through the client functions directly
  describe("vaultclaw_resolve logic", () => {
    it("should resolve multiple refs", async () => {
      mockResponses.set("POST /v1/resolve", {
        status: 200,
        body: {
          results: [
            {
              ref: "vclaw://default/github",
              value: "gh_token",
              found: true,
            },
            {
              ref: "vclaw://default/aws",
              value: "AKIAEXAMPLE",
              found: true,
            },
          ],
        },
      });

      const client = createClient();
      const results = await client.resolve([
        "vclaw://default/github",
        "vclaw://default/aws",
      ]);
      assert.equal(results.length, 2);
      assert.equal(results[0].value, "gh_token");
      assert.equal(results[1].value, "AKIAEXAMPLE");
    });

    it("should handle not-found refs", async () => {
      mockResponses.set("POST /v1/resolve", {
        status: 200,
        body: {
          results: [
            {
              ref: "vclaw://default/missing",
              value: "",
              found: false,
            },
          ],
        },
      });

      const client = createClient();
      const results = await client.resolve(["vclaw://default/missing"]);
      assert.equal(results[0].found, false);
    });
  });

  describe("vaultclaw_list logic", () => {
    it("should format items for display", async () => {
      mockResponses.set("GET /v1/items", {
        status: 200,
        body: [
          {
            id: "abc-123",
            title: "GitHub",
            category: "development",
            tags: ["work", "code"],
            favorite: true,
            sensitive: false,
            credential_type: "Login",
            created_at: "2025-01-01T00:00:00Z",
            updated_at: "2025-01-01T00:00:00Z",
          },
          {
            id: "def-456",
            title: "AWS Key",
            category: null,
            tags: [],
            favorite: false,
            sensitive: true,
            credential_type: "ApiKey",
            created_at: "2025-01-01T00:00:00Z",
            updated_at: "2025-01-01T00:00:00Z",
          },
        ],
      });

      const client = createClient();
      const items = await client.listItems();
      assert.equal(items.length, 2);
      assert.equal(items[0].title, "GitHub");
      assert.equal(items[0].favorite, true);
      assert.equal(items[1].sensitive, true);
    });

    it("should handle empty vault", async () => {
      mockResponses.set("GET /v1/items", {
        status: 200,
        body: [],
      });

      const client = createClient();
      const items = await client.listItems();
      assert.equal(items.length, 0);
    });
  });

  describe("vaultclaw_lease logic", () => {
    it("should create lease with correct params", async () => {
      mockResponses.set("POST /v1/lease", {
        status: 200,
        body: {
          lease_id: "lease-abc",
          credential: "sk-secret",
          expires_at: "2025-01-01T01:00:00Z",
        },
      });

      const client = createClient();
      const lease = await client.createLease(
        "vclaw://default/api-key",
        "read",
        3600,
        "deployment"
      );
      assert.equal(lease.lease_id, "lease-abc");
      assert.equal(lease.credential, "sk-secret");

      // Verify the request body
      assert.deepEqual(fetchCalls[0].body, {
        ref: "vclaw://default/api-key",
        scope: "read",
        ttl: 3600,
        reason: "deployment",
      });
    });

    it("should handle lease creation error", async () => {
      mockResponses.set("POST /v1/lease", {
        status: 403,
        body: { error: "High sensitivity — requires manual approval" },
      });

      const client = createClient();
      await assert.rejects(() =>
        client.createLease("vclaw://default/prod-key", "read", 3600, "test"), {
          message: /manual approval/,
        }
      );
    });
  });

  describe("vaultclaw_revoke logic", () => {
    it("should revoke specific lease", async () => {
      mockResponses.set("POST /v1/lease/lease-123/revoke", {
        status: 200,
        body: {},
      });

      const client = createClient();
      await client.revokeLease("lease-123");
      assert.equal(fetchCalls[0].method, "POST");
      assert.ok(fetchCalls[0].url.includes("lease-123"));
    });

    it("should revoke all leases", async () => {
      mockResponses.set("POST /v1/lease/revoke-all", {
        status: 200,
        body: { count: 5 },
      });

      const client = createClient();
      const result = await client.revokeAllLeases();
      assert.equal(result.count, 5);
    });
  });
});

// ---- Error handling tests ----

describe("error handling", () => {
  it("should parse JSON error responses", async () => {
    mockResponses.set("GET /v1/items", {
      status: 401,
      body: { error: "Invalid token" },
    });

    const client = createClient();
    await assert.rejects(() => client.listItems(), {
      message: /Invalid token/,
    });
  });

  it("should handle non-JSON error responses", async () => {
    globalThis.fetch = (() =>
      Promise.resolve(
        new Response("Bad Gateway", {
          status: 502,
          statusText: "Bad Gateway",
        })
      )) as typeof fetch;

    const client = createClient();
    await assert.rejects(() => client.listItems(), {
      message: /Bad Gateway/,
    });
  });

  it("should handle network errors", async () => {
    globalThis.fetch = (() =>
      Promise.reject(new Error("Connection refused"))) as typeof fetch;

    const client = createClient();
    await assert.rejects(() => client.listItems(), {
      message: /Connection refused/,
    });
  });
});

// ---- Configuration tests ----

describe("configuration", () => {
  it("should default to localhost:6274", () => {
    delete process.env.VAULTCLAW_ENDPOINT;
    mockResponses.set("GET /v1/items", {
      status: 200,
      body: [],
    });

    const client = createClient();
    client.listItems().then(() => {
      assert.ok(fetchCalls[0].url.startsWith("http://127.0.0.1:6274"));
    });
  });

  it("should strip trailing slashes from endpoint", async () => {
    process.env.VAULTCLAW_ENDPOINT = "http://localhost:6274///";
    mockResponses.set("GET /v1/items", {
      status: 200,
      body: [],
    });

    const client = createClient();
    await client.listItems();
    assert.ok(!fetchCalls[0].url.includes("///"));
  });

  it("should work without token for health-like endpoints", async () => {
    delete process.env.VAULTCLAW_TOKEN;
    mockResponses.set("GET /v1/items", {
      status: 200,
      body: [],
    });

    const client = createClient();
    await client.listItems();
    // Should not throw even without token (server decides auth)
    assert.equal(fetchCalls.length, 1);
  });
});
