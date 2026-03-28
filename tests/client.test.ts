/**
 * Unit tests for AgentShieldClient
 */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { AgentShieldClient } from "../src/client.js";

describe("AgentShieldClient", () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("should use API key auth when provided", async () => {
    let capturedHeaders: Record<string, string> = {};

    globalThis.fetch = async (input: any, init?: any) => {
      capturedHeaders = init?.headers || {};
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };

    const client = new AgentShieldClient({
      baseUrl: "https://test.example.com",
      apiKey: "test-key-123",
    });

    await client.request("GET", "/api/v1/health");
    assert.equal(capturedHeaders["X-API-Key"], "test-key-123");
  });

  it("should login and use bearer token when email/password provided", async () => {
    let callCount = 0;
    let capturedHeaders: Record<string, string> = {};

    globalThis.fetch = async (input: any, init?: any) => {
      callCount++;
      const url = typeof input === "string" ? input : input.toString();

      if (url.includes("/auth/login")) {
        return new Response(
          JSON.stringify({ access_token: "jwt-token-abc" }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }

      capturedHeaders = init?.headers || {};
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };

    const client = new AgentShieldClient({
      baseUrl: "https://test.example.com",
      email: "user@test.com",
      password: "pass123",
    });

    await client.request("GET", "/api/v1/scans");
    assert.equal(callCount, 2); // login + actual request
    assert.equal(capturedHeaders["Authorization"], "Bearer jwt-token-abc");
  });

  it("should throw on API error responses", async () => {
    globalThis.fetch = async () => {
      return new Response("Not Found", { status: 404 });
    };

    const client = new AgentShieldClient({
      baseUrl: "https://test.example.com",
      apiKey: "test-key",
    });

    await assert.rejects(
      () => client.request("GET", "/api/v1/nonexistent"),
      (err: Error) => {
        assert.ok(err.message.includes("404"));
        return true;
      }
    );
  });

  it("should throw on login failure", async () => {
    globalThis.fetch = async () => {
      return new Response("Unauthorized", { status: 401 });
    };

    const client = new AgentShieldClient({
      baseUrl: "https://test.example.com",
      email: "bad@test.com",
      password: "wrong",
    });

    await assert.rejects(
      () => client.request("GET", "/api/v1/scans"),
      (err: Error) => {
        assert.ok(err.message.includes("Login failed"));
        return true;
      }
    );
  });

  it("should send JSON body for POST requests", async () => {
    let capturedBody: string = "";
    let capturedHeaders: Record<string, string> = {};

    globalThis.fetch = async (input: any, init?: any) => {
      capturedBody = init?.body || "";
      capturedHeaders = init?.headers || {};
      return new Response(JSON.stringify({ scanned: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };

    const client = new AgentShieldClient({
      baseUrl: "https://test.example.com",
      apiKey: "test-key",
    });

    await client.request("POST", "/api/v1/scan/injection", {
      content: "test prompt",
    });

    assert.equal(capturedHeaders["Content-Type"], "application/json");
    const parsed = JSON.parse(capturedBody);
    assert.equal(parsed.content, "test prompt");
  });

  it("should append query parameters", async () => {
    let capturedUrl = "";

    globalThis.fetch = async (input: any) => {
      capturedUrl = typeof input === "string" ? input : input.toString();
      return new Response(JSON.stringify({}), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };

    const client = new AgentShieldClient({
      baseUrl: "https://test.example.com",
      apiKey: "test-key",
    });

    await client.request("GET", "/api/v1/scans", undefined, {
      limit: "10",
      offset: "5",
    });

    assert.ok(capturedUrl.includes("limit=10"));
    assert.ok(capturedUrl.includes("offset=5"));
  });

  it("should handle text responses", async () => {
    globalThis.fetch = async () => {
      return new Response("OK", {
        status: 200,
        headers: { "Content-Type": "text/plain" },
      });
    };

    const client = new AgentShieldClient({
      baseUrl: "https://test.example.com",
      apiKey: "test-key",
    });

    const result = await client.request("GET", "/api/v1/health");
    assert.equal(result, "OK");
  });

  it("should strip trailing slash from baseUrl", async () => {
    let capturedUrl = "";

    globalThis.fetch = async (input: any) => {
      capturedUrl = typeof input === "string" ? input : input.toString();
      return new Response(JSON.stringify({}), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };

    const client = new AgentShieldClient({
      baseUrl: "https://test.example.com/",
      apiKey: "test-key",
    });

    await client.request("GET", "/api/v1/health");
    assert.ok(
      capturedUrl.startsWith("https://test.example.com/api/"),
      `URL should not have double slash: ${capturedUrl}`
    );
  });
});
