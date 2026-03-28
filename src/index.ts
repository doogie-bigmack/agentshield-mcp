#!/usr/bin/env node
/**
 * AgentShield MCP Server
 *
 * Exposes AgentShield security scanning capabilities as MCP tools.
 * Tools: scan_prompt, scan_output, scan_tool, scan_mcp_server,
 *        check_policy, get_threat_patterns, list_scans, get_scan
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { AgentShieldClient } from "./client.js";

// --- Configuration ---
const config = {
  baseUrl:
    process.env.AGENTSHIELD_URL || "https://agentshield-api.bigmac-attack.com",
  apiKey: process.env.AGENTSHIELD_API_KEY,
  email: process.env.AGENTSHIELD_EMAIL,
  password: process.env.AGENTSHIELD_PASSWORD,
};

const client = new AgentShieldClient(config);

// --- Server ---
const server = new McpServer({
  name: "agentshield",
  version: "1.0.0",
});

// ==========================================
// Tool 1: scan_prompt
// ==========================================
server.tool(
  "scan_prompt",
  "Scan a prompt or user input for injection attacks (jailbreaks, prompt injection, role hijacking). Returns risk score and detected threats.",
  {
    content: z
      .string()
      .describe("The prompt or user input text to scan for injection attacks"),
    agent_id: z
      .string()
      .optional()
      .describe("Optional agent ID for tracking"),
  },
  async ({ content, agent_id }) => {
    try {
      const result = await client.request("POST", "/api/v1/scan/injection", {
        content,
        agent_id,
      });
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        content: [{ type: "text" as const, text: `Error: ${msg}` }],
        isError: true,
      };
    }
  }
);

// ==========================================
// Tool 2: scan_output
// ==========================================
server.tool(
  "scan_output",
  "Scan AI model output for data leakage, PII exposure, harmful content, or policy violations before delivering to the user.",
  {
    content: z.string().describe("The model output content to scan"),
    agent_id: z
      .string()
      .optional()
      .describe("Optional agent ID for tracking"),
    content_type: z
      .enum(["text", "code", "json", "markdown"])
      .optional()
      .describe("Type of content being scanned"),
  },
  async ({ content, agent_id, content_type }) => {
    try {
      const result = await client.request("POST", "/api/v1/scan/output", {
        content,
        agent_id,
        content_type,
      });
      return {
        content: [
          { type: "text" as const, text: JSON.stringify(result, null, 2) },
        ],
      };
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        content: [{ type: "text" as const, text: `Error: ${msg}` }],
        isError: true,
      };
    }
  }
);

// ==========================================
// Tool 3: scan_tool
// ==========================================
server.tool(
  "scan_tool",
  "Scan an API tool definition for security risks before allowing an AI agent to use it. Checks for SSRF, data exfiltration, privilege escalation, etc.",
  {
    name: z.string().describe("Tool name (e.g., 'send_email')"),
    endpoint_url: z
      .string()
      .describe("The API endpoint URL this tool calls"),
    method: z
      .string()
      .optional()
      .default("GET")
      .describe("HTTP method (GET, POST, PUT, DELETE)"),
    description: z
      .string()
      .optional()
      .describe("Human-readable description of the tool"),
    parameters: z
      .record(z.string(), z.unknown())
      .optional()
      .describe("JSON schema of tool parameters"),
    headers: z
      .record(z.string(), z.string())
      .optional()
      .describe("Headers the tool sends"),
  },
  async ({ name, endpoint_url, method, description, parameters, headers }) => {
    try {
      const result = await client.request("POST", "/api/v1/scan/tool", {
        name,
        endpoint_url,
        method,
        description,
        parameters,
        headers,
      });
      return {
        content: [
          { type: "text" as const, text: JSON.stringify(result, null, 2) },
        ],
      };
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        content: [{ type: "text" as const, text: `Error: ${msg}` }],
        isError: true,
      };
    }
  }
);

// ==========================================
// Tool 4: scan_mcp_server
// ==========================================
server.tool(
  "scan_mcp_server",
  "Scan an MCP server and its tools for security risks. Analyzes tool definitions, permissions, and potential attack vectors.",
  {
    name: z.string().describe("MCP server name"),
    url: z.string().describe("Server URL or package command"),
    tools: z
      .array(
        z.object({
          name: z.string(),
          description: z.string().optional(),
          input_schema: z.record(z.string(), z.unknown()).optional(),
        })
      )
      .describe("List of tools exposed by the MCP server"),
  },
  async ({ name, url, tools }) => {
    try {
      const result = await client.request("POST", "/api/v1/scan/mcp", {
        name,
        url,
        tools,
      });
      return {
        content: [
          { type: "text" as const, text: JSON.stringify(result, null, 2) },
        ],
      };
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        content: [{ type: "text" as const, text: `Error: ${msg}` }],
        isError: true,
      };
    }
  }
);

// ==========================================
// Tool 5: check_policy
// ==========================================
server.tool(
  "check_policy",
  "List or check security policies. Returns all active policies for tool security, MCP security, or memory governance.",
  {
    policy_type: z
      .enum(["tool-security", "mcp-security", "memory-governance"])
      .describe("Type of policies to retrieve"),
  },
  async ({ policy_type }) => {
    try {
      let path: string;
      switch (policy_type) {
        case "tool-security":
          path = "/api/v1/tool-security/policies";
          break;
        case "mcp-security":
          path = "/api/v1/mcp-security/policies";
          break;
        case "memory-governance":
          path = "/api/v1/memory/governance/policies";
          break;
      }
      const result = await client.request("GET", path);
      return {
        content: [
          { type: "text" as const, text: JSON.stringify(result, null, 2) },
        ],
      };
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        content: [{ type: "text" as const, text: `Error: ${msg}` }],
        isError: true,
      };
    }
  }
);

// ==========================================
// Tool 6: get_threat_patterns
// ==========================================
server.tool(
  "get_threat_patterns",
  "Get a breakdown of threat patterns detected across scans. Useful for understanding what types of attacks are most common.",
  {
    days: z
      .number()
      .optional()
      .default(30)
      .describe("Number of days to look back (default 30)"),
  },
  async ({ days }) => {
    try {
      const result = await client.request(
        "GET",
        "/api/v1/analytics/threats",
        undefined,
        { days: String(days) }
      );
      return {
        content: [
          { type: "text" as const, text: JSON.stringify(result, null, 2) },
        ],
      };
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        content: [{ type: "text" as const, text: `Error: ${msg}` }],
        isError: true,
      };
    }
  }
);

// ==========================================
// Tool 7: list_scans
// ==========================================
server.tool(
  "list_scans",
  "List recent security scans with their results. Filter by status or type.",
  {
    limit: z
      .number()
      .optional()
      .default(20)
      .describe("Max results to return"),
    offset: z.number().optional().default(0).describe("Pagination offset"),
  },
  async ({ limit, offset }) => {
    try {
      const result = await client.request(
        "GET",
        "/api/v1/scans",
        undefined,
        {
          limit: String(limit),
          offset: String(offset),
        }
      );
      return {
        content: [
          { type: "text" as const, text: JSON.stringify(result, null, 2) },
        ],
      };
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        content: [{ type: "text" as const, text: `Error: ${msg}` }],
        isError: true,
      };
    }
  }
);

// ==========================================
// Tool 8: get_scan
// ==========================================
server.tool(
  "get_scan",
  "Get detailed results for a specific scan by ID.",
  {
    scan_id: z.string().describe("The scan ID to retrieve"),
  },
  async ({ scan_id }) => {
    try {
      const result = await client.request(
        "GET",
        `/api/v1/scans/${scan_id}`
      );
      return {
        content: [
          { type: "text" as const, text: JSON.stringify(result, null, 2) },
        ],
      };
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        content: [{ type: "text" as const, text: `Error: ${msg}` }],
        isError: true,
      };
    }
  }
);

// ==========================================
// Tool 9: scan_pii
// ==========================================
server.tool(
  "scan_pii",
  "Scan text content for personally identifiable information (PII) like emails, phone numbers, SSNs, credit cards, etc.",
  {
    content: z.string().describe("Text content to scan for PII"),
  },
  async ({ content }) => {
    try {
      const result = await client.request("POST", "/api/v1/pii/scan", {
        content,
      });
      return {
        content: [
          { type: "text" as const, text: JSON.stringify(result, null, 2) },
        ],
      };
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        content: [{ type: "text" as const, text: `Error: ${msg}` }],
        isError: true,
      };
    }
  }
);

// ==========================================
// Tool 10: scan_memory
// ==========================================
server.tool(
  "scan_memory",
  "Scan agent memory stores (JSON, SQLite, Redis, VectorDB) for security issues like poisoned data, prompt injection in stored content, or unauthorized access patterns.",
  {
    memory_type: z
      .enum(["json", "sqlite", "redis", "vectordb", "unified"])
      .describe("Type of memory store to scan"),
    connection_string: z
      .string()
      .optional()
      .describe("Connection string for the memory store"),
    content: z
      .string()
      .optional()
      .describe("Inline JSON/text content to scan"),
  },
  async ({ memory_type, connection_string, content }) => {
    try {
      const path =
        memory_type === "unified"
          ? "/api/v1/memory/scan/unified"
          : `/api/v1/memory/scan/${memory_type}`;

      const body: Record<string, unknown> = {};
      if (connection_string) body.connection_string = connection_string;
      if (content) body.content = content;

      const result = await client.request("POST", path, body);
      return {
        content: [
          { type: "text" as const, text: JSON.stringify(result, null, 2) },
        ],
      };
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        content: [{ type: "text" as const, text: `Error: ${msg}` }],
        isError: true,
      };
    }
  }
);

// --- Start Server ---
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("AgentShield MCP Server running on stdio");
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
