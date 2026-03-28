# AgentShield MCP Server

[![Build & Test](https://github.com/doogie-bigmack/agentshield-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/doogie-bigmack/agentshield-mcp/actions/workflows/ci.yml)

Expose [AgentShield](https://agentshield.io) security scanning as MCP (Model Context Protocol) tools. Any MCP-compatible AI client can scan prompts, outputs, tools, and MCP servers for security threats.

## Quick Start

```bash
# Install dependencies
npm install

# Build
npm run build

# Run (stdio transport)
AGENTSHIELD_API_KEY=as_xxx node dist/index.js
```

## Configuration

Set environment variables:

| Variable | Required | Description |
|----------|----------|-------------|
| `AGENTSHIELD_URL` | No | API base URL (default: `https://agentshield-api.bigmac-attack.com`) |
| `AGENTSHIELD_API_KEY` | Yes* | API key from AgentShield dashboard |
| `AGENTSHIELD_EMAIL` | Alt* | Email for login-based auth |
| `AGENTSHIELD_PASSWORD` | Alt* | Password for login-based auth |

*Either `AGENTSHIELD_API_KEY` or both `AGENTSHIELD_EMAIL` + `AGENTSHIELD_PASSWORD` required.

## MCP Client Configuration

### Claude Desktop / Cursor / etc.

Add to your MCP config:

```json
{
  "mcpServers": {
    "agentshield": {
      "command": "node",
      "args": ["/path/to/agentshield-mcp/dist/index.js"],
      "env": {
        "AGENTSHIELD_API_KEY": "as_your_key_here"
      }
    }
  }
}
```

## Tools

| Tool | Description |
|------|-------------|
| `scan_prompt` | Scan user input for injection attacks (jailbreaks, prompt injection) |
| `scan_output` | Scan model output for data leakage, PII, harmful content |
| `scan_tool` | Scan API tool definitions for SSRF, exfiltration risks |
| `scan_mcp_server` | Scan MCP server + tools for security risks |
| `check_policy` | List active security policies (tool, MCP, memory) |
| `get_threat_patterns` | Get threat pattern analytics over time |
| `list_scans` | List recent scan history |
| `get_scan` | Get detailed scan results by ID |
| `scan_pii` | Scan text for PII (emails, SSNs, credit cards) |
| `scan_memory` | Scan agent memory stores for poisoned data |

## Testing

```bash
npm test         # Run integration tests (vitest)
```

Tests mock the AgentShield API client and verify all 10 MCP tools call the correct endpoints with the correct parameters. No live API connection needed.

## Development

```bash
npm run build    # Compile TypeScript
npm run dev      # Build + run
npm test         # Run tests
```

## License

MIT
