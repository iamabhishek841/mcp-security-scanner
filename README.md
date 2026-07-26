# MCP Server Security & Trust Scanner

Audits any [Model Context Protocol](https://modelcontextprotocol.io) server for common
security and trust issues, and outputs a scored, shareable report.

## What it checks

**Static (schema-only, no live calls):**
- Secrets/API keys/tokens accidentally embedded in tool names or descriptions
- Prompt-injection-style language in tool descriptions (agent-directed instructions)
- Parameters that accept URLs/paths (SSRF/path-traversal risk surface)
- Schema quality (missing descriptions, untyped parameters)

**Dynamic (live test calls — optional, on by default):**
- SSRF probes: does the server accept internal/metadata URLs as tool arguments?
- Malformed input handling: does bad input leak stack traces?
- Auth bypass: does a tool respond successfully without an Authorization header?

**Output:** a 0–100 trust score (A–F grade) plus a full findings list, as both
structured JSON (Apify dataset) and a human-readable Markdown report (key-value store).

## Local development

```bash
pip install -r requirements.txt --break-system-packages
python -m src.main
```

Set input via `apify run` locally, or by creating `storage/key_value_stores/default/INPUT.json`:

```json
{
  "serverUrl": "https://your-mcp-server.example.com/mcp",
  "authHeader": "Bearer sk-...",
  "runDynamicChecks": true,
  "maxToolsToTest": 10
}
```

## Deploying to Apify

1. Install the Apify CLI: `npm install -g apify-cli`
2. Log in: `apify login`
3. From the project root: `apify push`
4. Once built, go to the Apify Console → your Actor → **Publish to Store**
   to list it publicly with pay-per-event pricing.

## Important: scope and legality

Only run the dynamic checks against MCP servers you **own or are explicitly
authorized to test**. The SSRF/auth probes are non-destructive canary tests
used across the security industry, but scanning third-party infrastructure
without permission can violate that provider's terms of service.

## Roadmap ideas (not yet built)
- Static analysis of the server's *source code* (secrets scanning, `bandit`/`semgrep`) when a GitHub repo is provided instead of a live URL
- Scheduled re-scans + score history / regression alerts
- "Verified by [scanner]" badge issuance for server authors
