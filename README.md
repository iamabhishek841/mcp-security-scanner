# MCP Server Security & Trust Scanner

**Preflight security and trust analysis for remote Model Context Protocol (MCP) servers.**

Inspect an MCP server before connecting it to Claude, ChatGPT, an internal agent, or an automated workflow. The scanner discovers exposed tools, analyzes their schemas and descriptions, optionally performs authorized behavioral checks, and generates a scored report that can be reviewed, exported, or shared with your engineering and security teams.

> Designed for MCP server developers, AI platform teams, security reviewers, integration engineers, and organizations evaluating third-party MCP servers.

## Why use this scanner?

MCP servers can expose powerful capabilities to AI agents: fetching URLs, reading files, calling internal APIs, querying databases, or triggering business actions. A poorly described or weakly protected tool can introduce avoidable risk before the server is ever connected to an agent.

This Actor helps you perform a fast, repeatable preflight review by highlighting:

- Potential credential exposure in tool metadata
- Agent-directed or prompt-injection-style instructions
- URL/path input surfaces that may require SSRF or path-traversal controls
- Weak or ambiguous tool schemas
- Unexpected unauthenticated tool behavior
- Error responses that may disclose stack traces or implementation details
- Suspicious handling of internal or cloud-metadata URL inputs

It produces both a machine-readable result and a human-readable report, making it suitable for one-off reviews, CI workflows, vendor assessments, and repeatable MCP onboarding checks.

## Key capabilities

### 1. MCP endpoint discovery

The scanner connects to a remote MCP **Streamable HTTP** endpoint and performs the protocol calls needed to:

- Initialize the MCP connection
- Read server identity and protocol information when available
- Enumerate tools through `tools/list`
- Capture tool names, descriptions, and input schemas

### 2. Metadata and schema analysis

This mode analyzes the exposed tool metadata without executing the tools themselves.

Checks include:

- **Potential secret exposure**  
  Detects credential-like patterns in tool names and descriptions, including common API-key, cloud-key, access-token, JWT, and private-key formats.

- **Prompt-injection indicators**  
  Flags agent-directed language such as attempts to override prior instructions, hide behavior from the user, force tool ordering, or bypass refusal behavior.

- **URL and path risk surfaces**  
  Identifies top-level parameters with names such as `url`, `uri`, `endpoint`, `host`, `target`, `path`, `file`, `filepath`, or `callback`. These parameters are not automatically vulnerabilities, but they often require strong server-side validation.

- **Schema quality issues**  
  Flags missing or very short tool descriptions and input parameters without a declared type.

### 3. Optional authorized dynamic checks

Dynamic checks execute live `tools/call` requests against a limited number of exposed tools. They should only be enabled for MCP servers that you own or are explicitly authorized to test.

Checks include:

- **Internal URL acceptance probe**  
  For tools exposing URL-like parameters, the scanner submits a controlled internal/cloud-metadata-style URL and reports when the tool returns HTTP 200 without a top-level validation error. This is a risk indicator requiring manual verification; it does not by itself prove that the target URL was fetched.

- **Malformed-input handling**  
  Sends schema-invalid or oversized values and checks the response for stack-trace and framework-detail indicators.

- **Unexpected unauthenticated behavior**  
  When an authorization header is supplied for the scan, the scanner also makes a comparison call without that header and reports tools that appear to respond successfully. Some tools may intentionally permit public access, so the result should be reviewed in context.

You can cap dynamic testing from **1 to 50 tools** using `maxToolsToTest`.

## What you receive

Every successful run produces:

### Structured JSON result

Saved to the default Apify dataset and as the `OUTPUT` record in the key-value store.

The result contains:

- Scan timestamp
- Target server URL
- MCP server name and protocol version when available
- Reachability status
- Number of tools discovered
- 0–100 preflight score
- A–F grade
- Summary counts by check category
- Full severity-ranked findings list

### Human-readable Markdown report

Saved as `REPORT.md` in the Actor's key-value store. The report is ready to download, attach to a review ticket, or share with a developer, platform, security, or procurement team.

## Example report

```text
MCP Security & Trust Report

Server: https://example.com/mcp
Tools exposed: 14
Score: 72/100 (Grade C)

Summary
- Tools with possible secret leaks: 0
- Tools with prompt-injection-style language: 1
- Tools with URL/path risk surfaces: 3
- Tools with weak or incomplete schemas: 4
- Dynamic checks run: yes

Findings
[HIGH] prompt_injection_risk (system_lookup)
Tool description contains agent-directed instruction language.

[HIGH] ssrf_confirmed_or_unclear (fetch_resource)
The tool accepted an internal/cloud-metadata-style URL and returned 200
without a top-level validation error. Manual verification is required.

[LOW] schema_quality (create_ticket)
Parameter 'priority' has no declared type.
```

## Input

```json
{
  "serverUrl": "https://your-mcp-server.example.com/mcp",
  "authHeader": "Bearer sk-...",
  "runDynamicChecks": false,
  "maxToolsToTest": 10
}
```

### Input fields

| Field | Required | Description |
|---|---:|---|
| `serverUrl` | Yes | Full URL of the remote MCP Streamable HTTP endpoint. |
| `authHeader` | No | Authorization header used when the server requires authentication, for example `Bearer ...`. The field is configured as secret input and is not included in the generated reports. |
| `runDynamicChecks` | No | Enables live tool calls for behavioral checks. Keep disabled unless you own or are authorized to test the server. Default: `false`. |
| `maxToolsToTest` | No | Maximum number of discovered tools to test dynamically. Allowed range: 1–50. Default: `10`. |

## How to use

1. Click **Try for free**.
2. Enter the MCP server's remote Streamable HTTP endpoint.
3. Add an authorization header when the server requires one.
4. Leave dynamic checks disabled for metadata/schema-only analysis.
5. Enable dynamic checks only for a server you own or are authorized to test.
6. Run the Actor.
7. Review the dataset output or download `REPORT.md` from the key-value store.

## Common use cases

### Review an MCP server before connecting it to an AI agent

Run a preflight scan before adding a new MCP endpoint to Claude, ChatGPT, an IDE, an internal agent platform, or a production automation workflow.

### Validate your own MCP server before release

Catch risky metadata, ambiguous schemas, credential-like strings, weak validation signals, and error leakage before publishing your server.

### Compare MCP server versions

Run the scanner after changing tool descriptions, schemas, authentication, or input validation and compare the resulting score and findings.

### Support security and vendor assessment

Export the structured output or Markdown report as evidence for internal review. Findings are designed to guide follow-up verification rather than replace manual assessment.

### Integrate into automated workflows

Run the Actor through the Apify API from CI/CD, an internal security workflow, or an MCP server onboarding pipeline. Use the Actor's **API** tab to generate a ready-to-run request for your account and chosen language.

## Understanding the score

The scanner starts from 100 and applies weighted penalties based on the severity and category of the detected findings.

| Grade | Score | Interpretation |
|---|---:|---|
| A | 90–100 | Strong automated preflight result; review informational context before approval. |
| B | 75–89 | Generally acceptable, with findings that should be reviewed. |
| C | 60–74 | Multiple weaknesses or one or more material risk indicators. |
| D | 40–59 | Significant issues; remediation is recommended before connection. |
| F | 0–39 | High-risk automated result; do not rely on the server without deeper review. |

The score is a heuristic prioritization aid. It is not proof that a server is secure or insecure.

## Severity levels

- **Critical** — Credential or private-key-like material detected in exposed tool metadata
- **High** — Prompt-injection indicators, suspicious internal-URL handling, or unexpected unauthenticated behavior
- **Medium** — URL/path risk surfaces or stack-trace leakage
- **Low** — Missing descriptions, ambiguous parameter types, or schema-quality issues

## Security, privacy, and responsible use

- Only run dynamic checks against systems you own or are explicitly authorized to test.
- Dynamic mode executes tool calls and may cause the target server to process supplied arguments.
- Review the exposed tools before enabling dynamic mode, especially when the server includes tools that can modify data, send messages, trigger deployments, create transactions, or perform other side effects.
- The authorization value is accepted through a secret input field and is not written into the generated dataset or Markdown report.
- Do not scan third-party infrastructure without permission. Unauthorized scanning may violate contracts, terms of service, or applicable law.

## Scope and current limitations

This release is an automated preflight scanner, not a penetration-testing suite.

Current scope:

- Remote MCP servers exposed through Streamable HTTP
- Tool discovery via `tools/list`
- Tool invocation via `tools/call` for optional dynamic checks
- Tool names, descriptions, and top-level input-schema properties
- JSON and basic SSE response handling

Current limitations:

- Local `stdio` MCP servers are not supported
- Source-code repositories are not analyzed
- Detection is heuristic and may produce false positives or false negatives
- URL/path parameters indicate a risk surface, not a confirmed vulnerability
- A successful internal-URL probe does not prove that the server fetched the URL
- Successful unauthenticated responses may be intentional for public tools
- Some stateful or implementation-specific MCP endpoints may not be fully compatible
- The scanner does not replace threat modeling, code review, manual security testing, or a professional penetration test

## Local development

```bash
pip install -r requirements.txt --break-system-packages
python -m src.main
```

For local Actor execution, use `apify run` or create:

```text
storage/key_value_stores/default/INPUT.json
```

with an input object matching the schema shown above.

## Deploying your own copy to Apify

```bash
npm install -g apify-cli
apify login
apify push
```

After the build succeeds, open the Actor in the Apify Console and publish it to the Store.

## Roadmap

Planned extensions include:

- Source-code analysis when a GitHub repository is supplied
- Recursive inspection of nested JSON schemas
- Expanded credential and prompt-injection detection rules
- Safer per-tool allowlisting for dynamic checks
- Scheduled rescans and score history
- Regression alerts when a server's security posture changes
- CI/CD quality gates for MCP server releases
- Organization-level reports across multiple MCP servers
- Export formats for security and compliance workflows

## Important disclaimer

This Actor performs automated heuristic analysis. Results should be manually reviewed and validated. A high score does not certify an MCP server as secure, and a finding does not automatically confirm a vulnerability.
