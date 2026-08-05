# MCP Server Security & Trust Scanner

**A safe-by-default Apify Actor for reviewing MCP tools before an AI agent can use them.**

The scanner connects to a Model Context Protocol (MCP) Streamable HTTP
endpoint, discovers every advertised tool, analyzes agent-facing metadata and
JSON Schemas, and produces both structured output and a Markdown report.
Optional behavioral checks are restricted to tool names the operator explicitly
authorizes.

This is useful for AI platform teams, MCP server authors, security reviewers,
and agent builders deciding whether a new tool surface is suitable for an
agentic workflow.

## Safety model

Static analysis is always the default and does not execute MCP tools.

Dynamic checks run only when all of the following are true:

- `runDynamicChecks` is `true`.
- `authorizedToTest` is `true`.
- `dynamicToolAllowlist` contains at least one exact tool name.
- The advertised tool name exactly matches an allowlist entry.

An empty allowlist or missing authorization fails safely before any tool call.
The scanner never automatically executes every discovered tool. Dynamic checks
may still trigger target-side effects, so review each allowed tool before
enabling them.

SSRF behavioral testing has an additional gate: it runs only when `probeUrl` is
explicitly supplied. Use a callback endpoint you control. The scanner contains
no built-in cloud-metadata, localhost, or private-service targets.

## What is implemented

### MCP Streamable HTTP lifecycle

The client:

1. Sends `initialize` as the first MCP interaction.
2. Parses the server's negotiated protocol version.
3. Captures `Mcp-Session-Id` from the initialize response when supplied.
4. Sends `notifications/initialized`.
5. Includes `Mcp-Session-Id` and `MCP-Protocol-Version` on subsequent requests.
6. Preserves `Authorization`, `Content-Type`, and JSON/SSE `Accept` headers.
7. Handles plain JSON and Server-Sent Events (SSE).
8. Selects the SSE JSON-RPC response matching the request ID, ignoring unrelated
   notifications, server requests, and responses.
9. Reports top-level JSON-RPC errors without treating them as successful calls.
10. Follows opaque `nextCursor` values until all `tools/list` pages are read.

### Static checks

Static checks inspect tool names, descriptions, and relevant JSON Schema values.
Schema inspection is recursive across nested object properties, array item
schemas, schema compositions, descriptions, defaults, examples, and enum values.

The scanner reports:

- Credential-shaped metadata such as API keys, cloud access keys, tokens, JWTs,
  and private-key headers. Findings identify the pattern type but never copy the
  matched value.
- Clearly agent-directed or instruction-overriding prompt-injection language.
  Generic wording such as `act as` is not flagged on its own.
- Nested URL/path-shaped parameters that may require server-side SSRF or path
  controls.
- Missing descriptions and parameters without a declared type or equivalent
  schema contract.

### Authorized dynamic checks

For each exact allowlisted tool (up to `maxToolsToTest`), the scanner can:

- Submit the operator-controlled `probeUrl` to top-level URL/path-like
  parameters. Acceptance is only a risk signal; it does not prove the URL was
  fetched.
- Submit malformed values and inspect the response for stack-trace markers.
- When `authHeader` was supplied, initialize a separate MCP session without that
  header and compare the tool's unauthenticated behavior.

A call is considered successful only when the HTTP status is 2xx, there is no
top-level JSON-RPC error, and `result.isError` is not `true`.

## Actor input

| Field | Required | Description |
|---|---:|---|
| `serverUrl` | Yes | Full MCP Streamable HTTP endpoint. |
| `authHeader` | No | Authorization header for the authenticated scan. This secret is not written to output. Supplying it enables a separate unauthenticated comparison in authorized dynamic mode. |
| `runDynamicChecks` | No | Enables allowlisted live tool calls. Default: `false`. |
| `authorizedToTest` | For dynamic mode | Explicit confirmation that the operator owns or is authorized to test the server. Default: `false`. |
| `dynamicToolAllowlist` | For dynamic mode | Array of exact advertised tool names allowed to receive live calls. Default: `[]`. |
| `probeUrl` | No | Controlled callback URL. Without it, SSRF behavioral testing is skipped. |
| `maxToolsToTest` | No | Maximum matching allowlisted tools to test, from 1 to 50. Default: `10`. |

### Static-mode input

```json
{
  "serverUrl": "https://your-mcp-server.example.com/mcp",
  "authHeader": "Bearer your-secret",
  "runDynamicChecks": false,
  "authorizedToTest": false,
  "dynamicToolAllowlist": []
}
```

### Safe authorized dynamic-mode input

```json
{
  "serverUrl": "https://your-mcp-server.example.com/mcp",
  "authHeader": "Bearer your-secret",
  "runDynamicChecks": true,
  "authorizedToTest": true,
  "dynamicToolAllowlist": [
    "fetch_preview",
    "format_record"
  ],
  "probeUrl": "https://callback-you-control.example/mcp-scan",
  "maxToolsToTest": 2
}
```

## Output for users and AI agents

`.actor/output_schema.json` exposes three run outputs:

- Structured results in the default dataset.
- The complete `OUTPUT` JSON key-value-store record.
- The human-readable `REPORT.md` record.

Every successful assessment includes:

- `scanned_at`, `server_url`, `server_name`, and `protocol_version`
- `reachable` and `tool_count`
- `score`, `grade`, `summary`, and severity-ranked `findings`
- `scan_mode` (`static` or `static_and_dynamic`)
- `tools_tested_dynamically`
- `dynamic_tool_allowlist`
- `controlled_probe_url_used`
- run-specific `limitations`

Authorization values and detected credential strings are not included.

[View the sanitized report produced by the local demo](docs/sample-vulnerable-mcp-report.md).

## Safe reproducible demo

The repository includes an intentionally vulnerable local MCP server with
exactly three non-destructive tools. It simulates fake credential metadata,
prompt-injection wording, a weak schema, a URL-risk input, a stack trace, and
unauthenticated behavior. It never fetches URLs or accesses other services.

Install dependencies and start the demo from the repository root:

```bash
python -m pip install -r requirements-dev.txt
python examples/mock_mcp_server.py --host 127.0.0.1 --port 8765
```

The endpoint is `http://127.0.0.1:8765/mcp`.

To run the Actor locally in static mode, create
`storage/key_value_stores/default/INPUT.json` containing:

```json
{
  "serverUrl": "http://127.0.0.1:8765/mcp",
  "runDynamicChecks": false
}
```

Then run, in a second terminal:

```bash
python -m src.main
```

For the demo's authorized dynamic mode, replace `INPUT.json` with:

```json
{
  "serverUrl": "http://127.0.0.1:8765/mcp",
  "authHeader": "Bearer demo-only",
  "runDynamicChecks": true,
  "authorizedToTest": true,
  "dynamicToolAllowlist": [
    "fetch_preview",
    "credential_status",
    "format_record"
  ],
  "probeUrl": "https://callback-you-control.example/demo",
  "maxToolsToTest": 3
}
```

The mock server only acknowledges the callback string; it does not make a
network request. See [examples/README.md](examples/README.md) for its explicit
safety guarantees.

## Development and verification

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m ruff check src examples tests
python -m compileall -q src examples
```

`tests/test_demo_integration.py` starts the local demo on an ephemeral port and
runs discovery, recursive static checks, exact-allowlist dynamic checks,
controlled-callback handling, stack-trace detection, and an unauthenticated
comparison end to end.

## Score bands

| Grade | Score |
|---|---:|
| A | 90-100 |
| B | 75-89 |
| C | 60-74 |
| D | 40-59 |
| F | 0-39 |

The score is a prioritization aid, not a security certification.

## Limitations

- Only remote MCP Streamable HTTP endpoints are supported; local `stdio`
  servers are not.
- The scanner analyzes advertised metadata and observed responses, not server
  source code or downstream infrastructure.
- Credential, prompt-injection, schema, and stack-trace detection is heuristic.
- URL/path parameters are risk surfaces, not proof of a vulnerability.
- A successful controlled-probe response does not prove that the callback was
  fetched; verify callback telemetry separately.
- Successful unauthenticated behavior may be intentional for public tools.
- Dynamic checks may cause side effects in the target implementation even when
  supplied values appear harmless.
- The Actor does not replace threat modeling, code review, or a professional
  penetration test.

## Responsible use

Run dynamic checks only against systems you own or are explicitly authorized to
test. Review each exact allowlisted tool and its possible side effects. Do not
scan third-party infrastructure without permission.
