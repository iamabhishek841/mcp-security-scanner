# Safe vulnerable MCP demo

This local Streamable HTTP server exposes exactly three non-destructive tools:
`fetch_preview`, `credential_status`, and `format_record`. It deliberately
advertises fake credential-like metadata, agent-directed instructions, a weak
schema, and a URL-shaped parameter. It also returns a simulated stack trace for
one malformed call and intentionally accepts sessions with no Authorization
header.

The demo never fetches any URL, connects to cloud metadata or local services,
deletes data, sends messages, writes files, or modifies external systems.

Start it from the repository root:

```bash
python examples/mock_mcp_server.py --host 127.0.0.1 --port 8765
```

The MCP endpoint is `http://127.0.0.1:8765/mcp`. Stop it with `Ctrl+C`.
