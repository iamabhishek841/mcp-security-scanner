"""
Minimal MCP (Model Context Protocol) client.

Speaks JSON-RPC 2.0 over the Streamable HTTP transport, which is what
remote MCP servers expose. We only need a small slice of the protocol:
- initialize
- tools/list
- tools/call

This intentionally does NOT depend on the full official MCP SDK so the
scanner can probe servers that are slightly non-compliant too (which is
itself a useful signal).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx


class MCPClientError(Exception):
    pass


@dataclass
class MCPTool:
    name: str
    description: str = ""
    input_schema: dict = field(default_factory=dict)


@dataclass
class MCPProbeResult:
    reachable: bool
    protocol_version: str | None = None
    server_name: str | None = None
    tools: list[MCPTool] = field(default_factory=list)
    raw_initialize_response: dict | None = None
    transport_notes: list[str] = field(default_factory=list)
    error: str | None = None


class MCPClient:
    def __init__(self, base_url: str, auth_header: str | None = None, timeout: float = 15.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if auth_header:
            self.headers["Authorization"] = auth_header

    def _rpc_body(self, method: str, params: dict | None = None) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": method,
            "params": params or {},
        }

    async def _post(self, client: httpx.AsyncClient, body: dict, headers: dict | None = None) -> httpx.Response:
        return await client.post(
            self.base_url,
            json=body,
            headers=headers or self.headers,
            timeout=self.timeout,
        )

    @staticmethod
    def _parse_json_or_sse(resp: httpx.Response) -> dict:
        """MCP Streamable HTTP servers may reply with plain JSON or an SSE
        stream containing a single 'data: {...}' event. Handle both."""
        content_type = resp.headers.get("content-type", "")
        text = resp.text
        if "text/event-stream" in content_type:
            for line in text.splitlines():
                if line.startswith("data:"):
                    import json as _json
                    return _json.loads(line[len("data:"):].strip())
            raise MCPClientError("SSE response had no data: line")
        import json as _json
        return _json.loads(text)

    async def probe(self) -> MCPProbeResult:
        result = MCPProbeResult(reachable=False)
        try:
            async with httpx.AsyncClient(follow_redirects=True) as client:
                # 1. initialize
                init_body = self._rpc_body(
                    "initialize",
                    {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "mcp-security-scanner", "version": "0.1"},
                    },
                )
                init_resp = await self._post(client, init_body)
                if init_resp.status_code >= 400:
                    result.transport_notes.append(
                        f"initialize returned HTTP {init_resp.status_code}"
                    )
                else:
                    try:
                        init_json = self._parse_json_or_sse(init_resp)
                        result.raw_initialize_response = init_json
                        server_info = (init_json.get("result") or {}).get("serverInfo", {})
                        result.server_name = server_info.get("name")
                        result.protocol_version = (init_json.get("result") or {}).get(
                            "protocolVersion"
                        )
                    except Exception as e:  # noqa: BLE001
                        result.transport_notes.append(f"initialize response unparseable: {e}")

                result.reachable = True

                # 2. tools/list
                list_body = self._rpc_body("tools/list")
                list_resp = await self._post(client, list_body)
                if list_resp.status_code >= 400:
                    result.error = f"tools/list returned HTTP {list_resp.status_code}"
                    return result

                list_json = self._parse_json_or_sse(list_resp)
                if "error" in list_json:
                    result.error = f"tools/list JSON-RPC error: {list_json['error']}"
                    return result

                raw_tools = (list_json.get("result") or {}).get("tools", [])
                for t in raw_tools:
                    result.tools.append(
                        MCPTool(
                            name=t.get("name", "<unnamed>"),
                            description=t.get("description", "") or "",
                            input_schema=t.get("inputSchema", {}) or {},
                        )
                    )
                return result

        except httpx.RequestError as e:
            result.error = f"Connection failed: {e}"
            return result
        except Exception as e:  # noqa: BLE001
            result.error = f"Unexpected error: {e}"
            return result

    async def call_tool(
        self, client: httpx.AsyncClient, tool_name: str, arguments: dict, headers: dict | None = None
    ) -> tuple[int, dict | None, str | None]:
        """Returns (http_status, parsed_json_or_None, raw_text_snippet)."""
        body = self._rpc_body("tools/call", {"name": tool_name, "arguments": arguments})
        try:
            resp = await self._post(client, body, headers=headers)
            try:
                parsed = self._parse_json_or_sse(resp)
            except Exception:  # noqa: BLE001
                parsed = None
            return resp.status_code, parsed, resp.text[:500]
        except httpx.RequestError as e:
            return -1, None, str(e)
