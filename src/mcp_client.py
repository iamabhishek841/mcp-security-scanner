"""Small MCP Streamable HTTP client used by the scanner.

Only the lifecycle and tool operations needed by the Actor are implemented:
``initialize``, ``notifications/initialized``, ``tools/list``, and
``tools/call``. Keeping this client local also lets the scanner report useful
errors from servers that are not fully SDK-compatible.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx

LATEST_PROTOCOL_VERSION = "2025-06-18"


class MCPClientError(Exception):
    """Base error raised for invalid MCP transport or response behavior."""


class MCPProtocolError(MCPClientError):
    """A top-level JSON-RPC error returned by the MCP server."""

    def __init__(self, code: int | None, message: str):
        self.code = code
        self.message = message
        super().__init__(f"JSON-RPC error {code}: {message}")


@dataclass
class MCPTool:
    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)


@dataclass
class MCPProbeResult:
    reachable: bool
    protocol_version: str | None = None
    server_name: str | None = None
    tools: list[MCPTool] = field(default_factory=list)
    raw_initialize_response: dict[str, Any] | None = None
    transport_notes: list[str] = field(default_factory=list)
    error: str | None = None


def is_tool_call_success(http_status: int, parsed: dict[str, Any] | None) -> bool:
    """Return true only for a successful HTTP and MCP tool result.

    MCP distinguishes top-level protocol errors from tool execution errors in
    ``result.isError``. Both must be considered failures.
    """

    if not 200 <= http_status < 300 or not isinstance(parsed, dict):
        return False
    if parsed.get("error") is not None:
        return False
    result = parsed.get("result")
    return isinstance(result, dict) and result.get("isError") is not True


class MCPClient:
    def __init__(
        self,
        base_url: str,
        auth_header: str | None = None,
        timeout: float = 15.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.transport = transport
        self.protocol_version: str | None = None
        self.session_id: str | None = None
        self.initialized = False
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if auth_header:
            self.headers["Authorization"] = auth_header

    @staticmethod
    def _rpc_body(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": method,
            "params": params or {},
        }

    @staticmethod
    def _notification_body(
        method: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params:
            body["params"] = params
        return body

    def _request_headers(
        self,
        *,
        subsequent: bool,
        extra_headers: dict[str, str] | None = None,
        omit_authorization: bool = False,
    ) -> dict[str, str]:
        headers = dict(self.headers)
        if omit_authorization:
            headers = {k: v for k, v in headers.items() if k.lower() != "authorization"}
        if subsequent:
            if self.protocol_version:
                headers["MCP-Protocol-Version"] = self.protocol_version
            if self.session_id:
                headers["Mcp-Session-Id"] = self.session_id
        if extra_headers:
            headers.update(extra_headers)
        return headers

    async def _post(
        self,
        client: httpx.AsyncClient,
        body: dict[str, Any],
        *,
        subsequent: bool = True,
        headers: dict[str, str] | None = None,
        omit_authorization: bool = False,
    ) -> httpx.Response:
        return await client.post(
            self.base_url,
            json=body,
            headers=self._request_headers(
                subsequent=subsequent,
                extra_headers=headers,
                omit_authorization=omit_authorization,
            ),
            timeout=self.timeout,
        )

    @staticmethod
    def _select_message(payload: Any, request_id: str | int | None) -> dict[str, Any]:
        messages = payload if isinstance(payload, list) else [payload]
        candidates = [message for message in messages if isinstance(message, dict)]
        if request_id is None:
            if not candidates:
                raise MCPClientError("Response did not contain a JSON-RPC object")
            return candidates[0]
        for message in candidates:
            if message.get("id") == request_id:
                return message
        raise MCPClientError(f"Response did not contain JSON-RPC id {request_id!r}")

    @staticmethod
    def _parse_json_or_sse(
        resp: httpx.Response, request_id: str | int | None = None
    ) -> dict[str, Any]:
        """Parse JSON or SSE and select the response matching ``request_id``."""

        content_type = resp.headers.get("content-type", "").lower()
        if "text/event-stream" not in content_type:
            try:
                return MCPClient._select_message(resp.json(), request_id)
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
                raise MCPClientError(f"Invalid JSON response: {exc}") from exc

        data_lines: list[str] = []
        events: list[str] = []

        def finish_event() -> None:
            if data_lines:
                events.append("\n".join(data_lines))
                data_lines.clear()

        for line in resp.text.splitlines():
            if not line:
                finish_event()
            elif line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
        finish_event()

        if not events:
            raise MCPClientError("SSE response contained no data events")

        parse_errors: list[str] = []
        for event_data in events:
            if event_data == "[DONE]":
                continue
            try:
                payload = json.loads(event_data)
            except json.JSONDecodeError as exc:
                parse_errors.append(str(exc))
                continue
            try:
                return MCPClient._select_message(payload, request_id)
            except MCPClientError:
                continue

        if request_id is not None:
            raise MCPClientError(
                f"SSE response contained no JSON-RPC response matching id {request_id!r}"
            )
        detail = f": {parse_errors[0]}" if parse_errors else ""
        raise MCPClientError(f"SSE response contained no JSON-RPC object{detail}")

    @staticmethod
    def _result_or_raise(message: dict[str, Any], operation: str) -> dict[str, Any]:
        error = message.get("error")
        if error is not None:
            if isinstance(error, dict):
                code = error.get("code")
                raw_message = error.get("message", "Unknown protocol error")
            else:
                code = None
                raw_message = "Malformed JSON-RPC error"
            raise MCPProtocolError(code if isinstance(code, int) else None, str(raw_message))
        result = message.get("result")
        if not isinstance(result, dict):
            raise MCPClientError(f"{operation} response did not contain an object result")
        return result

    async def initialize(self, client: httpx.AsyncClient) -> dict[str, Any]:
        """Establish the MCP session and send ``notifications/initialized``."""

        init_body = self._rpc_body(
            "initialize",
            {
                "protocolVersion": LATEST_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mcp-security-scanner", "version": "0.2"},
            },
        )
        init_resp = await self._post(client, init_body, subsequent=False)
        if not 200 <= init_resp.status_code < 300:
            raise MCPClientError(f"initialize returned HTTP {init_resp.status_code}")

        init_json = self._parse_json_or_sse(init_resp, init_body["id"])
        init_result = self._result_or_raise(init_json, "initialize")
        negotiated_version = init_result.get("protocolVersion")
        if not isinstance(negotiated_version, str) or not negotiated_version:
            raise MCPClientError("initialize result omitted protocolVersion")

        self.protocol_version = negotiated_version
        self.session_id = init_resp.headers.get("Mcp-Session-Id") or None

        initialized_resp = await self._post(
            client,
            self._notification_body("notifications/initialized"),
            subsequent=True,
        )
        if not 200 <= initialized_resp.status_code < 300:
            raise MCPClientError(
                f"notifications/initialized returned HTTP {initialized_resp.status_code}"
            )
        self.initialized = True
        return init_json

    async def list_tools(self, client: httpx.AsyncClient) -> list[MCPTool]:
        """List all tools, following opaque ``nextCursor`` values."""

        tools: list[MCPTool] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()

        while True:
            params = {"cursor": cursor} if cursor is not None else {}
            list_body = self._rpc_body("tools/list", params)
            list_resp = await self._post(client, list_body, subsequent=True)
            if not 200 <= list_resp.status_code < 300:
                raise MCPClientError(f"tools/list returned HTTP {list_resp.status_code}")

            list_json = self._parse_json_or_sse(list_resp, list_body["id"])
            page = self._result_or_raise(list_json, "tools/list")
            raw_tools = page.get("tools", [])
            if not isinstance(raw_tools, list):
                raise MCPClientError("tools/list result contained a non-array tools value")

            for raw_tool in raw_tools:
                if not isinstance(raw_tool, dict):
                    continue
                schema = raw_tool.get("inputSchema")
                tools.append(
                    MCPTool(
                        name=str(raw_tool.get("name", "<unnamed>")),
                        description=str(raw_tool.get("description", "") or ""),
                        input_schema=schema if isinstance(schema, dict) else {},
                    )
                )

            next_cursor = page.get("nextCursor")
            if not isinstance(next_cursor, str) or not next_cursor:
                break
            if next_cursor in seen_cursors:
                raise MCPClientError("tools/list returned a repeated nextCursor")
            seen_cursors.add(next_cursor)
            cursor = next_cursor

        return tools

    async def probe(self) -> MCPProbeResult:
        result = MCPProbeResult(reachable=False)
        try:
            async with httpx.AsyncClient(
                follow_redirects=True, transport=self.transport
            ) as client:
                try:
                    init_json = await self.initialize(client)
                    result.reachable = True
                    result.raw_initialize_response = init_json
                    init_result = init_json["result"]
                    server_info = init_result.get("serverInfo", {})
                    if isinstance(server_info, dict):
                        server_name = server_info.get("name")
                        result.server_name = str(server_name) if server_name else None
                    result.protocol_version = self.protocol_version
                except MCPClientError as exc:
                    result.reachable = True
                    result.error = str(exc)
                    return result

                try:
                    result.tools = await self.list_tools(client)
                except MCPClientError as exc:
                    result.error = str(exc)
                return result

        except httpx.RequestError as exc:
            result.error = f"Connection failed: {type(exc).__name__}"
            return result
        except Exception as exc:  # noqa: BLE001
            result.error = f"Unexpected error: {exc}"
            return result

    async def call_tool(
        self,
        client: httpx.AsyncClient,
        tool_name: str,
        arguments: dict[str, Any],
        headers: dict[str, str] | None = None,
        *,
        omit_authorization: bool = False,
    ) -> tuple[int, dict[str, Any] | None, str | None]:
        """Return ``(HTTP status, parsed JSON-RPC response, short raw text)``."""

        body = self._rpc_body("tools/call", {"name": tool_name, "arguments": arguments})
        try:
            resp = await self._post(
                client,
                body,
                subsequent=True,
                headers=headers,
                omit_authorization=omit_authorization,
            )
            try:
                parsed = self._parse_json_or_sse(resp, body["id"])
            except MCPClientError:
                parsed = None
            return resp.status_code, parsed, resp.text[:500]
        except httpx.RequestError as exc:
            return -1, None, str(exc)
