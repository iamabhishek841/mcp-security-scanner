from __future__ import annotations

import asyncio
import json

import httpx

from src.mcp_client import (
    PREFERRED_PROTOCOL_VERSION,
    SUPPORTED_PROTOCOL_VERSIONS,
    MCPClient,
    MCPClientError,
    is_tool_call_success,
)


def test_supported_protocol_versions_are_explicit_stable_revisions() -> None:
    assert PREFERRED_PROTOCOL_VERSION == "2025-11-25"
    assert SUPPORTED_PROTOCOL_VERSIONS == {
        "2025-11-25",
        "2025-06-18",
        "2025-03-26",
    }


def test_tool_call_success_requires_http_rpc_and_tool_success() -> None:
    success = {"jsonrpc": "2.0", "id": "1", "result": {"isError": False}}
    assert is_tool_call_success(200, success)
    assert is_tool_call_success(204, {"result": {}})
    assert not is_tool_call_success(500, success)
    assert not is_tool_call_success(200, {"error": {"code": -32602}})
    assert not is_tool_call_success(200, {"result": {"isError": True}})
    assert not is_tool_call_success(200, None)


def test_sse_parser_selects_matching_json_rpc_id() -> None:
    response = httpx.Response(
        200,
        headers={"Content-Type": "text/event-stream"},
        text=(
            'event: message\ndata: {"jsonrpc":"2.0","method":"notifications/message"}\n\n'
            'data: {"jsonrpc":"2.0","id":"other","result":{"value":1}}\n\n'
            'data: {"jsonrpc":"2.0","id":"wanted","result":{"value":2}}\n\n'
        ),
    )
    parsed = MCPClient._parse_json_or_sse(response, "wanted")
    assert parsed["result"]["value"] == 2


def test_sse_parser_fails_when_request_id_is_missing() -> None:
    response = httpx.Response(
        200,
        headers={"Content-Type": "text/event-stream"},
        text='data: {"jsonrpc":"2.0","id":"other","result":{}}\n\n',
    )
    try:
        MCPClient._parse_json_or_sse(response, "wanted")
    except MCPClientError as exc:
        assert "matching id" in str(exc)
    else:
        raise AssertionError("Expected MCPClientError")


def test_lifecycle_headers_initialized_notification_and_pagination() -> None:
    requests: list[tuple[dict, httpx.Headers]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        requests.append((body, request.headers))
        if body["method"] == "initialize":
            assert body["params"]["protocolVersion"] == PREFERRED_PROTOCOL_VERSION
            return httpx.Response(
                200,
                headers={"Mcp-Session-Id": "session-123"},
                json={
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "mock", "version": "1"},
                    },
                },
            )
        if body["method"] == "notifications/initialized":
            return httpx.Response(202)
        if body["method"] == "tools/list" and not body["params"]:
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": {
                        "tools": [
                            {
                                "name": "first",
                                "description": "First safe tool",
                                "inputSchema": {"type": "object"},
                            }
                        ],
                        "nextCursor": "opaque-next",
                    },
                },
            )
        assert body["params"] == {"cursor": "opaque-next"}
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": {
                    "tools": [
                        {
                            "name": "second",
                            "description": "Second safe tool",
                            "inputSchema": {"type": "object"},
                        }
                    ]
                },
            },
        )

    client = MCPClient(
        "https://mcp.example.test/mcp",
        auth_header="Bearer test-only",
        transport=httpx.MockTransport(handler),
    )
    probe = asyncio.run(client.probe())

    assert probe.reachable
    assert probe.error is None
    assert probe.protocol_version == "2025-03-26"
    assert [tool.name for tool in probe.tools] == ["first", "second"]
    assert [body["method"] for body, _ in requests] == [
        "initialize",
        "notifications/initialized",
        "tools/list",
        "tools/list",
    ]
    assert "id" not in requests[1][0]
    assert "mcp-session-id" not in requests[0][1]
    assert "mcp-protocol-version" not in requests[0][1]
    for _, headers in requests[1:]:
        assert headers["Mcp-Session-Id"] == "session-123"
        assert headers["MCP-Protocol-Version"] == "2025-03-26"
        assert headers["Authorization"] == "Bearer test-only"
        assert headers["Content-Type"] == "application/json"
        assert "application/json" in headers["Accept"]


def test_initialize_json_rpc_error_is_reported_cleanly() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        body = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": body["id"],
                "error": {"code": -32602, "message": "Unsupported version"},
            },
        )

    client = MCPClient(
        "https://mcp.example.test/mcp", transport=httpx.MockTransport(handler)
    )
    probe = asyncio.run(client.probe())
    assert probe.reachable
    assert probe.error == "JSON-RPC error -32602: Unsupported version"
    assert calls == 1


def test_initialize_accepts_preferred_protocol_version() -> None:
    requests: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        requests.append(body)
        if body["method"] == "initialize":
            assert body["params"]["protocolVersion"] == PREFERRED_PROTOCOL_VERSION
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": {
                        "protocolVersion": PREFERRED_PROTOCOL_VERSION,
                        "capabilities": {"tools": {}},
                    },
                },
            )
        if body["method"] == "notifications/initialized":
            return httpx.Response(202)
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": {"tools": []},
            },
        )

    probe = asyncio.run(
        MCPClient(
            "https://mcp.example.test/mcp",
            transport=httpx.MockTransport(handler),
        ).probe()
    )
    assert probe.error is None
    assert probe.protocol_version == PREFERRED_PROTOCOL_VERSION
    assert [request["method"] for request in requests] == [
        "initialize",
        "notifications/initialized",
        "tools/list",
    ]


def test_initialize_rejects_unsupported_protocol_version() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        body = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": {
                    "protocolVersion": "2099-01-01\r\n# injected",
                    "capabilities": {},
                },
            },
        )

    probe = asyncio.run(
        MCPClient(
            "https://mcp.example.test/mcp",
            transport=httpx.MockTransport(handler),
        ).probe()
    )
    assert probe.reachable
    assert probe.error == "initialize negotiated an unsupported MCP protocol version"
    assert calls == 1
