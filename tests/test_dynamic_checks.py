from __future__ import annotations

import asyncio
from typing import Any

import pytest

from src.checks.dynamic_checks import (
    DynamicChecksAuthorizationError,
    run_dynamic_checks,
)
from src.mcp_client import MCPTool


class FakeClient:
    base_url = "https://mcp.example.test/mcp"
    timeout = 1.0
    transport = None

    def __init__(self, *, tool_error: bool = False):
        self.headers: dict[str, str] = {}
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.tool_error = tool_error

    async def call_tool(
        self, _client: Any, tool_name: str, arguments: dict[str, Any], **_: Any
    ) -> tuple[int, dict[str, Any], str]:
        self.calls.append((tool_name, arguments))
        return (
            200,
            {"jsonrpc": "2.0", "result": {"isError": self.tool_error}},
            "safe result",
        )


TOOLS = [
    MCPTool(
        name="allowed",
        description="An allowlisted URL demo tool.",
        input_schema={
            "type": "object",
            "properties": {"url": {"type": "string"}},
        },
    ),
    MCPTool(
        name="blocked",
        description="A tool that must never be called.",
        input_schema={
            "type": "object",
            "properties": {"value": {"type": "string"}},
        },
    ),
]


def test_no_dynamic_execution_without_authorization() -> None:
    client = FakeClient()
    with pytest.raises(DynamicChecksAuthorizationError):
        asyncio.run(
            run_dynamic_checks(
                client,
                TOOLS,
                authorized_to_test=False,
                dynamic_tool_allowlist=["allowed"],
            )
        )
    assert client.calls == []


def test_empty_allowlist_fails_without_execution() -> None:
    client = FakeClient()
    with pytest.raises(DynamicChecksAuthorizationError):
        asyncio.run(
            run_dynamic_checks(
                client,
                TOOLS,
                authorized_to_test=True,
                dynamic_tool_allowlist=[],
            )
        )
    assert client.calls == []


def test_exact_allowlist_is_enforced_and_no_probe_runs_without_probe_url() -> None:
    client = FakeClient()
    report = asyncio.run(
        run_dynamic_checks(
            client,
            TOOLS,
            authorized_to_test=True,
            dynamic_tool_allowlist=["allowed", "missing"],
        )
    )
    assert report.tools_tested_names == ["allowed"]
    assert report.probe_url_used is False
    assert [name for name, _ in client.calls] == ["allowed"]
    assert client.calls[0][1]["url"] == "A" * 5000
    assert all(name != "blocked" for name, _ in client.calls)
    assert report.ssrf_suspicious_tools == 0


def test_result_is_error_is_not_counted_as_successful_probe() -> None:
    client = FakeClient(tool_error=True)
    report = asyncio.run(
        run_dynamic_checks(
            client,
            TOOLS,
            authorized_to_test=True,
            dynamic_tool_allowlist=["allowed"],
            probe_url="https://controlled.example.test/callback",
        )
    )
    assert len(client.calls) == 2
    assert report.probe_url_used is True
    assert report.ssrf_suspicious_tools == 0


def test_supplied_probe_is_not_reported_used_without_url_parameter() -> None:
    client = FakeClient()
    report = asyncio.run(
        run_dynamic_checks(
            client,
            TOOLS,
            authorized_to_test=True,
            dynamic_tool_allowlist=["blocked"],
            probe_url="https://controlled.example.test/callback",
        )
    )
    assert report.probe_url_used is False
    assert [name for name, _ in client.calls] == ["blocked"]
    assert any("was supplied, but" in limitation for limitation in report.limitations)
