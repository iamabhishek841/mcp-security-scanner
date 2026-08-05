from __future__ import annotations

import asyncio
import threading

from examples.mock_mcp_server import create_server
from src.checks.dynamic_checks import run_dynamic_checks
from src.checks.static_checks import run_static_checks
from src.mcp_client import MCPClient


def test_safe_demo_server_end_to_end() -> None:
    server = create_server(port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        endpoint = f"http://127.0.0.1:{server.server_port}/mcp"
        client = MCPClient(endpoint, auth_header="Bearer demo-only")
        probe = asyncio.run(client.probe())
        assert probe.reachable
        assert probe.error is None
        assert probe.server_name == "safe-vulnerable-demo"
        assert probe.protocol_version == "2025-06-18"
        assert [tool.name for tool in probe.tools] == [
            "fetch_preview",
            "credential_status",
            "format_record",
        ]

        static = run_static_checks(probe.tools)
        assert static.tools_with_secrets == 1
        assert static.tools_with_injection_risk == 1
        assert static.tools_with_ssrf_prone_params == 1
        assert static.tools_with_poor_schema == 1

        dynamic = asyncio.run(
            run_dynamic_checks(
                client,
                probe.tools,
                authorized_to_test=True,
                dynamic_tool_allowlist=[tool.name for tool in probe.tools],
                probe_url="https://controlled.example.test/callback",
                also_test_unauth=True,
            )
        )
        assert dynamic.tools_tested == 3
        assert dynamic.ssrf_suspicious_tools == 1
        assert dynamic.stack_trace_leaks == 1
        assert dynamic.unauth_comparison_performed
        assert dynamic.unauth_accessible_tools == 3
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
