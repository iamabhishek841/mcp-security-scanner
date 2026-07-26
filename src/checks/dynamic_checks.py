"""
Dynamic checks: live test calls against the target MCP server.

These are intentionally conservative, non-destructive probes — the goal
is to observe BEHAVIOR (does it follow an internal URL, does it respond
without auth, does it leak a stack trace) not to exploit anything.

IMPORTANT: only run this against servers you own or are explicitly
authorized to test. Treat this the same as any other security scanner —
scanning third-party infrastructure without permission may be against
that provider's terms of service or the law in your jurisdiction.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx

from src.checks.static_checks import Finding, SENSITIVE_PARAM_NAMES
from src.mcp_client import MCPClient, MCPTool

# Benign, well-known "canary" targets used across the security industry to
# detect SSRF without touching anything sensitive.
SSRF_PROBE_URLS = [
    "http://169.254.169.254/latest/meta-data/",  # cloud metadata endpoint
    "http://localhost:22",
    "http://127.0.0.1:6379",  # common redis default port
]

STACK_TRACE_MARKERS = [
    "Traceback (most recent call last)",
    "at java.",
    "System.Exception",
    "  File \"",
    "node_modules",
    "NullPointerException",
]


@dataclass
class DynamicCheckReport:
    findings: list[Finding] = field(default_factory=list)
    tools_tested: int = 0
    ssrf_suspicious_tools: int = 0
    unauth_accessible_tools: int = 0
    stack_trace_leaks: int = 0


def _find_sensitive_params(tool: MCPTool) -> list[str]:
    props = (tool.input_schema or {}).get("properties", {})
    return [p for p in props if p.lower() in SENSITIVE_PARAM_NAMES]


def _build_malformed_args(tool: MCPTool) -> dict:
    """Build an arguments dict that violates the declared schema slightly
    (wrong types / oversized strings) to see how gracefully the server fails."""
    props = (tool.input_schema or {}).get("properties", {})
    args = {}
    for pname, pschema in props.items():
        ptype = (pschema or {}).get("type", "string")
        if ptype == "string":
            args[pname] = "A" * 5000  # oversized string
        elif ptype in ("number", "integer"):
            args[pname] = "not_a_number"  # wrong type
        elif ptype == "boolean":
            args[pname] = "maybe"
        elif ptype == "array":
            args[pname] = "not_an_array"
        else:
            args[pname] = None
    return args


async def run_dynamic_checks(
    client_wrapper: MCPClient,
    tools: list[MCPTool],
    max_tools: int = 10,
    also_test_unauth: bool = False,
) -> DynamicCheckReport:
    report = DynamicCheckReport()
    tools_subset = tools[:max_tools]

    async with httpx.AsyncClient(follow_redirects=False) as http_client:
        for tool in tools_subset:
            report.tools_tested += 1

            # --- 1. SSRF probe (only if tool has a URL-like param) ---
            sensitive_params = _find_sensitive_params(tool)
            if sensitive_params:
                for probe_url in SSRF_PROBE_URLS[:1]:  # keep it light: one probe per tool
                    args = {p: probe_url for p in sensitive_params}
                    status, parsed, raw = await client_wrapper.call_tool(http_client, tool.name, args)
                    if status == 200 and parsed and "error" not in parsed:
                        report.findings.append(
                            Finding(
                                severity="high",
                                category="ssrf_confirmed_or_unclear",
                                tool=tool.name,
                                message=(
                                    f"Tool accepted an internal/metadata URL ({probe_url}) as input "
                                    "and returned 200 without a validation error. Manually verify "
                                    "whether the server actually fetched it (possible SSRF)."
                                ),
                            )
                        )
                        report.ssrf_suspicious_tools += 1

            # --- 2. Malformed input / error leakage ---
            malformed_args = _build_malformed_args(tool)
            if malformed_args:
                status, parsed, raw = await client_wrapper.call_tool(
                    http_client, tool.name, malformed_args
                )
                text_blob = raw or ""
                for marker in STACK_TRACE_MARKERS:
                    if marker in text_blob:
                        report.findings.append(
                            Finding(
                                severity="medium",
                                category="error_leakage",
                                tool=tool.name,
                                message=(
                                    "Malformed input triggered what looks like a raw stack trace "
                                    "in the response — this can leak internal paths/framework details."
                                ),
                            )
                        )
                        report.stack_trace_leaks += 1
                        break

            # --- 3. Unauthenticated access check ---
            if also_test_unauth:
                no_auth_headers = {
                    k: v for k, v in client_wrapper.headers.items() if k.lower() != "authorization"
                }
                status, parsed, raw = await client_wrapper.call_tool(
                    http_client, tool.name, {}, headers=no_auth_headers
                )
                if status == 200 and parsed and "error" not in parsed:
                    report.findings.append(
                        Finding(
                            severity="high",
                            category="missing_auth",
                            tool=tool.name,
                            message=(
                                "Tool responded successfully WITHOUT an Authorization header, "
                                "even though one was supplied for this scan. Verify this tool "
                                "doesn't require auth by design."
                            ),
                        )
                    )
                    report.unauth_accessible_tools += 1

    return report
