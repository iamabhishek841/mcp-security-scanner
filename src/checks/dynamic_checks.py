"""Explicitly authorized live checks against an allowlist of MCP tools.

Every tool call can trigger target-side effects. Callers must independently
confirm authorization and provide exact tool names before entering this module.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx

from src.checks.static_checks import (
    SENSITIVE_PARAM_NAMES,
    Finding,
    sanitize_single_line,
)
from src.mcp_client import MCPClient, MCPClientError, MCPTool, is_tool_call_success

STACK_TRACE_MARKERS = [
    "Traceback (most recent call last)",
    "at java.",
    "System.Exception",
    "  File \"",
    "node_modules",
    "NullPointerException",
]


class DynamicChecksAuthorizationError(ValueError):
    """Dynamic checks were requested without the required safety inputs."""


@dataclass
class DynamicCheckReport:
    findings: list[Finding] = field(default_factory=list)
    tools_tested: int = 0
    tools_tested_names: list[str] = field(default_factory=list)
    dynamic_tool_allowlist: list[str] = field(default_factory=list)
    probe_url_used: bool = False
    unauth_comparison_performed: bool = False
    ssrf_suspicious_tools: int = 0
    unauth_accessible_tools: int = 0
    stack_trace_leaks: int = 0
    limitations: list[str] = field(default_factory=list)


def _find_sensitive_params(tool: MCPTool) -> list[str]:
    """Return top-level URL/path-like properties safe to place in call args."""

    props = (tool.input_schema or {}).get("properties", {})
    if not isinstance(props, dict):
        return []
    return [str(name) for name in props if str(name).lower() in SENSITIVE_PARAM_NAMES]


def _build_malformed_args(tool: MCPTool) -> dict[str, Any]:
    props = (tool.input_schema or {}).get("properties", {})
    if not isinstance(props, dict):
        return {}
    args: dict[str, Any] = {}
    for name, schema in props.items():
        schema = schema if isinstance(schema, dict) else {}
        parameter_type = schema.get("type", "string")
        if parameter_type == "string":
            args[str(name)] = "A" * 5000
        elif parameter_type in ("number", "integer"):
            args[str(name)] = "not_a_number"
        elif parameter_type == "boolean":
            args[str(name)] = "maybe"
        elif parameter_type == "array":
            args[str(name)] = "not_an_array"
        else:
            args[str(name)] = None
    return args


def _validate_dynamic_request(
    *, authorized_to_test: bool, dynamic_tool_allowlist: list[str]
) -> None:
    if not authorized_to_test:
        raise DynamicChecksAuthorizationError(
            "Dynamic checks require authorizedToTest=true; no tools were executed."
        )
    if not dynamic_tool_allowlist:
        raise DynamicChecksAuthorizationError(
            "Dynamic checks require a non-empty dynamicToolAllowlist; no tools were executed."
        )


async def run_dynamic_checks(
    client_wrapper: MCPClient,
    tools: list[MCPTool],
    *,
    authorized_to_test: bool,
    dynamic_tool_allowlist: list[str],
    probe_url: str | None = None,
    max_tools: int = 10,
    also_test_unauth: bool = False,
) -> DynamicCheckReport:
    """Run conservative probes only against exact allowlisted tool names."""

    _validate_dynamic_request(
        authorized_to_test=authorized_to_test,
        dynamic_tool_allowlist=dynamic_tool_allowlist,
    )

    normalized_allowlist = list(dict.fromkeys(dynamic_tool_allowlist))
    allowed_names = set(normalized_allowlist)
    selected = [tool for tool in tools if tool.name in allowed_names][:max_tools]
    report = DynamicCheckReport(
        dynamic_tool_allowlist=[
            sanitize_single_line(name) for name in normalized_allowlist
        ],
    )

    missing = [name for name in normalized_allowlist if name not in {tool.name for tool in tools}]
    if missing:
        report.limitations.append(
            "Some allowlisted tool names were not advertised and were not executed: "
            + ", ".join(sanitize_single_line(name) for name in missing)
            + "."
        )
    if len(selected) < len([tool for tool in tools if tool.name in allowed_names]):
        report.limitations.append(
            f"Dynamic execution was capped at maxToolsToTest={max_tools}."
        )
    if not probe_url:
        report.limitations.append(
            "No controlled probe URL was supplied; SSRF behavioral testing was skipped."
        )

    no_auth_client: MCPClient | None = None
    async with httpx.AsyncClient(
        follow_redirects=False, transport=client_wrapper.transport
    ) as http_client:
        if also_test_unauth and selected:
            no_auth_client = MCPClient(
                base_url=client_wrapper.base_url,
                timeout=client_wrapper.timeout,
                transport=client_wrapper.transport,
            )
            try:
                await no_auth_client.initialize(http_client)
                report.unauth_comparison_performed = True
            except MCPClientError as exc:
                report.limitations.append(
                    "Unauthenticated comparison session could not be initialized: "
                    f"{sanitize_single_line(exc)}."
                )
                no_auth_client = None
        elif not also_test_unauth:
            report.limitations.append(
                "No Authorization header was supplied; unauthenticated comparison was skipped."
            )

        for tool in selected:
            safe_tool_name = sanitize_single_line(tool.name)
            report.tools_tested += 1
            report.tools_tested_names.append(safe_tool_name)

            sensitive_params = _find_sensitive_params(tool)
            if probe_url and sensitive_params:
                report.probe_url_used = True
                args = {name: probe_url for name in sensitive_params}
                status, parsed, _ = await client_wrapper.call_tool(
                    http_client, tool.name, args
                )
                if is_tool_call_success(status, parsed):
                    report.findings.append(
                        Finding(
                            severity="high",
                            category="ssrf_confirmed_or_unclear",
                            tool=safe_tool_name,
                            message=(
                                "Tool accepted the explicitly supplied controlled callback URL "
                                "without an MCP error. Confirm callback receipt before treating "
                                "this as SSRF; acceptance alone does not prove a fetch."
                            ),
                        )
                    )
                    report.ssrf_suspicious_tools += 1

            malformed_args = _build_malformed_args(tool)
            if malformed_args:
                _, _, raw = await client_wrapper.call_tool(
                    http_client, tool.name, malformed_args
                )
                text_blob = raw or ""
                if any(marker in text_blob for marker in STACK_TRACE_MARKERS):
                    report.findings.append(
                        Finding(
                            severity="medium",
                            category="error_leakage",
                            tool=safe_tool_name,
                            message=(
                                "Malformed input triggered a response resembling a raw stack "
                                "trace, which can leak internal paths or framework details."
                            ),
                        )
                    )
                    report.stack_trace_leaks += 1

            if no_auth_client is not None:
                status, parsed, _ = await no_auth_client.call_tool(
                    http_client, tool.name, {}
                )
                if is_tool_call_success(status, parsed):
                    report.findings.append(
                        Finding(
                            severity="high",
                            category="missing_auth",
                            tool=safe_tool_name,
                            message=(
                                "Tool call succeeded in a separately initialized session without "
                                "the Authorization header supplied for the authenticated scan. "
                                "Verify whether public access is intentional."
                            ),
                        )
                    )
                    report.unauth_accessible_tools += 1

    if not selected:
        report.limitations.append(
            "No advertised tools matched the exact dynamic allowlist; no tools were executed."
        )
    elif probe_url and not report.probe_url_used:
        report.limitations.append(
            "A controlled probe URL was supplied, but no selected tool had a top-level "
            "URL/path-like parameter; SSRF behavioral testing was skipped."
        )
    return report
