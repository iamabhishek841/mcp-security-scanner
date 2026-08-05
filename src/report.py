from __future__ import annotations

import datetime as dt
import html
import re
from typing import Any

from src.checks.dynamic_checks import DynamicCheckReport
from src.checks.scoring import ScoreResult
from src.checks.static_checks import (
    StaticCheckReport,
    sanitize_single_line,
    sanitize_url,
)
from src.mcp_client import MCPProbeResult

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
MARKDOWN_PUNCTUATION = re.compile(r"([\\`*_{}\[\]()#+\-.!|>~])")


def _markdown_code_span(value: Any) -> str:
    """Put untrusted single-line text in a non-breakable Markdown code span."""

    text = sanitize_single_line(value)
    longest_run = max(
        (len(match.group(0)) for match in re.finditer(r"`+", text)),
        default=0,
    )
    delimiter = "`" * (longest_run + 1)
    return f"{delimiter} {text} {delimiter}"


def _markdown_inline_text(value: Any) -> str:
    """Escape untrusted text so it cannot create Markdown or raw HTML."""

    text = html.escape(sanitize_single_line(value), quote=False)
    return MARKDOWN_PUNCTUATION.sub(r"\\\1", text)


def _default_limitations(
    dynamic_report: DynamicCheckReport | None, auth_header_supplied: bool
) -> list[str]:
    limitations = [
        "Findings are heuristic and may include false positives or false negatives.",
        "The scanner does not inspect server source code or downstream systems.",
        "A successful tool response does not prove that a supplied callback URL was fetched.",
    ]
    if dynamic_report is None:
        limitations.append(
            "No tools were executed; authentication, callback handling, and error behavior "
            "were not tested."
        )
    elif not auth_header_supplied:
        limitations.append(
            "No Authorization header was supplied, so an unauthenticated comparison was not run."
        )
    if dynamic_report:
        limitations.extend(dynamic_report.limitations)
    return list(dict.fromkeys(limitations))


def build_report_dict(
    server_url: str,
    probe: MCPProbeResult,
    static_report: StaticCheckReport,
    dynamic_report: DynamicCheckReport | None,
    score: ScoreResult,
    *,
    dynamic_tool_allowlist: list[str] | None = None,
    auth_header_supplied: bool = False,
) -> dict[str, Any]:
    all_findings = list(static_report.findings)
    if dynamic_report:
        all_findings += dynamic_report.findings
    all_findings.sort(key=lambda finding: SEVERITY_ORDER.get(finding.severity, 9))

    raw_allowlist = (
        dynamic_report.dynamic_tool_allowlist
        if dynamic_report
        else (dynamic_tool_allowlist or [])
    )
    allowlist = [sanitize_single_line(name) for name in raw_allowlist]
    limitations = _default_limitations(dynamic_report, auth_header_supplied)

    return {
        "scanned_at": dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z"),
        "server_url": sanitize_url(server_url),
        "server_name": (
            sanitize_single_line(probe.server_name) if probe.server_name else None
        ),
        "protocol_version": (
            sanitize_single_line(probe.protocol_version)
            if probe.protocol_version
            else None
        ),
        "reachable": probe.reachable,
        "tool_count": len(probe.tools),
        "score": score.score,
        "grade": score.grade,
        "scan_mode": "static_and_dynamic" if dynamic_report else "static",
        "tools_tested_dynamically": (
            [sanitize_single_line(name) for name in dynamic_report.tools_tested_names]
            if dynamic_report
            else []
        ),
        "dynamic_tool_allowlist": allowlist,
        "controlled_probe_url_used": bool(dynamic_report and dynamic_report.probe_url_used),
        "limitations": [sanitize_single_line(item) for item in limitations],
        "summary": {
            "tools_with_secrets": static_report.tools_with_secrets,
            "tools_with_injection_risk": static_report.tools_with_injection_risk,
            "tools_with_ssrf_prone_params": static_report.tools_with_ssrf_prone_params,
            "tools_with_poor_schema": static_report.tools_with_poor_schema,
            "dynamic_checks_run": dynamic_report is not None,
            "ssrf_suspicious_tools": (
                dynamic_report.ssrf_suspicious_tools if dynamic_report else None
            ),
            "unauth_accessible_tools": (
                dynamic_report.unauth_accessible_tools if dynamic_report else None
            ),
            "stack_trace_leaks": (
                dynamic_report.stack_trace_leaks if dynamic_report else None
            ),
        },
        "findings": [
            {
                "severity": finding.severity,
                "category": finding.category,
                "tool": sanitize_single_line(finding.tool) if finding.tool else None,
                "message": sanitize_single_line(finding.message),
            }
            for finding in all_findings
        ],
    }


def build_markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# MCP Security & Trust Report",
        "",
        f"**Server:** {_markdown_code_span(report['server_url'])}",
    ]
    if report.get("server_name"):
        lines.append(f"**Name:** {_markdown_code_span(report['server_name'])}")
    lines.extend(
        [
            f"**Scanned at:** {_markdown_inline_text(report['scanned_at'])}",
            f"**Tools exposed:** {report['tool_count']}",
            f"**Scan mode:** {_markdown_code_span(report['scan_mode'])}",
            (
                f"**Controlled probe URL used:** "
                f"{'yes' if report['controlled_probe_url_used'] else 'no'}"
            ),
            "",
            (
                f"## Score: {report['score']}/100 (Grade {report['grade']})"
                if report.get("score") is not None
                else "## Score: unavailable (scan incomplete)"
            ),
            "",
        ]
    )

    if not report["reachable"]:
        lines.append("**Server was not reachable; the scan is incomplete.**")
        return "\n".join(lines)

    summary = report["summary"]
    lines.extend(
        [
            "## Execution transparency",
            "",
            "- Dynamic tool allowlist: "
            + (
                ", ".join(
                    _markdown_code_span(name)
                    for name in report["dynamic_tool_allowlist"]
                )
                or "none"
            ),
            "- Tools tested dynamically: "
            + (
                ", ".join(
                    _markdown_code_span(name)
                    for name in report["tools_tested_dynamically"]
                )
                or "none"
            ),
            "",
            "## Summary",
            "",
            f"- Tools with possible secret leaks: **{summary['tools_with_secrets']}**",
            (
                "- Tools with prompt-injection-style language: "
                f"**{summary['tools_with_injection_risk']}**"
            ),
            (
                "- Tools with URL/path risk surfaces: "
                f"**{summary['tools_with_ssrf_prone_params']}**"
            ),
            (
                "- Tools with weak or missing schema documentation: "
                f"**{summary['tools_with_poor_schema']}**"
            ),
        ]
    )
    if summary["dynamic_checks_run"]:
        lines.extend(
            [
                (
                    "- Controlled callback accepted without MCP error: "
                    f"**{summary['ssrf_suspicious_tools']}**"
                ),
                (
                    "- Tools callable in the unauthenticated comparison: "
                    f"**{summary['unauth_accessible_tools']}**"
                ),
                f"- Stack-trace-like responses: **{summary['stack_trace_leaks']}**",
            ]
        )
    else:
        lines.append("- Dynamic checks: **not run**")

    lines.extend(["", "## Findings", ""])
    if not report["findings"]:
        lines.append("No findings.")
    for finding in report["findings"]:
        tool_part = (
            f" ({_markdown_code_span(finding['tool'])})" if finding["tool"] else ""
        )
        lines.append(
            f"- **[{_markdown_inline_text(finding['severity'].upper())}]** "
            f"{_markdown_inline_text(finding['category'])}{tool_part}: "
            f"{_markdown_inline_text(finding['message'])}"
        )

    lines.extend(["", "## Limitations", ""])
    for limitation in report["limitations"]:
        lines.append(f"- {_markdown_inline_text(limitation)}")

    lines.extend(
        [
            "",
            "---",
            (
                "_Generated by MCP Security Scanner. This automated heuristic scan is "
                "not a substitute for manual security review._"
            ),
        ]
    )
    return "\n".join(lines)
