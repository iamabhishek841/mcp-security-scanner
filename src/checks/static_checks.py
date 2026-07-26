"""
Static checks: everything we can evaluate WITHOUT calling the server,
just by inspecting the tool schemas returned by tools/list.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from src.mcp_client import MCPTool

# Patterns that suggest a secret/credential leaked into a tool description
# or a default/example value in its schema.
SECRET_PATTERNS = [
    (r"sk-[a-zA-Z0-9]{20,}", "OpenAI-style API key"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key ID"),
    (r"ghp_[a-zA-Z0-9]{30,}", "GitHub personal access token"),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API key"),
    (r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", "JWT token"),
    (r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----", "Private key material"),
]

# Phrases that suggest a tool description is trying to instruct the AGENT
# (prompt injection) rather than just describing what the tool does.
PROMPT_INJECTION_PHRASES = [
    "ignore previous instructions",
    "ignore all previous",
    "disregard the system prompt",
    "you must always",
    "do not tell the user",
    "without informing the user",
    "always call this tool first",
    "never refuse",
    "this overrides",
    "act as",
    "do not mention this instruction",
]

SENSITIVE_PARAM_NAMES = {"url", "uri", "endpoint", "host", "target", "path", "file", "filepath", "callback"}


@dataclass
class Finding:
    severity: str  # "critical" | "high" | "medium" | "low" | "info"
    category: str
    tool: str | None
    message: str


@dataclass
class StaticCheckReport:
    findings: list[Finding] = field(default_factory=list)
    tools_with_secrets: int = 0
    tools_with_injection_risk: int = 0
    tools_with_ssrf_prone_params: int = 0
    tools_with_poor_schema: int = 0


def _scan_text_for_secrets(text: str, tool_name: str, findings: list[Finding]) -> bool:
    found_any = False
    for pattern, label in SECRET_PATTERNS:
        if re.search(pattern, text):
            findings.append(
                Finding(
                    severity="critical",
                    category="secret_leak",
                    tool=tool_name,
                    message=f"Possible {label} found embedded in tool metadata.",
                )
            )
            found_any = True
    return found_any


def _scan_text_for_injection(text: str, tool_name: str, findings: list[Finding]) -> bool:
    lowered = text.lower()
    found_any = False
    for phrase in PROMPT_INJECTION_PHRASES:
        if phrase in lowered:
            findings.append(
                Finding(
                    severity="high",
                    category="prompt_injection_risk",
                    tool=tool_name,
                    message=f"Tool description contains agent-directed instruction language: '{phrase}'.",
                )
            )
            found_any = True
    return found_any


def _scan_schema_params(tool: MCPTool, findings: list[Finding]) -> bool:
    props = (tool.input_schema or {}).get("properties", {})
    found_any = False
    for param_name in props:
        if param_name.lower() in SENSITIVE_PARAM_NAMES:
            findings.append(
                Finding(
                    severity="medium",
                    category="ssrf_prone_param",
                    tool=tool.name,
                    message=(
                        f"Parameter '{param_name}' accepts a URL/path-like value. "
                        "If unvalidated server-side, this can enable SSRF or path traversal."
                    ),
                )
            )
            found_any = True
    return found_any


def _check_schema_quality(tool: MCPTool, findings: list[Finding]) -> bool:
    poor = False
    if not tool.description or len(tool.description.strip()) < 10:
        findings.append(
            Finding(
                severity="low",
                category="schema_quality",
                tool=tool.name,
                message="Tool has little or no description — harder for agents to use safely and correctly.",
            )
        )
        poor = True

    props = (tool.input_schema or {}).get("properties", {})
    for pname, pschema in props.items():
        if not isinstance(pschema, dict) or "type" not in pschema:
            findings.append(
                Finding(
                    severity="low",
                    category="schema_quality",
                    tool=tool.name,
                    message=f"Parameter '{pname}' has no declared type — ambiguous input contract.",
                )
            )
            poor = True
    return poor


def run_static_checks(tools: list[MCPTool]) -> StaticCheckReport:
    report = StaticCheckReport()
    for tool in tools:
        combined_text = f"{tool.name} {tool.description}"

        if _scan_text_for_secrets(combined_text, tool.name, report.findings):
            report.tools_with_secrets += 1

        if _scan_text_for_injection(combined_text, tool.name, report.findings):
            report.tools_with_injection_risk += 1

        if _scan_schema_params(tool, report.findings):
            report.tools_with_ssrf_prone_params += 1

        if _check_schema_quality(tool, report.findings):
            report.tools_with_poor_schema += 1

    return report
