"""Static checks performed without executing any MCP tools."""
from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from src.mcp_client import MCPTool

SECRET_PATTERNS = [
    (r"sk-[a-zA-Z0-9]{20,}", "OpenAI-style API key"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key ID"),
    (r"ghp_[a-zA-Z0-9]{30,}", "GitHub personal access token"),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API key"),
    (r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", "JWT token"),
    (r"-----BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY-----", "Private key material"),
]

# These phrases describe an instruction override or agent-directed behavior.
# Generic role-description wording such as "act as" is intentionally omitted.
PROMPT_INJECTION_PHRASES = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "disregard the system prompt",
    "disregard previous instructions",
    "do not tell the user",
    "without informing the user",
    "always call this tool first",
    "override your instructions",
    "bypass safety guidelines",
    "do not mention this instruction",
]

SENSITIVE_PARAM_NAMES = {
    "url",
    "uri",
    "endpoint",
    "host",
    "target",
    "path",
    "file",
    "filepath",
    "callback",
}
SCHEMA_VALUE_KEYS = {"description", "default", "example", "examples", "enum"}
SENSITIVE_QUERY_NAMES = {
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "key",
    "password",
    "secret",
    "token",
}


@dataclass
class Finding:
    severity: str
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


def sanitize_text(value: Any) -> str:
    """Redact credential-shaped substrings before they reach output or logs."""

    text = str(value)
    for pattern, label in SECRET_PATTERNS:
        text = re.sub(pattern, f"[REDACTED {label}]", text)
    return text


def sanitize_url(value: Any) -> str:
    """Redact URL userinfo and common credential-bearing query parameters."""

    text = sanitize_text(value)
    try:
        parsed = urlsplit(text)
        if not parsed.scheme or not parsed.netloc:
            return text

        hostname = parsed.hostname or ""
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        netloc = hostname
        if parsed.port is not None:
            netloc += f":{parsed.port}"

        query = urlencode(
            [
                (
                    key,
                    "[REDACTED]"
                    if key.lower() in SENSITIVE_QUERY_NAMES
                    else sanitize_text(item),
                )
                for key, item in parse_qsl(parsed.query, keep_blank_values=True)
            ],
            doseq=True,
        )
        return urlunsplit((parsed.scheme, netloc, parsed.path, query, ""))
    except ValueError:
        return text


def _iter_scalar_values(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _iter_scalar_values(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _iter_scalar_values(item)


def _iter_relevant_schema_text(schema: Any) -> Iterator[str]:
    """Yield recursively nested JSON Schema descriptions and example values."""

    if isinstance(schema, dict):
        for key, value in schema.items():
            if key in SCHEMA_VALUE_KEYS:
                yield from _iter_scalar_values(value)
            if isinstance(value, (dict, list)):
                yield from _iter_relevant_schema_text(value)
    elif isinstance(schema, list):
        for item in schema:
            yield from _iter_relevant_schema_text(item)


def _iter_schema_properties(
    schema: Any, prefix: str = ""
) -> Iterator[tuple[str, str, Any]]:
    """Yield ``(leaf name, dotted path, property schema)`` recursively."""

    if isinstance(schema, dict):
        properties = schema.get("properties", {})
        if isinstance(properties, dict):
            for name, property_schema in properties.items():
                path = f"{prefix}.{name}" if prefix else str(name)
                yield str(name), path, property_schema
                yield from _iter_schema_properties(property_schema, path)

        items = schema.get("items")
        if isinstance(items, (dict, list)):
            item_prefix = f"{prefix}[]" if prefix else "[]"
            yield from _iter_schema_properties(items, item_prefix)

        for keyword in ("allOf", "anyOf", "oneOf", "$defs", "definitions"):
            nested = schema.get(keyword)
            if isinstance(nested, (dict, list)):
                yield from _iter_schema_properties(nested, prefix)
    elif isinstance(schema, list):
        for item in schema:
            yield from _iter_schema_properties(item, prefix)


def _scan_text_for_secrets(texts: Iterator[str], tool_name: str, findings: list[Finding]) -> bool:
    found_labels: set[str] = set()
    safe_tool_name = sanitize_text(tool_name)
    for text in texts:
        for pattern, label in SECRET_PATTERNS:
            if label not in found_labels and re.search(pattern, text):
                findings.append(
                    Finding(
                        severity="critical",
                        category="secret_leak",
                        tool=safe_tool_name,
                        message=f"Possible {label} found embedded in tool metadata.",
                    )
                )
                found_labels.add(label)
    return bool(found_labels)


def _scan_text_for_injection(text: str, tool_name: str, findings: list[Finding]) -> bool:
    lowered = text.lower()
    matched = [phrase for phrase in PROMPT_INJECTION_PHRASES if phrase in lowered]
    for phrase in matched:
        findings.append(
            Finding(
                severity="high",
                category="prompt_injection_risk",
                tool=sanitize_text(tool_name),
                message=(
                    "Tool description contains agent-directed instruction language: "
                    f"'{phrase}'."
                ),
            )
        )
    return bool(matched)


def _scan_schema_params(tool: MCPTool, findings: list[Finding]) -> bool:
    found_any = False
    seen_paths: set[str] = set()
    for param_name, path, _ in _iter_schema_properties(tool.input_schema or {}):
        if param_name.lower() not in SENSITIVE_PARAM_NAMES or path in seen_paths:
            continue
        findings.append(
            Finding(
                severity="medium",
                category="ssrf_prone_param",
                tool=sanitize_text(tool.name),
                message=(
                    f"Parameter '{sanitize_text(path)}' accepts a URL/path-like value. "
                    "If unvalidated server-side, this can enable SSRF or path traversal."
                ),
            )
        )
        seen_paths.add(path)
        found_any = True
    return found_any


def _has_type_contract(schema: Any) -> bool:
    if not isinstance(schema, dict):
        return False
    return any(
        keyword in schema
        for keyword in ("type", "$ref", "enum", "const", "oneOf", "anyOf", "allOf")
    )


def _check_schema_quality(tool: MCPTool, findings: list[Finding]) -> bool:
    poor = False
    safe_tool_name = sanitize_text(tool.name)
    if not tool.description or len(tool.description.strip()) < 10:
        findings.append(
            Finding(
                severity="low",
                category="schema_quality",
                tool=safe_tool_name,
                message="Tool has little or no description, making agent use less reliable.",
            )
        )
        poor = True

    if not isinstance(tool.input_schema, dict) or not tool.input_schema:
        findings.append(
            Finding(
                severity="low",
                category="schema_quality",
                tool=safe_tool_name,
                message="Tool has no usable input schema.",
            )
        )
        return True

    for _, path, property_schema in _iter_schema_properties(tool.input_schema):
        if not _has_type_contract(property_schema):
            findings.append(
                Finding(
                    severity="low",
                    category="schema_quality",
                    tool=safe_tool_name,
                    message=(
                        f"Parameter '{sanitize_text(path)}' has no declared type or equivalent "
                        "schema contract."
                    ),
                )
            )
            poor = True
    return poor


def run_static_checks(tools: list[MCPTool]) -> StaticCheckReport:
    report = StaticCheckReport()
    for tool in tools:
        secret_texts = iter(
            [tool.name, tool.description, *_iter_relevant_schema_text(tool.input_schema)]
        )
        if _scan_text_for_secrets(secret_texts, tool.name, report.findings):
            report.tools_with_secrets += 1

        injection_text = " ".join(
            [tool.description, *_iter_relevant_schema_text(tool.input_schema)]
        )
        if _scan_text_for_injection(injection_text, tool.name, report.findings):
            report.tools_with_injection_risk += 1

        if _scan_schema_params(tool, report.findings):
            report.tools_with_ssrf_prone_params += 1

        if _check_schema_quality(tool, report.findings):
            report.tools_with_poor_schema += 1

    return report
