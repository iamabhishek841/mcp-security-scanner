"""
Turns raw findings into a single 0-100 trust score plus a letter grade.

Rubric (matches the weighting discussed for the product):
  Auth handling         25%
  Input validation/SSRF 25%
  Secrets handling       20%
  Schema quality/clarity 15%
  Error hygiene           15%
"""
from __future__ import annotations

from dataclasses import dataclass

from src.checks.dynamic_checks import DynamicCheckReport
from src.checks.static_checks import StaticCheckReport

SEVERITY_PENALTY = {
    "critical": 40,
    "high": 20,
    "medium": 8,
    "low": 2,
    "info": 0,
}

CATEGORY_WEIGHTS = {
    "missing_auth": 0.25,
    "ssrf_prone_param": 0.25,
    "ssrf_confirmed_or_unclear": 0.25,
    "secret_leak": 0.20,
    "prompt_injection_risk": 0.20,
    "schema_quality": 0.15,
    "error_leakage": 0.15,
}


@dataclass
class ScoreResult:
    score: int
    grade: str
    category_scores: dict


def _grade_for(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def compute_score(
    static_report: StaticCheckReport, dynamic_report: DynamicCheckReport | None
) -> ScoreResult:
    all_findings = list(static_report.findings)
    if dynamic_report:
        all_findings += dynamic_report.findings

    # Start at 100, subtract weighted penalties per finding, floor at 0.
    score = 100.0
    category_hits: dict[str, int] = {}

    for f in all_findings:
        weight = CATEGORY_WEIGHTS.get(f.category, 0.10)
        penalty = SEVERITY_PENALTY.get(f.severity, 5) * weight
        score -= penalty
        category_hits[f.category] = category_hits.get(f.category, 0) + 1

    score = max(0, min(100, round(score)))
    return ScoreResult(score=score, grade=_grade_for(score), category_scores=category_hits)
