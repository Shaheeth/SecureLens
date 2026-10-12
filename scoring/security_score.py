"""
Security scoring engine.

Produces a 0-100 security score from a list of Findings using a weighted
deduction model, then clamps and grades it. Deliberately simple and
explainable (a portfolio/interview reviewer should be able to follow the
math), rather than a black-box ML score.
"""
from __future__ import annotations

from backend.models import Finding, Severity

# Base point deduction per finding, scaled by confidence.
_SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 12,
    Severity.MEDIUM: 6,
    Severity.LOW: 2,
    Severity.INFO: 0.5,
}

# Diminishing returns: after N findings of the same severity, further ones
# count less, so 50 "Low" findings don't unrealistically zero out the score.
_DIMINISHING_FACTOR = 0.85


def calculate_security_score(findings: list[Finding]) -> float:
    if not findings:
        return 100.0

    by_severity: dict[Severity, list[Finding]] = {}
    for f in findings:
        by_severity.setdefault(f.severity, []).append(f)

    total_deduction = 0.0
    for severity, items in by_severity.items():
        base_weight = _SEVERITY_WEIGHTS.get(severity, 3)
        for i, finding in enumerate(items):
            decay = _DIMINISHING_FACTOR ** i
            total_deduction += base_weight * finding.confidence * decay

    score = max(0.0, 100.0 - total_deduction)
    return round(score, 1)


def severity_counts(findings: list[Finding]) -> dict:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        key = f.severity.value if hasattr(f.severity, "value") else f.severity
        counts[key] = counts.get(key, 0) + 1
    return counts


def grade_for_score(score: float) -> str:
    if score >= 90:
        return "A (Excellent)"
    if score >= 75:
        return "B (Good)"
    if score >= 60:
        return "C (Needs Improvement)"
    if score >= 40:
        return "D (Poor)"
    return "F (Critical Risk)"


def category_breakdown(findings: list[Finding]) -> dict:
    counts: dict = {}
    for f in findings:
        key = f.category.value if hasattr(f.category, "value") else f.category
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True))
