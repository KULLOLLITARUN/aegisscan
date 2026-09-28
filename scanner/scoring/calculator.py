"""
Scoring calculator — computes security_score and optimization_score.

Formula (plan §4 V4):
  score = max(0, 100 - sum(weight[severity] × confidence per finding))

Weight table (heuristic — not yet calibrated, revisit after §7 benchmark runs):
  CRITICAL  20 pts
  HIGH      10 pts
  MEDIUM     5 pts
  LOW        2 pts
  INFO       0 pts

Security score   : all findings except category="performance"
Optimization score: only category="performance" findings

Scores are 0–100 (100 = no issues detected). They can go below 0 for
severely vulnerable projects but are clamped at 0.

Design note: these weights are intentionally heuristic starting points.
The numbers were chosen to produce intuitive results on the benchmark
examples (vulnerable_python ≈ 20, clean_project ≈ 95+) but have not
been calibrated against real-world CVE datasets. Do not treat as
scientifically meaningful until V7+ calibration work.
"""
from __future__ import annotations

from scanner.models.finding import Finding, Severity

# heuristic severity weights — not yet calibrated, revisit after §7 benchmark
_SECURITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 20.0,
    Severity.HIGH:     10.0,
    Severity.MEDIUM:    5.0,
    Severity.LOW:       2.0,
    Severity.INFO:      0.0,
}

BASE_SCORE: float = 100.0


def security_score(findings: list[Finding]) -> float:
    """
    Compute the security score (0–100).

    Considers all findings except category='performance'.
    100 = no security issues found.
    """
    penalty = sum(
        _SECURITY_WEIGHTS.get(f.severity, 0.0) * f.confidence
        for f in findings
        if f.category != "performance"
    )
    return max(0.0, round(BASE_SCORE - penalty, 1))


def optimization_score(findings: list[Finding]) -> float:
    """
    Compute the optimization score (0–100).

    Considers only category='performance' findings.
    100 = no performance issues found.
    """
    penalty = sum(
        _SECURITY_WEIGHTS.get(f.severity, 0.0) * f.confidence
        for f in findings
        if f.category == "performance"
    )
    return max(0.0, round(BASE_SCORE - penalty, 1))


def score_label(score: float) -> str:
    """Human-readable label for a score value."""
    if score >= 90:
        return "Excellent"
    if score >= 75:
        return "Good"
    if score >= 55:
        return "Fair"
    if score >= 30:
        return "Poor"
    return "Critical"


def score_color(score: float) -> str:
    """Hex colour for a score — used in HTML report."""
    if score >= 90:
        return "#3fb950"   # green
    if score >= 75:
        return "#79c0ff"   # blue
    if score >= 55:
        return "#f0b429"   # amber
    if score >= 30:
        return "#ff6b35"   # orange
    return "#ff4444"       # red
