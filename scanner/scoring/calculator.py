"""
Scoring calculator - computes security_score and optimization_score.

Formula:
  penalty = sum(weight[severity] x confidence per finding)
  size    = max(files analysed, SIZE_FLOOR)
  score   = 100 x exp(-penalty / (size x DENSITY_SCALE))

Weight table (heuristic):
  CRITICAL  20 pts
  HIGH      10 pts
  MEDIUM     5 pts
  LOW        2 pts
  INFO       0 pts

Security score    : all findings except category="performance"
Optimization score: only category="performance" findings

Scores are 0-100 (100 = no issues detected). They fall towards 0 but never below it (a score
only reads 0.0 once it rounds to that, e.g. 50 HIGH findings in a small scan).

Why a density and a curve, not "100 - penalty" clamped at 0: scans of eight real repositories
showed the old score hit 0 for Django (5,650 files, 3,415 penalty points) just like it did for
deliberately vulnerable apps, so it could not tell them apart. Penalty per analysed file did:
mature projects sit at 0.25-0.6, intentionally vulnerable ones at 1.5-2.0. The exponential keeps
the score informative at any size (each unit of density removes the same share of what is left)
and is close to the old "100 - penalty" for small penalties.

  with 50+ files          flask 0.28/file -> 70    django 0.60 -> 47    NodeGoat 1.91 -> 9
  fewer than 50 files     size counts as 50, so one HIGH finding ~ 78, two ~ 61

Calibration is still heuristic: DENSITY_SCALE and SIZE_FLOOR were chosen so that those eight
repositories (four mature, one clean sample, three intentionally vulnerable) land in sensible
bands, which makes them a fit to the data, not an independent test. Files analysed is only a rough
measure of size; lines of code would be better. Scores from earlier versions are not comparable
(the history delta across the upgrade is meaningless).
"""
from __future__ import annotations

import math

from scanner.models.finding import Finding, Severity

# heuristic severity weights
_SECURITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 20.0,
    Severity.HIGH:     10.0,
    Severity.MEDIUM:    5.0,
    Severity.LOW:       2.0,
    Severity.INFO:      0.0,
}

BASE_SCORE: float = 100.0
SIZE_FLOOR: int = 50          # a scan of fewer files is treated as this many
DENSITY_SCALE: float = 0.8    # penalty points per file at which the score falls to 1/e (37)


def _score(penalty: float, files_analyzed: int | None) -> float:
    size = max(files_analyzed or 0, SIZE_FLOOR)
    return round(BASE_SCORE * math.exp(-penalty / (size * DENSITY_SCALE)), 1)


def security_score(findings: list[Finding], files_analyzed: int | None = None) -> float:
    """
    Compute the security score (0-100) from all findings except category='performance'.

    Pass the number of files analysed so large projects are judged by density; without it the
    scan is treated as SIZE_FLOOR files.
    """
    penalty = sum(
        _SECURITY_WEIGHTS.get(f.severity, 0.0) * f.confidence
        for f in findings
        if f.category != "performance"
    )
    return _score(penalty, files_analyzed)


def optimization_score(findings: list[Finding], files_analyzed: int | None = None) -> float:
    """Compute the optimization score (0-100) from category='performance' findings only."""
    penalty = sum(
        _SECURITY_WEIGHTS.get(f.severity, 0.0) * f.confidence
        for f in findings
        if f.category == "performance"
    )
    return _score(penalty, files_analyzed)


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
    """Hex colour for a score in the HTML report: the web UI's Night status scale (good, warning,
    serious, critical) with the same bands as ui/src/lib/score.js. Always shown next to a label."""
    if score >= 75:
        return "#5ac576"   # good
    if score >= 55:
        return "#eec651"   # warning
    if score >= 30:
        return "#f28e42"   # serious
    return "#ff645f"       # critical
