"""Tests for V4 scoring calculator and HTML report generator.

Covers:
  - security_score drops correctly based on severity and confidence
  - optimization_score considers only category='performance'
  - score_label and score_color map correctly
  - generate_html produces a non-empty HTML file containing expected elements
"""
from __future__ import annotations

from pathlib import Path

from scanner.models.finding import Finding, Severity
from scanner.models.scan import ScanResult
from scanner.reporting.html_report import generate_html
from scanner.scoring.calculator import (
    SIZE_FLOOR,
    optimization_score,
    score_color,
    score_label,
    security_score,
)


def _finding(
    severity: Severity = Severity.HIGH,
    confidence: float = 1.0,
    category: str = "injection",
) -> Finding:
    return Finding(
        file_path=Path("app.py"),
        issue_type="Test Finding",
        category=category,
        severity=severity,
        confidence=confidence,
        line_start=1,
        line_end=5,
        evidence="code",
        explanation="explanation",
        rule_source="bandit",
    )


def test_security_score_perfect_on_empty() -> None:
    assert security_score([]) == 100.0


def test_optimization_score_perfect_on_empty() -> None:
    assert optimization_score([]) == 100.0


def test_security_score_deductions() -> None:
    # One HIGH (penalty 10) in a small scan (size floor 50, scale 0.8 -> 40): 100 * exp(-10/40)
    f = _finding(severity=Severity.HIGH, confidence=1.0, category="injection")
    assert security_score([f]) == 77.9
    # Close to the old linear "100 - penalty" for a tiny penalty
    low = _finding(severity=Severity.LOW, confidence=0.5, category="injection")   # penalty 1
    assert security_score([low]) == 97.5


def test_optimization_score_filters_category() -> None:
    sec_f = _finding(severity=Severity.CRITICAL, category="injection")
    opt_f = _finding(severity=Severity.HIGH, category="performance")

    assert security_score([sec_f, opt_f]) == 60.7        # 100 * exp(-20/40)
    assert optimization_score([sec_f, opt_f]) == 77.9    # 100 * exp(-10/40)


def test_score_stays_in_range_and_keeps_ordering() -> None:
    few = [_finding(severity=Severity.HIGH) for _ in range(5)]
    more = [_finding(severity=Severity.HIGH) for _ in range(15)]
    many = [_finding(severity=Severity.HIGH) for _ in range(500)]
    assert 0.0 < security_score(more) < security_score(few) < 100.0
    assert 0.0 <= security_score(many) <= security_score(more)


def test_same_findings_score_better_in_a_bigger_project() -> None:
    """Density, not the raw count: 100 medium findings are normal in a 5,000-file codebase."""
    findings = [_finding(severity=Severity.MEDIUM, confidence=0.8) for _ in range(100)]
    small = security_score(findings, 60)
    big = security_score(findings, 5000)
    assert small < 5.0
    assert big > 90.0


def test_small_scans_use_the_size_floor() -> None:
    f = [_finding(severity=Severity.HIGH)]
    assert security_score(f, 1) == security_score(f) == security_score(f, SIZE_FLOOR)
    assert security_score(f, SIZE_FLOOR + 50) > security_score(f)


def test_real_repository_bands() -> None:
    """Penalty and size measured on real scans: mature projects land mid-range, deliberately
    vulnerable ones at the bottom, whatever their size (Django used to score 0 like them)."""
    def score(penalty: float, files: int) -> float:
        n = int(penalty / 5)
        return security_score([_finding(severity=Severity.MEDIUM, confidence=1.0) for _ in range(n)], files)

    assert 55 <= score(65, 231) <= 80          # Flask
    assert 35 <= score(3415, 5650) <= 60       # Django
    assert score(168, 88) < 15                 # NodeGoat (intentionally vulnerable)
    assert score(340, 232) < 25                # DVWA
    assert score(893, 450) < 15                # pygoat
    assert score(3415, 5650) > score(340, 232)


def test_score_labels_and_colors() -> None:
    assert score_label(95) == "Excellent"
    assert score_label(80) == "Good"
    assert score_label(60) == "Fair"
    assert score_label(40) == "Poor"
    assert score_label(10) == "Critical"

    assert score_color(95) == "#3fb950"
    assert score_color(10) == "#ff4444"


def test_generate_html_creates_file(tmp_path: Path) -> None:
    out_file = tmp_path / "report.html"
    f = _finding()
    result = ScanResult(
        target_path=tmp_path,
        files_discovered=5,
        files_analyzed=3,
        chunks_created=10,
        security_score=90.0,
        optimization_score=100.0,
        findings=[f],
    )

    generate_html(result, out_file)
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert "AegisScan Report" in content
    assert "Security Score" in content
    assert "Optimization Score" in content
    assert "Test Finding" in content
