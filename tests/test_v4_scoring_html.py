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
    # High finding (weight 10) * confidence 1.0 = deduction 10 -> score 90.0
    f = _finding(severity=Severity.HIGH, confidence=1.0, category="injection")
    assert security_score([f]) == 90.0


def test_optimization_score_filters_category() -> None:
    sec_f = _finding(severity=Severity.CRITICAL, category="injection")
    opt_f = _finding(severity=Severity.HIGH, category="performance")

    assert security_score([sec_f, opt_f]) == 80.0     # 100 - 20 = 80
    assert optimization_score([sec_f, opt_f]) == 90.0  # 100 - 10 = 90


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
