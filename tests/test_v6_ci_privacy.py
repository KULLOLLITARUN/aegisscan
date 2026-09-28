"""Tests for V6 Production & CI Integration layer.

Covers:
  - GitDiffScanner changed file detection
  - evaluate_ci_gate threshold matching (security:high, optimization:medium, etc.)
  - Privacy modes (standard, redact, strict) in redactor.py
"""
from __future__ import annotations

from pathlib import Path

from scanner.ci.ci_gate import evaluate_ci_gate
from scanner.ingestion.git_diff import get_changed_files
from scanner.llm.redactor import PrivacyMode, redact
from scanner.models.finding import Finding, Severity
from scanner.models.scan import ScanResult


def _finding(
    severity: Severity = Severity.HIGH,
    category: str = "injection",
) -> Finding:
    return Finding(
        file_path=Path("app.py"),
        issue_type="Test Finding",
        category=category,
        severity=severity,
        confidence=0.9,
        line_start=1,
        line_end=5,
        evidence="code",
        explanation="explanation",
        rule_source="bandit",
    )


# ---------------------------------------------------------------------------
# CI Gate Tests
# ---------------------------------------------------------------------------

def test_ci_gate_disabled_returns_false() -> None:
    result = ScanResult(target_path=Path("."), findings=[_finding(Severity.CRITICAL)])
    failed, msg = evaluate_ci_gate(result, "")
    assert failed is False
    assert "disabled" in msg


def test_ci_gate_triggers_on_high_security() -> None:
    result = ScanResult(target_path=Path("."), findings=[_finding(Severity.HIGH, category="injection")])
    failed, msg = evaluate_ci_gate(result, "security:high")
    assert failed is True
    assert "CI GATE FAILED" in msg


def test_ci_gate_passes_low_security_when_threshold_high() -> None:
    result = ScanResult(target_path=Path("."), findings=[_finding(Severity.LOW, category="injection")])
    failed, msg = evaluate_ci_gate(result, "security:high")
    assert failed is False
    assert "CI GATE PASSED" in msg


def test_ci_gate_category_filtering() -> None:
    sec_f = _finding(Severity.HIGH, category="injection")
    opt_f = _finding(Severity.HIGH, category="performance")

    # Gate for performance should ignore security finding
    result_sec_only = ScanResult(target_path=Path("."), findings=[sec_f])
    failed, _ = evaluate_ci_gate(result_sec_only, "optimization:high")
    assert failed is False

    # Gate for performance should trigger on performance finding
    result_opt = ScanResult(target_path=Path("."), findings=[opt_f])
    failed, _ = evaluate_ci_gate(result_opt, "optimization:high")
    assert failed is True


# ---------------------------------------------------------------------------
# Redactor Privacy Modes Tests
# ---------------------------------------------------------------------------

def test_redactor_standard_mode() -> None:
    code = 'key = "sk-123456789012345678901234"\nuser_email = "test@example.com"'
    res = redact(code, mode=PrivacyMode.STANDARD)
    assert "[REDACTED" in res
    assert "test@example.com" in res  # standard does NOT redact emails


def test_redactor_redact_mode() -> None:
    code = 'server_ip = "192.168.1.1"\nuser_email = "admin@corp.com"'
    res = redact(code, mode=PrivacyMode.REDACT)
    assert "[REDACTED_IP]" in res
    assert "[REDACTED_EMAIL]" in res


def test_redactor_strict_mode() -> None:
    code = 'greeting = "Hello, World!"\ncount = 42'
    res = redact(code, mode=PrivacyMode.STRICT)
    assert '"[REDACTED_LITERAL]"' in res
    assert "Hello, World!" not in res


# ---------------------------------------------------------------------------
# Git Diff Scanner Tests
# ---------------------------------------------------------------------------

def test_git_diff_returns_set_or_none(tmp_path: Path) -> None:
    # Non-git directory returns None gracefully
    res = get_changed_files(tmp_path)
    assert res is None or isinstance(res, set)
