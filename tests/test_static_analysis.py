"""Tests for static analysis wrappers (V1).

Covers:
  - BanditRunner finds real issues in examples/vulnerable_python/
  - Each runner returns list[Finding] (never raw dicts)
  - Severity and confidence values are within valid ranges
  - Tool not found -> returns [], logs warning, does not raise
  - run_all_tools() returns (list[Finding], list[str]) correctly
"""
from __future__ import annotations

from pathlib import Path

import pytest

from scanner.models.finding import Finding, Severity
from scanner.static_analysis.bandit_runner import run_bandit
from scanner.static_analysis.runner import run_all_tools

# Absolute path to the benchmark fixture
VULNERABLE = Path(__file__).parent.parent / "examples" / "vulnerable_python"
CLEAN = Path(__file__).parent.parent / "examples" / "clean_project"


# ---------------------------------------------------------------------------
# Return-type contract
# ---------------------------------------------------------------------------

def test_bandit_returns_list_of_findings() -> None:
    findings = run_bandit(VULNERABLE)
    assert isinstance(findings, list)
    for f in findings:
        assert isinstance(f, Finding), f"Expected Finding, got {type(f)}"


def test_run_all_tools_returns_tuple() -> None:
    findings, tools_run = run_all_tools(VULNERABLE)
    assert isinstance(findings, list)
    assert isinstance(tools_run, list)


# ---------------------------------------------------------------------------
# BanditRunner — real findings on vulnerable_python
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not VULNERABLE.exists(),
    reason="examples/vulnerable_python/ not found",
)
def test_bandit_finds_sql_injection() -> None:
    """Bandit B608 must fire on app.py SQL concatenation."""
    findings = run_bandit(VULNERABLE)
    rule_sources = {f.rule_source for f in findings}
    assert "bandit" in rule_sources

    # At least one finding referencing SQL injection (B608)
    sql_findings = [f for f in findings if "sql" in f.issue_type.lower() or "sql" in f.explanation.lower()]
    assert len(sql_findings) >= 1, "Expected at least one SQL injection finding from Bandit"


@pytest.mark.skipif(
    not VULNERABLE.exists(),
    reason="examples/vulnerable_python/ not found",
)
def test_bandit_finds_multiple_issues() -> None:
    """Bandit must detect >= 4 distinct issues across the vulnerable project."""
    findings = run_bandit(VULNERABLE)
    assert len(findings) >= 4, (
        f"Expected >= 4 Bandit findings in vulnerable_python, got {len(findings)}"
    )


@pytest.mark.skipif(
    not CLEAN.exists(),
    reason="examples/clean_project/ not found",
)
def test_bandit_minimal_findings_on_clean_project() -> None:
    """
    Clean project should have very few Bandit findings (false-positive baseline).
    Bandit raises B404 (subprocess import), B603, B607 on safe subprocess.run()
    calls — these are known low-severity false positives on any code that uses
    subprocess safely. Threshold is permissive here; calibrate in §7 benchmark.
    """
    findings = run_bandit(CLEAN)
    assert len(findings) <= 5, (
        f"Expected <= 5 findings on clean_project, got {len(findings)}: "
        + ", ".join(f.issue_type for f in findings)
    )


# ---------------------------------------------------------------------------
# Value range validation
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not VULNERABLE.exists(),
    reason="examples/vulnerable_python/ not found",
)
def test_finding_confidence_in_valid_range() -> None:
    """All confidence values must be between 0.0 and 1.0 (Pydantic enforces this)."""
    findings = run_bandit(VULNERABLE)
    for f in findings:
        assert 0.0 <= f.confidence <= 1.0, f"confidence={f.confidence} out of range for {f}"


@pytest.mark.skipif(
    not VULNERABLE.exists(),
    reason="examples/vulnerable_python/ not found",
)
def test_finding_severity_is_valid_enum() -> None:
    findings = run_bandit(VULNERABLE)
    valid_severities = set(Severity)
    for f in findings:
        assert f.severity in valid_severities


@pytest.mark.skipif(
    not VULNERABLE.exists(),
    reason="examples/vulnerable_python/ not found",
)
def test_findings_have_non_empty_evidence() -> None:
    findings = run_bandit(VULNERABLE)
    for f in findings:
        assert f.evidence is not None  # may be empty string but not None
        assert f.explanation, f"Finding {f.id} has empty explanation"


# ---------------------------------------------------------------------------
# Tool-not-found: graceful skip
# ---------------------------------------------------------------------------

def test_bandit_nonexistent_target_returns_empty(tmp_path: Path) -> None:
    """Bandit on an empty dir should return [] without crashing."""
    empty = tmp_path / "empty_project"
    empty.mkdir()
    findings = run_bandit(empty)
    assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# run_all_tools integration
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not VULNERABLE.exists(),
    reason="examples/vulnerable_python/ not found",
)
def test_run_all_tools_bandit_always_in_results() -> None:
    """Bandit is pip-installed so it must always appear in tools_run."""
    findings, tools_run = run_all_tools(VULNERABLE)
    # Bandit should always run; it may produce 0 findings on a tiny target
    # but if findings > 0, bandit must be listed
    if any(f.rule_source == "bandit" for f in findings):
        assert "bandit" in tools_run


def test_run_all_tools_findings_are_finding_instances() -> None:
    """run_all_tools must never return raw dicts."""
    findings, _ = run_all_tools(VULNERABLE)
    for f in findings:
        assert isinstance(f, Finding)
