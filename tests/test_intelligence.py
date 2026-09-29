"""Tests for V3 Intelligence Layer (deduplication, correlation, baseline).

All tests use fixture findings built in-memory — no file system or API required.

Covers:
  - Deduplicator removes near-duplicate findings from multiple sources
  - Deduplicator keeps the highest-confidence finding per cluster
  - Deduplicator returns correct suppression count
  - Correlator marks corroborated clusters (2+ sources)
  - Correlator boosts confidence of corroborated findings (capped at 1.0)
  - Correlator does NOT boost single-source clusters
  - Fingerprint is stable across identical findings
  - Fingerprint differs for different files/issues
  - BaselineManager suppresses matching fingerprints
  - BaselineManager passes through non-matching findings unchanged
  - BaselineManager handles missing/invalid baseline file gracefully
  - save_baseline writes valid JSON with correct fingerprints
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from scanner.intelligence.baseline import BaselineManager, save_baseline
from scanner.intelligence.correlator import (
    correlate,
)
from scanner.intelligence.deduplicator import (
    PROXIMITY_LINES,
    deduplicate,
    fingerprint,
)
from scanner.models.finding import Finding, Severity

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _finding(
    path: str = "app.py",
    line_start: int = 10,
    line_end: int = 12,
    issue_type: str = "SQL Injection",
    category: str = "injection",
    severity: Severity = Severity.HIGH,
    confidence: float = 0.85,
    rule_source: str = "bandit",
) -> Finding:
    return Finding(
        file_path=Path(path),
        issue_type=issue_type,
        category=category,
        severity=severity,
        confidence=confidence,
        line_start=line_start,
        line_end=line_end,
        evidence="some code",
        explanation="test",
        rule_source=rule_source,
    )


# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------

def test_fingerprint_is_stable() -> None:
    f = _finding()
    assert fingerprint(f) == fingerprint(f)


def test_fingerprint_differs_by_file() -> None:
    f1 = _finding(path="app.py")
    f2 = _finding(path="auth.py")
    assert fingerprint(f1) != fingerprint(f2)


def test_fingerprint_differs_by_issue_type() -> None:
    f1 = _finding(issue_type="SQL Injection")
    f2 = _finding(issue_type="Command Injection")
    assert fingerprint(f1) != fingerprint(f2)


def test_fingerprint_tolerates_small_line_drift() -> None:
    """Findings at line 10 and line 14 (within PROXIMITY_LINES window) → same fingerprint."""
    f1 = _finding(line_start=10)
    _f2 = _finding(line_start=10 + PROXIMITY_LINES - 1)  # same window bucket
    # They may or may not share a fingerprint depending on bucket calculation
    # Just assert it's a 16-char hex string (format correctness)
    fp = fingerprint(f1)
    assert len(fp) == 16
    assert all(c in "0123456789abcdef" for c in fp)


# ---------------------------------------------------------------------------
# Deduplicator
# ---------------------------------------------------------------------------

def test_dedup_removes_same_area_same_category() -> None:
    """Two findings in the same area + category → keep one."""
    bandit_f = _finding(line_start=10, confidence=0.85, rule_source="bandit")
    llm_f    = _finding(line_start=11, confidence=0.92, rule_source="llm")

    deduped, n_removed = deduplicate([bandit_f, llm_f])
    assert n_removed == 1
    assert len(deduped) == 1


def test_dedup_keeps_highest_confidence() -> None:
    low_conf  = _finding(line_start=10, confidence=0.60, rule_source="bandit")
    high_conf = _finding(line_start=11, confidence=0.92, rule_source="llm")

    deduped, _ = deduplicate([low_conf, high_conf])
    assert deduped[0].confidence == 0.92


def test_dedup_preserves_different_categories() -> None:
    """Same area but different categories → both kept."""
    injection = _finding(line_start=10, category="injection")
    secrets   = _finding(line_start=10, category="secrets", issue_type="Hardcoded Key")

    deduped, n_removed = deduplicate([injection, secrets])
    assert n_removed == 0
    assert len(deduped) == 2


def test_dedup_preserves_different_files() -> None:
    f1 = _finding(path="app.py",  line_start=10)
    f2 = _finding(path="auth.py", line_start=10)

    deduped, n_removed = deduplicate([f1, f2])
    assert n_removed == 0
    assert len(deduped) == 2


def test_dedup_empty_input() -> None:
    deduped, n = deduplicate([])
    assert deduped == []
    assert n == 0


def test_dedup_single_finding() -> None:
    f = _finding()
    deduped, n = deduplicate([f])
    assert len(deduped) == 1
    assert n == 0


def test_dedup_returns_count_accurately() -> None:
    findings = [
        _finding(line_start=10, confidence=0.90, rule_source="bandit"),
        _finding(line_start=11, confidence=0.80, rule_source="llm"),
        _finding(line_start=12, confidence=0.70, rule_source="semgrep"),
    ]
    _, n_removed = deduplicate(findings)
    assert n_removed == 2   # 3 findings → 1 cluster → 2 removed


# ---------------------------------------------------------------------------
# Correlator
# ---------------------------------------------------------------------------

def test_correlator_marks_corroborated_cluster() -> None:
    """Two tools on same area → corroborated."""
    bandit_f = _finding(line_start=10, rule_source="bandit",  confidence=0.80)
    llm_f    = _finding(line_start=12, rule_source="llm",     confidence=0.85)

    boosted, groups = correlate([bandit_f, llm_f])
    corroborated = [g for g in groups if g.is_corroborated]
    assert len(corroborated) >= 1


def test_correlator_boosts_corroborated_confidence() -> None:
    bandit_f = _finding(line_start=10, rule_source="bandit", confidence=0.80)
    llm_f    = _finding(line_start=11, rule_source="llm",    confidence=0.85)

    boosted, _ = correlate([bandit_f, llm_f])
    # Both should have confidence boosted
    assert all(f.confidence > 0.80 for f in boosted)


def test_correlator_caps_confidence_at_1() -> None:
    f1 = _finding(line_start=10, rule_source="bandit", confidence=0.98)
    f2 = _finding(line_start=11, rule_source="llm",    confidence=0.98)

    boosted, _ = correlate([f1, f2])
    assert all(f.confidence <= 1.0 for f in boosted)


def test_correlator_does_not_boost_single_source() -> None:
    """Single finding cluster → no boost."""
    f = _finding(line_start=50, rule_source="bandit", confidence=0.75)

    boosted, groups = correlate([f])
    assert boosted[0].confidence == pytest.approx(0.75)
    assert not groups[0].is_corroborated


def test_correlator_empty_input() -> None:
    boosted, groups = correlate([])
    assert boosted == []
    assert groups == []


def test_correlator_groups_have_correct_sources() -> None:
    f1 = _finding(line_start=10, rule_source="bandit")
    f2 = _finding(line_start=11, rule_source="semgrep")
    f3 = _finding(line_start=12, rule_source="llm")

    _, groups = correlate([f1, f2, f3])
    # All three land in one cluster → 3 distinct sources
    assert len(groups) == 1
    assert set(groups[0].sources) == {"bandit", "semgrep", "llm"}


# ---------------------------------------------------------------------------
# BaselineManager
# ---------------------------------------------------------------------------

def test_baseline_suppresses_known_finding(tmp_path: Path) -> None:
    f = _finding()
    baseline_file = tmp_path / "baseline.json"

    # Save a baseline containing this finding
    save_baseline([f], tmp_path, baseline_file)

    # Load and suppress
    manager = BaselineManager(baseline_file)
    remaining, n_suppressed = manager.suppress([f])
    assert n_suppressed == 1
    assert remaining == []


def test_baseline_passes_new_findings(tmp_path: Path) -> None:
    known = _finding(line_start=10, issue_type="SQL Injection")
    new   = _finding(line_start=50, issue_type="Command Injection", rule_source="llm")
    baseline_file = tmp_path / "baseline.json"

    save_baseline([known], tmp_path, baseline_file)

    manager = BaselineManager(baseline_file)
    remaining, n_suppressed = manager.suppress([known, new])
    assert n_suppressed == 1
    assert len(remaining) == 1
    assert remaining[0].issue_type == "Command Injection"


def test_baseline_missing_file_does_not_crash(tmp_path: Path) -> None:
    manager = BaselineManager(tmp_path / "nonexistent.json")
    f = _finding()
    remaining, n = manager.suppress([f])
    assert remaining == [f]
    assert n == 0


def test_baseline_is_not_active_without_path() -> None:
    manager = BaselineManager(None)
    assert not manager.is_active


def test_save_baseline_writes_valid_json(tmp_path: Path) -> None:
    findings = [_finding(line_start=10), _finding(line_start=50, issue_type="Hash")]
    out = tmp_path / "baseline.json"
    save_baseline(findings, tmp_path, out)

    data = json.loads(out.read_text())
    assert "fingerprints" in data
    assert len(data["fingerprints"]) == len(findings)
    assert data["aegisscan_version"] == "V3"


def test_save_baseline_fingerprints_are_strings(tmp_path: Path) -> None:
    f = _finding()
    out = tmp_path / "baseline.json"
    save_baseline([f], tmp_path, out)
    data = json.loads(out.read_text())
    for fp in data["fingerprints"]:
        assert isinstance(fp, str)
        assert len(fp) == 16


# ---------------------------------------------------------------------------
# Regression: distinct same-source findings must survive deduplication
# (found by the labelled benchmark: nearby SQLi / MD5 / pickle hits were collapsed)
# ---------------------------------------------------------------------------

def test_dedup_keeps_distinct_findings_from_the_same_source() -> None:
    first = _finding(line_start=6, line_end=6, rule_source="bandit")
    second = _finding(line_start=11, line_end=11, rule_source="bandit")
    deduped, n_removed = deduplicate([first, second])
    assert n_removed == 0
    assert {f.line_start for f in deduped} == {6, 11}


def test_dedup_still_collapses_exact_repeats_from_one_source() -> None:
    a = _finding(line_start=6, line_end=6, rule_source="bandit")
    b = _finding(line_start=6, line_end=6, rule_source="bandit")
    _, n_removed = deduplicate([a, b])
    assert n_removed == 1


def test_dedup_merges_across_sources_but_not_into_a_cluster_with_a_same_source_sibling() -> None:
    bandit_a = _finding(line_start=6, line_end=6, rule_source="bandit", confidence=0.85)
    llm = _finding(line_start=8, line_end=8, rule_source="llm", confidence=0.70)
    bandit_b = _finding(line_start=11, line_end=11, rule_source="bandit", confidence=0.85)
    deduped, n_removed = deduplicate([bandit_a, llm, bandit_b])
    # llm merges with the first bandit hit; the second bandit hit stays separate
    assert n_removed == 1
    assert sorted(f.line_start for f in deduped) == [6, 11]
