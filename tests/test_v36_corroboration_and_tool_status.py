"""Corroboration survives deduplication, and a tool that did not run is reported, not hidden."""
from __future__ import annotations

import subprocess
import threading
from pathlib import Path

import pytest

from scanner.intelligence.correlator import correlate
from scanner.intelligence.deduplicator import deduplicate
from scanner.models.finding import Finding, Severity
from scanner.static_analysis import bandit_runner, runner, semgrep_runner, status


def _f(source: str, line: int = 10, category: str = "injection", conf: float = 0.80, path: str = "app.py") -> Finding:
    return Finding(
        file_path=Path(path), issue_type="SQL Injection", category=category, severity=Severity.HIGH,
        confidence=conf, line_start=line, line_end=line, evidence="x", explanation="t", rule_source=source,
    )


# ---------------------------------------------------------------- corroboration
def test_dedup_records_who_agreed_and_correlator_boosts_the_kept_finding() -> None:
    kept, removed = deduplicate([_f("bandit", conf=0.80), _f("semgrep", conf=0.75)])
    assert removed == 1 and len(kept) == 1
    assert kept[0].corroborated_by == ["semgrep"]            # bandit won, semgrep agreed

    boosted, groups = correlate(kept)
    assert boosted[0].confidence == pytest.approx(0.85)
    assert groups[0].is_corroborated and set(groups[0].sources) == {"bandit", "semgrep"}


def test_single_tool_finding_is_not_boosted() -> None:
    kept, _ = deduplicate([_f("bandit")])
    boosted, groups = correlate(kept)
    assert boosted[0].confidence == pytest.approx(0.80)
    assert not groups[0].is_corroborated


def test_different_categories_nearby_do_not_corroborate() -> None:
    boosted, groups = correlate([_f("bandit", 10, "secrets"), _f("semgrep", 12, "best_practices")])
    assert all(f.confidence == pytest.approx(0.80) for f in boosted)
    assert not any(g.is_corroborated for g in groups)


def test_same_category_neighbours_from_two_tools_still_corroborate() -> None:
    boosted, groups = correlate([_f("bandit", 10), _f("semgrep", 14)])
    assert all(f.confidence == pytest.approx(0.85) for f in boosted)
    assert groups[0].is_corroborated


def test_neighbours_recorded_agreement_does_not_boost_an_unrelated_finding() -> None:
    merged = _f("bandit", 10).model_copy(update={"corroborated_by": ["semgrep"]})
    boosted, _ = correlate([merged, _f("bandit", 16)])
    by_line = {f.line_start: f for f in boosted}
    assert by_line[10].confidence == pytest.approx(0.85)
    assert by_line[16].confidence == pytest.approx(0.80)      # same tool nearby: no agreement


def test_corroboration_is_not_applied_twice() -> None:
    kept, _ = deduplicate([_f("bandit", conf=0.80), _f("semgrep", conf=0.75), _f("llm", conf=0.70)])
    boosted, _ = correlate(kept)
    assert boosted[0].confidence == pytest.approx(0.85)
    assert boosted[0].corroborated_by == ["llm", "semgrep"]


# ---------------------------------------------------------------- tool status
def test_problem_is_ignored_outside_a_collector_and_first_reason_wins() -> None:
    status.problem("semgrep", "ignored")                      # no collector: must not raise
    with status.collect() as issues:
        status.problem("semgrep", "first")
        status.problem("semgrep", "second")
    assert issues == {"semgrep": "first"}


def test_collect_nests_into_the_outer_collector() -> None:
    with status.collect() as outer:
        with status.collect() as inner:
            status.problem("bandit", "x")
        assert inner is outer
    assert outer == {"bandit": "x"}


def _quiet_tools(monkeypatch) -> None:
    for name in ("run_bandit", "run_semgrep", "run_gitleaks", "run_osv", "run_optimizer"):
        monkeypatch.setattr(runner, name, lambda *a, **k: [])


def _failing_semgrep(*args, **kwargs):
    status.problem("semgrep", "timed out after 300 s")
    return []


def test_a_tool_that_ran_clean_is_listed_and_one_that_failed_is_not(tmp_path: Path, monkeypatch) -> None:
    _quiet_tools(monkeypatch)
    monkeypatch.setattr(runner, "run_semgrep", _failing_semgrep)
    with status.collect() as issues:
        findings, tools = runner.run_all_tools(tmp_path)
    assert findings == []
    assert "bandit" in tools and "aegis-optimizer" in tools   # ran, found nothing
    assert "semgrep" not in tools
    assert issues == {"semgrep": "timed out after 300 s"}


def test_scans_in_other_threads_do_not_share_issue_reports(tmp_path: Path, monkeypatch) -> None:
    _quiet_tools(monkeypatch)
    monkeypatch.setattr(runner, "run_semgrep", _failing_semgrep)
    seen: dict[str, dict] = {}

    def other_scan() -> None:                                  # a new thread starts with no collector
        with status.collect() as issues:
            status.problem("bandit", "other")
        seen["other"] = dict(issues)

    with status.collect() as mine:
        t = threading.Thread(target=other_scan)
        t.start()
        t.join()
        runner.run_all_tools(tmp_path)
    assert mine == {"semgrep": "timed out after 300 s"}
    assert seen["other"] == {"bandit": "other"}


def test_semgrep_timeout_and_missing_binary_are_reported(monkeypatch) -> None:
    def boom(cmd, timeout_s):
        raise subprocess.TimeoutExpired(cmd, timeout_s)

    monkeypatch.setattr(semgrep_runner, "_run_bounded", boom)
    with status.collect() as issues:
        assert semgrep_runner._run_semgrep_once(["semgrep"]) == []
    assert "timed out" in issues["semgrep"]

    monkeypatch.setattr(semgrep_runner, "_find_tool", lambda name: None)
    with status.collect() as issues:
        assert semgrep_runner.run_semgrep(Path(".")) == []
    assert issues["semgrep"] == "not installed"


def test_semgrep_empty_output_and_rule_errors_are_reported(monkeypatch) -> None:
    def fake(out: str):
        return lambda cmd, t: subprocess.CompletedProcess(cmd, 7, out, "boom")

    monkeypatch.setattr(semgrep_runner, "_run_bounded", fake(""))
    with status.collect() as issues:
        semgrep_runner._run_semgrep_once(["semgrep"])
    assert "no report" in issues["semgrep"]

    errors = '{"results": [], "errors": [{"level": "error", "message": "404 pack"}]}'
    monkeypatch.setattr(semgrep_runner, "_run_bounded", fake(errors))
    with status.collect() as issues:
        semgrep_runner._run_semgrep_once(["semgrep"])
    assert "404 pack" in issues["semgrep"]


def test_semgrep_clean_run_reports_nothing(monkeypatch) -> None:
    clean = '{"results": [], "errors": []}'
    monkeypatch.setattr(semgrep_runner, "_run_bounded",
                        lambda cmd, t: subprocess.CompletedProcess(cmd, 0, clean, ""))
    with status.collect() as issues:
        assert semgrep_runner._run_semgrep_once(["semgrep"]) == []
    assert issues == {}


def test_bandit_failures_are_reported(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(bandit_runner, "_find_bandit", lambda: None)
    with status.collect() as issues:
        assert bandit_runner.run_bandit(tmp_path) == []
    assert issues == {"bandit": "not installed"}

    def timeout(*a, **k):
        raise subprocess.TimeoutExpired("bandit", 120)

    monkeypatch.setattr(bandit_runner.subprocess, "run", timeout)
    with status.collect() as issues:
        bandit_runner._run_once(["bandit"], tmp_path)
    assert "timed out" in issues["bandit"]

    monkeypatch.setattr(bandit_runner.subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(a, 0, "not json", ""))
    with status.collect() as issues:
        bandit_runner._run_once(["bandit"], tmp_path)
    assert "unreadable" in issues["bandit"]


def test_scan_result_and_html_report_carry_the_issues(tmp_path: Path, monkeypatch) -> None:
    import main
    from scanner.reporting.html_report import generate_html

    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")

    def fake_tools(*args, **kwargs):
        status.problem("semgrep", "timed out after 300 s")
        return [], ["bandit"]

    monkeypatch.setattr(main, "run_all_tools", fake_tools)
    result, _, _ = main.run(tmp_path, static_only=True, record_history=False)
    assert result.static_tool_issues == {"semgrep": "timed out after 300 s"}
    out = tmp_path / "report.html"
    generate_html(result, out)
    html_text = out.read_text(encoding="utf-8")
    assert "Incomplete:" in html_text and "timed out after 300 s" in html_text


# ---------------------------------------------------------------- dedup determinism and speed
def _spread(n: int) -> list[Finding]:
    import random
    rng = random.Random(7)
    out = []
    for i in range(n):
        line = rng.randint(1, 300)
        out.append(Finding(
            file_path=Path(f"f{i % 400}.py"), issue_type=f"t{i % 5}",
            category=rng.choice(["injection", "secrets", "best_practices"]), severity=Severity.HIGH,
            confidence=rng.random(), line_start=line, line_end=line, evidence="x", explanation="t",
            rule_source=rng.choice(["bandit", "semgrep", "llm"]),
        ))
    return out


def test_deduplicate_gives_the_same_result_whatever_order_the_tools_reported_in() -> None:
    import random
    findings = _spread(1500)
    expected, _ = deduplicate(findings)
    ident = lambda fs: sorted((str(f.file_path), f.line_start, f.rule_source, f.issue_type, f.confidence) for f in fs)
    for seed in range(4):
        shuffled = findings[:]
        random.Random(seed).shuffle(shuffled)
        again, _ = deduplicate(shuffled)
        assert ident(again) == ident(expected)


def test_deduplicate_scales_to_thousands_of_findings() -> None:
    import time
    findings = _spread(6000)
    start = time.perf_counter()
    deduplicate(findings)
    assert time.perf_counter() - start < 2.0      # about 0.05 s now; it took about 5 s with the old all-pairs scan
