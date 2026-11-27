"""The static tools run in parallel; results, status reports and callbacks must not depend on timing."""
from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from scanner.models.finding import Finding
from scanner.static_analysis import runner, status
from tests.test_v14_progress import _make_finding


def _stub_all(monkeypatch, **overrides) -> None:
    for name in ("run_bandit", "run_semgrep", "run_gitleaks", "run_osv", "run_optimizer"):
        monkeypatch.setattr(runner, name, overrides.get(name, lambda *a, **k: []))


def test_tools_actually_overlap(tmp_path: Path, monkeypatch) -> None:
    running = 0
    peak = 0
    lock = threading.Lock()

    def slow(*_a, **_k):
        nonlocal running, peak
        with lock:
            running += 1
            peak = max(peak, running)
        time.sleep(0.3)
        with lock:
            running -= 1
        return []

    _stub_all(monkeypatch, run_bandit=slow, run_semgrep=slow, run_gitleaks=slow, run_osv=slow)
    started = time.monotonic()
    runner.run_all_tools(tmp_path)
    assert peak >= 3
    assert time.monotonic() - started < 1.0, "four 0.3 s tools should not take 1.2 s"


def test_problem_reported_from_a_worker_thread_is_kept(tmp_path: Path, monkeypatch) -> None:
    def failing_semgrep(*_a, **_k):
        status.problem("semgrep", "timed out after 1 s")
        return []

    _stub_all(monkeypatch, run_semgrep=failing_semgrep)
    with status.collect() as issues:
        _, tools_run = runner.run_all_tools(tmp_path)
    assert issues == {"semgrep": "timed out after 1 s"}
    assert "semgrep" not in tools_run
    assert "bandit" in tools_run


def test_issues_of_concurrent_scans_do_not_mix(tmp_path: Path, monkeypatch) -> None:
    both_running = threading.Barrier(2)

    def semgrep(target, *_a, **_k):
        both_running.wait(timeout=10)  # the two scans are inside their tools at the same time
        if target.name == "broken":
            status.problem("semgrep", "boom")
        return []

    _stub_all(monkeypatch, run_semgrep=semgrep)
    (tmp_path / "broken").mkdir()
    (tmp_path / "clean").mkdir()
    seen: dict[str, dict[str, str]] = {}

    def scan(name: str) -> None:
        with status.collect() as issues:
            runner.run_all_tools(tmp_path / name)
        seen[name] = dict(issues)

    threads = [threading.Thread(target=scan, args=(n,)) for n in ("broken", "clean")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert seen == {"broken": {"semgrep": "boom"}, "clean": {}}


def test_results_come_back_in_fixed_order(tmp_path: Path, monkeypatch) -> None:
    f_bandit = _make_finding(tmp_path / "b.py")
    f_semgrep = _make_finding(tmp_path / "s.py")

    def slow_bandit(*_a, **_k):
        time.sleep(0.3)
        return [f_bandit]

    _stub_all(monkeypatch, run_bandit=slow_bandit, run_semgrep=lambda *a, **k: [f_semgrep])
    findings, tools_run = runner.run_all_tools(tmp_path)
    assert findings == [f_bandit, f_semgrep], "Bandit finishes last but still comes first"
    assert tools_run == ["bandit", "semgrep", "gitleaks", "osv-scanner", "aegis-optimizer"]


def test_callbacks_are_never_concurrent(tmp_path: Path, monkeypatch) -> None:
    for name in ("run_bandit", "run_semgrep", "run_gitleaks", "run_osv", "run_optimizer"):
        monkeypatch.setattr(runner, name, lambda *a, **k: [_make_finding(tmp_path / "a.py")])
    inside = 0
    overlap = False

    def cb(_tool: str, _found: list[Finding]) -> None:
        nonlocal inside, overlap
        inside += 1
        if inside > 1:
            overlap = True
        time.sleep(0.05)
        inside -= 1

    runner.run_all_tools(tmp_path, on_findings=cb)
    assert not overlap


def test_a_crashing_tool_still_raises(tmp_path: Path, monkeypatch) -> None:
    def crash(*_a, **_k):
        raise RuntimeError("tool exploded")

    _stub_all(monkeypatch, run_gitleaks=crash)
    with pytest.raises(RuntimeError, match="tool exploded"):
        runner.run_all_tools(tmp_path)
