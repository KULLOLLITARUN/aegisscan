"""Tests for the real progress callback threaded from main.run() to the SSE stream."""
from __future__ import annotations

import threading
from pathlib import Path

import main
from scanner.llm.auditor import LLMAuditor
from scanner.providers.manager import ProviderManager
from scanner.static_analysis import runner
from tests.test_v10_server import _create_mock_request_handler
from tests.test_v12_remaining import _chunk, _Echo
from tests.test_v13_coverage import _events, _fake_result


def _fast_tools(monkeypatch) -> None:
    """Replace run_all_tools with a stub that still reports per-tool progress."""
    def fake(target, progress=None, only_files=None, privacy="standard"):
        for name in ("Bandit", "Semgrep"):
            if progress:
                progress(name)
        return [], []

    monkeypatch.setattr(main, "run_all_tools", fake)


def test_run_reports_phases_in_order(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    _fast_tools(monkeypatch)
    calls: list[tuple[str, int, str]] = []
    main.run(tmp_path, static_only=True, progress=lambda p, pct, d="": calls.append((p, pct, d)))

    phases = [c[0] for c in calls]
    assert phases[0] == "Crawling workspace"
    assert phases[-1] == "Deduplicating and scoring"
    pcts = [c[1] for c in calls]
    assert pcts == sorted(pcts) and all(0 <= p <= 100 for p in pcts)
    assert ("Static analysis", 30, "Bandit") in calls
    assert ("Static analysis", 30, "Semgrep") in calls


def test_run_without_progress_still_works(tmp_path: Path, monkeypatch) -> None:
    _fast_tools(monkeypatch)
    result, _, _ = main.run(tmp_path, static_only=True)
    assert result.security_score is not None


def test_run_survives_a_failing_progress_callback(tmp_path: Path, monkeypatch) -> None:
    _fast_tools(monkeypatch)

    def bad(*_a, **_k):
        raise RuntimeError("ui exploded")

    result, _, _ = main.run(tmp_path, static_only=True, progress=bad)
    assert result.security_score is not None


def test_run_all_tools_reports_each_tool(tmp_path: Path, monkeypatch) -> None:
    for name in ("run_bandit", "run_semgrep", "run_gitleaks", "run_osv"):
        monkeypatch.setattr(runner, name, lambda *a, **k: [])
    monkeypatch.setattr(runner, "run_optimizer", lambda *a, **k: [])
    seen: list[str] = []
    runner.run_all_tools(tmp_path, progress=seen.append)
    assert seen == ["Bandit", "Semgrep", "Gitleaks", "OSV-Scanner", "Optimizer"]


def test_auditor_reports_per_chunk_progress(monkeypatch) -> None:
    monkeypatch.setenv("AEGISSCAN_LLM_RPM", "6000")
    monkeypatch.setenv("AEGISSCAN_LLM_WORKERS", "4")
    pm = ProviderManager(providers=[_Echo()])
    lock = threading.Lock()
    ticks: list[tuple[int, int]] = []

    def cb(done: int, total: int) -> None:
        with lock:
            ticks.append((done, total))

    LLMAuditor(pm).analyze_chunks([_chunk(i) for i in range(6)], [], deep=True, progress=cb)
    assert sorted(d for d, _ in ticks) == [1, 2, 3, 4, 5, 6]
    assert {t for _, t in ticks} == {6}


def test_auditor_survives_failing_progress_callback(monkeypatch) -> None:
    monkeypatch.setenv("AEGISSCAN_LLM_RPM", "6000")
    monkeypatch.setenv("AEGISSCAN_LLM_WORKERS", "1")

    def bad(_d: int, _t: int) -> None:
        raise RuntimeError("boom")

    pm = ProviderManager(providers=[_Echo()])
    LLMAuditor(pm).analyze_chunks([_chunk(0)], [], deep=True, progress=bad)
    assert pm.requests_count == 1


def test_sse_forwards_run_progress_and_no_longer_fakes_phases(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AEGISSCAN_ALLOWED_ROOTS", str(tmp_path))

    def fake_run(**kwargs):
        kwargs["progress"]("Static analysis", 30, "Bandit")
        kwargs["progress"]("LLM analysis", 60, "3/9 chunks")
        return _fake_result(1), None, None

    monkeypatch.setattr("main.run", fake_run)
    handler = _create_mock_request_handler("GET", f"/api/scan/stream?path={tmp_path}")
    handler.do_GET()

    progress = [d for n, d in _events(handler) if n == "progress"]
    phases = [d["phase"] for d in progress]
    assert phases == ["Static analysis: Bandit", "LLM analysis: 3/9 chunks", "Complete"]
    assert [d["pct"] for d in progress] == [30, 60, 100]


def test_make_console_safe_survives_legacy_codepage(monkeypatch) -> None:
    import io
    import sys

    import main as cli

    buf = io.BytesIO()
    fake = io.TextIOWrapper(buf, encoding="cp1252", errors="strict")
    monkeypatch.setattr(sys, "stdout", fake)
    cli._make_console_safe()
    print("non‑breaking hyphen")  # U+2011 has no cp1252 mapping; used to raise
    fake.flush()
    assert b"non" in buf.getvalue()


def test_run_reports_the_analysable_files_once(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "a.py").write_text("x = 1\ny = 2\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("z = 3\n", encoding="utf-8")
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01\x02\x03")
    _fast_tools(monkeypatch)
    seen: list[list[dict]] = []
    main.run(tmp_path, static_only=True, on_files=seen.append)

    assert len(seen) == 1
    by_path = {f["path"]: f["lines"] for f in seen[0]}
    assert by_path == {"b.py": 1, "pkg/a.py": 2}


def test_run_survives_a_failing_on_files_callback(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    _fast_tools(monkeypatch)

    def bad(_files):
        raise RuntimeError("ui exploded")

    result, _, _ = main.run(tmp_path, static_only=True, on_files=bad)
    assert result.security_score is not None


def _make_finding(path: Path, severity: str = "high"):
    from scanner.models.finding import Finding

    return Finding(
        file_path=path, line_start=1, line_end=1, severity=severity, confidence=0.9, category="injection",
        issue_type="x", evidence="e", explanation="e", rule_source="bandit",
    )


def test_run_all_tools_reports_findings_after_each_tool(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(runner, "run_bandit", lambda *a, **k: [_make_finding(tmp_path / "a.py")])
    for name in ("run_semgrep", "run_gitleaks", "run_osv", "run_optimizer"):
        monkeypatch.setattr(runner, name, lambda *a, **k: [])
    seen: list[tuple[str, int]] = []
    runner.run_all_tools(tmp_path, on_findings=lambda tool, fs: seen.append((tool, len(fs))))
    assert seen == [("Bandit", 1)], "tools with no findings are not reported"


def test_run_streams_preview_grouped_by_file(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    low = _make_finding(tmp_path / "a.py", "low")
    crit = _make_finding(tmp_path / "a.py", "critical")

    def fake(target, progress=None, only_files=None, privacy="standard", on_findings=None):
        on_findings("Bandit", [low, crit])
        return [low, crit], ["bandit"]

    monkeypatch.setattr(main, "run_all_tools", fake)
    seen: list[tuple[str, list[dict]]] = []
    main.run(tmp_path, static_only=True, on_findings=lambda tool, fs: seen.append((tool, fs)))
    assert seen == [("Bandit", [{"path": "a.py", "worst": "critical", "count": 2}])]
