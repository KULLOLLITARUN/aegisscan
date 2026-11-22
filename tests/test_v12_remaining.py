"""Tests for: extra tree-sitter languages, threaded LLM pass, optimizer benchmark,
and opt-in live-provider smoke tests."""
from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

from scanner.chunking.dispatcher import chunk_file
from scanner.llm.auditor import LLMAuditor
from scanner.models.chunk import CodeChunk
from scanner.models.file_info import FileInfo
from scanner.models.finding import Finding, Severity
from scanner.providers.base import LLMProvider, LLMResponse
from scanner.providers.groq_provider import GroqProvider
from scanner.providers.manager import ProviderManager
from scanner.static_analysis.optimization_runner import run_optimizer

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


# ------------------------------------------------------- new chunk languages
_SAMPLES = {
    "Go": ("a.go", "package main\n\nfunc Add(a, b int) int {\n\treturn a + b\n}\n\nfunc (s *S) Run() {}\n",
           {"Add", "Run"}),
    "Java": ("A.java", "class A {\n  A() {}\n  int add(int a, int b) { return a + b; }\n}\n",
             {"A", "add"}),
    "PHP": ("a.php", "<?php\nfunction add($a, $b) { return $a + $b; }\nclass Foo { function bar() {} }\n",
            {"add", "Foo", "bar"}),
    "C#": ("A.cs", "class A {\n  public int Add(int a, int b) { return a + b; }\n}\n",
           {"A", "Add"}),
}


@pytest.mark.parametrize("language", list(_SAMPLES))
def test_tree_sitter_extracts_symbols(tmp_path: Path, language: str) -> None:
    filename, source, expected = _SAMPLES[language]
    path = tmp_path / filename
    path.write_text(source, encoding="utf-8")
    fi = FileInfo(path=path, language=language, size_bytes=path.stat().st_size)
    chunks = chunk_file(fi)
    names = {c.symbol_name for c in chunks}
    assert expected <= names, f"{language}: got {names}"
    assert all(c.symbol_name is not None for c in chunks)  # real symbols, not generic fallback


# ------------------------------------------------------------- concurrency
class _Echo(LLMProvider):
    """Returns an empty findings list; records how many calls overlapped."""

    def __init__(self) -> None:
        self.active = 0
        self.peak = 0
        self._lock = threading.Lock()
        self._barrier = threading.Barrier(2, timeout=2)

    name = property(lambda self: "echo")
    is_available = property(lambda self: True)
    default_model = "echo-1"

    def complete(self, messages, model, max_tokens=2048, temperature=0.0):
        with self._lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            self._barrier.wait()      # only passes if two calls are in flight together
        except threading.BrokenBarrierError:
            pass
        with self._lock:
            self.active -= 1
        return LLMResponse(content='{"findings": []}', model=model, provider="echo",
                           input_tokens=2, output_tokens=1)


def _chunk(i: int) -> CodeChunk:
    return CodeChunk(file_path=Path(f"f{i}.py"), language="python", symbol_name=f"fn{i}",
                     symbol_type="function", line_start=1, line_end=2, code="x = 1")


def test_auditor_overlaps_calls_and_counts_telemetry(monkeypatch) -> None:
    monkeypatch.setenv("AEGISSCAN_LLM_RPM", "6000")
    monkeypatch.setenv("AEGISSCAN_LLM_WORKERS", "4")
    provider = _Echo()
    pm = ProviderManager(providers=[provider])
    LLMAuditor(pm).analyze_chunks([_chunk(i) for i in range(8)], [], deep=True)
    assert provider.peak >= 2                     # calls really ran concurrently
    assert pm.requests_count == 8                 # no lost updates
    assert (pm.total_input_tokens, pm.total_output_tokens) == (16, 8)


def test_single_worker_is_sequential(monkeypatch) -> None:
    monkeypatch.setenv("AEGISSCAN_LLM_RPM", "6000")
    monkeypatch.setenv("AEGISSCAN_LLM_WORKERS", "1")
    provider = _Echo()
    provider._barrier = threading.Barrier(1)
    LLMAuditor(ProviderManager(providers=[provider])).analyze_chunks(
        [_chunk(i) for i in range(3)], [], deep=True)
    assert provider.peak == 1


def test_manager_counters_thread_safe(monkeypatch) -> None:
    monkeypatch.setenv("AEGISSCAN_LLM_RPM", "60000")
    provider = _Echo()
    provider._barrier = threading.Barrier(1)
    pm = ProviderManager(providers=[provider])
    threads = [threading.Thread(target=lambda: [pm.complete([{"role": "user", "content": "x"}])
                                                for _ in range(25)]) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert pm.requests_count == 200


# ------------------------------------------- optimizer precision / recall
# ground truth: (file, line-of-flagged-statement, rule prefix)
_EXPECTED = {
    ("orders.py", "Database call inside loop"),
    ("orders.py", "String concatenation in loop"),
    ("orders.py", "Nested loop over same collection"),
    ("orders.py", "Regex pattern re-resolved in loop"),
    ("reports.py", "Network call inside loop"),
    ("reports.py", "String concatenation in loop"),
    ("reports.py", "Database call inside loop"),
    ("reports.py", "Nested loop over same collection"),
}


def test_optimizer_precision_and_recall() -> None:
    found = {
        (f.file_path.name, f.issue_type.split(" (")[0])
        for f in run_optimizer(EXAMPLES / "slow_python")
    }
    tp = len(found & _EXPECTED)
    precision = tp / len(found) if found else 1.0
    recall = tp / len(_EXPECTED)
    assert precision == 1.0, f"false positives: {found - _EXPECTED}"
    assert recall == 1.0, f"missed: {_EXPECTED - found}"


def test_optimizer_no_false_positives_on_lookalikes() -> None:
    assert run_optimizer(EXAMPLES / "tricky_clean_python") == []


# -------------------------------------- live providers (opt-in, need keys)
_PROMPT = [{"role": "user", "content": 'Reply with exactly: {"findings": []}'}]


@pytest.mark.skipif(not os.environ.get("GROQ_API_KEY"), reason="GROQ_API_KEY not set")
def test_live_groq_roundtrip() -> None:
    out = GroqProvider().complete(_PROMPT)
    assert out.content and out.provider == "groq"


# ------------------------------------------------- groq model failover
def test_groq_skips_retired_models(monkeypatch) -> None:
    monkeypatch.setenv("GROQ_API_KEY", "test")
    monkeypatch.delenv("AEGISSCAN_GROQ_MODELS", raising=False)
    calls: list[str] = []

    class _Completions:
        def create(self, model, **_):
            calls.append(model)
            if model != "openai/gpt-oss-120b":
                raise RuntimeError("Error code: 404 - model_not_found")
            msg = type("M", (), {"content": "ok"})()
            usage = type("U", (), {"prompt_tokens": 1, "completion_tokens": 1})()
            return type("R", (), {"choices": [type("C", (), {"message": msg})()],
                                  "usage": usage, "model": model})()

    fake = type("Client", (), {"chat": type("Chat", (), {"completions": _Completions()})(),
                               "api_key": "test"})()
    provider = GroqProvider()
    monkeypatch.setattr(provider, "_get_client", lambda: fake)
    out = provider.complete([{"role": "user", "content": "x"}])
    assert out.content == "ok" and out.model == "openai/gpt-oss-120b"
    assert calls == ["openai/gpt-oss-20b", "openai/gpt-oss-120b"]


def test_groq_models_env_override(monkeypatch) -> None:
    monkeypatch.setenv("GROQ_API_KEY", "test")
    monkeypatch.setenv("AEGISSCAN_GROQ_MODELS", "my/model-a, my/model-b")
    assert GroqProvider().default_model == "my/model-a"


# ------------------------------------------------- SARIF + history batching
def _finding(i: int = 1) -> Finding:
    return Finding(file_path=Path("main.py"), issue_type="Command Injection", category="injection",
                   severity=Severity.HIGH, confidence=0.9, line_start=i, line_end=i,
                   evidence="os.system(x)", explanation="bad", rule_source="bandit")


def test_sarif_report_structure_and_duration(tmp_path: Path) -> None:
    import json

    from scanner.models.scan import ScanResult
    from scanner.reporting.sarif_report import generate_sarif

    result = ScanResult(target_path=tmp_path, scan_duration_seconds=3.5, findings=[_finding()])
    out = tmp_path / "r.sarif"
    generate_sarif(result, out)
    doc = json.loads(out.read_text(encoding="utf-8"))
    run = doc["runs"][0]
    assert doc["version"] == "2.1.0"
    assert len(run["results"]) == 1
    assert run["invocations"][0]["properties"]["duration_seconds"] == 3.5
    assert "your-org" not in out.read_text(encoding="utf-8")


def test_history_records_many_findings_in_one_batch(tmp_path: Path) -> None:
    import sqlite3

    from scanner.models.scan import ScanResult
    from scanner.storage.history import ScanHistoryDB

    db_file = tmp_path / "h.db"
    result = ScanResult(target_path=tmp_path, findings=[_finding(i) for i in range(1, 51)])
    ScanHistoryDB(db_path=db_file).record_scan(result)
    with sqlite3.connect(db_file) as conn:
        assert conn.execute("SELECT COUNT(*) FROM scan_findings").fetchone()[0] == 50
