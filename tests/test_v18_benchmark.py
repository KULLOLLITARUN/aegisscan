"""Labelled benchmark: evaluator maths, manifest sanity, real-pipeline regression gate,
and JSON-validity telemetry for the LLM pass."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scanner.evaluation.benchmark import (
    BenchmarkRunner,
    Label,
    LabelManifest,
    _llm_summary,
    calibration_bins,
    evaluate,
    load_manifest,
)
from scanner.llm.auditor import LLMAuditor
from scanner.models.chunk import CodeChunk
from scanner.models.finding import Finding, Severity
from scanner.providers.base import LLMProvider, LLMResponse
from scanner.providers.manager import ProviderManager

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples" / "benchmark_labels.json"
STATIC_TOOLS = {"bandit", "gitleaks", "aegis-opt"}


def _finding(path: str, line: int, *, source: str = "bandit", confidence: float = 0.8, end: int | None = None) -> Finding:
    return Finding(
        file_path=Path(path), issue_type="x", category="injection", severity=Severity.HIGH,
        confidence=confidence, line_start=line, line_end=end or line, evidence="e",
        explanation="e", rule_source=source,
    )


def _manifest(tolerance: int = 1) -> LabelManifest:
    return LabelManifest(
        files={
            "a.py": [
                Label("a.py", 10, 12, "injection", frozenset({"bandit"})),
                Label("a.py", 30, 30, "secrets", frozenset({"gitleaks"})),
                Label("a.py", 50, 50, "logic", frozenset({"llm"})),        # only an LLM could catch it
            ],
            "clean.py": [],
        },
        line_tolerance=tolerance,
    )


# --------------------------------------------------------------------- evaluator maths
def test_true_positive_false_positive_and_recall_scopes(tmp_path: Path) -> None:
    findings = [_finding("a.py", 11), _finding("a.py", 40)]            # TP, FP
    m = evaluate(findings, _manifest(), tmp_path, STATIC_TOOLS)
    assert (m.true_positives, m.false_positives) == (1, 1)
    assert m.precision == 0.5
    assert m.labels_total == 3 and m.labels_in_scope == 2
    assert m.recall == 0.5                       # 1 of 2 in-scope labels (LLM-only label excluded)
    assert m.recall_all == pytest.approx(1 / 3)
    assert m.false_negatives == 1
    assert any("a.py:30" in item for item in m.missed) and not any("a.py:50" in i for i in m.missed)
    assert any("a.py:40" in item for item in m.false_positive_items)


def test_llm_label_enters_scope_when_llm_is_active(tmp_path: Path) -> None:
    m = evaluate([], _manifest(), tmp_path, STATIC_TOOLS | {"llm"})
    assert m.labels_in_scope == 3 and m.recall == 0.0


def test_line_tolerance_and_range_overlap(tmp_path: Path) -> None:
    near = evaluate([_finding("a.py", 9)], _manifest(1), tmp_path, STATIC_TOOLS)          # 1 above range
    far = evaluate([_finding("a.py", 8)], _manifest(1), tmp_path, STATIC_TOOLS)
    spans = evaluate([_finding("a.py", 5, end=40)], _manifest(0), tmp_path, STATIC_TOOLS)  # spans two labels
    assert near.true_positives == 1 and far.true_positives == 0
    assert spans.true_positives == 1 and spans.labels_matched == 2


def test_several_findings_on_one_label_count_once_for_recall(tmp_path: Path) -> None:
    findings = [_finding("a.py", 10), _finding("a.py", 11, source="llm")]
    m = evaluate(findings, _manifest(), tmp_path, STATIC_TOOLS)
    assert m.true_positives == 2 and m.labels_matched == 1


def test_clean_file_findings_and_false_positive_rate(tmp_path: Path) -> None:
    m = evaluate([_finding("clean.py", 3)], _manifest(), tmp_path, STATIC_TOOLS)
    assert m.clean_findings == 1 and m.clean_files == 1 and m.clean_files_flagged == 1
    assert m.false_positive_rate == 1.0
    assert evaluate([], _manifest(), tmp_path, STATIC_TOOLS).false_positive_rate == 0.0


def test_files_outside_manifest_and_outside_base_are_ignored(tmp_path: Path) -> None:
    findings = [_finding("unlisted.py", 1), _finding(str(tmp_path.parent / "elsewhere.py"), 1)]
    m = evaluate(findings, _manifest(), tmp_path, STATIC_TOOLS)
    assert m.true_positives == m.false_positives == 0 and m.precision == 1.0


def test_absolute_paths_resolve_against_base(tmp_path: Path) -> None:
    m = evaluate([_finding(str(tmp_path / "a.py"), 10)], _manifest(), tmp_path, STATIC_TOOLS)
    assert m.true_positives == 1


def test_per_source_and_per_category_breakdowns(tmp_path: Path) -> None:
    findings = [_finding("a.py", 10), _finding("a.py", 99, source="semgrep"), _finding("a.py", 30, source="gitleaks")]
    m = evaluate(findings, _manifest(), tmp_path, STATIC_TOOLS)
    assert m.per_source["bandit"] == {"findings": 1, "true_positives": 1, "precision": 1.0}
    assert m.per_source["semgrep"]["precision"] == 0.0
    assert m.per_category_recall["injection"]["recall"] == 1.0
    assert m.per_category_recall["secrets"]["matched"] == 1
    assert "logic" not in m.per_category_recall            # out of scope


def test_f1_and_empty_inputs(tmp_path: Path) -> None:
    empty = evaluate([], LabelManifest(files={}), tmp_path, STATIC_TOOLS)
    assert (empty.precision, empty.recall, empty.recall_all) == (1.0, 1.0, 1.0)
    m = evaluate([_finding("a.py", 10), _finding("a.py", 99)], _manifest(), tmp_path, STATIC_TOOLS)
    assert m.f1_score == pytest.approx(2 * m.precision * m.recall / (m.precision + m.recall))


# --------------------------------------------------------------------- calibration
def test_perfectly_calibrated_points_have_zero_ece() -> None:
    points = [(0.8, True)] * 4 + [(0.8, False)]
    bins, ece, brier = calibration_bins(points)
    assert len(bins) == 1 and bins[0].accuracy == 0.8 and bins[0].mean_confidence == 0.8
    assert ece == 0.0
    assert brier == pytest.approx(0.16)


def test_overconfidence_is_measured() -> None:
    bins, ece, brier = calibration_bins([(0.95, False)] * 4)
    assert bins[0].accuracy == 0.0 and ece == pytest.approx(0.95) and brier == pytest.approx(0.9025)


def test_bin_edges_and_empty_input() -> None:
    bins, _, _ = calibration_bins([(0.5, True), (0.49, True), (1.0, True), (0.9, True)])
    assert [(b.low, b.count) for b in bins] == [(0.0, 1), (0.5, 1), (0.9, 2)]
    assert calibration_bins([]) == ([], 0.0, 0.0)


# --------------------------------------------------------------------- manifest sanity
def test_manifest_is_well_formed_and_matches_files_on_disk() -> None:
    manifest = load_manifest(MANIFEST)
    assert len(manifest.files) >= 30 and len(manifest.labels) >= 80
    known_tools = {"bandit", "semgrep", "gitleaks", "aegis-opt", "llm"}
    for rel, labels in manifest.files.items():
        path = ROOT / "examples" / rel
        assert path.is_file(), rel
        n_lines = len(path.read_text(encoding="utf-8").splitlines())
        for lab in labels:
            assert 1 <= lab.line_start <= lab.line_end <= n_lines, (rel, lab)
            assert lab.expected_by and lab.expected_by <= known_tools, (rel, lab)
            assert lab.note and lab.category, (rel, lab)


def test_manifest_has_both_clean_and_vulnerable_files_and_all_directories_exist() -> None:
    manifest = load_manifest(MANIFEST)
    assert sum(1 for labs in manifest.files.values() if not labs) >= 10
    assert sum(1 for labs in manifest.files.values() if labs) >= 15
    for d in manifest.directories:
        assert (ROOT / "examples" / d).is_dir(), d


def test_load_manifest_parses_fields(tmp_path: Path) -> None:
    p = tmp_path / "m.json"
    p.write_text(json.dumps({
        "line_tolerance": 3,
        "files": [{"path": "d/x.py", "labels": [{"lines": [2, 4], "category": "c", "expected_by": ["bandit"], "note": "n"}]},
                  {"path": "d/y.py"}],
    }), encoding="utf-8")
    m = load_manifest(p)
    assert m.line_tolerance == 3 and m.directories == ["d"]
    assert m.files["d/x.py"][0] == Label("d/x.py", 2, 4, "c", frozenset({"bandit"}), "n")
    assert m.files["d/y.py"] == []


# --------------------------------------------------------------------- real pipeline gate
@pytest.fixture(scope="module")
def real_metrics():
    """Run the real static pipeline over the labelled corpus with Semgrep stubbed out
    (it needs the network), so the numbers are deterministic."""
    import scanner.static_analysis.runner as tool_runner

    original = tool_runner.run_semgrep
    tool_runner.run_semgrep = lambda *a, **k: []
    try:
        runner = BenchmarkRunner(root_dir=ROOT, active_sources=STATIC_TOOLS)
        yield runner, runner.run_benchmark(static_only=True)
    finally:
        tool_runner.run_semgrep = original


def test_pipeline_meets_quality_gates(real_metrics) -> None:
    _, m = real_metrics
    assert m.labels_in_scope >= 60
    assert m.recall >= 0.95, f"missed: {m.missed}"
    assert m.precision >= 0.80, f"false positives: {m.false_positive_items}"
    assert m.expected_calibration_error <= 0.20 and m.brier_score <= 0.20
    assert m.total_duration_seconds >= 0.0 and m.llm is None


def test_pipeline_regression_distinct_nearby_findings_survive(real_metrics) -> None:
    """The deduplicator once collapsed SQLi/MD5/pickle hits a few lines apart."""
    _, m = real_metrics
    assert not any("vuln_sqli.py" in item for item in m.missed)
    assert not any("vuln_deserialize.py" in item for item in m.missed)
    assert not any("auth.py:25" in item for item in m.missed)


def test_pipeline_performance_and_secrets_are_fully_found(real_metrics) -> None:
    _, m = real_metrics
    assert m.per_category_recall["performance"]["recall"] == 1.0
    assert m.per_category_recall["secrets"]["recall"] == 1.0
    assert m.per_source["aegis-opt"]["precision"] == 1.0


def test_benchmark_does_not_write_history_databases(real_metrics) -> None:
    dbs = list((ROOT / "examples" / "benchmark_corpus").glob("*.db"))
    assert dbs == []


def test_report_and_json_output(real_metrics, capsys, tmp_path: Path) -> None:
    runner, m = real_metrics
    runner.print_report(m)
    out = capsys.readouterr().out
    for needle in ("BENCHMARK & CALIBRATION REPORT", "Precision", "Recall (in scope)", "Per-source precision",
                   "Per-category recall", "Confidence calibration", "ECE", "False positives"):
        assert needle in out
    dumped = json.loads(json.dumps(m.to_dict()))
    assert dumped["labels_total"] == m.labels_total and dumped["calibration"]


# --------------------------------------------------------------------- LLM telemetry
def _result(**kw):
    base = dict(llm_requests_count=0, llm_total_latency_seconds=0.0, llm_json_valid_count=0,
                llm_json_repaired_count=0, llm_json_failed_count=0, llm_chunks_analyzed=0, llm_rate_limit_hits=0)
    return SimpleNamespace(**{**base, **kw})


def test_llm_summary_none_without_requests() -> None:
    assert _llm_summary([_result()]) is None


def test_llm_summary_rates_and_latency() -> None:
    s = _llm_summary([
        _result(llm_requests_count=6, llm_total_latency_seconds=3.0, llm_json_valid_count=6, llm_chunks_analyzed=5),
        _result(llm_requests_count=4, llm_total_latency_seconds=5.0, llm_json_valid_count=1,
                llm_json_repaired_count=2, llm_json_failed_count=1, llm_chunks_analyzed=3, llm_rate_limit_hits=2),
    ])
    assert s["requests"] == 10 and s["latency_per_request_seconds"] == 0.8
    assert s["json_valid_first_try_rate"] == pytest.approx(7 / 10)
    assert s["json_valid_after_repair_rate"] == pytest.approx(9 / 10)
    assert s["json_failed"] == 1 and s["chunks_analyzed"] == 8 and s["rate_limit_hits"] == 2


class _Scripted(LLMProvider):
    """Returns queued responses in order."""

    name = property(lambda self: "scripted")
    is_available = property(lambda self: True)
    default_model = "s-1"

    def __init__(self, replies: list[str]) -> None:
        self._replies = list(replies)

    def complete(self, messages, model, max_tokens=2048, temperature=0.0):
        return LLMResponse(content=self._replies.pop(0), model=model, provider="scripted", input_tokens=1, output_tokens=1)


def _chunk() -> CodeChunk:
    return CodeChunk(file_path=Path("f.py"), language="python", symbol_name="fn", symbol_type="function",
                     line_start=1, line_end=2, code="x = 1")


def _audit(monkeypatch, replies: list[str]) -> LLMAuditor:
    monkeypatch.setenv("AEGISSCAN_LLM_RPM", "6000")
    monkeypatch.setenv("AEGISSCAN_LLM_WORKERS", "1")
    auditor = LLMAuditor(ProviderManager(providers=[_Scripted(replies)]))
    auditor.analyze_chunks([_chunk()], [], deep=True)
    return auditor


def test_auditor_counts_json_valid_first_try(monkeypatch) -> None:
    a = _audit(monkeypatch, ['{"findings": []}'])
    assert (a.json_valid_count, a.json_repaired_count, a.json_failed_count) == (1, 0, 0)


def test_auditor_counts_json_repaired(monkeypatch) -> None:
    a = _audit(monkeypatch, ["not json at all", '{"findings": []}'])
    assert (a.json_valid_count, a.json_repaired_count, a.json_failed_count) == (0, 1, 0)


def test_auditor_counts_json_failed(monkeypatch) -> None:
    a = _audit(monkeypatch, ["not json", "still not json"])
    assert (a.json_valid_count, a.json_repaired_count, a.json_failed_count) == (0, 0, 1)


def test_run_without_history_writes_no_database(tmp_path: Path, monkeypatch) -> None:
    import main

    db = tmp_path / "data" / "history.db"
    monkeypatch.setenv("AEGISSCAN_HISTORY_DB", str(db))
    target = tmp_path / "project"
    target.mkdir()
    monkeypatch.setattr(main, "run_all_tools", lambda *a, **k: ([], []))
    (target / "a.py").write_text("x = 1\n", encoding="utf-8")
    main.run(target, static_only=True, record_history=False)
    assert not db.exists()
    main.run(target, static_only=True)
    assert db.exists()
    # nothing is ever written into the folder that was scanned
    assert sorted(p.name for p in target.iterdir()) == ["a.py"]


def test_cli_accepts_benchmark_json_flag() -> None:
    from main import _build_parser

    args = _build_parser().parse_args(["--benchmark", "--benchmark-json", "out.json"])
    assert args.benchmark is True and args.benchmark_json == Path("out.json")
