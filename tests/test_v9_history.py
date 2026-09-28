"""Tests for V9 Scan History & SQLite Persistence.

Covers:
  - schema.sql validation
  - ScanHistoryDB initialization and schema execution
  - record_scan & get_history queries
  - Score delta calculation
  - CLI --history flag
"""
from __future__ import annotations

from pathlib import Path

from main import _build_parser, _print_history
from scanner.models.finding import Finding, Severity
from scanner.models.scan import ScanResult
from scanner.storage.history import _SCHEMA_FILE, ScanHistoryDB


def test_schema_file_exists() -> None:
    assert _SCHEMA_FILE.exists()
    content = _SCHEMA_FILE.read_text(encoding="utf-8")
    assert "CREATE TABLE IF NOT EXISTS scans" in content
    assert "CREATE TABLE IF NOT EXISTS scan_findings" in content


def test_history_db_records_and_retrieves_scan(tmp_path: Path) -> None:
    db_file = tmp_path / "test_history.db"
    db = ScanHistoryDB(db_path=db_file)

    finding = Finding(
        file_path=Path("main.py"),
        issue_type="Command Injection",
        category="injection",
        severity=Severity.HIGH,
        confidence=0.9,
        line_start=5,
        line_end=5,
        evidence="os.system(user_cmd)",
        explanation="Untrusted command passed to os.system.",
        rule_source="bandit",
    )

    result = ScanResult(
        target_path=tmp_path,
        files_analyzed=10,
        files_discovered=12,
        security_score=85.5,
        optimization_score=95.0,
        findings=[finding],
    )

    scan_id = db.record_scan(result)
    assert scan_id == result.scan_id

    history = db.get_history(limit=5)
    assert len(history) == 1
    assert history[0]["security_score"] == 85.5
    assert history[0]["total_findings"] == 1
    assert history[0]["high_count"] == 1


def test_history_score_delta_calculation(tmp_path: Path) -> None:
    db_file = tmp_path / "test_delta.db"
    db = ScanHistoryDB(db_path=db_file)

    res1 = ScanResult(
        target_path=tmp_path,
        files_analyzed=5,
        files_discovered=5,
        security_score=70.0,
        optimization_score=80.0,
        findings=[],
    )
    res2 = ScanResult(
        target_path=tmp_path,
        files_analyzed=5,
        files_discovered=5,
        security_score=85.0,
        optimization_score=90.0,
        findings=[],
    )

    db.record_scan(res1)
    db.record_scan(res2)

    delta = db.get_latest_score_delta()
    assert delta is not None
    assert delta["security_delta"] == 15.0
    assert delta["optimization_delta"] == 10.0


def test_cli_parser_supports_history_flag() -> None:
    parser = _build_parser()
    args = parser.parse_args(["--history"])
    assert args.history is True


def test_print_history_runs_without_error(tmp_path: Path, capsys) -> None:
    _print_history(tmp_path)
    captured = capsys.readouterr()
    assert "No scan history found" in captured.out
