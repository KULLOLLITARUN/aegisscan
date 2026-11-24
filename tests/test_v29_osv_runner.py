"""OSV-Scanner runner: report parsing, scoped runs, exclusions, degradation, strict privacy."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from scanner.models.finding import Severity
from scanner.static_analysis import osv_runner
from scanner.static_analysis.osv_runner import is_lockfile, parse_report, run_osv
from scanner.static_analysis.runner import run_all_tools


def _report(lockfile: Path, score: str | None = "9.8") -> dict:
    return {"results": [{
        "source": {"path": str(lockfile), "type": "lockfile"},
        "packages": [{
            "package": {"name": "Django", "version": "3.0.0", "ecosystem": "PyPI"},
            "vulnerabilities": [
                {"id": "GHSA-aaaa", "aliases": ["CVE-2020-1"], "summary": "SQL injection in Django"},
                {"id": "PYSEC-1", "aliases": ["CVE-2020-1"], "summary": "dup"},
            ],
            "groups": [{"ids": ["GHSA-aaaa", "PYSEC-1"], "max_severity": score}],
        }],
    }]}


@pytest.fixture()
def project(tmp_path: Path) -> Path:
    (tmp_path / "requirements.txt").write_text("flask==2.0.0\nDjango==3.0.0\n", encoding="utf-8")
    return tmp_path


def _completed(payload: object, code: int = 1) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], code, stdout=json.dumps(payload), stderr="")


def test_parse_report_builds_one_finding_per_advisory_group(project: Path) -> None:
    findings = parse_report(_report(project / "requirements.txt"), project)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_source == "osv" and f.category == "dependencies"
    assert f.severity is Severity.CRITICAL
    assert f.line_start == 2 and "Django==3.0.0" in f.evidence
    assert "CVE-2020-1" in f.explanation and "GHSA-aaaa" in f.explanation
    assert "Upgrade Django" in (f.suggested_fix or "")


@pytest.mark.parametrize("score,expected", [
    ("9.0", Severity.CRITICAL), ("7.5", Severity.HIGH), ("5.0", Severity.MEDIUM),
    ("2.0", Severity.LOW), (None, Severity.MEDIUM), ("garbage", Severity.MEDIUM),
])
def test_severity_from_cvss(score: str | None, expected: Severity) -> None:
    assert osv_runner._severity(score, None) is expected


def test_severity_falls_back_to_advisory_label() -> None:
    assert osv_runner._severity(None, "moderate") is Severity.MEDIUM
    assert osv_runner._severity(None, "HIGH") is Severity.HIGH


def test_relative_source_path_resolves_against_target(project: Path) -> None:
    rep = _report(Path("requirements.txt"))
    assert parse_report(rep, project)[0].file_path == project / "requirements.txt"


@pytest.mark.parametrize("bad", [None, [], "x", {"results": None}, {"results": [{"packages": None}]}])
def test_parse_report_tolerates_odd_documents(bad: object, project: Path) -> None:
    assert parse_report(bad, project) == []


def test_missing_package_in_lockfile_falls_back_to_line_one(tmp_path: Path) -> None:
    lock = tmp_path / "requirements.txt"
    lock.write_text("other==1\n", encoding="utf-8")
    assert parse_report(_report(lock), tmp_path)[0].line_start == 1


def test_is_lockfile() -> None:
    assert is_lockfile(Path("a/Package-Lock.json")) and is_lockfile(Path("requirements.txt"))
    assert not is_lockfile(Path("main.py"))


def test_no_binary_means_no_findings(project: Path) -> None:
    with patch.object(osv_runner, "_find_tool", return_value=None):
        assert run_osv(project) == []


def test_full_scan_uses_recursive_and_parses(project: Path) -> None:
    with patch.object(osv_runner, "_find_tool", return_value="osv"), \
         patch("subprocess.run", return_value=_completed(_report(project / "requirements.txt"))) as run:
        out = run_osv(project)
    assert len(out) == 1
    cmd = run.call_args.args[0]
    assert cmd[:4] == ["osv", "scan", "source", "--format"] and "--recursive" in cmd


def test_scoped_scan_runs_only_for_changed_lockfiles(project: Path) -> None:
    py = project / "app.py"
    py.write_text("x = 1\n", encoding="utf-8")
    with patch.object(osv_runner, "_find_tool", return_value="osv"), patch("subprocess.run") as run:
        assert run_osv(project, [py]) == []
        run.assert_not_called()
    lock = project / "requirements.txt"
    with patch.object(osv_runner, "_find_tool", return_value="osv"), \
         patch("subprocess.run", return_value=_completed(_report(lock))) as run:
        out = run_osv(project, [py, lock])
    assert len(out) == 1 and run.call_count == 1 and "--lockfile" in run.call_args.args[0]


def test_many_changed_lockfiles_use_one_tree_run(tmp_path: Path) -> None:
    locks = []
    for i in range(osv_runner._MAX_PER_FILE_RUNS + 1):
        d = tmp_path / f"p{i}"
        d.mkdir()
        lf = d / "requirements.txt"
        lf.write_text("Django==3.0.0\n", encoding="utf-8")
        locks.append(lf)
    with patch.object(osv_runner, "_find_tool", return_value="osv"), \
         patch("subprocess.run", return_value=_completed(_report(locks[0]))) as run:
        out = run_osv(tmp_path, locks)
    assert run.call_count == 1 and len(out) == 1


def test_exclude_dirs_drops_findings(tmp_path: Path) -> None:
    d = tmp_path / "examples"
    d.mkdir()
    lf = d / "requirements.txt"
    lf.write_text("Django==3.0.0\n", encoding="utf-8")
    with patch.object(osv_runner, "_find_tool", return_value="osv"), \
         patch("subprocess.run", return_value=_completed(_report(lf))):
        assert run_osv(tmp_path, exclude_dirs=frozenset({"examples"})) == []
        assert run_osv(tmp_path, [lf], frozenset({"examples"})) == []


@pytest.mark.parametrize("exc", [subprocess.TimeoutExpired("osv", 1), FileNotFoundError(), OSError()])
def test_subprocess_failures_degrade(project: Path, exc: Exception) -> None:
    with patch.object(osv_runner, "_find_tool", return_value="osv"), patch("subprocess.run", side_effect=exc):
        assert run_osv(project) == []


def test_bad_json_and_empty_output_degrade(project: Path) -> None:
    bad = subprocess.CompletedProcess([], 1, stdout="not json", stderr="")
    nothing = subprocess.CompletedProcess([], 128, stdout="", stderr="no packages")
    crashed = subprocess.CompletedProcess([], 2, stdout="", stderr="boom")
    with patch.object(osv_runner, "_find_tool", return_value="osv"):
        for proc in (bad, nothing, crashed):
            with patch("subprocess.run", return_value=proc):
                assert run_osv(project) == []


def test_run_all_tools_includes_osv_and_strict_privacy_skips_it(project: Path) -> None:
    fake = parse_report(_report(project / "requirements.txt"), project)
    with patch("scanner.static_analysis.runner.run_osv", return_value=fake) as osv:
        _, tools = run_all_tools(project)
        assert "osv-scanner" in tools and osv.call_count == 1
        _, tools = run_all_tools(project, privacy="strict")
        assert "osv-scanner" not in tools and osv.call_count == 1  # not called again
