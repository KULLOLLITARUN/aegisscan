"""--changed-only end to end: the filter must apply to static findings, not just to chunking/LLM."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

import main
from scanner.ingestion.git_diff import get_changed_files
from scanner.models.finding import Finding, Severity

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

_BAD = "import os\nos.system(input())\n"


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", *args],
        cwd=repo, check=True, capture_output=True,
    )


def _finding_in(path: Path) -> Finding:
    return Finding(
        file_path=path, issue_type="Command injection", category="injection", severity=Severity.HIGH,
        confidence=0.9, line_start=2, line_end=2, evidence="os.system(input())", explanation="bad",
        rule_source="bandit",
    )


@pytest.fixture
def fake_tools(monkeypatch):
    """Static tools that flag every .py file under the target, like Bandit does for the whole tree."""
    def run_all_tools(target: Path, progress=None):
        return [_finding_in(p) for p in sorted(target.rglob("*.py"))], ["fake"]
    monkeypatch.setattr(main, "run_all_tools", run_all_tools)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q")
    (tmp_path / "old.py").write_text(_BAD)
    (tmp_path / "changed.py").write_text(_BAD)
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-q", "-m", "init")
    (tmp_path / "changed.py").write_text(_BAD + "# touched\n")
    return tmp_path


def _scan(path: Path, **kw):
    result, files, _ = main.run(path, static_only=True, record_history=False, **kw)
    return result, files


def _names(result) -> set[str]:
    return {f.file_path.name for f in result.findings}


def test_without_flag_reports_every_file(repo: Path, fake_tools) -> None:
    result, files = _scan(repo)
    assert _names(result) == {"old.py", "changed.py"}
    assert {f.path.name for f in files} == {"old.py", "changed.py"}


def test_changed_only_drops_static_findings_in_unchanged_files(repo: Path, fake_tools) -> None:
    # Regression: the filter used to apply only to chunking/LLM, so a PR that touched one file
    # was still blamed for every pre-existing static finding in the repo.
    result, files = _scan(repo, changed_only=True)
    assert _names(result) == {"changed.py"}
    assert {f.path.name for f in files} == {"changed.py"}


def test_changed_only_includes_untracked_and_staged_files(repo: Path, fake_tools) -> None:
    (repo / "new_untracked.py").write_text(_BAD)
    (repo / "new_staged.py").write_text(_BAD)
    _git(repo, "add", "new_staged.py")
    result, _ = _scan(repo, changed_only=True)
    assert _names(result) == {"changed.py", "new_untracked.py", "new_staged.py"}


def test_changed_only_on_clean_repo_scans_nothing(repo: Path, fake_tools) -> None:
    _git(repo, "checkout", "--", "changed.py")          # discard the edit: nothing differs from HEAD
    result, files = _scan(repo, changed_only=True)
    assert result.findings == []
    assert files == []


def test_changed_only_outside_a_git_repo_falls_back_to_full_scan(tmp_path: Path, fake_tools, monkeypatch) -> None:
    # The temp dir can sit under a parent repo (e.g. a home directory that is itself a git repo);
    # stop git searching above it so this really is "not a repository".
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path.parent))
    (tmp_path / "a.py").write_text(_BAD)
    (tmp_path / "b.py").write_text(_BAD)
    assert get_changed_files(tmp_path) is None
    result, _ = _scan(tmp_path, changed_only=True)
    assert _names(result) == {"a.py", "b.py"}           # unknown != nothing changed; never silently scan nothing


def test_repo_with_no_commits_uses_git_status_only(tmp_path: Path) -> None:
    # `git diff HEAD` fails when HEAD does not exist yet; untracked files must still be reported.
    _git(tmp_path, "init", "-q")
    (tmp_path / "first.py").write_text(_BAD)
    assert get_changed_files(tmp_path) == {(tmp_path / "first.py").resolve()}


def test_changed_only_flag_is_parsed() -> None:
    assert main._build_parser().parse_args([".", "--changed-only"]).changed_only is True
    assert main._build_parser().parse_args(["."]).changed_only is False
