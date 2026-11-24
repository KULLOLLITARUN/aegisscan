"""CI audit step: --changed-since, exclude_dirs for every tool, and the gitleaks:allow marker."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

import main
import scanner.static_analysis.gitleaks_runner as gitleaks_runner
import scanner.static_analysis.runner as tool_runner
import scanner.static_analysis.semgrep_runner as semgrep_runner
from scanner.ingestion.git_diff import get_changed_files
from scanner.models.finding import Finding

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def _git(repo: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", *args],
        cwd=repo, check=True, capture_output=True, text=True,
    )
    return out.stdout


def _commit(repo: Path, message: str) -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)


def _names(files: set[Path] | None) -> set[str]:
    assert files is not None
    return {p.name for p in files}


@pytest.fixture
def repo(tmp_path: Path, monkeypatch) -> Path:
    # the temp dir can sit under a parent repository; keep git from looking above it
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path.parent))
    _git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "old.py").write_text("x = 1\n")
    (tmp_path / "keep.py").write_text("x = 1\n")
    _commit(tmp_path, "first")
    (tmp_path / "keep.py").write_text("x = 2\n")
    (tmp_path / "new.py").write_text("y = 1\n")
    _commit(tmp_path, "second")
    return tmp_path


# ----------------------------------------------------------------------------- git_diff
@needs_git
def test_clean_checkout_sees_nothing_without_since_but_the_commit_with_it(repo: Path) -> None:
    assert _names(get_changed_files(repo)) == set()
    assert _names(get_changed_files(repo, "HEAD~1")) == {"keep.py", "new.py"}


@needs_git
def test_since_also_includes_uncommitted_and_untracked_files(repo: Path) -> None:
    (repo / "old.py").write_text("x = 99\n")
    (repo / "fresh.py").write_text("z = 1\n")
    assert _names(get_changed_files(repo, "HEAD~1")) == {"keep.py", "new.py", "old.py", "fresh.py"}


@needs_git
def test_since_skips_files_deleted_since_the_ref(repo: Path) -> None:
    (repo / "keep.py").unlink()
    _commit(repo, "delete")
    assert _names(get_changed_files(repo, "HEAD~2")) == {"new.py"}


@needs_git
def test_since_compares_against_the_merge_base_like_a_pull_request(repo: Path) -> None:
    _git(repo, "checkout", "-q", "-b", "feature")
    (repo / "feature.py").write_text("f = 1\n")
    _commit(repo, "feature work")
    _git(repo, "checkout", "-q", "main")
    (repo / "main_only.py").write_text("m = 1\n")
    _commit(repo, "main moves on")
    _git(repo, "checkout", "-q", "feature")
    # main gained main_only.py after the branch point; the pull request did not change it
    assert _names(get_changed_files(repo, "main")) == {"feature.py"}


@needs_git
@pytest.mark.parametrize("ref", ["no-such-branch", "0" * 40, "--output=/tmp/x", "-h"])
def test_unusable_since_ref_means_scan_everything_not_nothing(repo: Path, ref: str) -> None:
    assert get_changed_files(repo, ref) is None


@needs_git
def test_since_in_a_subfolder_reports_only_files_inside_it(repo: Path) -> None:
    sub = repo / "pkg"
    sub.mkdir()
    (sub / "inner.py").write_text("i = 1\n")
    _commit(repo, "add pkg")
    assert _names(get_changed_files(sub, "HEAD~1")) == {"inner.py"}


@needs_git
def test_since_outside_a_git_repo_returns_none(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path.parent))
    assert get_changed_files(tmp_path, "HEAD~1") is None


# ----------------------------------------------------------------------------- main / CLI
def test_cli_parses_changed_since() -> None:
    args = main._build_parser().parse_args([".", "--changed-since", "origin/main"])
    assert args.changed_since == "origin/main" and args.changed_only is False
    assert main._build_parser().parse_args(["."]).changed_since is None


@needs_git
def test_run_with_changed_since_scans_only_what_changed_on_a_clean_tree(repo: Path, monkeypatch) -> None:
    scopes: list[list[str] | None] = []

    def fake_tools(target, progress=None, only_files=None, privacy="standard"):
        scopes.append(None if only_files is None else sorted(Path(f).name for f in only_files))
        return [], []

    monkeypatch.setattr(main, "run_all_tools", fake_tools)

    main.run(repo, static_only=True, record_history=False, changed_since="HEAD~1")   # implies scoping
    main.run(repo, static_only=True, record_history=False, changed_only=True)        # clean tree: nothing
    main.run(repo, static_only=True, record_history=False, changed_since="no-such-ref")  # unknown: everything

    assert scopes == [["keep.py", "new.py"], [], None]


# ----------------------------------------------------------------------------- semgrep
def _fake_semgrep(monkeypatch) -> list[list[str]]:
    calls: list[list[str]] = []

    def fake_run(cmd, timeout_s=None, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({"results": []}), stderr="")

    monkeypatch.setattr(semgrep_runner, "_find_tool", lambda name: "semgrep")
    monkeypatch.setattr(semgrep_runner, "_run_bounded", fake_run)
    return calls


def test_semgrep_gets_an_exclude_flag_per_excluded_directory(tmp_path: Path, monkeypatch) -> None:
    calls = _fake_semgrep(monkeypatch)
    semgrep_runner.run_semgrep(tmp_path, exclude_dirs=frozenset({"tests", "examples"}))
    cmd = calls[0]
    assert [cmd[i + 1] for i, a in enumerate(cmd) if a == "--exclude"] == ["examples", "tests"]
    assert cmd[-1] == str(tmp_path)


def test_semgrep_without_exclusions_has_no_exclude_flag(tmp_path: Path, monkeypatch) -> None:
    calls = _fake_semgrep(monkeypatch)
    semgrep_runner.run_semgrep(tmp_path)
    assert "--exclude" not in calls[0]


# ----------------------------------------------------------------------------- gitleaks
_SECRET = "password = 'hunter2hunter2'\n"


@pytest.fixture
def secrets_tree(tmp_path: Path) -> Path:
    for rel in ("src/app.py", "tests/t.py", "deep/tests/t2.py", "mytests/ok.py"):
        f = tmp_path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(_SECRET, encoding="utf-8")
    return tmp_path


def _rels(findings: list[Finding], root: Path) -> set[str]:
    return {f.file_path.resolve().relative_to(root.resolve()).as_posix() for f in findings}


def test_builtin_scanner_skips_excluded_directory_names_at_any_depth(secrets_tree: Path, monkeypatch) -> None:
    monkeypatch.setattr(gitleaks_runner, "_find_tool", lambda name: None)
    found = gitleaks_runner.run_gitleaks(secrets_tree, exclude_dirs=frozenset({"tests"}))
    assert _rels(found, secrets_tree) == {"src/app.py", "mytests/ok.py"}   # "mytests" is a different name


def test_without_exclusions_everything_is_scanned(secrets_tree: Path, monkeypatch) -> None:
    monkeypatch.setattr(gitleaks_runner, "_find_tool", lambda name: None)
    assert len(_rels(gitleaks_runner.run_gitleaks(secrets_tree), secrets_tree)) == 4


def test_binary_findings_in_excluded_directories_are_dropped(secrets_tree: Path, monkeypatch) -> None:
    def item(rel: str):
        return gitleaks_runner._normalize(
            {"File": str(secrets_tree / rel), "StartLine": 1, "Description": "d", "RuleID": "r"}
        )

    monkeypatch.setattr(gitleaks_runner, "_find_tool", lambda name: "gitleaks")
    monkeypatch.setattr(
        gitleaks_runner, "_run_gitleaks_binary", lambda b, t: [item("src/app.py"), item("tests/t.py")]
    )
    found = gitleaks_runner.run_gitleaks(secrets_tree, exclude_dirs=frozenset({"tests"}))
    # tests/t.py (binary) and the built-in scanner's tests/ hits are gone; mytests/ stays
    assert _rels(found, secrets_tree) == {"src/app.py", "mytests/ok.py"}


def test_file_list_drops_excluded_files_and_skips_everything_if_none_remain(secrets_tree: Path, monkeypatch) -> None:
    monkeypatch.setattr(gitleaks_runner, "_find_tool", lambda name: "gitleaks")
    monkeypatch.setattr(gitleaks_runner, "_run_gitleaks_binary", lambda *a: pytest.fail("binary was started"))
    assert gitleaks_runner.run_gitleaks(
        secrets_tree, files=[secrets_tree / "tests" / "t.py"], exclude_dirs=frozenset({"tests"})
    ) == []


def test_gitleaks_allow_marker_silences_that_line_only(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(gitleaks_runner, "_find_tool", lambda name: None)
    (tmp_path / "m.py").write_text(
        "password = 'hunter2hunter2'  # gitleaks:allow\n"
        "password = 'hunter3hunter3'  # GITLEAKS:ALLOW\n"
        "password = 'hunter4hunter4'\n",
        encoding="utf-8",
    )
    assert [f.line_start for f in gitleaks_runner.run_gitleaks(tmp_path)] == [3]


def test_the_scanners_own_pem_header_pattern_is_not_reported() -> None:
    """Scanning this repo's gitleaks_runner.py used to raise a critical finding on its own regex."""
    src = Path(gitleaks_runner.__file__)
    assert gitleaks_runner._run_python_secret_scanner(src.parent, [src]) == []


# ----------------------------------------------------------------------------- orchestrator
def test_full_scan_passes_exclude_dirs_to_semgrep_and_gitleaks(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / ".aegisscan.toml").write_text('exclude_dirs = ["tests", "examples"]\n', encoding="utf-8")
    seen: dict[str, tuple] = {}

    def spy(name):
        def fn(*a, **k):
            seen[name] = a
            return []
        return fn

    for name in ("run_bandit", "run_semgrep", "run_gitleaks", "run_optimizer"):
        monkeypatch.setattr(tool_runner, name, spy(name))

    tool_runner.run_all_tools(tmp_path)

    want = frozenset({"tests", "examples"})
    assert seen["run_semgrep"][2] == want
    assert seen["run_gitleaks"][2] == want


def test_a_finding_in_an_excluded_directory_is_not_reported_end_to_end(tmp_path: Path, monkeypatch) -> None:
    """Same project, same tool outputs; only the config differs."""
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "t.py").write_text(_SECRET, encoding="utf-8")
    (tmp_path / "app.py").write_text(_SECRET, encoding="utf-8")
    monkeypatch.setattr(gitleaks_runner, "_find_tool", lambda name: None)
    for name in ("run_semgrep", "run_bandit", "run_optimizer"):
        monkeypatch.setattr(tool_runner, name, lambda *a, **k: [])

    before, _ = tool_runner.run_all_tools(tmp_path)
    (tmp_path / ".aegisscan.toml").write_text('exclude_dirs = ["tests"]\n', encoding="utf-8")
    after, _ = tool_runner.run_all_tools(tmp_path)

    assert {f.file_path.name for f in before} == {"t.py", "app.py"}
    assert {f.file_path.name for f in after} == {"app.py"}
