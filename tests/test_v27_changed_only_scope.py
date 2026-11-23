"""--changed-only makes the static tools read only the changed files (not the whole tree)."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import main
import scanner.static_analysis.bandit_runner as bandit_runner
import scanner.static_analysis.gitleaks_runner as gitleaks_runner
import scanner.static_analysis.optimization_runner as optimization_runner
import scanner.static_analysis.runner as tool_runner
import scanner.static_analysis.semgrep_runner as semgrep_runner
from scanner.static_analysis.scope import batches, within

_VULN = "import os\nos.system(input())\npassword = 'hunter2hunter2'\n"
_SLOW = "def f(db, ids):\n    out = []\n    for i in ids:\n        out.append(db.execute('select 1'))\n    return out\n"


@pytest.fixture
def tree(tmp_path: Path) -> dict[str, Path]:
    files = {
        "a": tmp_path / "a.py",
        "b": tmp_path / "b.py",
        "js": tmp_path / "web.js",
        "skipped": tmp_path / "node_modules" / "lib" / "x.py",
    }
    files["skipped"].parent.mkdir(parents=True)
    for p in files.values():
        p.write_text(_VULN, encoding="utf-8")
    (tmp_path / "slow.py").write_text(_SLOW, encoding="utf-8")
    return {k: v.resolve() for k, v in files.items()} | {"root": tmp_path.resolve()}


# ----------------------------------------------------------------------------- helpers
def test_within_keeps_files_under_target_and_drops_skipped_dirs(tmp_path: Path) -> None:
    keep = tmp_path / "src" / "a.py"
    out = [
        keep,
        tmp_path / "node_modules" / "x.py",
        tmp_path / "src" / ".venv" / "y.py",
        tmp_path.parent / "elsewhere.py",
    ]
    assert within(tmp_path, out, {"node_modules", ".venv"}) == [keep]


def test_batches_split_long_lists_and_keep_every_path(tmp_path: Path) -> None:
    paths = [tmp_path / ("x" * 200 + str(i) + ".py") for i in range(300)]
    groups = list(batches(paths))
    assert len(groups) > 1
    assert [p for g in groups for p in g] == [str(p) for p in paths]
    assert all(sum(len(p) + 1 for p in g) <= 20_000 for g in groups)
    assert list(batches([])) == []


# ----------------------------------------------------------------------------- bandit
def test_bandit_scans_only_the_given_python_files(tree) -> None:
    found = bandit_runner.run_bandit(tree["root"], files=[tree["a"]])
    assert {f.file_path.resolve() for f in found} == {tree["a"]}


def test_bandit_with_no_python_files_does_not_start(tree, monkeypatch) -> None:
    monkeypatch.setattr(bandit_runner.subprocess, "run", lambda *a, **k: pytest.fail("bandit was started"))
    assert bandit_runner.run_bandit(tree["root"], files=[tree["js"]]) == []
    assert bandit_runner.run_bandit(tree["root"], files=[]) == []


def test_bandit_splits_a_huge_file_list_across_runs(tmp_path: Path, monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({"results": []}), stderr="")

    monkeypatch.setattr(bandit_runner.subprocess, "run", fake_run)
    monkeypatch.setattr(bandit_runner, "_find_bandit", lambda: "bandit")
    files = [tmp_path / ("d" * 150 + f"{i}.py") for i in range(400)]

    bandit_runner.run_bandit(tmp_path, files=files)

    assert len(calls) > 1
    assert sorted(a for c in calls for a in c if a.endswith(".py")) == sorted(str(f) for f in files)
    assert all("-r" not in c for c in calls)


# ----------------------------------------------------------------------------- semgrep
def _fake_semgrep(monkeypatch) -> list[list[str]]:
    calls: list[list[str]] = []

    def fake_run(cmd, timeout_s=None, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({"results": []}), stderr="")

    monkeypatch.setattr(semgrep_runner, "_find_tool", lambda name: "semgrep")
    monkeypatch.setattr(semgrep_runner, "_run_bounded", fake_run)
    return calls


def test_semgrep_gets_the_files_not_the_directory(tmp_path: Path, monkeypatch) -> None:
    calls = _fake_semgrep(monkeypatch)
    a, b = tmp_path / "a.py", tmp_path / "b.js"

    semgrep_runner.run_semgrep(tmp_path, files=[a, b])

    assert len(calls) == 1
    assert calls[0][-2:] == [str(a), str(b)]
    assert str(tmp_path) not in calls[0][-2:]            # only the project root flag mentions the folder


def test_semgrep_without_files_still_scans_the_directory(tmp_path: Path, monkeypatch) -> None:
    calls = _fake_semgrep(monkeypatch)
    semgrep_runner.run_semgrep(tmp_path)
    assert calls[0][-1] == str(tmp_path)


def test_semgrep_with_empty_file_list_does_not_start(tmp_path: Path, monkeypatch) -> None:
    calls = _fake_semgrep(monkeypatch)
    assert semgrep_runner.run_semgrep(tmp_path, files=[]) == []
    assert calls == []


def test_semgrep_splits_a_huge_file_list(tmp_path: Path, monkeypatch) -> None:
    calls = _fake_semgrep(monkeypatch)
    files = [tmp_path / ("s" * 150 + f"{i}.py") for i in range(400)]
    semgrep_runner.run_semgrep(tmp_path, files=files)
    assert len(calls) > 1
    assert sum(1 for c in calls for a in c if a.endswith(".py")) == 400


# ----------------------------------------------------------------------------- gitleaks
def test_builtin_secret_scanner_reads_only_the_given_files(tree, monkeypatch) -> None:
    monkeypatch.setattr(gitleaks_runner, "_find_tool", lambda name: None)
    found = gitleaks_runner.run_gitleaks(tree["root"], files=[tree["b"]])
    assert {f.file_path.resolve() for f in found} == {tree["b"]}


def test_gitleaks_with_empty_file_list_does_nothing(tree, monkeypatch) -> None:
    monkeypatch.setattr(gitleaks_runner, "_find_tool", lambda name: "gitleaks")
    monkeypatch.setattr(gitleaks_runner, "_run_gitleaks_binary", lambda *a: pytest.fail("binary was started"))
    assert gitleaks_runner.run_gitleaks(tree["root"], files=[]) == []


def test_gitleaks_binary_runs_once_per_file_for_a_few_files(tree, monkeypatch) -> None:
    targets: list[Path] = []
    monkeypatch.setattr(gitleaks_runner, "_find_tool", lambda name: "gitleaks")
    monkeypatch.setattr(gitleaks_runner, "_run_gitleaks_binary", lambda b, t: targets.append(t) or [])
    gitleaks_runner.run_gitleaks(tree["root"], files=[tree["a"], tree["b"]])
    assert targets == [tree["a"], tree["b"]]


def test_gitleaks_uses_one_tree_run_for_many_files_and_keeps_only_wanted(tree, monkeypatch) -> None:
    root = tree["root"]
    wanted = [root / f"f{i}.py" for i in range(gitleaks_runner._MAX_PER_FILE_RUNS + 1)]
    for w in wanted:
        w.write_text("x = 1\n", encoding="utf-8")
    targets: list[Path] = []
    other = gitleaks_runner._normalize({"File": str(tree["a"]), "StartLine": 3, "Description": "d", "RuleID": "r"})
    mine = gitleaks_runner._normalize({"File": str(wanted[0]), "StartLine": 1, "Description": "d", "RuleID": "r"})

    def fake(bin_, target):
        targets.append(target)
        return [other, mine]

    monkeypatch.setattr(gitleaks_runner, "_find_tool", lambda name: "gitleaks")
    monkeypatch.setattr(gitleaks_runner, "_run_gitleaks_binary", fake)

    found = gitleaks_runner.run_gitleaks(root, files=wanted)

    assert targets == [root]
    assert [f.file_path for f in found] == [wanted[0]]


# ----------------------------------------------------------------------------- optimizer
def test_optimizer_analyzes_only_the_given_files(tree) -> None:
    slow = tree["root"] / "slow.py"
    assert optimization_runner.run_optimizer(tree["root"], files=[tree["a"]]) == []
    only = optimization_runner.run_optimizer(tree["root"], files=[slow])
    assert only and {f.file_path.resolve() for f in only} == {slow.resolve()}


# ----------------------------------------------------------------------------- orchestrator
# Position of the `files` argument in each tool's signature (the exclusions come before or after it).
_FILES_ARG = {"run_bandit": 2, "run_semgrep": 1, "run_gitleaks": 1, "run_optimizer": 2}


def test_run_all_tools_with_nothing_to_scan_starts_no_tool(tree, monkeypatch) -> None:
    for name in ("run_bandit", "run_semgrep", "run_gitleaks", "run_optimizer"):
        monkeypatch.setattr(tool_runner, name, lambda *a, **k: pytest.fail("a tool was started"))
    assert tool_runner.run_all_tools(tree["root"], only_files=[]) == ([], [])
    # files that are all inside skipped directories or outside the target count as nothing
    assert tool_runner.run_all_tools(tree["root"], only_files=[tree["skipped"], Path(__file__)]) == ([], [])


def test_run_all_tools_hands_each_tool_the_same_scoped_files(tree, monkeypatch) -> None:
    seen: dict[str, object] = {}
    for name in ("run_bandit", "run_semgrep", "run_gitleaks", "run_optimizer"):
        monkeypatch.setattr(tool_runner, name, lambda *a, _n=name, **k: seen.setdefault(_n, a[_FILES_ARG[_n]]) and [])

    tool_runner.run_all_tools(tree["root"], only_files=[tree["b"], tree["a"], tree["skipped"]])

    assert all(v == [tree["a"], tree["b"]] for v in seen.values()) and len(seen) == 4


def test_run_all_tools_without_scope_passes_none(tree, monkeypatch) -> None:
    seen: dict[str, object] = {}
    for name in ("run_bandit", "run_semgrep", "run_gitleaks", "run_optimizer"):
        monkeypatch.setattr(tool_runner, name, lambda *a, _n=name, **k: seen.setdefault(_n, ("called", a[_FILES_ARG[_n]])) and [])
    tool_runner.run_all_tools(tree["root"])
    assert all(v[1] is None for v in seen.values()) and len(seen) == 4


def test_changed_only_run_passes_just_the_changed_files_to_the_tools(tmp_path: Path, monkeypatch) -> None:
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"]
    for args in (["init", "-q"], ):
        subprocess.run([*git, *args], cwd=tmp_path, check=True, capture_output=True)
    (tmp_path / "old.py").write_text(_VULN)
    (tmp_path / "changed.py").write_text(_VULN)
    subprocess.run([*git, "add", "."], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run([*git, "commit", "-q", "-m", "i"], cwd=tmp_path, check=True, capture_output=True)
    (tmp_path / "changed.py").write_text(_VULN + "# touched\n")
    scopes: list[object] = []

    def fake(target, progress=None, only_files=None):
        scopes.append(None if only_files is None else sorted(Path(f).name for f in only_files))
        return [], []

    monkeypatch.setattr(main, "run_all_tools", fake)
    main.run(tmp_path, static_only=True, record_history=False, changed_only=True)
    main.run(tmp_path, static_only=True, record_history=False, changed_only=False)

    assert scopes == [["changed.py"], None]


def test_exclude_dirs_apply_to_all_four_tools(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / ".aegisscan.toml").write_text('exclude_dirs = ["tests"]\n', encoding="utf-8")
    (tmp_path / "tests").mkdir()
    inside, outside = (tmp_path / "tests" / "t.py").resolve(), (tmp_path / "app.py").resolve()
    for f in (inside, outside):
        f.write_text("x = 1\n", encoding="utf-8")
    seen: dict[str, object] = {}
    for name in ("run_bandit", "run_semgrep", "run_gitleaks", "run_optimizer"):
        monkeypatch.setattr(tool_runner, name, lambda *a, _n=name, **k: seen.setdefault(_n, a[_FILES_ARG[_n]]) and [])

    tool_runner.run_all_tools(tmp_path, only_files=[inside, outside])

    assert seen["run_bandit"] == seen["run_optimizer"] == seen["run_semgrep"] == seen["run_gitleaks"] == [outside]
