"""Coverage for scanner/ingestion/git_diff.py and scanner/llm/patcher.py.

git_diff: happy paths run against a real throw-away git repo; error paths are mocked.
patcher: the LLM path uses the real LLMResponse type (the older V8 test hands the patcher
a tuple, which raises inside the try block and silently exercises only the fallback).
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from scanner.ingestion import git_diff
from scanner.ingestion.git_diff import get_changed_files
from scanner.llm import patcher
from scanner.llm.patcher import generate_patch_for_finding
from scanner.models.finding import Finding, Severity
from scanner.providers.base import LLMResponse

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


# ------------------------------------------------------------------ git_diff
def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com",
         "-c", "commit.gpgsign=false", *args],
        cwd=repo, check=True, capture_output=True,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q")
    (tmp_path / "tracked.py").write_text("x = 1\n")
    (tmp_path / "old_name.py").write_text("y = 2\n")
    (tmp_path / "gone.py").write_text("z = 3\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-q", "-m", "init")
    return tmp_path


@needs_git
def test_changed_files_reports_modified_untracked_staged_and_renamed(repo: Path) -> None:
    (repo / "tracked.py").write_text("x = 2\n")            # unstaged modification
    (repo / "untracked.py").write_text("u = 1\n")           # untracked
    (repo / "staged.py").write_text("s = 1\n")
    _git(repo, "add", "staged.py")                          # staged new file
    _git(repo, "mv", "old_name.py", "new_name.py")          # rename: 'R  old -> new'
    (repo / "gone.py").unlink()                             # deleted: must not be reported

    changed = get_changed_files(repo)

    assert changed == {
        (repo / n).resolve() for n in ("tracked.py", "untracked.py", "staged.py", "new_name.py")
    }


@needs_git
def test_changed_files_clean_repo_is_empty_set_not_none(repo: Path) -> None:
    assert get_changed_files(repo) == set()


def _fake_run(outputs: dict[str, subprocess.CompletedProcess]):
    def run(cmd, **kwargs):
        return outputs[cmd[1]]
    return run


def _cp(returncode: int = 0, stdout: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr="")


def test_changed_files_outside_repo_returns_none(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(git_diff.subprocess, "run", _fake_run({"rev-parse": _cp(128)}))
    assert get_changed_files(tmp_path) is None


def test_changed_files_rev_parse_not_true_returns_none(monkeypatch, tmp_path: Path) -> None:
    # e.g. inside a bare repo / .git dir: rc 0 but the answer is "false"
    monkeypatch.setattr(git_diff.subprocess, "run", _fake_run({"rev-parse": _cp(0, "false\n")}))
    assert get_changed_files(tmp_path) is None


@pytest.mark.parametrize("exc", [FileNotFoundError("git"), subprocess.TimeoutExpired("git", 5), OSError("boom")])
def test_changed_files_git_failure_returns_none(monkeypatch, tmp_path: Path, exc: Exception) -> None:
    def boom(cmd, **kwargs):
        raise exc
    monkeypatch.setattr(git_diff.subprocess, "run", boom)
    assert get_changed_files(tmp_path) is None


def test_changed_files_skips_blank_lines_missing_paths_and_failed_commands(monkeypatch, tmp_path: Path) -> None:
    real = tmp_path / "real.py"
    real.write_text("a = 1\n")
    outputs = {
        "rev-parse": _cp(0, "true\n"),
        "status": _cp(0, "\n?? real.py\n M ghost.py\n"),     # blank line + file that does not exist
        "diff": _cp(0, "\nreal.py\nghost2.py\n"),            # duplicate of status + missing file
    }
    monkeypatch.setattr(git_diff.subprocess, "run", _fake_run(outputs))
    assert get_changed_files(tmp_path) == {real.resolve()}

    outputs["status"] = _cp(1)
    outputs["diff"] = _cp(1)
    assert get_changed_files(tmp_path) == set()             # failed commands degrade to "nothing changed"


# ------------------------------------------------------------------ patcher
def _finding(evidence: str, issue: str = "Some issue") -> Finding:
    return Finding(
        file_path=Path("src/app.py"),
        issue_type=issue,
        category="injection",
        severity=Severity.HIGH,
        confidence=0.9,
        line_start=7,
        line_end=7,
        evidence=evidence,
        explanation="why",
        rule_source="llm",
    )


class _PM:
    """Minimal ProviderManager stand-in returning a real LLMResponse."""

    def __init__(self, content: str | None = None, exc: Exception | None = None, available: bool = True):
        self.is_available = available
        self._content, self._exc = content, exc
        self.calls: list[dict] = []

    def complete(self, messages, **kwargs):
        self.calls.append({"messages": messages, **kwargs})
        if self._exc:
            raise self._exc
        return LLMResponse(content=self._content, model="m", provider="groq")


_DIFF = "--- a/src/app.py\n+++ b/src/app.py\n@@ -7 +7 @@\n-a\n+b"


@pytest.mark.parametrize(
    "raw",
    [_DIFF, f"```diff\n{_DIFF}\n```", f"```\n{_DIFF}\n```", f"  \n{_DIFF}\n  "],
    ids=["plain", "diff-fence", "bare-fence", "whitespace"],
)
def test_llm_patch_is_returned_with_fences_stripped(raw: str) -> None:
    pm = _PM(raw)
    assert generate_patch_for_finding(_finding("a"), pm) == _DIFF
    sent = pm.calls[0]
    assert sent["max_tokens"] == 1024
    assert sent["temperature"] == 0.1
    assert sent["messages"][0]["role"] == "system"
    user_prompt = sent["messages"][1]["content"]
    assert f"File: {Path('src/app.py')}" in user_prompt
    assert "```python\na\n```" in user_prompt          # the evidence is what gets sent for fixing


@pytest.mark.parametrize("pm", [
    _PM(exc=RuntimeError("provider down")),
    _PM(content=""),
    _PM(available=False),
    None,
], ids=["exception", "empty-content", "unavailable", "no-manager"])
def test_llm_failure_or_absence_falls_back_to_template(pm) -> None:
    out = generate_patch_for_finding(_finding("eval(x)"), pm)
    assert out is not None
    assert out.startswith("--- a/app.py\n+++ b/app.py\n@@ -7,1 +7,3 @@\n-eval(x)")
    if pm is not None and pm.is_available:
        assert len(pm.calls) == 1               # the LLM was tried before falling back


@pytest.mark.parametrize("evidence", ["", "   \n  "])
def test_blank_evidence_returns_none_even_with_provider(evidence: str) -> None:
    pm = _PM(_DIFF)
    assert generate_patch_for_finding(_finding(evidence), pm) is None
    assert pm.calls == []


@pytest.mark.parametrize(
    "evidence,issue,expected",
    [
        ("subprocess.run(cmd, shell=True)", "x", "+subprocess.run(cmd, shell=False)"),
        # os.system alone is NOT swapped: the branch only triggers when "subprocess" appears in the
        # line or issue type, so the os.system replace is unreachable on its own (known heuristic gap).
        ("os.system(cmd)", "x", "# Safe Remediation:"),
        ("run(cmd)", "Command injection via subprocess", "shlex.split"),          # issue_type mentions subprocess -> template
        ("subprocess.call(cmd)", "x", "shlex.split"),                             # nothing to swap -> template
        ("result = eval(user)", "x", "ast.literal_eval("),
        ("exec(code)", "x", "# exec disabled"),
        ("password = 'hunter2'", "x", "os.environ.get('APP_SECRET_KEY')"),
        ("API_KEY = 'abc'", "x", "os.environ.get('APP_SECRET_KEY')"),
        ("data = pickle.loads(blob)", "x", "json.loads(blob)"),
        ("something_else()", "x", "# Safe Remediation:"),
    ],
)
def test_fallback_patch_templates(evidence: str, issue: str, expected: str) -> None:
    out = patcher._generate_fallback_patch(_finding(evidence, issue))
    assert expected in out
    assert out.splitlines()[3] == f"-{evidence.splitlines()[0]}"   # original line is what gets removed
    assert out.splitlines()[0] == "--- a/app.py"


def test_fallback_uses_only_first_evidence_line() -> None:
    out = patcher._generate_fallback_patch(_finding("eval(a)\nprint('second')"))
    assert "second" not in out
