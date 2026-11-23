"""Item 26: with the Gitleaks binary present, the built-in scanner still runs and the results
are merged, so installing Gitleaks never lowers secret recall."""
from __future__ import annotations

from pathlib import Path

import scanner.static_analysis.gitleaks_runner as gr


def _real(path: Path, start: int, end: int | None = None):
    return gr._normalize({
        "File": str(path), "StartLine": start, "EndLine": end or start,
        "Description": "AWS key", "RuleID": "aws-access-token", "Secret": "AKIA...",
    })


def _project(tmp_path: Path) -> Path:
    # line 1: an AWS key id (both tools find it); line 3: a generic password (only the built-in does)
    (tmp_path / "app.py").write_text(
        'KEY = "AKIAABCDEFGHIJKLMNOP"\n'
        "x = 1\n"
        'db_password = "hunter2hunter2"\n',
        encoding="utf-8",
    )
    return tmp_path


def test_builtin_findings_are_added_when_binary_misses_them(tmp_path, monkeypatch):
    root = _project(tmp_path)
    monkeypatch.setattr(gr, "_find_tool", lambda name: "gitleaks")
    monkeypatch.setattr(gr, "_run_gitleaks_binary", lambda b, t: [_real(root / "app.py", 1)])

    lines = sorted(f.line_start for f in gr.run_gitleaks(root))

    assert lines == [1, 3]  # line 1 once (not duplicated), line 3 from the built-in scanner


def test_binary_finding_wins_over_builtin_on_same_line(tmp_path, monkeypatch):
    root = _project(tmp_path)
    monkeypatch.setattr(gr, "_find_tool", lambda name: "gitleaks")
    monkeypatch.setattr(gr, "_run_gitleaks_binary", lambda b, t: [_real(root / "app.py", 1)])

    first = [f for f in gr.run_gitleaks(root) if f.line_start == 1]

    assert len(first) == 1 and first[0].issue_type == "AWS key"


def test_multiline_binary_finding_covers_builtin_lines_inside_it(tmp_path, monkeypatch):
    root = _project(tmp_path)
    monkeypatch.setattr(gr, "_find_tool", lambda name: "gitleaks")
    monkeypatch.setattr(gr, "_run_gitleaks_binary", lambda b, t: [_real(root / "app.py", 1, 3)])

    assert [f.line_start for f in gr.run_gitleaks(root)] == [1]


def test_empty_binary_result_still_yields_builtin_findings(tmp_path, monkeypatch):
    root = _project(tmp_path)
    monkeypatch.setattr(gr, "_find_tool", lambda name: "gitleaks")
    monkeypatch.setattr(gr, "_run_gitleaks_binary", lambda b, t: [])

    assert sorted(f.line_start for f in gr.run_gitleaks(root)) == [1, 3]


def test_binary_failure_falls_back_to_builtin(tmp_path, monkeypatch):
    root = _project(tmp_path)
    monkeypatch.setattr(gr, "_find_tool", lambda name: "gitleaks")
    monkeypatch.setattr(gr, "_run_gitleaks_binary", lambda b, t: None)

    assert sorted(f.line_start for f in gr.run_gitleaks(root)) == [1, 3]


def test_no_binary_uses_builtin_only(tmp_path, monkeypatch):
    root = _project(tmp_path)
    monkeypatch.setattr(gr, "_find_tool", lambda name: None)

    def boom(b, t):  # the binary path must not be touched
        raise AssertionError("binary should not run")

    monkeypatch.setattr(gr, "_run_gitleaks_binary", boom)

    assert sorted(f.line_start for f in gr.run_gitleaks(root)) == [1, 3]


def test_merge_keeps_findings_in_other_files(tmp_path):
    a, b = tmp_path / "a.py", tmp_path / "b.py"
    a.write_text("x\n", encoding="utf-8")
    b.write_text("x\n", encoding="utf-8")

    merged = gr._merge_secret_findings([_real(a, 1)], [_real(b, 1)])

    assert len(merged) == 2
