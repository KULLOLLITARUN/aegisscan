"""Noise found by hand-labelling 70 findings on redash and spring-petclinic (docs/accuracy_eval)."""
from __future__ import annotations

from pathlib import Path

from scanner.intelligence.context import cap_ci_hygiene
from scanner.static_analysis.optimization_runner import run_optimizer
from tests.test_v14_progress import _make_finding

_DB = "db.session.execute(text(q))"


def _issues(tmp_path: Path, body: str) -> list[str]:
    (tmp_path / "m.py").write_text(body, encoding="utf-8")
    return [f.issue_type for f in run_optimizer(tmp_path, set(), None)]


def test_first_iterable_of_a_comprehension_is_not_a_loop_call(tmp_path: Path) -> None:
    body = f"def f(db, text, q):\n    return {{n: v for (n, v) in {_DB}}}\n"
    assert not [i for i in _issues(tmp_path, body) if "N+1" in i]


def test_call_in_the_comprehension_body_is_still_a_loop_call(tmp_path: Path) -> None:
    body = "def f(db, text, ids):\n    return [db.session.execute(text(i)) for i in ids]\n"
    assert any("Database call inside loop" in i for i in _issues(tmp_path, body))


def test_call_in_a_later_iterable_is_still_a_loop_call(tmp_path: Path) -> None:
    body = "def f(db, text, ids):\n    return [r for i in ids for r in db.session.execute(text(i))]\n"
    assert any("Database call inside loop" in i for i in _issues(tmp_path, body))


def _workflow(tmp_path: Path, uses: str) -> Path:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    path = wf / "ci.yml"
    path.write_text(f"steps:\n  - {uses}\n", encoding="utf-8")
    return path


def _pin_note(path: Path):
    f = _make_finding(path)
    return f.model_copy(update={
        "category": "best_practices", "rule_source": "semgrep", "line_start": 2, "line_end": 2,
        "explanation": "GitHub Actions step uses a mutable tag or branch reference.",
    })


def test_pin_note_for_a_github_owned_action_is_dropped(tmp_path: Path) -> None:
    path = _workflow(tmp_path, "uses: actions/checkout@v4")
    kept, _ = cap_ci_hygiene([_pin_note(path)], tmp_path)
    assert kept == []


def test_pin_note_for_a_third_party_action_is_kept(tmp_path: Path) -> None:
    path = _workflow(tmp_path, "uses: some-vendor/deploy-action@v1")
    kept, _ = cap_ci_hygiene([_pin_note(path)], tmp_path)
    assert len(kept) == 1
