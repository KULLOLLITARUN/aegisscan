"""ORM-aware and tighter N+1 heuristics for the Python optimizer (OPT001)."""
from __future__ import annotations

from pathlib import Path

import pytest

from scanner.static_analysis.optimization_runner import run_optimizer


def _scan(tmp_path: Path, body: str):
    (tmp_path / "m.py").write_text(body, encoding="utf-8")
    return run_optimizer(tmp_path)


def _loop(stmt: str) -> str:
    return f"def f(items):\n    for it in items:\n        {stmt}\n"


@pytest.mark.parametrize(
    "stmt,kind",
    [
        # Django ORM
        ("Order.objects.filter(user=it).count()", "Database"),
        ("Profile.objects.get(user_id=it.id)", "Database"),
        ("Order.objects.filter(user=it)", "Database"),
        ("self.model.objects.exists()", "Database"),
        # SQLAlchemy
        ("session.query(Order).filter_by(user_id=it.id).all()", "Database"),
        ("self.session.query(Order).first()", "Database"),
        ("db.session.query(Order).filter(Order.id == it).one()", "Database"),
        ("session.get(Order, it.id)", "Database"),
        ("session.scalars(select(Order))", "Database"),
        ("db_session.query(Order).count()", "Database"),
        # DB-API (unchanged)
        ("cur.execute('select 1')", "Database"),
        # network
        ("requests.get(url)", "Network"),
        ("httpx.post(endpoint, json=it)", "Network"),
        ("self.client.get(f'/users/{it}')", "Network"),
        ("session.get('https://api.example.com/x')", "Network"),
        ("client.post(api_url, json=it)", "Network"),
        ("urllib.request.urlopen(it.link_url)", "Network"),
        ("urlopen(url)", "Network"),
    ],
)
def test_flags_round_trip_in_loop(tmp_path: Path, stmt: str, kind: str) -> None:
    findings = _scan(tmp_path, _loop(stmt))
    assert len(findings) == 1, stmt
    assert findings[0].issue_type.startswith(f"{kind} call inside loop")
    assert findings[0].category == "performance"


@pytest.mark.parametrize(
    "stmt",
    [
        "parser.query(it)",                      # arbitrary .query() is not a DB call
        "search_index.query('a')",
        "session.get('user_id')",                # Flask-style session lookup
        "client.get(key)",                       # cache/dict-style lookup, no URL evidence
        "cache.get(it)",
        "d.get(it)",
        "self.objects.get(it)",                  # plain attribute called 'objects'
        "items.filter(it)",                      # no manager / session root
        "session.get(it)",                       # one positional arg, not (Model, pk)
        "results.all()",
    ],
)
def test_ignores_lookalikes_in_loop(tmp_path: Path, stmt: str) -> None:
    assert _scan(tmp_path, _loop(stmt)) == [], stmt


def test_orm_call_outside_loop_is_fine(tmp_path: Path) -> None:
    body = (
        "def f(ids):\n"
        "    rows = Order.objects.filter(id__in=ids)\n"
        "    return session.query(Order).all(), rows\n"
    )
    assert _scan(tmp_path, body) == []


def test_orm_call_in_comprehension_is_flagged_once(tmp_path: Path) -> None:
    body = "def f(users):\n    return [Order.objects.filter(user=u).count() for u in users]\n"
    findings = _scan(tmp_path, body)
    assert len(findings) == 1


def test_orm_findings_carry_orm_specific_fix_and_lower_confidence(tmp_path: Path) -> None:
    django = _scan(tmp_path, _loop("Order.objects.get(pk=it)"))[0]
    assert "select_related" in django.suggested_fix and django.confidence == 0.6
    (tmp_path / "m.py").unlink()
    sqla = _scan(tmp_path, _loop("session.query(Order).first()"))[0]
    assert "joinedload" in sqla.suggested_fix
    (tmp_path / "m.py").unlink()
    raw = _scan(tmp_path, _loop("cur.execute('x')"))[0]
    assert raw.confidence == 0.65


def test_only_first_round_trip_per_loop_is_reported(tmp_path: Path) -> None:
    body = _loop("Order.objects.get(pk=it)\n        session.query(Order).all()")
    assert len(_scan(tmp_path, body)) == 1
