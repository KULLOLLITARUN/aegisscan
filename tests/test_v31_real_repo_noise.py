"""Fixes found by scanning real repositories (Flask, Express, NodeGoat, pygoat):
several rules of one tool on one line, and demo/test code dominating the severity counts."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scanner.intelligence.context import is_non_production, weight_by_context
from scanner.intelligence.deduplicator import deduplicate
from scanner.models.finding import Finding, Severity
from scanner.static_analysis import semgrep_runner


def _f(path="app.js", line=10, category="injection", severity=Severity.HIGH, conf=0.8,
       source="semgrep", issue="rule-a") -> Finding:
    return Finding(
        file_path=Path(path), issue_type=issue, category=category, severity=severity,
        confidence=conf, line_start=line, line_end=line, evidence="x", explanation="why",
        rule_source=source,
    )


# ---- same tool, same line ----

def test_three_rules_on_one_eval_line_become_one_finding() -> None:
    fs = [
        _f(category="best_practices", issue="a", severity=Severity.HIGH),
        _f(category="best_practices", issue="b", severity=Severity.HIGH),
        _f(category="injection", issue="c", severity=Severity.HIGH),
    ]
    kept, n = deduplicate(fs)
    assert len(kept) == 1 and n == 2
    assert kept[0].category == "injection"          # the specific category wins the tie


def test_nine_best_practice_hits_on_one_line_collapse_to_the_most_severe() -> None:
    fs = [_f(category="best_practices", severity=Severity.LOW, issue=str(i)) for i in range(8)]
    fs.append(_f(category="best_practices", severity=Severity.MEDIUM, issue="worst"))
    kept, n = deduplicate(fs)
    assert [k.issue_type for k in kept] == ["worst"] and n == 8


def test_different_lines_stay_separate() -> None:
    kept, _ = deduplicate([_f(line=10, issue="a"), _f(line=40, issue="b")])
    assert len(kept) == 2


def test_two_specific_categories_on_one_line_stay_separate() -> None:
    kept, _ = deduplicate([_f(category="injection"), _f(category="crypto", issue="b")])
    assert len(kept) == 2


def test_different_tools_on_one_line_are_not_collapsed_here() -> None:
    # cross-tool merging is the clustering step's job (and it still works)
    fs = [_f(source="semgrep"), _f(source="bandit", issue="b")]
    kept, n = deduplicate(fs)
    assert len(kept) == 1 and n == 1


# ---- context weighting ----

def test_path_classification(tmp_path: Path) -> None:
    root = tmp_path
    assert is_non_production(root / "tests" / "a.py", root)
    assert is_non_production(root / "examples" / "x" / "a.js", root)
    assert is_non_production(root / "src" / "test_thing.py", root)
    assert is_non_production(root / "docs" / "a.py", root)
    assert not is_non_production(root / "src" / "app.py", root)
    assert not is_non_production(root / "src" / "contest.py", root)
    # the scan target itself being named "tests" does not demote its content
    assert not is_non_production(root / "a.py", root)
    assert not is_non_production(tmp_path.parent / "other" / "tests" / "a.py", root)


def test_test_code_is_lowered_one_level_and_halved(tmp_path: Path) -> None:
    prod = _f(path=str(tmp_path / "src" / "a.py"), severity=Severity.HIGH, conf=0.8)
    test = _f(path=str(tmp_path / "tests" / "a.py"), severity=Severity.HIGH, conf=0.8)
    out, n = weight_by_context([prod, test], tmp_path)
    assert n == 1
    assert out[0].severity == Severity.HIGH and out[0].confidence == 0.8
    assert out[1].severity == Severity.MEDIUM and out[1].confidence == 0.4
    assert out[1].explanation.startswith("[non-production path")


def test_performance_and_low_findings_are_handled(tmp_path: Path) -> None:
    perf = _f(path=str(tmp_path / "tests" / "a.py"), category="performance", severity=Severity.MEDIUM)
    low = _f(path=str(tmp_path / "tests" / "b.py"), severity=Severity.LOW)
    out, n = weight_by_context([perf, low], tmp_path)
    assert out[0].severity == Severity.MEDIUM and out[0].confidence == perf.confidence
    assert out[1].severity == Severity.LOW and n == 1


# ---- bundled rule: MongoDB $where (missed in NodeGoat) ----

_JS_RULES = Path(semgrep_runner.__file__).parent / "rules" / "js_security.yml"
_SEMGREP = semgrep_runner._find_tool("semgrep")


@pytest.mark.skipif(not _SEMGREP, reason="semgrep binary not installed")
def test_mongo_where_rule(tmp_path: Path) -> None:
    src = tmp_path / "t.js"
    src.write_text(
        "const a = { $where: `this.userId == ${u}` };\n"            # 1 flagged
        "const b = { $where: 'this.userId == ' + u };\n"            # 2 flagged
        "const c = { $where: 'this.stocks > 5' };\n"                # 3 literal: fine
        "const d = { userId: u, stocks: { $gt: 5 } };\n",           # 4 parameterised: fine
        encoding="utf8",
    )
    proc = subprocess.run(
        [_SEMGREP, "--config", str(_JS_RULES), "--json", "--quiet", "--metrics=off", str(src)],
        capture_output=True, text=True, timeout=300,
    )
    hits = {r["start"]["line"] for r in json.loads(proc.stdout)["results"]
            if r["check_id"].endswith("aegis-js-mongo-where-injection")}
    assert hits == {1, 2}
