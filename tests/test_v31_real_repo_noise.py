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


# ---- CI hygiene cap (Gin: 17 of 22 findings were workflow notes) ----

def test_workflow_hygiene_notes_are_capped_at_low(tmp_path: Path) -> None:
    from scanner.intelligence.context import cap_ci_hygiene

    wf = str(tmp_path / ".github" / "workflows" / "ci.yml")
    notes = _f(path=wf, category="best_practices", severity=Severity.MEDIUM)
    info = _f(path=str(tmp_path / ".github" / "dependabot.yml"), category="best_practices", severity=Severity.INFO)
    real = _f(path=wf, category="injection", severity=Severity.HIGH)            # script injection stays
    elsewhere = _f(path=str(tmp_path / "src" / "a.js"), category="best_practices", severity=Severity.MEDIUM)
    out, n = cap_ci_hygiene([notes, info, real, elsewhere], tmp_path)
    assert n == 1
    assert out[0].severity == Severity.LOW and out[0].explanation.startswith("[CI configuration")
    assert out[1].severity == Severity.INFO          # never raised
    assert out[2].severity == Severity.HIGH
    assert out[3].severity == Severity.MEDIUM


# ---- found by scanning Django ----

def test_performance_findings_in_tests_are_dropped(tmp_path: Path) -> None:
    from scanner.intelligence.context import drop_test_performance

    in_test = _f(path=str(tmp_path / "tests" / "a.py"), category="performance", severity=Severity.MEDIUM)
    in_src = _f(path=str(tmp_path / "src" / "a.py"), category="performance", severity=Severity.MEDIUM)
    sec_test = _f(path=str(tmp_path / "tests" / "a.py"), category="injection")
    out, n = drop_test_performance([in_test, in_src, sec_test], tmp_path)
    assert n == 1 and out == [in_src, sec_test]


def _bandit(issue, explanation, evidence, line=5, sev=Severity.HIGH) -> Finding:
    return Finding(
        file_path=Path("a.py"), issue_type=issue, category="crypto", severity=sev, confidence=0.8,
        line_start=line, line_end=line, evidence=evidence, explanation=explanation, rule_source="bandit",
    )


def test_trojansource_with_only_direction_marks_is_capped() -> None:
    from scanner.intelligence.context import soften_bandit_false_alarms

    # Bandit's message spells the code points out as the text \u200f, not as the characters
    marks = _bandit("Trojansource", "contains bidirectional control characters ('\\u200f').", "5 X = 1")
    attack = _bandit("Trojansource", "contains bidirectional control characters ('\\u202e').", "5 X = 1")
    mixed = _bandit("Trojansource", "contains bidirectional control characters ('\\u200f', '\\u2067').", "5 X = 1")
    out, n = soften_bandit_false_alarms([marks, attack, mixed])
    assert n == 1
    assert out[0].severity == Severity.LOW
    assert out[1].severity == Severity.HIGH and out[2].severity == Severity.HIGH


def test_weak_hash_is_capped_unless_the_line_is_about_a_secret() -> None:
    from scanner.intelligence.context import soften_bandit_false_alarms

    cache_key = _bandit("Hashlib", "Use of weak SHA1 hash for security.",
                        '4     x = 1\n5     return sha1(text.encode()).hexdigest()\n6 y = 2')
    password = _bandit("Hashlib", "Use of weak MD5 hash for security.",
                       "4     self.check(password, salt)\n5     h = hashlib.md5(salt + password).hexdigest()")
    unknown = _bandit("Hashlib", "Use of weak MD5 hash for security.", "no numbered lines here")
    out, n = soften_bandit_false_alarms([cache_key, password, unknown])
    assert n == 1
    assert out[0].severity == Severity.LOW and out[0].explanation.startswith("[likely benign")
    assert out[1].severity == Severity.HIGH           # password hashing stays high
    assert out[2].severity == Severity.HIGH           # cannot tell: leave it alone


# ---- found by the live LLM run on Gin: the model echoed Semgrep's workflow notes ----

def _llm(path, line=10, category="access_control", severity=Severity.HIGH, conf=1.0) -> Finding:
    return _f(path=path, line=line, category=category, severity=severity, conf=conf, source="llm", issue="Mutable action reference")


def test_llm_notes_about_workflow_files_are_capped_in_severity_and_confidence(tmp_path: Path) -> None:
    from scanner.intelligence.context import LLM_CI_CONFIDENCE_CAP, cap_ci_hygiene

    wf = str(tmp_path / ".github" / "workflows" / "ci.yml")
    echo = _llm(wf)                                                   # access_control, high, 1.00
    secrets = _llm(wf, category="secrets", severity=Severity.MEDIUM, conf=0.85)
    script_injection = _llm(wf, category="injection")                 # a real problem class: untouched
    static_access = _f(path=wf, category="access_control", severity=Severity.HIGH, source="semgrep")
    elsewhere = _llm(str(tmp_path / "src" / "a.go"))
    already_small = _llm(wf, severity=Severity.LOW, conf=0.4)
    out, n = cap_ci_hygiene([echo, secrets, script_injection, static_access, elsewhere, already_small], tmp_path)
    assert n == 2
    assert (out[0].severity, out[0].confidence) == (Severity.LOW, LLM_CI_CONFIDENCE_CAP)
    assert (out[1].severity, out[1].confidence) == (Severity.LOW, LLM_CI_CONFIDENCE_CAP)
    assert out[2] is script_injection
    assert out[3] is static_access
    assert out[4] is elsewhere
    assert out[5] is already_small


def test_llm_relabel_of_a_static_note_on_the_same_lines_is_dropped() -> None:
    static = _f(path="a.yml", line=10, category="best_practices", severity=Severity.MEDIUM, source="semgrep")
    echo = _llm("a.yml", line=10)
    kept, n = deduplicate([static, echo])
    assert kept == [static] and n == 1


def test_llm_findings_that_say_more_than_a_catch_all_note_are_kept() -> None:
    static = _f(path="a.js", line=10, category="best_practices", source="semgrep")
    for category in ("injection", "xss", "deserialization", "path_traversal"):
        kept, _ = deduplicate([static, _llm("a.js", line=10, category=category)])
        assert len(kept) == 2, category
    # a different line, or a different file, is a different finding
    assert len(deduplicate([static, _llm("a.js", line=40)])[0]) == 2
    assert len(deduplicate([static, _llm("b.js", line=10)])[0]) == 2
    # a static finding that is not the catch-all category does not absorb it either
    other = _f(path="a.js", line=10, category="crypto", source="semgrep")
    assert len(deduplicate([other, _llm("a.js", line=10)])[0]) == 2
