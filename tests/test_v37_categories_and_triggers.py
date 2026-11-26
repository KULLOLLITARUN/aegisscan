"""Semgrep category inference uses whole words and CWEs; the LLM trigger knows non-Python sinks."""
from __future__ import annotations

from pathlib import Path

import pytest

from scanner.llm.trigger import TriggerEngine
from scanner.models.chunk import CodeChunk
from scanner.static_analysis.semgrep_runner import _infer_category


# ---------------------------------------------------------------- categories
@pytest.mark.parametrize(
    "rule",
    ["monkey-patch-config", "author-field-required", "operand-order", "brand-colours", "keyboard-shortcut",
     "perform-update"],
)
def test_words_that_merely_contain_a_keyword_are_not_categorised(rule: str) -> None:
    assert _infer_category(rule) == "best_practices"


@pytest.mark.parametrize(
    "rule,cat",
    [
        ("python.lang.security.sql-injection", "injection"),
        ("dangerous-exec-command", "injection"),
        ("hardcoded-api-key", "secrets"),
        ("hardcoded-credentials", "secrets"),
        ("missing-csrf-protection", "access_control"),
        ("missing-authentication", "access_control"),
        ("insecure-random", "crypto"),
        ("weak-hash-md5", "crypto"),
        ("slow-n+1-query", "performance"),
    ],
)
def test_real_keywords_still_categorise(rule: str, cat: str) -> None:
    assert _infer_category(rule) == cat


def test_a_cwe_in_the_metadata_wins_over_the_rule_name() -> None:
    assert _infer_category("some-opaque-rule", {"cwe": ["CWE-89: SQL Injection"]}) == "injection"
    assert _infer_category("some-opaque-rule", {"cwe": "CWE-798: Hard-coded Credentials"}) == "secrets"
    assert _infer_category("monkey-patch", {"cwe": ["CWE-327: Broken crypto"]}) == "crypto"


def test_an_unmapped_or_missing_cwe_falls_back_to_the_rule_name() -> None:
    assert _infer_category("weak-hash", {"cwe": ["CWE-1000"]}) == "crypto"
    assert _infer_category("weak-hash", {"cwe": None}) == "crypto"
    assert _infer_category("weak-hash", "not a dict") == "crypto"


# ---------------------------------------------------------------- triggers
def _chunk(code: str, name: str) -> CodeChunk:
    return CodeChunk(file_path=Path(name), language="text", line_start=1, line_end=code.count("\n") + 1, code=code)


@pytest.mark.parametrize(
    "name,code",
    [
        ("A.java", 'Process p = Runtime.getRuntime().exec(cmd);'),
        ("A.java", 'ObjectInputStream in = new ObjectInputStream(stream);'),
        ("A.java", 'MessageDigest md = MessageDigest.getInstance("MD5");'),
        ("a.js", "const cp = require('child_process');"),
        ("a.js", "el.innerHTML = userInput;"),
        ("a.js", "const h = crypto.createHash('md5');"),
        ("a.go", 'out, err := exec.Command("sh", "-c", cmd).Output()'),
        ("a.go", "tls.Config{InsecureSkipVerify: true}"),
        ("a.php", '$obj = unserialize($_COOKIE["data"]);'),
        ("a.php", 'include($_GET["page"]);'),
        ("a.php", 'system($cmd);'),
        ("A.cs", 'Process.Start(userPath);'),
        ("A.cs", 'var f = new BinaryFormatter();'),
        ("A.cs", 'var h = MD5.Create();'),
    ],
)
def test_trigger_fires_on_non_python_risky_code(name: str, code: str) -> None:
    assert TriggerEngine().should_analyze(_chunk(code, name), []) is True


@pytest.mark.parametrize(
    "name,code",
    [
        ("A.java", "int total = items.stream().mapToInt(Item::price).sum();"),
        ("a.js", "const total = items.reduce((a, b) => a + b.price, 0);"),
        ("a.go", "func add(a, b int) int { return a + b }"),
        ("a.php", "function add($a, $b) { return $a + $b; }"),
        ("A.cs", "public int Add(int a, int b) => a + b;"),
        ("a.js", "// the system is fine; includes a list"),
    ],
)
def test_trigger_skips_ordinary_non_python_code(name: str, code: str) -> None:
    assert TriggerEngine().should_analyze(_chunk(code, name), []) is False
