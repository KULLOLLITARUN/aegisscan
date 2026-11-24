"""Per-rule confidence for the bundled Semgrep rules, and the Semgrep severity defaults."""
from __future__ import annotations

import glob
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from scanner.static_analysis import semgrep_runner
from scanner.static_analysis.semgrep_runner import _SEMGREP_CONFIDENCE, _normalize, _rule_confidence

RULES = sorted(glob.glob(str(Path(semgrep_runner.__file__).parent / "rules" / "*_security.yml")))


def _item(severity: str, metadata: dict | None) -> dict:
    return {
        "check_id": "x", "path": "a.py", "start": {"line": 1}, "end": {"line": 1},
        "extra": {"severity": severity, "message": "m", "lines": "x", "metadata": metadata or {}},
    }


@pytest.mark.parametrize("value,expected", [("0.9", 0.9), (0.9, 0.9), (1, 1.0), ("0.01", 0.01)])
def test_valid_rule_confidence_is_used(value: float, expected: float) -> None:
    assert _rule_confidence({"aegis_confidence": value}) == expected
    assert _normalize(_item("WARNING", {"aegis_confidence": value})).confidence == expected


@pytest.mark.parametrize("bad", [None, "high", "", True, 0, "0", -0.5, "1.5", [], {}])
def test_invalid_rule_confidence_falls_back_to_severity_default(bad: object) -> None:
    meta = {"aegis_confidence": bad}
    assert _rule_confidence(meta) is None
    assert _normalize(_item("ERROR", meta)).confidence == _SEMGREP_CONFIDENCE["ERROR"]


@pytest.mark.parametrize("metadata", [None, "text", 3, []])
def test_non_dict_metadata_is_ignored(metadata: object) -> None:
    assert _rule_confidence(metadata) is None


def test_severity_defaults_for_registry_rules() -> None:
    assert _normalize(_item("WARNING", None)).confidence == 0.75
    assert _normalize(_item("ERROR", None)).confidence == 0.80
    assert _normalize(_item("INFO", None)).confidence == 0.50


def _all_rules() -> list[dict]:
    rules: list[dict] = []
    for path in RULES:
        rules.extend(yaml.safe_load(Path(path).read_text(encoding="utf-8"))["rules"])
    return rules


def test_every_bundled_rule_declares_a_confidence() -> None:
    rules = _all_rules()
    assert len(rules) >= 38
    for rule in rules:
        value = rule["metadata"].get("aegis_confidence")
        assert isinstance(value, str) and 0.5 <= float(value) <= 0.95, rule["id"]


def test_confidence_follows_the_rubric_by_severity() -> None:
    # An ERROR rule is never scored below the 0.85 non-literal-sink tier, a WARNING sink never above 0.80
    # except through the request-source tier; this keeps ERROR >= WARNING within one rubric.
    for rule in _all_rules():
        value = float(rule["metadata"]["aegis_confidence"])
        if rule["severity"] == "ERROR":
            assert value >= 0.85, rule["id"]
        else:
            assert value <= 0.80, rule["id"]


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
@pytest.mark.parametrize("path", RULES, ids=[Path(p).name for p in RULES])
def test_bundled_rules_pass_semgrep_validation(path: str) -> None:
    # Semgrep silently drops a rule file it cannot load (a bare float in metadata did exactly that),
    # so check with Semgrep's own validator, not just a YAML parser.
    proc = subprocess.run(
        [shutil.which("semgrep"), "--validate", "--config", path, "--disable-version-check", "--metrics=off"],
        capture_output=True, text=True, timeout=120,
    )
    assert "Configuration is valid" in proc.stdout + proc.stderr, (proc.stdout + proc.stderr)[-500:]
