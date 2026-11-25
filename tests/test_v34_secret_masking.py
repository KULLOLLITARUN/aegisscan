"""A secret finding must never carry the secret value into the dashboard, kept results or exports."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import main
from scanner.intelligence.masking import mask_findings
from scanner.llm.redactor import mask_known_secrets
from scanner.models.finding import Finding, Severity
from scanner.static_analysis import gitleaks_runner
from scanner.static_analysis.gitleaks_runner import _run_python_secret_scanner

GROQ = "gsk_" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2Yz3Ab4Cd5Ef6"  # 48 chars after the prefix


def _scan(tmp_path: Path, name: str, content: str) -> list[Finding]:
    (tmp_path / name).write_text(content, encoding="utf-8")
    return _run_python_secret_scanner(tmp_path)


def test_env_file_key_is_masked_but_the_variable_name_stays(tmp_path: Path) -> None:
    (f,) = _scan(tmp_path, ".env", f"GROQ_API_KEY={GROQ}\n")
    assert GROQ not in f.evidence and "gsk_Ab1" not in f.evidence
    assert f.evidence == "GROQ_API_KEY=[REDACTED]"
    assert f.issue_type == "Groq API Key" and f.line_start == 1


@pytest.mark.parametrize(
    "name,line,secret",
    [
        ("A.java", 'private static final String DB_PASSWORD = "Pr0d-Passw0rd-2024!";', "Pr0d-Passw0rd-2024!"),
        ("main.go", 'const apiSecret = "sk_live_51HxK9aB3cD4eF5gH6iJ7kL8mN9oP0qR"', "sk_live_51HxK9aB3cD4eF5gH6iJ7kL8mN9oP0qR"),
        ("index.php", '$db = new mysqli("localhost", "root", "Sup3rS3cret-Prod!", "shop");', "Sup3rS3cret-Prod!"),
        ("Svc.cs", 'const string Cs = "Server=db;Database=app;User Id=sa;Password=Adm1n-Pr0d-2024;";', "Adm1n-Pr0d-2024"),
        ("app.properties", "jdbc.url=jdbc:sqlserver://db;user=sa;password=Adm1n-Pr0d-2024;", "Adm1n-Pr0d-2024"),
        ("cfg.py", "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'", "AKIAIOSFODNN7EXAMPLE"),
    ],
)
def test_every_builtin_pattern_masks_its_value_and_keeps_the_context(tmp_path: Path, name: str, line: str, secret: str) -> None:
    (f,) = _scan(tmp_path, name, f"// header\n{line}\n")
    assert secret not in f.evidence
    assert "[REDACTED]" in f.evidence
    assert f.evidence.split("[REDACTED]")[0].strip(), "the text before the secret is kept for context"


def test_private_key_header_line_is_left_alone(tmp_path: Path) -> None:
    (f,) = _scan(tmp_path, "k.cfg", "-----BEGIN PRIVATE KEY-----\nMIIE\n")  # gitleaks:allow
    assert f.evidence == "-----BEGIN PRIVATE KEY-----"  # gitleaks:allow


def test_real_gitleaks_secret_is_dropped_but_the_line_is_kept() -> None:
    item = {"File": "a.env", "Description": "k", "StartLine": 1, "Secret": GROQ, "Match": f"KEY={GROQ}", "RuleID": "r"}
    f = gitleaks_runner._normalize(item)
    assert f.evidence == "KEY=[REDACTED]"
    assert gitleaks_runner._normalize({**item, "Match": ""}).evidence == "[REDACTED]"
    assert gitleaks_runner._normalize({"File": "a", "StartLine": 1}).evidence == ""


def _finding(**kw) -> Finding:
    base = dict(file_path=Path("a.py"), issue_type="x", category="injection", severity=Severity.LOW, confidence=0.9,
                line_start=1, line_end=1, evidence="e", explanation="e", rule_source="bandit")
    return Finding(**{**base, **kw})


def test_safety_net_masks_tokens_in_any_finding_and_in_patches() -> None:
    evidence = f'password = "correct-horse-battery"\nclient = Client("{GROQ}")'
    patch = f"--- a\n+++ b\n-API_KEY={GROQ}\n+API_KEY=os.environ['API_KEY']\n"
    clean = _finding(evidence="x = compute(a, b)")
    out = mask_findings([_finding(evidence=evidence, fix_patch=patch), clean])
    assert GROQ not in out[0].evidence and "correct-horse-battery" not in out[0].evidence
    assert GROQ not in out[0].fix_patch and "os.environ['API_KEY']" in out[0].fix_patch
    assert out[1] is clean, "untouched findings are returned as they are"


def test_masking_leaves_ordinary_long_hex_and_base64_text_alone() -> None:
    text = "digest = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'"
    assert mask_known_secrets(text) == text


def test_run_returns_masked_findings_end_to_end(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / ".env").write_text(f"GROQ_API_KEY={GROQ}\n", encoding="utf-8")
    monkeypatch.setattr(
        main, "run_all_tools",
        lambda target, progress=None, only_files=None, privacy="standard", on_findings=None:
        (gitleaks_runner._run_python_secret_scanner(target), ["gitleaks"]),
    )
    result, _, _ = main.run(tmp_path, static_only=True, record_history=False)
    dumped = result.model_dump_json()
    assert GROQ not in dumped and "gsk_Ab1" not in dumped
    assert any(f.evidence == "GROQ_API_KEY=[REDACTED]" for f in result.findings)
    json.loads(dumped)
