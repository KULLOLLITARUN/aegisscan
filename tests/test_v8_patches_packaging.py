"""Tests for V8 Distribution Packaging & AI Fix Patch Generator.

Covers:
  - Finding fix_patch field serialization
  - Patch generator logic
  - LLMAuditor generate_patches configuration
  - main.py CLI --generate-patches parser
  - pyproject.toml package configuration
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from main import _build_parser
from scanner.llm.auditor import LLMAuditor
from scanner.llm.patcher import generate_patch_for_finding
from scanner.models.finding import Finding, Severity
from scanner.providers.manager import ProviderManager


def _mock_finding() -> Finding:
    return Finding(
        file_path=Path("app.py"),
        issue_type="SQL Injection",
        category="injection",
        severity=Severity.HIGH,
        confidence=0.9,
        line_start=10,
        line_end=10,
        evidence="query = f'SELECT * FROM users WHERE id = {user_input}'",
        explanation="Unsanitized input concatenated into SQL query string.",
        rule_source="llm",
    )


def test_finding_fix_patch_field() -> None:
    f = _mock_finding()
    assert f.fix_patch is None
    f.fix_patch = "--- a/app.py\n+++ b/app.py\n@@ -10 +10 @@\n-query = f'SELECT * FROM users WHERE id = {user_input}'\n+query = 'SELECT * FROM users WHERE id = %s'"
    assert "--- a/app.py" in f.fix_patch


def test_generate_patch_for_finding() -> None:
    f = _mock_finding()
    mock_pm = MagicMock(spec=ProviderManager)
    mock_pm.complete.return_value = (
        "```diff\n--- a/app.py\n+++ b/app.py\n@@ -10 +10 @@\n-query = f'SELECT * FROM users'\n+query = 'SELECT * FROM users'\n```",
        "groq",
        "llama-3.3-70b",
    )

    patch = generate_patch_for_finding(f, mock_pm)
    assert patch is not None
    assert patch.startswith("--- a/app.py")
    assert "```" not in patch


def test_generate_patch_empty_evidence_returns_none() -> None:
    f = _mock_finding()
    f.evidence = ""
    mock_pm = MagicMock(spec=ProviderManager)
    assert generate_patch_for_finding(f, mock_pm) is None


def test_llm_auditor_generate_patches_flag() -> None:
    mock_pm = MagicMock(spec=ProviderManager)
    mock_pm.is_available = True
    auditor = LLMAuditor(provider_manager=mock_pm, generate_patches=True)
    assert auditor._generate_patches is True


def test_cli_parser_supports_generate_patches() -> None:
    parser = _build_parser()
    args = parser.parse_args(["--generate-patches"])
    assert args.generate_patches is True


def test_pyproject_contains_console_script() -> None:
    root = Path(__file__).resolve().parents[1]
    pyproject_path = root / "pyproject.toml"
    assert pyproject_path.exists()
    content = pyproject_path.read_text(encoding="utf-8")
    assert "[project.scripts]" in content
    assert 'aegisscan = "main:main"' in content
