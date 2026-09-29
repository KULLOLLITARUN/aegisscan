"""Tests for V2 LLM layer.

Tests are written to run WITHOUT a real GROQ_API_KEY by mocking the
ProviderManager. The full API round-trip is validated manually.

Covers:
  - Secret redactor removes known patterns
  - TriggerEngine correctly identifies triggered/skipped chunks
  - LLMResponseSchema validates correct JSON and rejects invalid input
  - LLMAuditor returns [] when provider unavailable (graceful degradation)
  - LLMAuditor returns Finding objects (never raw dicts) with mock provider
  - Confidence suppression threshold applied correctly
  - ProviderManager.is_available = False when GROQ_API_KEY absent
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from scanner.llm.auditor import LLMAuditor
from scanner.llm.redactor import redact
from scanner.llm.schemas import LLMFindingDraft, LLMResponseSchema
from scanner.llm.trigger import TriggerEngine
from scanner.models.chunk import CodeChunk
from scanner.models.finding import Finding, Severity
from scanner.providers.base import LLMResponse
from scanner.providers.manager import ProviderManager

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_chunk(
    code: str,
    path: str = "test.py",
    language: str = "Python",
    line_start: int = 1,
    line_end: int = 10,
    symbol_name: str | None = "test_func",
) -> CodeChunk:
    return CodeChunk(
        file_path=Path(path),
        language=language,
        symbol_name=symbol_name,
        symbol_type="function",
        line_start=line_start,
        line_end=line_end,
        code=code,
        imports=[],
    )


def _make_finding(
    path: str = "test.py",
    line_start: int = 1,
    severity: Severity = Severity.HIGH,
    rule_source: str = "bandit",
) -> Finding:
    return Finding(
        file_path=Path(path),
        issue_type="Test Issue",
        category="injection",
        severity=severity,
        confidence=0.85,
        line_start=line_start,
        line_end=line_start + 2,
        evidence="some code",
        explanation="test explanation",
        rule_source=rule_source,
    )


def _make_provider_manager(response_content: str, model: str = "llama-3.3-70b-versatile") -> ProviderManager:
    """Return a ProviderManager whose complete() returns a canned response."""
    pm = MagicMock(spec=ProviderManager)
    pm.is_available = True
    pm.active_provider = "groq"
    pm.default_model = model
    pm.complete.return_value = LLMResponse(
        content=response_content,
        model=model,
        provider="groq",
        input_tokens=100,
        output_tokens=50,
    )
    return pm


# ---------------------------------------------------------------------------
# Secret redactor
# ---------------------------------------------------------------------------

def test_redact_removes_api_key() -> None:
    code = 'API_KEY = "sk-abcdefghij1234567890xyz"'
    result = redact(code)
    assert "sk-abcdefghij1234567890xyz" not in result
    assert "REDACTED" in result


def test_redact_removes_password_assignment() -> None:
    code = 'password = "super_secret_pass"'
    result = redact(code)
    assert "super_secret_pass" not in result


def test_redact_removes_groq_key() -> None:
    code = 'GROQ_KEY = "gsk_abcdefghij1234567890xyz"'
    result = redact(code)
    assert "gsk_abcdefghij1234567890xyz" not in result


def test_redact_preserves_code_structure() -> None:
    code = "def foo(x):\n    return x + 1\n"
    result = redact(code)
    # Clean code should not be altered
    assert "def foo" in result
    assert "return x + 1" in result


def test_redact_removes_bearer_token() -> None:
    code = 'headers = {"Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9abc"}'
    result = redact(code)
    assert "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9abc" not in result


# ---------------------------------------------------------------------------
# TriggerEngine
# ---------------------------------------------------------------------------

def test_trigger_fires_on_static_finding() -> None:
    engine = TriggerEngine()
    chunk = _make_chunk("def foo():\n    conn.execute(query)", line_start=5, line_end=10)
    finding = _make_finding(path="test.py", line_start=6)

    assert engine.should_analyze(chunk, [finding]) is True


def test_trigger_fires_on_risky_pattern() -> None:
    engine = TriggerEngine()
    chunk = _make_chunk("import pickle\ndata = pickle.loads(raw)", path="proc.py")

    assert engine.should_analyze(chunk, []) is True  # no static finding needed


def test_trigger_skips_clean_chunk() -> None:
    engine = TriggerEngine()
    chunk = _make_chunk("def add(a, b):\n    return a + b\n", path="math.py")

    assert engine.should_analyze(chunk, []) is False


def test_trigger_deep_mode_fires_on_all() -> None:
    engine = TriggerEngine()
    chunk = _make_chunk("def add(a, b):\n    return a + b\n", path="math.py")

    assert engine.should_analyze(chunk, [], deep=True) is True


def test_trigger_skips_empty_chunk() -> None:
    engine = TriggerEngine()
    chunk = _make_chunk("", path="empty.py")

    assert engine.should_analyze(chunk, [], deep=True) is False


def test_trigger_get_chunk_findings_filters_by_line() -> None:
    engine = TriggerEngine()
    chunk = _make_chunk("x = 1", path="app.py", line_start=10, line_end=15)
    f_inside = _make_finding(path="app.py", line_start=12)
    f_outside = _make_finding(path="app.py", line_start=30)
    f_other_file = _make_finding(path="other.py", line_start=12)

    result = engine.get_chunk_findings(chunk, [f_inside, f_outside, f_other_file])
    assert f_inside in result
    assert f_outside not in result
    assert f_other_file not in result


# ---------------------------------------------------------------------------
# LLMResponseSchema validation
# ---------------------------------------------------------------------------

def test_schema_valid_findings() -> None:
    data = {
        "findings": [
            {
                "issue_type": "SQL Injection",
                "category": "injection",
                "severity": "HIGH",        # uppercase — should normalise
                "confidence": 0.92,
                "line_start": 5,
                "line_end": 7,
                "evidence": "query += user_id",
                "explanation": "Unsanitised input concatenated into SQL query.",
            }
        ]
    }
    schema = LLMResponseSchema.model_validate(data)
    assert len(schema.findings) == 1
    assert schema.findings[0].severity == "high"   # normalised to lowercase


def test_schema_empty_findings() -> None:
    schema = LLMResponseSchema.model_validate({"findings": []})
    assert schema.findings == []


def test_schema_clamps_bad_confidence() -> None:
    """Confidence outside 0–1 is rejected by Pydantic ge/le validators."""
    with pytest.raises(ValidationError):
        LLMFindingDraft(confidence=1.5)


def test_schema_normalises_unknown_category() -> None:
    draft = LLMFindingDraft(category="random-nonsense")
    assert draft.category == "best_practices"


# ---------------------------------------------------------------------------
# LLMAuditor — no API key (graceful degradation)
# ---------------------------------------------------------------------------

def test_auditor_returns_empty_when_no_key(monkeypatch) -> None:
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    auditor = LLMAuditor()
    chunk = _make_chunk("def foo():\n    pass\n")
    result = auditor.analyze_chunks([chunk], [])
    assert result == []


# ---------------------------------------------------------------------------
# LLMAuditor — mocked provider
# ---------------------------------------------------------------------------

GOOD_JSON = '{"findings": [{"issue_type": "SQL Injection", "category": "injection", "severity": "high", "confidence": 0.95, "line_start": 1, "line_end": 3, "evidence": "query += user_id", "explanation": "SQL injection risk."}]}'

EMPTY_JSON = '{"findings": []}'

INVALID_JSON = "I found one issue with the code. There is SQL injection."


def test_auditor_returns_findings_from_mock(monkeypatch) -> None:
    pm = _make_provider_manager(GOOD_JSON)
    auditor = LLMAuditor(provider_manager=pm)
    chunk = _make_chunk("query = 'SELECT * FROM users WHERE id = ' + user_id\n")
    result = auditor.analyze_chunks([chunk], [], deep=True)

    assert len(result) == 1
    assert isinstance(result[0], Finding)
    assert result[0].rule_source == "llm"
    assert result[0].provider == "groq"


def test_auditor_returns_empty_when_no_findings(monkeypatch) -> None:
    pm = _make_provider_manager(EMPTY_JSON)
    auditor = LLMAuditor(provider_manager=pm)
    chunk = _make_chunk("def add(a, b):\n    return a + b\n")
    result = auditor.analyze_chunks([chunk], [], deep=True)
    assert result == []


def test_auditor_suppresses_low_confidence(monkeypatch) -> None:
    low_conf_json = '{"findings": [{"issue_type": "Maybe an issue", "category": "best_practices", "severity": "low", "confidence": 0.40, "line_start": 1, "line_end": 1, "evidence": "x", "explanation": "Unclear."}]}'
    pm = _make_provider_manager(low_conf_json)
    auditor = LLMAuditor(provider_manager=pm)
    chunk = _make_chunk("x = 1\n")
    result = auditor.analyze_chunks([chunk], [], deep=True)
    # 0.40 < SUPPRESSION_THRESHOLD (0.60) → suppressed
    assert result == []


def test_auditor_handles_invalid_json_with_repair(monkeypatch) -> None:
    """On invalid JSON, auditor retries once with repair prompt."""
    pm = MagicMock(spec=ProviderManager)
    pm.is_available = True
    pm.active_provider = "groq"
    pm.default_model = "llama-3.3-70b-versatile"
    # First call returns garbage, repair call returns valid JSON
    pm.complete.side_effect = [
        LLMResponse(content=INVALID_JSON, model="llama-3.3-70b-versatile", provider="groq"),
        LLMResponse(content=EMPTY_JSON,   model="llama-3.3-70b-versatile", provider="groq"),
    ]
    auditor = LLMAuditor(provider_manager=pm)
    chunk = _make_chunk("x = 1")
    result = auditor.analyze_chunks([chunk], [], deep=True)
    assert isinstance(result, list)
    assert pm.complete.call_count == 2   # initial + repair


def test_auditor_findings_are_finding_instances(monkeypatch) -> None:
    pm = _make_provider_manager(GOOD_JSON)
    auditor = LLMAuditor(provider_manager=pm)
    chunk = _make_chunk("query += user_id\n")
    result = auditor.analyze_chunks([chunk], [], deep=True)
    for f in result:
        assert isinstance(f, Finding), f"Expected Finding, got {type(f)}"


# ---------------------------------------------------------------------------
# ProviderManager — no API key
# ---------------------------------------------------------------------------

def test_provider_manager_unavailable_without_key(monkeypatch) -> None:
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    pm = ProviderManager()
    assert pm.is_available is False
