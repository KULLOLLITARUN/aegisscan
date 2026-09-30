"""LLM findings must land on the line their evidence is on, not where the model guessed.

Found by the first live benchmark run: every finding in a file came back at line 2, so correct
LLM findings scored as false positives, and (because the deduplicator keeps the highest-confidence
finding in a cluster) they displaced the correctly placed static findings.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from scanner.llm.auditor import LLMAuditor, _locate_lines
from scanner.llm.schemas import LLMFindingDraft
from scanner.models.chunk import CodeChunk
from scanner.models.finding import Finding, Severity
from scanner.providers.base import LLMProvider, LLMResponse
from scanner.providers.manager import ProviderManager

CODE = "\n".join([
    '"""module docstring"""',           # 1
    "import os",                        # 2
    "import subprocess",                # 3
    "",                                 # 4
    "",                                 # 5
    "def ping(host):",                  # 6
    '    os.system("ping -c 1 " + host)',  # 7
    "",                                 # 8
    "",                                 # 9
    "def run(cmd):",                    # 10
    "    exec(cmd)",                    # 11
    "    exec(cmd)",                    # 12
])


def _chunk(code: str = CODE, start: int = 1) -> CodeChunk:
    return CodeChunk(file_path=Path("x.py"), language="python", line_start=start,
                     line_end=start + code.count("\n"), code=code)


def _draft(evidence: str = "", start: int = 1, end: int = 1) -> LLMFindingDraft:
    return LLMFindingDraft(issue_type="Command injection", category="injection", severity="high",
                           confidence=0.9, line_start=start, line_end=end, evidence=evidence,
                           explanation="bad")


# ------------------------------------------------------------------ evidence wins
@pytest.mark.parametrize("model_line", [1, 2, 3, 99, 0])
def test_evidence_beats_whatever_line_the_model_reported(model_line: int) -> None:
    d = _draft('os.system("ping -c 1 " + host)', start=model_line, end=model_line)
    assert _locate_lines(d, _chunk(), [CODE]) == (7, 7)


def test_evidence_may_be_a_fragment_of_the_line() -> None:
    assert _locate_lines(_draft("os.system("), _chunk(), [CODE]) == (7, 7)


def test_multi_line_evidence_spans_its_lines() -> None:
    d = _draft("def ping(host):\n    os.system(\"ping -c 1 \" + host)", start=2, end=2)
    assert _locate_lines(d, _chunk(), [CODE]) == (6, 7)


def test_repeated_evidence_picks_the_occurrence_nearest_the_models_hint() -> None:
    assert _locate_lines(_draft("exec(cmd)", start=11, end=11), _chunk(), [CODE]) == (11, 11)
    assert _locate_lines(_draft("exec(cmd)", start=12, end=12), _chunk(), [CODE]) == (12, 12)


def test_chunk_that_starts_mid_file_yields_absolute_lines() -> None:
    chunk = _chunk("def f(h):\n    a = 1\n    os.system(h)\n    return a", start=40)
    for model_line in (3, 42, 1):                       # relative, absolute, junk
        assert _locate_lines(_draft("os.system(h)", start=model_line), chunk, [chunk.code]) == (42, 42)


def test_evidence_is_matched_against_the_redacted_text_first() -> None:
    sent = 'password = "[REDACTED]"\nprint(password)'
    chunk = _chunk('password = "hunter2hunter2"\nprint(password)')
    assert _locate_lines(_draft('password = "[REDACTED]"'), chunk, [sent, chunk.code]) == (1, 1)


# ------------------------------------------------------------------ fallbacks
def test_falls_back_to_model_line_when_evidence_is_not_in_the_code() -> None:
    assert _locate_lines(_draft("not in file", start=7), _chunk(), [CODE]) == (7, 7)


def test_fallback_treats_out_of_range_numbers_as_chunk_relative() -> None:
    chunk = _chunk("a\nb\nc\nd", start=100)
    assert _locate_lines(_draft("", start=3), chunk, [chunk.code]) == (102, 102)     # relative -> 102
    assert _locate_lines(_draft("", start=101), chunk, [chunk.code]) == (101, 101)   # already absolute


def test_fallback_clamps_to_the_chunk_and_keeps_end_after_start() -> None:
    chunk = _chunk("a\nb\nc", start=10)
    assert _locate_lines(_draft("", start=500, end=600), chunk, [chunk.code]) == (12, 12)
    assert _locate_lines(_draft("", start=10, end=12), chunk, [chunk.code]) == (10, 12)
    start, end = _locate_lines(_draft("", start=12, end=10), chunk, [chunk.code])
    assert end >= start


def test_too_short_evidence_is_not_trusted() -> None:
    assert _locate_lines(_draft("x", start=11), _chunk(), [CODE]) == (11, 11)        # 'x' also occurs earlier


# ------------------------------------------------------------------ end to end
class _WrongLines(LLMProvider):
    """Reports a real vulnerability but always at line 2, like the live model did."""

    name = property(lambda self: "fake")
    is_available = property(lambda self: True)
    default_model = "fake-1"

    def complete(self, messages, model=None, max_tokens=2048, temperature=0.0):
        body = {"findings": [{
            "issue_type": "Command injection via os.system", "category": "injection", "severity": "high",
            "confidence": 0.95, "line_start": 2, "line_end": 2,
            "evidence": 'os.system("ping -c 1 " + host)', "explanation": "concatenated into a shell",
        }]}
        return LLMResponse(content=json.dumps(body), model="fake-1", provider="fake")


def test_auditor_places_the_finding_on_the_evidence_line() -> None:
    auditor = LLMAuditor(ProviderManager(providers=[_WrongLines()]))
    findings = auditor.analyze_chunks([_chunk()], [], deep=True)
    assert [(f.rule_source, f.line_start, f.line_end) for f in findings] == [("llm", 7, 7)]


def test_located_llm_finding_and_static_finding_dedupe_onto_the_real_line() -> None:
    from scanner.intelligence.deduplicator import deduplicate

    static = Finding(file_path=Path("x.py"), issue_type="Starting a process with a shell", category="injection",
                     severity=Severity.HIGH, confidence=0.8, line_start=7, line_end=7,
                     evidence="os.system(...)", explanation="bandit", rule_source="bandit")
    auditor = LLMAuditor(ProviderManager(providers=[_WrongLines()]))
    llm = auditor.analyze_chunks([_chunk()], [static], deep=True)
    kept, removed = deduplicate([static, *llm])
    assert removed == 1
    assert [f.line_start for f in kept] == [7]          # before the fix the survivor sat on line 2
