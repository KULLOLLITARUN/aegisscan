"""Items 23/24: a missing LLM line is 'unlocated' (not silently line 1); Groq's internal 429
failover is counted in the manager's telemetry."""
from pathlib import Path
from types import SimpleNamespace

from scanner.llm.auditor import _locate_lines
from scanner.llm.schemas import LLMFindingDraft, LLMResponseSchema
from scanner.models.chunk import CodeChunk
from scanner.providers.base import LLMProvider, LLMResponse
from scanner.providers.groq_provider import GroqProvider
from scanner.providers.manager import ProviderManager


def _chunk(start=40, code="a = 1\nb = 2\nos.system(cmd)\nc = 3"):
    return CodeChunk(file_path=Path("x.py"), language="python", line_start=start,
                     line_end=start + code.count("\n"), code=code)


def test_missing_lines_default_to_none():
    d = LLMFindingDraft()
    assert d.line_start is None and d.line_end is None


def test_bad_line_values_become_none():
    for bad in (None, "n/a", "", 0, -3, True, [1]):
        assert LLMFindingDraft(line_start=bad).line_start is None, bad
    assert LLMFindingDraft(line_start="12").line_start == 12


def test_whole_response_survives_a_garbage_line():
    r = LLMResponseSchema.model_validate({"findings": [{"issue_type": "X", "line_start": "unknown"}]})
    assert r.findings[0].line_start is None


def test_unlocated_without_evidence_anchors_at_chunk_start_not_line_1():
    assert _locate_lines(LLMFindingDraft(), _chunk(), [_chunk().code]) == (40, 40)


def test_unlocated_with_evidence_is_found_by_snippet():
    d = LLMFindingDraft(evidence="os.system(cmd)")
    assert _locate_lines(d, _chunk(), [_chunk().code]) == (42, 42)


class _Fake429Client:
    def __init__(self):
        self.calls = 0
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))
        self.api_key = "k"

    def _create(self, **kw):
        self.calls += 1
        if self.calls <= 2:
            raise RuntimeError("Error code: 429 rate_limit_exceeded")
        msg = SimpleNamespace(content="ok")
        return SimpleNamespace(choices=[SimpleNamespace(message=msg)], model=kw["model"],
                               usage=SimpleNamespace(prompt_tokens=1, completion_tokens=1))


def test_groq_internal_429_failover_reaches_manager_telemetry(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "k")
    monkeypatch.setenv("AEGISSCAN_GROQ_MODELS", "m1,m2,m3")
    g = GroqProvider()
    g._client = _Fake429Client()
    g._served_checked = True
    monkeypatch.setattr("scanner.providers.groq_provider.time.sleep", lambda s: None)
    pm = ProviderManager(providers=[g])
    pm._rate_limiter.acquire = lambda: None
    resp = pm.complete([{"role": "user", "content": "hi"}])
    assert resp.content == "ok"
    assert g.rate_limit_hits == 2
    assert pm.rate_limit_hits == 2


def test_providers_without_counter_still_work():
    class P(LLMProvider):
        name = "p"
        is_available = True
        def complete(self, messages, model, max_tokens=2048, temperature=0.0):
            return LLMResponse(content="x", model=model, provider="p")
    assert ProviderManager(providers=[P()]).rate_limit_hits == 0
