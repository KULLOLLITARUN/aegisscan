"""Groq model-list rot: retired models are remembered, and models.list() prunes the failover chain."""
from __future__ import annotations

import pytest

from scanner.providers.groq_provider import GroqProvider

M20, M120, MQ = "openai/gpt-oss-20b", "openai/gpt-oss-120b", "qwen/qwen3.8-27b"
_MSG = [{"role": "user", "content": "x"}]


class _FakeGroq:
    """Chat completions that 404 for `retired` models and 429 for `limited` ones; models.list() optional."""

    def __init__(self, retired=(), limited=(), served=None, list_error: Exception | None = None):
        self.api_key = "test"
        self.calls: list[str] = []
        self.list_calls = 0
        retired, limited = set(retired), set(limited)
        outer = self

        class _Completions:
            def create(self, model, **_):
                outer.calls.append(model)
                if model in retired:
                    raise RuntimeError("Error code: 404 - model_not_found")
                if model in limited:
                    raise RuntimeError("Error code: 429 - rate_limit_exceeded")
                msg = type("M", (), {"content": "ok"})()
                usage = type("U", (), {"prompt_tokens": 1, "completion_tokens": 1})()
                return type("R", (), {"choices": [type("C", (), {"message": msg})()], "usage": usage, "model": model})()

        class _Models:
            def list(self):
                outer.list_calls += 1
                if list_error:
                    raise list_error
                return type("L", (), {"data": [type("D", (), {"id": i})() for i in (served or [])]})()

        self.chat = type("Chat", (), {"completions": _Completions()})()
        self.models = _Models()


@pytest.fixture
def make(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test")
    monkeypatch.delenv("AEGISSCAN_GROQ_MODELS", raising=False)

    def _make(**kw):
        client = _FakeGroq(**kw)
        provider = GroqProvider()
        monkeypatch.setattr(provider, "_get_client", lambda: client)
        return provider, client

    return _make


def test_retired_model_is_not_retried_on_later_requests(make) -> None:
    provider, client = make(retired=[M20])
    assert provider.complete(_MSG).model == M120
    assert provider.complete(_MSG).model == M120
    assert client.calls == [M20, M120, M120]          # the 404 was paid for once, not twice


def test_rate_limit_does_not_mark_a_model_retired(make) -> None:
    provider, client = make(limited=[M20])
    provider.complete(_MSG)
    provider.complete(_MSG)
    assert client.calls == [M20, M120, M20, M120]     # 429 is temporary; the model stays in the chain


def test_models_list_prunes_models_the_key_cannot_use(make) -> None:
    provider, client = make(served=[M120, "some/other-model"])
    assert provider.complete(_MSG).model == M120
    assert provider.complete(_MSG).model == M120
    assert client.calls == [M120, M120]               # never touched the unserved models
    assert client.list_calls == 1                     # listed once, cached


def test_models_list_failure_falls_back_to_per_request_failover(make) -> None:
    provider, client = make(retired=[M20], list_error=RuntimeError("network"))
    assert provider.complete(_MSG).model == M120
    assert client.calls == [M20, M120]
    assert client.list_calls == 1


def test_empty_models_list_is_treated_as_unknown(make) -> None:
    provider, client = make(served=[])
    assert provider.complete(_MSG).model == M20
    assert client.calls == [M20]


def test_warns_with_available_ids_when_no_configured_model_is_served(make, caplog) -> None:
    provider, client = make(served=["vendor/new-model-1", "vendor/new-model-2"], retired=[M20, M120, MQ])
    with caplog.at_level("WARNING"):
        out = provider.complete(_MSG)
    assert out.content == ""                          # nothing usable: degrade, do not crash
    assert client.calls == [M20, M120, MQ]            # still tried, in case models.list() was wrong
    assert "vendor/new-model-1" in caplog.text
    assert "AEGISSCAN_GROQ_MODELS" in caplog.text


def test_when_every_model_is_marked_retired_it_retries_instead_of_giving_up(make) -> None:
    provider, client = make(retired=[M20, M120, MQ])
    provider.complete(_MSG)
    provider.complete(_MSG)
    assert client.calls == [M20, M120, MQ] * 2


def test_env_override_is_respected_by_the_pruning(make, monkeypatch) -> None:
    monkeypatch.setenv("AEGISSCAN_GROQ_MODELS", "my/a, my/b")
    provider, client = make(served=["my/b"])
    assert provider.complete(_MSG).model == "my/b"
    assert client.calls == ["my/b"]
