"""Tests for V5 Scale & Provider Resilience layer.

Covers:
  - Token-bucket RateLimiter acquire pacing
  - execute_with_backoff exponential retry and rate limit callbacks
  - OllamaProvider properties and offline fallback behavior
  - ProviderManager multi-provider failover chain (Primary fails -> Secondary fallback)
  - Telemetry accumulation (requests, tokens, latency, rate limit hits)
"""
from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest

from scanner.providers.base import LLMProvider, LLMResponse
from scanner.providers.manager import ProviderManager
from scanner.providers.ollama_provider import OllamaProvider
from scanner.providers.rate_limiter import RateLimiter, execute_with_backoff

# ---------------------------------------------------------------------------
# RateLimiter & Backoff
# ---------------------------------------------------------------------------

def test_rate_limiter_acquires_tokens() -> None:
    limiter = RateLimiter(requests_per_minute=600)  # 10 tokens/sec
    t0 = time.monotonic()
    for _ in range(5):
        limiter.acquire()
    duration = time.monotonic() - t0
    assert duration < 1.0


def test_execute_with_backoff_retries_on_rate_limit() -> None:
    attempts = 0
    on_limit_called = False

    def _on_limit():
        nonlocal on_limit_called
        on_limit_called = True

    def _faulty():
        nonlocal attempts
        attempts += 1
        if attempts < 2:
            raise Exception("HTTP 429 Too Many Requests")
        return "success"

    res = execute_with_backoff(
        _faulty,
        max_retries=2,
        base_delay=0.01,
        on_rate_limit=_on_limit,
    )
    assert res == "success"
    assert attempts == 2
    assert on_limit_called is True


def test_execute_with_backoff_raises_after_max_retries() -> None:
    def _always_fail():
        raise Exception("429 rate limit exceeded")

    with pytest.raises(Exception, match="429"):
        execute_with_backoff(_always_fail, max_retries=1, base_delay=0.01)


# ---------------------------------------------------------------------------
# OllamaProvider
# ---------------------------------------------------------------------------

def test_ollama_provider_offline_graceful() -> None:
    provider = OllamaProvider(host="http://localhost:99999")  # invalid port
    assert provider.name == "ollama"
    assert provider.is_available is False
    resp = provider.complete(messages=[{"role": "user", "content": "hi"}])
    assert resp.content == ""
    assert resp.provider == "ollama"


# ---------------------------------------------------------------------------
# ProviderManager Failover & Telemetry
# ---------------------------------------------------------------------------

def test_provider_manager_fallback_chain() -> None:
    """Primary fails -> failover to secondary provider."""
    primary = MagicMock(spec=LLMProvider)
    primary.name = "primary"
    primary.is_available = True
    primary.complete.side_effect = Exception("API connection error")

    secondary = MagicMock(spec=LLMProvider)
    secondary.name = "secondary"
    secondary.is_available = True
    secondary.complete.return_value = LLMResponse(
        content="fallback response",
        model="sec-model",
        provider="secondary",
        input_tokens=50,
        output_tokens=25,
    )

    pm = ProviderManager(providers=[primary, secondary])
    assert pm.is_available is True
    assert pm.active_provider == "primary"

    resp = pm.complete(messages=[{"role": "user", "content": "test"}])
    assert resp.content == "fallback response"
    assert resp.provider == "secondary"
    assert pm.fallback_triggered is True
    assert pm.requests_count == 1
    assert pm.total_input_tokens == 50
    assert pm.total_output_tokens == 25


def test_provider_manager_telemetry_accumulation() -> None:
    provider = MagicMock(spec=LLMProvider)
    provider.name = "mock_provider"
    provider.is_available = True
    provider.complete.return_value = LLMResponse(
        content="ok",
        model="mock-model",
        provider="mock_provider",
        input_tokens=100,
        output_tokens=40,
    )

    pm = ProviderManager(providers=[provider])
    pm.complete(messages=[])
    pm.complete(messages=[])

    assert pm.requests_count == 2
    assert pm.total_input_tokens == 200
    assert pm.total_output_tokens == 80
    assert pm.total_latency_seconds >= 0.0
