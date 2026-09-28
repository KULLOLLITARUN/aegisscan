"""
ProviderManager — single entry point for all LLM completions (V5).

Manages provider failover (Groq -> Ollama -> Fallback), rate limiting,
exponential backoff with jitter, and aggregate telemetry tracking.
"""
from __future__ import annotations

import logging
import os
import time
from typing import Sequence

from scanner.providers.base import LLMProvider, LLMResponse
from scanner.providers.groq_provider import DEFAULT_MODEL, GroqProvider
from scanner.providers.ollama_provider import OllamaProvider
from scanner.providers.rate_limiter import RateLimiter, execute_with_backoff

log = logging.getLogger(__name__)


class ProviderManager:
    """
    Manages LLM provider instances, multi-provider fallback chain,
    rate limiting, backoff retries, and usage metrics collection.
    """

    def __init__(self, providers: Sequence[LLMProvider] | None = None) -> None:
        if providers is not None:
            self._providers = list(providers)
        else:
            self._providers = [GroqProvider(), OllamaProvider()]

        llm_rpm = int(os.environ.get("AEGISSCAN_LLM_RPM", "10"))
        self._rate_limiter = RateLimiter(requests_per_minute=llm_rpm, initial_tokens=1)

        # Telemetry metrics
        self.requests_count: int = 0
        self.total_input_tokens: int = 0
        self.total_output_tokens: int = 0
        self.total_latency_seconds: float = 0.0
        self.rate_limit_hits: int = 0
        self.fallback_triggered: bool = False

    @property
    def available_providers(self) -> list[LLMProvider]:
        """List of providers currently available and configured."""
        return [p for p in self._providers if p.is_available]

    @property
    def is_available(self) -> bool:
        """True if at least one provider is available."""
        return len(self.available_providers) > 0

    @property
    def active_provider(self) -> str:
        """Name of the primary available provider."""
        avail = self.available_providers
        return avail[0].name if avail else "none"

    @property
    def default_model(self) -> str:
        avail = self.available_providers
        if avail and avail[0].name == "groq":
            return DEFAULT_MODEL
        if avail and avail[0].name == "ollama":
            return "llama3"
        return DEFAULT_MODEL

    def _increment_rate_limit_hits(self) -> None:
        self.rate_limit_hits += 1

    def complete(
        self,
        messages: list[dict],
        model: str | None = None,
        max_tokens: int = 2048,
        temperature: float = 0.0,
    ) -> LLMResponse:
        """
        Send chat completion request using the fallback chain with backoff and rate limiting.
        """
        avail = self.available_providers
        if not avail:
            log.debug("ProviderManager: no provider available")
            return LLMResponse(content="", model=model or self.default_model, provider="none")

        resolved_model = model or self.default_model

        for idx, provider in enumerate(avail):
            if idx > 0:
                self.fallback_triggered = True
                log.info("ProviderManager: failing over to provider %s", provider.name)

            self._rate_limiter.acquire()
            t0 = time.monotonic()

            try:
                def _do_call() -> LLMResponse:
                    return provider.complete(
                        messages=messages,
                        model=resolved_model,
                        max_tokens=max_tokens,
                        temperature=temperature,
                    )

                response = execute_with_backoff(
                    _do_call,
                    max_retries=2,
                    on_rate_limit=self._increment_rate_limit_hits,
                )

                duration = time.monotonic() - t0
                self.requests_count += 1
                self.total_latency_seconds += duration
                self.total_input_tokens += response.input_tokens
                self.total_output_tokens += response.output_tokens

                if response.content:
                    return response

                log.warning("Provider %s returned empty response, trying fallback...", provider.name)

            except Exception as exc:
                duration = time.monotonic() - t0
                self.total_latency_seconds += duration
                log.warning("Provider %s failed with error: %s", provider.name, exc)

        return LLMResponse(content="", model=resolved_model, provider="none")
