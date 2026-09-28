"""
GroqProvider — LLM provider implementation for Groq with automatic model failover.

API key is read from the GROQ_API_KEY environment variable.
If the key is absent or invalid, is_available returns False and complete()
returns an empty response — the auditor degrades gracefully.

Default model sequence (fails over on 429 rate limits):
1. llama-3.1-8b-instant
2. llama-3.3-70b-versatile
3. mixtral-8x7b-32768
4. gemma2-9b-it
"""
from __future__ import annotations

import logging
import os
import time

from scanner.providers.base import LLMProvider, LLMResponse

log = logging.getLogger(__name__)

DEFAULT_MODEL = "llama-3.1-8b-instant"
FALLBACK_MODELS = [
    "llama-3.1-8b-instant",
    "llama-3.3-70b-versatile",
    "mixtral-8x7b-32768",
    "gemma2-9b-it",
]


class GroqProvider(LLMProvider):
    """Groq cloud LLM provider with automatic rate-limit model failover."""

    def __init__(self) -> None:
        self._api_key = os.environ.get("GROQ_API_KEY", "").strip()
        self._client = None   # lazy-initialised on first use

        if not self._api_key:
            log.warning(
                "GROQ_API_KEY not set — LLM auditor will be skipped. "
                "Set the variable and restart to enable AI reasoning."
            )

    @property
    def name(self) -> str:
        return "groq"

    @property
    def is_available(self) -> bool:
        self._api_key = os.environ.get("GROQ_API_KEY", "").strip()
        return bool(self._api_key)

    def _get_client(self):
        """Lazy-init the Groq client (avoids import cost when not configured)."""
        if self._client is None or self._client.api_key != self._api_key:
            from groq import Groq  # noqa: PLC0415
            self._client = Groq(api_key=self._api_key, max_retries=0)
        return self._client

    def complete(
        self,
        messages: list[dict],
        model: str = DEFAULT_MODEL,
        max_tokens: int = 2048,
        temperature: float = 0.0,
    ) -> LLMResponse:
        if not self.is_available:
            return LLMResponse(content="", model=model, provider=self.name)

        models_to_try = [model] + [m for m in FALLBACK_MODELS if m != model]

        client = self._get_client()

        for current_model in models_to_try:
            try:
                resp = client.chat.completions.create(
                    model=current_model,
                    messages=messages,
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
                content = resp.choices[0].message.content or ""
                usage = resp.usage
                return LLMResponse(
                    content=content,
                    model=resp.model,
                    provider=self.name,
                    input_tokens=getattr(usage, "prompt_tokens", 0),
                    output_tokens=getattr(usage, "completion_tokens", 0),
                )
            except Exception as exc:
                exc_str = str(exc)
                if "429" in exc_str or "rate_limit" in exc_str.lower():
                    log.warning("Groq rate limit on model %s — failing over to next model...", current_model)
                    time.sleep(0.2)
                    continue
                else:
                    log.warning("Groq API call failed on model %s: %s", current_model, exc)
                    break

        return LLMResponse(content="", model=model, provider=self.name)
