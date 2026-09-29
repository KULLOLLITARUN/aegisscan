"""
GroqProvider — LLM provider implementation for Groq with automatic model failover.

API key is read from the GROQ_API_KEY environment variable.
If the key is absent or invalid, is_available returns False and complete()
returns an empty response — the auditor degrades gracefully.

Default model sequence (fails over on 429 rate limits and on
unknown/retired models — Groq retires models regularly):
1. openai/gpt-oss-20b
2. openai/gpt-oss-120b
3. qwen/qwen3.8-27b

Override with AEGISSCAN_GROQ_MODELS (comma-separated, first is the default).
"""
from __future__ import annotations

import logging
import os
import time

from scanner.providers.base import LLMProvider, LLMResponse

log = logging.getLogger(__name__)

_BUILTIN_MODELS = ["openai/gpt-oss-20b", "openai/gpt-oss-120b", "qwen/qwen3.8-27b"]


def _configured_models() -> list[str]:
    raw = os.environ.get("AEGISSCAN_GROQ_MODELS", "")
    models = [m.strip() for m in raw.split(",") if m.strip()]
    return models or list(_BUILTIN_MODELS)


DEFAULT_MODEL = _BUILTIN_MODELS[0]
FALLBACK_MODELS = _BUILTIN_MODELS


def _is_model_unavailable(exc_str: str) -> bool:
    low = exc_str.lower()
    return (
        "404" in exc_str
        or "model_not_found" in low
        or "decommissioned" in low
        or "does not exist" in low
    )


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
    def default_model(self) -> str:
        return _configured_models()[0]

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
        model: str | None = None,
        max_tokens: int = 2048,
        temperature: float = 0.0,
    ) -> LLMResponse:
        model = model or self.default_model
        if not self.is_available:
            return LLMResponse(content="", model=model, provider=self.name)

        models_to_try = [model] + [m for m in _configured_models() if m != model]

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
                elif _is_model_unavailable(exc_str):
                    log.warning("Groq model %s unavailable for this key — trying next model...", current_model)
                    continue
                else:
                    log.warning("Groq API call failed on model %s: %s", current_model, exc)
                    break

        return LLMResponse(content="", model=model, provider=self.name)
