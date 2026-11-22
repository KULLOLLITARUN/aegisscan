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

Rot handling: on first use the provider asks Groq which models the key can use
(models.list, one call) and drops configured models that are not served, warning
if none are. A model that still 404s is remembered as retired for the life of the
provider, so a scan does not pay for the same failure on every request.
"""
from __future__ import annotations

import logging
import os
import threading
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
        self._lock = threading.Lock()               # complete() is called from worker threads
        self._dead_models: set[str] = set()         # models Groq said do not exist for this key
        self._served: set[str] | None = None        # ids from models.list(); None = unknown
        self._served_checked = False
        self.rate_limit_hits = 0                    # 429s seen; the manager adds these to its telemetry

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

    def _served_models(self, client) -> set[str] | None:
        """Model ids Groq serves for this key (one models.list() call, cached). None if unknown."""
        with self._lock:
            if self._served_checked:
                return self._served
            self._served_checked = True
            try:
                self._served = {m.id for m in client.models.list().data} or None
            except Exception as exc:  # the list is an optimisation; never let it block a scan
                log.debug("Groq models.list() unavailable (%s) — relying on per-request failover", exc)
                self._served = None
            return self._served

    def _candidates(self, client, model: str) -> list[str]:
        """Configured models in failover order, minus ones known to be retired."""
        ordered = [model] + [m for m in _configured_models() if m != model]
        with self._lock:
            live = [m for m in ordered if m not in self._dead_models]
        served = self._served_models(client)
        if served:
            in_service = [m for m in live if m in served]
            if in_service:
                return in_service
            log.warning(
                "None of the configured Groq models (%s) are served for this key. Trying them anyway; "
                "set AEGISSCAN_GROQ_MODELS to one of: %s",
                ", ".join(ordered), ", ".join(sorted(served)[:8]),
            )
        return live or ordered   # everything marked retired: retry rather than give up silently

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

        client = self._get_client()
        models_to_try = self._candidates(client, model)

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
                    with self._lock:
                        self.rate_limit_hits += 1
                    log.warning("Groq rate limit on model %s — failing over to next model...", current_model)
                    time.sleep(0.2)
                    continue
                elif _is_model_unavailable(exc_str):
                    with self._lock:
                        self._dead_models.add(current_model)   # do not pay for this 404 on every request
                    log.warning("Groq model %s unavailable for this key — trying next model...", current_model)
                    continue
                else:
                    log.warning("Groq API call failed on model %s: %s", current_model, exc)
                    break

        return LLMResponse(content="", model=model, provider=self.name)
