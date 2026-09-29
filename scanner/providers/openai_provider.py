"""
OpenAIProvider — OpenAI-compatible chat completions over plain HTTPS (no SDK).

Configuration (environment):
  OPENAI_API_KEY          required; provider is unavailable without it
  OPENAI_BASE_URL         optional; default https://api.openai.com/v1
                          (works with any OpenAI-compatible endpoint)
  AEGISSCAN_OPENAI_MODEL  optional; default gpt-4o-mini

Like every provider, complete() never raises — failures return empty content
so the ProviderManager can fail over.
"""
from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request

from scanner.providers.base import LLMProvider, LLMResponse

log = logging.getLogger(__name__)

DEFAULT_OPENAI_URL = "https://api.openai.com/v1"
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"


class OpenAIProvider(LLMProvider):
    """OpenAI (or OpenAI-compatible) chat completions provider."""

    def __init__(self, timeout: float = 60.0) -> None:
        self._timeout = timeout

    @property
    def name(self) -> str:
        return "openai"

    @property
    def default_model(self) -> str:
        return os.environ.get("AEGISSCAN_OPENAI_MODEL", DEFAULT_OPENAI_MODEL)

    @property
    def is_available(self) -> bool:
        return bool(os.environ.get("OPENAI_API_KEY", "").strip())

    def complete(
        self,
        messages: list[dict],
        model: str | None = None,
        max_tokens: int = 2048,
        temperature: float = 0.0,
    ) -> LLMResponse:
        target_model = model or self.default_model
        if not self.is_available:
            return LLMResponse(content="", model=target_model, provider=self.name)

        base = os.environ.get("OPENAI_BASE_URL", DEFAULT_OPENAI_URL).rstrip("/")
        payload = {
            "model": target_model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        req = urllib.request.Request(
            f"{base}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {os.environ['OPENAI_API_KEY'].strip()}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            content = data["choices"][0]["message"].get("content") or ""
            usage = data.get("usage") or {}
            return LLMResponse(
                content=content,
                model=data.get("model", target_model),
                provider=self.name,
                input_tokens=usage.get("prompt_tokens", 0),
                output_tokens=usage.get("completion_tokens", 0),
            )
        except urllib.error.HTTPError as exc:
            # Surface 429 in the message so execute_with_backoff can recognise it.
            log.warning("OpenAI HTTP %s: %s", exc.code, exc.reason)
            if exc.code == 429:
                raise RuntimeError("429 rate_limit from OpenAI") from exc
        except Exception as exc:
            log.warning("OpenAI completion error: %s", exc)
        return LLMResponse(content="", model=target_model, provider=self.name)
