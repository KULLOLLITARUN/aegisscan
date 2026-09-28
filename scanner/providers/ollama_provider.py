"""
OllamaProvider — V5 local/offline LLM integration.

Communicates with a local Ollama daemon (default: http://localhost:11434).
If Ollama is not installed or not running, is_available returns False gracefully.
"""
from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any

from scanner.providers.base import LLMProvider, LLMResponse

log = logging.getLogger(__name__)

DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_OLLAMA_MODEL = "llama3"


class OllamaProvider(LLMProvider):
    """Local Ollama provider implementation."""

    def __init__(
        self,
        host: str = DEFAULT_OLLAMA_URL,
        default_model: str = DEFAULT_OLLAMA_MODEL,
    ) -> None:
        self.host = host.rstrip("/")
        self.default_model = default_model
        self._checked_available: bool | None = None

    @property
    def name(self) -> str:
        return "ollama"

    @property
    def is_available(self) -> bool:
        """Check if local Ollama daemon is active."""
        if self._checked_available is not None:
            return self._checked_available

        try:
            req = urllib.request.Request(f"{self.host}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                self._checked_available = (resp.status == 200)
        except Exception:
            self._checked_available = False

        return self._checked_available

    def complete(
        self,
        messages: list[dict],
        model: str | None = None,
        max_tokens: int = 2048,
        temperature: float = 0.0,
    ) -> LLMResponse:
        """Send completion request to Ollama /api/chat."""
        target_model = model or self.default_model

        if not self.is_available:
            log.warning("Ollama provider called but daemon is not available")
            return LLMResponse(content="", model=target_model, provider=self.name)

        payload: dict[str, Any] = {
            "model": target_model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }

        try:
            data_bytes = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                f"{self.host}/api/chat",
                data=data_bytes,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30.0) as resp:
                result = json.loads(resp.read().decode("utf-8"))

            content = result.get("message", {}).get("content", "")
            eval_count = result.get("eval_count", 0)
            prompt_eval_count = result.get("prompt_eval_count", 0)

            return LLMResponse(
                content=content,
                model=target_model,
                provider=self.name,
                input_tokens=prompt_eval_count,
                output_tokens=eval_count,
            )
        except Exception as exc:
            log.error("Ollama completion error: %s", exc)
            return LLMResponse(content="", model=target_model, provider=self.name)
