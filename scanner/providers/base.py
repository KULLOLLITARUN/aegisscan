"""
LLMProvider — abstract interface for all LLM provider implementations.

Design rule (plan §2 rule 2): The LLM auditor NEVER imports a specific provider
directly. It only calls ProviderManager, which owns the provider instances.
Swapping or adding providers (V5) must never require rewriting the auditor.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class LLMResponse:
    """Raw response from a provider completion call."""
    content: str        # the text response from the model
    model: str          # model name that actually responded
    provider: str       # provider name e.g. "groq"
    input_tokens: int = 0
    output_tokens: int = 0


class LLMProvider(ABC):
    """Abstract base for all LLM provider implementations."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider identifier string e.g. 'groq'."""
        ...

    @property
    @abstractmethod
    def is_available(self) -> bool:
        """True if the provider is configured and reachable."""
        ...

    @abstractmethod
    def complete(
        self,
        messages: list[dict],
        model: str,
        max_tokens: int = 2048,
        temperature: float = 0.0,
    ) -> LLMResponse:
        """
        Send a chat completion request and return the response.

        Must never raise — return an LLMResponse with empty content on failure
        so the auditor can handle it gracefully.
        """
        ...
