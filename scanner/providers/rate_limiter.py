"""
RateLimiter & Retry Backoff Helper — V5

Manages API request pacing via a token-bucket algorithm and provides
exponential backoff with jitter for handling HTTP 429 / transient rate limits.
"""
from __future__ import annotations

import logging
import random
import time
from typing import Callable, TypeVar

log = logging.getLogger(__name__)

T = TypeVar("T")


class RateLimiter:
    """
    Token-bucket rate limiter.

    Args:
        requests_per_minute: Maximum requests allowed per 60-second window.
    """

    def __init__(self, requests_per_minute: int = 30, initial_tokens: int | None = None) -> None:
        self.capacity = requests_per_minute
        self.tokens = float(requests_per_minute if initial_tokens is None else max(0, min(initial_tokens, requests_per_minute)))
        self.refill_rate = requests_per_minute / 60.0  # tokens per second
        self.last_refill = time.monotonic()

    def _refill(self) -> None:
        now = time.monotonic()
        delta = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + delta * self.refill_rate)
        self.last_refill = now

    def acquire(self) -> None:
        """Block until a token is available."""
        while True:
            self._refill()
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return
            sleep_time = (1.0 - self.tokens) / self.refill_rate
            time.sleep(max(0.05, sleep_time))


def execute_with_backoff(
    func: Callable[[], T],
    max_retries: int = 3,
    base_delay: float = 2.0,
    max_delay: float = 30.0,
    on_rate_limit: Callable[[], None] | None = None,
) -> T:
    """
    Execute a function with exponential backoff and jitter on 429 / rate-limit exceptions.

    Args:
        func: Callable to execute.
        max_retries: Maximum retry attempts.
        base_delay: Initial backoff delay in seconds.
        max_delay: Maximum delay cap in seconds.
        on_rate_limit: Callback invoked whenever a rate-limit (429) hit occurs.

    Returns:
        Result of func().
    """
    attempt = 0
    while True:
        try:
            return func()
        except Exception as exc:
            exc_str = str(exc).lower()
            is_rate_limit = "429" in exc_str or "rate limit" in exc_str or "too many requests" in exc_str

            if is_rate_limit and on_rate_limit is not None:
                on_rate_limit()

            attempt += 1
            if attempt > max_retries:
                log.warning("Max retries (%d) reached for call: %s", max_retries, exc)
                raise

            # Exponential backoff + jitter (±20%)
            delay = min(max_delay, base_delay * (2 ** (attempt - 1)))
            jitter = delay * random.uniform(-0.2, 0.2)
            actual_delay = max(0.5, delay + jitter)

            log.info(
                "Rate limit / transient error on attempt %d/%d. Retrying in %.2fs... (%s)",
                attempt, max_retries, actual_delay, exc,
            )
            time.sleep(actual_delay)
