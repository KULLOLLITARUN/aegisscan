"""
Secret Redactor & Privacy Modes — V6

Scrubs sensitive values from code before external LLM transmission.

Privacy Modes:
  - standard: Redacts API keys, tokens, passwords, AWS keys, hex/b64 secrets.
  - redact: standard + email addresses, IP addresses, JWT tokens.
  - strict: redact + masks all string literals ("...") and numeric constants.
"""
from __future__ import annotations

import re
from enum import Enum


class PrivacyMode(str, Enum):
    STANDARD = "standard"
    REDACT   = "redact"
    STRICT   = "strict"


# ---------------------------------------------------------------------------
# Standard redaction patterns
# ---------------------------------------------------------------------------

_STANDARD_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'\b(sk-[a-zA-Z0-9]{20,})\b'), '[REDACTED_API_KEY]'),
    (re.compile(r'\b(gsk_[a-zA-Z0-9]{20,})\b'), '[REDACTED_GROQ_KEY]'),
    (re.compile(r'(Bearer\s+)[a-zA-Z0-9._\-]{20,}', re.IGNORECASE), r'\1[REDACTED_TOKEN]'),
    (re.compile(r'\b(AKIA[0-9A-Z]{16})\b'), '[REDACTED_AWS_KEY]'),
    (re.compile(r'\b([a-zA-Z0-9/+]{40})\b(?=.*aws)', re.IGNORECASE), '[REDACTED_AWS_SECRET]'),
    (
        re.compile(
            r'(?i)(password|passwd|secret(?:_key)?|api[_-]?key|token|auth[_-]?key|private[_-]?key)'
            r'(\s*[=:]\s*["\'])([^"\']{8,})(["\'])',
        ),
        r'\1\2[REDACTED]\4',
    ),
    (re.compile(r'\b([0-9a-fA-F]{32,})\b'), '[REDACTED_HEX]'),
    (re.compile(r'(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{40,}={0,2})(?![A-Za-z0-9+/=])'), '[REDACTED_B64]'),
]

# ---------------------------------------------------------------------------
# Extra patterns for 'redact' privacy mode
# ---------------------------------------------------------------------------

_REDACT_EXTRA_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Emails
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'), '[REDACTED_EMAIL]'),
    # IPv4 addresses
    (re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'), '[REDACTED_IP]'),
    # JWT tokens
    (re.compile(r'\b(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\b'), '[REDACTED_JWT]'),
]

# ---------------------------------------------------------------------------
# Strict patterns (masks literals)
# ---------------------------------------------------------------------------

_STRICT_STRING_PATTERN = re.compile(r'(["\'])(?:(?=(\\?))\2.)*?\1')


def redact(code: str, mode: PrivacyMode | str = PrivacyMode.STANDARD) -> str:
    """
    Apply redaction patterns to *code* according to *mode*.
    """
    if isinstance(mode, str):
        try:
            mode = PrivacyMode(mode.lower())
        except ValueError:
            mode = PrivacyMode.STANDARD

    result = code

    # Apply standard patterns
    for pattern, replacement in _STANDARD_PATTERNS:
        result = pattern.sub(replacement, result)

    if mode in (PrivacyMode.REDACT, PrivacyMode.STRICT):
        for pattern, replacement in _REDACT_EXTRA_PATTERNS:
            result = pattern.sub(replacement, result)

    if mode == PrivacyMode.STRICT:
        # Mask string literals
        result = _STRICT_STRING_PATTERN.sub('"[REDACTED_LITERAL]"', result)

    return result


def redact_finding_evidence(evidence: str, mode: PrivacyMode | str = PrivacyMode.STANDARD) -> str:
    """Redact a Finding.evidence snippet before sending to LLM."""
    return redact(evidence, mode=mode)
