"""
Pydantic schemas for validating LLM JSON responses.

The LLM is instructed to return a JSON object matching LLMResponseSchema.
Pydantic validates the structure; invalid or missing fields get sensible defaults
rather than crashing — the auditor applies retry/repair only on total JSON failure.
"""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field, field_validator


class LLMFindingDraft(BaseModel):
    """A single finding as returned by the LLM — pre-normalization."""

    issue_type: str = "Unknown Issue"
    category: str = "best_practices"
    severity: str = "low"                       # will be mapped to Severity enum
    confidence: float = Field(default=0.70, ge=0.0, le=1.0)
    # None = the model gave no usable line; the auditor then locates the finding by its evidence
    # snippet, and failing that anchors it at the chunk start (never a silent "line 1" of the file).
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    evidence: str = ""
    explanation: str = ""
    suggested_fix: Optional[str] = None

    @field_validator("line_start", "line_end", mode="before")
    @classmethod
    def lenient_line(cls, v: object) -> Optional[int]:
        """Accept ints and numeric strings; anything else (missing, null, 'n/a', <1) means unlocated."""
        if isinstance(v, bool):
            return None
        try:
            n = int(v)  # type: ignore[call-overload]
        except (TypeError, ValueError):
            return None
        return n if n >= 1 else None

    @field_validator("severity", mode="before")
    @classmethod
    def normalise_severity(cls, v: str) -> str:
        return str(v).lower().strip()

    @field_validator("category", mode="before")
    @classmethod
    def normalise_category(cls, v: str) -> str:
        valid = {"injection", "secrets", "access_control", "crypto", "performance", "best_practices", "other"}
        v = str(v).lower().strip().replace(" ", "_").replace("-", "_")
        return v if v in valid else "best_practices"


class LLMResponseSchema(BaseModel):
    """Top-level schema for LLM JSON output."""
    findings: list[LLMFindingDraft] = Field(default_factory=list)
