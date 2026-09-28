"""
Finding — the universal contract for a single security or optimization finding.

Design rules (plan §2):
- Confidence and severity are independent axes (rule 5): Critical + confidence 0.6
  means "potentially severe, not yet trustworthy" — not "ignore" and not "alarm".
- Confidence is stored as a raw float 0.0–1.0. Percentage display is deferred to
  the reporting layer (V4+) — there is nothing to display in V0.
- provider and model fields exist for V2+ (Groq integration); they are Optional
  and unused in V0.
"""
import uuid
from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    """Maps to the donut-chart slices in the UI plan §3.1."""
    INJECTION = "injection"
    SECRETS = "secrets"
    ACCESS_CONTROL = "access_control"
    CRYPTO = "crypto"
    PERFORMANCE = "performance"
    BEST_PRACTICES = "best_practices"
    OTHER = "other"


class Finding(BaseModel):
    """
    A single security or optimization finding, normalized from any source.

    rule_source values:
      "semgrep"    — Semgrep SAST rule (V1)
      "bandit"     — Bandit Python analyser (V1)
      "gitleaks"   — Gitleaks secrets scanner (V1)
      "llm"        — LLM-only finding (V2)
      "correlated" — merged static + LLM finding on same location/category (V3)
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    file_path: Path
    issue_type: str          # human-readable label e.g. "SQL Injection"
    category: str            # Category enum value or free-form string
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)   # raw float; display % in V4+
    line_start: int
    line_end: int
    evidence: str            # raw code snippet that triggered this finding
    explanation: str         # rule description or LLM-authored reasoning
    suggested_fix: Optional[str] = None          # corrected code / guidance (V2+)
    fix_patch: Optional[str] = None              # unified git diff patch snippet (V8+)

    # Source tracking
    rule_source: str         # "semgrep" | "bandit" | "gitleaks" | "llm" | "correlated"
    provider: Optional[str] = None   # "groq" (V2+; Groq only per project constraint)
    model: Optional[str] = None      # e.g. "llama-3.3-70b" (V2+)

    # History tracking (V10+)
    first_seen_scan_id: Optional[str] = None  # scan_id of the first run that surfaced this finding
