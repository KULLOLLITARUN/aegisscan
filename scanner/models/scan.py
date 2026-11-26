"""
ScanResult — top-level output of a complete AegisScan run.

Scoring note (plan §4 V4):
  security_score and optimization_score are intentionally absent until V4.
  They are present as Optional[float] = None with a TODO marker so the model
  shape is stable across versions, but they must not be populated before V4
  when real findings exist to calibrate weights against.
"""
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from scanner.models.finding import Finding


class ScanResult(BaseModel):
    """Top-level output: scan metadata + file inventory + findings list."""

    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    target_path: Path

    # ---- File inventory (populated by V0 crawler + classifier) ----
    files_discovered: int = 0   # total non-ignored files found
    files_analyzed: int = 0     # files passed to static / LLM pipeline
    files_ignored: int = 0      # excluded by .gitignore or hardcoded rules
    files_binary: int = 0       # binary files (skipped from analysis)
    files_generated: int = 0    # auto-generated files (skipped from analysis)
    files_oversized: int = 0    # files above the size threshold (skipped)
    chunks_created: int = 0     # CodeChunks produced by the chunker (V1+)

    language_breakdown: dict[str, int] = Field(default_factory=dict)

    # ---- Timing & tooling (populated by orchestration in main.py) ----
    scan_duration_seconds: float = 0.0
    static_tools_run: list[str] = Field(default_factory=list)  # V1+: tools that ran to completion
    # Tools that did not run or ran incompletely, with the reason (a failed tool must not look like a clean scan)
    static_tool_issues: dict[str, str] = Field(default_factory=dict)
    llm_provider: Optional[str] = None    # V2+: provider name e.g. 'groq'
    llm_model: Optional[str] = None       # V2+: model name used for LLM pass
    llm_chunks_analyzed: int = 0          # V2+: chunks sent to LLM auditor
    findings_deduplicated: int = 0        # V3+: findings removed by deduplicator
    findings_suppressed: int = 0          # V3+: findings removed by baseline
    findings_corroborated: int = 0        # V3+: findings confirmed by 2+ sources

    # ---- Telemetry & API Performance (V5+) ----
    llm_requests_count: int = 0           # V5+: total API requests made to LLM
    llm_total_input_tokens: int = 0       # V5+: total input tokens consumed
    llm_total_output_tokens: int = 0      # V5+: total output tokens generated
    llm_total_latency_seconds: float = 0.0# V5+: total time spent in LLM API calls
    llm_rate_limit_hits: int = 0          # V5+: total 429 rate limit responses encountered
    llm_fallback_triggered: bool = False  # V5+: True if provider fallback was used
    llm_json_valid_count: int = 0         # responses that parsed on the first try
    llm_json_repaired_count: int = 0      # responses that needed the repair prompt
    llm_json_failed_count: int = 0        # responses that never parsed (chunk skipped)

    # ---- Scores — TODO: uncalibrated — introduced in V4 only ----
    security_score: Optional[float] = None       # 0–100, higher = safer
    optimization_score: Optional[float] = None   # 0–100, higher = better

    # ---- Findings (populated by V1+ analysis) ----
    findings: list[Finding] = Field(default_factory=list)
