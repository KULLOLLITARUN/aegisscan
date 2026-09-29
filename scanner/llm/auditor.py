"""
LLMAuditor — the V2 AI reasoning layer.

Pipeline per chunk:
  1. TriggerEngine decides if LLM should analyze this chunk
  2. Secret redactor scrubs sensitive values (plan §2 rule 8)
  3. Prompt is built with code + existing static findings as context
  4. ProviderManager sends to Groq
  5. JSON response is validated with Pydantic (LLMResponseSchema)
  6. On invalid JSON → one repair retry
  7. Confidence bucketing applied (≥0.90 confirmed, etc.)
  8. Findings below SUPPRESSION_THRESHOLD are dropped (not in output by default)
  9. Surviving findings are returned as typed Finding objects

The auditor NEVER imports a provider directly — only ProviderManager.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from pydantic import ValidationError

from scanner.llm.prompts import REPAIR_PROMPT, SYSTEM_PROMPT, build_user_prompt
from scanner.llm.redactor import redact
from scanner.llm.schemas import LLMFindingDraft, LLMResponseSchema
from scanner.llm.trigger import TriggerEngine
from scanner.models.chunk import CodeChunk
from scanner.models.finding import Finding, Severity
from scanner.providers.manager import ProviderManager

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Confidence bucketing thresholds (plan §4 V2)
# ---------------------------------------------------------------------------

#: Findings below this threshold are suppressed from output by default.
SUPPRESSION_THRESHOLD: float = 0.60

_CONFIDENCE_LABELS: list[tuple[float, str]] = [
    (0.90, "confirmed"),
    (0.75, "strong"),
    (0.60, "needs review"),
    (0.00, "suppressed"),
]

# Severity string → Severity enum  (LLM may return any casing)
_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high":     Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "low":      Severity.LOW,
    "info":     Severity.INFO,
}


def _confidence_label(confidence: float) -> str:
    for threshold, label in _CONFIDENCE_LABELS:
        if confidence >= threshold:
            return label
    return "suppressed"


def _max_workers() -> int:
    """Worker threads for the LLM pass (env AEGISSCAN_LLM_WORKERS, default 4)."""
    try:
        return max(1, int(os.environ.get("AEGISSCAN_LLM_WORKERS", "4")))
    except ValueError:
        return 4


class LLMAuditor:
    """
    Orchestrates the LLM reasoning pass for a set of code chunks.

    Usage::

        auditor = LLMAuditor()
        llm_findings = auditor.analyze_chunks(chunks, static_findings, deep=False)
    """

    def __init__(
        self,
        provider_manager: ProviderManager | None = None,
        privacy_mode: str = "standard",
        generate_patches: bool = False,
    ) -> None:
        self._manager = provider_manager or ProviderManager()
        self._trigger = TriggerEngine()
        self._privacy_mode = privacy_mode
        self._generate_patches = generate_patches
        # JSON-contract telemetry (plan section 7): responses valid first try / after repair / never
        self._json_lock = threading.Lock()
        self.json_valid_count = 0
        self.json_repaired_count = 0
        self.json_failed_count = 0

    def _record_json(self, attr: str) -> None:
        with self._json_lock:
            setattr(self, attr, getattr(self, attr) + 1)

    @property
    def is_available(self) -> bool:
        return self._manager.is_available

    def analyze_chunks(
        self,
        chunks: list[CodeChunk],
        static_findings: list[Finding],
        deep: bool = False,
        progress: Callable[[int, int], None] | None = None,
    ) -> list[Finding]:
        """
        Run the LLM over triggered chunks and return new/enriched findings.

        Returns [] immediately if no provider is configured (graceful degradation).
        """
        if not self.is_available:
            log.info("LLMAuditor: no provider available — skipping LLM pass")
            return []

        all_llm_findings: list[Finding] = []
        suppressed = 0

        work: list[tuple[CodeChunk, list[Finding]]] = []
        for chunk in chunks:
            if self._trigger.should_analyze(chunk, static_findings, deep=deep):
                work.append((chunk, self._trigger.get_chunk_findings(chunk, static_findings)))
        triggered = len(work)
        skipped = len(chunks) - triggered

        done = 0
        done_lock = threading.Lock()

        def _tick() -> None:
            nonlocal done
            if progress is None:
                return
            with done_lock:
                done += 1
                current = done
            try:
                progress(current, triggered)
            except Exception:  # a UI callback must never break the scan
                log.debug("progress callback failed", exc_info=True)

        def _process(item: tuple[CodeChunk, list[Finding]]) -> tuple[list[Finding], int]:
            chunk, chunk_static = item
            findings = self._analyze_one(chunk, chunk_static)
            kept = [f for f in findings if f.confidence >= SUPPRESSION_THRESHOLD]
            if self._generate_patches:
                from scanner.llm.patcher import generate_patch_for_finding
                for f in kept:
                    if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
                        f.fix_patch = generate_patch_for_finding(f, self._manager)
            _tick()
            return kept, len(findings) - len(kept)

        # Chunks are independent, so overlap the network waits. Pacing is still
        # enforced globally by the ProviderManager's (thread-safe) rate limiter.
        workers = max(1, min(_max_workers(), len(work)))
        if workers == 1:
            results = [_process(item) for item in work]
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                results = list(pool.map(_process, work))   # map preserves chunk order
        for kept, n_suppressed in results:
            all_llm_findings.extend(kept)
            suppressed += n_suppressed

        log.info(
            "LLMAuditor: %d chunks triggered, %d skipped, %d LLM findings kept, %d suppressed",
            triggered, skipped, len(all_llm_findings), suppressed,
        )
        return all_llm_findings

    # ------------------------------------------------------------------
    # Internal: analyze a single chunk
    # ------------------------------------------------------------------

    def _analyze_one(
        self,
        chunk: CodeChunk,
        static_findings: list[Finding],
    ) -> list[Finding]:
        """Analyze one chunk — returns validated Finding objects."""

        # Step 1: redact before transmission (plan §2 rule 8)
        redacted_code = redact(chunk.code, mode=self._privacy_mode)

        # Step 2: build messages
        user_msg = build_user_prompt(chunk, static_findings, redacted_code)
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_msg},
        ]

        # Step 3: call provider
        response = self._manager.complete(messages, max_tokens=2048, temperature=0.0)
        if not response.content:
            return []

        # Step 4: parse + validate JSON (with one repair retry)
        parsed = self._parse_response(response.content, messages)
        if parsed is None:
            return []

        # Step 5: convert drafts → Finding
        findings: list[Finding] = []
        for draft in parsed.findings:
            finding = self._draft_to_finding(
                draft=draft,
                chunk=chunk,
                provider=response.provider,
                model=response.model,
            )
            if finding is not None:
                findings.append(finding)

        return findings

    def _parse_response(
        self,
        content: str,
        messages: list[dict],
    ) -> LLMResponseSchema | None:
        """Parse JSON response with one repair retry on failure."""

        def _try_parse(text: str) -> LLMResponseSchema | None:
            text = text.strip()
            # Strip markdown code fences if present
            if text.startswith("```"):
                lines = text.splitlines()
                text = "\n".join(
                    ln for ln in lines
                    if not ln.strip().startswith("```")
                )
            try:
                data = json.loads(text)
                return LLMResponseSchema.model_validate(data)
            except (json.JSONDecodeError, ValidationError) as exc:
                log.debug("JSON parse failed: %s", exc)
                return None

        result = _try_parse(content)
        if result is not None:
            self._record_json("json_valid_count")
            return result

        # One repair attempt
        log.debug("LLM returned invalid JSON — sending repair prompt")
        repair_messages = messages + [
            {"role": "assistant", "content": content},
            {"role": "user",      "content": REPAIR_PROMPT},
        ]
        repair_response = self._manager.complete(repair_messages, max_tokens=1024, temperature=0.0)
        if not repair_response.content:
            self._record_json("json_failed_count")
            return None

        result = _try_parse(repair_response.content)
        if result is None:
            self._record_json("json_failed_count")
            log.warning("LLM repair attempt failed — skipping chunk")
        else:
            self._record_json("json_repaired_count")
        return result

    @staticmethod
    def _draft_to_finding(
        draft: LLMFindingDraft,
        chunk: CodeChunk,
        provider: str,
        model: str,
    ) -> Finding | None:
        """Convert a validated LLMFindingDraft into a Finding."""
        severity = _SEVERITY_MAP.get(draft.severity, Severity.LOW)
        label = _confidence_label(draft.confidence)
        log.debug(
            "LLM finding: %s | %s | confidence %.0f%% (%s)",
            draft.issue_type, severity.value, draft.confidence * 100, label,
        )

        try:
            return Finding(
                file_path=chunk.file_path,
                issue_type=draft.issue_type,
                category=draft.category,
                severity=severity,
                confidence=draft.confidence,
                line_start=draft.line_start or chunk.line_start,
                line_end=draft.line_end or chunk.line_end,
                evidence=draft.evidence or chunk.code[:300],
                explanation=draft.explanation,
                suggested_fix=draft.suggested_fix,
                rule_source="llm",
                provider=provider,
                model=model,
            )
        except Exception as exc:
            log.debug("Failed to build Finding from draft: %s", exc)
            return None
