"""
Deduplicator — removes near-duplicate findings across tools and sources.

Deduplication strategy (V3):
  Two findings are considered duplicates if they share:
    - Same file
    - Overlapping or adjacent line ranges (within PROXIMITY_LINES lines)
    - Same semantic category

  A finding never merges into a cluster that already holds a *different* finding from
  its own source: one tool reports each distinct issue once, so two hits from the same
  tool a few lines apart (e.g. two SQL injections) are separate issues, not duplicates.
  Only identical repeats (same source, issue type and lines) collapse within a source.

  When duplicates are found, the one with the HIGHEST confidence is kept.
  If confidence is equal, source priority applies:
    llm > bandit > semgrep > gitleaks

  This is the V3 baseline dedup. V5 will add ML-assisted similarity matching.

Fingerprint:
  Each Finding gets a stable 16-char hex fingerprint based on
  file + line + issue_type + rule_source. Used by the baseline system.
"""
from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from scanner.models.finding import Finding

log = logging.getLogger(__name__)

# Lines within this distance are considered "same area" for dedup
PROXIMITY_LINES: int = 5

# Source priority for tie-breaking (higher index = lower priority)
_SOURCE_PRIORITY: dict[str, int] = {
    "llm":      0,   # highest — LLM provides nuanced reasoning
    "bandit":   1,
    "semgrep":  2,
    "gitleaks": 3,
    "aegis-opt": 4,
}


def _fingerprint_path(file_path: Path, root: Path | None) -> str:
    """Path component of a fingerprint.

    With *root* (the scan target) the path is made relative and slash-normalised, so the same
    finding fingerprints identically on Windows/Linux and in any checkout directory. Without
    *root* it is the path exactly as scanned (legacy, machine-specific). A path outside *root*
    cannot be made relative and falls back to its slash-normalised form.
    """
    if root is None:
        return str(file_path)
    try:
        return Path(file_path).resolve().relative_to(Path(root).resolve()).as_posix()
    except (ValueError, OSError):
        return Path(file_path).as_posix()


def fingerprint(finding: Finding, root: Path | None = None) -> str:
    """
    Stable 16-char hex identifier for a finding — same across scan runs.

    Used by the baseline suppression system to suppress already-known issues.
    The fingerprint is intentionally coarser than the UUID (which changes every
    run) to allow minor line-number drift while still matching the same issue.

    Pass the scan target as *root* to get a portable fingerprint (see _fingerprint_path).
    """
    key = (
        f"{_fingerprint_path(finding.file_path, root)}:"
        f"{finding.line_start // PROXIMITY_LINES}:"   # tolerates small line shifts
        f"{finding.issue_type.lower().replace(' ', '_')}:"
        f"{finding.category}:"
        f"{finding.rule_source}"
    )
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _source_priority(finding: Finding) -> int:
    return _SOURCE_PRIORITY.get(finding.rule_source, 99)


def _findings_overlap(a: Finding, b: Finding) -> bool:
    """True if two findings are in the same file, same category, and nearby lines."""
    if a.file_path != b.file_path:
        return False
    if a.category != b.category:
        return False
    # Proximity check: do line ranges overlap or are they within PROXIMITY_LINES?
    a_start, a_end = a.line_start, a.line_end
    b_start, b_end = b.line_start, b.line_end
    return a_start <= b_end + PROXIMITY_LINES and b_start <= a_end + PROXIMITY_LINES


def _same_issue(a: Finding, b: Finding) -> bool:
    """An exact repeat of the same finding by the same source."""
    return (
        a.rule_source == b.rule_source
        and a.issue_type == b.issue_type
        and a.line_start == b.line_start
        and a.line_end == b.line_end
    )


def _can_join(finding: Finding, cluster: list[Finding]) -> bool:
    if not _findings_overlap(finding, cluster[0]):
        return False
    return all(m.rule_source != finding.rule_source or _same_issue(m, finding) for m in cluster)


def deduplicate(findings: list[Finding]) -> tuple[list[Finding], int]:
    """
    Remove near-duplicate findings and return (deduped_list, n_suppressed).

    Algorithm: greedy clustering — each finding is assigned to the first
    existing cluster it overlaps with. The best finding per cluster is kept.
    """
    if not findings:
        return [], 0

    # Cluster findings
    clusters: list[list[Finding]] = []

    for f in findings:
        placed = False
        for cluster in clusters:
            if _can_join(f, cluster):
                cluster.append(f)
                placed = True
                break
        if not placed:
            clusters.append([f])

    # Pick the best from each cluster
    kept: list[Finding] = []
    for cluster in clusters:
        if len(cluster) == 1:
            kept.append(cluster[0])
            continue

        # Sort: highest confidence first, then by source priority
        best = sorted(
            cluster,
            key=lambda f: (-f.confidence, _source_priority(f)),
        )[0]
        kept.append(best)

    n_suppressed = len(findings) - len(kept)
    if n_suppressed:
        log.info("Deduplicator: removed %d duplicate finding(s)", n_suppressed)

    return kept, n_suppressed
