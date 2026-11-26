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
  Exception: when the winner is an LLM finding and a static finding is within
  STATIC_LOCATION_MARGIN of its confidence, the static one is kept, because its
  location is exact while the LLM's is inferred.

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

# A static finding this close in confidence to an LLM finding wins the cluster (exact location)
STATIC_LOCATION_MARGIN: float = 0.10

# Source priority for tie-breaking (higher index = lower priority)
_SOURCE_PRIORITY: dict[str, int] = {
    "llm":      0,   # highest — LLM provides nuanced reasoning
    "bandit":   1,
    "semgrep":  2,
    "gitleaks": 3,
    "aegis-opt": 4,
    "osv":      5,
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


def _pick_best(cluster: list[Finding]) -> Finding:
    """Highest confidence wins, then source priority; but a static tool's location beats an LLM's.

    The LLM only sees a chunk of code and its line numbers are located after the fact, so when
    a static finding is within STATIC_LOCATION_MARGIN of the best LLM finding we keep the static
    one: its file:line is exact, the LLM's may be a few lines off.
    """
    ranked = sorted(cluster, key=lambda f: (-f.confidence, _source_priority(f)))
    best = ranked[0]
    if best.rule_source == "llm":
        for f in ranked[1:]:
            if f.rule_source != "llm" and f.confidence >= best.confidence - STATIC_LOCATION_MARGIN:
                return f
        return _bound_llm_severity(best, cluster)
    return best


def _bound_llm_severity(llm: Finding, cluster: list[Finding]) -> Finding:
    """An LLM finding that wins a cluster on confidence does not also inherit a higher severity.

    Found live on Gin: the model rated `unsafe` string conversion high at 0.95 and, being more
    confident than Semgrep's 0.75 note on the same lines, replaced Semgrep's medium with its own
    high. When a static tool flagged the same spot, its severity is the ceiling, except for
    categories where the model may be telling us something the tool cannot (injection, XSS, ...).
    """
    static = [f for f in cluster if f.rule_source != "llm"]
    if not static or llm.category in _HIGH_IMPACT_LLM_CATEGORIES:
        return llm
    ceiling = max((f.severity for f in static), key=lambda s: _SEVERITY_RANK.get(s.value, 0))
    if _SEVERITY_RANK.get(llm.severity.value, 0) <= _SEVERITY_RANK.get(ceiling.value, 0):
        return llm
    return llm.model_copy(update={"severity": ceiling})


_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _same_spot(a: Finding, b: Finding) -> bool:
    """Same tool, same file, same exact lines, and compatible categories.

    One tool often reports one line through several rules (eval flagged as injection and as
    two "best practice" rules; nine session-cookie settings on one `session({...})` call).
    The catch-all "best_practices" category is compatible with any other, because the registry
    rules that land there are really the same sink under a vaguer name.
    """
    if (a.file_path, a.line_start, a.line_end, a.rule_source) != (
        b.file_path, b.line_start, b.line_end, b.rule_source,
    ):
        return False
    return a.category == b.category or "best_practices" in (a.category, b.category)


def _collapse_same_spot(findings: list[Finding]) -> list[Finding]:
    """Keep one finding per (tool, exact lines); the most severe, then most confident, wins."""
    groups: list[list[Finding]] = []
    index: dict[tuple, list[list[Finding]]] = {}
    for f in findings:
        key = (f.file_path, f.line_start, f.line_end, f.rule_source)
        for g in index.get(key, []):
            if _same_spot(g[0], f):
                g.append(f)
                break
        else:
            g = [f]
            groups.append(g)
            index.setdefault(key, []).append(g)

    def rank(f: Finding) -> tuple[int, float, bool]:
        # A specific category beats the catch-all when severity and confidence tie.
        return (_SEVERITY_RANK.get(f.severity.value, 0), f.confidence, f.category != "best_practices")

    return [max(g, key=rank) if len(g) > 1 else g[0] for g in groups]


# An LLM finding in one of these categories is never dropped for echoing a static note: a static
# "best practice" hit on the same line must not hide a model's claim of injection or XSS.
_HIGH_IMPACT_LLM_CATEGORIES: frozenset[str] = frozenset({"injection", "xss", "deserialization", "path_traversal"})


def _ranges_intersect(a: Finding, b: Finding) -> bool:
    return a.line_start <= b.line_end and b.line_start <= a.line_end


def _drop_llm_echoes(findings: list[Finding]) -> list[Finding]:
    """Drop an LLM finding that re-labels a static catch-all note on the very same lines.

    Found live on Gin: the model re-reported Semgrep's "mutable action tag" notes under other
    categories (`access_control`, `secrets`) and at confidence 1.00, so the same line counted twice
    and the copy outranked the original. The clustering step cannot merge them, because it needs
    equal categories. The static finding has the exact location and the vaguer label, so it stays.
    """
    static_notes = [f for f in findings if f.rule_source != "llm" and f.category == "best_practices"]
    if not static_notes:
        return findings
    kept: list[Finding] = []
    for f in findings:
        if (
            f.rule_source == "llm"
            and f.category not in ("best_practices", *_HIGH_IMPACT_LLM_CATEGORIES)
            and any(s.file_path == f.file_path and _ranges_intersect(s, f) for s in static_notes)
        ):
            continue
        kept.append(f)
    return kept


def deduplicate(findings: list[Finding]) -> tuple[list[Finding], int]:
    """
    Remove near-duplicate findings and return (deduped_list, n_suppressed).

    Algorithm: greedy clustering — each finding is assigned to the first
    existing cluster it overlaps with. The best finding per cluster is kept. Before that, several
    rules of one tool on the same exact lines collapse into the most severe one.
    """
    if not findings:
        return [], 0

    total = len(findings)
    findings = _drop_llm_echoes(_collapse_same_spot(findings))

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

        best = _pick_best(cluster)
        # The cluster merged findings from several tools: remember who agreed with the one we keep.
        others = sorted({m.rule_source for m in cluster if m.rule_source != best.rule_source})
        if others:
            best = best.model_copy(update={"corroborated_by": sorted({*best.corroborated_by, *others})})
        kept.append(best)

    n_suppressed = total - len(kept)
    if n_suppressed:
        log.info("Deduplicator: removed %d duplicate finding(s)", n_suppressed)

    return kept, n_suppressed
