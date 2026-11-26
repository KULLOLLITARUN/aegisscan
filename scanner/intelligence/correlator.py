"""
Correlator — groups related findings and marks multi-source corroboration.

Correlation means: when two or more tools independently flag the same code spot, those
findings are "corroborated" and their confidence is bumped slightly.

The deduplicator runs first and merges findings from different tools that point at the same spot
into one, so the agreement is no longer visible as separate findings here. It records it on the
kept finding (``Finding.corroborated_by``), and that is what counts. In addition, two findings of
the same category from different tools within CORRELATION_WINDOW lines still corroborate each
other. Findings of different categories never do: a hard-coded secret three lines from an
unrelated style warning is not agreement.

Confidence boost note:
  The +0.05 corroboration boost is a heuristic, not yet calibrated —
  revisit after benchmark runs in §7 of the plan.

Output:
  The correlator returns:
    - A list of Finding objects (with confidence potentially boosted)
    - A list of CorrelationGroup objects summarising the clusters (for V4 reports)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from scanner.models.finding import Finding

log = logging.getLogger(__name__)

# Findings within this many lines of each other are considered correlated
CORRELATION_WINDOW: int = 10

# heuristic confidence boost for corroborated findings — revisit after §7 benchmark
CORROBORATION_BOOST: float = 0.05
MAX_CONFIDENCE: float = 1.0


@dataclass
class CorrelationGroup:
    """A cluster of findings that reference the same code area from multiple sources."""
    file_path: Path
    line_center: int                    # approximate centre of the cluster
    findings: list[Finding] = field(default_factory=list)

    @property
    def sources(self) -> list[str]:
        """Every tool that flagged this area, including those merged away by the deduplicator."""
        return sorted({f.rule_source for f in self.findings} | {s for f in self.findings for s in f.corroborated_by})

    @property
    def is_corroborated(self) -> bool:
        """True if 2+ distinct sources agree on this area."""
        return len(self.sources) >= 2

    @property
    def highest_severity(self):
        return min(self.findings, key=lambda f: list(__import__("scanner.models.finding", fromlist=["Severity"]).Severity).index(f.severity)).severity


def _in_same_window(a: Finding, b: Finding) -> bool:
    """True if two findings are in the same file and category, within CORRELATION_WINDOW lines."""
    if a.file_path != b.file_path or a.category != b.category:
        return False
    centre_a = (a.line_start + a.line_end) // 2
    centre_b = (b.line_start + b.line_end) // 2
    return abs(centre_a - centre_b) <= CORRELATION_WINDOW


def correlate(findings: list[Finding]) -> tuple[list[Finding], list[CorrelationGroup]]:
    """
    Group findings into correlation clusters, boost confidence for corroborated ones.

    Returns:
        boosted_findings : same findings with confidence boosted where corroborated
        groups           : list[CorrelationGroup] for use by report/UI layers (V4+)
    """
    if not findings:
        return [], []

    # Build clusters using the same greedy approach as the deduplicator, but only compare findings
    # that share a file and category, so a big scan does not compare every finding with every cluster.
    clusters: list[list[Finding]] = []
    by_bucket: dict[tuple[Path, str], list[list[Finding]]] = {}
    for f in findings:
        bucket = by_bucket.setdefault((f.file_path, f.category), [])
        for cluster in bucket:
            if _in_same_window(f, cluster[0]):
                cluster.append(f)
                break
        else:
            cluster = [f]
            bucket.append(cluster)
            clusters.append(cluster)

    boosted: list[Finding] = []
    groups: list[CorrelationGroup] = []

    for cluster in clusters:
        centre_line = sum(
            (f.line_start + f.line_end) // 2 for f in cluster
        ) // len(cluster)

        group = CorrelationGroup(
            file_path=cluster[0].file_path,
            line_center=centre_line,
            findings=list(cluster),
        )
        groups.append(group)

        for f in cluster:
            # Another tool agrees with this finding: one the deduplicator merged into it, or a
            # neighbour in the cluster that came from a different tool.
            agreeing = ({g.rule_source for g in cluster if g is not f} | set(f.corroborated_by)) - {f.rule_source}
            if agreeing:
                # heuristic boost — not yet calibrated, revisit after §7 benchmark
                new_conf = min(f.confidence + CORROBORATION_BOOST, MAX_CONFIDENCE)
                boosted.append(f.model_copy(update={
                    "confidence": new_conf,
                    "corroborated_by": sorted({*f.corroborated_by, *agreeing}),
                }))
            else:
                boosted.append(f)

    corroborated_count = sum(1 for g in groups if g.is_corroborated)
    if corroborated_count:
        log.info(
            "Correlator: %d corroborated cluster(s) found (confidence boosted by %.0f%%)",
            corroborated_count, CORROBORATION_BOOST * 100,
        )

    return boosted, groups
