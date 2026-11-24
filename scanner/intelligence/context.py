"""
Context weighting: findings in tests, examples, docs and fixtures are down-weighted.

On real repositories most high-severity hits in `tests/` and `examples/` are deliberate
(`debug=True` in a test app, a throwaway secret key, a demo that echoes input). They are still
reported, but one severity level lower and at half confidence, so they do not dominate the
score or the high-severity count. Paths are judged relative to the scan target, so scanning a
folder such as `tests/` directly does not demote everything in it.
"""
from __future__ import annotations

import logging
from pathlib import Path

from scanner.models.finding import Finding, Severity

log = logging.getLogger(__name__)

# Directory names (any depth, relative to the scan target) that hold non-production code.
NON_PRODUCTION_DIRS: frozenset[str] = frozenset({
    "test", "tests", "__tests__", "spec", "specs", "testing", "testdata", "fixtures",
    "example", "examples", "demo", "demos", "sample", "samples", "docs", "doc", "benchmark",
})

CONFIDENCE_FACTOR: float = 0.5
NOTE = "[non-production path: test, example or docs code; severity lowered one level] "

_DEMOTE = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
}


def is_non_production(file_path: Path, root: Path) -> bool:
    try:
        rel = Path(file_path).resolve().relative_to(Path(root).resolve())
    except (ValueError, OSError):
        return False
    parts = [p.lower() for p in rel.parts[:-1]]
    name = rel.name.lower()
    if any(p in NON_PRODUCTION_DIRS for p in parts):
        return True
    return name.startswith("test_") or name.endswith(("_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts", "_test.go"))


def weight_by_context(findings: list[Finding], root: Path) -> tuple[list[Finding], int]:
    """Return (findings, n_demoted). Performance findings are left alone."""
    out: list[Finding] = []
    n = 0
    for f in findings:
        if f.category == "performance" or not is_non_production(f.file_path, root):
            out.append(f)
            continue
        n += 1
        out.append(f.model_copy(update={
            "severity": _DEMOTE.get(f.severity, f.severity),
            "confidence": round(f.confidence * CONFIDENCE_FACTOR, 4),
            "explanation": NOTE + f.explanation,
        }))
    if n:
        log.info("Context weighting: lowered %d finding(s) in test/example/docs paths", n)
    return out, n
