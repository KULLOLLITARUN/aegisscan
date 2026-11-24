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
import re
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


CI_HYGIENE_NOTE = "[CI configuration hygiene note; severity capped at low] "
LLM_CI_CONFIDENCE_CAP: float = 0.5   # a model's notes about workflow files are never stated as near-certain
_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _in_github_config(file_path: Path, root: Path) -> bool:
    try:
        rel = Path(file_path).resolve().relative_to(Path(root).resolve())
    except (ValueError, OSError):
        return False
    return bool(rel.parts) and rel.parts[0].lower() == ".github"


def _ci_hygiene_update(f: Finding) -> dict | None:
    """The changes to make to a finding in a `.github/` file, or None to leave it alone.

    A static tool's "best practice" note is hygiene. An LLM finding in any category except
    injection is treated the same way: on Gin the model labelled the same workflow notes
    `access_control` / `secrets` at confidence 1.00 and rated seven of them high, which pulled the
    score from 70 to 27.
    """
    from_llm = f.rule_source == "llm" and f.category != "injection"
    if f.category != "best_practices" and not from_llm:
        return None
    update: dict = {}
    if _SEVERITY_ORDER.index(f.severity) > _SEVERITY_ORDER.index(Severity.LOW):
        update["severity"] = Severity.LOW
    if from_llm and f.confidence > LLM_CI_CONFIDENCE_CAP:
        update["confidence"] = LLM_CI_CONFIDENCE_CAP
    if update:
        update["explanation"] = CI_HYGIENE_NOTE + f.explanation
    return update or None


def cap_ci_hygiene(findings: list[Finding], root: Path) -> tuple[list[Finding], int]:
    """Cap "best practice" notes about `.github/` files at low severity.

    Registry rules flag every workflow step that uses a tag instead of a commit SHA and every
    Dependabot file without a cooldown. These are worth fixing, but they say nothing about the
    code, and on a well-run project (Gin: 17 of 22 findings) they drag the score down.
    Real problems in those files, such as `${{ github.* }}` interpolated into a `run:` step,
    are category "injection" and are not touched.
    """
    out: list[Finding] = []
    n = 0
    for f in findings:
        update = _ci_hygiene_update(f) if _in_github_config(f.file_path, root) else None
        if update:
            n += 1
            f = f.model_copy(update=update)
        out.append(f)
    if n:
        log.info("Context weighting: capped %d CI hygiene finding(s) at low", n)
    return out, n


# ---------------------------------------------------------------------------
# Found by scanning Django (2,521 findings, none of its 11 "high" ones a real vulnerability)
# ---------------------------------------------------------------------------

def drop_test_performance(findings: list[Finding], root: Path) -> tuple[list[Finding], int]:
    """Remove performance findings in test, example and docs paths (368 of Django's 445).

    Looping over database calls is how tests build their data; it is not a production cost.
    Security findings in those paths are kept (and lowered by weight_by_context).
    """
    kept = [f for f in findings if not (f.category == "performance" and is_non_production(f.file_path, root))]
    n = len(findings) - len(kept)
    if n:
        log.info("Context weighting: dropped %d performance finding(s) in test/example/docs paths", n)
    return kept, n


# Direction marks used by right-to-left languages; unlike the embedding/override/isolate
# characters (U+202A-202E, U+2066-2069) they cannot make code read differently from how it runs.
_HARMLESS_BIDI = frozenset({0x200E, 0x200F, 0x061C})
_UNICODE_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")
_SECURITY_NAME = re.compile(r"(?i)passw|pwd|passphrase|secret|token|credential|api[_-]?key")
BANDIT_NOTE = "[likely benign here; severity capped at low] "


def _flagged_line(f: Finding) -> str | None:
    """The source line a finding points at, taken from its numbered evidence."""
    for raw in f.evidence.splitlines():
        number, _, text = raw.partition(" ")
        if number.isdigit() and int(number) == f.line_start:
            return text
    return None


def soften_bandit_false_alarms(findings: list[Finding]) -> tuple[list[Finding], int]:
    """Cap two Bandit patterns that are almost never a vulnerability in real code.

    * "Trojansource" when the only bidirectional characters are the harmless direction marks
      (Django's Arabic and Persian date formats). Real Trojan Source uses the override,
      embedding or isolate characters, which keep their severity.
    * MD5/SHA1 ("Hashlib") on a line that does not mention a password, secret, token or key
      (cache keys, SQLite functions, checksums). A hash of a password stays high.
    """
    out: list[Finding] = []
    n = 0
    for f in findings:
        soften = False
        if f.rule_source == "bandit" and f.severity.value in ("high", "medium"):
            if f.issue_type == "Trojansource":
                points = {int(h, 16) for h in _UNICODE_ESCAPE.findall(f.explanation)}
                soften = bool(points) and points <= _HARMLESS_BIDI
            elif f.issue_type == "Hashlib":
                line = _flagged_line(f)
                soften = line is not None and not _SECURITY_NAME.search(line)
        if soften:
            n += 1
            out.append(f.model_copy(update={"severity": Severity.LOW, "explanation": BANDIT_NOTE + f.explanation}))
        else:
            out.append(f)
    if n:
        log.info("Context weighting: capped %d benign Bandit finding(s) at low", n)
    return out, n
