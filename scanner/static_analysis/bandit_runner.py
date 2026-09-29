"""
BanditRunner — wraps Bandit (Python SAST tool) and normalizes output to Finding.

Bandit is a pip-installable package so it is always available in V1.
It is run as a subprocess on the target directory for consistent behavior
with the other tool wrappers.

Confidence mapping note:
  The HIGH→0.85 / MEDIUM→0.65 / LOW→0.45 values are heuristic mappings,
  not yet calibrated — revisit after benchmark runs in §7 of the plan.
"""
from __future__ import annotations

import json
import logging
import subprocess
import sys
from pathlib import Path

from scanner.models.finding import Finding, Severity

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity / confidence maps
# ---------------------------------------------------------------------------

_BANDIT_SEVERITY: dict[str, Severity] = {
    "HIGH":      Severity.HIGH,
    "MEDIUM":    Severity.MEDIUM,
    "LOW":       Severity.LOW,
    "UNDEFINED": Severity.INFO,
}

# heuristic mapping, not yet calibrated — revisit after benchmark runs in §7
_BANDIT_CONFIDENCE: dict[str, float] = {
    "HIGH":      0.85,
    "MEDIUM":    0.65,
    "LOW":       0.45,
    "UNDEFINED": 0.30,
}

# Bandit test-id prefix → AegisScan category
_BANDIT_CATEGORY_MAP: dict[str, str] = {
    "B1": "best_practices",   # B101–B199 misc
    "B2": "best_practices",   # B201–B299
    "B3": "crypto",           # B301–B399 crypto / deserialization
    "B4": "best_practices",   # B401–B499 imports
    "B5": "best_practices",   # B501–B599 TLS / HTTP
    "B6": "injection",        # B601–B699 injection (shell, subprocess)
    "B7": "injection",        # B701–B799 injection (XML, template)
}


# Bandit's B401-B415 flag the mere *import* of a risky module (subprocess, pickle, xml...).
# Bandit is certain the import exists, but an import is not a vulnerability: on the labelled
# benchmark 0 of 6 such findings were real issues. The call-site checks (B301, B602, ...)
# are what matter, so import-only findings carry low confidence.
_IMPORT_CHECK_CONFIDENCE = 0.30


def _is_import_check(test_id: str) -> bool:
    return test_id[:2].upper() == "B4" and len(test_id) == 4


def _infer_category(test_id: str) -> str:
    prefix = test_id[:2].upper() if len(test_id) >= 2 else ""
    return _BANDIT_CATEGORY_MAP.get(prefix, "best_practices")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_bandit(target: Path, exclude_dirs: frozenset[str] = frozenset()) -> list[Finding]:
    """
    Run Bandit on *target* directory and return a normalized list of Findings.

    Returns [] if Bandit is not installed, produces no findings, or errors out.
    Errors are logged as warnings — the scanner continues without Bandit output.
    """
    bandit_cmd = _find_bandit()
    if bandit_cmd is None:
        log.warning("Bandit not found on PATH or in venv — skipping")
        return []

    # tests/ and examples/ are scanned by default; opt out via .aegisscan.toml.
    _EXCLUDE_DIRS = [".venv", "venv", "node_modules", "__pycache__", "dist", ".git", "build", *sorted(exclude_dirs)]
    exclude_str = ",".join(
        str(target / d) for d in _EXCLUDE_DIRS if (target / d).exists()
    )
    cmd = [bandit_cmd, "-r", str(target), "-f", "json", "-q", "--exit-zero",
           "--skip", "B101"]  # B101 assert-used is noise in test files
    if exclude_str:
        cmd += ["--exclude", exclude_str]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        log.warning("Bandit subprocess failed: %s", exc)
        return []

    if not proc.stdout.strip():
        log.debug("Bandit produced no output")
        return []

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        log.warning("Bandit output is not valid JSON: %s", exc)
        return []

    findings: list[Finding] = []
    for item in data.get("results", []):
        try:
            findings.append(_normalize(item, target))
        except Exception as exc:
            log.debug("Failed to normalize Bandit result: %s — %s", item, exc)

    log.info("Bandit: %d findings in %s", len(findings), target)
    return findings


def _find_bandit() -> str | None:
    """Return the bandit executable path, preferring the active venv."""
    # Prefer venv-local bandit
    venv_bandit = Path(sys.executable).parent / "bandit"
    if venv_bandit.exists():
        return str(venv_bandit)
    venv_bandit_exe = venv_bandit.with_suffix(".exe")
    if venv_bandit_exe.exists():
        return str(venv_bandit_exe)
    # Fall back to PATH
    import shutil
    return shutil.which("bandit")


def _normalize(item: dict, target: Path) -> Finding:
    severity_str = item.get("issue_severity", "UNDEFINED").upper()
    confidence_str = item.get("issue_confidence", "UNDEFINED").upper()
    test_id = item.get("test_id", "B000")

    line_start = int(item.get("line_number", 1))
    line_range = item.get("line_range", [line_start])
    line_end = int(max(line_range)) if line_range else line_start

    return Finding(
        file_path=Path(item["filename"]),
        issue_type=item.get("test_name", "unknown").replace("_", " ").title(),
        category=_infer_category(test_id),
        severity=_BANDIT_SEVERITY.get(severity_str, Severity.INFO),
        confidence=(
            _IMPORT_CHECK_CONFIDENCE if _is_import_check(test_id) else _BANDIT_CONFIDENCE.get(confidence_str, 0.30)
        ),
        line_start=line_start,
        line_end=line_end,
        evidence=item.get("code", "").strip(),
        explanation=item.get("issue_text", ""),
        suggested_fix=item.get("more_info"),   # Bandit provides a doc URL
        rule_source="bandit",
    )
