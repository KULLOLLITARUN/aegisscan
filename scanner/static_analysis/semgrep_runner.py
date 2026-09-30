"""
SemgrepRunner — wraps Semgrep CLI and normalizes output to Finding.

Config: --config=p/python --config=p/javascript (no login required, OSS ruleset).
This choice is intentional (plan §2 + user decision): a V1 static layer that
blocks headlessly waiting for auth is a bad foundation.

Semgrep is optional: if not on PATH the runner logs a warning and returns [].

Confidence mapping note:
  The severity→confidence values are heuristic mappings, not yet calibrated —
  revisit after benchmark runs in §7 of the plan.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
import sys
from pathlib import Path

from scanner.models.finding import Finding, Severity

log = logging.getLogger(__name__)


def _find_tool(name: str) -> str | None:
    """Find a tool on PATH or in the current venv's Scripts directory."""
    found = shutil.which(name)
    if found:
        return found
    # Fallback: check the active venv's Scripts directory (pip-installed tools)
    if hasattr(sys, 'prefix'):
        venv_scripts = Path(sys.prefix) / "Scripts" / f"{name}.exe"
        if venv_scripts.is_file():
            return str(venv_scripts)
        venv_bin = Path(sys.prefix) / "bin" / name
        if venv_bin.is_file():
            return str(venv_bin)
    return None

# heuristic mapping, not yet calibrated — revisit after benchmark runs in §7
_SEMGREP_SEVERITY_MAP: dict[str, Severity] = {
    "ERROR":   Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO":    Severity.LOW,
}

_SEMGREP_CONFIDENCE: dict[str, float] = {
    "ERROR":   0.80,
    "WARNING": 0.65,
    "INFO":    0.50,
}

_SEMGREP_CONFIGS = ["p/python", "p/javascript", "p/owasp-top-ten", "p/security-audit", "p/nodejsscan"]

#: AegisScan's own rules (bundled with the package); they run offline alongside the registry packs.
_LOCAL_RULES = Path(__file__).parent / "rules" / "js_security.yml"


def _infer_category(rule_id: str) -> str:
    rl = rule_id.lower()
    if any(k in rl for k in ("injection", "sqli", "xss", "ssrf", "rce", "command", "exec")):
        return "injection"
    if any(k in rl for k in ("secret", "key", "token", "credential", "password", "api-key")):
        return "secrets"
    if any(k in rl for k in ("auth", "access", "permission", "privilege", "csrf")):
        return "access_control"
    if any(k in rl for k in ("crypto", "hash", "cipher", "tls", "ssl", "rand")):
        return "crypto"
    if any(k in rl for k in ("perf", "performance", "n+1", "cache", "complexity")):
        return "performance"
    return "best_practices"


def run_semgrep(target: Path) -> list[Finding]:
    """
    Run Semgrep on *target* and return normalized Findings.
    Returns [] if Semgrep is not installed or produces no output.
    """
    semgrep_bin = _find_tool("semgrep")
    if semgrep_bin is None:
        log.warning("semgrep not found on PATH or venv — skipping")
        return []

    config_flags = []
    for cfg in _SEMGREP_CONFIGS:
        config_flags += ["--config", cfg]
    if _LOCAL_RULES.is_file():
        config_flags += ["--config", str(_LOCAL_RULES)]

    cmd = [
        semgrep_bin, "scan",
        *config_flags,
        "--json",
        "--quiet",
        "--no-git-ignore",        # respect our own ignore list, not semgrep's
        str(target),
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        log.warning("Semgrep subprocess failed: %s", exc)
        return []

    output = proc.stdout.strip()
    if not output:
        log.debug("Semgrep produced no output")
        return []

    try:
        data = json.loads(output)
    except json.JSONDecodeError as exc:
        log.warning("Semgrep output is not valid JSON: %s", exc)
        return []

    # A single invalid config (e.g. a renamed registry pack -> HTTP 404) makes Semgrep
    # exit 7 with zero results, which used to look identical to "nothing found".
    for err in data.get("errors", []):
        if err.get("level") == "error":
            log.warning("Semgrep error (exit %d): %s", proc.returncode, str(err.get("message", ""))[:200])

    findings: list[Finding] = []
    for item in data.get("results", []):
        try:
            findings.append(_normalize(item))
        except Exception as exc:
            log.debug("Failed to normalize Semgrep result: %s — %s", item, exc)

    log.info("Semgrep: %d findings in %s", len(findings), target)
    return findings


def _normalize(item: dict) -> Finding:
    meta  = item.get("extra", {})
    sev   = meta.get("severity", "INFO").upper()
    start = item.get("start", {})
    end   = item.get("end", {})

    return Finding(
        file_path=Path(item["path"]),
        issue_type=meta.get("message", "Semgrep finding")[:120],
        category=meta.get("metadata", {}).get("aegis_category") or _infer_category(item.get("check_id", "")),
        severity=_SEMGREP_SEVERITY_MAP.get(sev, Severity.INFO),
        confidence=_SEMGREP_CONFIDENCE.get(sev, 0.50),
        line_start=int(start.get("line", 1)),
        line_end=int(end.get("line", start.get("line", 1))),
        evidence=meta.get("lines", "").strip(),
        explanation=meta.get("message", ""),
        suggested_fix=None,
        rule_source="semgrep",
    )
