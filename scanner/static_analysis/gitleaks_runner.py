"""
GitleaksRunner — wraps Gitleaks CLI and normalizes output to Finding,
with a built-in pure-Python regex secret scanner fallback when Gitleaks binary is absent.

Confidence note:
  All secret findings map to confidence=0.80.
"""
from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from scanner.models.finding import Finding, Severity

log = logging.getLogger(__name__)


def _find_tool(name: str) -> str | None:
    """Find a tool on PATH or in the current venv Scripts directory."""
    found = shutil.which(name)
    if found:
        return found
    if hasattr(sys, 'prefix'):
        venv_scripts = Path(sys.prefix) / "Scripts" / f"{name}.exe"
        if venv_scripts.is_file():
            return str(venv_scripts)
        venv_bin = Path(sys.prefix) / "bin" / name
        if venv_bin.is_file():
            return str(venv_bin)
    return None


_GITLEAKS_CONFIDENCE: float = 0.80

# Pure-Python secret regex patterns fallback
_SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", Severity.HIGH),
    (r"ASIA[0-9A-Z]{16}", "AWS Temporary Access Key ID", Severity.HIGH),
    (r"(?i)aws_secret_access_key\s*=\s*['\"][0-9a-zA-Z/+]{40}['\"]", "AWS Secret Access Key", Severity.CRITICAL),
    (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Live API Key", Severity.CRITICAL),
    (r"SG\.[0-9a-zA-Z._-]{20,60}", "SendGrid API Key", Severity.HIGH),
    (r"ghp_[0-9a-zA-Z]{36}", "GitHub Personal Access Token", Severity.CRITICAL),
    (r"gsk_[0-9a-zA-Z]{48}", "Groq API Key", Severity.CRITICAL),
    (r"-----BEGIN PRIVATE KEY-----", "Unencrypted RSA/PEM Private Key", Severity.CRITICAL),
    (r"(?i)(jwt_secret|secret_key|api_secret)\s*=\s*['\"][^'\"]{8,}['\"]", "Hardcoded Secret / JWT Key", Severity.HIGH),
    (r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]", "Hardcoded Password String", Severity.MEDIUM),
    # Password inside a connection string (.NET / JDBC / ODBC style): "...;Password=Abc123xyz;..."
    # The lookahead skips placeholders such as {0}, %s, $var, <secret>, @param.
    (r"(?i)\b(password|pwd)=(?![{%$<@])[^;'\"\s]{6,};", "Hardcoded Password in Connection String", Severity.MEDIUM),
    # Positional DB credentials: mysqli("host", "user", "password", ...), mysqli_connect(...), new PDO("dsn", "user", "password")
    (
        r"(?i)(?:mysqli(?:_connect)?|new\s+PDO)\s*\(\s*['\"][^'\"]*['\"]\s*,\s*['\"][^'\"]*['\"]\s*,\s*['\"][^'\"]{6,}['\"]",
        "Hardcoded Database Password (positional argument)",
        Severity.MEDIUM,
    ),
]

# Extensions the fallback scanner reads. It used to cover only Python/JS/TS/config/markdown, so
# secrets in Java, Go, PHP, C# and friends were never even opened.
_SCAN_GLOBS = (
    "*.py", "*.js", "*.jsx", "*.mjs", "*.cjs", "*.ts", "*.tsx",
    "*.java", "*.kt", "*.go", "*.php", "*.cs", "*.rb", "*.rs", "*.swift", "*.c", "*.cpp", "*.h",
    "*.sh", "*.gradle", "*.properties", "*.xml", "*.toml", "*.ini", "*.cfg", "*.conf", "*.tf",
    "*.json", "*.env", "*.yml", "*.yaml", "*.md",
)


def run_gitleaks(target: Path) -> list[Finding]:
    """
    Run secret detection on *target* and return normalized Findings.

    Without the Gitleaks binary, the built-in pure-Python scanner is used. With it, both run and
    the results are merged: Gitleaks' default rules are narrower than the built-in patterns (it
    misses generic hardcoded passwords, JWT secrets and connection-string credentials), so
    installing Gitleaks must not lower secret recall.
    """
    gitleaks_bin = _find_tool("gitleaks")
    if gitleaks_bin is None:
        log.info("gitleaks binary absent — using built-in pure-Python secret scanner")
        return _run_python_secret_scanner(target)

    real = _run_gitleaks_binary(gitleaks_bin, target)
    builtin = _run_python_secret_scanner(target)
    if real is None:
        return builtin
    return _merge_secret_findings(real, builtin)


def _merge_secret_findings(primary: list[Finding], extra: list[Finding]) -> list[Finding]:
    """Keep every *primary* finding and add *extra* ones that no primary finding already covers
    (same file, line inside the primary finding's line range)."""
    def key(path: Path) -> str:
        try:
            return str(path.resolve())
        except OSError:
            return str(path)

    covered = [(key(f.file_path), f.line_start, f.line_end) for f in primary]
    merged = list(primary)
    for f in extra:
        path = key(f.file_path)
        if not any(p == path and start <= f.line_start <= end for p, start, end in covered):
            merged.append(f)
    return merged


def _run_gitleaks_binary(gitleaks_bin: str, target: Path) -> list[Finding] | None:
    """Run the Gitleaks CLI. Returns None if it could not be run or its report could not be read."""
    # Write JSON report to a temp file (gitleaks doesn't support stdout reliably)
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        report_path = Path(tmp.name)

    cmd = [
        gitleaks_bin, "dir",
        "--report-format", "json",
        "--report-path", str(report_path),
        "--no-banner",
        str(target),
    ]

    try:
        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        log.warning("Gitleaks subprocess failed: %s", exc)
        return None

    try:
        text = report_path.read_text(encoding="utf-8")
        report_path.unlink(missing_ok=True)
    except OSError as exc:
        log.warning("Cannot read Gitleaks report: %s", exc)
        return None

    if not text.strip() or text.strip() == "null":
        return []

    try:
        items = json.loads(text)
    except json.JSONDecodeError as exc:
        log.warning("Gitleaks output is not valid JSON: %s", exc)
        return []

    if not isinstance(items, list):
        return []

    findings: list[Finding] = []
    for item in items:
        try:
            findings.append(_normalize(item))
        except Exception as exc:
            log.debug("Failed to normalize Gitleaks result: %s — %s", item, exc)

    log.info("Gitleaks: %d secrets found in %s", len(findings), target)
    return findings


def _run_python_secret_scanner(target: Path) -> list[Finding]:
    """Pure-Python fallback secret scanner for environments without gitleaks CLI."""
    findings: list[Finding] = []
    files_to_scan: list[Path] = []

    if target.is_file():
        files_to_scan.append(target)
    elif target.is_dir():
        for ext in _SCAN_GLOBS:
            files_to_scan.extend(target.rglob(ext))

    for filepath in files_to_scan:
        if any(ignored in str(filepath) for ignored in ("node_modules", ".git", "venv", ".venv", "dist")):
            continue
        try:
            content = filepath.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for line_idx, line in enumerate(content.splitlines(), start=1):
            for pattern, issue_type, severity in _SECRET_PATTERNS:
                match = re.search(pattern, line)
                if match:
                    findings.append(
                        Finding(
                            file_path=filepath,
                            issue_type=issue_type,
                            category="secrets",
                            severity=severity,
                            confidence=_GITLEAKS_CONFIDENCE,
                            line_start=line_idx,
                            line_end=line_idx,
                            evidence=line.strip(),
                            explanation=f"Hardcoded secret pattern matched: '{issue_type}'.",
                            suggested_fix="Store secrets in environment variables or a secrets manager.",
                            rule_source="gitleaks",
                        )
                    )
                    break  # one finding per line max

    log.info("Python Secret Scanner: %d secrets detected in %s", len(findings), target)
    return findings


def _normalize(item: dict) -> Finding:
    return Finding(
        file_path=Path(item.get("File", "unknown")),
        issue_type=item.get("Description", "Secret detected"),
        category="secrets",
        severity=Severity.HIGH,
        confidence=_GITLEAKS_CONFIDENCE,
        line_start=int(item.get("StartLine", 1)),
        line_end=int(item.get("EndLine", item.get("StartLine", 1))),
        evidence=item.get("Secret", "").strip(),
        explanation=(
            f"Gitleaks rule '{item.get('RuleID', 'unknown')}' matched. "
            f"Entropy: {item.get('Entropy', 'n/a')}"
        ),
        suggested_fix="Remove this secret and rotate it immediately. Store secrets in environment variables or a secrets manager.",
        rule_source="gitleaks",
    )
