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
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from scanner.models.finding import Finding, Severity
from scanner.static_analysis import status
from scanner.static_analysis.scope import batches

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
    "WARNING": 0.75,   # was 0.65; the benchmark showed WARNING findings correct ~90% of the time
    "INFO":    0.50,
}

_SEMGREP_CONFIGS = ["p/python", "p/javascript", "p/owasp-top-ten", "p/security-audit", "p/nodejsscan"]

#: AegisScan's own rules (bundled with the package); they run offline alongside the registry packs.
_RULES_DIR = Path(__file__).parent / "rules"
_LOCAL_RULES = _RULES_DIR / "js_security.yml"
# AegisScan's own rules, one file per language (js, java, go, php, csharp), loaded next to the registry packs.
_LOCAL_RULE_FILES = tuple(sorted(_RULES_DIR.glob("*_security.yml")))


# Words that decide a category. Matched against whole words of the rule id, never inside a word:
# a substring test sent `monkey-patch` to secrets, `author` to access_control and `operand` to crypto.
# `_CATEGORY_STEMS` are matched as word prefixes, which is safe for long stems (`injection`,
# `credential`) and so also covers `credentials`, `hashing`, `exec`/`execute`.
_CATEGORY_WORDS: tuple[tuple[str, frozenset[str], tuple[str, ...]], ...] = (
    ("injection", frozenset({"sqli", "xss", "ssrf", "rce", "xxe"}), ("injection", "command", "exec")),
    ("secrets", frozenset({"secret", "secrets", "key", "keys", "apikey", "token", "tokens", "password",
                           "passwords", "passwd"}), ("credential",)),
    ("access_control", frozenset({"auth", "authn", "authz", "csrf", "access", "permission", "permissions",
                                  "privilege", "privileges"}), ("authentication", "authorization", "unauthenticated")),
    ("crypto", frozenset({"crypto", "hash", "hashes", "cipher", "tls", "ssl", "rand", "random", "md5", "sha1"}),
     ("cryptograph", "hashing", "encrypt", "decrypt")),
    ("performance", frozenset({"perf", "performance", "n+1", "cache", "complexity"}), ()),
)

# CWE ids that name a category outright. A rule that carries a CWE is more reliable than its id.
_CWE_CATEGORY: dict[int, str] = {
    **dict.fromkeys((20, 22, 23, 77, 78, 79, 88, 89, 90, 91, 94, 95, 98, 113, 117, 502, 611, 643, 652, 918), "injection"),
    **dict.fromkeys((256, 259, 321, 522, 532, 798), "secrets"),
    **dict.fromkeys((284, 285, 287, 306, 352, 639, 862, 863), "access_control"),
    **dict.fromkeys((295, 310, 326, 327, 328, 329, 330, 331, 338, 347), "crypto"),
}


def _category_from_cwe(metadata: object) -> str | None:
    """Category named by the first mapped CWE in the rule's metadata, or None."""
    if not isinstance(metadata, dict):
        return None
    cwe = metadata.get("cwe")
    for entry in cwe if isinstance(cwe, list) else [cwe]:
        match = re.search(r"CWE-(\d+)", str(entry or ""), re.IGNORECASE)
        if match and int(match.group(1)) in _CWE_CATEGORY:
            return _CWE_CATEGORY[int(match.group(1))]
    return None


def _infer_category(rule_id: str, metadata: object = None) -> str:
    """Category for a Semgrep rule: its CWE if it names one, else whole words of the rule id."""
    by_cwe = _category_from_cwe(metadata)
    if by_cwe:
        return by_cwe
    words = [w for w in re.split(r"[^a-z0-9+]+", rule_id.lower()) if w]
    for category, exact, stems in _CATEGORY_WORDS:
        if any(w in exact or w.startswith(stems) for w in words):
            return category
    return "best_practices"


def _semgrep_timeout() -> int:
    """Seconds Semgrep may run. Shorter in hosted mode so a slow Semgrep cannot use up the whole scan limit."""
    try:
        return max(10, int(os.environ["AEGISSCAN_SEMGREP_TIMEOUT_S"]))
    except (KeyError, ValueError):
        return 150 if os.environ.get("AEGISSCAN_MODE", "").strip().lower() == "hosted" else 300


def _kill_tree(proc: subprocess.Popen) -> None:
    """Stop Semgrep and the semgrep-core workers it started (killing only the parent leaves them running)."""
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True, timeout=15)
        else:
            proc.kill()
    except Exception:  # noqa: BLE001 - best effort
        pass
    try:
        proc.kill()
    except Exception:  # noqa: BLE001
        pass


def _run_bounded(cmd: list[str], timeout_s: int) -> subprocess.CompletedProcess:
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        out, err = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        proc.communicate()
        raise
    return subprocess.CompletedProcess(cmd, proc.returncode, out, err)


def run_semgrep(
    target: Path,
    files: list[Path] | None = None,
    exclude_dirs: frozenset[str] = frozenset(),
) -> list[Finding]:
    """
    Run Semgrep on *target* and return normalized Findings.

    Directories named in *exclude_dirs* (``.aegisscan.toml``) are skipped. With *files*
    (``--changed-only``) only those files are scanned, in as few Semgrep runs as the command-line
    length allows; the caller has already dropped excluded files, since ``--exclude`` does not
    apply to explicitly listed files. Returns [] if Semgrep is not installed or produces no output.
    """
    semgrep_bin = _find_tool("semgrep")
    if semgrep_bin is None:
        log.warning("semgrep not found on PATH or venv — skipping")
        status.problem("semgrep", "not installed")
        return []

    config_flags = []
    for cfg in _SEMGREP_CONFIGS:
        config_flags += ["--config", cfg]
    for rule_file in _LOCAL_RULE_FILES:
        config_flags += ["--config", str(rule_file)]

    base = [
        semgrep_bin, "scan",
        *config_flags,
        "--json",
        "--quiet",
        "--no-git-ignore",        # respect our own ignore list, not semgrep's
        # Without a project root, Semgrep treats a folder that is not a Git repo as "somewhere inside
        # your disk" and walks up and around the user's profile folders (minutes of wasted time).
        # Pinning the root to the scanned folder keeps it there and also avoids creating any files.
        *(["--project-root", str(target)] if Path(target).is_dir() else []),
        "--metrics=off",
        *(arg for d in sorted(exclude_dirs) for arg in ("--exclude", d)),
    ]

    if files is None:
        findings = _run_semgrep_once([*base, str(target)])
    else:
        if not files:
            return []
        findings = []
        for batch in batches(files, fixed_len=sum(len(a) + 1 for a in base)):
            findings.extend(_run_semgrep_once([*base, *batch]))
    log.info("Semgrep: %d findings in %s", len(findings), target)
    return findings


def _run_semgrep_once(cmd: list[str]) -> list[Finding]:
    """Run one Semgrep command line and normalise its JSON output."""
    timeout_s = _semgrep_timeout()
    try:
        proc = _run_bounded(cmd, timeout_s)
    except subprocess.TimeoutExpired:
        log.warning("Semgrep stopped after %d s; continuing with the other tools' results", timeout_s)
        status.problem("semgrep", f"timed out after {timeout_s} s")
        return []
    except (FileNotFoundError, OSError) as exc:
        log.warning("Semgrep subprocess failed: %s", exc)
        status.problem("semgrep", f"could not be started ({exc})")
        return []

    output = proc.stdout.strip()
    if not output:
        # With --json Semgrep always prints a document, even with no results.
        log.warning("Semgrep produced no output (exit %d): %s", proc.returncode, proc.stderr.strip()[:200])
        status.problem("semgrep", f"produced no report (exit {proc.returncode})")
        return []

    try:
        data = json.loads(output)
    except json.JSONDecodeError as exc:
        log.warning("Semgrep output is not valid JSON: %s", exc)
        status.problem("semgrep", "produced an unreadable report")
        return []

    # A single invalid config (e.g. a renamed registry pack -> HTTP 404) makes Semgrep
    # exit 7 with zero results, which used to look identical to "nothing found".
    for err in data.get("errors", []):
        if err.get("level") == "error":
            message = str(err.get("message", ""))[:200]
            log.warning("Semgrep error (exit %d): %s", proc.returncode, message)
            status.problem("semgrep", f"reported an error, results may be incomplete: {message}")

    findings: list[Finding] = []
    seen: set[tuple] = set()
    for item in data.get("results", []):
        # Semgrep can report one match several times (seen with `$X.$M($ARG, ...)` rules); the
        # deduplicator never merges two findings from the same source, so drop exact repeats here.
        start, end = item.get("start", {}), item.get("end", {})
        key = (item.get("check_id"), item.get("path"),
               start.get("line"), start.get("col"), end.get("line"), end.get("col"))
        if key in seen:
            continue
        seen.add(key)
        try:
            findings.append(_normalize(item))
        except Exception as exc:
            log.debug("Failed to normalize Semgrep result: %s — %s", item, exc)

    return findings


def _rule_confidence(metadata: object) -> float | None:
    """A rule's own ``aegis_confidence`` (bundled rules set it), or None to use the severity default.

    Rubric for bundled rules, by the shape of the rule and not by benchmark results: 0.90 unsafe by
    construction or a visible request source; 0.85 a dangerous sink guarded to non-literal
    arguments; 0.80 request-driven or name-based weak crypto; 0.70 a sink whose argument may or may
    not be attacker-controlled (no taint tracking).
    """
    if not isinstance(metadata, dict):
        return None
    # Stored as a quoted string ("0.85") because Semgrep's rule loader rejects float metadata values.
    value = metadata.get("aegis_confidence")
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    try:
        number = float(value)
    except ValueError:
        return None
    return number if 0.0 < number <= 1.0 else None


def _normalize(item: dict) -> Finding:
    meta  = item.get("extra", {})
    sev   = meta.get("severity", "INFO").upper()
    start = item.get("start", {})
    end   = item.get("end", {})

    return Finding(
        file_path=Path(item["path"]),
        issue_type=meta.get("message", "Semgrep finding")[:120],
        category=meta.get("metadata", {}).get("aegis_category") or _infer_category(item.get("check_id", ""), meta.get("metadata")),
        severity=_SEMGREP_SEVERITY_MAP.get(sev, Severity.INFO),
        confidence=_rule_confidence(meta.get("metadata")) or _SEMGREP_CONFIDENCE.get(sev, 0.50),
        line_start=int(start.get("line", 1)),
        line_end=int(end.get("line", start.get("line", 1))),
        evidence=meta.get("lines", "").strip(),
        explanation=meta.get("message", ""),
        suggested_fix=None,
        rule_source="semgrep",
    )
