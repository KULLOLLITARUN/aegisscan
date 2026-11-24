"""
OsvRunner — dependency vulnerability scanning (SCA) through the OSV-Scanner CLI.

OSV-Scanner reads lockfiles / manifests (requirements.txt, package-lock.json, go.mod, ...) and
looks every package up in the OSV database. Findings point at the lockfile line that pins the
vulnerable version, use ``category="dependencies"`` and ``rule_source="osv"``.

Privacy: package names and versions are sent to api.osv.dev. ``--privacy strict`` therefore
disables this tool (see ``run_all_tools``); the code itself is never sent.

Graceful degradation (plan §2 rule 6): no binary, a timeout, an unreadable report -> no findings.
"""
from __future__ import annotations

import json
import logging
import re
import subprocess
from pathlib import Path

from scanner.models.finding import Finding, Severity
from scanner.static_analysis.gitleaks_runner import _find_tool, _is_excluded

log = logging.getLogger(__name__)

RULE_SOURCE = "osv"
_CONFIDENCE = 0.90  # a known advisory against an exact pinned version

# Files OSV-Scanner can extract packages from (the common ones; others are still found by a
# full-tree scan, this list only decides which changed files are worth a run in scoped mode).
LOCKFILE_NAMES = frozenset({
    "requirements.txt", "poetry.lock", "pipfile.lock", "pdm.lock", "uv.lock",
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "go.mod", "cargo.lock", "pom.xml", "gradle.lockfile", "composer.lock", "gemfile.lock",
    "packages.lock.json", "pubspec.lock",
})

_MAX_PER_FILE_RUNS = 25
_TIMEOUT = 180


def is_lockfile(path: Path) -> bool:
    return path.name.lower() in LOCKFILE_NAMES


def _severity(score: str | None, label: str | None) -> Severity:
    """CVSS base score (preferred) or a textual label from the advisory -> Severity."""
    if score:
        try:
            value = float(score)
        except ValueError:
            value = -1.0
        if value >= 9.0:
            return Severity.CRITICAL
        if value >= 7.0:
            return Severity.HIGH
        if value >= 4.0:
            return Severity.MEDIUM
        if value >= 0.0:
            return Severity.LOW
    mapping = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MODERATE": Severity.MEDIUM,
               "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
    return mapping.get((label or "").upper(), Severity.MEDIUM)


def _locate(lockfile: Path, name: str) -> tuple[int, str]:
    """First line of *lockfile* that mentions the package *name*, with its text (line 1 if none)."""
    try:
        lines = lockfile.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return 1, name
    pattern = re.compile(rf"(?<![\w.-]){re.escape(name)}(?![\w.-])", re.IGNORECASE)
    for idx, line in enumerate(lines, start=1):
        if pattern.search(line):
            return idx, line.strip()
    return 1, name


def parse_report(data: object, target: Path) -> list[Finding]:
    """Turn OSV-Scanner's ``--format json`` document into Findings (one per package + advisory group)."""
    if not isinstance(data, dict):
        return []
    findings: list[Finding] = []
    for result in data.get("results") or []:
        source = (result.get("source") or {}).get("path") or ""
        lockfile = Path(source)
        if not lockfile.is_absolute():
            lockfile = target / lockfile
        for entry in result.get("packages") or []:
            pkg = entry.get("package") or {}
            name, version = pkg.get("name", "unknown"), pkg.get("version", "?")
            vulns = {v.get("id"): v for v in entry.get("vulnerabilities") or [] if v.get("id")}
            groups = entry.get("groups") or [{"ids": list(vulns), "max_severity": None}]
            line, evidence = _locate(lockfile, name)
            for group in groups:
                ids = [i for i in group.get("ids") or [] if i in vulns] or list(vulns)[:1]
                if not ids:
                    continue
                primary = vulns[ids[0]]
                aliases = sorted({a for i in ids for a in (vulns[i].get("aliases") or [])} | set(ids))
                label = (primary.get("database_specific") or {}).get("severity")
                summary = primary.get("summary") or (primary.get("details") or "").split("\n")[0]
                findings.append(Finding(
                    file_path=lockfile,
                    issue_type=f"Vulnerable dependency: {name} {version}",
                    category="dependencies",
                    severity=_severity(group.get("max_severity"), label),
                    confidence=_CONFIDENCE,
                    line_start=line,
                    line_end=line,
                    evidence=evidence,
                    explanation=f"{name} {version} is affected by {', '.join(aliases)}. {summary}".strip(),
                    suggested_fix=f"Upgrade {name} to a version that fixes {ids[0]} (see https://osv.dev/{ids[0]}).",
                    rule_source=RULE_SOURCE,
                ))
    return findings


def _run(osv_bin: str, args: list[str], target: Path) -> list[Finding] | None:
    """Run one OSV-Scanner command. None = could not run / unreadable output."""
    cmd = [osv_bin, "scan", "source", "--format", "json", *args]
    try:
        # Exit code 1 means "vulnerabilities found", 128 "nothing to scan": both carry JSON/empty.
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=_TIMEOUT)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        log.warning("OSV-Scanner subprocess failed: %s", exc)
        return None
    text = proc.stdout.strip()
    if not text:
        if proc.returncode not in (0, 128):
            log.warning("OSV-Scanner exited %s: %s", proc.returncode, proc.stderr.strip()[:300])
            return None
        return []
    try:
        return parse_report(json.loads(text), target)
    except json.JSONDecodeError as exc:
        log.warning("OSV-Scanner output is not valid JSON: %s", exc)
        return None


def run_osv(
    target: Path,
    files: list[Path] | None = None,
    exclude_dirs: frozenset[str] = frozenset(),
) -> list[Finding]:
    """
    Scan dependency manifests under *target*. With *files* (``--changed-only`` / ``--changed-since``)
    only the changed lockfiles among them are scanned; no changed lockfile means no run at all.
    """
    osv_bin = _find_tool("osv-scanner")
    if osv_bin is None:
        log.info("osv-scanner binary absent — dependency scan skipped")
        return []

    if files is None:
        found = _run(osv_bin, ["--recursive", str(target)], target)
    else:
        lockfiles = [f for f in files if is_lockfile(f) and not _is_excluded(f, target, exclude_dirs)]
        if not lockfiles:
            return []
        found = []
        if len(lockfiles) <= _MAX_PER_FILE_RUNS:
            for lf in lockfiles:
                found.extend(_run(osv_bin, ["--lockfile", str(lf)], target) or [])
        else:
            tree = _run(osv_bin, ["--recursive", str(target)], target) or []
            wanted = {f.resolve() for f in lockfiles}
            found = [f for f in tree if f.file_path.resolve() in wanted]
    result = [f for f in (found or []) if not _is_excluded(f.file_path, target, exclude_dirs)]
    log.info("OSV-Scanner: %d vulnerable dependencies in %s", len(result), target)
    return result
