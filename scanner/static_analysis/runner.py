"""
run_all_tools — aggregates all static analysis tools into a single call.

Returns (findings, tools_run) where tools_run is the list of tool names
that actually executed (for ScanResult.static_tools_run).

Design rules (plan §2):
  - Each tool is optional; absence → skip + warn, never crash.
  - All returns are list[Finding], never raw dicts.
  - Tools run sequentially in V1; parallel execution is a V5 concern.
"""
from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from pathlib import Path

from scanner.config import load_config
from scanner.models.finding import Finding
from scanner.static_analysis.bandit_runner import run_bandit
from scanner.static_analysis.gitleaks_runner import run_gitleaks
from scanner.static_analysis.optimization_runner import run_optimizer
from scanner.static_analysis.osv_runner import run_osv
from scanner.static_analysis.scope import within
from scanner.static_analysis.semgrep_runner import run_semgrep

log = logging.getLogger(__name__)

# Directories no tool should look into (the tools' own defaults, applied to explicit file lists too).
_ALWAYS_SKIP = {".venv", "venv", "node_modules", "__pycache__", "dist", ".git", "build", "site-packages"}


def run_all_tools(
    target: Path,
    progress: Callable[[str], None] | None = None,
    only_files: Iterable[Path] | None = None,
    privacy: str = "standard",
    on_findings: Callable[[str, list[Finding]], None] | None = None,
) -> tuple[list[Finding], list[str]]:
    """
    Run all configured static analysis tools against *target*.

    *only_files* (``--changed-only``) limits every tool to those files instead of the whole tree;
    an empty collection means there is nothing to scan and no tool is started.

    *on_findings*, if given, is called as ``on_findings(tool, findings)`` as soon as each tool has
    finished, before the next one starts, so a live UI can show results as they arrive. Exceptions it
    raises are swallowed.

    Returns:
        findings    : Combined list[Finding] from all tools that ran.
        tools_run   : Names of tools that actually produced output
                      (for ScanResult.static_tools_run).
    """
    all_findings: list[Finding] = []
    tools_run: list[str] = []

    def _step(name: str) -> None:
        if progress:
            progress(name)

    def _done(name: str, found: list[Finding]) -> None:
        if on_findings and found:
            try:
                on_findings(name, list(found))
            except Exception:
                log.debug("on_findings callback failed", exc_info=True)

    # --- Bandit (Python SAST, always available via pip) ---
    config = load_config(target)
    # .aegisscan.toml's exclude_dirs applies to every tool, in full and scoped scans alike.
    files: list[Path] | None = None
    if only_files is not None:
        target = target.resolve()
        files = within(target, (Path(f).resolve() for f in only_files), _ALWAYS_SKIP | set(config.exclude_dirs))
        if not files:
            log.info("No changed files to scan; skipping static analysis")
            return [], []

    _step("Bandit")
    bandit_findings = run_bandit(target, config.exclude_dirs, files)
    _done("Bandit", bandit_findings)
    if bandit_findings:
        all_findings.extend(bandit_findings)
        tools_run.append("bandit")
    else:
        log.debug("Bandit: no findings or not available")

    # --- Semgrep (optional CLI) ---
    _step("Semgrep")
    semgrep_findings = run_semgrep(target, files, config.exclude_dirs)
    _done("Semgrep", semgrep_findings)
    if semgrep_findings:
        all_findings.extend(semgrep_findings)
        tools_run.append("semgrep")
    else:
        log.debug("Semgrep: no findings or not available")

    # --- Gitleaks (optional CLI) ---
    _step("Gitleaks")
    gitleaks_findings = run_gitleaks(target, files, config.exclude_dirs)
    _done("Gitleaks", gitleaks_findings)
    if gitleaks_findings:
        all_findings.extend(gitleaks_findings)
        tools_run.append("gitleaks")
    else:
        log.debug("Gitleaks: no findings or not available")

    # --- OSV-Scanner (optional CLI; dependency CVEs). It sends package names and versions to
    # api.osv.dev, so --privacy strict switches it off. ---
    if privacy == "strict":
        log.info("OSV-Scanner skipped: --privacy strict forbids sending package names to api.osv.dev")
    else:
        _step("OSV-Scanner")
        osv_findings = run_osv(target, files, config.exclude_dirs)
        _done("OSV-Scanner", osv_findings)
        if osv_findings:
            all_findings.extend(osv_findings)
            tools_run.append("osv-scanner")

    # --- Optimizer (pure-Python AST checks, always available) ---
    _step("Optimizer")
    opt_findings = run_optimizer(target, set(config.exclude_dirs), files)
    _done("Optimizer", opt_findings)
    if opt_findings:
        all_findings.extend(opt_findings)
        tools_run.append("aegis-optimizer")

    log.info(
        "Static analysis complete: %d findings from %d tool(s): %s",
        len(all_findings),
        len(tools_run),
        ", ".join(tools_run) or "none",
    )
    return all_findings, tools_run
