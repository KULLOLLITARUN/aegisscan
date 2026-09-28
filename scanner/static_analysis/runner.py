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
from pathlib import Path

from scanner.models.finding import Finding
from scanner.static_analysis.bandit_runner import run_bandit
from scanner.static_analysis.gitleaks_runner import run_gitleaks
from scanner.static_analysis.optimization_runner import run_optimizer
from scanner.static_analysis.semgrep_runner import run_semgrep

log = logging.getLogger(__name__)


def run_all_tools(target: Path) -> tuple[list[Finding], list[str]]:
    """
    Run all configured static analysis tools against *target*.

    Returns:
        findings    : Combined list[Finding] from all tools that ran.
        tools_run   : Names of tools that actually produced output
                      (for ScanResult.static_tools_run).
    """
    all_findings: list[Finding] = []
    tools_run: list[str] = []

    # --- Bandit (Python SAST, always available via pip) ---
    bandit_findings = run_bandit(target)
    if bandit_findings:
        all_findings.extend(bandit_findings)
        tools_run.append("bandit")
    else:
        log.debug("Bandit: no findings or not available")

    # --- Semgrep (optional CLI) ---
    semgrep_findings = run_semgrep(target)
    if semgrep_findings:
        all_findings.extend(semgrep_findings)
        tools_run.append("semgrep")
    else:
        log.debug("Semgrep: no findings or not available")

    # --- Gitleaks (optional CLI) ---
    gitleaks_findings = run_gitleaks(target)
    if gitleaks_findings:
        all_findings.extend(gitleaks_findings)
        tools_run.append("gitleaks")
    else:
        log.debug("Gitleaks: no findings or not available")

    # --- Optimizer (pure-Python AST checks, always available) ---
    opt_findings = run_optimizer(target)
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
