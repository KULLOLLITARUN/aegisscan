"""
run_all_tools — aggregates all static analysis tools into a single call.

Returns (findings, tools_run) where tools_run is the list of tool names
that actually executed (for ScanResult.static_tools_run).

Design rules (plan §2):
  - Each tool is optional; absence → skip + warn, never crash.
  - All returns are list[Finding], never raw dicts.
  - Tools run in parallel; results are returned in a fixed order.
"""
from __future__ import annotations

import contextvars
import logging
import threading
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from scanner.config import load_config
from scanner.models.finding import Finding
from scanner.static_analysis.bandit_runner import run_bandit
from scanner.static_analysis.gitleaks_runner import run_gitleaks
from scanner.static_analysis.optimization_runner import run_optimizer
from scanner.static_analysis.osv_runner import run_osv
from scanner.static_analysis import status
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

    A tool that did not run or ran incompletely (not installed, timed out, unreadable report) is
    recorded through ``status.problem`` and left out of ``tools_run``, so it is not mistaken for a
    clean result. Open ``status.collect()`` around this call to read the reasons.

    Returns:
        findings    : Combined list[Finding] from all tools that ran.
        tools_run   : Names of tools that ran to completion, with or without findings
                      (for ScanResult.static_tools_run).
    """
    with status.collect() as issues:
        return _run_all_tools(target, progress, only_files, privacy, on_findings, issues)


def _run_all_tools(
    target: Path,
    progress: Callable[[str], None] | None,
    only_files: Iterable[Path] | None,
    privacy: str,
    on_findings: Callable[[str, list[Finding]], None] | None,
    issues: dict[str, str],
) -> tuple[list[Finding], list[str]]:
    all_findings: list[Finding] = []
    tools_run: list[str] = []

    def _step(name: str) -> None:
        if progress:
            progress(name)

    config = load_config(target)
    root = target.resolve()

    def _keep(found: list[Finding] | None) -> list[Finding]:
        """Drop findings in files matched by .aegisscan.toml exclude_files."""
        found = list(found or [])
        if not config.exclude_files:
            return found
        out = []
        for f in found:
            try:
                rel = f.file_path.resolve().relative_to(root).as_posix()
            except (ValueError, OSError):
                rel = f.file_path.name
            if not config.is_file_excluded(rel):
                out.append(f)
        return out

    def _done(name: str, found: list[Finding]) -> None:
        if on_findings and found:
            try:
                on_findings(name, list(found))
            except Exception:
                log.debug("on_findings callback failed", exc_info=True)

    # --- Bandit (Python SAST, always available via pip) ---
    # .aegisscan.toml's exclude_dirs applies to every tool, in full and scoped scans alike.
    files: list[Path] | None = None
    if only_files is not None:
        target = target.resolve()
        files = within(target, (Path(f).resolve() for f in only_files), _ALWAYS_SKIP | set(config.exclude_dirs))
        if not files:
            log.info("No changed files to scan; skipping static analysis")
            return [], []

    # The tools are independent, so they run side by side. Each one runs in a copy of this thread's
    # context: the status collector is a ContextVar, and a worker thread would otherwise report its
    # problems into nothing. Results are put back in a fixed order, so the output does not depend on
    # which tool finishes first. Callbacks are serialised, since the UI and progress code assume one
    # caller at a time.
    callback_lock = threading.Lock()

    def _announce(name: str, found: list[Finding]) -> None:
        with callback_lock:
            _done(name, found)

    # .aegisscan.toml's exclude_dirs applies to every tool, in full and scoped scans alike.
    # (label, tool name in static_tools_run, runner). A None tool name means "always counts as run".
    jobs: list[tuple[str, str | None, Callable[[], list[Finding]]]] = [
        ("Bandit", "bandit", lambda: run_bandit(target, config.exclude_dirs, files)),
        ("Semgrep", "semgrep", lambda: run_semgrep(target, files, config.exclude_dirs)),
        ("Gitleaks", "gitleaks", lambda: run_gitleaks(target, files, config.exclude_dirs)),
    ]
    # OSV-Scanner sends package names and versions to api.osv.dev, so --privacy strict switches it off.
    if privacy == "strict":
        log.info("OSV-Scanner skipped: --privacy strict forbids sending package names to api.osv.dev")
    else:
        jobs.append(("OSV-Scanner", "osv-scanner", lambda: run_osv(target, files, config.exclude_dirs)))
    # Pure-Python AST checks, always available.
    jobs.append(("Optimizer", None, lambda: run_optimizer(target, set(config.exclude_dirs), files)))

    def _work(label: str, fn: Callable[[], list[Finding]]) -> list[Finding]:
        found = _keep(fn())
        _announce(label, found)
        return found

    with ThreadPoolExecutor(max_workers=len(jobs), thread_name_prefix="aegis-tool") as pool:
        futures = []
        for label, _tool, fn in jobs:
            _step(label)
            futures.append(pool.submit(contextvars.copy_context().run, _work, label, fn))
        results = [f.result() for f in futures]  # re-raises the first failure, after all tools stopped

    for (_label, tool, _fn), found in zip(jobs, results):
        all_findings.extend(found)
        if tool is None:
            tools_run.append("aegis-optimizer")
        elif tool not in issues:
            tools_run.append(tool)

    for tool, reason in issues.items():
        log.warning("Static analysis: %s %s", tool, reason)
    log.info(
        "Static analysis complete: %d findings from %d tool(s): %s",
        len(all_findings),
        len(tools_run),
        ", ".join(tools_run) or "none",
    )
    return all_findings, tools_run
