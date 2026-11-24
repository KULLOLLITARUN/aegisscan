"""
AegisScan V4 — CLI entrypoint.

Usage:
    aegisscan <path>                          # full pipeline (static + LLM + intelligence + scoring)
    aegisscan <path> --html report.html       # generate HTML report
    aegisscan <path> --deep                   # LLM on all eligible chunks
    aegisscan <path> --static-only            # skip LLM pass
    aegisscan <path> --baseline baseline.json # suppress known findings
    aegisscan <path> --save-baseline out.json # save this run's fingerprints
    aegisscan <path> --verbose                # show per-file details
    aegisscan <path> --json                   # print ScanResult as JSON
    aegisscan <path> --log-level INFO         # show pipeline progress

V4 pipeline:
  crawl → classify → chunk → static analysis → LLM reasoning
       → deduplicate → correlate → baseline suppression → scoring → HTML report / CLI report
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from collections import Counter
from collections.abc import Callable
from pathlib import Path

# Load .env before any env-var reads (GROQ_API_KEY, etc.)
from dotenv import load_dotenv

load_dotenv()

from scanner.chunking.dispatcher import chunk_file
from scanner.ci.ci_gate import evaluate_ci_gate
from scanner.ingestion.classifier import FileClassifier
from scanner.ingestion.crawler import WorkspaceCrawler
from scanner.ingestion.git_diff import get_changed_files
from scanner.intelligence.baseline import BaselineManager, save_baseline
from scanner.intelligence.context import (
    cap_ci_hygiene,
    drop_test_performance,
    soften_bandit_false_alarms,
    weight_by_context,
)
from scanner.intelligence.correlator import CorrelationGroup, correlate
from scanner.intelligence.deduplicator import deduplicate
from scanner.llm.auditor import SUPPRESSION_THRESHOLD, LLMAuditor
from scanner.models.file_info import FileInfo
from scanner.models.finding import Finding, Severity
from scanner.models.scan import ScanResult
from scanner.providers.manager import ProviderManager
from scanner.reporting.html_report import generate_html
from scanner.scoring.calculator import optimization_score, score_label, security_score
from scanner.static_analysis.runner import run_all_tools


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aegisscan",
        description="AegisScan -- AI-driven workspace security & optimization scanner",
    )
    p.add_argument("path", type=Path, nargs="?", default=Path("."), help="Target directory to scan")
    p.add_argument("--verbose", "-v", action="store_true", help="Show per-file details")
    p.add_argument("--benchmark", action="store_true", help="Run precision/recall calibration benchmark suite")
    p.add_argument("--benchmark-json", metavar="FILE", type=Path, help="With --benchmark: also write metrics as JSON")
    p.add_argument("--deep", action="store_true", help="Run LLM on ALL eligible chunks")
    p.add_argument("--static-only", action="store_true", help="Skip LLM pass")
    p.add_argument(
        "--baseline",
        metavar="FILE",
        type=Path,
        help="Suppress findings present in this baseline JSON",
    )
    p.add_argument(
        "--save-baseline",
        metavar="FILE",
        type=Path,
        help="Save this run's finding fingerprints as a new baseline",
    )
    p.add_argument(
        "--html",
        metavar="FILE",
        type=Path,
        help="Generate a self-contained HTML report at this path",
    )
    p.add_argument("--json", action="store_true", help="Output ScanResult as JSON")
    p.add_argument(
        "--changed-only",
        action="store_true",
        help="Scan only git modified/staged/untracked files",
    )
    p.add_argument(
        "--changed-since",
        metavar="REF",
        help="Like --changed-only, but also include files changed between REF (a branch, tag or commit) "
             "and HEAD; for CI runs on a clean checkout, e.g. --changed-since origin/main",
    )
    p.add_argument(
        "--fail-on",
        metavar="SPEC",
        type=str,
        help="Fail build (exit code 2) if findings breach threshold (e.g. security:high, critical)",
    )
    p.add_argument(
        "--privacy",
        default="standard",
        choices=["standard", "redact", "strict"],
        help="Secret redaction privacy level before sending code to LLM",
    )
    p.add_argument(
        "--generate-patches",
        action="store_true",
        help="Generate unified git diff fix patches for findings via LLM",
    )
    p.add_argument(
        "--sarif",
        metavar="FILE",
        type=Path,
        help="Generate a SARIF v2.1.0 report for GitHub Security tab / PR annotations",
    )
    p.add_argument(
        "--history",
        action="store_true",
        help="Display historical scan runs and score trends from SQLite DB",
    )
    p.add_argument(
        "--server",
        action="store_true",
        help="Launch the interactive AegisScan Web Server dashboard",
    )
    p.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port number for the web server (default: 8000)",
    )
    p.add_argument(
        "--log-level",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    return p


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

_SEV_LABEL = {
    Severity.CRITICAL: "CRIT",
    Severity.HIGH:     "HIGH",
    Severity.MEDIUM:   "MED ",
    Severity.LOW:      "LOW ",
    Severity.INFO:     "INFO",
}


def _print_report(
    result: ScanResult,
    all_files: list[FileInfo],
    groups: list[CorrelationGroup],
    verbose: bool,
    static_only: bool,
    baseline_active: bool,
) -> None:
    sep = "-" * 72

    llm_status = (
        "skipped (--static-only)" if static_only
        else f"groq / {result.llm_model or 'n/a'}" if result.llm_provider
        else "no GROQ_API_KEY -- skipped"
    )

    print(f"\n{'AegisScan V4':^72}")
    print(sep)
    print(f"  Target   : {result.target_path}")
    print(f"  Scan ID  : {result.scan_id}")
    print(f"  Time     : {result.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  Duration : {result.scan_duration_seconds:.2f}s")
    print(f"  Static   : {', '.join(result.static_tools_run) or 'none'}")
    print(f"  LLM      : {llm_status}")
    if result.llm_chunks_analyzed:
        print(f"  LLM chunks: {result.llm_chunks_analyzed} analyzed")
    print(sep)

    # ---- Telemetry & API Performance (V5) ----
    if result.llm_requests_count:
        print("\n  LLM TELEMETRY & API PERFORMANCE (V5)")
        print(f"    {'API requests made':<40} {result.llm_requests_count:>6}")
        print(f"    {'Total input tokens':<40} {result.llm_total_input_tokens:>6}")
        print(f"    {'Total output tokens':<40} {result.llm_total_output_tokens:>6}")
        print(f"    {'API latency total':<40} {result.llm_total_latency_seconds:>5.2f}s")
        if result.llm_rate_limit_hits:
            print(f"    {'Rate limit hits (429)':<40} {result.llm_rate_limit_hits:>6}")
        if result.llm_fallback_triggered:
            print(f"    {'Fallback provider active':<40} {'YES':>6}")

    # ---- Scores (V4) ----
    sec_sc = result.security_score if result.security_score is not None else 100.0
    opt_sc = result.optimization_score if result.optimization_score is not None else 100.0
    print("\n  SCORES (V4 — Heuristic)")
    print(f"    Security Score     : {sec_sc:>5.1f} / 100  ({score_label(sec_sc)})")
    print(f"    Optimization Score : {opt_sc:>5.1f} / 100  ({score_label(opt_sc)})")
    print("    * Scores are heuristic estimates, not calibrated against CVE datasets.")

    # ---- File inventory ----
    print("\n  FILE INVENTORY")
    print(f"  {'Discovered':<40} {result.files_discovered:>6}")
    print(f"  {'Ignored (.gitignore / blocklist)':<40} {result.files_ignored:>6}")
    print(f"  {'Analyzable':<40} {result.files_analyzed:>6}")
    print(f"  {'Binary':<40} {result.files_binary:>6}")
    print(f"  {'Generated':<40} {result.files_generated:>6}")
    print(f"  {'Oversized (> 1 MB)':<40} {result.files_oversized:>6}")
    print(f"  {'Chunks created (Tree-sitter)':<40} {result.chunks_created:>6}")

    if result.language_breakdown:
        print("\n  LANGUAGE BREAKDOWN")
        for lang, count in sorted(result.language_breakdown.items(), key=lambda x: -x[1]):
            print(f"    {lang:<36} {count:>6}")

    # ---- Intelligence summary ----
    print("\n  INTELLIGENCE LAYER (V3/V4)")
    if result.findings_deduplicated:
        print(f"    Duplicates removed      {result.findings_deduplicated:>6}")
    if result.findings_corroborated:
        print(f"    Corroborated findings   {result.findings_corroborated:>6}  (multi-source agreement)")
    if result.findings_suppressed and baseline_active:
        print(f"    Baseline suppressed     {result.findings_suppressed:>6}  (known from previous scan)")
    if not any([result.findings_deduplicated, result.findings_corroborated, result.findings_suppressed]):
        print("    No deduplication or suppression applied.")

    # ---- Findings ----
    static_findings = [f for f in result.findings if f.rule_source != "llm"]
    llm_findings    = [f for f in result.findings if f.rule_source == "llm"]

    print(f"\n  FINDINGS  ({len(result.findings)} total | "
          f"{len(static_findings)} static | {len(llm_findings)} LLM)")

    if not result.findings:
        print("  No findings.")
    else:
        sev_counts: Counter[Severity] = Counter(f.severity for f in result.findings)
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            if sev_counts[sev]:
                print(f"    {_SEV_LABEL[sev]}  {sev_counts[sev]}")

        print()
        print(f"  {'SEV':<5} {'CONF':>5}  {'SOURCE':<8}  {'FILE:LINE':<35}  ISSUE")
        print("  " + "-" * 70)

        def _sort_key(f: Finding):
            return (list(Severity).index(f.severity), f.file_path.name, f.line_start)

        for f in sorted(result.findings, key=_sort_key):
            loc   = f"{f.file_path.name}:{f.line_start}"
            conf  = f"{f.confidence * 100:.0f}%"
            issue = f.issue_type[:40]
            print(f"  {_SEV_LABEL[f.severity]:<5} {conf:>5}  {f.rule_source:<8}  {loc:<35}  {issue}")

        if llm_findings:
            print(f"\n  Note: LLM findings below {SUPPRESSION_THRESHOLD:.0%} confidence were suppressed.")

    if verbose and all_files:
        print("\n  PER-FILE DETAILS")
        for fi in all_files:
            flags = []
            if fi.is_binary:    flags.append("binary")
            if fi.is_generated: flags.append("generated")
            if fi.is_oversized: flags.append("oversized")
            flag_str  = f" [{', '.join(flags)}]" if flags else ""
            lang_str  = f"  [{fi.language}]" if fi.language else ""
            lines_str = f"  {fi.line_count} lines" if fi.line_count is not None else ""
            print(f"  {fi.path}{lang_str}{lines_str}{flag_str}")

    print(f"\n{sep}")
    print("  V4 complete. Run with --json or --html <file> for report outputs.")
    print(sep + "\n")


# ---------------------------------------------------------------------------
# Core pipeline
# ---------------------------------------------------------------------------

def run(
    path: Path,
    deep: bool = False,
    static_only: bool = False,
    baseline_path: Path | None = None,
    changed_only: bool = False,
    changed_since: str | None = None,
    privacy: str = "standard",
    generate_patches: bool = False,
    progress: Callable[[str, int, str], None] | None = None,
    record_history: bool = True,
) -> tuple[ScanResult, list[FileInfo], list[CorrelationGroup]]:
    """
    V6/V8 pipeline:
      crawl → [git diff filter] → classify → chunk → static → LLM (privacy, patches)
            → deduplicate → correlate → baseline suppress → scoring → ScanResult

    *progress*, if given, is called as ``progress(phase, pct, detail)`` at each
    pipeline phase (pct is 0-100). Exceptions it raises are swallowed.
    """
    def _progress(phase: str, pct: int, detail: str = "") -> None:
        if progress is None:
            return
        try:
            progress(phase, pct, detail)
        except Exception:
            log.debug("progress callback failed", exc_info=True)

    if not path.exists():
        print(f"ERROR: path does not exist: {path}", file=sys.stderr)
        sys.exit(1)
    if not path.is_dir():
        print(f"ERROR: path is not a directory: {path}", file=sys.stderr)
        sys.exit(1)

    t0 = time.monotonic()

    # ---- 1. Crawl ----
    _progress("Crawling workspace", 5)
    crawl = WorkspaceCrawler(path).crawl()
    discovered_files = crawl.discovered
    _progress("Discovered files", 10, f"{len(discovered_files)} files")

    # Incremental scan filter (V6). None = not a git repo / git unavailable -> scan everything.
    changed: set[Path] | None = get_changed_files(path, changed_since) if (changed_only or changed_since) else None
    if changed is not None:
        discovered_files = [f for f in discovered_files if f.resolve() in changed]

    # ---- 2. Classify ----
    classifier = FileClassifier()
    all_files: list[FileInfo] = []
    lang_counter: Counter[str] = Counter()
    binary_count = generated_count = oversized_count = analyzable_count = 0

    for file_path in discovered_files:
        fi = classifier.classify(file_path)
        all_files.append(fi)
        if fi.is_binary:        binary_count += 1
        elif fi.is_oversized:   oversized_count += 1
        elif fi.is_generated:   generated_count += 1
        else:                   analyzable_count += 1
        if fi.language:
            lang_counter[fi.language] += 1

    # ---- 3. Chunk ----
    _progress("Chunking files", 15)
    all_chunks = []
    for fi in all_files:
        if not fi.is_binary and not fi.is_oversized and not fi.is_generated:
            all_chunks.extend(chunk_file(fi))

    # ---- 4. Static analysis ----
    _progress("Static analysis", 25)
    static_findings, tools_run = run_all_tools(
        path.resolve(),
        progress=lambda tool: _progress("Static analysis", 30, tool),
        # --changed-only: the tools read just the changed files (discovered_files was already cut
        # down to them above) instead of the whole tree. None = scan everything.
        only_files=discovered_files if changed is not None else None,
        privacy=privacy,
    )
    if changed is not None:
        # Safety net: a tool must never blame a change for issues in files that did not change,
        # otherwise a CI gate would fail on every pre-existing issue in the repo.
        static_findings = [f for f in static_findings if f.file_path.resolve() in changed]

    # ---- 5. LLM reasoning ----
    llm_findings: list[Finding] = []
    llm_provider: str | None = None
    llm_model: str | None = None
    llm_chunks_analyzed: int = 0
    pm: ProviderManager | None = None
    json_counts = (0, 0, 0)

    if not static_only or generate_patches:
        pm = ProviderManager()
        if not static_only and pm.is_available:
            from scanner.llm.trigger import TriggerEngine  # noqa: PLC0415
            trigger = TriggerEngine()
            triggered = [
                c for c in all_chunks
                if trigger.should_analyze(c, static_findings, deep=deep)
            ]
            llm_chunks_analyzed = len(triggered)
            auditor = LLMAuditor(pm, privacy_mode=privacy, generate_patches=generate_patches)
            _progress("LLM analysis", 50, f"0/{llm_chunks_analyzed} chunks")
            llm_findings = auditor.analyze_chunks(
                all_chunks, static_findings, deep=deep,
                progress=lambda d, t: _progress("LLM analysis", 50 + int(35 * d / max(t, 1)), f"{d}/{t} chunks"),
            )
            json_counts = (auditor.json_valid_count, auditor.json_repaired_count, auditor.json_failed_count)
            llm_provider = pm.active_provider
            llm_model = pm.default_model

        if generate_patches:
            from scanner.llm.patcher import generate_patch_for_finding
            for f in static_findings:
                if not f.fix_patch:
                    f.fix_patch = generate_patch_for_finding(f, pm)

    all_raw_findings = static_findings + llm_findings

    # ---- 6. Deduplicate ----
    _progress("Deduplicating and scoring", 90)
    deduped, n_deduped = deduplicate(all_raw_findings)
    deduped, _ = weight_by_context(deduped, path)
    deduped, _ = cap_ci_hygiene(deduped, path)
    deduped, _ = drop_test_performance(deduped, path)
    deduped, _ = soften_bandit_false_alarms(deduped)

    # ---- 7. Correlate ----
    correlated, groups = correlate(deduped)
    n_corroborated = sum(1 for g in groups if g.is_corroborated)

    # ---- 8. Baseline suppression ----
    baseline = BaselineManager(baseline_path)
    final_findings, n_suppressed = baseline.suppress(correlated, path)

    # ---- 9. Scoring (V4) ----
    sec_sc = security_score(final_findings, analyzable_count)
    opt_sc = optimization_score(final_findings, analyzable_count)

    duration = time.monotonic() - t0

    result = ScanResult(
        target_path=path.resolve(),
        files_discovered=len(crawl.discovered),
        files_ignored=crawl.ignored_count,
        files_analyzed=analyzable_count,
        files_binary=binary_count,
        files_generated=generated_count,
        files_oversized=oversized_count,
        chunks_created=len(all_chunks),
        language_breakdown=dict(lang_counter),
        scan_duration_seconds=round(duration, 3),
        static_tools_run=tools_run,
        llm_provider=llm_provider,
        llm_model=llm_model,
        llm_chunks_analyzed=llm_chunks_analyzed,
        findings_deduplicated=n_deduped,
        findings_suppressed=n_suppressed,
        findings_corroborated=n_corroborated,
        llm_requests_count=pm.requests_count if pm else 0,
        llm_total_input_tokens=pm.total_input_tokens if pm else 0,
        llm_total_output_tokens=pm.total_output_tokens if pm else 0,
        llm_total_latency_seconds=round(pm.total_latency_seconds, 3) if pm else 0.0,
        llm_rate_limit_hits=pm.rate_limit_hits if pm else 0,
        llm_fallback_triggered=pm.fallback_triggered if pm else False,
        llm_json_valid_count=json_counts[0],
        llm_json_repaired_count=json_counts[1],
        llm_json_failed_count=json_counts[2],
        security_score=sec_sc,
        optimization_score=opt_sc,
        findings=final_findings,
    )

    if record_history:
        try:
            from scanner.storage.history import ScanHistoryDB
            ScanHistoryDB().record_scan(result)
        except Exception as exc:
            log.warning("Failed to record scan to history DB: %s", exc)

    return result, all_files, groups


def _print_history(target_path: Path) -> None:
    from scanner.storage.history import ScanHistoryDB, default_db_path
    db_file = default_db_path()
    db = ScanHistoryDB(db_path=db_file)
    history = db.get_history(limit=15)

    if not history:
        print(f"\nNo scan history found at {db_file}")
        return

    print("\n" + "=" * 78)
    print(" AEGISSCAN HISTORICAL SCAN LOG (V9 SQLite)")
    print("=" * 78)
    print(f" {'Timestamp':<20} | {'Scan ID':<10} | {'Security':<9} | {'Optim':<9} | {'Findings':<8} | {'Duration'}")
    print("-" * 78)
    for h in history:
        ts = str(h["timestamp"])[:19]
        sid = str(h["scan_id"])[:8]
        sec = f"{h['security_score']:.1f}" if h["security_score"] is not None else "N/A"
        opt = f"{h['optimization_score']:.1f}" if h["optimization_score"] is not None else "N/A"
        tot = h["total_findings"]
        dur = f"{h['duration_seconds']:.2f}s"
        print(f" {ts:<20} | {sid:<10} | {sec:<9} | {opt:<9} | {tot:<8} | {dur}")
    print("=" * 78)

    delta = db.get_latest_score_delta()
    if delta:
        sec_d = delta["security_delta"]
        sec_sign = f"+{sec_d}" if sec_d > 0 else str(sec_d)
        print(f" Latest Security Score Delta: {sec_sign} pts\n")


log = logging.getLogger(__name__)


def _make_console_safe() -> None:
    """Findings carry arbitrary text; never let a legacy console codepage (cp1252) crash a report."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)   # absent on non-text streams (e.g. pytest capture)
        if reconfigure is None:
            continue
        try:
            reconfigure(errors="replace")
        except ValueError:
            pass


def main() -> None:
    _make_console_safe()
    parser = _build_parser()
    args = parser.parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level))

    if args.server:
        from scanner.server.app import run_server
        run_server(port=args.port)
        return

    if args.history:
        _print_history(args.path)
        return

    if args.benchmark:
        from scanner.evaluation.benchmark import BenchmarkRunner
        runner = BenchmarkRunner()
        metrics = runner.run_benchmark(static_only=args.static_only)
        runner.print_report(metrics)
        if args.benchmark_json:
            args.benchmark_json.write_text(json.dumps(metrics.to_dict(), indent=2), encoding="utf-8")
            print(f"Benchmark metrics written to {args.benchmark_json}")
        return

    result, all_files, groups = run(
        args.path,
        deep=args.deep,
        static_only=args.static_only,
        baseline_path=args.baseline,
        changed_only=args.changed_only,
        changed_since=args.changed_since,
        privacy=args.privacy,
        generate_patches=args.generate_patches,
    )

    if args.save_baseline:
        save_baseline(result.findings, args.path, args.save_baseline)

    if args.html:
        generate_html(result, args.html)
        print(f"  HTML report generated: {args.html}")

    if args.sarif:
        from scanner.reporting.sarif_report import generate_sarif
        generate_sarif(result, args.sarif)
        print(f"  SARIF report generated: {args.sarif}")

    if args.json:
        print(result.model_dump_json(indent=2))
    else:
        _print_report(
            result,
            all_files=all_files,
            groups=groups,
            verbose=args.verbose,
            static_only=args.static_only,
            baseline_active=args.baseline is not None,
        )

    # CI gate enforcement (V6)
    if args.fail_on:
        failed, gate_msg = evaluate_ci_gate(result, args.fail_on)
        print(f"\n[CI GATE] {gate_msg}")
        if failed:
            sys.exit(2)


if __name__ == "__main__":
    main()
