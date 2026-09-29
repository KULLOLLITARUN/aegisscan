"""
Benchmark & Calibration Evaluator (plan section 7).

Scores AegisScan against a ground-truth manifest (``examples/benchmark_labels.json``).
The labels were written by reading the code, NOT taken from tool output, so recall
is a real measurement rather than a tautology.

Metrics
  * precision (finding level), recall over labels, F1, false-positive rate
    (share of clean files that were flagged)
  * recall is reported twice: ``recall`` counts only labels that at least one *active*
    tool is expected to catch (so a missing Semgrep or a static-only run is not blamed
    for issues only an LLM could find); ``recall_all`` counts every label
  * per-source precision and per-category recall
  * confidence calibration: reliability bins, expected calibration error (ECE) and
    Brier score. "Does 0.8 confidence actually mean ~80% correct?"
  * LLM runs additionally report JSON validity rate and latency per request

Matching rule: a finding matches a label when it is in the same file and its line
range overlaps the label's range widened by ``line_tolerance``. Every file listed in
the manifest is exhaustively labelled, so a finding that matches nothing is a false
positive.
"""
from __future__ import annotations

import json
import logging
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path

from main import run
from scanner.models.finding import Finding

log = logging.getLogger(__name__)

# Reliability-diagram bin edges (lower inclusive, upper exclusive; last bin includes 1.0).
CALIBRATION_EDGES: tuple[float, ...] = (0.0, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0)
_ALWAYS_ACTIVE = {"gitleaks", "aegis-opt"}   # pure-Python paths that need no external binary


# --------------------------------------------------------------------------- manifest
@dataclass(frozen=True)
class Label:
    file: str
    line_start: int
    line_end: int
    category: str
    expected_by: frozenset[str]
    note: str = ""


@dataclass(frozen=True)
class LabelManifest:
    files: dict[str, list[Label]]     # every evaluated file, including clean ones (empty list)
    line_tolerance: int = 1

    @property
    def labels(self) -> list[Label]:
        return [lab for labs in self.files.values() for lab in labs]

    @property
    def directories(self) -> list[str]:
        """Top-level example directories that must be scanned, in manifest order."""
        seen: dict[str, None] = {}
        for rel in self.files:
            seen.setdefault(rel.split("/", 1)[0], None)
        return list(seen)


def load_manifest(path: Path) -> LabelManifest:
    data = json.loads(path.read_text(encoding="utf-8"))
    files: dict[str, list[Label]] = {}
    for entry in data["files"]:
        rel = entry["path"]
        files[rel] = [
            Label(
                file=rel,
                line_start=int(lab["lines"][0]),
                line_end=int(lab["lines"][1]),
                category=lab["category"],
                expected_by=frozenset(lab.get("expected_by", [])),
                note=lab.get("note", ""),
            )
            for lab in entry.get("labels", [])
        ]
    return LabelManifest(files=files, line_tolerance=int(data.get("line_tolerance", 1)))


# --------------------------------------------------------------------------- metrics
@dataclass
class CalibrationBin:
    low: float
    high: float
    count: int
    mean_confidence: float
    accuracy: float


@dataclass
class BenchmarkMetrics:
    vulnerable_findings: int          # findings in files that carry labels
    clean_findings: int               # findings in files with no labels
    true_positives: int               # findings matching a label
    false_positives: int              # findings matching no label
    false_negatives: int              # in-scope labels no finding matched
    precision: float
    recall: float                     # over labels an active tool is expected to catch
    f1_score: float
    false_positive_rate: float        # clean files flagged / clean files
    total_duration_seconds: float
    labels_total: int = 0
    labels_in_scope: int = 0
    labels_matched: int = 0
    recall_all: float = 0.0           # over every label, regardless of active tools
    files_evaluated: int = 0
    clean_files: int = 0
    clean_files_flagged: int = 0
    active_sources: list[str] = field(default_factory=list)
    per_source: dict[str, dict] = field(default_factory=dict)
    per_category_recall: dict[str, dict] = field(default_factory=dict)
    calibration: list[CalibrationBin] = field(default_factory=list)
    expected_calibration_error: float = 0.0
    brier_score: float = 0.0
    missed: list[str] = field(default_factory=list)
    false_positive_items: list[str] = field(default_factory=list)
    llm: dict | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _rel(finding: Finding, base: Path) -> str | None:
    p = finding.file_path
    try:
        return (p if p.is_absolute() else base / p).resolve().relative_to(base.resolve()).as_posix()
    except (ValueError, OSError):
        return None


def _overlaps(finding: Finding, label: Label, tolerance: int) -> bool:
    return finding.line_start <= label.line_end + tolerance and finding.line_end >= label.line_start - tolerance


def _ratio(num: int, den: int, empty: float = 1.0) -> float:
    return num / den if den else empty


def calibration_bins(points: list[tuple[float, bool]]) -> tuple[list[CalibrationBin], float, float]:
    """Reliability bins, ECE and Brier score for (confidence, was_correct) pairs."""
    n = len(points)
    bins: list[CalibrationBin] = []
    ece = 0.0
    for low, high in zip(CALIBRATION_EDGES, CALIBRATION_EDGES[1:], strict=False):
        last = high == CALIBRATION_EDGES[-1]
        members = [(c, y) for c, y in points if low <= c and (c <= high if last else c < high)]
        if not members:
            continue
        mean_conf = sum(c for c, _ in members) / len(members)
        acc = sum(1 for _, y in members if y) / len(members)
        bins.append(CalibrationBin(low, high, len(members), round(mean_conf, 4), round(acc, 4)))
        ece += len(members) / n * abs(acc - mean_conf)
    brier = sum((c - (1.0 if y else 0.0)) ** 2 for c, y in points) / n if n else 0.0
    return bins, round(ece, 4), round(brier, 4)


def evaluate(
    findings: Iterable[Finding],
    manifest: LabelManifest,
    base_dir: Path,
    active_sources: set[str],
) -> BenchmarkMetrics:
    """Score *findings* against *manifest*. Pure: no scanning, no I/O beyond path resolution."""
    tol = manifest.line_tolerance
    matched_labels: set[tuple[str, int]] = set()          # (file, label index)
    points: list[tuple[float, bool]] = []
    by_source: dict[str, list[bool]] = defaultdict(list)
    flagged_files: set[str] = set()
    tp = fp = vuln_findings = clean_findings = 0
    fp_items: list[str] = []

    for f in findings:
        rel = _rel(f, base_dir)
        if rel is None or rel not in manifest.files:
            continue
        labels = manifest.files[rel]
        hit = False
        for idx, lab in enumerate(labels):
            if _overlaps(f, lab, tol):
                matched_labels.add((rel, idx))
                hit = True
        if labels:
            vuln_findings += 1
        else:
            clean_findings += 1
            flagged_files.add(rel)
        points.append((f.confidence, hit))
        by_source[f.rule_source].append(hit)
        if hit:
            tp += 1
        else:
            fp += 1
            fp_items.append(f"{rel}:{f.line_start} [{f.rule_source}] {f.issue_type}")

    in_scope = matched_in_scope = 0
    cat: dict[str, list[bool]] = defaultdict(list)
    missed: list[str] = []
    for rel, labels in manifest.files.items():
        for idx, lab in enumerate(labels):
            hit = (rel, idx) in matched_labels
            if lab.expected_by & active_sources:
                in_scope += 1
                matched_in_scope += hit
                cat[lab.category].append(hit)
                if not hit:
                    missed.append(f"{rel}:{lab.line_start} {lab.category}: {lab.note}")

    total_labels = len(manifest.labels)
    precision = _ratio(tp, tp + fp)
    recall = _ratio(matched_in_scope, in_scope)
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    clean_files = sum(1 for labs in manifest.files.values() if not labs)
    bins, ece, brier = calibration_bins(points)

    return BenchmarkMetrics(
        vulnerable_findings=vuln_findings,
        clean_findings=clean_findings,
        true_positives=tp,
        false_positives=fp,
        false_negatives=in_scope - matched_in_scope,
        precision=precision,
        recall=recall,
        f1_score=f1,
        false_positive_rate=_ratio(len(flagged_files), clean_files, empty=0.0),
        total_duration_seconds=0.0,
        labels_total=total_labels,
        labels_in_scope=in_scope,
        labels_matched=len(matched_labels),
        recall_all=_ratio(len(matched_labels), total_labels),
        files_evaluated=len(manifest.files),
        clean_files=clean_files,
        clean_files_flagged=len(flagged_files),
        active_sources=sorted(active_sources),
        per_source={
            src: {"findings": len(v), "true_positives": sum(v), "precision": round(sum(v) / len(v), 4)}
            for src, v in sorted(by_source.items())
        },
        per_category_recall={
            c: {"labels": len(v), "matched": sum(v), "recall": round(sum(v) / len(v), 4)}
            for c, v in sorted(cat.items())
        },
        calibration=bins,
        expected_calibration_error=ece,
        brier_score=brier,
        missed=missed,
        false_positive_items=fp_items,
    )


# --------------------------------------------------------------------------- runner
def _detect_active_sources(results: list) -> set[str]:
    """Tools that could have contributed: installed binaries plus the always-on Python paths."""
    from scanner.static_analysis.bandit_runner import _find_bandit
    from scanner.static_analysis.semgrep_runner import _find_tool

    active = set(_ALWAYS_ACTIVE)
    if _find_bandit():
        active.add("bandit")
    if _find_tool("semgrep"):
        active.add("semgrep")
    if any(r.llm_provider for r in results):
        active.add("llm")
    return active


def _llm_summary(results: list) -> dict | None:
    requests = sum(r.llm_requests_count for r in results)
    if not requests:
        return None
    valid = sum(r.llm_json_valid_count for r in results)
    repaired = sum(r.llm_json_repaired_count for r in results)
    failed = sum(r.llm_json_failed_count for r in results)
    attempts = valid + repaired + failed
    return {
        "requests": requests,
        "chunks_analyzed": sum(r.llm_chunks_analyzed for r in results),
        "latency_per_request_seconds": round(sum(r.llm_total_latency_seconds for r in results) / requests, 3),
        "json_valid_first_try_rate": round(_ratio(valid, attempts), 4),
        "json_valid_after_repair_rate": round(_ratio(valid + repaired, attempts), 4),
        "json_failed": failed,
        "rate_limit_hits": sum(r.llm_rate_limit_hits for r in results),
    }


class BenchmarkRunner:
    """Scans the labelled example directories and scores the findings."""

    def __init__(
        self,
        root_dir: Path | None = None,
        manifest_path: Path | None = None,
        active_sources: set[str] | None = None,
    ) -> None:
        self.root_dir = root_dir or Path(__file__).resolve().parents[2]
        self.examples_dir = self.root_dir / "examples"
        self.manifest_path = manifest_path or self.examples_dir / "benchmark_labels.json"
        self._active_override = active_sources

    def run_benchmark(self, static_only: bool = True) -> BenchmarkMetrics:
        manifest = load_manifest(self.manifest_path)
        findings: list[Finding] = []
        results = []
        duration = 0.0
        for directory in manifest.directories:
            scan_dir = self.examples_dir / directory
            result, _, _ = run(scan_dir, static_only=static_only, record_history=False)
            results.append(result)
            duration += result.scan_duration_seconds
            for f in result.findings:
                p = f.file_path
                findings.append(f.model_copy(update={"file_path": p if p.is_absolute() else scan_dir / p}))

        active = self._active_override if self._active_override is not None else _detect_active_sources(results)
        metrics = evaluate(findings, manifest, self.examples_dir, active)
        metrics.total_duration_seconds = round(duration, 3)
        metrics.llm = _llm_summary(results)
        return metrics

    def print_report(self, metrics: BenchmarkMetrics) -> None:
        """Print the benchmark report to the console."""
        m = metrics
        line = "=" * 64
        print(f"\n{line}\n AEGISSCAN BENCHMARK & CALIBRATION REPORT\n{line}")
        print(f" Files evaluated            : {m.files_evaluated} ({m.clean_files} clean)")
        print(f" Active sources             : {', '.join(m.active_sources)}")
        print(f" Labels (in scope / total)  : {m.labels_in_scope} / {m.labels_total}")
        print(f" Findings in labelled files : {m.vulnerable_findings}")
        print(f" Findings in clean files    : {m.clean_findings}")
        print("-" * 64)
        print(f" True Positives (TP)        : {m.true_positives}")
        print(f" False Positives (FP)       : {m.false_positives}")
        print(f" False Negatives (in scope) : {m.false_negatives}")
        print(f" Precision                  : {m.precision:.2%}")
        print(f" Recall (in scope)          : {m.recall:.2%}")
        print(f" Recall (all labels)        : {m.recall_all:.2%}")
        print(f" F1 Score                   : {m.f1_score:.2%}")
        print(f" False Positive Rate (files): {m.false_positive_rate:.2%} "
              f"({m.clean_files_flagged}/{m.clean_files} clean files flagged)")
        print(f" Total Evaluation Time      : {m.total_duration_seconds:.2f}s")

        if m.per_source:
            print(f"{'-' * 64}\n Per-source precision")
            for src, s in m.per_source.items():
                print(f"   {src:<10} {s['true_positives']:>3}/{s['findings']:<3} correct  ({s['precision']:.0%})")
        if m.per_category_recall:
            print(f"{'-' * 64}\n Per-category recall (in scope)")
            for c, s in m.per_category_recall.items():
                print(f"   {c:<15} {s['matched']:>3}/{s['labels']:<3}  ({s['recall']:.0%})")

        print(f"{'-' * 64}\n Confidence calibration (stated confidence vs actual precision)")
        print("   bin          n   mean_conf   actual")
        for b in m.calibration:
            print(f"   {b.low:.1f}-{b.high:.1f}   {b.count:>4}   {b.mean_confidence:>8.2f}   {b.accuracy:>6.2f}")
        print(f"   ECE {m.expected_calibration_error:.3f}   Brier {m.brier_score:.3f}   (lower is better; 0 = perfectly calibrated)")

        if m.llm:
            print(f"{'-' * 64}\n LLM: {m.llm['requests']} requests, "
                  f"{m.llm['latency_per_request_seconds']}s/request, "
                  f"JSON valid first try {m.llm['json_valid_first_try_rate']:.0%}, "
                  f"after repair {m.llm['json_valid_after_repair_rate']:.0%}")
        if m.missed:
            print(f"{'-' * 64}\n Missed (in scope)")
            for item in m.missed[:25]:
                print(f"   - {item}")
        if m.false_positive_items:
            print(f"{'-' * 64}\n False positives")
            for item in m.false_positive_items[:25]:
                print(f"   - {item}")
        print(line + "\n")
