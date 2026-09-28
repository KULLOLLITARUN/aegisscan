"""Tests for V7 Benchmark & Calibration layer.

Covers:
  - BenchmarkRunner execution on examples suite
  - Metrics computation (TP, FP, Precision, Recall, F1, FPR)
"""
from __future__ import annotations

from pathlib import Path

from scanner.evaluation.benchmark import BenchmarkMetrics, BenchmarkRunner


def test_benchmark_runner_runs() -> None:
    root = Path(__file__).resolve().parents[1]
    runner = BenchmarkRunner(root_dir=root)
    metrics = runner.run_benchmark(static_only=True)

    assert isinstance(metrics, BenchmarkMetrics)
    assert metrics.vulnerable_findings > 0
    assert metrics.clean_findings == 0
    assert metrics.true_positives > 0
    assert metrics.false_positives == 0
    assert 0.0 <= metrics.precision <= 1.0
    assert 0.0 <= metrics.recall <= 1.0
    assert 0.0 <= metrics.f1_score <= 1.0
    assert metrics.false_positive_rate == 0.0
    assert metrics.total_duration_seconds >= 0.0


def test_benchmark_print_report(capsys) -> None:
    root = Path(__file__).resolve().parents[1]
    runner = BenchmarkRunner(root_dir=root)
    metrics = runner.run_benchmark(static_only=True)
    runner.print_report(metrics)

    captured = capsys.readouterr()
    assert "AEGISSCAN BENCHMARK & CALIBRATION REPORT" in captured.out
    assert "Precision" in captured.out
    assert "F1 Score" in captured.out
