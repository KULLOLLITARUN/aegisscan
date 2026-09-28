"""
CI Gate Evaluator — V6

Evaluates scan results against a user-specified failure spec (e.g. `--fail-on security:high`).
Returns a boolean indicating whether the build gate failed, along with a human-readable message.
"""
from __future__ import annotations

import logging

from scanner.models.finding import Finding, Severity
from scanner.models.scan import ScanResult

log = logging.getLogger(__name__)

_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def evaluate_ci_gate(result: ScanResult, fail_on_spec: str) -> tuple[bool, str]:
    """
    Evaluate whether ScanResult breaches the threshold specified by fail_on_spec.

    Args:
        result: The ScanResult object.
        fail_on_spec: Specification string, e.g., 'security:high', 'optimization:medium', 'high', 'critical'.

    Returns:
        (failed: bool, message: str)
    """
    if not fail_on_spec:
        return False, "CI gate disabled."

    spec = fail_on_spec.strip().lower()

    target_category: str | None = None
    target_sev_str: str = spec

    if ":" in spec:
        cat_part, target_sev_str = spec.split(":", 1)
        if cat_part in ("security", "sec"):
            target_category = "security"
        elif cat_part in ("optimization", "opt", "performance", "perf"):
            target_category = "performance"
        else:
            target_category = cat_part

    # Parse target severity
    sev_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "med": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }

    if target_sev_str not in sev_map:
        return False, f"Unknown CI gate severity: '{target_sev_str}'. Valid: critical, high, medium, low, info."

    threshold_sev = sev_map[target_sev_str]
    threshold_idx = _SEVERITY_ORDER.index(threshold_sev)

    # Filter findings
    breaching_findings: list[Finding] = []

    for finding in result.findings:
        is_perf = (finding.category == "performance")
        if target_category == "security" and is_perf:
            continue
        if target_category == "performance" and not is_perf:
            continue

        finding_idx = _SEVERITY_ORDER.index(finding.severity)
        if finding_idx <= threshold_idx:
            breaching_findings.append(finding)

    if breaching_findings:
        msg = (
            f"CI GATE FAILED: Found {len(breaching_findings)} finding(s) matching or exceeding "
            f"threshold '{fail_on_spec}'."
        )
        return True, msg

    return False, f"CI GATE PASSED: No findings breached threshold '{fail_on_spec}'."
