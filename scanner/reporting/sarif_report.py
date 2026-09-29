"""
SARIF v2.1.0 Report Generator for AegisScan.

Produces GitHub Security tab / PR annotation compatible SARIF JSON output.
Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scanner.models.finding import Finding, Severity
from scanner.models.scan import ScanResult

_SARIF_LEVEL: dict[str, str] = {
    Severity.CRITICAL.value: "error",
    Severity.HIGH.value:     "error",
    Severity.MEDIUM.value:   "warning",
    Severity.LOW.value:      "note",
    Severity.INFO.value:     "none",
}

_RULE_IDS_SEEN: dict[str, bool] = {}


def _make_rule_id(finding: Finding) -> str:
    """Stable rule ID from source + issue type, safe for SARIF format."""
    raw = f"{finding.rule_source}/{finding.issue_type}"
    return re.sub(r"[^a-zA-Z0-9/_.-]", "-", raw)[:64]


def _extract_rules(findings: list[Finding]) -> list[dict]:
    """Deduplicate findings into SARIF rules array."""
    seen: dict[str, dict] = {}
    for f in findings:
        rule_id = _make_rule_id(f)
        if rule_id not in seen:
            seen[rule_id] = {
                "id": rule_id,
                "name": f.issue_type,
                "shortDescription": {"text": f.issue_type},
                "fullDescription": {"text": f.explanation or f.issue_type},
                "defaultConfiguration": {
                    "level": _SARIF_LEVEL.get(f.severity.value, "warning"),
                },
                "help": {
                    "text": f.suggested_fix or f"Review and remediate: {f.issue_type}",
                },
                "properties": {
                    "security-severity": _severity_to_cvss(f.severity),
                    "category": f.category,
                },
            }
    return list(seen.values())


def _severity_to_cvss(sev: Severity) -> str:
    """Map AegisScan severity to a CVSS-like numeric string for GitHub Security tab."""
    return {
        Severity.CRITICAL: "9.8",
        Severity.HIGH:     "7.5",
        Severity.MEDIUM:   "5.0",
        Severity.LOW:      "3.1",
        Severity.INFO:     "0.0",
    }.get(sev, "5.0")


def _result_from_finding(finding: Finding, target_path: Path) -> dict:
    """Convert a single Finding to a SARIF result object."""
    try:
        relative_uri = str(finding.file_path.relative_to(target_path)).replace("\\", "/")
    except ValueError:
        relative_uri = str(finding.file_path).replace("\\", "/")

    result: dict[str, Any] = {
        "ruleId": _make_rule_id(finding),
        "level": _SARIF_LEVEL.get(finding.severity.value, "warning"),
        "message": {
            "text": finding.explanation or finding.issue_type,
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": relative_uri,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": finding.line_start,
                        "endLine": finding.line_end,
                        "snippet": {"text": finding.evidence[:500]} if finding.evidence else {},
                    },
                },
            }
        ],
        "properties": {
            "confidence": round(finding.confidence, 2),
            "category": finding.category,
            "source": finding.rule_source,
        },
    }

    if finding.fix_patch:
        result["fixes"] = [
            {
                "description": {"text": "AI-generated fix patch"},
                "changes": [],  # Full patch is in properties to avoid SARIF complexity
            }
        ]
        result["properties"]["fix_patch"] = finding.fix_patch

    return result


def generate_sarif(
    scan_result: ScanResult,
    output_path: Path,
) -> None:
    """
    Write a SARIF v2.1.0 JSON file for the given ScanResult.

    Args:
        scan_result: The completed scan result containing findings.
        output_path: Destination file path (e.g. Path("report.sarif")).
    """
    target = scan_result.target_path
    findings = scan_result.findings

    rules = _extract_rules(findings)
    results = [_result_from_finding(f, target) for f in findings]

    sarif: dict = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.6.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AegisScan",
                        "version": "1.0.0",
                        "organization": "AegisScan Security",
                        "rules": rules,
                        "properties": {
                            "scan_id": str(scan_result.scan_id) if hasattr(scan_result, 'scan_id') else "",
                            "llm_provider": scan_result.llm_provider or "none",
                            "llm_model": scan_result.llm_model or "none",
                        },
                    }
                },
                "originalUriBaseIds": {
                    "%SRCROOT%": {"uri": target.as_uri()},
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": datetime.now(timezone.utc).isoformat(),
                        "properties": {
                            "files_analyzed": scan_result.files_analyzed,
                            "files_discovered": scan_result.files_discovered,
                            "duration_seconds": round(scan_result.scan_duration_seconds, 2),
                        },
                    }
                ],
            }
        ],
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(sarif, indent=2, default=str), encoding="utf-8")
