"""
Baseline suppression — save and load a scan baseline to suppress known findings.

Workflow:
  1. First scan: aegisscan <path> --save-baseline baseline.json
     → Saves fingerprints of all current findings to baseline.json.

  2. Next scan:  aegisscan <path> --baseline baseline.json
     → Loads baseline fingerprints and filters them out of results.
     → Only NEW findings are shown.

Baseline format (JSON):
  {
    "aegisscan_version": "V3",
    "fingerprint_version": 2,
    "created_at": "2026-08-09T...",
    "target_path": "/absolute/path",
    "fingerprint_count": 17,
    "fingerprints": ["abc123", ...]
  }

This allows CI gates to alert only on regressions, not pre-existing issues.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from scanner.intelligence.deduplicator import fingerprint
from scanner.models.finding import Finding

log = logging.getLogger(__name__)

_AEGISSCAN_VERSION = "V3"
# 1 = path exactly as scanned (machine-specific, files without the field); 2 = path relative to the scan target
_FINGERPRINT_VERSION = 2


class BaselineManager:
    """Load and apply a saved baseline of finding fingerprints."""

    def __init__(self, baseline_path: Path | None = None) -> None:
        self._fingerprints: set[str] = set()
        if baseline_path is not None:
            self._load(baseline_path)

    def _load(self, path: Path) -> None:
        if not path.exists():
            log.warning("Baseline file not found: %s — proceeding without suppression", path)
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            fps = data.get("fingerprints", [])
            self._fingerprints = set(fps)
            if data.get("fingerprint_version", 1) < _FINGERPRINT_VERSION:
                log.warning(
                    "Baseline %s is in the legacy format (absolute paths): it only matches on the "
                    "machine and directory that created it. Re-create it with --save-baseline for a "
                    "portable one.", path,
                )
            log.info("Baseline loaded: %d suppressed fingerprints from %s", len(fps), path)
        except (json.JSONDecodeError, OSError) as exc:
            log.warning("Failed to load baseline %s: %s — proceeding without suppression", path, exc)

    @property
    def is_active(self) -> bool:
        return bool(self._fingerprints)

    def _is_known(self, finding: Finding, root: Path | None) -> bool:
        if root is not None and fingerprint(finding, root) in self._fingerprints:
            return True
        # Legacy baselines (no fingerprint_version) hashed the path exactly as scanned, so they
        # only match on the machine and directory that created them. Still honour that.
        return fingerprint(finding) in self._fingerprints

    def suppress(self, findings: list[Finding], root: Path | None = None) -> tuple[list[Finding], int]:
        """
        Remove findings whose fingerprint is in the baseline.

        *root* is the scan target; with it, fingerprints are path-relative and match across
        machines and checkout directories.

        Returns (surviving_findings, n_suppressed).
        """
        if not self._fingerprints:
            return findings, 0

        kept = [f for f in findings if not self._is_known(f, root)]
        n_suppressed = len(findings) - len(kept)

        if n_suppressed:
            log.info("Baseline suppressed %d known finding(s)", n_suppressed)

        return kept, n_suppressed


def save_baseline(findings: list[Finding], target_path: Path, output_path: Path) -> None:
    """
    Save a baseline file from the current scan's findings.

    Args:
        findings    : The final finding list (after dedup/correlation).
        target_path : The scanned directory (for provenance).
        output_path : Where to write the baseline JSON file.
    """
    fps = [fingerprint(f, target_path) for f in findings]
    data = {
        "aegisscan_version": _AEGISSCAN_VERSION,
        "fingerprint_version": _FINGERPRINT_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "target_path": str(target_path.resolve()),
        "fingerprint_count": len(fps),
        "fingerprints": fps,
    }

    try:
        output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        log.info("Baseline saved: %d fingerprints -> %s", len(fps), output_path)
        print(f"  Baseline saved: {len(fps)} fingerprints -> {output_path}")
    except OSError as exc:
        log.error("Failed to save baseline to %s: %s", output_path, exc)
        print(f"  ERROR: could not save baseline: {exc}")
