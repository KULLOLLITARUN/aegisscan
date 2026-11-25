"""Full scan results kept for the web UI, so a page reload or a History click can show a past scan.

Only local-mode web scans are kept (hosted mode keeps nothing). One JSON file per scan, next to the
history database in AegisScan's own data folder, never inside a scanned folder. The newest
KEEP_RESULTS are kept; older files are deleted when a new one is written.
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path

from scanner.models.scan import ScanResult
from scanner.storage.history import default_db_path

log = logging.getLogger(__name__)

KEEP_RESULTS = 30
# scan ids are UUIDs; anything else is refused before it can become part of a path
_SCAN_ID = re.compile(r"^[0-9a-fA-F-]{8,64}$")


def results_dir() -> Path:
    return default_db_path().parent / "results"


def _path_for(scan_id: str) -> Path | None:
    if not _SCAN_ID.match(scan_id or ""):
        return None
    return results_dir() / f"{scan_id}.json"


def save_result(result: ScanResult) -> None:
    """Write the result and prune the oldest beyond KEEP_RESULTS. Never raises: a scan must not fail
    because its copy for the UI could not be written."""
    try:
        path = _path_for(getattr(result, "scan_id", "") or "")
        if path is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(result.model_dump_json(), encoding="utf-8")
        os.replace(tmp, path)
        kept = sorted(path.parent.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        for old in kept[KEEP_RESULTS:]:
            old.unlink(missing_ok=True)
    except Exception as exc:  # noqa: BLE001 - keeping a copy for the UI must never fail the scan
        log.warning("Could not keep the scan result for the UI: %s", exc)


def load_result(scan_id: str) -> str | None:
    """The stored result as JSON text, or None when it was never kept or has been pruned."""
    path = _path_for(scan_id)
    if path is None or not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def latest_result() -> str | None:
    """The most recently written result as JSON text, or None."""
    folder = results_dir()
    if not folder.is_dir():
        return None
    files = sorted(folder.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for f in files:
        try:
            return f.read_text(encoding="utf-8")
        except OSError:
            continue
    return None


def kept_ids() -> set[str]:
    folder = results_dir()
    return {p.stem for p in folder.glob("*.json")} if folder.is_dir() else set()
