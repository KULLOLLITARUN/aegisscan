"""Triage decisions made in the web UI: a finding marked a false positive or an accepted risk.

Stored per scan target in one JSON file in AegisScan's own data folder (local mode only). A finding
is identified by a key the UI derives from its relative path, rule source, issue type and category
(not its line, so a decision survives edits above it). Decisions do not change what the scanner
reports; the UI uses them to label and hide findings. For CI suppression use --save-baseline.
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

from scanner.storage.history import default_db_path

STATUSES = ("false_positive", "accepted")
_MAX_KEY = 600
_MAX_TARGET = 1000
_lock = threading.Lock()


def triage_path() -> Path:
    return default_db_path().parent / "triage.json"


def _norm_target(target: str) -> str:
    return str(target or "").replace("\\", "/").rstrip("/").lower()


def _load() -> dict:
    try:
        data = json.loads(triage_path().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def get_triage(target: str) -> dict[str, str]:
    """{finding key: status} for one scan target."""
    entries = _load().get(_norm_target(target), {})
    return {k: v["status"] for k, v in entries.items() if isinstance(v, dict) and v.get("status") in STATUSES}


def set_triage(target: str, key: str, status: str | None) -> None:
    """Record a decision, or clear it with status None. Raises ValueError on bad input."""
    if not target or len(target) > _MAX_TARGET:
        raise ValueError("target is required")
    if not key or len(key) > _MAX_KEY:
        raise ValueError("key is required")
    if status is not None and status not in STATUSES:
        raise ValueError(f"status must be one of {', '.join(STATUSES)} or null")
    with _lock:
        data = _load()
        entries = data.setdefault(_norm_target(target), {})
        if status is None:
            entries.pop(key, None)
        else:
            entries[key] = {"status": status, "at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        if not entries:
            data.pop(_norm_target(target), None)
        path = triage_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
        os.replace(tmp, path)
