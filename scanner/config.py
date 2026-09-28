"""
Per-project configuration, read from ``.aegisscan.toml`` in the scan target.

    # .aegisscan.toml
    exclude_dirs = ["tests", "examples"]   # extra directory names skipped by static tools

Missing or malformed files fall back to defaults (graceful degradation, plan §2
rule 6) — a bad config must never abort a scan.
"""
from __future__ import annotations

import logging
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

CONFIG_FILENAME = ".aegisscan.toml"


@dataclass(frozen=True)
class ScanConfig:
    exclude_dirs: frozenset[str] = field(default_factory=frozenset)


def load_config(target: Path) -> ScanConfig:
    path = target / CONFIG_FILENAME
    if not path.is_file():
        return ScanConfig()
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        log.warning("Ignoring invalid %s: %s", path, exc)
        return ScanConfig()

    raw = data.get("exclude_dirs", [])
    if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
        log.warning("%s: exclude_dirs must be a list of strings — ignored", path)
        raw = []
    return ScanConfig(exclude_dirs=frozenset(raw))
